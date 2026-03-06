"""
Checkmarx One MCP Server
Uses /api/results and /api/scans endpoints with flat tool arguments (no nested params).
"""

import json
import os
import time
import asyncio
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional, List, Dict, Any
from collections import defaultdict

import httpx
from dotenv import load_dotenv
from mcp.server.fastmcp import FastMCP

load_dotenv()

CX_BASE_URL  = os.getenv("CX_BASE_URL", "").rstrip("/")
CX_IAM_URL   = os.getenv("CX_IAM_URL",  "").rstrip("/")
CX_API_KEY   = os.getenv("CX_API_KEY", "")
CX_CLIENT_ID = os.getenv("CX_CLIENT_ID", "ast-app")
CX_TENANT    = os.getenv("CX_TENANT", "")
HISTORY_FILE = Path(os.getenv("HISTORY_FILE", "./report_history.json"))

mcp = FastMCP("checkmarx_mcp")

_token_cache: Dict[str, Any] = {"access_token": None, "expires_at": 0}


# ─── Auth ─────────────────────────────────────────────────────────────────────

async def _get_token() -> str:
    now = time.time()
    if _token_cache["access_token"] and now < _token_cache["expires_at"] - 30:
        return _token_cache["access_token"]
    iam_base  = CX_IAM_URL or CX_BASE_URL
    token_url = f"{iam_base}/auth/realms/{CX_TENANT}/protocol/openid-connect/token"
    async with httpx.AsyncClient(timeout=30) as client:
        resp = await client.post(token_url, data={
            "grant_type":    "refresh_token",
            "client_id":     CX_CLIENT_ID,
            "refresh_token": CX_API_KEY,
        })
        resp.raise_for_status()
        data = resp.json()
    _token_cache["access_token"] = data["access_token"]
    _token_cache["expires_at"]   = now + data.get("expires_in", 3600)
    return _token_cache["access_token"]


async def _get(path: str, params: Dict = None) -> Any:
    token = await _get_token()
    async with httpx.AsyncClient(timeout=60) as client:
        resp = await client.get(
            f"{CX_BASE_URL}{path}",
            params=params or {},
            headers={"Authorization": f"Bearer {token}"}
        )
        resp.raise_for_status()
        return resp.json()


def _err(e: Exception) -> str:
    if isinstance(e, httpx.HTTPStatusError):
        sc = e.response.status_code
        if sc == 401:
            return "Error 401: Auth failed. Check CX_API_KEY — it may have expired."
        if sc == 403:
            return "Error 403: Forbidden. Check your account permissions."
        if sc == 404:
            return f"Error 404: Not found. URL: {e.request.url}"
        return f"Error {sc}: {e.response.text[:500]}"
    return f"Error ({type(e).__name__}): {e}"


def _compute_metrics(findings: List[Dict]) -> Dict:
    total   = len(findings)
    by_sev  = defaultdict(int)
    by_stat = defaultdict(int)
    by_proj: Dict[str, Any] = defaultdict(lambda: defaultdict(int))
    oldest_open: Dict[str, str] = {}

    for f in findings:
        sev  = (f.get("severity") or "Unknown").capitalize()
        stat = (f.get("status")   or f.get("state") or "Unknown").capitalize()
        proj = f.get("projectId") or f.get("project_id") or "unknown"
        by_sev[sev]         += 1
        by_stat[stat]       += 1
        by_proj[proj][sev]  += 1
        by_proj[proj][stat] += 1
        if sev == "High" and stat in ("Open", "To_verify", "Confirmed", "Urgent"):
            detected = f.get("firstFoundAt") or f.get("detectedAt") or ""
            if detected and (not oldest_open.get(proj) or detected < oldest_open[proj]):
                oldest_open[proj] = detected

    high   = by_sev.get("High", 0)
    medium = by_sev.get("Medium", 0)
    low    = by_sev.get("Low", 0)
    fixed  = by_stat.get("Fixed", 0) + by_stat.get("Not_exploitable", 0)

    mttr: Dict[str, Any] = {}
    for proj, earliest in oldest_open.items():
        try:
            dt = datetime.fromisoformat(earliest.replace("Z", "+00:00"))
            mttr[proj] = (datetime.now(timezone.utc) - dt).days
        except Exception:
            mttr[proj] = None

    return {
        "total_findings": total,
        "severity_distribution": {"high": high, "medium": medium, "low": low, "info": by_sev.get("Info", 0)},
        "status_distribution": dict(by_stat),
        "fix_rate_pct": round(fixed / total * 100, 1) if total else 0.0,
        "risk_score": high * 10 + medium * 5 + low,
        "per_project": {p: dict(v) for p, v in by_proj.items()},
        "open_high_age_days_by_project": mttr,
        "computed_at": datetime.now(timezone.utc).isoformat(),
    }


def _load_history() -> List[Dict]:
    if HISTORY_FILE.exists():
        try:
            return json.loads(HISTORY_FILE.read_text())
        except Exception:
            return []
    return []


def _save_history(h: List[Dict]) -> None:
    HISTORY_FILE.parent.mkdir(parents=True, exist_ok=True)
    HISTORY_FILE.write_text(json.dumps(h, indent=2))


# ─── Tools (flat arguments — no nested params model) ──────────────────────────

@mcp.tool(name="checkmarx_list_projects")
async def checkmarx_list_projects(
    limit: int = 100,
    offset: int = 0,
) -> str:
    """List all Checkmarx One projects. Returns id and name for each project."""
    try:
        data     = await _get("/api/projects", {"limit": limit, "offset": offset})
        projects = data.get("projects", data) if isinstance(data, dict) else data
        items    = []
        for p in (projects if isinstance(projects, list) else []):
            items.append({
                "id":        p.get("id") or p.get("projectId", ""),
                "name":      p.get("name", ""),
                "createdAt": p.get("createdAt", ""),
            })
        return json.dumps({
            "total":    data.get("filteredTotalCount", len(items)) if isinstance(data, dict) else len(items),
            "count":    len(items),
            "projects": items,
        }, indent=2)
    except Exception as e:
        return _err(e)


@mcp.tool(name="checkmarx_get_scans")
async def checkmarx_get_scans(
    project_id: str = "",
    limit: int = 20,
) -> str:
    """
    List recent scans. Optionally filter by project_id.
    Returns scan id, projectId, status, createdAt, branch.
    """
    try:
        query: Dict[str, Any] = {"limit": limit, "sort": "-created_at"}
        if project_id:
            query["project-id"] = project_id
        data  = await _get("/api/scans", query)
        scans = data.get("scans", data) if isinstance(data, dict) else data
        items = []
        for s in (scans if isinstance(scans, list) else []):
            items.append({
                "id":        s.get("id", ""),
                "projectId": s.get("projectId") or s.get("project", {}).get("id", ""),
                "status":    s.get("status", ""),
                "branch":    s.get("branch", ""),
                "createdAt": s.get("createdAt", ""),
            })
        return json.dumps({"count": len(items), "scans": items}, indent=2)
    except Exception as e:
        return _err(e)


@mcp.tool(name="checkmarx_get_results")
async def checkmarx_get_results(
    project_id: str = "",
    scan_id: str = "",
    severity: str = "",
    status: str = "",
    limit: int = 500,
    save_history: bool = True,
) -> str:
    """
    Fetch security findings from Checkmarx One.
    Filter by project_id, scan_id, severity (HIGH/MEDIUM/LOW), or status.
    Returns findings and pre-computed metrics including risk score and fix rate.
    Call this tool to get security data before computing metrics or compliance summaries.
    """
    try:
        query: Dict[str, Any] = {"limit": limit}
        if project_id:
            query["project-id"] = project_id
        if scan_id:
            query["scan-id"] = scan_id
        if severity:
            query["severity"] = severity
        if status:
            query["status"] = status

        data     = await _get("/api/results", query)
        results  = data.get("results", data) if isinstance(data, dict) else data
        findings = results if isinstance(results, list) else []
        metrics  = _compute_metrics(findings)

        if save_history:
            history = _load_history()
            history.append({"timestamp": metrics["computed_at"], "metrics": metrics})
            _save_history(history)

        return json.dumps({
            "status":   "success",
            "count":    len(findings),
            "metrics":  metrics,
            "findings": findings[:100],
            "note":     f"Showing first 100 of {len(findings)} findings. Metrics computed on all {len(findings)}.",
        }, indent=2)
    except Exception as e:
        return _err(e)


@mcp.tool(name="checkmarx_compute_metrics")
async def checkmarx_compute_metrics(results_json: str) -> str:
    """
    Compute risk metrics from a results JSON string.
    Pass the raw JSON output from checkmarx_get_results.
    Returns severity distribution, fix rate, and risk score.
    """
    try:
        data     = json.loads(results_json)
        findings = data.get("findings") or data.get("results") or (data if isinstance(data, list) else [])
        return json.dumps(_compute_metrics(findings), indent=2)
    except json.JSONDecodeError as e:
        return f"Error: Invalid JSON — {e}"
    except Exception as e:
        return _err(e)


@mcp.tool(name="checkmarx_get_historical_trends")
async def checkmarx_get_historical_trends(
    project_id: str = "",
    last_n: int = 10,
) -> str:
    """
    Show risk score and fix rate trends over time using locally saved snapshots.
    Requires at least 2 prior calls to checkmarx_get_results with save_history=True.
    """
    try:
        history = _load_history()
        if not history:
            return json.dumps({
                "status":  "no_data",
                "message": "No history yet. Call checkmarx_get_results first to start building trend data.",
            })

        if project_id:
            history = [s for s in history if project_id in s.get("metrics", {}).get("per_project", {})]

        history = history[-last_n:]

        if len(history) < 2:
            return json.dumps({
                "status":  "insufficient_data",
                "message": f"Only {len(history)} snapshot(s). Need at least 2 to show trends.",
                "snapshots": history,
            })

        first_risk = history[0].get("metrics", {}).get("risk_score", 0)
        last_risk  = history[-1].get("metrics", {}).get("risk_score", 0)
        if last_risk < first_risk * 0.95:
            trend = "improving"
        elif last_risk > first_risk * 1.05:
            trend = "worsening"
        else:
            trend = "stable"

        return json.dumps({
            "status":            "success",
            "snapshots_shown":   len(history),
            "trend_direction":   trend,
            "risk_score_change": last_risk - first_risk,
            "snapshots": [
                {
                    "timestamp":  s.get("timestamp"),
                    "risk_score": s.get("metrics", {}).get("risk_score"),
                    "fix_rate":   s.get("metrics", {}).get("fix_rate_pct"),
                    "total":      s.get("metrics", {}).get("total_findings"),
                    "high":       s.get("metrics", {}).get("severity_distribution", {}).get("high"),
                }
                for s in history
            ],
        }, indent=2)
    except Exception as e:
        return _err(e)


@mcp.tool(name="checkmarx_compare_projects")
async def checkmarx_compare_projects(
    results_json: str,
    top_n: int = 5,
) -> str:
    """
    Rank projects by risk score from a results JSON string.
    Pass raw JSON from checkmarx_get_results.
    Returns top N riskiest projects with severity breakdown and fix rates.
    """
    try:
        data     = json.loads(results_json)
        findings = data.get("findings") or data.get("results") or (data if isinstance(data, list) else [])

        by_proj: Dict[str, List] = defaultdict(list)
        for f in findings:
            proj = f.get("projectId") or f.get("project_id") or "unknown"
            by_proj[proj].append(f)

        ranked = []
        for proj_id, proj_findings in by_proj.items():
            m = _compute_metrics(proj_findings)
            ranked.append({
                "project_id":   proj_id,
                "risk_score":   m["risk_score"],
                "fix_rate_pct": m["fix_rate_pct"],
                "total":        m["total_findings"],
                "high":         m["severity_distribution"]["high"],
                "medium":       m["severity_distribution"]["medium"],
                "low":          m["severity_distribution"]["low"],
            })

        ranked.sort(key=lambda x: x["risk_score"], reverse=True)
        return json.dumps({"total_projects": len(ranked), "top_riskiest": ranked[:top_n]}, indent=2)
    except json.JSONDecodeError as e:
        return f"Error: Invalid JSON — {e}"
    except Exception as e:
        return _err(e)


@mcp.tool(name="checkmarx_compliance_summary")
async def checkmarx_compliance_summary(
    project_id: str = "",
    results_json: str = "",
) -> str:
    """
    Generate an executive compliance and risk summary.
    Fetches fresh data automatically if results_json is not provided.
    Returns a Markdown report with risk flags and recommendations.
    """
    try:
        if results_json:
            data     = json.loads(results_json)
            findings = data.get("findings") or data.get("results") or (data if isinstance(data, list) else [])
        else:
            query: Dict[str, Any] = {"limit": 500}
            if project_id:
                query["project-id"] = project_id
            raw      = await _get("/api/results", query)
            findings = raw.get("results", raw) if isinstance(raw, dict) else raw

        m = _compute_metrics(findings)

        flags = []
        if m["severity_distribution"]["high"] > 0:
            flags.append(f"🔴 {m['severity_distribution']['high']} HIGH severity findings require immediate attention")
        if m["fix_rate_pct"] < 50:
            flags.append(f"🟡 Fix rate is {m['fix_rate_pct']}% — below the recommended 50% threshold")
        if m["risk_score"] > 500:
            flags.append(f"🔴 Risk score {m['risk_score']} is CRITICAL")
        elif m["risk_score"] > 200:
            flags.append(f"🟡 Risk score {m['risk_score']} is ELEVATED")
        else:
            flags.append(f"🟢 Risk score {m['risk_score']} is within acceptable range")

        for proj, days in m.get("open_high_age_days_by_project", {}).items():
            if days and days > 30:
                flags.append(f"🔴 Project {proj}: High severity finding open {days} days (SLA breach)")

        summary = f"""# Checkmarx One Compliance Summary
**Generated:** {m['computed_at'][:10]}

## Overview
| Metric | Value |
|--------|-------|
| Total Findings | {m['total_findings']} |
| High Severity | {m['severity_distribution']['high']} |
| Medium Severity | {m['severity_distribution']['medium']} |
| Low Severity | {m['severity_distribution']['low']} |
| Fix Rate | {m['fix_rate_pct']}% |
| Risk Score | {m['risk_score']} |

## Risk Flags
{chr(10).join(flags) if flags else '✅ No critical flags'}

## Recommendations
- Prioritise remediation of all HIGH severity findings
- Target fix rate >80% for compliance
- Ensure no HIGH finding remains open >30 days
- Schedule weekly scans across all projects
"""
        return summary
    except Exception as e:
        return _err(e)



# ─── Analytics KPI Tool (appended) ───────────────────────────────────────────


@mcp.tool(name="checkmarx_get_analytics_kpi")
async def checkmarx_get_analytics_kpi(
    kpi_names: str = "ALL",
    project_ids: str = "",
    application_ids: str = "",
    start_date: str = "",
    end_date: str = "",
    time_resolution: str = "MONTH",
    scan_type: str = "",
    severity: str = "",
) -> str:
    """
    Retrieve Analytics KPI data from Checkmarx One via POST /api/data_analytics.
    Returns pre-aggregated executive metrics from the Analytics module.

    kpi_names options (comma-separated or ALL):
      OPEN_VULNERABILITIES, RESOLVED_VULNERABILITIES, MTTR,
      VULNERABILITIES_BY_SEVERITY, VULNERABILITIES_BY_STATUS,
      VULNERABILITIES_OVER_TIME, TOP_VULNERABLE_PROJECTS,
      TOP_VULNERABILITIES, SCAN_COVERAGE, FAILED_SCANS

    time_resolution: DAY, WEEK, or MONTH (default MONTH)
    project_ids: comma-separated project IDs (optional)
    start_date / end_date: ISO date strings e.g. 2024-01-01 (optional)
    scan_type: SAST, SCA, KICS, or API (optional)
    severity: HIGH, MEDIUM, LOW, or INFO (optional)
    """
    try:
        ALL_KPIS = [
            "OPEN_VULNERABILITIES", "RESOLVED_VULNERABILITIES", "MTTR",
            "VULNERABILITIES_BY_SEVERITY", "VULNERABILITIES_BY_STATUS",
            "VULNERABILITIES_OVER_TIME", "TOP_VULNERABLE_PROJECTS",
            "TOP_VULNERABILITIES", "SCAN_COVERAGE", "FAILED_SCANS",
        ]

        selected = ALL_KPIS if kpi_names.strip().upper() == "ALL" else [k.strip().upper() for k in kpi_names.split(",")]

        body: Dict[str, Any] = {
            "kpiNames": selected,
            "timeResolution": time_resolution.upper(),
        }
        if project_ids:
            body["projectIds"] = [p.strip() for p in project_ids.split(",")]
        if application_ids:
            body["applicationIds"] = [a.strip() for a in application_ids.split(",")]
        if start_date:
            body["startDate"] = start_date
        if end_date:
            body["endDate"] = end_date
        if scan_type:
            body["scanType"] = scan_type.upper()
        if severity:
            body["severity"] = severity.upper()

        token = await _get_token()
        async with httpx.AsyncClient(timeout=60) as client:
            resp = await client.post(
                f"{CX_BASE_URL}/api/data_analytics",
                json=body,
                headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
            )
            resp.raise_for_status()
            data = resp.json()

        return json.dumps({
            "status": "success",
            "kpis_requested": selected,
            "filters": {"project_ids": project_ids or "all", "time_resolution": time_resolution},
            "data": data,
        }, indent=2)

    except httpx.HTTPStatusError as e:
        if e.response.status_code == 404:
            return json.dumps({
                "error": "Analytics KPI endpoint not found (404). The Analytics module may not be enabled on your tenant.",
                "endpoint": f"{CX_BASE_URL}/api/data_analytics",
            })
        return _err(e)
    except Exception as e:
        return _err(e)



# ─── SCA Export Helper ────────────────────────────────────────────────────────

SCA_EXPORT_BASE = "https://us.ast.checkmarx.net/api/sca/export"
SCA_RISK_BASE   = "https://us.ast.checkmarx.net/api/sca/management-of-risk"


async def _sca_post(url: str, body: Dict) -> Any:
    token = await _get_token()
    async with httpx.AsyncClient(timeout=60) as client:
        resp = await client.post(url, json=body, headers={
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
        })
        resp.raise_for_status()
        if resp.content:
            return resp.json()
        return {"status": "ok"}


async def _sca_get(url: str, params: Dict = None) -> Any:
    token = await _get_token()
    async with httpx.AsyncClient(timeout=60) as client:
        resp = await client.get(url, params=params or {}, headers={"Authorization": f"Bearer {token}"})
        resp.raise_for_status()
        if resp.content:
            return resp.json()
        return {}


# ─── SCA Export Tools ─────────────────────────────────────────────────────────

@mcp.tool(name="checkmarx_sca_create_export")
async def checkmarx_sca_create_export(
    scan_id: str,
    file_format: str = "ScanReportJson",
    hide_dev_dependencies: bool = False,
    show_only_effective_licenses: bool = False,
    exclude_packages: bool = False,
    exclude_licenses: bool = False,
    exclude_vulnerabilities: bool = False,
    exclude_policies: bool = False,
) -> str:
    """
    Create an SCA export report for a specific scan. Returns an exportId to use for polling.

    file_format options:
      - ScanReportJson (default) — full JSON scan report
      - ScanReportPdf            — PDF report
      - ScanReportXml            — XML report
      - ScanReportCsv            — CSV report
      - CycloneDxJson            — SBOM in CycloneDX JSON format
      - CycloneDxXml             — SBOM in CycloneDX XML format
      - SpdxJson                 — SBOM in SPDX JSON format
      - RemediatedPackagesJson   — recommended manifest file with fixed package versions

    Use checkmarx_get_scans to get a scan_id first, then pass it here.
    After getting the exportId, call checkmarx_sca_poll_export to get the download link.
    """
    try:
        body: Dict[str, Any] = {
            "scanId": scan_id,
            "fileFormat": file_format,
        }

        is_sbom = file_format.startswith("CycloneDx") or file_format.startswith("Spdx")
        is_report = file_format.startswith("ScanReport")

        if is_sbom:
            body["exportParameters"] = {
                "hideDevAndTestDependencies": hide_dev_dependencies,
                "showOnlyEffectiveLicenses": show_only_effective_licenses,
            }
        elif is_report:
            body["exportParameters"] = {
                "hideDevAndTestDependencies": hide_dev_dependencies,
                "showOnlyEffectiveLicenses": show_only_effective_licenses,
                "excludePackages": exclude_packages,
                "excludeLicenses": exclude_licenses,
                "excludeVulnerabilities": exclude_vulnerabilities,
                "excludePolicies": exclude_policies,
            }

        data = await _sca_post(f"{SCA_EXPORT_BASE}/requests", body)
        export_id = data.get("exportId", "")

        return json.dumps({
            "status": "accepted",
            "exportId": export_id,
            "fileFormat": file_format,
            "message": "Export started. Call checkmarx_sca_poll_export with this exportId to get the download link.",
        }, indent=2)

    except Exception as e:
        return _err(e)


@mcp.tool(name="checkmarx_sca_poll_export")
async def checkmarx_sca_poll_export(
    export_id: str,
    wait_for_completion: bool = True,
) -> str:
    """
    Poll the status of an SCA export report created by checkmarx_sca_create_export.
    If wait_for_completion is True (default), waits up to 3 minutes for the export to finish
    and returns the download URL when ready.

    exportStatus values: Pending, Exporting, Completed, Failed
    When Completed, fileUrl contains the download link.
    """
    try:
        max_wait = 180
        interval = 5
        elapsed  = 0

        while True:
            data   = await _sca_get(f"{SCA_EXPORT_BASE}/requests", {"exportId": export_id})
            status = data.get("exportStatus", "")
            file_url = data.get("fileUrl", "")

            if status == "Completed":
                return json.dumps({
                    "status": "completed",
                    "exportId": export_id,
                    "fileUrl": file_url,
                    "message": "Export ready. Use the fileUrl to download (requires bearer token). Or call checkmarx_sca_download_export.",
                }, indent=2)

            if status == "Failed":
                return json.dumps({
                    "status": "failed",
                    "exportId": export_id,
                    "error": data.get("errorMessage", "Unknown error"),
                })

            if not wait_for_completion or elapsed >= max_wait:
                return json.dumps({
                    "status": status or "pending",
                    "exportId": export_id,
                    "message": f"Export still in progress after {elapsed}s. Call again to check.",
                })

            await asyncio.sleep(interval)
            elapsed += interval

    except Exception as e:
        return _err(e)


@mcp.tool(name="checkmarx_sca_download_export")
async def checkmarx_sca_download_export(export_id: str) -> str:
    """
    Download a completed SCA export by exportId.
    Returns the raw content as a string (JSON/XML/CSV) or a summary for binary formats (PDF).
    Call checkmarx_sca_poll_export first to confirm the export is completed.
    """
    try:
        token = await _get_token()
        async with httpx.AsyncClient(timeout=120) as client:
            resp = await client.get(
                f"{SCA_EXPORT_BASE}/requests/{export_id}/download",
                headers={"Authorization": f"Bearer {token}"},
                follow_redirects=True,
            )
            resp.raise_for_status()

        content_type = resp.headers.get("content-type", "")

        if "json" in content_type:
            try:
                parsed = resp.json()
                return json.dumps({
                    "status": "success",
                    "format": "json",
                    "content": parsed,
                }, indent=2)
            except Exception:
                pass

        if "pdf" in content_type or "octet-stream" in content_type:
            return json.dumps({
                "status": "success",
                "format": "binary",
                "size_bytes": len(resp.content),
                "message": "Binary file (PDF/ZIP) downloaded. File cannot be displayed as text. Use the fileUrl from checkmarx_sca_poll_export to download it directly in your browser.",
            })

        # Text-based (XML, CSV)
        text = resp.text[:5000]
        return json.dumps({
            "status": "success",
            "format": "text",
            "content_preview": text,
            "truncated": len(resp.text) > 5000,
        }, indent=2)

    except Exception as e:
        return _err(e)


# ─── SCA Management of Risk Tools ─────────────────────────────────────────────

@mcp.tool(name="checkmarx_sca_triage_vulnerability")
async def checkmarx_sca_triage_vulnerability(
    package_name: str,
    package_version: str,
    package_manager: str,
    vulnerability_id: str,
    project_ids: str,
    action: str = "ChangeState",
    value: str = "ToVerify",
    comment: str = "",
) -> str:
    """
    Triage (update state or risk score) for a specific SCA vulnerability instance.

    action options:
      - ChangeState  — change the triage state (default)
      - ChangeScore  — override the CVSS risk score

    value for ChangeState (pick one):
      - ToVerify              — needs assessment (default/initial state)
      - NotExploitable        — confirmed not exploitable
      - ProposedNotExploitable — suggested not exploitable, pending review
      - Confirmed             — confirmed vulnerability
      - Urgent                — critical, needs immediate fix

    value for ChangeScore:
      - A number between 0.0 and 10.0 (e.g. "7.5")

    project_ids: comma-separated list of project IDs this triage applies to
    comment: required — explain the rationale for this triage decision

    Example: Mark CVE-2021-44906 in minimist@0.0.10 (Npm) as NotExploitable
    """
    try:
        if not comment:
            return "Error: comment is required. Explain why you are making this triage decision."

        proj_list = [p.strip() for p in project_ids.split(",") if p.strip()]
        if not proj_list:
            return "Error: project_ids is required. Provide at least one project ID."

        score_value: Any = value
        if action == "ChangeScore":
            try:
                score_value = float(value)
            except ValueError:
                return f"Error: For ChangeScore, value must be a number between 0.0 and 10.0, got: {value}"

        body = {
            "packageName": package_name,
            "packageVersion": package_version,
            "packageManager": package_manager,
            "vulnerabilityId": vulnerability_id,
            "projectIds": proj_list,
            "actions": [{"actionType": action, "value": score_value, "comment": comment}],
        }

        await _sca_post(f"{SCA_RISK_BASE}/package-vulnerabilities", body)

        return json.dumps({
            "status": "success",
            "message": f"Vulnerability {vulnerability_id} in {package_name}@{package_version} triaged as {action}={value}",
            "affected_projects": proj_list,
        }, indent=2)

    except Exception as e:
        return _err(e)


@mcp.tool(name="checkmarx_sca_triage_vulnerabilities_bulk")
async def checkmarx_sca_triage_vulnerabilities_bulk(
    vulnerabilities_json: str,
    action: str = "ChangeState",
    value: str = "ToVerify",
    comment: str = "",
) -> str:
    """
    Triage multiple SCA vulnerabilities at once with the same action.

    vulnerabilities_json: JSON array of vulnerability objects, each with:
      - packageName, packageVersion, packageManager, vulnerabilityId, projectIds (list)

    Example vulnerabilities_json:
    [
      {"packageName": "minimist", "packageVersion": "0.0.10", "packageManager": "Npm",
       "vulnerabilityId": "CVE-2021-44906", "projectIds": ["proj-id-1"]},
      {"packageName": "utile", "packageVersion": "0.2.1", "packageManager": "Npm",
       "vulnerabilityId": "Cx61ff18e9-706e", "projectIds": ["proj-id-1"]}
    ]

    action / value / comment: same as checkmarx_sca_triage_vulnerability
    """
    try:
        if not comment:
            return "Error: comment is required."

        vulns = json.loads(vulnerabilities_json)
        if not isinstance(vulns, list) or not vulns:
            return "Error: vulnerabilities_json must be a non-empty JSON array."

        score_value: Any = value
        if action == "ChangeScore":
            try:
                score_value = float(value)
            except ValueError:
                return f"Error: For ChangeScore, value must be a number 0.0-10.0, got: {value}"

        body = {
            "packageVulnerabilitiesProfile": vulns,
            "actions": [{"actionType": action, "value": score_value, "comment": comment}],
        }

        await _sca_post(f"{SCA_RISK_BASE}/package-vulnerabilities/bulk", body)

        return json.dumps({
            "status": "success",
            "message": f"Bulk triage applied: {action}={value} to {len(vulns)} vulnerability instances.",
        }, indent=2)

    except json.JSONDecodeError as e:
        return f"Error: Invalid JSON in vulnerabilities_json — {e}"
    except Exception as e:
        return _err(e)


@mcp.tool(name="checkmarx_sca_mute_package")
async def checkmarx_sca_mute_package(
    package_name: str,
    package_version: str,
    package_manager: str,
    project_id: str,
    state: str = "Muted",
    comment: str = "",
    snooze_until: str = "",
) -> str:
    """
    Mute or snooze an SCA package so its vulnerabilities are hidden from scan results.

    state options:
      - Muted     — permanently hide vulnerabilities for this package (until manually unset)
      - Snooze    — temporarily hide until snooze_until date
      - Monitored — revert back to showing results (un-mute/un-snooze)

    snooze_until: ISO datetime string required when state=Snooze (e.g. "2025-06-30T21:00:00.000Z")
    comment: required — explain why you are muting/snoozing this package
    project_id: the project this mute applies to
    package_manager: e.g. Npm, Maven, PyPI, NuGet, Go, etc.
    """
    try:
        if not comment:
            return "Error: comment is required. Explain why you are muting this package."
        if state == "Snooze" and not snooze_until:
            return "Error: snooze_until is required when state=Snooze. Provide an ISO datetime e.g. 2025-12-31T00:00:00.000Z"

        action_value: Dict[str, Any] = {"state": state, "endDate": snooze_until if state == "Snooze" else None}

        body = {
            "packageName": package_name,
            "packageVersion": package_version,
            "packageManager": package_manager,
            "projectId": project_id,
            "actions": [{"actionType": "Ignore", "value": action_value, "comment": comment}],
        }

        await _sca_post(f"{SCA_RISK_BASE}/packages", body)

        msg = {
            "Muted":     f"Package {package_name}@{package_version} permanently muted in project {project_id}.",
            "Snooze":    f"Package {package_name}@{package_version} snoozed until {snooze_until} in project {project_id}.",
            "Monitored": f"Package {package_name}@{package_version} restored to Monitored (mute/snooze removed) in project {project_id}.",
        }.get(state, f"Package state set to {state}.")

        return json.dumps({"status": "success", "message": msg}, indent=2)

    except Exception as e:
        return _err(e)


@mcp.tool(name="checkmarx_sca_mute_packages_bulk")
async def checkmarx_sca_mute_packages_bulk(
    packages_json: str,
    state: str = "Muted",
    comment: str = "",
    snooze_until: str = "",
) -> str:
    """
    Mute or snooze multiple SCA packages at once.

    packages_json: JSON array of package objects, each with:
      - packageName, packageVersion, packageManager, projectId

    Example:
    [
      {"packageName": "lodash", "packageVersion": "4.17.15", "packageManager": "Npm", "projectId": "proj-id-1"},
      {"packageName": "axios",  "packageVersion": "0.21.1",  "packageManager": "Npm", "projectId": "proj-id-1"}
    ]

    state / comment / snooze_until: same as checkmarx_sca_mute_package
    """
    try:
        if not comment:
            return "Error: comment is required."
        if state == "Snooze" and not snooze_until:
            return "Error: snooze_until is required when state=Snooze."

        packages = json.loads(packages_json)
        if not isinstance(packages, list) or not packages:
            return "Error: packages_json must be a non-empty JSON array."

        action_value: Dict[str, Any] = {"state": state, "endDate": snooze_until if state == "Snooze" else None}

        body = {
            "packagesProfile": packages,
            "actions": [{"actionType": "Ignore", "value": action_value, "comment": comment}],
        }

        await _sca_post(f"{SCA_RISK_BASE}/packages/bulk", body)

        return json.dumps({
            "status": "success",
            "message": f"Bulk package {state.lower()} applied to {len(packages)} packages.",
        }, indent=2)

    except json.JSONDecodeError as e:
        return f"Error: Invalid JSON — {e}"
    except Exception as e:
        return _err(e)


@mcp.tool(name="checkmarx_sca_triage_supply_chain_risk")
async def checkmarx_sca_triage_supply_chain_risk(
    package_name: str,
    package_version: str,
    package_manager: str,
    supply_chain_risk_id: str,
    project_ids: str,
    action: str = "ChangeState",
    value: str = "ToVerify",
    comment: str = "",
) -> str:
    """
    Triage a supply chain risk (suspected malicious package) in SCA.

    supply_chain_risk_id: the specific supply chain risk UUID from scan results
    project_ids: comma-separated project IDs
    action: ChangeState or ChangeScore
    value for ChangeState: ToVerify, NotExploitable, ProposedNotExploitable, Confirmed, Urgent
    value for ChangeScore: a number 0.0-10.0
    comment: required
    """
    try:
        if not comment:
            return "Error: comment is required."

        proj_list = [p.strip() for p in project_ids.split(",") if p.strip()]
        if not proj_list:
            return "Error: project_ids is required."

        score_value: Any = value
        if action == "ChangeScore":
            try:
                score_value = float(value)
            except ValueError:
                return f"Error: For ChangeScore, value must be 0.0-10.0, got: {value}"

        body = {
            "packageName": package_name,
            "packageVersion": package_version,
            "packageManager": package_manager,
            "supplyChainRiskId": supply_chain_risk_id,
            "projectIds": proj_list,
            "actions": [{"actionType": action, "value": score_value, "comment": comment}],
        }

        await _sca_post(f"{SCA_RISK_BASE}/package-supply-chain-risks", body)

        return json.dumps({
            "status": "success",
            "message": f"Supply chain risk {supply_chain_risk_id} in {package_name}@{package_version} triaged: {action}={value}",
            "affected_projects": proj_list,
        }, indent=2)

    except Exception as e:
        return _err(e)



# ─── Scan Tools ───────────────────────────────────────────────────────────────

async def _cx_patch(path: str, body: Dict) -> Any:
    token = await _get_token()
    async with httpx.AsyncClient(timeout=60) as client:
        resp = await client.patch(
            f"{CX_BASE_URL}{path}",
            json=body,
            headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
        )
        resp.raise_for_status()
        return resp.json() if resp.content else {}


async def _cx_delete(path: str) -> Any:
    token = await _get_token()
    async with httpx.AsyncClient(timeout=60) as client:
        resp = await client.delete(
            f"{CX_BASE_URL}{path}",
            headers={"Authorization": f"Bearer {token}"}
        )
        resp.raise_for_status()
        return {}


async def _cx_put(path: str, body: Dict) -> Any:
    token = await _get_token()
    async with httpx.AsyncClient(timeout=60) as client:
        resp = await client.put(
            f"{CX_BASE_URL}{path}",
            json=body,
            headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
        )
        resp.raise_for_status()
        return resp.json() if resp.content else {}


async def _cx_post_scan(path: str, body: Dict) -> Any:
    token = await _get_token()
    async with httpx.AsyncClient(timeout=60) as client:
        resp = await client.post(
            f"{CX_BASE_URL}{path}",
            json=body,
            headers={
                "Authorization": f"Bearer {token}",
                "Content-Type": "application/json; version=1.0",
                "Accept": "*/*; version=1.0",
            }
        )
        resp.raise_for_status()
        return resp.json() if resp.content else {}


@mcp.tool(name="checkmarx_run_scan")
async def checkmarx_run_scan(
    project_id: str,
    source_type: str = "git",
    repo_url: str = "",
    branch: str = "main",
    git_token: str = "",
    upload_url: str = "",
    scanners: str = "sast,sca,kics",
    incremental: bool = False,
    tags: str = "",
) -> str:
    """
    Run a new Checkmarx One scan on a project.

    source_type options:
      - git    (default) — scan from a Git repository
      - upload           — scan from a pre-uploaded zip file (requires upload_url)

    scanners: comma-separated list of scanners to run:
      sast, sca, kics, apisec, containers, microengines
      Example: "sast,sca,kics" or "sast,sca"

    git_token: personal access token or API key for private repos (leave empty for public)
    upload_url: required when source_type=upload — URL from POST /api/uploads
    incremental: if True, only scans changed code since last scan (SAST only)
    tags: comma-separated key:value pairs e.g. "env:prod,team:backend"
    branch: Git branch to scan (default: main)

    Returns the scan ID and status. Use checkmarx_get_scan_details to poll status.
    """
    try:
        # Build config array from scanners list
        scanner_list = [s.strip().lower() for s in scanners.split(",") if s.strip()]
        config = []
        for scanner in scanner_list:
            if scanner == "sast":
                config.append({"type": "sast", "value": {
                    "incremental": str(incremental).lower(),
                    "presetName": "Checkmarx Default",
                }})
            elif scanner == "sca":
                config.append({"type": "sca", "value": {
                    "exploitablePath": "false",
                    "enableContainersScan": "false" if "containers" in scanner_list else "true",
                }})
            elif scanner in ("kics", "iac"):
                config.append({"type": "kics", "value": {}})
            elif scanner == "apisec":
                config.append({"type": "apisec", "value": {}})
            elif scanner == "containers":
                config.append({"type": "containers", "value": {}})
            elif scanner in ("microengines", "secrets", "scorecard"):
                config.append({"type": "microengines", "value": {
                    "scorecard": "true" if "scorecard" in scanner else "false",
                    "2ms": "true" if scanner in ("microengines", "secrets") else "false",
                }})

        # Build tags dict
        tags_dict: Dict[str, str] = {}
        if tags:
            for tag in tags.split(","):
                tag = tag.strip()
                if ":" in tag:
                    k, v = tag.split(":", 1)
                    tags_dict[k.strip()] = v.strip()
                elif tag:
                    tags_dict[tag] = ""

        # Build handler
        if source_type == "git":
            if not repo_url:
                return "Error: repo_url is required for git scans."
            handler: Dict[str, Any] = {"branch": branch, "repoUrl": repo_url}
            if git_token:
                handler["credentials"] = {"username": "", "type": "apiKey", "value": git_token}
        elif source_type == "upload":
            if not upload_url:
                return "Error: upload_url is required for upload scans."
            handler = {"uploadUrl": upload_url, "branch": branch}
        else:
            return f"Error: unsupported source_type '{source_type}'. Use 'git' or 'upload'."

        body = {
            "type": source_type,
            "handler": handler,
            "project": {"id": project_id},
            "config": config,
            "tags": tags_dict,
        }

        data = await _cx_post_scan("/api/scans", body)

        return json.dumps({
            "status": "created",
            "scan_id": data.get("id", ""),
            "scan_status": data.get("status", ""),
            "project_id": project_id,
            "branch": branch,
            "scanners": scanner_list,
            "created_at": data.get("createdAt", ""),
            "message": "Scan started. Use checkmarx_get_scan_details to poll for completion.",
        }, indent=2)

    except Exception as e:
        return _err(e)


@mcp.tool(name="checkmarx_get_scan_details")
async def checkmarx_get_scan_details(scan_id: str) -> str:
    """
    Get details and current status of a specific scan.
    Status values: Queued, Running, Completed, Failed, Partial, Canceled.
    Use this to poll a scan started by checkmarx_run_scan.
    """
    try:
        data = await _get(f"/api/scans/{scan_id}")
        return json.dumps({
            "scan_id":      data.get("id", ""),
            "status":       data.get("status", ""),
            "project_id":   data.get("projectId", ""),
            "project_name": data.get("projectName", ""),
            "branch":       data.get("branch", ""),
            "created_at":   data.get("createdAt", ""),
            "updated_at":   data.get("updatedAt", ""),
            "initiator":    data.get("initiator", ""),
            "engines":      data.get("engines", []),
            "source_type":  data.get("sourceType", ""),
            "status_details": data.get("statusDetails", []),
            "tags":         data.get("tags", {}),
        }, indent=2)
    except Exception as e:
        return _err(e)


@mcp.tool(name="checkmarx_list_scans")
async def checkmarx_list_scans(
    project_id: str = "",
    status: str = "",
    branch: str = "",
    limit: int = 20,
    offset: int = 0,
    from_date: str = "",
    sort: str = "-created_at",
) -> str:
    """
    List scans in your Checkmarx One account with optional filters.

    status filter options: Queued, Running, Completed, Failed, Partial, Canceled
    sort options: -created_at (newest first, default), +created_at, -status, +status, -branch, +branch
    from_date: ISO-8601 datetime e.g. 2024-01-01T00:00:00Z
    """
    try:
        params: Dict[str, Any] = {"limit": limit, "offset": offset, "sort": sort}
        if project_id:
            params["project-id"] = project_id
        if status:
            params["statuses"] = status
        if branch:
            params["branch"] = branch
        if from_date:
            params["from-date"] = from_date

        data  = await _get("/api/scans", params)
        scans = data.get("scans", [])
        items = []
        for s in scans:
            items.append({
                "id":           s.get("id", ""),
                "status":       s.get("status", ""),
                "project_id":   s.get("projectId", ""),
                "project_name": s.get("projectName", ""),
                "branch":       s.get("branch", ""),
                "created_at":   s.get("createdAt", ""),
                "initiator":    s.get("initiator", ""),
                "engines":      s.get("engines", []),
                "source_type":  s.get("sourceType", ""),
                "tags":         s.get("tags", {}),
            })

        return json.dumps({
            "total":            data.get("totalCount", len(items)),
            "filtered_total":   data.get("filteredTotalCount", len(items)),
            "count":            len(items),
            "scans":            items,
        }, indent=2)
    except Exception as e:
        return _err(e)


@mcp.tool(name="checkmarx_get_scan_workflow")
async def checkmarx_get_scan_workflow(scan_id: str) -> str:
    """
    Get the detailed step-by-step workflow/task log for a specific scan.
    Useful for diagnosing why a scan failed or understanding what steps ran.
    Returns a list of timestamped task events from each service involved in the scan.
    """
    try:
        data = await _get(f"/api/scans/{scan_id}/workflow")
        tasks = data if isinstance(data, list) else []
        return json.dumps({
            "scan_id": scan_id,
            "task_count": len(tasks),
            "workflow": [
                {
                    "source":    t.get("source", ""),
                    "timestamp": t.get("timestamp", ""),
                    "info":      t.get("info", ""),
                }
                for t in tasks
            ],
        }, indent=2)
    except Exception as e:
        return _err(e)


@mcp.tool(name="checkmarx_cancel_scan")
async def checkmarx_cancel_scan(scan_id: str) -> str:
    """
    Cancel a scan that is currently Queued or Running.
    The scan status will be set to Canceled.
    Cannot cancel scans that have already Completed, Failed, or been Canceled.
    """
    try:
        await _cx_patch(f"/api/scans/{scan_id}", {"status": "Canceled"})
        return json.dumps({
            "status": "success",
            "message": f"Scan {scan_id} cancellation requested.",
        }, indent=2)
    except Exception as e:
        return _err(e)


@mcp.tool(name="checkmarx_delete_scan")
async def checkmarx_delete_scan(scan_id: str) -> str:
    """
    Permanently delete a scan and its results.
    Warning: this action is irreversible. Results will no longer be accessible.
    """
    try:
        await _cx_delete(f"/api/scans/{scan_id}")
        return json.dumps({
            "status": "success",
            "message": f"Scan {scan_id} deleted permanently.",
        }, indent=2)
    except Exception as e:
        return _err(e)


@mcp.tool(name="checkmarx_get_scan_status_summary")
async def checkmarx_get_scan_status_summary() -> str:
    """
    Get a summary count of scans in your account grouped by status.
    Returns how many scans are in each state: Queued, Running, Completed, Failed, Partial, Canceled.
    Useful for a quick health check of your tenant's scan activity.
    """
    try:
        data = await _get("/api/scans/summary")
        return json.dumps({
            "status": "success",
            "summary": data.get("Status", data),
        }, indent=2)
    except Exception as e:
        return _err(e)


@mcp.tool(name="checkmarx_get_scan_tags")
async def checkmarx_get_scan_tags() -> str:
    """
    Get all scan tags used across your Checkmarx One tenant.
    Returns a list of all key:value tag pairs ever assigned to scans.
    Useful for discovering what tags exist before filtering scans by tag.
    """
    try:
        data = await _get("/api/scans/tags")
        return json.dumps({"status": "success", "tags": data}, indent=2)
    except Exception as e:
        return _err(e)


@mcp.tool(name="checkmarx_update_scan_tags")
async def checkmarx_update_scan_tags(
    scan_id: str,
    tags: str,
) -> str:
    """
    Update the tags on a completed scan. Replaces all existing tags.
    tags: comma-separated key:value pairs e.g. "env:prod,team:backend,reviewed:"
    Note: this replaces ALL existing tags — include any tags you want to keep.
    Can only be used after the scan has completed.
    """
    try:
        tags_dict: Dict[str, str] = {}
        for tag in tags.split(","):
            tag = tag.strip()
            if ":" in tag:
                k, v = tag.split(":", 1)
                tags_dict[k.strip()] = v.strip()
            elif tag:
                tags_dict[tag] = ""

        await _cx_put(f"/api/scans/{scan_id}/tags", {"tags": tags_dict})
        return json.dumps({
            "status": "success",
            "scan_id": scan_id,
            "tags_applied": tags_dict,
        }, indent=2)
    except Exception as e:
        return _err(e)


@mcp.tool(name="checkmarx_run_scan_recalculation")
async def checkmarx_run_scan_recalculation(
    project_id: str,
    branch: str,
) -> str:
    """
    Trigger an SCA scan recalculation for a project branch.
    Recalculation reassesses previous scan results using current vulnerability data
    without resubmitting source code — useful when new CVEs are published or
    when risk states/policies have changed.
    Currently only supported for the SCA scanner.
    """
    try:
        body = {
            "project_id": project_id,
            "branch": branch,
            "engines": ["sca"],
        }
        data = await _cx_post_scan("/api/scans/recalculate", body)
        return json.dumps({
            "status": "success",
            "recalculation_scan_id": data.get("id", ""),
            "scan_status": data.get("status", ""),
            "project_id": project_id,
            "branch": branch,
            "message": "Recalculation started. Use checkmarx_get_scan_details to track progress.",
        }, indent=2)
    except Exception as e:
        return _err(e)


@mcp.tool(name="checkmarx_poll_scan_until_complete")
async def checkmarx_poll_scan_until_complete(
    scan_id: str,
    timeout_minutes: int = 30,
) -> str:
    """
    Poll a scan repeatedly until it reaches a terminal state (Completed, Failed, Partial, Canceled).
    Waits up to timeout_minutes (default 30) before giving up.
    Use this after checkmarx_run_scan to wait for results before fetching findings.
    """
    try:
        terminal = {"Completed", "Failed", "Partial", "Canceled"}
        deadline = time.time() + timeout_minutes * 60
        interval = 15

        while time.time() < deadline:
            data   = await _get(f"/api/scans/{scan_id}")
            status = data.get("status", "")

            if status in terminal:
                return json.dumps({
                    "status": "done",
                    "scan_status": status,
                    "scan_id": scan_id,
                    "project_id": data.get("projectId", ""),
                    "branch": data.get("branch", ""),
                    "updated_at": data.get("updatedAt", ""),
                    "status_details": data.get("statusDetails", []),
                    "message": f"Scan {status}. Use checkmarx_get_results with scan_id to fetch findings." if status == "Completed" else f"Scan ended with status: {status}",
                }, indent=2)

            await asyncio.sleep(interval)

        return json.dumps({
            "status": "timeout",
            "scan_id": scan_id,
            "message": f"Scan did not complete within {timeout_minutes} minutes. Call checkmarx_get_scan_details to check manually.",
        })
    except Exception as e:
        return _err(e)


if __name__ == "__main__":
    mcp.run(transport="stdio")