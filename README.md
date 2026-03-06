# Checkmarx One AI Security Agent

A fully local, private AI agent for querying and managing your Checkmarx One security data. Built with [Ollama](https://ollama.com), [LangChain](https://langchain.com), and [MCP (Model Context Protocol)](https://modelcontextprotocol.io). No data leaves your machine.

![Python](https://img.shields.io/badge/Python-3.10%2B-blue) ![Ollama](https://img.shields.io/badge/Ollama-Local%20LLM-orange) ![MCP](https://img.shields.io/badge/MCP-FastMCP-green) ![Streamlit](https://img.shields.io/badge/UI-Streamlit-red)

---

## What it does

Ask natural language questions about your Checkmarx One security posture and get answers backed by live API data:

> *"Which project has the most high-severity open findings?"*  
> *"Run a SAST and SCA scan on the main branch of my repo"*  
> *"Mark CVE-2021-44906 in minimist as Not Exploitable — it's not called in production"*  
> *"Generate a CycloneDX SBOM for the latest scan of project X"*  
> *"Give me a compliance summary with risk flags"*

---

## Architecture

```
┌─────────────────────────────────────────────┐
│              Your MacBook                    │
│                                             │
│  ┌──────────┐    ┌───────────────────────┐  │
│  │ Streamlit│───▶│   LangChain Agent     │  │
│  │  Web UI  │    │  (ReAct + Tool calls) │  │
│  └──────────┘    └──────────┬────────────┘  │
│                             │               │
│                    ┌────────▼────────┐       │
│                    │  Ollama (LLM)   │       │
│                    │  qwen3:8b local │       │
│                    └────────┬────────┘       │
│                             │               │
│                    ┌────────▼────────┐       │
│                    │  MCP Server     │       │
│                    │  mcp_server.py  │       │
│                    └────────┬────────┘       │
│                             │               │
└─────────────────────────────┼───────────────┘
                              │ HTTPS
                    ┌─────────▼─────────┐
                    │  Checkmarx One    │
                    │  us.ast.checkmarx │
                    └───────────────────┘
```

- **Streamlit** — browser-based chat UI at `localhost:8501`
- **LangChain ReAct Agent** — decides which tools to call based on your question
- **Ollama** — runs the LLM locally (no data sent to OpenAI or Anthropic)
- **MCP Server** — exposes 27 Checkmarx One API tools via stdio transport
- **Checkmarx One APIs** — live data from your tenant

---

## Tools (27 total)

### Core Analytics
| Tool | Description |
|---|---|
| `checkmarx_list_projects` | List all projects in your tenant |
| `checkmarx_get_results` | Fetch security findings with filters |
| `checkmarx_compute_metrics` | Risk score, fix rate, severity breakdown |
| `checkmarx_compare_projects` | Rank projects by risk |
| `checkmarx_compliance_summary` | Executive risk report with flags |
| `checkmarx_get_historical_trends` | Track risk score over time |
| `checkmarx_get_analytics_kpi` | Analytics module KPI data |

### Scan Management
| Tool | Description |
|---|---|
| `checkmarx_run_scan` | Trigger a new scan (Git or upload) |
| `checkmarx_list_scans` | List scans with filters |
| `checkmarx_get_scan_details` | Status and details for a scan |
| `checkmarx_get_scan_workflow` | Step-by-step task log |
| `checkmarx_poll_scan_until_complete` | Wait for scan to finish |
| `checkmarx_cancel_scan` | Cancel a running scan |
| `checkmarx_delete_scan` | Delete a scan permanently |
| `checkmarx_get_scan_status_summary` | Count of scans by status |
| `checkmarx_get_scan_tags` | All scan tags in your tenant |
| `checkmarx_update_scan_tags` | Replace tags on a scan |
| `checkmarx_run_scan_recalculation` | Re-evaluate SCA without re-scanning |

### SCA Export
| Tool | Description |
|---|---|
| `checkmarx_sca_create_export` | Create SBOM or scan report export |
| `checkmarx_sca_poll_export` | Wait for export and get download URL |
| `checkmarx_sca_download_export` | Fetch export content |

### SCA Risk Management
| Tool | Description |
|---|---|
| `checkmarx_sca_triage_vulnerability` | Change state or score for a CVE |
| `checkmarx_sca_triage_vulnerabilities_bulk` | Triage multiple CVEs at once |
| `checkmarx_sca_mute_package` | Mute or snooze a package |
| `checkmarx_sca_mute_packages_bulk` | Mute/snooze multiple packages |
| `checkmarx_sca_triage_supply_chain_risk` | Triage suspected malicious packages |

---

## Prerequisites

- macOS (Apple Silicon recommended)
- Python 3.10+
- [Ollama](https://ollama.com) app installed

---

## Setup

### 1. Clone the repo

```bash
git clone https://github.com/your-username/cxone-ai-agent.git
cd cxone-ai-agent/files
```

### 2. Install Ollama and pull a model

Open the Ollama app, then in terminal:

```bash
ollama pull qwen3:8b
```

Recommended models for Apple Silicon:

| Model | RAM | Tool Calling | Speed |
|---|---|---|---|
| `qwen3:8b` ✅ | ~6 GB | Excellent | Fast |
| `qwen3:14b` | ~11 GB | Excellent | Medium |
| `llama3.1:8b` | ~5 GB | Very Good | Fast |

### 3. Configure credentials

```bash
cp .env.example .env
```

Edit `.env`:

```env
CX_BASE_URL=https://us.ast.checkmarx.net
CX_IAM_URL=https://us.iam.checkmarx.net
CX_TENANT=your-tenant-name
CX_CLIENT_ID=ast-app
CX_API_KEY=your-api-key-here
```

> Your API Key acts as a refresh token — the agent exchanges it automatically for short-lived access tokens. See the [Checkmarx One Authentication API guide](https://checkmarx.stoplight.io/docs/checkmarx-one-api-reference-guide/branches/main/yjaxkqnhqmdrl-authentication-api) for how to generate one.

### 4. Create a Python virtual environment and install dependencies

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install mcp httpx pydantic python-dotenv \
            langchain langchain-ollama langchain-mcp-adapters \
            langgraph langchain-core streamlit watchdog
```

### 5. Run

```bash
streamlit run streamlit_app.py
```

Opens at **http://localhost:8501**

Or use the terminal agent:

```bash
python agent.py --model qwen3:8b
```

---

## Every session

```bash
# Make sure Ollama app is running, then:
cd files
source .venv/bin/activate
streamlit run streamlit_app.py
```

---

## Example queries

```
List all my Checkmarx projects
Show me the riskiest projects
Run a SAST and SCA scan on project <id> from https://github.com/myorg/myrepo
What is the status of scan <scan-id>?
Generate a CycloneDX SBOM for scan <scan-id>
Mark CVE-2021-44906 in minimist@0.0.10 as NotExploitable in project <id>
Mute the lodash@4.17.15 package in project <id> — it's an internal tool
Give me a compliance summary
What is our fix rate trend over the last 5 snapshots?
```

---

## Project structure

```
files/
├── mcp_server.py        # MCP server — 27 Checkmarx One API tools
├── streamlit_app.py     # Browser UI
├── agent.py             # Terminal chat agent
├── .env.example         # Credentials template
├── .env                 # Your credentials (git-ignored)
└── report_history.json  # Auto-generated trend history
```

---

## Security & Privacy

- **100% local** — the LLM runs on your machine via Ollama
- **No telemetry** — no data is sent to OpenAI, Anthropic, or any third party
- **Credentials** — stored in `.env` only, never logged or transmitted
- **API calls** — go directly from your machine to `us.ast.checkmarx.net`

---

## Troubleshooting

| Problem | Fix |
|---|---|
| `model not found` | `ollama pull qwen3:8b` |
| `connection refused` | Open the Ollama app |
| `Error 401` | Regenerate API Key in CX One portal (keys expire on license updates) |
| `Error 403` | Your account may lack required permissions |
| `No tools loaded` | Check MCP deps: `pip install mcp httpx pydantic python-dotenv` |
| Slow responses | Try `llama3.1:8b` — faster on Apple Silicon |

---

## Acknowledgements

- [Checkmarx One API](https://checkmarx.stoplight.io/docs/checkmarx-one-api-reference-guide)
- [Model Context Protocol](https://modelcontextprotocol.io)
- [LangChain](https://langchain.com)
- [Ollama](https://ollama.com)
- [FastMCP](https://github.com/jlowin/fastmcp)
