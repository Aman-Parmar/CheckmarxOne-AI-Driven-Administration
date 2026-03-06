"""
Checkmarx One LangChain Agent
Interactive terminal chat connecting to the Checkmarx MCP server.

Usage:
    python agent.py
    python agent.py --model qwen3:8b
"""

import asyncio
import argparse
import sys
from pathlib import Path

from langchain_ollama import ChatOllama
from langchain_mcp_adapters.client import MultiServerMCPClient
from langgraph.prebuilt import create_react_agent
from langchain_core.messages import HumanMessage, AIMessage

# ─── Configuration ────────────────────────────────────────────────────────────

DEFAULT_MODEL   = "qwen3:8b"
OLLAMA_BASE_URL = "http://localhost:11434"

# All files are flat in the same folder as this script
MCP_SERVER_PATH = str(Path(__file__).parent / "mcp_server.py")

SYSTEM_PROMPT = """You are a security analytics assistant for Checkmarx One.
Your job is to help engineering leaders understand their application security posture.

You have access to tools that can:
- List Checkmarx projects
- Generate and retrieve security reports
- Compute leadership metrics (severity distributions, fix rates, risk scores)
- Analyse trends over time
- Compare projects by risk
- Generate compliance summaries

When answering questions:
1. Always fetch fresh data using the tools unless the user has already provided report JSON
2. Explain metrics clearly in business language
3. Proactively flag critical issues (high severity, low fix rates, aging findings)
4. Suggest follow-up actions when risks are identified
5. Format numbers clearly; use tables and bullet points for readability

Available metrics you can compute from reports:
- Severity distribution: High / Medium / Low / Info counts
- Fix rate: % of findings that have been resolved
- Risk score: High x 10 + Medium x 5 + Low x 1
- Open high age: days since oldest unresolved High finding (MTTR proxy)
- Per-project breakdowns for benchmarking

Always be concise but thorough. Leadership wants actionable insights, not raw data dumps.
"""


# ─── Chat Loop ────────────────────────────────────────────────────────────────

async def chat_loop(model: str):
    print("\n" + "=" * 60)
    print("  Checkmarx One Security Analytics Agent")
    print(f"  Model: {model} via Ollama")
    print("  Type 'quit' or Ctrl+C to exit")
    print("=" * 60 + "\n")

    print("Building agent and connecting to MCP server...")

    llm = ChatOllama(
        model=model,
        base_url=OLLAMA_BASE_URL,
        temperature=0.1,
        num_predict=4096,
    )

    mcp_client = MultiServerMCPClient(
        {
            "checkmarx": {
                "command": "python3",
                "args": [MCP_SERVER_PATH],
                "transport": "stdio",
            }
        }
    )

    try:
        tools = await mcp_client.get_tools()
    except Exception as e:
        print(f"\n Failed to load MCP tools: {e}")
        print("\nTroubleshooting:")
        print("  1. Is Ollama running?        ->  open the Ollama app or run: ollama serve")
        print(f"  2. Is model pulled?          ->  ollama pull {model}")
        print(f"  3. Does mcp_server.py exist? ->  looking at: {MCP_SERVER_PATH}")
        print("  4. Are MCP deps installed?   ->  pip install mcp httpx pydantic python-dotenv")
        sys.exit(1)

    if not tools:
        print("Warning: No tools loaded - check mcp_server.py and your .env file.")
        sys.exit(1)

    print(f"Loaded {len(tools)} MCP tools: {[t.name for t in tools]}")

    agent = create_react_agent(llm, tools)

    print("Agent ready. Ask me anything about your Checkmarx findings!\n")
    print("Example queries:")
    examples = [
        "List all my Checkmarx projects",
        "Generate a report for all projects and show me the fix rate",
        "Which project has the most high-severity open findings?",
        "Give me a compliance summary",
        "What is the risk score trend over the last 5 snapshots?",
    ]
    for q in examples:
        print(f"  - {q}")
    print()

    conversation_history = []

    while True:
        try:
            user_input = input("You: ").strip()
        except (EOFError, KeyboardInterrupt):
            print("\n\nGoodbye!")
            break

        if not user_input:
            continue
        if user_input.lower() in ("quit", "exit", "q"):
            print("Goodbye!")
            break

        print("\nAssistant: ", end="", flush=True)
        try:
            messages = [HumanMessage(content=SYSTEM_PROMPT + "\n\nUser question: " + user_input)]
            messages += conversation_history[-10:]

            result   = await agent.ainvoke({"messages": messages})
            last_msg = result["messages"][-1]
            answer   = last_msg.content if hasattr(last_msg, "content") else str(last_msg)

            print(answer)
            conversation_history.append(HumanMessage(content=user_input))
            conversation_history.append(AIMessage(content=answer))

        except Exception as e:
            err = str(e)
            print(f"\nError: {err}")
            if "connection refused" in err.lower():
                print("  -> Is Ollama running? Open the Ollama app.")
            elif "not found" in err.lower() or "model" in err.lower():
                print(f"  -> Try: ollama pull {model}")

        print()


# ─── Main ─────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="Checkmarx One Agent")
    parser.add_argument("--model", "-m", default=DEFAULT_MODEL,
                        help=f"Ollama model name (default: {DEFAULT_MODEL})")
    args = parser.parse_args()
    asyncio.run(chat_loop(args.model))


if __name__ == "__main__":
    main()