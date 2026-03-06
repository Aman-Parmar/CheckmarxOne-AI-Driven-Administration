"""
Checkmarx One — Streamlit Web Chat
Run:
    streamlit run streamlit_app.py
"""

import asyncio
import sys
from pathlib import Path

import streamlit as st
from langchain_ollama import ChatOllama
from langchain_mcp_adapters.client import MultiServerMCPClient
from langgraph.prebuilt import create_react_agent
from langchain_core.messages import HumanMessage

# ── Config ───────────────────────────────────────────────────────────────────

MCP_SERVER_PATH = str(Path(__file__).parent / "mcp_server.py")

SYSTEM_PROMPT = """You are a security analytics assistant for Checkmarx One.
Help engineering leaders understand their application security posture with
clear, business-friendly insights. Use tools to fetch live data. Be concise."""

MODELS = [
    "qwen3:8b",
    "qwen3-vl:latest",
    "qwen2.5:14b-instruct",
    "llama3.1:8b-instruct",
    "llama3.2:3b-instruct",
]

# ── Page Setup ───────────────────────────────────────────────────────────────

st.set_page_config(
    page_title="Checkmarx Security Analytics",
    page_icon="🔐",
    layout="wide",
)

st.title("🔐 Checkmarx One Security Analytics")
st.caption("Powered by Ollama + LangChain MCP — Running 100% locally")

# ── Sidebar ──────────────────────────────────────────────────────────────────

with st.sidebar:
    st.header("⚙️ Configuration")
    model = st.selectbox("Ollama Model", MODELS, index=0)
    ollama_url = st.text_input("Ollama URL", value="http://localhost:11434")

    st.divider()
    st.markdown("**Quick Queries**")
    quick_queries = [
        "List all projects",
        "Generate report for all projects",
        "Which project is riskiest?",
        "Show fix rate trends",
        "Compliance summary",
    ]
    for q in quick_queries:
        if st.button(q, use_container_width=True):
            st.session_state.pending_query = q

    st.divider()
    if st.button("🗑️ Clear Chat", use_container_width=True):
        st.session_state.messages = []
        st.rerun()

    st.divider()
    st.markdown("""
    **Metrics Reference**
    - 🔴 **Risk Score** = High×10 + Med×5 + Low×1
    - ✅ **Fix Rate** = Fixed / Total × 100%
    - 📅 **MTTR Proxy** = Days since oldest open High
    """)

# ── Chat State ───────────────────────────────────────────────────────────────

if "messages" not in st.session_state:
    st.session_state.messages = []

# Display existing messages
for msg in st.session_state.messages:
    with st.chat_message(msg["role"]):
        st.markdown(msg["content"])

# ── Agent Runner ─────────────────────────────────────────────────────────────

async def run_agent(user_input: str, model_name: str, base_url: str) -> str:
    llm = ChatOllama(
        model=model_name,
        base_url=base_url,
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
        return f"❌ Failed to connect to MCP server: {e}\n\nMake sure mcp_server.py deps are installed:\n`pip install mcp httpx pydantic python-dotenv`"

    if not tools:
        return "❌ No tools loaded from MCP server. Check your .env file."

    agent  = create_react_agent(llm, tools)
    result = await agent.ainvoke({
        "messages": [HumanMessage(content=SYSTEM_PROMPT + "\n\nUser: " + user_input)]
    })

    last = result["messages"][-1]
    return last.content if hasattr(last, "content") else str(last)


def ask(user_input: str) -> str:
    try:
        # Python 3.14 compatible asyncio run
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            return loop.run_until_complete(run_agent(user_input, model, ollama_url))
        finally:
            loop.close()
    except Exception as e:
        return f"❌ Error: {e}"


# ── Handle Input ─────────────────────────────────────────────────────────────

# Check for quick query button press
user_input = st.chat_input("Ask about your security findings...")
if "pending_query" in st.session_state:
    user_input = st.session_state.pop("pending_query")

if user_input:
    # Show user message
    st.session_state.messages.append({"role": "user", "content": user_input})
    with st.chat_message("user"):
        st.markdown(user_input)

    # Get and show assistant response
    with st.chat_message("assistant"):
        with st.spinner("Thinking and calling tools..."):
            response = ask(user_input)
        st.markdown(response)

    st.session_state.messages.append({"role": "assistant", "content": response})