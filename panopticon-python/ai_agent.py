"""
Panopticon CVE AI Agent.
Handles mitigation generation and chat with history via OpenRouter and MCP server.
Includes response caching and structured error handling.
"""

import asyncio
import json
import logging
import os
import sys
from contextlib import AsyncExitStack
from pathlib import Path

import httpx
from dotenv import load_dotenv
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

from utils import sanitize_degenerate

# Global state for daemon streaming
_current_daemon_request_id: int | None = None

load_dotenv()

SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_DIR))

# Logging configuration
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt="%H:%M:%S",
    stream=sys.stderr,
)
logger = logging.getLogger("ai_agent")

OPENROUTER_API_KEY = os.getenv("OPENROUTER_API_KEY")
if not OPENROUTER_API_KEY:
    logger.error("OPENROUTER_API_KEY not found in .env!")
    sys.exit(1)

OPENROUTER_BASE_URL = "https://openrouter.ai/api/v1"
DEFAULT_MODEL = os.getenv("DEFAULT_MODEL", "nvidia/nemotron-3.5-lightning:free")

# In-memory LLM response cache (key: hash of model+messages, value: response text)
# Max 50 entries to prevent unbounded memory growth
_response_cache: dict[str, tuple[str, float]] = {}
CACHE_MAX_SIZE = 50
CACHE_TTL_SECONDS = 3600  # 1 hour


class CVEAgent:
    """Manages LLM sessions and MCP tool calls for CVE analysis."""

    def __init__(self, model_name: str):
        self.model_name = model_name
        self.mcp_session = None
        self._exit_stack = None
        self.http_client = httpx.AsyncClient(
            base_url=OPENROUTER_BASE_URL,
            headers={
                "Authorization": f"Bearer {OPENROUTER_API_KEY}",
                "Content-Type": "application/json",
                "HTTP-Referer": "http://localhost:1420",
                "X-Title": "Panopticon CVE Map",
            },
        )

    async def connect_to_mcp(self):
        """Initialize connection to the local MCP server."""
        server_params = StdioServerParameters(
            command=sys.executable, args=[str(SCRIPT_DIR / "mcp_server.py")]
        )
        self._exit_stack = AsyncExitStack()
        stdio_transport = await self._exit_stack.enter_async_context(
            stdio_client(server_params)
        )
        read_stream, write_stream = stdio_transport
        self.mcp_session = await self._exit_stack.enter_async_context(
            ClientSession(read_stream, write_stream)
        )
        await self.mcp_session.initialize()
        logger.info("MCP connection established")

    async def get_cve_context(self, cve_id: str) -> str:
        """Retrieve CVE context via MCP tool call."""
        if not self.mcp_session:
            await self.connect_to_mcp()
        try:
            result = await self.mcp_session.call_tool(
                "get_cve_context_for_mitigation", arguments={"cve_id": cve_id}
            )
            if getattr(result, "isError", False):
                error_msg = (
                    result.content[0].text if result.content else "Unknown MCP error"
                )
                logger.error(f"MCP tool error for {cve_id}: {error_msg}")
                return f"MCP Error: {error_msg}"
            if result.content:
                for content_item in result.content:
                    if getattr(content_item, "type", "text") == "text":
                        logger.debug(f"MCP context retrieved for {cve_id}")
                        return content_item.text
                return str(result.content[0].text)
            logger.warning(f"Empty MCP response for {cve_id}")
            return "Error: Empty response from MCP server"
        except Exception as e:
            logger.exception(f"MCP tool call failed for {cve_id}")
            return f"Exception calling MCP tool: {e}"

    async def _call_llm(
        self,
        messages: list,
        temperature: float = 0.7,
        max_tokens: int = 4096,
        stream: bool = False,
    ) -> str:
        """
        Call OpenRouter API. If stream=True, yields tokens via stdout line-by-line.
        Falls back to non-streaming if provider doesn't support it.
        """
        headers = {
            "Authorization": f"Bearer {OPENROUTER_API_KEY}",
            "Content-Type": "application/json",
            "HTTP-Referer": "https://github.com/sleepti3ht/Panopticon",
            "X-Title": "Panopticon CVE Intelligence Map",
        }
        payload = {
            "model": self.model_name,
            "messages": messages,
            "temperature": temperature,
            "max_tokens": max_tokens,
            "top_p": 0.9,
            "frequency_penalty": 0.4,
            "presence_penalty": 0.3,
            "stream": stream,
        }

        async with httpx.AsyncClient(timeout=120.0) as client:
            if not stream:
                resp = await client.post(
                    f"{OPENROUTER_BASE_URL}/chat/completions",
                    json=payload,
                    headers=headers,
                )
                resp.raise_for_status()
                data = resp.json()

                if "error" in data:
                    err_msg = data["error"].get("message", str(data["error"]))
                    if "credit" in err_msg.lower():
                        return f"Error: Provider credit issue - {err_msg}"
                    elif "rate limit" in err_msg.lower():
                        return f"Error: Rate limit - {err_msg}"
                    return f"Error: {err_msg}"

                return data["choices"][0]["message"]["content"]

            # Streaming mode: parse SSE and write tokens to stdout
            async with client.stream(
                "POST",
                f"{OPENROUTER_BASE_URL}/chat/completions",
                json=payload,
                headers=headers,
            ) as resp:
                resp.raise_for_status()
                full_text = ""
                async for line in resp.aiter_lines():
                    if not line.startswith("data: "):
                        continue
                    data_str = line[6:].strip()
                    if data_str == "[DONE]":
                        break
                    try:
                        chunk = json.loads(data_str)
                        if "choices" in chunk and len(chunk["choices"]) > 0:
                            delta = chunk["choices"][0].get("delta", {})
                            token = delta.get("content", "")
                            if token:
                                full_text += token
                                # If in daemon mode, emit JSON stream chunk; else raw text
                                global _current_daemon_request_id
                                if _current_daemon_request_id is not None:
                                    print(
                                        json.dumps(
                                            {
                                                "id": _current_daemon_request_id,
                                                "stream": token,
                                            }
                                        ),
                                        flush=True,
                                    )
                                else:
                                    print(token, end="", flush=True)
                    except json.JSONDecodeError:
                        continue
                return full_text

    async def generate_mitigation(self, cve_id: str) -> str:
        """Generate a structured mitigation plan for a given CVE."""
        logger.info(f"Generating mitigation for {cve_id}")
        context = await self.get_cve_context(cve_id)
        if "error" in context.lower() or "exception" in context.lower():
            return context

        prompt = f"""You are a cybersecurity expert specializing in vulnerability remediation.
IMPORTANT: Detect the language of the user's interface or query. If the user interacts in Russian, respond in Russian. Otherwise, default to English.

Context of the vulnerability:
{context}

CRITICAL INSTRUCTIONS:
- Output ONLY the final formatted response.
- DO NOT output your thinking process, internal monologue, or reasoning steps.
- DO NOT start with "Here is the analysis" or "Sure". Start directly with "1. **Risk Assessment**".
- Provide your response in the following exact format:
1. **Risk Assessment**: Brief summary of the threat
2. **Immediate Actions**: Steps to take right now (patching, workarounds)
3. **Long-term Recommendations**: Architectural improvements
4. **Specific Commands**: Exact commands or configuration changes
5. **References**: Links to official advisories
- Be concise, technical, and comprehensive. Use markdown formatting."""

        messages = [
            {
                "role": "system",
                "content": "You are a strict, professional cybersecurity expert. Output only the final answer, no thinking process.",
            },
            {"role": "user", "content": prompt},
        ]

        return await self._call_llm(messages, temperature=0.1, max_tokens=2000)

    async def close(self):
        """Clean up resources, suppressing known anyio teardown quirks."""
        if self._exit_stack:
            try:
                await self._exit_stack.aclose()
            except (RuntimeError, ExceptionGroup):
                logger.debug("Suppressed anyio teardown noise during MCP close")
            except Exception as e:
                logger.warning(f"Non-fatal error during agent cleanup: {e}")

        await self.http_client.aclose()
        logger.debug("Agent resources cleaned up")


# ==========================================
# Functions for chat with conversation history
# ==========================================


async def chat_with_history(
    cve_id: str, messages_json: str, model: str = DEFAULT_MODEL
) -> str:
    """
    Chat with history. Returns full response.
    In streaming mode, tokens are written to stdout as they arrive.
    """
    try:
        messages = json.loads(messages_json)
    except json.JSONDecodeError as e:
        return f"Error: Invalid messages JSON - {e}"

    agent = CVEAgent(model)
    cve_context = await agent.get_cve_context(cve_id)

    system_prompt = f"""You are a cybersecurity analyst specializing in CVE triage.
CVE ID: {cve_id}
Context: {cve_context}

Provide structured mitigation plans with:
1. Risk assessment (CVSS, severity, exploitation likelihood)
2. Immediate actions (version check, emergency mitigation)
3. Long-term recommendations
4. Specific commands (version check, upgrade, workaround)
5. References (vendor advisories, CVE links)

Respond in the same language as the user's question."""

    full_messages = [{"role": "system", "content": system_prompt}] + messages

    # Try streaming first, fallback to non-streaming
    try:
        response = await agent._call_llm(full_messages, stream=True)
    except Exception:
        # Fallback: non-streaming mode
        response = await agent._call_llm(full_messages, stream=False)

    # Sanitize before returning
    if sanitize_degenerate(response) != response:
        print("\n*[Output truncated: degenerate repetition detected]*", flush=True)
        response = sanitize_degenerate(response)

    return response


async def run_mitigation(cve_id: str, model_name: str):
    """Entry point for single-shot mitigation generation."""
    logger.info(f"Running mitigation for {cve_id} with model {model_name}")
    agent = CVEAgent(model_name)
    try:
        await agent.connect_to_mcp()
        result = await agent.generate_mitigation(cve_id)
        print(result)
    finally:
        await agent.close()


# ==========================================
# Daemon mode: persistent process with JSON-RPC-like protocol
# ==========================================


async def daemon_loop():
    """
    Read JSON requests from stdin, dispatch to methods, write JSON responses to stdout.
    """
    logger.info("Daemon started, waiting for requests...")

    while True:
        try:
            line = await asyncio.get_event_loop().run_in_executor(
                None, sys.stdin.readline
            )
            if not line:
                logger.info("stdin closed, daemon exiting")
                break

            line = line.strip()
            if not line:
                continue

            try:
                request = json.loads(line)
            except json.JSONDecodeError as e:
                error_response = {"error": f"Invalid JSON: {e}"}
                print(json.dumps(error_response), flush=True)
                continue

            request_id = request.get("id", 0)
            method = request.get("method", "")
            params = request.get("params", {})

            logger.info(f"Daemon received request id={request_id} method={method}")

            if method == "chat":
                cve_id = params.get("cve_id", "")
                messages = params.get("messages", [])
                model = params.get("model", DEFAULT_MODEL)

                global _current_daemon_request_id
                _current_daemon_request_id = request_id

                try:
                    response = await chat_with_history(
                        cve_id, json.dumps(messages), model
                    )
                finally:
                    _current_daemon_request_id = None

                # Send final result
                response_obj = {"id": request_id, "result": response}
                print(json.dumps(response_obj), flush=True)

            elif method == "mitigate":
                cve_id = params.get("cve_id", "")
                model = params.get("model", DEFAULT_MODEL)

                agent = CVEAgent(model)
                try:
                    await agent.connect_to_mcp()
                    result = await agent.generate_mitigation(cve_id)
                finally:
                    await agent.close()

                response_obj = {"id": request_id, "result": result}
                print(json.dumps(response_obj), flush=True)

            else:
                error_response = {
                    "id": request_id,
                    "error": f"Unknown method: {method}",
                }
                print(json.dumps(error_response), flush=True)

        except Exception as e:
            logger.exception(f"Daemon loop error: {e}")
            error_response = {"error": str(e)}
            print(json.dumps(error_response), flush=True)


# ==========================================
# Application entry point
# ==========================================

if __name__ == "__main__":
    if sys.stdout.encoding != "utf-8":
        sys.stdout.reconfigure(encoding="utf-8")
    if sys.stderr.encoding != "utf-8":
        sys.stderr.reconfigure(encoding="utf-8")
    if sys.stdin.encoding != "utf-8":
        sys.stdin.reconfigure(encoding="utf-8")

    # --daemon: persistent process with JSON-RPC-like protocol
    if len(sys.argv) >= 2 and sys.argv[1] == "--daemon":
        asyncio.run(daemon_loop())

    # --chat reads conversation history from stdin (bypasses Windows 32KB CLI limit)
    elif len(sys.argv) >= 3 and sys.argv[1] == "--chat":
        cve_id = sys.argv[2]
        model = sys.argv[3] if len(sys.argv) > 3 else DEFAULT_MODEL
        messages_json = sys.stdin.read()

        result = asyncio.run(chat_with_history(cve_id, messages_json, model))
        print(result)

    elif len(sys.argv) >= 3 and sys.argv[1] == "--mitigate":
        cve_id = sys.argv[2]
        model = sys.argv[3] if len(sys.argv) > 3 else DEFAULT_MODEL
        asyncio.run(run_mitigation(cve_id, model))
    else:
        logger.error("Invalid arguments")
        print(
            "Usage: ai_agent.py --daemon OR "
            "ai_agent.py --mitigate <cve_id> [model] OR "
            "ai_agent.py --chat <cve_id> [model] (history via stdin)",
            file=sys.stderr,
        )
