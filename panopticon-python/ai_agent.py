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
from pathlib import Path
from contextlib import AsyncExitStack
from dotenv import load_dotenv
import httpx
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client
from utils import sanitize_degenerate

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

    async def _call_llm(self, messages: list[dict], temperature: float, max_tokens: int) -> str:
        """
        Internal LLM call with caching and error categorization.
        Returns response text or error message.
        """
        # Generate cache key from model + messages hash
        cache_key = f"{self.model_name}:{hash(json.dumps(messages, sort_keys=True))}"
        
        # Check cache (with TTL)
        if cache_key in _response_cache:
            cached_text, cached_time = _response_cache[cache_key]
            import time
            if time.time() - cached_time < CACHE_TTL_SECONDS:
                logger.info(f"Cache hit for {self.model_name}")
                return cached_text
            else:
                # Expired entry
                del _response_cache[cache_key]

        logger.info(f"Calling LLM: model={self.model_name}, messages={len(messages)}")

        try:
            response = await self.http_client.post(
                "/chat/completions",
                json={
                    "model": self.model_name,
                    "messages": messages,
                    "temperature": temperature,
                    "max_tokens": max_tokens,
                    "top_p": 0.9,
                    # Sampling penalties reduce repetition collapse on free-tier models
                    "frequency_penalty": 0.4,
                    "presence_penalty": 0.3,
                },
                timeout=60.0,
            )

            # Categorize errors by HTTP status
            if response.status_code == 429:
                logger.warning("Rate limit exceeded (429)")
                return "Error: Rate limit exceeded. Please wait a moment or try a different model."
            
            if response.status_code == 402:
                logger.warning("Insufficient credits (402)")
                return "Error: Insufficient API credits. Please add funds to your OpenRouter account."
            
            if response.status_code == 503:
                logger.warning("Provider unavailable (503)")
                return "Error: AI provider temporarily unavailable. Please try again later."

            if response.status_code != 200:
                logger.error(f"HTTP error: {response.status_code}")
                return f"Error: HTTP {response.status_code} - {response.text[:200]}"

            data = response.json()

            # Defensive check: OpenRouter may return 200 with error payload
            if "error" in data:
                err_msg = data["error"].get("message", str(data["error"]))
                
                # Categorize provider errors
                if "credit" in err_msg.lower() or "balance" in err_msg.lower():
                    logger.warning(f"Provider error (credits): {err_msg}")
                    return f"Error: Provider credit issue - {err_msg}"
                elif "rate limit" in err_msg.lower():
                    logger.warning(f"Provider rate limit: {err_msg}")
                    return f"Error: Rate limit - {err_msg}"
                elif "overloaded" in err_msg.lower() or "unavailable" in err_msg.lower():
                    logger.warning(f"Provider overloaded: {err_msg}")
                    return f"Error: Provider overloaded - {err_msg}"
                else:
                    logger.error(f"Provider error: {err_msg}")
                    return f"Error: Provider error - {err_msg}"

            if "choices" not in data or not data["choices"]:
                logger.error(f"Unexpected response format: {str(data)[:200]}")
                return f"Error: Unexpected API response format (no choices)"

            result_text = data["choices"][0]["message"]["content"]
            # Sanitize before caching: poisoned responses must not persist for 1h
            if sanitize_degenerate(result_text) != result_text:
                logger.warning(f"Degenerate repetition detected and truncated ({self.model_name})")
                result_text = sanitize_degenerate(result_text)            
            # Store in cache (evict oldest if at capacity)
            import time
            if len(_response_cache) >= CACHE_MAX_SIZE:
                oldest_key = min(_response_cache, key=lambda k: _response_cache[k][1])
                del _response_cache[oldest_key]
            _response_cache[cache_key] = (result_text, time.time())
            
            logger.info(f"LLM response cached ({len(result_text)} chars)")
            return result_text

        except httpx.RemoteProtocolError as e:
            logger.error(f"Connection interrupted: {e}")
            return "Error: Connection interrupted. Please check your network and try again."
        except httpx.RequestError as e:
            logger.error(f"Network error: {e}")
            return f"Error: Network error - {e}"
        except Exception as e:
            logger.exception("Unexpected LLM call error")
            return f"Error: Unexpected error - {e}"

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
        """Clean up resources."""
        if self._exit_stack:
            await self._exit_stack.aclose()
        await self.http_client.aclose()
        logger.debug("Agent resources cleaned up")


# ==========================================
# Functions for chat with conversation history
# ==========================================


async def chat_with_history(cve_id: str, messages_json: str, model_name: str) -> str:
    """Chat with conversation history (accepts JSON string)."""
    logger.info(f"Chat request: cve_id={cve_id}, model={model_name}")
    
    try:
        messages = json.loads(messages_json)
        logger.debug(f"Parsed {len(messages)} messages from JSON")
    except json.JSONDecodeError as e:
        logger.error(f"Invalid messages JSON: {e}")
        return "Error: Invalid messages JSON format"

    agent = CVEAgent(model_name)
    try:
        await agent.connect_to_mcp()
        context = await agent.get_cve_context(cve_id)

        if "error" in context.lower() or "exception" in context.lower():
            return f"Failed to get CVE context: {context}"

        system_prompt = f"""You are a cybersecurity expert analyzing CVE {cve_id}.

Context of the vulnerability:
{context}

IMPORTANT:
- Answer in the SAME LANGUAGE as the user's question
- Use conversation history to maintain context
- Be concise and technical
- If asked follow-up questions, refer to previous answers"""

        api_messages = [{"role": "system", "content": system_prompt}]
        api_messages.extend(messages[-10:])  # Last 10 messages

        return await agent._call_llm(api_messages, temperature=0.2, max_tokens=2000)

    finally:
        await agent.close()


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


if __name__ == "__main__":
    if sys.stdout.encoding != "utf-8":
        sys.stdout.reconfigure(encoding="utf-8")
    if sys.stderr.encoding != "utf-8":
        sys.stderr.reconfigure(encoding="utf-8")
    if sys.stdin.encoding != "utf-8":
        sys.stdin.reconfigure(encoding="utf-8")

    # --chat reads conversation history from stdin (bypasses Windows 32KB CLI limit)
    if len(sys.argv) >= 3 and sys.argv[1] == "--chat":
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
            "Usage: ai_agent.py --mitigate <cve_id> [model] OR "
            "ai_agent.py --chat <cve_id> [model] (history via stdin)",
            file=sys.stderr,
        )