<div align="center">

<a href="https://github.com/sleepti3ht/Panopticon"><img src="https://raw.githubusercontent.com/sleepti3ht/Panopticon/main/src-tauri/icons/icon.png" width="140" alt="Panopticon logo"/></a>

# Panopticon

### CVE Intelligence Map · Threat graph + local AI mitigation agent + CISA KEV flags

[![Tauri](https://img.shields.io/badge/tauri-v2-black?style=flat&logo=tauri&color=1a1b26)](https://tauri.app)
[![Rust](https://img.shields.io/badge/rust-1.75+-black?style=flat&logo=rust&color=1a1b26)](https://www.rust-lang.org)
[![Python](https://img.shields.io/badge/python-3.12+-black?style=flat&logo=python&color=1a1b26)](https://python.org)
[![Vanilla JS](https://img.shields.io/badge/vanilla-es6-black?style=flat&logo=javascript&color=1a1b26)](https://developer.mozilla.org/en-US/docs/Web/JavaScript)
[![MCP](https://img.shields.io/badge/MCP-server-black?style=flat&color=7c3aed)](https://modelcontextprotocol.io)
[![PyPI](https://img.shields.io/pypi/v/panopticon-mcp-server?style=flat&color=7c3aed&label=panopticon-mcp-server)](https://pypi.org/project/panopticon-mcp-server/)
[![CISA KEV](https://img.shields.io/badge/CISA-KEV-black?style=flat&color=dc2626)](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)
[![XERJ Corpus Hub contributor](https://hub.xerj.org/contributors/sleepti3ht/badge.svg)](https://hub.xerj.org/contributors/sleepti3ht)
[![License](https://img.shields.io/github/license/sleepti3ht/Panopticon?style=flat&color=7c3aed)](LICENSE)

</div>

> 👁️ **A desktop-native CVE intelligence map** — interactive force-directed graph of vendor↔CVE relationships wired to a local AI agent that drafts mitigation plans in streaming mode, maintains a versioned chat history, and resumes conversations across sessions. Actively exploited CVEs are flagged straight from the CISA KEV catalog.

> 🤖 **Also available as a standalone MCP server** — [`panopticon-mcp-server`](https://pypi.org/project/panopticon-mcp-server/) on PyPI for external AI agents (Claude Desktop, Cursor, VSCode Copilot). No desktop app required.

Built on **Tauri 2** (Rust shell), **Python** (async AI + MCP client + resident daemon), and **Vanilla JS** with `vis-network`. Local-first, no telemetry, no cloud lock-in.

## Screenshots

<p align="center">
  <img src="docs/img/01-hero-log4shell.png" width="49%" alt="Threat graph centered on Log4Shell with CVSS-colored nodes" />
  <img src="docs/img/04-chat-versions.png" width="49%" alt="CVE details with streaming AI mitigation chat" />
  <img src="docs/img/05-reports.png" width="49%" alt="Saved conversations with pins and tags" />
  <img src="docs/img/06-theme-dark.png" width="49%" alt="Dark theme" />
</p>

---

## Two ways to use Panopticon

### Option A: Desktop app (full UI)

```bash
git clone https://github.com/sleepti3ht/Panopticon.git
cd Panopticon

# Python backend
cd panopticon-python
python -m venv venv
venv\Scripts\activate        # Windows
source venv/bin/activate     # macOS / Linux
pip install -r requirements.txt
cp .env.example .env         # add your OPENROUTER_API_KEY

# Frontend + Tauri
cd ..
npm install
npm run tauri dev
```

> First launch auto-creates `panopticon.db` (SQLite) with the schema.

### Option B: Standalone MCP server (for Claude Desktop, Cursor, any MCP client)

```bash
pip install panopticon-mcp-server

# Live-only mode (NVD API + CISA KEV, no local DB required)
panopticon-mcp-server

# Local+live mode (uses existing Panopticon SQLite for fast lookups)
panopticon-mcp-server --db-path /path/to/panopticon.db
```

Register in your MCP client (Claude Desktop `claude_desktop_config.json`, Cursor MCP settings):

```json
{
  "mcpServers": {
    "panopticon": {
      "command": "panopticon-mcp-server",
      "args": ["--transport", "stdio"]
    }
  }
}
```

Six tools available: `get_cve_details`, `search_cves`, `is_cve_exploited`, `get_cwe_hierarchy`, `get_cve_context_for_mitigation`, `db_status`.

### Data: mock or real

```bash
cd panopticon-python
python seed_mock.py          # 50 synthetic CVEs — instant, no API keys
python ingestor.py 4000 90   # real NVD feed: last 90 days, up to 4000 CVEs with CPE
```

The ingestor uses a rolling window counted from request time and auto-chunks requests to respect the NVD 120-day-per-query limit. With a free `NVD_API_KEY` in `.env` it runs ~10× faster (50 vs 5 requests per 30s).

### Configuration (`.env`)

| Variable | Required | Purpose |
|---|---|---|
| `OPENROUTER_API_KEY` | yes (desktop) | LLM gateway key |
| `NVD_API_KEY` | no | raises NVD rate limit for ingestion |
| `AVAILABLE_MODELS` | no | comma-separated model list for the chat selector |
| `DEFAULT_MODEL` | no | preselected chat model (default: `nemotron-3.5-lightning`) |

## 🔋 Batteries Included

**🕸 Force-directed threat graph**

- `vis-network` with `forceAtlas2Based` solver, auto-stabilization and CPU-off after 1500 iterations
- CVSS-based node coloring (critical → red, high → orange, low → green)
- KEV-listed CVEs get a thick red ring regardless of CVSS
- Search any CVE → graph rebuilds around its vendor scope and the camera focuses on the node
- Instant theme swap (light/dark) via `network.setOptions()` — no re-render

**🔥 CISA KEV awareness**

- Lazy-loads the official Known Exploited Vulnerabilities catalog (~1.7k entries), cached per process
- `ACTIVELY EXPLOITED` row with patch due date in the CVE details panel
- Live NVD API fallback: CVEs missing from the local DB are resolved on the fly and cached for 1 hour

**🤖 Streaming AI mitigation agent**

- **Resident Python daemon** with JSON-RPC over stdin/stdout — IPC latency <50 ms (was 300–800 ms under spawn-per-call)
- **Real-time token streaming** via Tauri Events: LLM tokens appear in the UI as they're generated, no micro-freeze on long reports
- Model Context Protocol (MCP) client for live CVE context retrieval
- Pluggable OpenRouter models via `AVAILABLE_MODELS` (tested: `nemotron-3.5-lightning`, `gemma-4-31b-it`, `qwen-3.8` family)
- Strict 5-point mitigation prompts (risk, immediate actions, long-term, commands, refs)
- Automatic language detection — responds in the user's language
- Categorized provider errors (rate limit / credits / overload) instead of silent failures
- **Degenerate-repetition guard**: n-gram detection + sanitization prevents LLM collapse loops from being cached or saved to DB

**💬 Versioned chat with memory**

- 10-message sliding window passed to Python via stdin — bypasses the Windows 32KB CLI argument limit
- Copy & Regenerate on every message, version indicator (`2/3`)
- Race-condition-safe UI (`isProcessing` guard + `finally`-unblock)
- XSS-safe markdown rendering (HTML-tag escaping before transform)

**📚 Reports — resumable conversations**

- Auto-save to SQLite after every assistant turn
- Click a report → rebuild graph around that CVE (default → vendor-scoped fallback)
- Pins 📌 and tags (up to 8 per report); pinned reports float to the top
- Bulk selection + bulk delete, single delete with confirmation
- Markdown export to a configurable directory (Settings → Export Directory) with explicit AI-generated draft disclosure banner
- Filter box across CVE id, title and tags
- Expand/collapse details panel for long reads (state persisted)
- `save_report.py purge` cleans legacy rows with invalid JSON payloads

**⚙️ Desktop shell**

- No startup flash (window hidden until first paint)
- External links open in system browser
- Debounced search (300ms), mutually exclusive side panels
- Settings popover with `localStorage` for API keys and export path

## 🤖 Standalone MCP Server

[`panopticon-mcp-server`](https://pypi.org/project/panopticon-mcp-server/) is the CVE intelligence layer extracted as an independent PyPI package. Any MCP-compatible AI agent can query CVE data without installing the desktop app.

```bash
pip install panopticon-mcp-server
```

### Tools

| Tool | Description |
|---|---|
| `db_status` | Agent self-awareness: data mode, DB path, cache sizes |
| `get_cve_details` | Full CVE info: CVSS, CWE, affected products, references, KEV status |
| `search_cves` | Vendor search with CVSS filter (local DB only) |
| `is_cve_exploited` | CISA KEV status with full metadata (date added, due date, ransomware usage) |
| `get_cwe_hierarchy` | CWE IDs with related-CVE counts for pattern analysis |
| `get_cve_context_for_mitigation` | LLM-ready structured prompt for mitigation plan generation |

### Architecture

- **Config cascade**: CLI flag → env var `PANOPTICON_DB_PATH` → auto-discovery (`~/.panopticon/panopticon.db`, CWD) → live-only mode
- **Bounded LRU caches**: NVD 50 entries / KEV 2000 entries — prevents memory leaks in long-running MCP processes
- **Asyncio locks** on NVD fetches — serialized rate limiting even under concurrent tool calls
- **Lazy KEV load** — ~1.7k entries fetched once on first use, then served from memory
- **Live NVD fallback** — any CVE missing from local DB is resolved on the fly with rate-limit awareness

## 📸 Preview

<p align="center">
  <img src="https://raw.githubusercontent.com/sleepti3ht/Panopticon/main/docs/img/01-hero-log4shell.png" alt="Panopticon threat graph centered on CVE-2021-44228" width="100%" />
  <em>Vendor↔CVE force-directed graph · camera focus on critical node · light theme</em>
</p>

## Why Panopticon

Vulnerability triage today is a browser tab soup: NVD, vendor advisories, CISA KEV, ChatGPT, internal runbooks — all in separate windows. The analyst context-switches constantly and the mental model of "this CVE, this vendor, these affected products, these mitigations" never lives in one place.

Panopticon collapses that into a single native surface:

- **Spatial memory** — the graph is the mental map; clicking a CVE recenters the world around it.
- **Stateful analysis** — the AI remembers the conversation and the CVE context simultaneously.
- **Resumable work** — close the app, open it tomorrow, pick up exactly where you left off.
- **Prioritized triage** — KEV flags cut through CVSS noise: exploited beats theoretical.
- **Local by default** — no telemetry, no SaaS middleman, your keys stay on your disk.
- **Composable** — same intelligence layer exposed as a PyPI package for your existing AI toolchain.

## How it works

```
┌─────────────────────────────────────────────────────────────────┐
│                    Vanilla JS (Vite + vis-network)              │
│                                                                 │
│   invoke("chat_with_agent", { cveId, messages, model })         │
│   listen("llm_chunk") → streaming token updates to DOM          │
└────────────────────┬────────────────────────────────────────────┘
                     │
                     ▼
┌─────────────────────────────────────────────────────────────────┐
│              Tauri 2  ·  Rust (tokio) command handlers          │
│                                                                 │
│   DaemonManager: Arc<Mutex<Child>> · JSON-RPC over stdin/stdout │
│   AsyncBufReadExt::read() 1KB chunks → Tauri Event "llm_chunk"  │
└────────────────────┬────────────────────────────────────────────┘
                     │ single long-lived process, serialized IPC
                     ▼
┌─────────────────────────────────────────────────────────────────┐
│            Python resident daemon (ai_agent.py --daemon)        │
│                                                                 │
│   ai_agent ──► MCP client ──► mcp_server.py (CVE context)       │
│        │                              │                         │
│        │                              ├─► SQLite (local CVE DB) │
│        │                              └─► CISA KEV catalog      │
│        │                                    + NVD live fallback │
│        └──► OpenRouter API (streaming) + SQLite (chat_reports)  │
└─────────────────────────────────────────────────────────────────┘
```

The Rust layer is deliberately thin: it owns the window, routes IPC, manages the resident Python daemon, and serializes requests to prevent stdin/stdout races. All heavy logic (LLM orchestration, graph building, search, persistence) lives in Python, which is easier to iterate on for ML-adjacent work. The same Python intelligence is extracted as [`panopticon-mcp-server`](https://pypi.org/project/panopticon-mcp-server/) for external clients.

## 🧩 Project structure

```
Panopticon/                          # monorepo root
├── src/                             # Vanilla JS + CSS
│   ├── main.js                      # UI, graph, chat, panels, reports
│   └── styles.css                   # Dark/light theme (purple accents)
├── src-tauri/                       # Rust shell + IPC commands
│   ├── src/lib.rs                   # DaemonManager + handlers
│   └── tauri.conf.json              # Window defaults, permissions
├── panopticon-python/               # Backend (monorepo)
│   ├── panopticon_mcp/              # Standalone MCP server (published to PyPI)
│   │   ├── __init__.py              # Version
│   │   ├── server.py                # FastMCP tools + CLI entry
│   │   ├── config.py                # DB path cascade, rate-limit constants
│   │   ├── nvd.py                   # Live NVD client + bounded LRU cache
│   │   ├── kev.py                   # CISA KEV client + lazy load
│   │   ├── dbreader.py              # SQLite read layer + resolve cascade
│   │   └── context.py               # CWE patterns + mitigation prompt builder
│   ├── pyproject.toml               # Package metadata (panopticon-mcp-server)
│   ├── README.md                    # PyPI-facing readme
│   ├── ai_agent.py                  # Resident daemon + LLM orchestration
│   ├── mcp_server.py                # Internal MCP server (desktop use)
│   ├── graph_builder.py             # Vendor↔CVE graph + KEV flags
│   ├── global_search.py             # Cross-table search
│   ├── get_vendors.py               # Vendor list with CVE counts
│   ├── save_report.py               # chat_reports CRUD + migrations
│   ├── ingestor.py                  # NVD → SQLite rolling-window pipeline
│   ├── db.py                        # Schema + atomic inserts
│   ├── config.py                    # Desktop env-driven constants
│   ├── utils.py                     # Secret masking + degenerate-repetition helpers
│   ├── seed_mock.py                 # 50 synthetic CVEs for demos
│   ├── requirements.txt             # Desktop dependencies
│   └── panopticon.db                # (auto-created, gitignored)
├── .github/workflows/publish.yml    # PyPI OIDC publish on mcp-v* tags
├── docs/
│   └── img/                         # README + article screenshots
├── index.html
├── vite.config.js
└── package.json
```

## 🧑‍💻 Built with

- **[Tauri 2](https://tauri.app)** — native desktop shell
- **[vis-network](https://visjs.org)** — force-directed graph rendering
- **[MCP](https://modelcontextprotocol.io)** — tool-use protocol for LLM context
- **[OpenRouter](https://openrouter.ai)** — multi-model gateway (free tier)
- **[CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)** — exploited-vulnerability catalog
- **[SQLite](https://sqlite.org)** — zero-config local persistence
- **[tokio](https://tokio.rs)** — async runtime for daemon IPC and streaming

## Roadmap

- [x] Streaming LLM responses via Tauri Events
- [x] Resident Python daemon (JSON-RPC IPC, <50ms latency)
- [x] Degenerate-repetition guard for LLM outputs
- [x] CISA KEV lazy-load integration
- [x] Standalone MCP server published to PyPI
- [x] Reports CRUD (pins, tags, bulk delete, Markdown export with AI-draft disclosure)
- [x] Focus-CVE graph resolution
- [ ] In-UI "Sync" button with live ingest log stream (Tauri Events)
- [ ] Persist CISA KEV catalog to a local table (zero-latency flags, offline mode)
- [ ] CWE layer in the graph (vendor weakness patterns)
- [ ] Dashboard trends: 7/30-day publication spikes, top vendors
- [ ] `json_repair` integration for malformed LLM outputs
- [ ] OS-level secret storage (replace `localStorage` API keys)
- [ ] Encrypted `.panopticon` export/import for team handoffs
- [ ] CI release builds for desktop app (GitHub Actions artifacts per OS)

## 📖 Deep Dive

Read the full architectural breakdown on dev.to: [Building Panopticon: A Local-First CVE Intelligence Map with Tauri 2 + Rust + Python](https://dev.to/sleepti3ht/building-panopticon-a-local-first-cve-intelligence-map-with-tauri-2-rust-python-4p6p)

Covers sampling penalties for LLM repetition collapse, stdin transport bypassing Windows CLI limits, CISA KEV projection bugs, and why vanilla JS won over React for this tool.

## 🧑‍🍳 Related

- **[tauri-ui](https://github.com/agmmnn/tauri-ui)** — inspired the dark/purple visual direction and the README structure
- **[GooEye](https://github.com/sleepti3ht/GooEye)** — sibling project: a stealth sniper bot for 闲鱼 (Goofish)
- **[Murmur](https://github.com/sleepti3ht/Murmur)** — sibling project: local-first Git secret scanner with Tauri dashboard

> _Built something with Panopticon's architecture? [Open a PR](https://github.com/sleepti3ht/Panopticon/pulls) adding it to this list — one line with a link and a short description._

---

## License

MIT
