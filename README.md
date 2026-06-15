# netcat-mcp

A small [MCP](https://modelcontextprotocol.io) server that profiles network hosts by shelling out to the `nc` (netcat) binary. Built for asset inventory, service profiling, and troubleshooting on hosts you own or are authorized to test.

## Tools

| Tool | What it does |
|------|--------------|
| `port_scan` | Probes a handful of well-known service ports (ssh, http, https, smb, mysql, redis, plus VoIP: SIP, Asterisk AMI, IAX2, SCCP, FreeSWITCH ESL, H.323) to profile a device. Not an exhaustive 65k sweep. |
| `banner_grab` | Connects to `host:port` and captures the service banner. Sends a minimal safe probe for request-driven services (HTTP/Redis). |
| `raw_send_recv` | Sends arbitrary text to `host:port` over TCP/UDP and returns the reply. A generic nc pipe for poking custom protocols. |
| `os_fingerprint` | Best-effort OS guess from service banners + ICMP TTL. **Heuristic only** — true OS detection needs stack fingerprinting (`nmap -O`). |
| `http_fetch` | Fetches a URL with curl and returns the raw HTTP response (status, headers, final URL, body). For scraping and API probing. |
| `web_scrape` | Fetches a page with curl and extracts title, visible text, and absolutised links (scripts/styles stripped). Stdlib HTML parser, no extra deps. |

## Requirements

- Python 3.10+
- The `nc` binary on `PATH` (OpenBSD or GNU netcat). On macOS it's preinstalled; on Debian/Ubuntu: `sudo apt install netcat-openbsd`.
- The `curl` binary on `PATH` (used by `http_fetch` / `web_scrape`). Preinstalled on macOS and most Linux distros.
- `ping` on `PATH` (optional — only used by `os_fingerprint` for the TTL hint).

## Project layout

- `netcat.py` — netcat subprocess wrapper, validation, OS heuristics (no MCP dependency).
- `curl.py` — curl subprocess wrapper + stdlib HTML parsing (no MCP dependency).
- `tools.py` — the six MCP tool definitions; `register(mcp)` attaches them.
- `server.py` — entry point: loads `.env`, builds the FastMCP server, and runs it.
- `requirements.txt` — pip dependency list (`mcp`, `python-dotenv`).
- `pyproject.toml` — project metadata + dependencies for [uv](https://docs.astral.sh/uv/).
- `.env.example` — template for the optional environment-variable overrides (see [Configuration](#configuration)).

## Setup

The Python dependencies are the `mcp` SDK and `python-dotenv` (see
`requirements.txt` / `pyproject.toml`). Two equivalent paths — pick one:

### Recommended: venv + pip

```bash
cd netcat-mcp
python3 -m venv .venv          # create an isolated environment
source .venv/bin/activate      # Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

That's it. The `.venv/bin/python` created here is the interpreter you'll point
Claude Desktop at below.

### Alternative: uv

[uv](https://docs.astral.sh/uv/) reads `pyproject.toml` directly, so the project
is uv-native. From the repo root:

```bash
cd netcat-mcp
uv sync                        # creates .venv and installs from pyproject.toml
```

`uv sync` resolves and installs everything into `.venv` (writing a `uv.lock`),
and `uv run` below uses that environment automatically — no `source activate`
step needed. If you'd rather drive it from `requirements.txt`, `uv venv && uv pip
install -r requirements.txt` works too.

## Run

With a venv active:

```bash
python server.py        # serves over stdio; Ctrl-C to stop
```

Or with uv (no activation needed — it uses the `.venv` from `uv sync`):

```bash
uv run python server.py
```

A normal start prints nothing and waits for an MCP client to connect over
stdio — that's expected. You usually don't run it by hand; Claude Desktop
launches it for you (next section). To do a quick self-check that it imports and
registers all six tools:

```bash
python -c "import server, asyncio; print([t.name for t in asyncio.run(server.mcp.list_tools())])"
# uv equivalent:
uv run python -c "import server, asyncio; print([t.name for t in asyncio.run(server.mcp.list_tools())])"
```

## Connect to Claude Desktop

1. Open **Settings → Developer → Edit Config** to open `claude_desktop_config.json`.
2. Add the `netcat` server below, replacing the paths with **absolute** paths on
   your machine. Point `command` at the Python inside the venv you created so the
   `mcp` package is found:

```json
{
  "mcpServers": {
    "netcat": {
      "command": "/ABSOLUTE/PATH/TO/netcat-mcp/.venv/bin/python",
      "args": ["/ABSOLUTE/PATH/TO/netcat-mcp/server.py"]
    }
  }
}
```

   On Windows the command path is `...\.venv\Scripts\python.exe`.

   **If you used uv**, point `command` at uv and let it run the project from its
   directory (it picks up the `.venv` created by `uv sync`):

```json
{
  "mcpServers": {
    "netcat": {
      "command": "uv",
      "args": ["run", "--directory", "/ABSOLUTE/PATH/TO/netcat-mcp", "python", "server.py"]
    }
  }
}
```

   This requires `uv` itself to be on the `PATH` of the shell that launches Claude
   Desktop (use the absolute path to the `uv` binary if it isn't).

3. **Fully quit and reopen** Claude Desktop. The six tools (`port_scan`,
   `banner_grab`, `raw_send_recv`, `os_fingerprint`, `http_fetch`, `web_scrape`)
   then appear under the 🔌 / tools menu, and you can drive them with the example
   prompts below.

### Troubleshooting

- **Server won't start / "No module named mcp":** `command` isn't pointing at the
  venv Python. Use the full `.venv/bin/python` path, not bare `python3`.
- **Tools don't appear:** make sure you fully quit Claude Desktop (not just closed
  the window) and that the JSON is valid (no trailing commas).
- **`nc`/`curl` not found errors:** install them (see Requirements) and confirm
  they're on the `PATH` of the shell that launches Claude Desktop.

## Connect to llmCLIent (mcpc)

This server also works as a tool source for [llmCLIent](https://github.com/finleyh/llmCLIent),
a CLI MCP client (`mcpc`) that plays the same host role Claude Desktop does. Because
`netcat-mcp` speaks MCP over stdio, `mcpc` connects to it with `mcp add stdio` — no code
changes on either side.

Use **absolute** paths, and point the command at the venv Python you created in Setup so
the `mcp` package resolves:

```
mcpc> mcp add stdio netcat /ABSOLUTE/PATH/TO/netcat-mcp/.venv/bin/python /ABSOLUTE/PATH/TO/netcat-mcp/server.py
mcpc> mcp connect netcat
mcpc> mcp tools
mcpc> chat profile 192.168.1.10 — which common services are open?
```

On Windows the command path is `...\.venv\Scripts\python.exe`. If you used uv instead of a
venv, point the command at uv and run from the project directory:
`mcp add stdio netcat uv run --directory /ABSOLUTE/PATH/TO/netcat-mcp python server.py`.

`mcp connect` spawns the server, initializes against it, and lists its tools. The six tools
are then exposed to the remote LLM as `netcat__<tool>` functions (e.g. `netcat__port_scan`),
and `mcpc`'s tool-call loop dispatches them automatically — same as any other stdio server
it hosts. The example prompts below work verbatim from the `mcpc> chat …` prompt.

## Example prompts

- "Profile 192.168.1.10 — which common services are open?"
- "Grab the SSH banner from 10.0.0.5 port 22."
- "Send `INFO\r\n` to 127.0.0.1:6379 and show the reply."
- "Take a guess at what OS 10.0.0.5 is running."
- "Scrape the title, text, and links from https://example.com."
- "Fetch https://api.example.com/status and show me the JSON and headers."

## Configuration

Every tunable is optional — the server boots with sane defaults and **no `.env`
required**. To override them, copy the template and edit:

```bash
cp .env.example .env
```

`server.py` loads `.env` automatically on startup (real shell environment
variables take precedence over `.env` entries). The available variables:

| Variable | Default | Purpose |
|----------|---------|---------|
| `NETCAT_MCP_NC_BIN` | (auto-detected) | Path to the `nc` binary |
| `NETCAT_MCP_CURL_BIN` | (auto-detected) | Path to the `curl` binary |
| `NETCAT_MCP_MAX_TIMEOUT` | `15` | Hard ceiling, seconds per nc connection |
| `NETCAT_MCP_DEFAULT_TIMEOUT` | `4` | Default per-connection timeout, seconds |
| `NETCAT_MCP_MAX_PAYLOAD_BYTES` | `8192` | Cap on `raw_send_recv` payload |
| `NETCAT_MCP_MAX_RECV_BYTES` | `65536` | Cap on captured reply size |
| `NETCAT_MCP_WEB_DEFAULT_TIMEOUT` | `15` | Default whole-request timeout, seconds |
| `NETCAT_MCP_WEB_MAX_TIMEOUT` | `60` | Hard ceiling for web requests, seconds |
| `NETCAT_MCP_WEB_MAX_REDIRECTS` | `10` | Max redirects to follow |
| `NETCAT_MCP_WEB_MAX_BYTES` | `5000000` | Hard cap on downloaded body (5 MB) |
| `NETCAT_MCP_USER_AGENT` | `netcat-mcp/1.0 (+curl)` | User-Agent for `http_fetch` / `web_scrape` |

`.env` is git-ignored; `.env.example` is the committed template.

## Safety & limits

- Per-connection timeout is capped at **15s**; `raw_send_recv` payloads are capped at **8 KB**; replies are truncated at **64 KB**.
- `port_scan` only touches the small well-known-service list — it will never become a wide, aggressive sweep.
- Hosts and ports are validated before any command runs; arguments are passed to `nc` as an argv list (no shell), so there is no shell-injection surface.

## Responsible use

Port scanning and banner grabbing third-party systems without authorization may
be illegal in your jurisdiction. Only point this at hosts you own or have
explicit permission to test.
