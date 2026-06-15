# netadmin-mcp

A small [MCP](https://modelcontextprotocol.io) server for network profiling and administration. It wraps **nmap** (structured scanning + OS detection), **curl** (HTTP fetch/scrape), and a **guarded bash runner** (for scripted admin tasks like driving the Asterisk Manager Interface over netcat). Built for asset inventory, service profiling, and troubleshooting on hosts you own or are authorized to test.

## Tools

| Tool | What it does |
|------|--------------|
| `nmap_scan` | Scans a host with nmap and returns parsed JSON: open TCP ports, service/version (`-sV`), and an OS-family guess with accuracy (`-O`). Defaults to nmap's top 100 ports; pass `ports=[...]` or `top_ports=N`. Connect scan (`-sT`) works without root; `os_detect` needs root and warns if it can't run. |
| `http_fetch` | Fetches a URL with curl and returns the raw HTTP response (status, headers, final URL, body). For scraping and API probing. |
| `web_scrape` | Fetches a page with curl and extracts title, visible text, and absolutised links (scripts/styles stripped). Stdlib HTML parser, no extra deps. |
| `bash_exec` | Runs an **allowlisted** bash command/pipeline and returns stdout, stderr, and exit code (own process group, timeout + output caps). The "leverage bash" tool — e.g. pipe `printf` payloads into `nc` to drive a line protocol like the Asterisk Manager Interface (AMI). Only allowlisted commands run; command substitution is rejected. |

## Requirements

- Python 3.10+
- The `nmap` binary on `PATH` (used by `nmap_scan`). Debian/Ubuntu: `sudo apt install nmap`; macOS: `brew install nmap`. OS detection (`-O`) and SYN scans need root.
- The `curl` binary on `PATH` (used by `http_fetch` / `web_scrape`). Preinstalled on macOS and most Linux distros.
- `bash` on `PATH`, plus whatever binaries you allowlist for `bash_exec` (e.g. `nc` for AMI: `sudo apt install netcat-openbsd`).

## Project layout

- `nmap_engine.py` — nmap subprocess wrapper + XML→JSON parsing (no MCP dependency).
- `curl_engine.py` — curl subprocess wrapper + stdlib HTML parsing (no MCP dependency).
- `bash_engine.py` — guarded bash runner behind `bash_exec`: command allowlist, `bash -c` in its own process group, timeout + output caps (no MCP dependency).
- `mcp_tools.py` — the four MCP tool definitions; `register(mcp)` attaches them.
- `server.py` — entry point: loads `.env`, builds the FastMCP server, and runs it.
- `requirements.txt` — pip dependency list (`mcp`, `python-dotenv`).
- `pyproject.toml` — project metadata + dependencies for [uv](https://docs.astral.sh/uv/).
- `.env.example` — template for the optional environment-variable overrides (see [Configuration](#configuration)).

## Setup

The Python dependencies are the `mcp` SDK and `python-dotenv` (see
`requirements.txt` / `pyproject.toml`). Two equivalent paths — pick one:

### Recommended: venv + pip

```bash
cd netadmin-mcp
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
cd netadmin-mcp
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
registers all four tools:

```bash
python -c "import server, asyncio; print([t.name for t in asyncio.run(server.mcp.list_tools())])"
# uv equivalent:
uv run python -c "import server, asyncio; print([t.name for t in asyncio.run(server.mcp.list_tools())])"
```

## Connect to Claude Desktop

1. Open **Settings → Developer → Edit Config** to open `claude_desktop_config.json`.
2. Add the `netadmin` server below, replacing the paths with **absolute** paths on
   your machine. Point `command` at the Python inside the venv you created so the
   `mcp` package is found:

```json
{
  "mcpServers": {
    "netadmin": {
      "command": "/ABSOLUTE/PATH/TO/netadmin-mcp/.venv/bin/python",
      "args": ["/ABSOLUTE/PATH/TO/netadmin-mcp/server.py"]
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
    "netadmin": {
      "command": "uv",
      "args": ["run", "--directory", "/ABSOLUTE/PATH/TO/netadmin-mcp", "python", "server.py"]
    }
  }
}
```

   This requires `uv` itself to be on the `PATH` of the shell that launches Claude
   Desktop (use the absolute path to the `uv` binary if it isn't).

3. **Fully quit and reopen** Claude Desktop. The four tools (`nmap_scan`,
   `http_fetch`, `web_scrape`, `bash_exec`) then appear under the 🔌 / tools
   menu, and you can drive them with the example prompts below.

### Troubleshooting

- **Server won't start / "No module named mcp":** `command` isn't pointing at the
  venv Python. Use the full `.venv/bin/python` path, not bare `python3`.
- **Tools don't appear:** make sure you fully quit Claude Desktop (not just closed
  the window) and that the JSON is valid (no trailing commas).
- **`nmap`/`curl` not found errors:** install them (see Requirements) and confirm
  they're on the `PATH` of the shell that launches Claude Desktop.
- **`bash_exec` says a command is blocked:** that's the allowlist. Add the binary
  via `NETADMIN_MCP_ALLOWED_CMDS` (this replaces the default set, so list everything
  you need).
- **`nmap_scan` warns about root for OS detection:** `-O` needs raw sockets. Run
  the server as root or skip `os_detect`.

## Connect to llmCLIent (mcpc)

This server also works as a tool source for [llmCLIent](https://github.com/finleyh/llmCLIent),
a CLI MCP client (`mcpc`) that plays the same host role Claude Desktop does. Because
`netadmin-mcp` speaks MCP over stdio, `mcpc` connects to it with `mcp add stdio` — no code
changes on either side.

Use **absolute** paths, and point the command at the venv Python you created in Setup so
the `mcp` package resolves:

```
mcpc> mcp add stdio netadmin /ABSOLUTE/PATH/TO/netadmin-mcp/.venv/bin/python /ABSOLUTE/PATH/TO/netadmin-mcp/server.py
mcpc> mcp connect netadmin
mcpc> mcp tools
mcpc> chat profile 192.168.1.10 — which common services are open?
```

On Windows the command path is `...\.venv\Scripts\python.exe`. If you used uv instead of a
venv, point the command at uv and run from the project directory:
`mcp add stdio netadmin uv run --directory /ABSOLUTE/PATH/TO/netadmin-mcp python server.py`.

`mcp connect` spawns the server, initializes against it, and lists its tools. The four tools
are then exposed to the remote LLM as `netadmin__<tool>` functions (e.g. `netadmin__nmap_scan`),
and `mcpc`'s tool-call loop dispatches them automatically — same as any other stdio server
it hosts. The example prompts below work verbatim from the `mcpc> chat …` prompt.

## Example prompts

- "Scan 192.168.1.10 — which services and versions are running?"
- "Run nmap against 10.0.0.5 ports 22 and 5038 with version detection."
- "Take a guess at what OS 10.0.0.5 is running." (needs root for `-O`)
- "Log into the Asterisk AMI at 10.0.0.5:5038 with user/secret and run `database show`." (uses `bash_exec`)
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
| `NETADMIN_MCP_NMAP_BIN` | (auto-detected) | Path to the `nmap` binary |
| `NETADMIN_MCP_CURL_BIN` | (auto-detected) | Path to the `curl` binary |
| `NETADMIN_MCP_BASH_BIN` | (auto-detected) | Path to the `bash` binary |
| `NETADMIN_MCP_NMAP_MAX_TIMEOUT` | `300` | Hard ceiling, seconds per nmap run |
| `NETADMIN_MCP_NMAP_DEFAULT_TIMEOUT` | `120` | Default nmap timeout, seconds |
| `NETADMIN_MCP_NMAP_TOP_PORTS` | `100` | Default `--top-ports` when no ports given |
| `NETADMIN_MCP_WEB_DEFAULT_TIMEOUT` | `15` | Default whole-request timeout, seconds |
| `NETADMIN_MCP_WEB_MAX_TIMEOUT` | `60` | Hard ceiling for web requests, seconds |
| `NETADMIN_MCP_WEB_MAX_REDIRECTS` | `10` | Max redirects to follow |
| `NETADMIN_MCP_WEB_MAX_BYTES` | `5000000` | Hard cap on downloaded body (5 MB) |
| `NETADMIN_MCP_USER_AGENT` | `netadmin-mcp/1.0 (+curl)` | User-Agent for `http_fetch` / `web_scrape` |
| `NETADMIN_MCP_BASH_MAX_TIMEOUT` | `120` | Hard ceiling, seconds per `bash_exec` run |
| `NETADMIN_MCP_BASH_DEFAULT_TIMEOUT` | `30` | Default `bash_exec` wall-clock timeout, seconds |
| `NETADMIN_MCP_BASH_MAX_OUTPUT_BYTES` | `262144` | Cap on captured `bash_exec` stdout/stderr (256 KB) |
| `NETADMIN_MCP_ALLOWED_CMDS` | (built-in set) | Space/comma list of allowed `bash_exec` commands. **Replaces** the default. |
| `NETADMIN_MCP_BASH_ALLOWLIST_DISABLED` | `0` | Set truthy to disable the allowlist (isolated envs only) |

`.env` is git-ignored; `.env.example` is the committed template.

## Safety & limits

- `nmap_scan` runs nmap as an **argv list** (no shell); hosts are validated and ports are ints, so there is no shell-injection surface. It defaults to nmap's top 100 ports and a connect scan — not a full 65k SYN sweep — and is bounded by a timeout (default 120s, ceiling 300s).
- **`bash_exec` is a deliberate shell**, guarded by a **command allowlist**: every invoked binary must be on the list (default: `nmap`, `nc`, `ping`, `dig`, `curl`, `printf`, `sleep`, `cat`, `grep`, …) and command substitution (`$(...)`, backticks) is rejected. It runs through `bash -c` in its own process group, bounded by a timeout (default 30s, ceiling 120s) with stdout/stderr capped at 256 KB.
- The allowlist is a **guard rail, not a sandbox.** For real isolation, run this server as an unprivileged user inside a container. Only enable it where running shell commands is acceptable, and target only hosts you are authorized to administer.

## Responsible use

Port scanning and banner grabbing third-party systems without authorization may
be illegal in your jurisdiction. Only point this at hosts you own or have
explicit permission to test.
