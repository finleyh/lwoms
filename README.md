# telnet-mcp

A small MCP server for **telnet sessions** and **port/HTTP recon**. It manages
persistent telnet connections and also exposes nmap and curl tools so you can
discover what's listening on a host and probe it. The telnet client has zero
third-party dependency — it speaks just enough of the telnet protocol itself over
a plain `asyncio` TCP stream (Python's built-in `telnetlib` was removed in 3.13).

> **Requirements:** the recon tools shell out to `nmap` and `curl`, so both must
> be installed and on `PATH` on the machine running the server.

## Quick start

Requires Python ≥ 3.11 (`mcpo` needs 3.11+); `uv sync` will fetch it for you.

```bash
# 1. Install dependencies (creates .venv, writes uv.lock)
uv sync

# 2. Serve the tools over HTTP on 0.0.0.0:8000 via mcpo (OpenAPI at /docs)
uv run mcpo --host 0.0.0.0 --port 8000 -- uv run server.py
```

Then open `http://localhost:8000/docs`.

> Running `uv run server.py` on its own is **silent on purpose** — that's the
> stdio transport (for MCP clients that launch the process). To bind a network
> port directly without mcpo, see [Running the server](#running-the-server).

## Tools

### Telnet (persistent sessions)

| Tool | What it does |
|------|--------------|
| `telnet_connect(host, port=23, timeout=10, read_banner=True)` | Open a connection, return a reusable `session_id` (and the connect banner). |
| `telnet_send(session_id, data, append_newline=True, newline="\r\n")` | Write text to a session without reading the reply. |
| `telnet_read(session_id, idle_timeout=1, max_wait=10, max_bytes=262144)` | Read output until the stream goes quiet (idle-based). |
| `telnet_send_command(session_id, command, ...)` | Send a command and read the response in one call. |
| `telnet_list()` | List live sessions with byte counts and idle/age timers. |
| `telnet_close(session_id)` | Close a session and free its connection. |

### Recon (stateless)

| Tool | What it does |
|------|--------------|
| `nmap_scan(host, ports=None, top_ports=None, service_detect=True, os_detect=False, skip_ping=False)` | Structured nmap scan → open ports, service/version, OS guess (parsed to JSON). |
| `http_fetch(url, method="GET", headers=None, data=None, ...)` | Fetch a URL with curl; returns status, headers, final URL, and body. |
| `web_scrape(url, max_links=100, max_text_chars=20000)` | Fetch a page and extract title, visible text, and absolutised links. |

## Example flows

Recon a host, then drive whatever it's running:

```
nmap_scan("192.0.2.10", top_ports=200)    -> open ports incl. 23/telnet, 80/http
http_fetch("http://192.0.2.10/")           -> probe the web service
telnet_connect("192.0.2.10", 23)           -> { session_id: "ab12...", banner: "login: " }
telnet_send_command("ab12...", "admin")    -> { data: "Password: " }
telnet_send_command("ab12...", "secret")   -> { data: "> " }
telnet_send_command("ab12...", "show status")
telnet_close("ab12...")
```

Reads are *idle-based*: telnet has no message boundaries, so a read returns once
the host has been silent for `idle_timeout` seconds (or `max_wait` / `max_bytes`
is hit, or the peer hangs up). Bump `idle_timeout` for slow hosts.

## Setup (uv)

This is a [uv](https://docs.astral.sh/uv/)-based project. **Requires Python ≥
3.11** (`mcpo` needs 3.11+). Dependencies are declared in `pyproject.toml` —
that's the source of truth.

```bash
uv sync          # creates .venv, installs mcp + mcpo, writes uv.lock
```

`uv sync` will fetch a Python 3.11 interpreter automatically if you don't have
one, resolve the dependency tree, and pin it in `uv.lock` (commit that file).

## Running the server

The server supports three transports. Pick one:

```bash
# stdio (default) — silent; for MCP clients that launch the process themselves
uv run server.py

# HTTP/OpenAPI via mcpo — recommended for serving over a network
uv run mcpo --host 0.0.0.0 --port 8000 -- uv run server.py   # docs at /docs

# native streamable-HTTP — bind a port without mcpo (endpoint at /mcp)
uv run server.py --transport http --host 0.0.0.0 --port 8000

# native SSE
uv run server.py --transport sse --host 0.0.0.0 --port 8000
```

Host/port can also be set with environment variables, which is convenient in
containers:

```bash
TELNET_MCP_TRANSPORT=http TELNET_MCP_HOST=0.0.0.0 TELNET_MCP_PORT=8000 \
    uv run server.py
```

**`mcpo` vs. native HTTP:** [`mcpo`](https://github.com/open-webui/mcpo) wraps
the server as an OpenAPI service with auto-generated Swagger docs at `/docs` —
ideal for Open WebUI and plain REST clients. The native `--transport http` mode
serves the raw MCP streamable-HTTP protocol at `/mcp` for MCP-aware clients, with
no extra process in front.

## Dependencies

| Package | Why |
|---------|-----|
| [`mcp`](https://pypi.org/project/mcp/) | MCP server framework (FastMCP). |
| [`mcpo`](https://pypi.org/project/mcpo/) | MCP→OpenAPI proxy for serving the tools over HTTP. |

The canonical list lives in `pyproject.toml` and is pinned in `uv.lock`. A
`requirements.txt` mirror is included for non-uv installs; regenerate it from the
lockfile with `uv export --no-hashes -o requirements.txt` if you change deps.

## Responsible use

Telnet is plaintext and unauthenticated, and nmap/curl reach out to whatever host
you name. Only target hosts you own or are explicitly authorized to access;
scanning third-party hosts without permission may be illegal.
