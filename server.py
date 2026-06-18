#!/usr/bin/env python3
"""
telnet-mcp — a small MCP service that manages persistent telnet connections.

This module just constructs the server and runs it. The protocol/engine work
lives in the engine modules; the MCP tool definitions live in ``mcp_tools.py``.

Exposed tools:
  Telnet (persistent sessions)
  - telnet_connect       : open a telnet connection, return a reusable session id
  - telnet_send          : write text to a session (no reply read)
  - telnet_read          : read output from a session until it goes quiet
  - telnet_send_command  : send a command and read the response in one call
  - telnet_list          : list live sessions
  - telnet_close         : close a session
  Recon (stateless)
  - nmap_scan            : structured nmap scan — open ports, service/version, OS
  - http_fetch           : fetch a URL with curl and return the raw HTTP response
  - web_scrape           : fetch a page with curl and extract title, text, links
  - public_ipv4          : get this machine's public IPv4 address via icanhazip
  - dns_reverse_lookup   : reverse-DNS (PTR) for an IP — reveals the operator
  - dns_lookup           : forward DNS lookup for a domain (A/AAAA/MX/NS/TXT/…)

Modules:
  - telnet_engine.py     : zero-dependency asyncio telnet client + session registry
  - nmap_engine.py       : nmap subprocess wrapper + XML→JSON parsing
  - curl_engine.py       : curl subprocess wrapper + stdlib HTML parsing
  - dns_engine.py        : dig subprocess wrapper + answer-section parsing
  - mcp_tools.py         : the MCP tool definitions; register(mcp) attaches them

Transports
----------
By default the server runs over **stdio** — it speaks JSON-RPC on stdin/stdout
and prints nothing to the terminal. That is correct and expected: stdio is meant
for an MCP client (Claude Desktop, etc.) to launch this process, not for running
by hand. To bind a network host/port, choose an HTTP transport instead:

  python server.py                                  # stdio (default, silent)
  python server.py --transport http --host 0.0.0.0 --port 8000
  python server.py --transport sse  --host 0.0.0.0 --port 8000

Equivalent environment variables (handy under `uv run` / containers):

  TELNET_MCP_TRANSPORT=http TELNET_MCP_HOST=0.0.0.0 TELNET_MCP_PORT=8000 \
      uv run server.py

With the http transport the streamable-HTTP endpoint is served at
``http://<host>:<port>/mcp``.

Scope / responsible use
-----------------------
Telnet is plaintext and unauthenticated, and nmap/curl reach out to whatever
host you name. Only target hosts you own or are explicitly authorized to access;
scanning third-party hosts without permission may be illegal. nmap and curl must
be installed on the machine running the server.
"""

from __future__ import annotations

import argparse
import os
import sys

from mcp.server.fastmcp import FastMCP

import mcp_tools

# Map our friendly transport names to FastMCP's transport identifiers.
_TRANSPORTS = {
    "stdio": "stdio",
    "http": "streamable-http",
    "sse": "sse",
}


def _build_server(host: str, port: int) -> FastMCP:
    """Construct the FastMCP server, binding host/port for HTTP transports."""
    mcp = FastMCP("telnet-mcp", host=host, port=port)
    mcp_tools.register(mcp)
    return mcp


def main() -> None:
    """Console-script entry point (`telnet-mcp`) and `python server.py`."""
    parser = argparse.ArgumentParser(
        prog="telnet-mcp",
        description="MCP server for telnet sessions and port/HTTP recon.",
    )
    parser.add_argument(
        "--transport",
        choices=sorted(_TRANSPORTS),
        default=os.getenv("TELNET_MCP_TRANSPORT", "stdio"),
        help="stdio (default), http (streamable-HTTP), or sse.",
    )
    parser.add_argument(
        "--host",
        default=os.getenv("TELNET_MCP_HOST", "127.0.0.1"),
        help="Bind address for http/sse transports (default 127.0.0.1).",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=int(os.getenv("TELNET_MCP_PORT", "8000")),
        help="Bind port for http/sse transports (default 8000).",
    )
    args = parser.parse_args()

    mcp = _build_server(args.host, args.port)
    transport = _TRANSPORTS[args.transport]

    if args.transport == "stdio":
        # Anything on stdout would corrupt the JSON-RPC stream, so log to stderr.
        print(
            "telnet-mcp: serving over stdio (no network port). "
            "Use --transport http --host 0.0.0.0 --port 8000 to bind a port.",
            file=sys.stderr,
        )
    else:
        print(
            f"telnet-mcp: serving {args.transport} on "
            f"http://{args.host}:{args.port}/"
            f"{'mcp' if args.transport == 'http' else 'sse'}",
            file=sys.stderr,
        )

    mcp.run(transport=transport)


if __name__ == "__main__":
    main()
