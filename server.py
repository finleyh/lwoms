#!/usr/bin/env python3
"""
netadmin-mcp — a small MCP service for network profiling and administration.

This module just constructs the server and runs it. The work lives in the
engine modules; the tool definitions live in ``mcp_tools.py``.

Exposed tools:
  - nmap_scan        : structured nmap scan — open ports, service/version, OS guess
  - http_fetch       : fetch a URL with curl and return the raw HTTP response
  - web_scrape       : fetch a page with curl and extract title, text, and links
  - bash_exec        : run an allowlisted bash command/pipeline (e.g. printf | nc for AMI)

Modules:
  - nmap_engine.py   : nmap subprocess wrapper + XML→JSON parsing
  - curl_engine.py   : curl subprocess wrapper + stdlib HTML parsing
  - bash_engine.py   : guarded bash runner (command allowlist, timeout, output caps)
  - mcp_tools.py     : the MCP tool definitions; register(mcp) attaches them

Scope / responsible use
-----------------------
Intended for scanning/administering hosts you own or are explicitly authorized
to test. Scanning third-party hosts without permission may be illegal. The
server caps timeouts and guards the bash tool with a command allowlist.
"""

from __future__ import annotations

from dotenv import load_dotenv

# Load .env (if present) BEFORE importing the engine modules, so their
# module-level config constants pick up any overrides. Real environment
# variables always win over .env values.
load_dotenv(override=False)

from mcp.server.fastmcp import FastMCP

import mcp_tools

mcp = FastMCP("netadmin-mcp")
mcp_tools.register(mcp)


def main() -> None:
    """Console-script entry point (`netadmin-mcp`) and `python server.py`."""
    mcp.run()


if __name__ == "__main__":
    main()
