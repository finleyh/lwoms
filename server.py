#!/usr/bin/env python3
"""
netcat-mcp — a small MCP service for network profiling via netcat (nc).

This module just constructs the server and runs it. The networking helpers
live in ``netcat.py`` and the tool definitions in ``tools.py``.

Exposed tools:
  - port_scan        : probe a handful of well-known service ports to profile a host
  - banner_grab      : connect to host:port and capture the service banner
  - raw_send_recv    : send arbitrary bytes/text to host:port and return the reply
  - os_fingerprint   : best-effort OS guess from banners + ICMP TTL (heuristic)

Scope / responsible use
-----------------------
Intended for scanning hosts you own or are explicitly authorized to test.
Scanning third-party hosts without permission may be illegal. The server caps
scan breadth and enforces per-connection timeouts to stay non-aggressive.
"""

from __future__ import annotations

from mcp.server.fastmcp import FastMCP

import tools

mcp = FastMCP("netcat-mcp")
tools.register(mcp)


if __name__ == "__main__":
    mcp.run()
