#!/usr/bin/env python3
"""
mcp_tools.py — the MCP tool definitions exposed by this server.

This is the MCP-facing layer. Each tool is a thin async wrapper around the
``telnet_engine`` and shapes the result for the client. ``register(mcp)``
attaches every tool to a FastMCP instance, keeping the tool definitions
decoupled from server construction/transport (see ``server.py``).

Telnet — a *persistent session* model:

    telnet_connect(host, port)  -> session_id (+ optional banner)
    telnet_send(session_id, "...")            # write a line
    telnet_read(session_id)                   # read what came back
    telnet_send_command(session_id, "...")    # send + read in one call
    telnet_list()                             # list live sessions
    telnet_close(session_id)                  # hang up

Recon — stateless tools for port/service discovery and HTTP probing:

    nmap_scan(host)             # structured nmap scan: open ports, services, OS
    http_fetch(url)             # raw HTTP response via curl
    web_scrape(url)             # title / text / links extracted from a page

Telnet is plaintext and unauthenticated at the transport level, and nmap/curl
reach out to whatever host you name — only point these at hosts you own or are
explicitly authorized to access. Scanning third-party hosts without permission
may be illegal.
"""

from __future__ import annotations

from typing import Optional

import telnet_engine
from telnet_engine import (
    CONNECT_DEFAULT_TIMEOUT,
    DEFAULT_PORT,
    READ_DEFAULT_IDLE,
    READ_DEFAULT_MAX_BYTES,
    READ_DEFAULT_MAX_WAIT,
    SessionNotFound,
    TelnetError,
)

import nmap_engine
from nmap_engine import NMAP_DEFAULT_TIMEOUT
from curl_engine import (
    WEB_DEFAULT_TIMEOUT,
    WEB_MAX_BYTES,
    decode_body,
    parse_html,
    run_curl,
    validate_url,
)


async def telnet_connect(
    host: str,
    port: int = DEFAULT_PORT,
    timeout: float = CONNECT_DEFAULT_TIMEOUT,
    read_banner: bool = True,
) -> dict:
    """
    Open a telnet connection to a host and return a reusable session id.

    Opens a TCP telnet connection and keeps it alive as a persistent session.
    Use the returned ``session_id`` with `telnet_send`, `telnet_read`,
    `telnet_send_command`, and `telnet_close`. Telnet option negotiation is
    handled automatically (the client refuses all options and stays in plain
    line mode).

    Args:
        host: target hostname or IP address.
        port: TCP port to connect to (default 23).
        timeout: seconds to wait for the connection to establish (1–120).
        read_banner: if True, capture whatever the host sends on connect (login
            prompt, MOTD) and return it as ``banner``.

    Returns:
        dict with ``ok``, ``session_id``, ``host``, ``port``, ``peer`` and, when
        ``read_banner`` is set, the initial ``banner`` text.

    Only connect to hosts you own or are explicitly authorized to access.
    """
    try:
        res = await telnet_engine.connect(
            host, port, timeout=timeout, read_banner=read_banner
        )
    except TelnetError as e:
        return {"ok": False, "host": host, "port": port, "error": str(e)}
    res["ok"] = True
    return res


async def telnet_send(
    session_id: str,
    data: str,
    append_newline: bool = True,
    newline: str = "\r\n",
) -> dict:
    """
    Send text to an open telnet session without waiting for the reply.

    Writes ``data`` to the session and returns immediately. Call `telnet_read`
    afterwards to collect the response, or use `telnet_send_command` to do both
    in one step.

    Args:
        session_id: id returned by `telnet_connect`.
        data: text to send (e.g. a username, password, or command line).
        append_newline: append ``newline`` to the data so the remote acts on the
            line. Set False to send a raw fragment (e.g. a single keystroke).
        newline: line terminator to append; telnet convention is CRLF ("\\r\\n").

    Returns:
        dict with ``ok`` and ``bytes_sent`` — or ``ok: false`` with an error if
        the session id is unknown or the write failed.
    """
    try:
        return await telnet_engine.send(
            session_id, data, append_newline=append_newline, newline=newline
        )
    except SessionNotFound as e:
        return {"ok": False, "session_id": session_id, "error": str(e)}
    except TelnetError as e:
        return {"ok": False, "session_id": session_id, "error": str(e)}


async def telnet_read(
    session_id: str,
    idle_timeout: float = READ_DEFAULT_IDLE,
    max_wait: float = READ_DEFAULT_MAX_WAIT,
    max_bytes: int = READ_DEFAULT_MAX_BYTES,
) -> dict:
    """
    Read output from an open telnet session until the stream goes quiet.

    Telnet has no message boundaries, so reads are idle-based: this collects
    output and returns once the connection has been silent for ``idle_timeout``
    seconds, or the ``max_wait`` ceiling is hit, or ``max_bytes`` is reached, or
    the peer closes the connection. Tune ``idle_timeout`` up for slow hosts.

    Args:
        session_id: id returned by `telnet_connect`.
        idle_timeout: quiet period in seconds that ends the read (0.05–60).
        max_wait: hard ceiling in seconds on the whole read (0.1–300).
        max_bytes: stop after collecting this many bytes (≤ 8 MB).

    Returns:
        dict with ``ok``, ``data`` (decoded text), ``bytes``, ``eof`` (True if
        the peer hung up), and ``truncated``.
    """
    try:
        return await telnet_engine.read(
            session_id,
            idle_timeout=idle_timeout,
            max_wait=max_wait,
            max_bytes=max_bytes,
        )
    except SessionNotFound as e:
        return {"ok": False, "session_id": session_id, "error": str(e)}
    except TelnetError as e:
        return {"ok": False, "session_id": session_id, "error": str(e)}


async def telnet_send_command(
    session_id: str,
    command: str,
    append_newline: bool = True,
    newline: str = "\r\n",
    idle_timeout: float = READ_DEFAULT_IDLE,
    max_wait: float = READ_DEFAULT_MAX_WAIT,
    max_bytes: int = READ_DEFAULT_MAX_BYTES,
) -> dict:
    """
    Send a command to a telnet session and read the response in one call.

    The convenient default for prompt-driven interaction: it writes ``command``
    (with a trailing newline) and then reads until the host goes quiet. Equivalent
    to `telnet_send` followed by `telnet_read` against the same session.

    Args:
        session_id: id returned by `telnet_connect`.
        command: command line to send.
        append_newline: append ``newline`` so the host runs the command.
        newline: line terminator to append (default CRLF).
        idle_timeout: quiet period in seconds that ends the read (0.05–60).
        max_wait: hard ceiling in seconds on the read (0.1–300).
        max_bytes: cap on bytes returned (≤ 8 MB).

    Returns:
        dict with ``ok``, ``data`` (the response text), ``bytes``, ``bytes_sent``,
        ``eof``, and ``truncated``.
    """
    try:
        return await telnet_engine.send_and_read(
            session_id,
            command,
            append_newline=append_newline,
            newline=newline,
            idle_timeout=idle_timeout,
            max_wait=max_wait,
            max_bytes=max_bytes,
        )
    except SessionNotFound as e:
        return {"ok": False, "session_id": session_id, "error": str(e)}
    except TelnetError as e:
        return {"ok": False, "session_id": session_id, "error": str(e)}


async def telnet_list() -> dict:
    """
    List all currently open telnet sessions.

    Returns:
        dict with ``ok``, ``count``, and ``sessions`` — each entry has
        ``session_id``, ``peer``, ``host``, ``port``, ``age_seconds``,
        ``idle_seconds``, ``bytes_sent``, and ``bytes_received``.
    """
    sessions = telnet_engine.list_sessions()
    return {"ok": True, "count": len(sessions), "sessions": sessions}


async def telnet_close(session_id: str) -> dict:
    """
    Close an open telnet session and free its connection.

    Args:
        session_id: id returned by `telnet_connect`.

    Returns:
        dict with ``ok`` and ``closed`` — or ``ok: false`` if the id is unknown.
    """
    try:
        return await telnet_engine.close(session_id)
    except SessionNotFound as e:
        return {"ok": False, "session_id": session_id, "error": str(e)}


# ── Recon: nmap port/service scanning ────────────────────────────────────────


async def nmap_scan(
    host: str,
    ports: Optional[list] = None,
    top_ports: Optional[int] = None,
    service_detect: bool = True,
    os_detect: bool = False,
    skip_ping: bool = False,
    timeout: float = NMAP_DEFAULT_TIMEOUT,
) -> dict:
    """
    Scan a host with nmap and return parsed results (open ports, services, OS).

    The structured port-recon tool: it runs nmap with XML output parsed into
    clean JSON, so you get machine-readable fields instead of nmap's console
    text. Use it to discover what's listening before driving a service with
    `telnet_connect` or `http_fetch`.

    What it detects:
      * open TCP ports (default: nmap's top 100; pass `ports` or `top_ports`);
      * service + version per port when `service_detect` is on (nmap -sV);
      * an OS-family guess with accuracy when `os_detect` is on (nmap -O).

    Privileges: it uses a TCP connect scan (-sT), which works without root.
    `os_detect` (-O) needs root/raw sockets — without them nmap says so and that
    message is surfaced in `warnings`.

    Args:
        host: target hostname or IP address.
        ports: explicit ports to scan, e.g. [22, 23, 80]. Overrides top_ports.
        top_ports: scan nmap's N most common ports instead of a fixed list.
        service_detect: run service/version detection (-sV). Default True.
        os_detect: attempt OS fingerprinting (-O). Needs root. Default False.
        skip_ping: treat the host as up and skip host discovery (-Pn). Useful
            for hosts that drop ICMP.
        timeout: overall nmap timeout in seconds (5–300).

    Returns:
        dict with ok, the host record(s) (address, state, open_ports with
        service/version, os_matches), the exact nmap argv, and any warnings.
        Only scan hosts you own or are authorized to test.
    """
    return await nmap_engine.scan(
        host,
        ports=ports,
        top_ports=top_ports,
        service_detect=service_detect,
        os_detect=os_detect,
        skip_ping=skip_ping,
        timeout=timeout,
    )


# ── Recon: HTTP fetching / scraping via curl ─────────────────────────────────


async def http_fetch(
    url: str,
    method: str = "GET",
    headers: Optional[dict] = None,
    data: Optional[str] = None,
    timeout: float = WEB_DEFAULT_TIMEOUT,
    follow_redirects: bool = True,
    max_bytes: int = WEB_MAX_BYTES,
    insecure: bool = False,
) -> dict:
    """
    Fetch a URL with curl and return the raw HTTP response.

    A thin, scriptable curl wrapper for probing web services and APIs found
    during recon: returns the status code, response headers, final URL (after
    redirects), and the decoded body. Body is capped at 5 MB. Use `web_scrape`
    instead if you want parsed text/links rather than raw markup.

    Args:
        url: http(s) URL to fetch.
        method: HTTP method (GET, HEAD, POST, PUT, DELETE, PATCH, OPTIONS).
        headers: optional dict of request headers, e.g. {"Authorization": "..."}.
        data: optional request body (for POST/PUT/PATCH).
        timeout: total request timeout in seconds (1–60).
        follow_redirects: follow 3xx redirects (up to 10 hops).
        max_bytes: cap on downloaded body size (≤ 5 MB).
        insecure: skip TLS certificate verification (curl -k). Use with care.

    Returns:
        dict with ok, status, final_url, headers, content_type, and body.
    """
    url = validate_url(url)
    res = await run_curl(
        url,
        method=method,
        headers=headers,
        data=data,
        timeout=timeout,
        follow_redirects=follow_redirects,
        max_bytes=max_bytes,
        insecure=insecure,
    )
    if not res.ok and res.error and res.status == 0:
        return {
            "url": url,
            "ok": False,
            "error": res.error,
            "timed_out": res.timed_out,
        }
    body_text = decode_body(res.body, res.content_type)
    return {
        "url": url,
        "ok": res.ok,
        "status": res.status,
        "final_url": res.final_url,
        "content_type": res.content_type,
        "headers": res.headers,
        "bytes": len(res.body),
        "body": body_text,
        "timed_out": res.timed_out,
    }


async def web_scrape(
    url: str,
    timeout: float = WEB_DEFAULT_TIMEOUT,
    max_links: int = 100,
    max_text_chars: int = 20000,
    insecure: bool = False,
) -> dict:
    """
    Fetch a web page with curl and extract its title, visible text, and links.

    Downloads the page (following redirects), strips scripts/styles/markup, and
    returns clean readable text plus absolutised links — handy for fingerprinting
    a web service turned up by `nmap_scan`. For non-HTML responses the raw body
    is returned as text.

    Args:
        url: http(s) URL to scrape.
        timeout: total request timeout in seconds (1–60).
        max_links: cap on the number of links returned.
        max_text_chars: cap on extracted text length.
        insecure: skip TLS certificate verification (curl -k).

    Returns:
        dict with status, final_url, title, text, and links.
    """
    url = validate_url(url)
    res = await run_curl(
        url, timeout=timeout, follow_redirects=True, insecure=insecure
    )
    if not res.ok and res.status == 0:
        return {"url": url, "ok": False, "error": res.error, "timed_out": res.timed_out}

    body_text = decode_body(res.body, res.content_type)
    is_html = "html" in res.content_type.lower() or "<html" in body_text[:1000].lower()

    if not is_html:
        return {
            "url": url,
            "ok": res.ok,
            "status": res.status,
            "final_url": res.final_url,
            "content_type": res.content_type,
            "title": "",
            "text": body_text[:max_text_chars],
            "links": [],
            "note": "Non-HTML response returned as raw text.",
        }

    parsed = parse_html(body_text, base_url=res.final_url)
    return {
        "url": url,
        "ok": res.ok,
        "status": res.status,
        "final_url": res.final_url,
        "content_type": res.content_type,
        "title": parsed["title"],
        "text": parsed["text"][:max_text_chars],
        "text_truncated": len(parsed["text"]) > max_text_chars,
        "link_count": len(parsed["links"]),
        "links": parsed["links"][:max_links],
    }


# All tools exposed by this server, in registration order.
ALL_TOOLS = [
    telnet_connect,
    telnet_send,
    telnet_read,
    telnet_send_command,
    telnet_list,
    telnet_close,
    nmap_scan,
    http_fetch,
    web_scrape,
]


def register(mcp) -> None:
    """Attach every tool in ALL_TOOLS to a FastMCP instance."""
    for fn in ALL_TOOLS:
        mcp.tool()(fn)
