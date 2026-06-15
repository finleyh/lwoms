#!/usr/bin/env python3
"""
tools.py — MCP tool definitions for netcat-mcp.

Each tool is a plain async function built on the helpers in ``netcat.py``.
``register(mcp)`` attaches them to a FastMCP instance, keeping the tool
definitions decoupled from server construction/transport (see ``server.py``).
"""

from __future__ import annotations

import asyncio
from typing import Optional

from netcat import (
    DEFAULT_TIMEOUT,
    MAX_PAYLOAD_BYTES,
    SERVICE_PROBES,
    WELL_KNOWN_SERVICES,
    clamp_timeout,
    decode_banner,
    os_from_banner,
    os_from_ttl,
    ping_ttl,
    run_nc,
    validate_host,
    validate_port,
)
from curl import (
    WEB_DEFAULT_TIMEOUT,
    WEB_MAX_BYTES,
    decode_body,
    parse_html,
    run_curl,
    validate_url,
)


async def port_scan(host: str, timeout: float = DEFAULT_TIMEOUT) -> dict:
    """
    Profile a host by checking a small set of well-known service ports.

    Connects (via `nc -z`) to common ports (ssh, http, https, smb, mysql, etc.)
    and reports which are open. Intended for quick device profiling, NOT a full
    65k-port sweep. Scan hosts you own or are authorized to test.

    Args:
        host: target hostname or IP address.
        timeout: per-port connect timeout in seconds (0.5–15).

    Returns:
        dict with the target, a list of open services, and the full per-port map.
    """
    host = validate_host(host)
    timeout = clamp_timeout(timeout)

    async def probe(port: int, name: str) -> tuple[int, str, bool]:
        res = await run_nc(host, port, timeout=timeout, scan=True)
        return port, name, res.open

    results = await asyncio.gather(
        *(probe(p, n) for p, n in WELL_KNOWN_SERVICES.items())
    )

    ports = [
        {"port": p, "service": n, "state": "open" if is_open else "closed/filtered"}
        for p, n, is_open in sorted(results)
    ]
    open_services = [
        {"port": p["port"], "service": p["service"]}
        for p in ports
        if p["state"] == "open"
    ]
    return {
        "host": host,
        "scanned_ports": len(WELL_KNOWN_SERVICES),
        "open_count": len(open_services),
        "open_services": open_services,
        "ports": ports,
        "note": "Well-known-service profile only; not an exhaustive scan.",
    }


async def banner_grab(host: str, port: int, timeout: float = DEFAULT_TIMEOUT) -> dict:
    """
    Connect to host:port and capture the service banner.

    For services that speak first (SSH, FTP, SMTP, etc.) the banner is read
    directly. For request-driven services (HTTP/Redis) a minimal, safe probe
    is sent to elicit a response.

    Args:
        host: target hostname or IP address.
        port: target TCP port (1–65535).
        timeout: connect/read timeout in seconds (0.5–15).

    Returns:
        dict with the captured banner (if any) and whether the port was open.
    """
    host = validate_host(host)
    port = validate_port(port)
    timeout = clamp_timeout(timeout)

    probe = SERVICE_PROBES.get(port)
    # First try: read whatever the server sends (with optional probe).
    res = await run_nc(host, port, payload=probe, timeout=timeout)

    banner = decode_banner(res.stdout)
    # If nothing came back but the port is open and we sent no probe, retry
    # with a generic newline nudge for chatty line-based services.
    if res.open and not banner and probe is None:
        res2 = await run_nc(host, port, payload=b"\r\n", timeout=timeout)
        banner = decode_banner(res2.stdout)

    return {
        "host": host,
        "port": port,
        "service": WELL_KNOWN_SERVICES.get(port, "unknown"),
        "open": res.open or bool(banner),
        "banner": banner,
        "banner_present": bool(banner),
    }


async def raw_send_recv(
    host: str,
    port: int,
    data: str,
    timeout: float = DEFAULT_TIMEOUT,
    udp: bool = False,
    append_crlf: bool = True,
) -> dict:
    """
    Send arbitrary text to host:port over netcat and return the reply.

    A generic nc pipe: useful for poking custom protocols, testing APIs at the
    socket level, or sending a crafted request. Payload is capped at 8 KB.

    Args:
        host: target hostname or IP address.
        port: target port (1–65535).
        data: text payload to send. Use \\r\\n / \\n for line breaks.
        timeout: connect/read timeout in seconds (0.5–15).
        udp: send over UDP instead of TCP.
        append_crlf: append CRLF to the payload if not already present.

    Returns:
        dict with the decoded reply and byte counts.
    """
    host = validate_host(host)
    port = validate_port(port)
    timeout = clamp_timeout(timeout)

    payload = data.encode("utf-8", "replace")
    if append_crlf and not payload.endswith((b"\n", b"\r\n")):
        payload += b"\r\n"
    if len(payload) > MAX_PAYLOAD_BYTES:
        raise ValueError(f"payload too large ({len(payload)} > {MAX_PAYLOAD_BYTES} bytes)")

    res = await run_nc(host, port, payload=payload, timeout=timeout, udp=udp)
    reply = decode_banner(res.stdout)
    return {
        "host": host,
        "port": port,
        "protocol": "udp" if udp else "tcp",
        "sent_bytes": len(payload),
        "open": res.open or bool(reply),
        "reply": reply,
        "reply_bytes": len(res.stdout),
        "timed_out": res.timed_out,
    }


async def os_fingerprint(host: str, timeout: float = DEFAULT_TIMEOUT) -> dict:
    """
    Best-effort OS guess for a host (HEURISTIC — not definitive).

    Combines two weak signals: (1) banners grabbed from any open well-known
    ports (OpenSSH/HTTP server strings often name the distro/OS), and (2) the
    ICMP echo TTL, whose common initial values differ by OS family. True OS
    fingerprinting requires TCP/IP stack analysis (e.g. nmap -O) which netcat
    cannot do; treat this as a hint only.

    Args:
        host: target hostname or IP address.
        timeout: per-probe timeout in seconds (0.5–15).

    Returns:
        dict with a guessed OS, a confidence label, and the evidence used.
    """
    host = validate_host(host)
    timeout = clamp_timeout(timeout)

    evidence: list[str] = []
    guesses: list[str] = []

    # Signal 1: TTL via ping.
    ttl = await ping_ttl(host, timeout=timeout)
    if ttl is not None:
        evidence.append(f"icmp_ttl={ttl}")
        g = os_from_ttl(ttl)
        if g:
            guesses.append(g)

    # Signal 2: banners from a few revealing ports.
    banner_ports = [22, 80, 443, 21, 25, 8080]
    grabbed: dict[int, str] = {}

    async def grab(p: int) -> tuple[int, str]:
        probe = SERVICE_PROBES.get(p)
        res = await run_nc(host, p, payload=probe, timeout=timeout)
        return p, decode_banner(res.stdout)

    for p, banner in await asyncio.gather(*(grab(p) for p in banner_ports)):
        if banner:
            grabbed[p] = banner
            g = os_from_banner(banner)
            if g:
                guesses.append(g)
                evidence.append(f"port {p} banner → {g}")

    # Pick the most specific guess (prefer a banner-derived one over TTL).
    banner_guesses = [g for g in guesses if "TTL" not in g]
    if banner_guesses:
        os_guess = banner_guesses[0]
        confidence = "medium" if len(set(banner_guesses)) == 1 else "low"
    elif guesses:
        os_guess = guesses[0]
        confidence = "low"
    else:
        os_guess = "unknown"
        confidence = "none"

    return {
        "host": host,
        "os_guess": os_guess,
        "confidence": confidence,
        "evidence": evidence,
        "banners": grabbed,
        "disclaimer": (
            "Heuristic only (banner + TTL). For reliable OS detection use "
            "active stack fingerprinting such as `nmap -O`."
        ),
    }


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

    A thin, scriptable curl wrapper for web scraping and API probing: returns
    the status code, response headers, final URL (after redirects), and the
    decoded body. Body is capped at 5 MB. Use `web_scrape` instead if you want
    parsed text/links rather than raw markup.

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
    returns clean readable text plus absolutised links — the typical building
    block for scraping. For non-HTML responses the raw body is returned as text.

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
    port_scan,
    banner_grab,
    raw_send_recv,
    os_fingerprint,
    http_fetch,
    web_scrape,
]


def register(mcp) -> None:
    """Attach every tool in ALL_TOOLS to a FastMCP instance."""
    for fn in ALL_TOOLS:
        mcp.tool()(fn)
