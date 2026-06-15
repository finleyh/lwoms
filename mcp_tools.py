#!/usr/bin/env python3
"""
mcp_tools.py — the MCP tool definitions exposed by this server.

This is the MCP-facing layer. Each tool is a plain async function that wraps one
of the engine modules and shapes its result for the client. ``register(mcp)``
attaches them to a FastMCP instance, keeping the tool definitions decoupled from
server construction/transport (see ``server.py``).

Engines used:
  * nmap_engine — structured nmap scan / OS detection (`nmap_scan`)
  * curl_engine — HTTP fetching + HTML scraping (`http_fetch`, `web_scrape`)
  * bash_engine — guarded bash command runner (`bash_exec`)
"""

from __future__ import annotations

from typing import Optional

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
from bash_engine import (
    BASH_DEFAULT_TIMEOUT,
    CommandNotAllowed,
    run_bash,
)


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

    This is the structured scanning + OS-detection tool, backed by nmap with XML
    output parsed into JSON. Use it instead of hand-running nmap when you want
    clean, machine-readable fields rather than nmap's console text.

    What it detects:
      * open TCP ports (default: nmap's top 100; pass `ports` or `top_ports`);
      * service + version per port when `service_detect` is on (nmap -sV);
      * an OS-family guess with accuracy when `os_detect` is on (nmap -O).

    Privileges: it uses a TCP connect scan (-sT), which works without root.
    `os_detect` (-O) needs root/raw sockets — without them nmap will say so and
    that message is surfaced in `warnings`.

    Args:
        host: target hostname or IP address.
        ports: explicit ports to scan, e.g. [22, 80, 5038]. Overrides top_ports.
        top_ports: scan nmap's N most common ports instead of a fixed list.
        service_detect: run service/version detection (-sV). Default True.
        os_detect: attempt OS fingerprinting (-O). Needs root. Default False.
        skip_ping: treat the host as up and skip host discovery (-Pn). Useful
            for hosts that drop ICMP.
        timeout: overall nmap timeout in seconds (5–300).

    Returns:
        dict with ok, the host record(s) (address, state, open_ports with
        service/version, os_matches), the exact nmap argv, and any warnings.
        Only hosts you own or are authorized to test should be scanned.
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


async def bash_exec(
    command: str,
    timeout: float = BASH_DEFAULT_TIMEOUT,
    cwd: Optional[str] = None,
    stdin: Optional[str] = None,
) -> dict:
    """
    Run an arbitrary bash command and return stdout, stderr, and the exit code.

    This is the general "leverage bash" tool: pass any shell command — including
    pipelines — and get the captured result. It is the right tool when you want
    to script multi-step administrative actions, e.g. piping a sequence of
    printf payloads into netcat to drive a line protocol:

        ( printf 'Action: Login\\r\\nUsername: admin\\r\\nSecret: ***\\r\\n\\r\\n'; \\
          sleep 1; \\
          printf 'Action: Command\\r\\nCommand: database show\\r\\n\\r\\n'; \\
          sleep 5 ) | nc -w 8 <ip> <port>

    Construct the pipeline as you would by hand and pass it as `command`. Keep
    CRLF (\\r\\n) line endings for line protocols like AMI, and quote payloads
    carefully when a secret contains shell metacharacters.

    The command runs through `bash -c` in its own process group, is bounded by
    `timeout` seconds, and stdout/stderr are each capped (256 KB by default).

    Allowlist: every command invoked must be on the configured allowlist (default
    covers nmap, nc, ping, printf, sleep, curl, dig, and similar network-admin
    tools). Command substitution ($(...), backticks) is rejected. Requests that
    invoke anything else come back with `blocked: true` and an explanation rather
    than running. Adjust the list with NETADMIN_MCP_ALLOWED_CMDS.

    Args:
        command: the bash command/script to execute.
        timeout: wall-clock limit in seconds (1–120).
        cwd: optional working directory to run in.
        stdin: optional text piped to the command's standard input.

    Returns:
        dict with command, exit_code, stdout, stderr, timed_out, and truncation
        flags — or {blocked: true, error: ...} if the allowlist rejected it.

    Safety: this executes shell commands on the machine running the server. The
    allowlist is a guard rail, not a sandbox — only enable this server where
    running shell commands is acceptable, and target only hosts you are
    authorized to administer.
    """
    try:
        res = await run_bash(command, timeout=timeout, cwd=cwd, stdin=stdin)
    except CommandNotAllowed as e:
        return {"command": command, "blocked": True, "error": str(e)}
    return {
        "command": res.command,
        "exit_code": res.returncode,
        "stdout": res.stdout,
        "stderr": res.stderr,
        "timed_out": res.timed_out,
        "stdout_truncated": res.stdout_truncated,
        "stderr_truncated": res.stderr_truncated,
    }


# All tools exposed by this server, in registration order.
ALL_TOOLS = [
    nmap_scan,
    http_fetch,
    web_scrape,
    bash_exec,
]


def register(mcp) -> None:
    """Attach every tool in ALL_TOOLS to a FastMCP instance."""
    for fn in ALL_TOOLS:
        mcp.tool()(fn)
