#!/usr/bin/env python3
"""
curl.py — low-level curl helpers for netcat-mcp's web-scraping tools.

MCP-agnostic, mirroring ``netcat.py``: a subprocess wrapper around the `curl`
binary plus small stdlib-only HTML parsers (title, links, visible text). The
tool definitions that use these live in ``tools.py``.
"""

from __future__ import annotations

import asyncio
import os
import re
import shutil
from dataclasses import dataclass, field
from html.parser import HTMLParser
from typing import Optional
from urllib.parse import urljoin, urlparse


def _env_int(name: str, default: int) -> int:
    """Read an int from the environment, falling back to ``default``."""
    raw = os.getenv(name)
    if raw is None or raw.strip() == "":
        return default
    try:
        return int(raw)
    except ValueError:
        return default


# --------------------------------------------------------------------------- #
# Configuration / safety limits
# --------------------------------------------------------------------------- #
# Overridable via environment variables (or .env). Defaults match the original
# hard-coded values.

CURL_BIN = os.getenv("NETCAT_MCP_CURL_BIN") or shutil.which("curl") or "curl"

WEB_DEFAULT_TIMEOUT = _env_int("NETCAT_MCP_WEB_DEFAULT_TIMEOUT", 15)  # seconds for a whole request
WEB_MAX_TIMEOUT = _env_int("NETCAT_MCP_WEB_MAX_TIMEOUT", 60)
WEB_MAX_REDIRECTS = _env_int("NETCAT_MCP_WEB_MAX_REDIRECTS", 10)
WEB_MAX_BYTES = _env_int("NETCAT_MCP_WEB_MAX_BYTES", 5_000_000)       # 5 MB hard cap on downloaded body
DEFAULT_USER_AGENT = os.getenv("NETCAT_MCP_USER_AGENT") or "netcat-mcp/1.0 (+curl)"
ALLOWED_METHODS = {"GET", "HEAD", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"}
ALLOWED_SCHEMES = {"http", "https"}


# --------------------------------------------------------------------------- #
# Validation
# --------------------------------------------------------------------------- #


def validate_url(url: str) -> str:
    url = (url or "").strip()
    if not url:
        raise ValueError("url must not be empty")
    parsed = urlparse(url)
    if parsed.scheme.lower() not in ALLOWED_SCHEMES:
        raise ValueError(f"url scheme must be http/https, got {parsed.scheme!r}")
    if not parsed.netloc:
        raise ValueError(f"url has no host: {url!r}")
    return url


def clamp_web_timeout(timeout: float) -> float:
    return max(1.0, min(float(timeout), WEB_MAX_TIMEOUT))


# --------------------------------------------------------------------------- #
# Core: shell out to curl
# --------------------------------------------------------------------------- #


@dataclass
class CurlResult:
    ok: bool
    status: int = 0
    final_url: str = ""
    headers: dict[str, str] = field(default_factory=dict)
    body: bytes = b""
    content_type: str = ""
    error: str = ""
    timed_out: bool = False
    cmd: list[str] = field(default_factory=list)


def _parse_last_header_block(raw_headers: str) -> tuple[int, dict[str, str]]:
    """Parse the final response header block (curl -L emits one per hop)."""
    blocks = [b for b in re.split(r"\r?\n\r?\n", raw_headers) if b.strip()]
    if not blocks:
        return 0, {}
    last = blocks[-1].splitlines()
    status = 0
    if last and last[0].upper().startswith("HTTP/"):
        m = re.search(r"\s(\d{3})\s", last[0] + " ")
        if m:
            status = int(m.group(1))
    headers: dict[str, str] = {}
    for line in last[1:]:
        if ":" in line:
            k, v = line.split(":", 1)
            headers[k.strip().lower()] = v.strip()
    return status, headers


async def run_curl(
    url: str,
    *,
    method: str = "GET",
    headers: Optional[dict[str, str]] = None,
    data: Optional[str] = None,
    timeout: float = WEB_DEFAULT_TIMEOUT,
    follow_redirects: bool = True,
    max_bytes: int = WEB_MAX_BYTES,
    user_agent: str = DEFAULT_USER_AGENT,
    insecure: bool = False,
) -> CurlResult:
    """
    Fetch ``url`` with curl and return status, headers, and body.

    Builds:  curl -sS -D <headerfile> [-L] [-X METHOD] [-H ...] [--data ...]
                  -A <ua> --max-time <t> --max-filesize <n> -o <bodyfile> url
    Headers are written to a temp file and parsed so the body stays clean.
    """
    import tempfile
    import os

    timeout = clamp_web_timeout(timeout)
    method = method.upper()
    if method not in ALLOWED_METHODS:
        raise ValueError(f"unsupported method {method!r}")
    max_bytes = max(1, min(int(max_bytes), WEB_MAX_BYTES))

    hdr_fd, hdr_path = tempfile.mkstemp(prefix="ncmcp_hdr_")
    body_fd, body_path = tempfile.mkstemp(prefix="ncmcp_body_")
    os.close(hdr_fd)
    os.close(body_fd)

    cmd = [
        CURL_BIN,
        "-sS",                      # silent but show errors
        "-D", hdr_path,             # dump headers here
        "-o", body_path,            # body here (keeps stdout clean)
        "-A", user_agent,
        "--max-time", str(int(timeout)),
        "--max-filesize", str(max_bytes),
        "-X", method,
    ]
    if follow_redirects:
        cmd += ["-L", "--max-redirs", str(WEB_MAX_REDIRECTS)]
    if insecure:
        cmd.append("-k")
    for k, v in (headers or {}).items():
        cmd += ["-H", f"{k}: {v}"]
    if data is not None:
        cmd += ["--data-binary", data]
    # Print the effective URL after redirects on stdout for capture.
    cmd += ["-w", "%{url_effective}", url]

    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        try:
            stdout, stderr = await asyncio.wait_for(
                proc.communicate(), timeout=timeout + 5
            )
        except asyncio.TimeoutError:
            proc.kill()
            await proc.wait()
            return CurlResult(ok=False, timed_out=True, error="request timed out", cmd=cmd)

        rc = proc.returncode
        final_url = stdout.decode("utf-8", "replace").strip()
        try:
            with open(hdr_path, "r", encoding="utf-8", errors="replace") as f:
                raw_headers = f.read()
        except OSError:
            raw_headers = ""
        try:
            with open(body_path, "rb") as f:
                body = f.read(WEB_MAX_BYTES)
        except OSError:
            body = b""
    finally:
        for p in (hdr_path, body_path):
            try:
                os.unlink(p)
            except OSError:
                pass

    if rc != 0 and not raw_headers:
        return CurlResult(
            ok=False,
            error=stderr.decode("utf-8", "replace").strip() or f"curl exited {rc}",
            final_url=final_url,
            cmd=cmd,
        )

    status, hdrs = _parse_last_header_block(raw_headers)
    return CurlResult(
        ok=200 <= status < 400 if status else rc == 0,
        status=status,
        final_url=final_url or url,
        headers=hdrs,
        body=body,
        content_type=hdrs.get("content-type", ""),
        error="" if rc == 0 else stderr.decode("utf-8", "replace").strip(),
        cmd=cmd,
    )


# --------------------------------------------------------------------------- #
# HTML parsing (stdlib only)
# --------------------------------------------------------------------------- #

_SKIP_TEXT_TAGS = {"script", "style", "noscript", "template", "head"}


class _Scraper(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.title: str = ""
        self._in_title = False
        self._skip_depth = 0
        self._text_parts: list[str] = []
        self.links: list[tuple[str, str]] = []  # (href, anchor_text)
        self._cur_href: Optional[str] = None
        self._cur_anchor: list[str] = []

    def handle_starttag(self, tag: str, attrs):
        if tag in _SKIP_TEXT_TAGS:
            self._skip_depth += 1
        if tag == "title":
            self._in_title = True
        if tag == "a":
            href = dict(attrs).get("href")
            if href:
                self._cur_href = href
                self._cur_anchor = []

    def handle_endtag(self, tag: str):
        if tag in _SKIP_TEXT_TAGS and self._skip_depth > 0:
            self._skip_depth -= 1
        if tag == "title":
            self._in_title = False
        if tag == "a" and self._cur_href is not None:
            self.links.append((self._cur_href, " ".join(self._cur_anchor).strip()))
            self._cur_href = None
            self._cur_anchor = []

    def handle_data(self, data: str):
        if self._in_title:
            self.title += data
        if self._skip_depth == 0:
            stripped = data.strip()
            if stripped:
                self._text_parts.append(stripped)
        if self._cur_href is not None:
            t = data.strip()
            if t:
                self._cur_anchor.append(t)

    @property
    def text(self) -> str:
        return re.sub(r"\n{3,}", "\n\n", "\n".join(self._text_parts)).strip()


def parse_html(html: str, base_url: str = "") -> dict:
    """Return {title, text, links} from an HTML string. Links are absolutised."""
    p = _Scraper()
    try:
        p.feed(html)
    except Exception:
        pass  # tolerate malformed markup; return whatever parsed
    links = []
    seen = set()
    for href, anchor in p.links:
        full = urljoin(base_url, href) if base_url else href
        if full not in seen:
            seen.add(full)
            links.append({"url": full, "text": anchor[:200]})
    return {
        "title": p.title.strip()[:300],
        "text": p.text,
        "links": links,
    }


def decode_body(body: bytes, content_type: str = "") -> str:
    """Decode response bytes to str, honoring a charset hint if present."""
    charset = "utf-8"
    m = re.search(r"charset=([\w-]+)", content_type, re.IGNORECASE)
    if m:
        charset = m.group(1)
    try:
        return body.decode(charset, "replace")
    except LookupError:
        return body.decode("utf-8", "replace")
