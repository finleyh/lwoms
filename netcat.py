#!/usr/bin/env python3
"""
netcat.py — low-level helpers for netcat-mcp.

Everything in here is MCP-agnostic: subprocess wrapper around the `nc` binary,
input validation, banner decoding, and OS heuristics. The MCP tool definitions
live in ``tools.py`` and the server entry point in ``server.py``.
"""

from __future__ import annotations

import asyncio
import ipaddress
import os
import re
import shutil
from dataclasses import dataclass, field
from typing import Optional


def _env_int(name: str, default: int) -> int:
    """Read an int from the environment, falling back to ``default``.

    Empty or malformed values are ignored so a stray ``FOO=`` can't crash boot.
    """
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
# Every knob below is overridable via an environment variable (or .env entry),
# so deployments can tighten/loosen limits without editing code. Defaults match
# the original hard-coded values.

NC_BIN = os.getenv("NETCAT_MCP_NC_BIN") or shutil.which("nc") or "nc"

# Hard ceilings so a single tool call can never become an aggressive scan.
MAX_TIMEOUT = _env_int("NETCAT_MCP_MAX_TIMEOUT", 15)              # seconds per nc connection
DEFAULT_TIMEOUT = _env_int("NETCAT_MCP_DEFAULT_TIMEOUT", 4)
MAX_PAYLOAD_BYTES = _env_int("NETCAT_MCP_MAX_PAYLOAD_BYTES", 8192)  # cap on raw_send_recv payload
MAX_RECV_BYTES = _env_int("NETCAT_MCP_MAX_RECV_BYTES", 65536)       # cap on captured reply size

# Well-known services used to *profile* a host. Deliberately small.
# Includes common VoIP / telephony control ports (SIP, Asterisk AMI, IAX2,
# Cisco SCCP, FreeSWITCH ESL, H.323). Note: these are scanned over TCP — SIP
# and IAX2 frequently run on UDP, so a "closed" result for 5060/4569 doesn't
# rule out a UDP listener.
WELL_KNOWN_SERVICES: dict[int, str] = {
    21: "ftp",
    22: "ssh",
    23: "telnet",
    25: "smtp",
    53: "dns",
    80: "http",
    110: "pop3",
    143: "imap",
    443: "https",
    445: "smb",
    1720: "h323",            # VoIP — H.323 call signalling (H.225)
    2000: "sccp",            # VoIP — Cisco SCCP / "Skinny"
    3306: "mysql",
    3389: "rdp",
    4569: "iax2",            # VoIP — Inter-Asterisk eXchange (often UDP)
    5038: "asterisk-ami",    # VoIP — Asterisk Manager Interface
    5060: "sip",             # VoIP — SIP (often UDP as well)
    5061: "sip-tls",         # VoIP — SIP over TLS
    5432: "postgresql",
    6379: "redis",
    8021: "freeswitch-esl",  # VoIP — FreeSWITCH Event Socket
    8080: "http-alt",
}

# A probe to elicit a banner from common services that wait for client input.
SERVICE_PROBES: dict[int, bytes] = {
    80: b"HEAD / HTTP/1.0\r\n\r\n",
    8080: b"HEAD / HTTP/1.0\r\n\r\n",
    443: b"HEAD / HTTP/1.0\r\n\r\n",
    6379: b"INFO\r\n",
}

# --------------------------------------------------------------------------- #
# Validation helpers
# --------------------------------------------------------------------------- #

_HOSTNAME_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))*$"
)


def validate_host(host: str) -> str:
    host = (host or "").strip()
    if not host:
        raise ValueError("host must not be empty")
    try:
        ipaddress.ip_address(host)
        return host
    except ValueError:
        pass
    if _HOSTNAME_RE.match(host):
        return host
    raise ValueError(f"invalid host: {host!r}")


def validate_port(port: int) -> int:
    if not isinstance(port, int) or not (1 <= port <= 65535):
        raise ValueError(f"port must be 1-65535, got {port!r}")
    return port


def clamp_timeout(timeout: float) -> float:
    return max(0.5, min(float(timeout), MAX_TIMEOUT))


# --------------------------------------------------------------------------- #
# Core: shell out to nc
# --------------------------------------------------------------------------- #


@dataclass
class NcResult:
    open: bool
    stdout: bytes = b""
    stderr: str = ""
    timed_out: bool = False
    cmd: list[str] = field(default_factory=list)


async def run_nc(
    host: str,
    port: int,
    *,
    payload: Optional[bytes] = None,
    timeout: float = DEFAULT_TIMEOUT,
    udp: bool = False,
    scan: bool = False,
) -> NcResult:
    """
    Invoke `nc` against host:port.

    Uses:  nc -v -w <timeout> [-u] [-z] host port

    Three modes:
      * scan=True            → add -z (zero-I/O): just open/close to test the
                               port. Fast, used by port_scan.
      * payload is None      → connect and READ whatever the server sends
                               (banner grab for chatty services like SSH/SMTP).
      * payload is not None  → pipe payload to stdin, then read the reply.
    """
    timeout = clamp_timeout(timeout)
    cmd = [NC_BIN, "-v", "-w", str(int(timeout))]
    if udp:
        cmd.append("-u")
    if scan:
        cmd.append("-z")  # zero-I/O scan; no banner read
    cmd += [host, str(port)]

    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdin=asyncio.subprocess.PIPE if payload is not None else asyncio.subprocess.DEVNULL,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
    except FileNotFoundError:
        return NcResult(open=False, stderr="nc binary not found on PATH", cmd=cmd)

    # Give the whole process a little longer than the connect timeout.
    wall = timeout + 3
    try:
        stdout, stderr = await asyncio.wait_for(
            proc.communicate(input=payload), timeout=wall
        )
    except asyncio.TimeoutError:
        proc.kill()
        await proc.wait()
        return NcResult(open=False, timed_out=True, cmd=cmd)

    stderr_text = stderr.decode("utf-8", "replace")
    # nc -v reports success on stderr: "... open" / "succeeded!" / "Connected"
    is_open = (
        bool(re.search(r"open|succeeded|Connected to", stderr_text, re.IGNORECASE))
        or bool(stdout)
        or (proc.returncode == 0 and not scan)
    )

    return NcResult(
        open=is_open,
        stdout=stdout[:MAX_RECV_BYTES] if stdout else b"",
        stderr=stderr_text.strip(),
        cmd=cmd,
    )


def decode_banner(data: bytes) -> str:
    if not data:
        return ""
    text = data.decode("utf-8", "replace")
    # Keep it readable: collapse trailing whitespace, cap length.
    return text.strip()[:2000]


# --------------------------------------------------------------------------- #
# OS heuristics
# --------------------------------------------------------------------------- #

_OS_BANNER_HINTS = [
    (re.compile(r"ubuntu", re.I), "Linux (Ubuntu)"),
    (re.compile(r"debian", re.I), "Linux (Debian)"),
    (re.compile(r"centos|red ?hat|rhel|fedora", re.I), "Linux (RHEL/CentOS/Fedora)"),
    (re.compile(r"\braspbian\b", re.I), "Linux (Raspbian)"),
    (re.compile(r"openssh.*linux|linux", re.I), "Linux"),
    (re.compile(r"microsoft|win32|win64|windows|iis", re.I), "Windows"),
    (re.compile(r"freebsd", re.I), "FreeBSD"),
    (re.compile(r"openbsd", re.I), "OpenBSD"),
    (re.compile(r"darwin|mac ?os", re.I), "macOS"),
    (re.compile(r"cisco|mikrotik|routeros|juniper", re.I), "Network device"),
]


def os_from_banner(banner: str) -> Optional[str]:
    for pat, label in _OS_BANNER_HINTS:
        if pat.search(banner):
            return label
    return None


def os_from_ttl(ttl: int) -> Optional[str]:
    # Common initial TTLs: Linux/Unix 64, Windows 128, network gear 255.
    if ttl <= 0:
        return None
    if ttl <= 64:
        return "Linux/Unix-like (TTL≈64)"
    if ttl <= 128:
        return "Windows (TTL≈128)"
    return "Network device / other (TTL≈255)"


async def ping_ttl(host: str, timeout: float = 3) -> Optional[int]:
    """Send one ICMP echo and parse the observed TTL. Best-effort."""
    cmd = ["ping", "-c", "1", "-W", str(int(max(1, timeout))), host]
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        out, _ = await asyncio.wait_for(proc.communicate(), timeout=timeout + 2)
    except (asyncio.TimeoutError, FileNotFoundError):
        return None
    m = re.search(r"ttl=(\d+)", out.decode("utf-8", "replace"), re.IGNORECASE)
    return int(m.group(1)) if m else None
