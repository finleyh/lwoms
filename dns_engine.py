#!/usr/bin/env python3
"""
dns_engine.py — a small subprocess wrapper around ``dig`` for DNS lookups.

Two operations back the MCP tools:

  * ``lookup(name, record_type)``  — forward DNS: resolve a domain to records of
    a given type (A, AAAA, MX, NS, TXT, CNAME, SOA, SRV, CAA, …).
  * ``reverse(ip)``                — reverse DNS: the PTR record(s) for an IP,
    whose hostname frequently reveals the hosting / telco / VPN provider.

It shells out to ``dig`` (BIND's lookup tool, usually packaged as ``dnsutils``
or ``bind-tools``), parses dig's ``+noall +answer`` answer section into clean
records, and bounds every call with a timeout. Like the nmap/curl engines, this
assumes the external binary is installed on the machine running the server.
"""

from __future__ import annotations

import asyncio
import ipaddress
import os
import re
import shutil
from dataclasses import dataclass

# ── Config (env-overridable) ─────────────────────────────────────────────────
DIG_BIN = os.getenv("TELNET_MCP_DIG_BIN") or shutil.which("dig") or "dig"


def _env_int(name: str, default: int) -> int:
    try:
        return int(os.getenv(name, str(default)))
    except (TypeError, ValueError):
        return default


DNS_DEFAULT_TIMEOUT = _env_int("TELNET_MCP_DNS_DEFAULT_TIMEOUT", 10)  # seconds
DNS_MAX_TIMEOUT = _env_int("TELNET_MCP_DNS_MAX_TIMEOUT", 60)

# Record types dig is allowed to query for the forward lookup.
ALLOWED_RECORD_TYPES = {
    "A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA",
    "PTR", "SRV", "CAA", "DS", "DNSKEY", "NAPTR", "ANY",
}

# Conservative hostname validation (labels, dots, optional trailing dot).
_HOSTNAME_RE = re.compile(
    r"^(?=.{1,253}\.?$)([A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)"
    r"(\.([A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?))*\.?$"
)


class DnsError(Exception):
    """Raised for invalid input or when dig cannot be run."""


def clamp_timeout(timeout: float) -> float:
    return max(1.0, min(float(timeout), float(DNS_MAX_TIMEOUT)))


def validate_ip(ip: str) -> str:
    """Return the normalized IP string, or raise DnsError."""
    try:
        return str(ipaddress.ip_address(ip.strip()))
    except ValueError as e:
        raise DnsError(f"not a valid IP address: {ip!r}") from e


def validate_hostname(name: str) -> str:
    name = (name or "").strip()
    if not name or not _HOSTNAME_RE.match(name):
        raise DnsError(f"not a valid hostname: {name!r}")
    return name


def validate_record_type(record_type: str) -> str:
    rt = (record_type or "A").strip().upper()
    if rt not in ALLOWED_RECORD_TYPES:
        raise DnsError(
            f"unsupported record type {record_type!r}; "
            f"allowed: {', '.join(sorted(ALLOWED_RECORD_TYPES))}"
        )
    return rt


def _validate_server(server: str) -> str:
    """A DNS server may be given as an IP; empty means 'system default'."""
    server = (server or "").strip()
    if not server:
        return ""
    return validate_ip(server)


@dataclass
class DigResult:
    ok: bool
    returncode: int
    stdout: str
    stderr: str
    timed_out: bool
    command: list


async def run_dig(args: list, *, timeout: float) -> DigResult:
    """Run ``dig`` with the given args, bounded by ``timeout`` seconds."""
    timeout = clamp_timeout(timeout)
    # Bound dig's own network waits too, so a dead resolver can't hang us.
    per_try = max(1, int(timeout))
    argv = [DIG_BIN, f"+time={per_try}", "+tries=1", *args]
    try:
        proc = await asyncio.create_subprocess_exec(
            *argv,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
    except FileNotFoundError as e:
        raise DnsError(
            f"could not run dig (is it installed? looked for {DIG_BIN!r}): {e}"
        ) from e

    try:
        out, err = await asyncio.wait_for(proc.communicate(), timeout=timeout + 1)
    except asyncio.TimeoutError:
        proc.kill()
        await proc.wait()
        return DigResult(False, -1, "", "dig timed out", True, argv)

    return DigResult(
        ok=(proc.returncode == 0),
        returncode=proc.returncode if proc.returncode is not None else -1,
        stdout=out.decode("utf-8", errors="replace"),
        stderr=err.decode("utf-8", errors="replace"),
        timed_out=False,
        command=argv,
    )


def parse_answer(stdout: str) -> list:
    """
    Parse dig's ``+noall +answer`` output into a list of record dicts.

    Each answer line looks like:
        example.com.        3600    IN    A       93.184.216.34
        example.com.        3600    IN    MX      10 mail.example.com.
    """
    records = []
    for line in stdout.splitlines():
        line = line.strip()
        if not line or line.startswith(";"):
            continue
        parts = line.split(None, 4)  # name ttl class type data
        if len(parts) < 5:
            continue
        name, ttl, rclass, rtype, data = parts
        try:
            ttl_int = int(ttl)
        except ValueError:
            ttl_int = None
        records.append(
            {
                "name": name,
                "ttl": ttl_int,
                "class": rclass,
                "type": rtype,
                "data": data,
            }
        )
    return records


async def lookup(
    name: str,
    record_type: str = "A",
    *,
    server: str = "",
    timeout: float = DNS_DEFAULT_TIMEOUT,
) -> dict:
    """Forward DNS lookup for ``name`` of type ``record_type``."""
    name = validate_hostname(name)
    rtype = validate_record_type(record_type)
    srv = _validate_server(server)

    args = ["+noall", "+answer", name, rtype]
    if srv:
        args.append(f"@{srv}")

    res = await run_dig(args, timeout=timeout)
    if not res.ok and not res.stdout:
        return {
            "ok": False,
            "query": name,
            "type": rtype,
            "error": res.stderr.strip() or "dig failed",
            "timed_out": res.timed_out,
            "command": res.command,
        }

    records = parse_answer(res.stdout)
    return {
        "ok": True,
        "query": name,
        "type": rtype,
        "server": srv or "system default",
        "record_count": len(records),
        "records": records,
    }


async def reverse(
    ip: str,
    *,
    server: str = "",
    timeout: float = DNS_DEFAULT_TIMEOUT,
) -> dict:
    """Reverse DNS (PTR) lookup for ``ip``."""
    ip = validate_ip(ip)
    srv = _validate_server(server)

    args = ["+noall", "+answer", "-x", ip]
    if srv:
        args.append(f"@{srv}")

    res = await run_dig(args, timeout=timeout)
    if not res.ok and not res.stdout:
        return {
            "ok": False,
            "ip": ip,
            "error": res.stderr.strip() or "dig failed",
            "timed_out": res.timed_out,
            "command": res.command,
        }

    records = parse_answer(res.stdout)
    ptr_names = [r["data"] for r in records if r["type"] == "PTR"]
    return {
        "ok": True,
        "ip": ip,
        "server": srv or "system default",
        "ptr_names": ptr_names,
        "record_count": len(records),
        "records": records,
    }
