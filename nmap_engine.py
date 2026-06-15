#!/usr/bin/env python3
"""
nmap_engine.py — structured Nmap engine behind the nmap_scan tool.

Where the old netcat engine *guessed* at open ports and OS family from banners +
TTL, nmap does it properly: real service/version detection (``-sV``) and TCP/IP
stack OS fingerprinting (``-O``). We invoke nmap with XML output (``-oX -``) and
parse it into clean JSON. The tool definition lives in ``mcp_tools.py``.

Key safety property: nmap is invoked as an **argv list** (no shell), and every
argument is either a fixed flag we choose or a value we validate (hosts, ints).
There is no shell-injection surface here — unlike ``bash_exec``, which is a shell
by design and is guarded by an allowlist instead.

Privileges: ``-O`` (OS detection) and SYN scans need root/raw sockets. This
module defaults to a TCP connect scan (``-sT``), which works unprivileged; if you
request ``os_detect`` without the needed privileges, nmap says so and we surface
that in ``warnings``.
"""

from __future__ import annotations

import asyncio
import ipaddress
import os
import re
import shutil
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from typing import Optional


def _env_int(name: str, default: int) -> int:
    raw = os.getenv(name)
    if raw is None or raw.strip() == "":
        return default
    try:
        return int(raw)
    except ValueError:
        return default


# --------------------------------------------------------------------------- #
# Configuration
# --------------------------------------------------------------------------- #

NMAP_BIN = os.getenv("NETADMIN_MCP_NMAP_BIN") or shutil.which("nmap") or "nmap"

NMAP_MAX_TIMEOUT = _env_int("NETADMIN_MCP_NMAP_MAX_TIMEOUT", 300)   # seconds, hard ceiling
NMAP_DEFAULT_TIMEOUT = _env_int("NETADMIN_MCP_NMAP_DEFAULT_TIMEOUT", 120)
NMAP_DEFAULT_TOP_PORTS = _env_int("NETADMIN_MCP_NMAP_TOP_PORTS", 100)


def clamp_nmap_timeout(timeout: float) -> float:
    return max(5.0, min(float(timeout), NMAP_MAX_TIMEOUT))


# --------------------------------------------------------------------------- #
# Validation
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
    port = int(port)
    if not (1 <= port <= 65535):
        raise ValueError(f"port must be 1-65535, got {port!r}")
    return port


# --------------------------------------------------------------------------- #
# Argv construction (no shell)
# --------------------------------------------------------------------------- #


def build_nmap_args(
    host: str,
    *,
    ports: Optional[list] = None,
    top_ports: Optional[int] = None,
    service_detect: bool = True,
    os_detect: bool = False,
    skip_ping: bool = False,
) -> list[str]:
    """
    Build the nmap argv. Everything here is a fixed flag or a validated value.

    Defaults to a TCP connect scan (``-sT``, unprivileged) with timing ``-T4``.
    Port selection precedence: explicit ``ports`` → ``--top-ports N`` → the
    configured default top-ports.
    """
    host = validate_host(host)
    args = [NMAP_BIN, "-oX", "-", "-sT", "-T4"]

    if service_detect:
        args.append("-sV")
    if os_detect:
        args.append("-O")
    if skip_ping:
        args.append("-Pn")

    if ports:
        validated = sorted({validate_port(p) for p in ports})
        args += ["-p", ",".join(str(p) for p in validated)]
    elif top_ports:
        n = max(1, min(int(top_ports), 65535))
        args += ["--top-ports", str(n)]
    else:
        args += ["--top-ports", str(NMAP_DEFAULT_TOP_PORTS)]

    args.append(host)
    return args


# --------------------------------------------------------------------------- #
# Runner
# --------------------------------------------------------------------------- #


@dataclass
class NmapResult:
    returncode: Optional[int] = None
    stdout: bytes = b""
    stderr: str = ""
    timed_out: bool = False
    cmd: list[str] = field(default_factory=list)


async def run_nmap(args: list[str], *, timeout: float = NMAP_DEFAULT_TIMEOUT) -> NmapResult:
    timeout = clamp_nmap_timeout(timeout)
    try:
        proc = await asyncio.create_subprocess_exec(
            *args,
            stdin=asyncio.subprocess.DEVNULL,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
    except FileNotFoundError:
        return NmapResult(stderr="nmap binary not found on PATH", cmd=args)

    try:
        out, err = await asyncio.wait_for(proc.communicate(), timeout=timeout + 5)
    except asyncio.TimeoutError:
        proc.kill()
        await proc.wait()
        return NmapResult(timed_out=True, cmd=args)

    return NmapResult(
        returncode=proc.returncode,
        stdout=out,
        stderr=err.decode("utf-8", "replace").strip(),
        cmd=args,
    )


# --------------------------------------------------------------------------- #
# XML parsing
# --------------------------------------------------------------------------- #


def parse_nmap_xml(xml_data: bytes) -> dict:
    """Parse ``nmap -oX -`` output into a JSON-friendly dict."""
    if not xml_data or not xml_data.strip():
        return {"hosts": [], "warnings": ["empty nmap output"]}

    try:
        root = ET.fromstring(xml_data)
    except ET.ParseError as e:
        return {"hosts": [], "warnings": [f"could not parse nmap XML: {e}"]}

    warnings: list[str] = []
    hosts: list[dict] = []

    for host_el in root.findall("host"):
        status_el = host_el.find("status")
        state = status_el.get("state") if status_el is not None else "unknown"

        # Prefer an IPv4/IPv6 address; fall back to the first address element.
        addr = ""
        for a in host_el.findall("address"):
            if a.get("addrtype") in ("ipv4", "ipv6"):
                addr = a.get("addr", "")
                break
        if not addr:
            a = host_el.find("address")
            addr = a.get("addr", "") if a is not None else ""

        hostnames = [
            hn.get("name", "")
            for hn in host_el.findall("hostnames/hostname")
            if hn.get("name")
        ]

        ports: list[dict] = []
        for p in host_el.findall("ports/port"):
            st = p.find("state")
            svc = p.find("service")
            service = {}
            if svc is not None:
                service = {
                    k: svc.get(k)
                    for k in ("name", "product", "version", "extrainfo", "tunnel")
                    if svc.get(k)
                }
            ports.append(
                {
                    "port": int(p.get("portid")) if p.get("portid") else None,
                    "protocol": p.get("protocol"),
                    "state": st.get("state") if st is not None else "unknown",
                    "reason": st.get("reason") if st is not None else None,
                    "service": service,
                }
            )

        os_matches = [
            {
                "name": m.get("name"),
                "accuracy": int(m.get("accuracy")) if m.get("accuracy") else None,
            }
            for m in host_el.findall("os/osmatch")
        ]

        hosts.append(
            {
                "address": addr,
                "hostnames": hostnames,
                "state": state,
                "open_ports": [p for p in ports if p["state"] == "open"],
                "ports": ports,
                "os_matches": os_matches,
            }
        )

    # Surface nmap's own warnings/errors (e.g. "requires root privileges").
    runstats = root.find("runstats/finished")
    if runstats is not None and runstats.get("exit") == "error":
        msg = runstats.get("errormsg")
        if msg:
            warnings.append(msg)

    return {
        "command": root.get("args", ""),
        "hosts": hosts,
        "warnings": warnings,
    }


async def scan(
    host: str,
    *,
    ports: Optional[list] = None,
    top_ports: Optional[int] = None,
    service_detect: bool = True,
    os_detect: bool = False,
    skip_ping: bool = False,
    timeout: float = NMAP_DEFAULT_TIMEOUT,
) -> dict:
    """Run nmap against ``host`` and return parsed JSON (or a structured error)."""
    args = build_nmap_args(
        host,
        ports=ports,
        top_ports=top_ports,
        service_detect=service_detect,
        os_detect=os_detect,
        skip_ping=skip_ping,
    )
    res = await run_nmap(args, timeout=timeout)

    if res.timed_out:
        return {"ok": False, "host": host, "error": "nmap timed out", "command": args}
    if res.returncode is None or (res.returncode != 0 and not res.stdout.strip()):
        return {
            "ok": False,
            "host": host,
            "error": res.stderr or "nmap failed to run",
            "command": args,
        }

    parsed = parse_nmap_xml(res.stdout)
    if res.stderr:
        parsed.setdefault("warnings", []).append(res.stderr)

    parsed["ok"] = True
    parsed["host"] = host
    parsed["command"] = args  # full argv, overrides the XML's args string
    return parsed
