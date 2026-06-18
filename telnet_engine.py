#!/usr/bin/env python3
"""
telnet_engine.py — a zero-dependency, asyncio telnet client engine.

Python's built-in ``telnetlib`` was removed in 3.13, so this engine speaks just
enough of the telnet protocol itself, over a plain ``asyncio`` TCP stream:

  * it opens a connection and keeps it alive as a *persistent session*;
  * it answers telnet option negotiation (IAC WILL/WONT/DO/DONT, and SB...SE
    sub-negotiation) by politely refusing every option, which is what a dumb
    line-oriented client wants — the remote side then falls back to plain text;
  * it strips those IAC control sequences out of the data handed back to you.

Sessions live in an in-process registry keyed by a short id. The MCP layer
(``mcp_tools.py``) calls ``connect`` once to get an id, then ``send`` / ``read``
against that id, and finally ``close``.

Nothing here is specific to any vendor or device — it's a generic telnet pipe.
Reads are *idle-based*: a read collects whatever has arrived and returns once the
stream has been quiet for ``idle_timeout`` seconds (or the hard ``max_wait`` cap
or ``max_bytes`` is reached), which is the usual way to scrape a prompt-driven
protocol without knowing the exact prompt string.
"""

from __future__ import annotations

import asyncio
import time
import uuid
from dataclasses import dataclass, field
from typing import Dict, Optional

# ── Telnet protocol bytes (RFC 854 / 855) ────────────────────────────────────
IAC = 255  # Interpret As Command — the escape byte that introduces a command
DONT = 254
DO = 253
WONT = 252
WILL = 251
SB = 250   # Subnegotiation Begin
SE = 240   # Subnegotiation End
GA = 249   # Go Ahead (and other 240-249 single-byte commands)

# ── Defaults (overridable per call by the MCP layer) ─────────────────────────
DEFAULT_PORT = 23
CONNECT_DEFAULT_TIMEOUT = 10.0   # seconds to establish the TCP connection
READ_DEFAULT_IDLE = 1.0          # quiet period that ends a read, in seconds
READ_DEFAULT_MAX_WAIT = 10.0     # hard ceiling on a single read, in seconds
READ_DEFAULT_MAX_BYTES = 256 * 1024  # cap on bytes returned by one read

# Bounds, so the MCP layer can't be handed absurd values.
CONNECT_TIMEOUT_BOUNDS = (1.0, 120.0)
IDLE_BOUNDS = (0.05, 60.0)
MAX_WAIT_BOUNDS = (0.1, 300.0)
MAX_BYTES_BOUNDS = (1, 8 * 1024 * 1024)


def _clamp(value: float, lo: float, hi: float) -> float:
    return max(lo, min(hi, value))


class TelnetError(Exception):
    """Raised for connect failures and operations on unusable sessions."""


class SessionNotFound(TelnetError):
    """Raised when a session id doesn't match any live session."""


@dataclass
class TelnetSession:
    """One live telnet connection plus the small bit of state a read needs."""

    id: str
    host: str
    port: int
    reader: asyncio.StreamReader
    writer: asyncio.StreamWriter
    created_at: float = field(default_factory=time.time)
    last_used: float = field(default_factory=time.time)
    bytes_sent: int = 0
    bytes_received: int = 0
    # Holds the tail of a partial IAC sequence split across two reads.
    _pending: bytes = b""
    closed: bool = False

    @property
    def peer(self) -> str:
        return f"{self.host}:{self.port}"


# In-process registry of live sessions. The MCP server is a single process, so a
# plain dict is all the bookkeeping we need.
_SESSIONS: Dict[str, TelnetSession] = {}


def _filter_iac(data: bytes, session: TelnetSession) -> bytes:
    """
    Strip telnet IAC command sequences from ``data`` and auto-refuse options.

    Returns the cleaned application bytes. Any option the peer offers or requests
    is answered with a refusal (DO->WONT, WILL->DONT) queued onto the session's
    writer, which keeps us in plain line mode. ``session._pending`` carries an
    incomplete sequence over to the next call.
    """
    buf = session._pending + data
    session._pending = b""
    out = bytearray()
    replies = bytearray()
    i = 0
    n = len(buf)

    while i < n:
        b = buf[i]
        if b != IAC:
            out.append(b)
            i += 1
            continue

        # We're at an IAC. Need at least one more byte to know the command.
        if i + 1 >= n:
            session._pending = bytes(buf[i:])
            break

        cmd = buf[i + 1]

        if cmd == IAC:
            # Escaped 0xFF in the data stream -> a single literal 0xFF byte.
            out.append(IAC)
            i += 2
            continue

        if cmd in (DO, DONT, WILL, WONT):
            # Option negotiation: IAC <cmd> <option>. Need the option byte too.
            if i + 2 >= n:
                session._pending = bytes(buf[i:])
                break
            option = buf[i + 2]
            if cmd == DO:
                replies += bytes((IAC, WONT, option))   # we won't do anything
            elif cmd == WILL:
                replies += bytes((IAC, DONT, option))    # don't, thanks
            # DONT / WONT need no reply.
            i += 3
            continue

        if cmd == SB:
            # Subnegotiation: IAC SB ... IAC SE. Skip to the closing IAC SE.
            j = i + 2
            while j < n:
                if buf[j] == IAC and j + 1 < n and buf[j + 1] == SE:
                    break
                j += 1
            else:
                # No terminator yet — stash and wait for more bytes.
                session._pending = bytes(buf[i:])
                i = n
                break
            i = j + 2
            continue

        # Other two-byte commands (GA, NOP, etc.): IAC <cmd>, just drop them.
        i += 2

    if replies:
        try:
            session.writer.write(bytes(replies))
        except Exception:
            # If the writer is gone the next read/send will surface it cleanly.
            pass

    return bytes(out)


async def connect(
    host: str,
    port: int = DEFAULT_PORT,
    *,
    timeout: float = CONNECT_DEFAULT_TIMEOUT,
    read_banner: bool = True,
    banner_idle: float = READ_DEFAULT_IDLE,
    banner_max_wait: float = 3.0,
) -> dict:
    """
    Open a telnet connection and register it as a persistent session.

    Args:
        host: target hostname or IP.
        port: TCP port (default 23).
        timeout: seconds to wait for the TCP connection to establish.
        read_banner: if True, read whatever the host emits on connect (login
            prompt / MOTD) and return it as ``banner``.
        banner_idle / banner_max_wait: read tuning for the banner grab.

    Returns:
        dict with ``session_id``, ``host``, ``port``, ``peer`` and (optionally)
        the initial ``banner`` text.

    Raises:
        TelnetError on connection failure or timeout.
    """
    if not host or not isinstance(host, str):
        raise TelnetError("host must be a non-empty string")
    port = int(port)
    if not (0 < port < 65536):
        raise TelnetError(f"port out of range: {port}")
    timeout = _clamp(float(timeout), *CONNECT_TIMEOUT_BOUNDS)

    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port), timeout=timeout
        )
    except asyncio.TimeoutError as e:
        raise TelnetError(
            f"connection to {host}:{port} timed out after {timeout:g}s"
        ) from e
    except OSError as e:
        raise TelnetError(f"could not connect to {host}:{port}: {e}") from e

    session = TelnetSession(
        id=uuid.uuid4().hex[:12],
        host=host,
        port=port,
        reader=reader,
        writer=writer,
    )
    _SESSIONS[session.id] = session

    result = {
        "session_id": session.id,
        "host": host,
        "port": port,
        "peer": session.peer,
    }

    if read_banner:
        banner = await read(
            session.id,
            idle_timeout=banner_idle,
            max_wait=banner_max_wait,
        )
        result["banner"] = banner["data"]
        result["banner_bytes"] = banner["bytes"]

    return result


def get_session(session_id: str) -> TelnetSession:
    """Return the live session for ``session_id`` or raise SessionNotFound."""
    session = _SESSIONS.get(session_id)
    if session is None or session.closed:
        raise SessionNotFound(f"no live session with id {session_id!r}")
    return session


async def send(
    session_id: str,
    data: str,
    *,
    append_newline: bool = True,
    newline: str = "\r\n",
    encoding: str = "utf-8",
) -> dict:
    """
    Write ``data`` to a session. Does not read the reply (call ``read`` for that).

    Args:
        session_id: id from ``connect``.
        data: text to send.
        append_newline: append ``newline`` to ``data`` (most line protocols need
            a terminator to act on the line).
        newline: line terminator to append; telnet convention is CRLF.
        encoding: text encoding used to turn ``data`` into bytes.

    Returns:
        dict with ``ok`` and ``bytes_sent``.
    """
    session = get_session(session_id)
    payload = data + (newline if append_newline else "")
    raw = payload.encode(encoding, errors="replace")
    # Escape any literal 0xFF so it isn't read as a telnet IAC by the peer.
    raw = raw.replace(bytes((IAC,)), bytes((IAC, IAC)))

    try:
        session.writer.write(raw)
        await session.writer.drain()
    except Exception as e:
        raise TelnetError(f"send failed on session {session_id}: {e}") from e

    session.bytes_sent += len(raw)
    session.last_used = time.time()
    return {"ok": True, "session_id": session_id, "bytes_sent": len(raw)}


async def read(
    session_id: str,
    *,
    idle_timeout: float = READ_DEFAULT_IDLE,
    max_wait: float = READ_DEFAULT_MAX_WAIT,
    max_bytes: int = READ_DEFAULT_MAX_BYTES,
    encoding: str = "utf-8",
) -> dict:
    """
    Read available output from a session until it goes quiet.

    The read accumulates data and returns once *any* of these is true: the
    stream has produced nothing for ``idle_timeout`` seconds, the total
    ``max_wait`` ceiling is hit, ``max_bytes`` is collected, or the peer closes
    the connection (EOF).

    Args:
        session_id: id from ``connect``.
        idle_timeout: quiet period (s) that ends the read once some data is in.
        max_wait: hard ceiling (s) on the whole read.
        max_bytes: stop after collecting this many cleaned bytes.
        encoding: decode collected bytes with this codec (errors replaced).

    Returns:
        dict with ``data`` (decoded text), ``bytes``, ``eof``, and ``truncated``.
    """
    session = get_session(session_id)
    idle_timeout = _clamp(float(idle_timeout), *IDLE_BOUNDS)
    max_wait = _clamp(float(max_wait), *MAX_WAIT_BOUNDS)
    max_bytes = int(_clamp(float(max_bytes), *MAX_BYTES_BOUNDS))

    collected = bytearray()
    deadline = time.time() + max_wait
    eof = False
    truncated = False

    while True:
        remaining = deadline - time.time()
        if remaining <= 0:
            break
        # Wait at most until the idle window or the hard deadline, whichever is
        # sooner. Before we have any data, wait the full idle window so a slow
        # first byte isn't missed.
        wait_for = min(idle_timeout, remaining)
        try:
            chunk = await asyncio.wait_for(session.reader.read(4096), timeout=wait_for)
        except asyncio.TimeoutError:
            # Idle window elapsed. If we already have data, we're done; if not,
            # keep waiting until the hard deadline.
            if collected:
                break
            continue
        except Exception as e:
            raise TelnetError(f"read failed on session {session_id}: {e}") from e

        if chunk == b"":
            eof = True
            break

        cleaned = _filter_iac(chunk, session)
        if cleaned:
            collected += cleaned
            if len(collected) >= max_bytes:
                truncated = True
                collected = collected[:max_bytes]
                break

    session.bytes_received += len(collected)
    session.last_used = time.time()
    return {
        "ok": True,
        "session_id": session_id,
        "data": collected.decode(encoding, errors="replace"),
        "bytes": len(collected),
        "eof": eof,
        "truncated": truncated,
    }


async def send_and_read(
    session_id: str,
    data: str,
    *,
    append_newline: bool = True,
    newline: str = "\r\n",
    idle_timeout: float = READ_DEFAULT_IDLE,
    max_wait: float = READ_DEFAULT_MAX_WAIT,
    max_bytes: int = READ_DEFAULT_MAX_BYTES,
    encoding: str = "utf-8",
) -> dict:
    """Convenience: ``send`` then ``read`` on the same session, in one call."""
    sent = await send(
        session_id,
        data,
        append_newline=append_newline,
        newline=newline,
        encoding=encoding,
    )
    got = await read(
        session_id,
        idle_timeout=idle_timeout,
        max_wait=max_wait,
        max_bytes=max_bytes,
        encoding=encoding,
    )
    got["bytes_sent"] = sent["bytes_sent"]
    return got


def list_sessions() -> list:
    """Return a summary record for every live session."""
    now = time.time()
    out = []
    for s in _SESSIONS.values():
        if s.closed:
            continue
        out.append(
            {
                "session_id": s.id,
                "peer": s.peer,
                "host": s.host,
                "port": s.port,
                "age_seconds": round(now - s.created_at, 1),
                "idle_seconds": round(now - s.last_used, 1),
                "bytes_sent": s.bytes_sent,
                "bytes_received": s.bytes_received,
            }
        )
    return out


async def close(session_id: str) -> dict:
    """Close a session's connection and drop it from the registry."""
    session = _SESSIONS.get(session_id)
    if session is None:
        raise SessionNotFound(f"no session with id {session_id!r}")
    if not session.closed:
        session.closed = True
        try:
            session.writer.close()
            await asyncio.wait_for(session.writer.wait_closed(), timeout=5.0)
        except Exception:
            pass  # best-effort close; the socket is going away regardless
    _SESSIONS.pop(session_id, None)
    return {"ok": True, "session_id": session_id, "closed": True}


async def close_all() -> dict:
    """Close every live session (handy for server shutdown)."""
    ids = list(_SESSIONS.keys())
    for sid in ids:
        try:
            await close(sid)
        except Exception:
            pass
    return {"ok": True, "closed_count": len(ids)}
