#!/usr/bin/env python3
"""
bash_engine.py — guarded bash execution engine behind the bash_exec tool.

This is the "leverage bash" layer behind the ``bash_exec`` tool. Instead of
hard-coding a single nc invocation, it lets callers drive *bash* directly: run
an arbitrary command (or pipeline) and capture stdout / stderr / exit code, with
a hard timeout and output caps.

Typical use is to script a multi-step protocol session by piping printf payloads
into netcat, e.g. an Asterisk Manager Interface (AMI) login + command:

    ( printf 'Action: Login\\r\\nUsername: admin\\r\\nSecret: ***\\r\\nEvents: off\\r\\n\\r\\n'
      sleep 1
      printf 'Action: Command\\r\\nCommand: database show\\r\\n\\r\\n'
      sleep 5 ) | nc -w 8 <ip> <port>

This module is MCP-agnostic; the tool definition lives in ``mcp_tools.py``.

Scope / responsible use
-----------------------
``run_bash`` executes shell commands on the host running this server. Only run
this server where that is acceptable, and only target hosts you are authorized
to administer.
"""

from __future__ import annotations

import asyncio
import os
import re
import shlex
import shutil
from dataclasses import dataclass, field
from typing import Optional


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
# Configuration / safety limits (all env-overridable)
# --------------------------------------------------------------------------- #

BASH_BIN = os.getenv("NETADMIN_MCP_BASH_BIN") or shutil.which("bash") or "bash"

# Hard ceiling + default for how long a single bash invocation may run.
BASH_MAX_TIMEOUT = _env_int("NETADMIN_MCP_BASH_MAX_TIMEOUT", 120)   # seconds
BASH_DEFAULT_TIMEOUT = _env_int("NETADMIN_MCP_BASH_DEFAULT_TIMEOUT", 30)

# Caps on captured output so a chatty command can't blow up the response.
BASH_MAX_OUTPUT_BYTES = _env_int("NETADMIN_MCP_BASH_MAX_OUTPUT_BYTES", 262144)  # 256 KB


def clamp_bash_timeout(timeout: float) -> float:
    return max(1.0, min(float(timeout), BASH_MAX_TIMEOUT))


# --------------------------------------------------------------------------- #
# Command allowlist
# --------------------------------------------------------------------------- #
# bash_exec is intentionally a shell, but we don't want the model to run just
# *anything*. Every command invoked in the pipeline must be on an allowlist, and
# command-substitution escapes are rejected outright. This is a guard rail, not
# a sandbox — for hard isolation, run this server as an unprivileged user inside
# a container. The allowlist is fully configurable; see the env vars below.

# Default set: network-admin tools plus the small shell builtins needed to drive
# line protocols (printf | nc ...). Deliberately excludes shells, eval, package
# managers, file destroyers, etc.
DEFAULT_ALLOWED_CMDS = {
    "nmap", "nc", "ncat", "netcat", "socat",
    "ping", "ping6", "traceroute", "dig", "host", "nslookup",
    "curl", "wget",
    "printf", "echo", "sleep", "cat", "head", "tail",
    "grep", "egrep", "tr", "cut", "sort", "uniq", "wc", "tee", "true", "false",
}


def _load_allowed_cmds() -> set[str]:
    raw = os.getenv("NETADMIN_MCP_ALLOWED_CMDS")
    if raw and raw.strip():
        # Full replacement of the default set; comma- or space-separated.
        return {c.strip() for c in re.split(r"[,\s]+", raw.strip()) if c.strip()}
    return set(DEFAULT_ALLOWED_CMDS)


ALLOWED_CMDS = _load_allowed_cmds()
# Escape hatch for power users who run the server in their own isolated env.
ALLOWLIST_DISABLED = (os.getenv("NETADMIN_MCP_BASH_ALLOWLIST_DISABLED") or "").strip().lower() in {
    "1", "true", "yes", "on",
}

# Shell operators that separate one command from the next. The token right after
# any of these (or at the very start) is a command position whose name we check.
_OPERATORS = {"|", "||", "&&", ";", "&", "(", ")", "{", "}", "|&"}
# Constructs we refuse outright because they can smuggle in disallowed commands.
_SUBSTITUTION_RE = re.compile(r"\$\(|`|<\(|>\(")
_ASSIGN_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=")


class CommandNotAllowed(ValueError):
    """Raised when a bash_exec command invokes a binary outside the allowlist."""


def check_command_allowed(command: str) -> None:
    """
    Best-effort allowlist check for a bash command/pipeline.

    Raises ``CommandNotAllowed`` if the command uses command substitution or
    invokes any executable not in ``ALLOWED_CMDS``. A no-op when the allowlist
    is disabled via ``NETADMIN_MCP_BASH_ALLOWLIST_DISABLED``.

    This parses command *positions* (the start, and the token after each shell
    operator) and checks the basename of each against the allowlist. It is a
    guard rail against the model wandering off to run arbitrary tools — not a
    security boundary. Treat OS-level isolation as the real boundary.
    """
    if ALLOWLIST_DISABLED:
        return

    if _SUBSTITUTION_RE.search(command):
        raise CommandNotAllowed(
            "command substitution ($(...), <(...), backticks) is not permitted"
        )

    try:
        lex = shlex.shlex(command, posix=True, punctuation_chars=True)
        lex.whitespace_split = True
        tokens = list(lex)
    except ValueError as e:
        raise CommandNotAllowed(f"could not parse command: {e}")

    expect_command = True  # next non-assignment token is a command name
    for tok in tokens:
        if tok in _OPERATORS:
            expect_command = True
            continue
        if not expect_command:
            continue
        # Leading VAR=value assignments don't change the command position.
        if _ASSIGN_RE.match(tok):
            continue
        name = os.path.basename(tok)
        if name not in ALLOWED_CMDS:
            raise CommandNotAllowed(
                f"command {name!r} is not in the allowlist "
                f"({', '.join(sorted(ALLOWED_CMDS))}). "
                f"Set NETADMIN_MCP_ALLOWED_CMDS to change it."
            )
        expect_command = False


# --------------------------------------------------------------------------- #
# Core: run an arbitrary bash command
# --------------------------------------------------------------------------- #


@dataclass
class BashResult:
    command: str
    returncode: Optional[int] = None
    stdout: str = ""
    stderr: str = ""
    timed_out: bool = False
    stdout_truncated: bool = False
    stderr_truncated: bool = False
    cmd: list[str] = field(default_factory=list)


def _decode_capped(data: bytes, cap: int) -> tuple[str, bool]:
    """Decode bytes to text, capping at ``cap`` bytes. Returns (text, truncated)."""
    if not data:
        return "", False
    truncated = len(data) > cap
    chunk = data[:cap] if truncated else data
    return chunk.decode("utf-8", "replace"), truncated


async def run_bash(
    command: str,
    *,
    timeout: float = BASH_DEFAULT_TIMEOUT,
    cwd: Optional[str] = None,
    env_extra: Optional[dict] = None,
    stdin: Optional[str] = None,
) -> BashResult:
    """
    Run ``command`` through ``bash -c`` and capture the result.

    The whole invocation is bounded by ``timeout`` (clamped to
    ``BASH_MAX_TIMEOUT``); on expiry the process group is killed and
    ``timed_out`` is set. stdout/stderr are each capped at
    ``BASH_MAX_OUTPUT_BYTES``.

    Args:
        command: the bash command/script to execute.
        timeout: wall-clock limit in seconds (1 .. BASH_MAX_TIMEOUT).
        cwd: optional working directory.
        env_extra: extra environment variables to overlay on the current env.
        stdin: optional text piped to the command's stdin.
    """
    if not command or not command.strip():
        raise ValueError("command must not be empty")

    # Guard rail: reject anything that invokes a binary outside the allowlist.
    check_command_allowed(command)

    timeout = clamp_bash_timeout(timeout)
    cmd = [BASH_BIN, "-c", command]

    env = None
    if env_extra:
        env = {**os.environ, **{str(k): str(v) for k, v in env_extra.items()}}

    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdin=asyncio.subprocess.PIPE if stdin is not None else asyncio.subprocess.DEVNULL,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            cwd=cwd,
            env=env,
            start_new_session=True,  # own process group so we can kill children (e.g. nc)
        )
    except FileNotFoundError:
        return BashResult(command=command, stderr="bash binary not found on PATH", cmd=cmd)

    stdin_bytes = stdin.encode("utf-8", "replace") if stdin is not None else None
    try:
        out, err = await asyncio.wait_for(
            proc.communicate(input=stdin_bytes), timeout=timeout
        )
    except asyncio.TimeoutError:
        _kill_process_group(proc)
        await proc.wait()
        return BashResult(command=command, timed_out=True, cmd=cmd)

    stdout, so_trunc = _decode_capped(out, BASH_MAX_OUTPUT_BYTES)
    stderr, se_trunc = _decode_capped(err, BASH_MAX_OUTPUT_BYTES)
    return BashResult(
        command=command,
        returncode=proc.returncode,
        stdout=stdout,
        stderr=stderr,
        stdout_truncated=so_trunc,
        stderr_truncated=se_trunc,
        cmd=cmd,
    )


def _kill_process_group(proc: asyncio.subprocess.Process) -> None:
    """Best-effort kill of the whole process group started with start_new_session."""
    try:
        os.killpg(os.getpgid(proc.pid), 9)
    except (ProcessLookupError, PermissionError, OSError):
        try:
            proc.kill()
        except ProcessLookupError:
            pass
