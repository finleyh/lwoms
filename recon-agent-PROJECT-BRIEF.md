# recon-agent — project brief & handoff

A standalone repo that builds **one Docker image** to replace the slim-Debian VM
currently running the recon agent. The image bundles the `mcpc` LLM/agent client
and the `netcat-mcp` tool server so they run together (client spawns server as a
local stdio child). The LLM stays **remote** — it is not in the image.

This file is the spec. Hand it to Claude in a new session and it can build the
repo from here.

---

## Decisions already made (do not relitigate)

- **Separate repo** owns only deployment glue. `netcat-mcp` and `llmCLIent` stay
  independent projects with their own tests/releases; this repo pins them.
- **Single image**, not multiple containers. `mcpc` launches MCP servers over
  **stdio as child processes**, so co-locating them avoids docker-in-docker.
- **LLM is remote.** Point `LLM_BASE_URL` at the existing endpoint. No model
  weights / GPU in this image.
- **Interactive-first.** Default behavior = drop into the `mcpc` REPL for manual
  driving and testing (`docker run -it`). This mirrors the current VM workflow.
- **Headless/k8s is deferred.** It needs a small upstream patch to `llmCLIent`
  (see "Known rough edge"). Document it; don't depend on it yet.
- **Base:** `python:3.12-slim-bookworm`. **Hardening:** non-root user, package
  managers neutralized after install. **Network:** `--network host` for LAN reach.

---

## The two upstream components

### netcat-mcp (this project's sibling)
- Files: `netcat.py`, `curl.py`, `tools.py`, `server.py`, `requirements.txt`.
- Runtime needs: Python + `mcp` package, and the binaries `nc` (netcat-openbsd),
  `curl`, `ping` (iputils-ping).
- Run command inside the image: `python /opt/netcat-mcp/server.py` (stdio).
- Exposes 6 tools: `port_scan`, `banner_grab`, `raw_send_recv`, `os_fingerprint`,
  `http_fetch`, `web_scrape`. In `mcpc` they appear namespaced as `netcat__*`.
- Already ships a standalone hardened `Dockerfile` — reuse its patterns
  (apt install + neutralize apt/dpkg/pip, non-root user 10001).

### llmCLIent  (repo: github.com/finleyh/llmCLIent, package `cli-mcp-client`)
- Pip-installable; provides the `mcpc` console script
  (`pip install git+https://github.com/finleyh/llmCLIent@<tag>`).
- Deps: httpx, python-dotenv, prompt-toolkit, rich, mcp>=1.2.0, tiktoken.
- **Auto-connects MCP servers from its SQLite DB on startup**
  (`Repl._autoconnect_servers`). → We pre-seed the DB at build time so the
  `netcat` server is already registered and connects on every boot.
- Config is read from env / `.env` (see env table below).

---

## Image build strategy

Single-stage is fine (both are Python). Order:

1. `apt-get install --no-install-recommends netcat-openbsd curl iputils-ping ca-certificates`.
2. `pip install` the `mcp` package (for netcat-mcp) and
   `git+https://github.com/finleyh/llmCLIent@${LLMCLIENT_REF}` (brings `mcpc`).
3. `COPY` the pinned `netcat-mcp` tree to `/opt/netcat-mcp/`.
4. **Pre-seed the mcpc DB** at a fixed `MCPC_DB_PATH` (e.g. `/opt/mcpc/mcpc.db`).
   Do NOT try to drive the REPL to do this — seed SQLite directly via the
   client's own Storage class so there's no TTY dependency at build:
   ```python
   # seed_mcp.py
   from pathlib import Path
   from cli_mcp_client.storage import Storage
   s = Storage(Path("/opt/mcpc/mcpc.db"))
   s.save_mcp_server("netcat", "stdio",
                     {"command": "python", "args": ["/opt/netcat-mcp/server.py"]})
   s.close()
   ```
   (Verify the `Storage` constructor + `save_mcp_server` signature against the
   pinned tag before relying on it.)
5. Clean caches; **neutralize package managers**: `pip uninstall -y pip`; `chmod 0000`
   the apt/dpkg family. Keep `nc`/`curl`/`ping`/`python` working.
6. Create non-root user (uid 10001). `chown` the dirs `mcpc` writes at runtime
   (`/opt/mcpc/` for the DB + `history` file) to that user.
7. `USER` the non-root user. `ENTRYPOINT ["mcpc"]`.

### Version pinning
Use build args so a tested triplet is reproducible:
- `LLMCLIENT_REF` — git tag/sha of llmCLIent.
- `NETCAT_MCP_REF` — git tag/sha of netcat-mcp (or vendor it as a git submodule
  under `vendor/netcat-mcp` and `COPY` that — preferred for offline/reproducible
  builds).

---

## Runtime

Manual driving (the current need):
```bash
docker run -it --rm --network host --env-file .env recon-agent:<tag>
# → mcpc REPL; netcat server auto-connects. Try:  agent run <objective>
```

`--network host` (Linux) so scans see the real LAN. Add `--cap-add=NET_RAW` only
if you want the `os_fingerprint` ping/TTL hint (degrades gracefully without it).

### Environment variables
| var | purpose |
|-----|---------|
| `LLM_BASE_URL` | remote OpenAI-compatible base, e.g. `http://llm-host:8000/v1` |
| `LLM_MODEL` | model id |
| `LLM_AUTH_TOKEN` | bearer token / API key |
| `MCPC_DB_PATH` | must match the pre-seeded path, e.g. `/opt/mcpc/mcpc.db` |
| `AGENT_READONLY_PREFIXES` | set to `netcat__` so scan tools auto-approve in hybrid mode |
| `AGENT_MAX_STEPS` | cap on agent reason→act loops (default 25) |
| `AGENT_AUTO_APPROVE_ALL` | leave `0` for manual driving; `1` only for headless |

Ship `.env.example` with these.

---

## Known rough edge (why headless is deferred)

`mcpc` is a `prompt_toolkit` REPL; **all** input — including the agent's
write-approval prompt — goes through it, and on EOF the approval returns *abort*.
So unattended/piped runs need `AGENT_AUTO_APPROVE_ALL=1`, and prompt_toolkit
wants a TTY. For manual use this is a non-issue (`docker run -it` gives a TTY).

**Future headless path (for k8s Jobs):** add a small non-interactive entrypoint
to `llmCLIent` that skips the REPL — load `Config`, run the server autoconnect,
call `AgentRunner.run(objective)`, exit. ~15 lines reusing existing classes
(`Config`, `MCPManager`, `AgentRunner`, `Storage`). Land that upstream, then this
image can offer a `--headless`/objective-via-env mode.

---

## Kubernetes notes (future, not now)

- Shape = **Job / CronJob** (run a sweep → exit), not a Deployment.
- `hostNetwork: true` (the `--network host` equivalent); `NET_RAW` for TTL.
- `LLM_AUTH_TOKEN` via Secret; other config via env/ConfigMap.
- SQLite (sessions/runs) is ephemeral in a pod — write scan **results** to a
  mounted volume / external sink, don't rely on container-local state. PVC for
  `MCPC_DB_PATH` only if run history must survive.
- Needs the headless entrypoint above to run cleanly without a TTY.

---

## Proposed repo layout

```
recon-agent/
  Dockerfile
  seed_mcp.py            # build-time DB seeding (above)
  .env.example
  .dockerignore
  README.md
  vendor/netcat-mcp/     # git submodule, pinned  (or pull via build arg)
  k8s/                   # future
    job.example.yaml
    cronjob.example.yaml
```

---

## Build checklist (for the pick-up session)

- [ ] Confirm `cli_mcp_client.storage.Storage.save_mcp_server(name, transport, config)`
      signature at the pinned llmCLIent tag; adjust `seed_mcp.py` if changed.
- [ ] Write `Dockerfile` per the strategy above; verify `nc -h`, `curl --version`,
      `python /opt/netcat-mcp/server.py` import-check all pass in-build.
- [ ] Write `seed_mcp.py`, run it in-build, confirm the server row exists
      (`mcpc` → `mcp list` shows `netcat`).
- [ ] Non-root user owns `MCPC_DB_PATH` dir + `history`; container starts without
      permission errors.
- [ ] `.env.example`, `.dockerignore`, `README.md` (build + run + manual-driving).
- [ ] Smoke test: `docker run -it --network host --env-file .env recon-agent`,
      then `agent run "profile <a host you own> and summarize open services"`.
- [ ] (Later) headless entrypoint patch to llmCLIent + k8s manifests.

---

## How to resume with Claude

Open a session in this new repo and paste:
> "Build the recon-agent Docker image per PROJECT-BRIEF.md. Start with the
> Dockerfile and seed_mcp.py, pinning llmCLIent and netcat-mcp to <tags>."

Claude has prior context on both `netcat-mcp` (it built it) and `llmCLIent`'s
internals (REPL autoconnect, Storage, AgentRunner, env config).
