# syntax=docker/dockerfile:1
#
# netcat-mcp — minimal, hardened image.
#
#   * Debian 12 "bookworm" slim base (glibc; same OpenBSD netcat we tested against).
#   * Runtime binaries only: netcat-openbsd, curl, iputils-ping, ca-certificates.
#   * Python deps installed from requirements.txt, then PACKAGE MANAGERS ARE
#     NEUTRALIZED so nothing can install software at runtime:
#       - pip is uninstalled outright
#       - apt / apt-get / apt-cache / dpkg* are chmod 0000 (non-executable)
#   * Runs as a non-root system user.
#   * Talks MCP over stdio — designed to be launched by a client as
#     `docker run -i --rm --network host netcat-mcp`.

FROM python:3.12-slim-bookworm

LABEL org.opencontainers.image.title="netcat-mcp" \
      org.opencontainers.image.description="MCP server for network profiling via netcat + curl" \
      org.opencontainers.image.source="https://github.com/finleyh" \
      org.opencontainers.image.licenses="MIT"

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /app

# ---- single build layer: install everything, then lock the box down ----
COPY requirements.txt ./
RUN set -eux; \
    apt-get update; \
    apt-get install -y --no-install-recommends \
        netcat-openbsd \
        curl \
        iputils-ping \
        ca-certificates; \
    # install Python deps
    pip install --no-cache-dir -r requirements.txt; \
    # strip apt metadata + caches
    apt-get clean; \
    rm -rf /var/lib/apt/lists/* /var/cache/apt/archives/* /root/.cache; \
    # --- neutralize package managers (defense in depth) ---
    # pip: remove it entirely (also kills `python -m pip`)
    pip uninstall -y pip || true; \
    # apt/dpkg: make the binaries non-executable (reversible only by root)
    for pm in \
        /usr/bin/apt /usr/bin/apt-get /usr/bin/apt-cache /usr/bin/apt-key \
        /usr/bin/apt-config /usr/bin/apt-mark \
        /usr/bin/dpkg /usr/bin/dpkg-deb /usr/bin/dpkg-query /usr/bin/dpkg-split; \
    do \
        if [ -e "$pm" ]; then chmod 0000 "$pm"; fi; \
    done; \
    # sanity: the binaries we DO need must still work
    nc -h 2>&1 | head -n1; \
    curl --version | head -n1; \
    # create the unprivileged runtime user
    useradd --system --no-create-home --uid 10001 scanner

# ---- application code ----
COPY netcat.py curl.py tools.py server.py ./

USER scanner

# stdio transport: the MCP client attaches to this process's stdin/stdout.
ENTRYPOINT ["python", "server.py"]
