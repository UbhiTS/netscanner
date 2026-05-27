# Netryx — self-contained container image.
# Pure-stdlib Python app; the only OS deps are the tools it shells out to
# (ping, ip neigh/route, arp). Build small and run with HOST networking so the
# container can actually see your LAN, ARP table, mDNS and SNMP traffic.

FROM python:3.12-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
        iputils-ping iproute2 net-tools \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
# netryx_mcp.py is required for the /mcp endpoint; openapi.yaml is optional
# (the spec is also generated dynamically) but handy to ship.
COPY netryx.py netryx_mcp.py ui.html openapi.yaml /app/

# Scan history, device names/notes, vendor DB, baseline and events persist here.
ENV NETRYX_DATA=/data \
    NETRYX_HOST=0.0.0.0 \
    NETRYX_PORT=8765 \
    NETRYX_NO_BROWSER=1

# Run as an unprivileged user (uid 10001) — smaller blast radius under host
# networking. ICMP ping still works via the NET_RAW capability (see compose).
# NOTE: with a host bind-mount for /data, chown it once on the host so this
# user can write:  sudo chown -R 10001:10001 ./netryx-data
# (or override in compose with  user: "0:0"  to revert to root).
RUN useradd -r -u 10001 -m -d /home/netryx netryx \
    && mkdir -p /data \
    && chown -R netryx:netryx /data /app
USER netryx

VOLUME ["/data"]
EXPOSE 8765

# Liveness probe: the unauthenticated /login page returns 200 when the server
# is up. (No curl in slim — use Python's stdlib.)
HEALTHCHECK --interval=30s --timeout=4s --start-period=10s --retries=3 \
    CMD python -c "import os,urllib.request; urllib.request.urlopen('http://127.0.0.1:'+os.environ.get('NETRYX_PORT','8765')+'/login', timeout=3)" || exit 1

# Note: with `--network host` (recommended) the EXPOSE above is informational;
# the app binds directly to the host's port 8765.
CMD ["python", "netryx.py"]
