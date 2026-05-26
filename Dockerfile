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

VOLUME ["/data"]
EXPOSE 8765

# Note: with `--network host` (recommended) the EXPOSE above is informational;
# the app binds directly to the host's port 8765.
CMD ["python", "netryx.py"]
