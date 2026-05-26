# NetScanner — Signal Cartography

A feature-rich, **web-based** network scanner and discovery tool. It finds every
device on your network, identifies what each one is, maps their open ports and
services, and gives you a **clickable URL** for anything running a web interface.
The UI is a polished dark "constellation atlas" dashboard with card, table, and
interactive topology-map views.

The engine is a single Python file with **zero external dependencies** (standard
library only). It runs a small local web server and serves the dashboard in your
browser. Nothing is sent to the cloud — all scanning and data stay on your machine.

It's also **scriptable and agent-ready**: a one-shot JSON CLI, a Model Context
Protocol (MCP) server for AI assistants, a documented HTTP/OpenAPI surface, and
proactive rogue-device alerts. See [Automation & AI agents](#automation--ai-agents).

---

## Files

| File | Purpose |
|------|---------|
| `netscanner.py` | The scanning engine + local web server + HTTP/MCP API |
| `ui.html` | The dashboard (served by the engine — **keep it next to `netscanner.py`**) |
| `netscanner_mcp.py` | Stdio MCP server for AI agents (keep next to `netscanner.py`) |
| `openapi.yaml` | OpenAPI 3.0 description of the HTTP API (also served at `/openapi.json`) |
| `run.bat` | Double-click launcher for Windows |
| `build.bat` | Builds a standalone `NetScanner.exe` (bundles `ui.html`) |
| `Dockerfile`, `docker-compose.yml`, `.dockerignore` | Run it as a container on a NAS/server |
| `DESIGN_PHILOSOPHY.md`, `signal_cartography.png/.pdf` | The visual design language behind the UI |

> `netscanner.py` and `ui.html` must live in the same folder. Keep
> `netscanner_mcp.py` alongside them too if you want the MCP server. Everything
> else is optional.

---

## Why it's "a local web app" and not pure in-browser JavaScript

A scanner running *entirely* inside a browser tab physically cannot probe your
LAN — browsers sandbox raw network access for security (no ICMP ping, no ARP, no
arbitrary TCP scans). NetScanner uses the standard, capable design: a tiny local
engine does the real scanning and serves the web UI you open in your browser.

---

## Option A — run locally (easiest, no install)

1. Install **Python 3.8+** (https://www.python.org/downloads/ — tick *"Add Python to PATH"*).
2. Double-click **`run.bat`** (or run `python netscanner.py`).
3. Your browser opens at `http://127.0.0.1:8765`; your subnet is auto-detected — press **Scan network**.

```
python netscanner.py                # launch + open browser
python netscanner.py --port 9000    # choose a port
python netscanner.py --no-browser   # don't auto-open the browser
python netscanner.py --host 0.0.0.0 # listen on all interfaces (use with care)
python netscanner.py --scan 192.168.1.0/24 --json   # one-shot scan, no server
```

## Option B — standalone Windows .exe (no Python on the target PC)

Run **`build.bat`** once on a Windows machine with Python. It uses PyInstaller to
produce `dist\NetScanner.exe` — a single file (the UI **and** the MCP server are
bundled inside) you can copy to any Windows PC and double-click. (A Windows
`.exe` must be built on Windows.)

## Option C — Docker on your NAS / server

The app is container-ready. From this folder:

```
docker compose up -d --build
```

Then open **`http://<your-NAS-IP>:8765`** from any browser on your network.

**Host networking is required.** A bridged container sits on its own virtual
network and cannot see your real LAN — no device discovery, no ARP, no mDNS/SNMP.
The provided `docker-compose.yml` sets `network_mode: host` and adds the `NET_RAW`
capability so ICMP ping works.

**You do not need `--privileged`.** NetScanner only uses ordinary sockets and the
`ping` command — it never reconfigures the network or sends raw packets. `NET_RAW`
is the only capability it benefits from (for ICMP), and even that is optional:
without it, discovery still works via TCP connect probing — you just lose ICMP
ping and the TTL-based OS guess. (`NET_ADMIN` is not needed.)

- On **Synology** (Container Manager) or **QNAP** (Container Station), import this
  project and make sure the container uses **host** network mode. If your NAS UI
  won't allow host mode, the app will still load but device discovery will be
  limited to the container's own network.
- Data (scan history, device names/notes, the downloaded vendor DB, baseline and
  events) persists in `./netscanner-data` on the host via the mounted volume.
- Change the port with the `NETSCANNER_PORT` env var if 8765 is taken.

Plain `docker` equivalent:

```
docker build -t netscanner .
docker run -d --name netscanner --network host \
  --cap-add NET_RAW \
  -e NETSCANNER_PORT=8765 -v "$PWD/netscanner-data:/data" \
  --restart unless-stopped netscanner
```

---

## Features

**Discovery & identification**
- Auto-detects your subnet (editable — scan any CIDR, e.g. `10.0.0.0/24`)
- Concurrent ping sweep **plus a TCP fallback**, so it finds devices that block ping
- MAC address resolution from the ARP table
- Vendor lookup from the MAC, with a **one-click "Download full" button** that
  fetches the complete IEEE OUI database for exhaustive vendor names
- Reverse-DNS hostnames
- **mDNS / Bonjour** discovery — surfaces Chromecasts, AirPlay, printers, Apple
  devices, Sonos, HomeKit, etc., with friendly names and service types
- **SNMP** (v2c) queries managed switches, printers and access points for their
  system name and description
- **NetBIOS** and **SSDP/UPnP** probing for Windows names and smart-device models
- OS guess (TTL) and device-type guess (ports + vendor + mDNS + SNMP)
- Round-trip latency

**Ports, services & exposure**
- Parallel TCP connect scanning — **Quick** (~90 ports), **Extended** (1–1024),
  **Full** (1–65535) — with service names and banner grabbing
- **Web URL detection** — HTTP/HTTPS ports become clickable links that open the
  device's web UI (80 → `http://ip`, 443 → `https://ip`, plus 8080/8443/8123/…)
- **Exposure scoring** — each device gets a risk tier (none → critical) based on
  risky open ports (Telnet, RDP, SMB, VNC, exposed databases, unauth Docker, …)

**Views & workflow**
- **Table** (default), **Cards**, and an interactive **Topology map** with
  multiple layouts and Obsidian-style floating physics
- Search, filter (web-only / open-ports / new / named), and sort
- **Live monitoring**: auto re-scan on a timer with **new-device detection** and
  **desktop notifications** (browser Notification API)
- **Scan history + change detection** — every scan is saved; reload and compare
- **Wake-on-LAN**, **custom names/notes** per device, **CSV/JSON export**

---

## Automation & AI agents

Everything below is pure standard library — no extra installs.

### One-shot CLI scan (no server)

Run a single scan and print the result — perfect for cron jobs and scripts:

```
python netscanner.py --scan 192.168.1.0/24                          # table output
python netscanner.py --scan 192.168.1.0/24 --json                   # machine-readable JSON
python netscanner.py --scan 192.168.1.0/24 --ports --profile quick --json
python netscanner.py --scan "10.0.0.0/24, 10.0.5.10" --no-snmp --no-mdns
```

Every device carries a `risk` assessment (`none`/`low`/`medium`/`high`/`critical`)
derived from its open ports. Exit code is non-zero if the targets are invalid.

### MCP server for AI agents (stdio)

`netscanner_mcp.py` is a [Model Context Protocol](https://modelcontextprotocol.io)
server, so assistants like Claude can scan and reason about your network. Point
your MCP client at it:

```
command: python
args:    ["/full/path/to/netscanner_mcp.py"]
```

Example `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "netscanner": {
      "command": "python",
      "args": ["C:\\path\\to\\netscanner_mcp.py"]
    }
  }
}
```

Tools exposed: `network_info`, `scan_network`, `list_devices`, `get_device`,
`find`, `whats_new`, `exposure_report`, `scan_ports`, `wake_device`,
`name_device`, `scan_history`, `get_baseline`, `set_baseline`, `check_rogues`,
`recent_events`. The MCP server shares NetScanner's data directory, so it sees
the same scan history your web UI produces.

### Remote MCP over HTTP

The web server also speaks MCP at `POST /mcp` (JSON-RPC 2.0), so a remote agent
can reach a NetScanner running on your NAS. Authorize it with an **API token**
(create one in the dashboard under **Settings → API tokens**, or use the legacy
`NETSCANNER_TOKEN` env var):

```
curl -X POST http://nas:8765/mcp \
  -H "Authorization: Bearer nsk_your_token" \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/list"}'
```

See [Security & access control](#security--access-control) for the full picture.
A `?token=` query parameter is also accepted (avoid it where requests get logged).

### OpenAPI

The full HTTP API is described at `GET /openapi.json` and `GET /openapi.yaml`
(also committed as `openapi.yaml`). Load it into Swagger UI, Postman, or an
agent's tool layer.

### Proactive monitoring: baseline + rogue alerts

Approve your current network as a known-good **baseline**, then every later scan
is diffed against it. The first time an **unapproved device** or an **unapproved
open port** appears, NetScanner logs an event and (optionally) pushes it out.

- Manage the baseline: `POST /api/baseline {"action":"set"|"approve"|"clear"}`,
  or the `set_baseline` MCP tool.
- Read recent events: `GET /api/events`, or the `recent_events` MCP tool.
- Deliver alerts to a **webhook** (HTTP POST) and/or **MQTT** by setting env vars
  (below). Each alert fires once (de-duplicated) until you re-approve the baseline.

Pair this with **Live monitoring** in the UI (or a cron'd `--scan`) for continuous
rogue-device detection with push notifications.

### Environment variables

| Variable | Purpose |
|----------|---------|
| `NETSCANNER_HOST` | Bind address (default `127.0.0.1`; Docker uses `0.0.0.0`) |
| `NETSCANNER_PORT` | Port (default `8765`) |
| `NETSCANNER_NO_BROWSER` | Don't auto-open a browser |
| `NETSCANNER_DATA` | Data dir (history, names, vendor DB, baseline, events, tokens) |
| `NETSCANNER_USER` | Admin username (default `admin`); seeds first launch |
| `NETSCANNER_PASS` | Seeds/overrides the admin password (default login is `admin`) |
| `NETSCANNER_TRUST_LOCALHOST` | `0` (default) prompts everywhere; `1` skips auth for `127.0.0.1` |
| `NETSCANNER_OPEN` | `1` disables auth entirely (trusted segments only) |
| `NETSCANNER_TOKEN` | Legacy static bearer token (managed tokens in the UI are preferred) |
| `NETSCANNER_WEBHOOK` | URL to POST events to |
| `NETSCANNER_MQTT` | MQTT broker `host` or `host:port` |
| `NETSCANNER_MQTT_TOPIC` | MQTT topic (default `netscanner/events`) |
| `NETSCANNER_MQTT_USER` / `NETSCANNER_MQTT_PASS` | MQTT credentials (optional) |

---

## Security & access control

NetScanner is **secure by default**. On first launch it creates an admin login
of **`admin` / `admin`** and requires it for the **whole** app — the dashboard,
every `/api/*` endpoint, and `/mcp`. Change it immediately under **Settings** in
the dashboard.

**Sign in:**

- **Humans** — log in with the admin username/password (HTTP Basic auth). Change
  them under **Settings → Admin login**; the new credentials are hashed (PBKDF2)
  and persisted to `netscanner-data/auth.json`, so they survive restarts. You can
  also seed the initial password with `NETSCANNER_PASS` (and `NETSCANNER_USER`),
  which additionally works as a recovery/override login.
- **Agents & scripts** — create **API tokens** under **Settings → API tokens**.
  Each token is named, shows when it was created and last used, and is
  **long-lived by default** (set an expiry in days if you want one). Token values
  stay **viewable**, so you can copy one back into an agent's config later. Use
  them with `Authorization: Bearer <token>` on the API and `/mcp`. Tokens live in
  `netscanner-data/tokens.json` (gitignored) — treat it as a secret.

**Prompting & localhost.** By default you're prompted everywhere, including on
the machine running NetScanner (`NETSCANNER_TRUST_LOCALHOST=0`). For a
frictionless local desktop, set `NETSCANNER_TRUST_LOCALHOST=1` to skip the prompt
for `127.0.0.1` while still requiring it from other devices.

**Run fully open** on a genuinely trusted segment with `NETSCANNER_OPEN=1`, which
disables auth entirely (a banner reminds you it's off).

### HTTPS with an nginx reverse proxy

NetScanner serves plain HTTP, so passwords and tokens travel in cleartext. On a
NAS or any untrusted segment, put it behind a reverse proxy that terminates TLS:

```nginx
server {
    listen 443 ssl;
    server_name netscanner.example.lan;

    ssl_certificate     /etc/nginx/certs/netscanner.crt;
    ssl_certificate_key /etc/nginx/certs/netscanner.key;

    location / {
        proxy_pass http://127.0.0.1:8765;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        # Pass the caller's credentials (Bearer token / Basic) through:
        proxy_set_header Authorization $http_authorization;
    }
}
```

**Gotcha:** nginx connects to NetScanner from `127.0.0.1`. Keep
`NETSCANNER_TRUST_LOCALHOST` at its default (`0`) so proxied requests are still
authenticated — setting it to `1` would make every proxied request look local and
skip auth. Two working patterns:

1. **App-enforced auth** (keeps in-app token management): set `NETSCANNER_PASS`
   and/or create API tokens, set `NETSCANNER_TRUST_LOCALHOST=0`, and let nginx
   pass `Authorization` through (as above). nginx only does TLS.
2. **Proxy-enforced auth**: let nginx do its own `auth_basic`, and leave
   NetScanner trusting localhost. Simpler, but you lose per-token management.

Either way, don't expose NetScanner directly to the internet.

---

## Notes & tips

- **Run as Administrator / root** for the most complete ARP and discovery results.
- **Allow it through your firewall** on private networks the first time.
- The local launcher binds to `127.0.0.1` only. The Docker/`--host 0.0.0.0` modes
  expose it to your whole LAN — appropriate for a NAS, but don't expose it to the
  internet. If you do expose `/mcp`, set `NETSCANNER_TOKEN`.
- **Full** port scans (65,535 ports/host) are thorough but slow — best used on a
  single host via the per-device **Scan ports** button.
- The downloaded vendor database is saved in the data folder and loaded
  automatically on the next scan.

## Ethical use

Only scan networks you own or are authorized to test.

---

## Continuous integration

This repo ships a GitHub Actions workflow (`.github/workflows/build.yml`) that runs on every push and pull request:

- **Docker image** → built and pushed to the GitHub Container Registry (GHCR) as `ghcr.io/<owner>/<repo>:latest` (and a `:<commit-sha>` tag). Pull and run it on your NAS with:

  ```
  docker run -d --name netscanner --network host \
    --cap-add NET_RAW \
    -v "$PWD/netscanner-data:/data" --restart unless-stopped \
    ghcr.io/<owner>/<repo>:latest
  ```

- **Standalone Windows .exe** → built with PyInstaller on a Windows runner and uploaded as a build **artifact** on every run. Pushing a version tag (e.g. `git tag v1.0.0 && git push --tags`) also publishes the `.exe` on a GitHub **Release**.

No secrets are required — the workflow authenticates to GHCR with the built-in `GITHUB_TOKEN`. After the first successful run, make the GHCR package public from your repo's *Packages* page if you want others to pull it.

## Privacy

Your scan results are local only. `.gitignore` excludes `netscanner_data/` (IPs, MACs, hostnames, device names/notes, scan history, baseline, events, API tokens and the admin login) and common secret files so they're never committed.
