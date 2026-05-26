#!/usr/bin/env python3
"""Netryx MCP server (stdio transport).

A zero-dependency Model Context Protocol server that lets AI agents talk to
Netryx: scan the LAN, list/search devices, assess exposure, scan ports,
wake machines and name devices. It speaks JSON-RPC 2.0 over newline-delimited
stdin/stdout (the stdio MCP transport).

It imports the Netryx engine (``netryx.py``, kept next to this file) and
shares the same on-disk data directory, so it sees the same scan history the
web UI produces and vice-versa.

Run it directly:

    python netryx_mcp.py

or wire it into an MCP client (Claude Desktop, etc.) as a stdio server with
command ``python`` and args ``["/path/to/netryx_mcp.py"]``.

Pure Python standard library only.
"""

import json
import os
import sys
import contextlib

# Import the engine that lives next to this file.
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import netryx as engine  # noqa: E402

SERVER_NAME = "netryx"
SERVER_VERSION = "1.0.0"
DEFAULT_PROTOCOL = "2024-11-05"

# The real stdout is reserved for JSON-RPC frames. Anything the engine prints
# (it shouldn't, but be safe) is redirected to stderr so it never corrupts the
# protocol stream.
_OUT = sys.stdout
_TIER_ORDER = {"none": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


# --------------------------------------------------------------------------- #
# Shared helpers over the engine's data
# --------------------------------------------------------------------------- #

def _current_devices():
    """The most relevant device set: the live in-process result if this server
    has run a scan, otherwise the newest saved history snapshot on disk."""
    devs = engine.LAST_RESULTS.get("devices") or []
    if devs:
        return devs, {"source": "live", "subnet": engine.LAST_RESULTS.get("subnet")}
    hist = engine.list_history()
    if hist:
        rec = engine._load_json(os.path.join(engine.HISTORY_DIR, hist[0]["file"]), None)
        if rec:
            return rec.get("devices", []), {"source": "history",
                                            "file": hist[0]["file"], "time": rec.get("time")}
    return [], {"source": "none"}


def _slim(d):
    """A compact device view for list/search results (full record is large)."""
    return {
        "ip": d.get("ip"),
        "mac": d.get("mac"),
        "name": d.get("name"),
        "hostname": d.get("hostname") or d.get("mdns_name"),
        "vendor": d.get("vendor"),
        "device_type": d.get("device_type"),
        "os": d.get("os"),
        "model": d.get("model"),
        "open_ports": [p.get("port") for p in d.get("ports", [])],
        "web_urls": [p.get("url") for p in d.get("ports", []) if p.get("url")],
        "risk": (d.get("risk") or engine.risk_of(d)).get("tier"),
        "is_gateway": d.get("is_gateway", False),
        "is_self": d.get("is_self", False),
        "new": d.get("new", False),
    }


# --------------------------------------------------------------------------- #
# Tools
# --------------------------------------------------------------------------- #

def tool_network_info(args):
    return {
        "local_ip": engine.get_primary_ip(),
        "gateway": engine.default_gateway(),
        "suggested_subnet": engine.default_subnet(),
        "platform": engine.platform.system() + " " + engine.platform.release(),
        "cpu": os.cpu_count(),
        "oui": engine.oui_status(),
        "data_dir": engine.DATA_DIR,
    }


def tool_scan_network(args):
    targets = (args.get("targets") or "").strip() or engine.default_subnet()
    res = engine.discover(
        targets,
        scan_ports=bool(args.get("scan_ports", False)),
        port_profile=args.get("port_profile", "quick"),
        use_mdns=bool(args.get("use_mdns", True)),
        use_snmp=bool(args.get("use_snmp", True)),
        req_workers=args.get("workers", "auto"),
    )
    if res.get("error"):
        raise ValueError(res["error"])
    return {
        "targets": targets,
        "count": len(res["devices"]),
        "new_devices": len(res.get("new_devices") or []),
        "new_ports": res.get("new_ports", 0),
        "note": res.get("note"),
        "devices": [_slim(d) for d in res["devices"]],
    }


def tool_list_devices(args):
    devs, meta = _current_devices()
    return {"source": meta, "count": len(devs), "devices": [_slim(d) for d in devs]}


def tool_get_device(args):
    ip = (args.get("ip") or "").strip()
    mac = (args.get("mac") or "").strip().lower()
    if not ip and not mac:
        raise ValueError("provide 'ip' or 'mac'")
    devs, meta = _current_devices()
    for d in devs:
        if (ip and d.get("ip") == ip) or (mac and (d.get("mac") or "").lower() == mac):
            return {"source": meta, "device": d}  # full record
    return {"source": meta, "device": None, "note": "not found in latest scan"}


def tool_find(args):
    q = (args.get("query") or "").strip().lower()
    if not q:
        raise ValueError("provide 'query'")
    devs, meta = _current_devices()
    hits = []
    for d in devs:
        hay = " ".join(str(x) for x in [
            d.get("ip"), d.get("mac"), d.get("name"), d.get("hostname"),
            d.get("mdns_name"), d.get("vendor"), d.get("model"), d.get("device_type"),
            d.get("os"), " ".join(d.get("mdns_services", []) or []),
            " ".join("%s %s" % (p.get("port"), p.get("service")) for p in d.get("ports", [])),
        ] if x).lower()
        if q in hay:
            hits.append(_slim(d))
    return {"source": meta, "query": q, "count": len(hits), "devices": hits}


def tool_whats_new(args):
    hist = engine.list_history()
    if not hist:
        return {"new_devices": [], "new_ports": [], "note": "no scans recorded yet"}
    newest = engine._load_json(os.path.join(engine.HISTORY_DIR, hist[0]["file"]), {}) or {}
    new_list = newest.get("devices", [])
    if len(hist) < 2:
        nd = [_slim(d) for d in new_list if d.get("new")]
        np = [{"ip": d.get("ip"), "port": p.get("port"), "service": p.get("service")}
              for d in new_list for p in d.get("ports", []) if p.get("new")]
        return {"compared": [hist[0]["file"], None], "new_devices": nd,
                "new_ports": np, "note": "only one scan on record; using its flags"}
    prev = engine._load_json(os.path.join(engine.HISTORY_DIR, hist[1]["file"]), {}) or {}
    prev_devs = prev.get("devices", [])
    prev_keys = {engine._dkey(d) for d in prev_devs}
    prev_ports = {engine._dkey(d): {p.get("port") for p in d.get("ports", [])} for d in prev_devs}
    new_devices, new_ports = [], []
    for d in new_list:
        k = engine._dkey(d)
        if k not in prev_keys:
            new_devices.append(_slim(d))
        else:
            had = prev_ports.get(k, set())
            for p in d.get("ports", []):
                if p.get("port") not in had:
                    new_ports.append({"ip": d.get("ip"), "port": p.get("port"),
                                      "service": p.get("service")})
    return {"compared": [hist[0]["file"], hist[1]["file"]],
            "new_devices": new_devices, "new_ports": new_ports}


def tool_exposure_report(args):
    min_tier = (args.get("min_tier") or "low").lower()
    floor = _TIER_ORDER.get(min_tier, 1)
    devs, meta = _current_devices()
    rows, summary = [], {"critical": 0, "high": 0, "medium": 0, "low": 0, "none": 0}
    for d in devs:
        r = d.get("risk") or engine.risk_of(d)
        summary[r["tier"]] = summary.get(r["tier"], 0) + 1
        if _TIER_ORDER.get(r["tier"], 0) >= floor:
            rows.append({
                "ip": d.get("ip"), "mac": d.get("mac"),
                "name": d.get("name") or d.get("hostname") or d.get("mdns_name"),
                "device_type": d.get("device_type"),
                "tier": r["tier"], "score": r["score"], "reasons": r["reasons"],
                "open_ports": [p.get("port") for p in d.get("ports", [])],
            })
    rows.sort(key=lambda x: (-_TIER_ORDER.get(x["tier"], 0), -x["score"]))
    return {"source": meta, "summary": summary, "min_tier": min_tier,
            "flagged": len(rows), "devices": rows}


def tool_scan_ports(args):
    ip = (args.get("ip") or "").strip()
    if not ip:
        raise ValueError("provide 'ip'")
    profile = args.get("profile", "extended")
    if profile not in engine.PORT_PROFILES:
        profile = "extended"
    _jid, job = engine.new_job("portscan")
    engine.run_portscan(job, ip, profile, args.get("workers", "auto"))
    return {"ip": ip, "profile": profile, "open_ports": job.get("result", [])}


def tool_wake_device(args):
    mac = (args.get("mac") or "").strip()
    if not mac:
        raise ValueError("provide 'mac'")
    ok = engine.wake_on_lan(mac)
    return {"ok": bool(ok), "mac": mac}


def _snmp_args(args):
    ip = (args.get("ip") or args.get("host") or "").strip()
    if not ip:
        raise ValueError("provide 'ip'")
    community = args.get("community") or "public"
    try:
        timeout = max(0.2, min(5.0, float(args.get("timeout", 1.5))))
    except Exception:
        timeout = 1.5
    try:
        port = int(args.get("port", 161))
    except Exception:
        port = 161
    return ip, community, timeout, port


def tool_snmp_get(args):
    ip, community, timeout, port = _snmp_args(args)
    oids = args.get("oids") or ([args.get("oid")] if args.get("oid") else [])
    if not oids:
        raise ValueError("provide 'oid' or 'oids'")
    res = engine.snmp_get(ip, oids, community, timeout, port)
    return {"ip": ip, "community": community, "results": res,
            "note": None if res else "no response (host unreachable, SNMP disabled, or wrong community)"}


def tool_snmp_walk(args):
    ip, community, timeout, port = _snmp_args(args)
    base = (args.get("oid") or args.get("base_oid") or "").strip()
    if not base:
        raise ValueError("provide 'oid' (the subtree root to walk)")
    rows = engine.snmp_walk(ip, base, community, timeout, args.get("max_rows", 256), port)
    return {"ip": ip, "base_oid": base, "community": community, "count": len(rows), "results": rows}


def tool_name_device(args):
    mac = (args.get("mac") or "").strip().lower()
    if not mac:
        raise ValueError("provide 'mac'")
    ok = engine.save_device_meta(mac, args.get("name"), args.get("notes"))
    for d in engine.LAST_RESULTS.get("devices", []):
        if (d.get("mac") or "").lower() == mac:
            if args.get("name") is not None:
                d["name"] = args.get("name")
            if args.get("notes") is not None:
                d["notes"] = args.get("notes")
    return {"ok": bool(ok), "mac": mac}


def tool_scan_history(args):
    f = (args.get("file") or "").strip()
    if f:
        import re
        if not re.match(r"^scan_\d+\.json$", f):
            raise ValueError("bad history file name")
        rec = engine._load_json(os.path.join(engine.HISTORY_DIR, f), None)
        if not rec:
            raise ValueError("history snapshot not found")
        return {"file": f, "time": rec.get("time"), "subnet": rec.get("subnet"),
                "count": rec.get("count"), "devices": [_slim(d) for d in rec.get("devices", [])]}
    return {"snapshots": engine.list_history()}


def tool_get_baseline(args):
    b = engine.load_baseline()
    devs, meta = _current_devices()
    diff = engine.diff_against_baseline(devs, b) if b.get("devices") else None
    return {"created": b.get("created"), "updated": b.get("updated"),
            "size": len(b.get("devices", {})), "source": meta, "diff": diff}


def tool_set_baseline(args):
    action = (args.get("action") or "set").lower()
    devs, meta = _current_devices()
    if action == "clear":
        engine.clear_baseline()
        engine._save_json(engine.ALERTS_FILE, [])
        return {"ok": True, "action": "clear", "size": 0}
    if action == "approve":
        b = engine.approve_devices(args.get("keys") or [], devs)
        return {"ok": True, "action": "approve", "size": len(b.get("devices", {}))}
    b = engine.baseline_from_devices(devs)
    engine._save_json(engine.ALERTS_FILE, [])
    return {"ok": True, "action": "set", "size": len(b.get("devices", {})), "source": meta}


def tool_check_rogues(args):
    devs, meta = _current_devices()
    b = engine.load_baseline()
    if not b.get("devices"):
        return {"note": "no baseline set; call set_baseline first", "source": meta}
    return {"source": meta, "diff": engine.diff_against_baseline(devs, b)}


def tool_recent_events(args):
    try:
        limit = int(args.get("limit", 50) or 50)
    except Exception:
        limit = 50
    return {"events": engine.list_events(limit)}


TOOLS = [
    {
        "name": "network_info",
        "description": "Get this host's network context: local IP, default gateway, a suggested subnet to scan, platform and OUI database status. Call this first to learn what to scan.",
        "inputSchema": {"type": "object", "properties": {}},
        "_fn": tool_network_info,
    },
    {
        "name": "scan_network",
        "description": "Run a live discovery scan of the LAN and return the devices found. Discovers hosts, MAC/vendor, hostnames, mDNS/SNMP/UPnP details, and (optionally) open ports. Saves the result to scan history.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "targets": {"type": "string", "description": "CIDR/IP/range list, e.g. '192.168.1.0/24, 10.0.0.5'. Defaults to the auto-detected local subnet."},
                "scan_ports": {"type": "boolean", "description": "Also scan TCP ports on each live host (slower). Default false."},
                "port_profile": {"type": "string", "enum": ["quick", "extended", "full"], "description": "Port set when scan_ports is true. Default 'quick'."},
                "use_mdns": {"type": "boolean", "description": "Use mDNS/Bonjour discovery. Default true."},
                "use_snmp": {"type": "boolean", "description": "Probe SNMP. Default true."},
                "workers": {"type": "string", "description": "Concurrency: a number or 'auto'. Default 'auto'."},
            },
        },
        "_fn": tool_scan_network,
    },
    {
        "name": "list_devices",
        "description": "List devices from the most recent scan (live if this server scanned, otherwise the newest saved snapshot). Returns a compact view per device.",
        "inputSchema": {"type": "object", "properties": {}},
        "_fn": tool_list_devices,
    },
    {
        "name": "get_device",
        "description": "Get the full record for a single device by IP or MAC from the latest scan.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "ip": {"type": "string", "description": "Device IP address."},
                "mac": {"type": "string", "description": "Device MAC address."},
            },
        },
        "_fn": tool_get_device,
    },
    {
        "name": "find",
        "description": "Search the latest scan's devices by a free-text query, matching IP, MAC, hostname, custom name, vendor, model, device type, OS, mDNS services and port/service names.",
        "inputSchema": {
            "type": "object",
            "properties": {"query": {"type": "string", "description": "Text to search for, e.g. 'printer', 'apple', '8080', 'synology'."}},
            "required": ["query"],
        },
        "_fn": tool_find,
    },
    {
        "name": "whats_new",
        "description": "Compare the two most recent scans and report devices and open ports that newly appeared. With only one scan on record, reports that scan's own new-device/new-port flags.",
        "inputSchema": {"type": "object", "properties": {}},
        "_fn": tool_whats_new,
    },
    {
        "name": "exposure_report",
        "description": "Assess network exposure: rank devices by a risk score derived from their open ports (e.g. Telnet, RDP, SMB, exposed databases). Returns reasons per device and a tier summary.",
        "inputSchema": {
            "type": "object",
            "properties": {"min_tier": {"type": "string", "enum": ["low", "medium", "high", "critical"], "description": "Only include devices at or above this tier. Default 'low'."}},
        },
        "_fn": tool_exposure_report,
    },
    {
        "name": "scan_ports",
        "description": "Scan TCP ports on a single host and return open ports with service names, banners and clickable web URLs.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "ip": {"type": "string", "description": "Target host IP."},
                "profile": {"type": "string", "enum": ["quick", "extended", "full"], "description": "Port set. Default 'extended'. 'full' = all 65535 ports (slow)."},
                "workers": {"type": "string", "description": "Concurrency: a number or 'auto'."},
            },
            "required": ["ip"],
        },
        "_fn": tool_scan_ports,
    },
    {
        "name": "wake_device",
        "description": "Send a Wake-on-LAN magic packet to a MAC address to power on a sleeping machine.",
        "inputSchema": {
            "type": "object",
            "properties": {"mac": {"type": "string", "description": "Target MAC address, e.g. 'AA:BB:CC:DD:EE:FF'."}},
            "required": ["mac"],
        },
        "_fn": tool_wake_device,
    },
    {
        "name": "snmp_get",
        "description": "Send an SNMP v2c GET to a host and return the value(s) for one or more OIDs. Read specific values from switches, printers, access points, UPSes, NAS units, etc.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "ip": {"type": "string", "description": "Target host IP."},
                "oid": {"type": "string", "description": "A single OID, e.g. 1.3.6.1.2.1.1.5.0 (sysName)."},
                "oids": {"type": "array", "items": {"type": "string"}, "description": "Multiple OIDs in one request."},
                "community": {"type": "string", "description": "SNMP community string. Default 'public'."},
                "timeout": {"type": "number", "description": "Seconds to wait (default 1.5)."},
                "port": {"type": "integer", "description": "UDP port (default 161)."}
            },
            "required": ["ip"]
        },
        "_fn": tool_snmp_get,
    },
    {
        "name": "snmp_walk",
        "description": "Walk an SNMP v2c subtree (GETNEXT) under an OID and return every row in order - e.g. an interface table (ifDescr), ARP table, or printer supply levels.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "ip": {"type": "string", "description": "Target host IP."},
                "oid": {"type": "string", "description": "Subtree root OID to walk, e.g. 1.3.6.1.2.1.2.2.1.2 (ifDescr)."},
                "community": {"type": "string", "description": "SNMP community string. Default 'public'."},
                "max_rows": {"type": "integer", "description": "Maximum rows to return (default 256)."},
                "timeout": {"type": "number", "description": "Per-request seconds (default 1.5)."},
                "port": {"type": "integer", "description": "UDP port (default 161)."}
            },
            "required": ["ip", "oid"]
        },
        "_fn": tool_snmp_walk,
    },
    {
        "name": "name_device",
        "description": "Save a custom name and/or notes for a device (keyed by MAC). Persists across scans.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "mac": {"type": "string", "description": "Device MAC address."},
                "name": {"type": "string", "description": "Friendly name to assign."},
                "notes": {"type": "string", "description": "Free-form notes."},
            },
            "required": ["mac"],
        },
        "_fn": tool_name_device,
    },
    {
        "name": "scan_history",
        "description": "List saved scan snapshots, or (with 'file') return the devices from a specific snapshot.",
        "inputSchema": {
            "type": "object",
            "properties": {"file": {"type": "string", "description": "A snapshot file name like 'scan_1700000000.json'. Omit to list all snapshots."}},
        },
        "_fn": tool_scan_history,
    },
    {
        "name": "get_baseline",
        "description": "Show the known-good baseline (approved devices and their approved ports) and, if set, a live diff of the latest scan against it.",
        "inputSchema": {"type": "object", "properties": {}},
        "_fn": tool_get_baseline,
    },
    {
        "name": "set_baseline",
        "description": "Manage the baseline. action 'set' approves the entire latest scan as known-good; 'approve' adds specific devices by key (mac or ip); 'clear' removes the baseline. Setting/clearing also resets alert de-duplication.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "action": {"type": "string", "enum": ["set", "approve", "clear"], "description": "Default 'set'."},
                "keys": {"type": "array", "items": {"type": "string"}, "description": "For action 'approve': device keys (MAC or IP) to approve."},
            },
        },
        "_fn": tool_set_baseline,
    },
    {
        "name": "check_rogues",
        "description": "Diff the latest scan against the baseline without changing anything: returns rogue (unapproved) devices, unapproved open ports, and approved devices currently missing.",
        "inputSchema": {"type": "object", "properties": {}},
        "_fn": tool_check_rogues,
    },
    {
        "name": "recent_events",
        "description": "Return recent proactive events (rogue devices, new open ports) detected against the baseline, newest first.",
        "inputSchema": {
            "type": "object",
            "properties": {"limit": {"type": "integer", "description": "Max events to return. Default 50."}},
        },
        "_fn": tool_recent_events,
    },
]
TOOL_INDEX = {t["name"]: t for t in TOOLS}


# --------------------------------------------------------------------------- #
# JSON-RPC / MCP plumbing
# --------------------------------------------------------------------------- #

def _ok(rid, result):
    return {"jsonrpc": "2.0", "id": rid, "result": result}


def _err(rid, code, message):
    return {"jsonrpc": "2.0", "id": rid, "error": {"code": code, "message": message}}


def _public_tools():
    return [{"name": t["name"], "description": t["description"],
             "inputSchema": t["inputSchema"]} for t in TOOLS]


def dispatch(req):
    """Process one JSON-RPC request object and return a response dict.

    Returns None for notifications (requests with no 'id'), which expect no
    reply. Shared by the stdio loop and the HTTP /mcp endpoint in the engine.
    """
    if not isinstance(req, dict) or req.get("jsonrpc") != "2.0":
        rid = req.get("id") if isinstance(req, dict) else None
        return _err(rid, -32600, "Invalid Request")
    method = req.get("method")
    rid = req.get("id")
    params = req.get("params") or {}
    is_notification = "id" not in req

    if method == "initialize":
        proto = params.get("protocolVersion") or DEFAULT_PROTOCOL
        return _ok(rid, {
            "protocolVersion": proto,
            "capabilities": {"tools": {"listChanged": False}},
            "serverInfo": {"name": SERVER_NAME, "version": SERVER_VERSION},
        })
    if method in ("notifications/initialized", "initialized"):
        return None
    if method == "ping":
        return _ok(rid, {})
    if method == "tools/list":
        return _ok(rid, {"tools": _public_tools()})
    if method == "tools/call":
        name = params.get("name")
        arguments = params.get("arguments") or {}
        tool = TOOL_INDEX.get(name)
        if not tool:
            return _err(rid, -32602, "Unknown tool: %s" % name)
        try:
            with contextlib.redirect_stdout(sys.stderr):
                out = tool["_fn"](arguments)
            return _ok(rid, {
                "content": [{"type": "text", "text": json.dumps(out, indent=2, default=str)}],
                "isError": False,
            })
        except Exception as e:
            return _ok(rid, {
                "content": [{"type": "text", "text": "Error: %s" % e}],
                "isError": True,
            })
    if is_notification:
        return None
    return _err(rid, -32601, "Method not found: %s" % method)


def _send(msg):
    _OUT.write(json.dumps(msg) + "\n")
    _OUT.flush()


def main():
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            req = json.loads(line)
        except Exception:
            _send(_err(None, -32700, "Parse error"))
            continue
        items = req if isinstance(req, list) else [req]
        for item in items:
            resp = dispatch(item)
            if resp is not None:
                _send(resp)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        pass
