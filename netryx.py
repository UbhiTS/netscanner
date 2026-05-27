#!/usr/bin/env python3
"""Netryx - a feature-rich local network scanner & discovery web app.

Pure Python standard library only (no pip installs). Runs a small local web
server and serves the Signal Cartography dashboard (ui.html) in your browser.

Features: ping-sweep + TCP-fallback host discovery, MAC/vendor (OUI) lookup
with full-IEEE-database download, reverse-DNS + mDNS/Bonjour + SNMP enrichment,
parallel TCP port scanning with banners + clickable web URLs, OS/device-type
guessing, card/table/topology views, live monitoring + desktop alerts, scan
history, Wake-on-LAN, names/notes, CSV/JSON export.

Usage:
    python netryx.py [--host H] [--port P] [--no-browser]
Env: NETRYX_HOST, NETRYX_PORT, NETRYX_NO_BROWSER, NETRYX_DATA
"""

import argparse
import base64
import csv
import hashlib
import hmac
import io
import ipaddress
import json
import os
import platform
import random
import re
import secrets
import socket
import ssl
import struct
import subprocess
import sys
import threading
import time
import urllib.request
import webbrowser
from concurrent.futures import ThreadPoolExecutor, wait, FIRST_COMPLETED
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

IS_WINDOWS = platform.system().lower().startswith("win")
SUBPROC_KW = {"creationflags": 0x08000000} if IS_WINDOWS else {}  # CREATE_NO_WINDOW

APP_DIR = os.path.dirname(os.path.abspath(
    sys.argv[0] if getattr(sys, "frozen", False) else __file__))
DATA_DIR = os.environ.get("NETRYX_DATA") or os.path.join(APP_DIR, "netryx_data")
HISTORY_DIR = os.path.join(DATA_DIR, "history")
DEVICES_FILE = os.path.join(DATA_DIR, "devices.json")
SEEN_FILE = os.path.join(DATA_DIR, "seen_macs.json")
# Access control. When any of these are set (or any API token exists), the whole
# app (UI + /api + /mcp) requires auth, except requests from localhost when
# NETRYX_TRUST_LOCALHOST is on. Humans use admin Basic auth; agents use tokens.
NETRYX_TOKEN = os.environ.get("NETRYX_TOKEN", "").strip()          # legacy static bearer token
NETRYX_USER = (os.environ.get("NETRYX_USER", "admin").strip() or "admin")
NETRYX_PASS = os.environ.get("NETRYX_PASS", "")
NETRYX_TRUST_LOCALHOST = os.environ.get("NETRYX_TRUST_LOCALHOST", "0").strip().lower() \
    in ("1", "true", "yes", "on")
NETRYX_OPEN = os.environ.get("NETRYX_OPEN", "").strip().lower() in ("1", "true", "yes", "on")
TOKENS_FILE = os.path.join(DATA_DIR, "tokens.json")
AUTH_FILE = os.path.join(DATA_DIR, "auth.json")
for _d in (DATA_DIR, HISTORY_DIR):
    try:
        os.makedirs(_d, exist_ok=True)
    except Exception:
        pass

COMMON_PORTS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS", 67: "DHCP",
    69: "TFTP", 80: "HTTP", 110: "POP3", 111: "RPC", 119: "NNTP", 123: "NTP",
    135: "MSRPC", 137: "NetBIOS", 139: "NetBIOS-SSN", 143: "IMAP", 161: "SNMP",
    179: "BGP", 389: "LDAP", 443: "HTTPS", 445: "SMB", 465: "SMTPS",
    514: "Syslog", 515: "Printer", 548: "AFP", 554: "RTSP", 587: "SMTP-Sub",
    631: "IPP/Printer", 873: "rsync", 902: "VMware", 993: "IMAPS", 995: "POP3S",
    1080: "SOCKS", 1194: "OpenVPN", 1433: "MSSQL", 1521: "Oracle", 1723: "PPTP",
    1883: "MQTT", 1900: "UPnP/SSDP", 2049: "NFS", 2082: "cPanel", 2083: "cPanel-SSL",
    2375: "Docker", 2376: "Docker-TLS", 3000: "Dev/HTTP", 3128: "Proxy",
    3306: "MySQL", 3389: "RDP", 3478: "STUN", 4444: "Alt", 4500: "IPsec-NAT",
    5000: "HTTP/UPnP", 5001: "HTTP-alt", 5060: "SIP", 5222: "XMPP", 5353: "mDNS",
    5432: "PostgreSQL", 5555: "ADB/Android", 5601: "Kibana", 5672: "AMQP",
    5900: "VNC", 5985: "WinRM", 5986: "WinRM-SSL", 6379: "Redis", 6443: "Kubernetes",
    7000: "HTTP-alt", 7070: "HTTP-alt", 8000: "HTTP-alt", 8008: "HTTP-alt",
    8009: "AJP", 8080: "HTTP-alt", 8081: "HTTP-alt", 8086: "InfluxDB",
    8088: "HTTP-alt", 8123: "HomeAssistant", 8443: "HTTPS-alt", 8554: "RTSP",
    8888: "HTTP-alt", 9000: "HTTP-alt", 9090: "HTTP-alt", 9100: "Printer-RAW",
    9200: "Elasticsearch", 9300: "Elastic", 10000: "Webmin", 11211: "Memcached",
    27017: "MongoDB", 32400: "Plex", 49152: "UPnP", 51820: "WireGuard",
    62078: "iOS-lockdown",
}
WEB_PORTS_HTTP = {80, 591, 2082, 3000, 5000, 5001, 7000, 7070, 8000, 8008, 8080,
                  8081, 8086, 8088, 8123, 8888, 9000, 9090, 5601, 10000, 32400}
WEB_PORTS_HTTPS = {443, 2083, 8443, 6443}
PORT_PROFILES = ("quick", "extended", "full")

# --------------------------------------------------------------------------- #
# Exposure / risk model
#
# A lightweight, opinionated heuristic: open ports that are commonly abused or
# that expose a management/data plane raise a device's exposure score. This is
# a *pure* function of already-collected scan data (no extra network I/O), so
# it's safe to attach to every device and to call from the CLI / MCP layers.
# --------------------------------------------------------------------------- #

RISK_TIERS = {"low": 1, "medium": 2, "high": 3, "critical": 4}
_TIER_NAME = {0: "none", 1: "low", 2: "medium", 3: "high", 4: "critical"}

# port -> (service label, tier, why)
RISKY_PORTS = {
    23:    ("Telnet", "critical", "unencrypted remote login"),
    2323:  ("Telnet-alt", "critical", "unencrypted remote login"),
    6379:  ("Redis", "critical", "frequently unauthenticated - remote code execution risk"),
    27017: ("MongoDB", "critical", "frequently unauthenticated database"),
    2375:  ("Docker", "critical", "unauthenticated Docker API exposes full host control"),
    11211: ("Memcached", "critical", "unauthenticated; DDoS amplification vector"),
    21:    ("FTP", "high", "often plaintext credentials"),
    69:    ("TFTP", "high", "unauthenticated file transfer"),
    512:   ("rexec", "high", "legacy remote execution"),
    513:   ("rlogin", "high", "legacy remote login"),
    445:   ("SMB", "high", "file sharing - common worm/ransomware vector"),
    139:   ("NetBIOS-SSN", "high", "legacy SMB session service"),
    3389:  ("RDP", "high", "remote desktop - common ransomware entry point"),
    5900:  ("VNC", "high", "remote desktop, often weakly authenticated"),
    5555:  ("ADB", "high", "Android Debug Bridge grants full device control"),
    1433:  ("MSSQL", "high", "database directly exposed"),
    3306:  ("MySQL", "high", "database directly exposed"),
    5432:  ("PostgreSQL", "high", "database directly exposed"),
    9200:  ("Elasticsearch", "high", "often unauthenticated; data disclosure"),
    9300:  ("Elasticsearch", "high", "cluster transport exposed"),
    1521:  ("Oracle", "high", "database directly exposed"),
    5984:  ("CouchDB", "high", "often unauthenticated database"),
    135:   ("MSRPC", "medium", "Windows RPC endpoint mapper"),
    137:   ("NetBIOS", "medium", "legacy name service"),
    161:   ("SNMP", "medium", "management plane; default community strings are common"),
    111:   ("RPC", "medium", "portmapper - service/info disclosure"),
    1900:  ("UPnP/SSDP", "medium", "UPnP exposed - history of CVEs"),
    514:   ("Syslog/rsh", "medium", "legacy remote shell / log service"),
    2049:  ("NFS", "medium", "network file system exposed"),
    873:   ("rsync", "medium", "file sync service exposed"),
    8086:  ("InfluxDB", "medium", "time-series database exposed"),
    10000: ("Webmin", "medium", "server admin panel"),
    5601:  ("Kibana", "medium", "analytics dashboard exposed"),
}


def risk_of(d):
    """Heuristic exposure assessment for a device, from its open ports.

    Returns {"tier", "score", "reasons"} where tier is one of
    none/low/medium/high/critical. Pure function - no network I/O."""
    ports = d.get("ports", []) or []
    reasons, score, worst = [], 0, 0
    seen = set()
    for p in ports:
        port = p.get("port")
        info = RISKY_PORTS.get(port)
        if info and port not in seen:
            seen.add(port)
            label, tier, why = info
            w = RISK_TIERS.get(tier, 1)
            score += w
            worst = max(worst, w)
            reasons.append({"port": port, "service": label, "tier": tier, "why": why})
    n_open = len({p.get("port") for p in ports})
    if n_open >= 15:
        score += 2
        worst = max(worst, 2)
        reasons.append({"port": None, "service": "broad surface", "tier": "medium",
                        "why": "%d open ports widen the attack surface" % n_open})
    elif n_open >= 8:
        score += 1
        worst = max(worst, 1)
    tier = _TIER_NAME.get(worst, "none") if n_open else "none"
    return {"tier": tier, "score": score, "reasons": reasons}

OUI = {
    "FCFBFB": "Apple", "F0F61C": "Apple", "A4B197": "Apple", "3C0754": "Apple",
    "8866A5": "Apple", "ACBC32": "Apple", "DCA904": "Apple", "F018A9": "Amazon",
    "44650D": "Amazon", "FCA667": "Amazon", "68543D": "Amazon", "B47C9C": "Amazon",
    "001A11": "Google", "F4F5E8": "Google", "3C5AB4": "Google", "A47733": "Google",
    "DA0F0E": "Google", "54600E": "Samsung", "E8508B": "Samsung", "FCC734": "Samsung",
    "5CF6DC": "Samsung", "D0176A": "Samsung", "8425DB": "Samsung", "B0EC8F": "Samsung",
    "B827EB": "Raspberry Pi", "DCA632": "Raspberry Pi", "E45F01": "Raspberry Pi",
    "D83ADD": "Raspberry Pi", "2CCF67": "Raspberry Pi", "001132": "Synology",
    "0011D8": "Asustek", "0019DB": "Dell", "001A2B": "Cisco", "00000C": "Cisco",
    "F09FC2": "Ubiquiti", "FCECDA": "Ubiquiti", "245A4C": "Ubiquiti", "788A20": "Ubiquiti",
    "B4FBE3": "Ubiquiti", "0418D6": "Ubiquiti", "EC4364": "TP-Link", "50C7BF": "TP-Link",
    "C46E1F": "TP-Link", "1C61B4": "TP-Link", "9C5322": "TP-Link", "AC84C6": "TP-Link",
    "F4EC38": "TP-Link", "001E2A": "Netgear", "A040A0": "Netgear", "9CD36D": "Netgear",
    "20E52A": "Netgear", "44944C": "Netgear", "002590": "Supermicro", "000C29": "VMware",
    "005056": "VMware", "001C42": "Parallels", "080027": "VirtualBox", "525400": "QEMU/KVM",
    "001D0F": "TP-Link", "B0BE76": "TP-Link", "D8074F": "Belkin/Linksys", "C0C9E3": "Belkin",
    "000D4B": "Roku", "DC3A5E": "Roku", "B83E59": "Roku", "CC6DA0": "Roku",
    "001788": "Philips Hue", "00178A": "Philips", "ECB5FA": "Philips Hue",
    "D052A8": "Wink/IoT", "18B430": "Nest", "641666": "Nest", "F4F5D8": "Google Nest",
    "B0C554": "D-Link", "1CBDB9": "D-Link", "284C53": "Sony", "FCF152": "Sony",
    "60BEB5": "Microsoft", "7C1E52": "Microsoft", "C83F26": "Microsoft Surface",
    "001AA0": "Dell", "F8BC12": "Dell", "A4BB6D": "Dell", "B083FE": "Dell",
    "001B21": "Intel", "A0A8CD": "Intel", "8CC681": "Intel", "3C970E": "Intel",
    "9C7BEF": "Hewlett-Packard", "643150": "Hewlett-Packard", "001321": "HP",
    "70106F": "HP", "00904C": "Epson", "44D244": "Sonos", "5CAAFD": "Sonos",
    "B8E937": "Sonos", "000E58": "Sonos", "78281D": "Sonos", "001E8C": "Asus",
    "2C56DC": "Asus", "AC220B": "Asus", "04D4C4": "Asus", "D850E6": "Asus",
    "1831BF": "Asus", "186472": "Aruba", "94B40F": "Aruba", "ACA31E": "Aruba",
}

# --------------------------------------------------------------------------- #
# Network helpers
# --------------------------------------------------------------------------- #


def get_primary_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        return s.getsockname()[0]
    except Exception:
        return "127.0.0.1"
    finally:
        s.close()


def default_subnet():
    ip = get_primary_ip()
    try:
        return str(ipaddress.ip_network(ip + "/24", strict=False))
    except Exception:
        return "192.168.1.0/24"


def default_gateway():
    try:
        if IS_WINDOWS:
            out = subprocess.run(["ipconfig"], capture_output=True, text=True,
                                 timeout=10, **SUBPROC_KW).stdout
            gws = re.findall(r"Default Gateway[ .:]*([\d]+\.[\d]+\.[\d]+\.[\d]+)", out)
            if gws:
                return gws[0]
        else:
            out = subprocess.run(["ip", "route"], capture_output=True, text=True, timeout=10).stdout
            m = re.search(r"default via ([\d.]+)", out)
            if m:
                return m.group(1)
            out = subprocess.run(["route", "-n", "get", "default"],
                                 capture_output=True, text=True, timeout=10).stdout
            m = re.search(r"gateway:\s*([\d.]+)", out)
            if m:
                return m.group(1)
    except Exception:
        pass
    return None


def ping(host, timeout_ms=700):
    if IS_WINDOWS:
        cmd = ["ping", "-n", "1", "-w", str(timeout_ms), host]
    else:
        cmd = ["ping", "-c", "1", "-W", str(max(1, int(round(timeout_ms / 1000.0)))), host]
    try:
        out = subprocess.run(cmd, capture_output=True, text=True,
                             timeout=timeout_ms / 1000.0 + 2, **SUBPROC_KW)
        text = (out.stdout or "") + (out.stderr or "")
        low = text.lower()
        alive = out.returncode == 0 and "unreachable" not in low and "100% packet loss" not in low
        if "ttl=" not in low and "ttl:" not in low:
            alive = alive and ("bytes from" in low or "reply from" in low)
            if IS_WINDOWS:
                alive = False
        ttl = None
        m = re.search(r"ttl[=\s:]*(\d+)", text, re.IGNORECASE)
        if m:
            ttl = int(m.group(1))
        latency = None
        m2 = re.search(r"time[=<]\s*([\d.]+)\s*ms", text, re.IGNORECASE)
        if m2:
            latency = float(m2.group(1))
        return alive, ttl, latency
    except Exception:
        return False, None, None


def scan_port(ip, port, timeout=0.6):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        return s.connect_ex((ip, port)) == 0
    except Exception:
        return False
    finally:
        try:
            s.close()
        except Exception:
            pass


_TCP_FALLBACK_PORTS = (80, 443, 22, 445, 139, 53, 8080, 3389)


def tcp_alive(ip, timeout=0.35):
    for p in _TCP_FALLBACK_PORTS:
        if scan_port(ip, p, timeout):
            return True
    return False


def host_alive_tcp(ip, ports=(80, 443, 22, 445), timeout=0.45):
    """Liveness without spawning a process: a connect that succeeds OR is refused
    (RST) proves the host is up. Scales to huge ranges where ping cannot."""
    for p in ports:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        try:
            s.connect((ip, p))
            return True
        except ConnectionRefusedError:
            return True
        except OSError:
            continue
        finally:
            try:
                s.close()
            except Exception:
                pass
    return False


def probe_host(ip):
    alive, ttl, latency = ping(ip)
    if alive:
        return {"ip": ip, "ttl": ttl, "latency": latency, "via": "icmp"}
    if tcp_alive(ip):
        return {"ip": ip, "ttl": None, "latency": None, "via": "tcp"}
    return None


def grab_banner(ip, port, timeout=1.0):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((ip, port))
        if port in WEB_PORTS_HTTP or port == 80:
            s.sendall(("HEAD / HTTP/1.0\r\nHost: %s\r\nUser-Agent: Netryx\r\n\r\n" % ip).encode())
        try:
            data = s.recv(512)
        except Exception:
            data = b""
        s.close()
        if not data:
            return None
        text = data.decode("utf-8", errors="ignore")
        m = re.search(r"Server:\s*(.+)", text, re.IGNORECASE)
        if m:
            return m.group(1).strip()[:80]
        line = re.sub(r"[^\x20-\x7e]", "", text.strip().splitlines()[0]) if text.strip() else ""
        return line[:80] or None
    except Exception:
        return None


def get_arp_table():
    table = {}
    try:
        if IS_WINDOWS:
            out = subprocess.run(["arp", "-a"], capture_output=True, text=True,
                                 timeout=15, **SUBPROC_KW).stdout
            for line in out.splitlines():
                m = re.search(r"(\d+\.\d+\.\d+\.\d+)\s+([0-9a-fA-F]{2}(?:[-:][0-9a-fA-F]{2}){5})", line)
                if m:
                    table[m.group(1)] = m.group(2).replace("-", ":").lower()
        else:
            out = subprocess.run(["ip", "neigh"], capture_output=True, text=True, timeout=15).stdout
            if not out.strip():
                out = subprocess.run(["arp", "-an"], capture_output=True, text=True, timeout=15).stdout
            for line in out.splitlines():
                ipm = re.search(r"(\d+\.\d+\.\d+\.\d+)", line)
                macm = re.search(r"([0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5})", line)
                if ipm and macm:
                    table[ipm.group(1)] = macm.group(1).lower()
    except Exception:
        pass
    return table


def reverse_dns(ip):
    try:
        socket.setdefaulttimeout(1.0)
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return None
    finally:
        socket.setdefaulttimeout(None)


def os_from_ttl(ttl):
    if ttl is None:
        return None
    if ttl > 128:
        return "Network device / Router"
    if ttl > 64:
        return "Windows"
    if ttl > 32:
        return "Linux / Unix / macOS / mobile"
    return "Unknown"


def web_url(ip, port):
    if port in WEB_PORTS_HTTPS:
        return "https://%s%s" % (ip, "" if port == 443 else ":%d" % port)
    if port in WEB_PORTS_HTTP:
        return "http://%s%s" % (ip, "" if port == 80 else ":%d" % port)
    return None


def get_ports(profile):
    if profile == "extended":
        s = set(range(1, 1025))
        s.update(COMMON_PORTS.keys())
        return sorted(s)
    if profile == "full":
        return list(range(1, 65536))
    return sorted(COMMON_PORTS.keys())


def wake_on_lan(mac):
    clean = re.sub(r"[^0-9a-fA-F]", "", mac)
    if len(clean) != 12:
        raise ValueError("Invalid MAC address")
    packet = b"\xff" * 6 + bytes.fromhex(clean) * 16
    sent = 0
    for addr in ("255.255.255.255", "<broadcast>"):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            for port in (9, 7):
                s.sendto(packet, (addr, port))
                sent += 1
            s.close()
        except Exception:
            pass
    return sent > 0


# --------------------------------------------------------------------------- #
# SNMP (minimal v2c GET, pure stdlib BER/ASN.1)
# --------------------------------------------------------------------------- #

SNMP_SYSDESCR = "1.3.6.1.2.1.1.1.0"
SNMP_SYSNAME = "1.3.6.1.2.1.1.5.0"


def _ber_len(n):
    if n < 0x80:
        return bytes([n])
    b = b""
    while n:
        b = bytes([n & 0xFF]) + b
        n >>= 8
    return bytes([0x80 | len(b)]) + b


def _ber(tag, body):
    return bytes([tag]) + _ber_len(len(body)) + body


def _ber_int(n):
    if n == 0:
        body = b"\x00"
    else:
        body = b""
        x = n
        while x:
            body = bytes([x & 0xFF]) + body
            x >>= 8
        if body[0] & 0x80:
            body = b"\x00" + body
    return _ber(0x02, body)


def _ber_oid(oid):
    parts = [int(p) for p in oid.strip(".").split(".")]
    body = bytes([40 * parts[0] + parts[1]])
    for p in parts[2:]:
        if p < 0x80:
            body += bytes([p])
        else:
            chunk = [p & 0x7F]
            p >>= 7
            while p:
                chunk.insert(0, (p & 0x7F) | 0x80)
                p >>= 7
            body += bytes(chunk)
    return _ber(0x06, body)


def _ber_tlvs(data):
    out = []
    i, n = 0, len(data)
    while i < n:
        tag = data[i]
        i += 1
        if i >= n:
            break
        ln = data[i]
        i += 1
        if ln & 0x80:
            k = ln & 0x7F
            ln = int.from_bytes(data[i:i + k], "big")
            i += k
        out.append((tag, data[i:i + ln]))
        i += ln
    return out


def _decode_oid(body):
    if not body:
        return ""
    arcs = [body[0] // 40, body[0] % 40]
    v = 0
    for b in body[1:]:
        v = (v << 7) | (b & 0x7F)
        if not (b & 0x80):
            arcs.append(v)
            v = 0
    return ".".join(str(a) for a in arcs)


def _decode_val(tag, body):
    if tag == 0x04:
        return body.decode("utf-8", "ignore").replace("\x00", "").strip()
    if tag == 0x06:
        return _decode_oid(body)
    if tag in (0x02, 0x41, 0x42, 0x43, 0x44, 0x46):
        return int.from_bytes(body, "big") if body else 0
    if tag == 0x05:
        return None
    return body.decode("latin-1", "ignore").strip()


def _snmp_parse(data):
    res = {}
    try:
        top = _ber_tlvs(data)
        if not top:
            return res
        seq = _ber_tlvs(top[0][1])
        pdu = None
        for tag, body in seq:
            if 0xA0 <= tag <= 0xA5:
                pdu = body
        if pdu is None:
            return res
        vblist = None
        for tag, body in _ber_tlvs(pdu):
            if tag == 0x30:
                vblist = body
        if vblist is None:
            return res
        for _tag, body in _ber_tlvs(vblist):
            kv = _ber_tlvs(body)
            if len(kv) >= 2:
                res[_decode_oid(kv[0][1])] = _decode_val(kv[1][0], kv[1][1])
    except Exception:
        pass
    return res


def _snmp_send(ip, oids, pdu_tag, community, timeout, port=161):
    """Send a v2c PDU (0xA0 GET / 0xA1 GETNEXT) and return the raw response bytes."""
    req_id = random.randint(1, 0x7FFFFFFF)
    vbs = b""
    for oid in oids:
        vbs += _ber(0x30, _ber_oid(oid) + _ber(0x05, b""))
    pdu = _ber(pdu_tag, _ber_int(req_id) + _ber_int(0) + _ber_int(0) + _ber(0x30, vbs))
    msg = _ber(0x30, _ber_int(1) + _ber(0x04, community.encode()) + pdu)  # version 1 == v2c
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(timeout)
    try:
        s.sendto(msg, (ip, int(port)))
        data, _ = s.recvfrom(8192)
        return data
    finally:
        try:
            s.close()
        except Exception:
            pass


def _snmp_parse_vbs(data):
    """Parse a response into (error_status, [(oid, value_tag, value), ...]), in order."""
    err, vbs = 0, []
    try:
        top = _ber_tlvs(data)
        if not top:
            return err, vbs
        seq = _ber_tlvs(top[0][1])
        pdu = None
        for tag, body in seq:
            if 0xA0 <= tag <= 0xA5:
                pdu = body
        if pdu is None:
            return err, vbs
        items = _ber_tlvs(pdu)
        if len(items) >= 2 and items[1][0] == 0x02 and items[1][1]:
            err = int.from_bytes(items[1][1], "big")
        vblist = None
        for tag, body in items:
            if tag == 0x30:
                vblist = body
        if vblist is None:
            return err, vbs
        for _t, body in _ber_tlvs(vblist):
            kv = _ber_tlvs(body)
            if len(kv) >= 2:
                vbs.append((_decode_oid(kv[0][1]), kv[1][0], _decode_val(kv[1][0], kv[1][1])))
    except Exception:
        pass
    return err, vbs


def snmp_get(ip, oids, community="public", timeout=0.9, port=161):
    """SNMP v2c GET one or more OIDs. Returns {oid: value} ({} on no response)."""
    try:
        data = _snmp_send(ip, oids, 0xA0, community, timeout, port)
    except Exception:
        return {}
    _err, vbs = _snmp_parse_vbs(data)
    return {oid: val for oid, _tag, val in vbs}


def snmp_walk(ip, base_oid, community="public", timeout=0.9, max_rows=256, port=161):
    """SNMP v2c walk (GETNEXT) of a subtree. Returns [{oid, value}, ...] in order."""
    base = (base_oid or "").strip().strip(".")
    if not base:
        return []
    prefix, cur, rows, seen = base + ".", base, [], set()
    try:
        max_rows = max(1, min(5000, int(max_rows)))
    except Exception:
        max_rows = 256
    for _ in range(max_rows):
        try:
            data = _snmp_send(ip, [cur], 0xA1, community, timeout, port)
        except Exception:
            break
        err, vbs = _snmp_parse_vbs(data)
        if err or not vbs:
            break
        oid, tag, val = vbs[0]
        if tag in (0x80, 0x81, 0x82):       # noSuchObject / noSuchInstance / endOfMibView
            break
        if not (oid == base or oid.startswith(prefix)):
            break
        if oid in seen:                     # guard against agents that loop
            break
        seen.add(oid)
        rows.append({"oid": oid, "value": val})
        cur = oid
    return rows


def snmp_probe(ip):
    r = snmp_get(ip, [SNMP_SYSDESCR, SNMP_SYSNAME, SNMP_SYSUPTIME,
                      SNMP_SYSLOCATION, SNMP_SYSCONTACT])
    if not r:
        return None
    out = {}
    if r.get(SNMP_SYSNAME):
        out["name"] = str(r[SNMP_SYSNAME])[:80]
    if r.get(SNMP_SYSDESCR):
        out["descr"] = str(r[SNMP_SYSDESCR])[:160]
    if r.get(SNMP_SYSLOCATION):
        out["location"] = str(r[SNMP_SYSLOCATION])[:80]
    if r.get(SNMP_SYSCONTACT):
        out["contact"] = str(r[SNMP_SYSCONTACT])[:80]
    up = r.get(SNMP_SYSUPTIME)
    if isinstance(up, int) and up > 0:
        out["uptime"] = _fmt_uptime(up)
    return out or None


# --------------------------------------------------------------------------- #
# mDNS / Bonjour
# --------------------------------------------------------------------------- #

MDNS_ADDR = "224.0.0.251"
MDNS_PORT = 5353
MDNS_SERVICES = [
    "_services._dns-sd._udp.local", "_http._tcp.local", "_https._tcp.local",
    "_ipp._tcp.local", "_ipps._tcp.local", "_printer._tcp.local", "_pdl-datastream._tcp.local",
    "_scanner._tcp.local", "_googlecast._tcp.local", "_airplay._tcp.local",
    "_raop._tcp.local", "_spotify-connect._tcp.local", "_ssh._tcp.local",
    "_sftp-ssh._tcp.local", "_smb._tcp.local", "_afpovertcp._tcp.local",
    "_workstation._tcp.local", "_companion-link._tcp.local", "_homekit._tcp.local",
    "_hap._tcp.local", "_sonos._tcp.local", "_amzn-wplay._tcp.local",
    "_device-info._tcp.local", "_rfb._tcp.local",
]
SERVICE_MAP = {
    "_googlecast": "Chromecast", "_airplay": "AirPlay", "_raop": "AirPlay Audio",
    "_spotify-connect": "Spotify", "_ipp": "Printer", "_ipps": "Printer",
    "_printer": "Printer", "_pdl-datastream": "Printer", "_scanner": "Scanner",
    "_http": "Web UI", "_https": "Web UI", "_ssh": "SSH", "_sftp-ssh": "SSH",
    "_smb": "File share", "_afpovertcp": "Apple file share", "_nfs": "NFS",
    "_workstation": "Computer", "_homekit": "HomeKit", "_hap": "HomeKit",
    "_companion-link": "Apple device", "_sonos": "Sonos", "_amzn-wplay": "Amazon device",
    "_rfb": "VNC", "_device-info": "Device", "_hue": "Philips Hue",
}


def _service_label(svc):
    for k, v in SERVICE_MAP.items():
        if svc.startswith(k):
            return v
    return None


def _dns_encode_name(name):
    out = b""
    for part in name.split("."):
        if part == "":
            continue
        b = part.encode("utf-8")
        out += bytes([len(b)]) + b
    return out + b"\x00"


def _mdns_build_query(names, qtype=12):
    header = struct.pack(">HHHHHH", 0, 0, len(names), 0, 0, 0)
    body = b""
    for n in names:
        body += _dns_encode_name(n) + struct.pack(">HH", qtype, 0x8001)  # QU + class IN
    return header + body


def _dns_read_name(data, off):
    labels = []
    next_off = None
    guard = 0
    while guard < 128:
        guard += 1
        if off >= len(data):
            break
        ln = data[off]
        if (ln & 0xC0) == 0xC0:
            if off + 1 >= len(data):
                break
            if next_off is None:
                next_off = off + 2
            off = ((ln & 0x3F) << 8) | data[off + 1]
            continue
        off += 1
        if ln == 0:
            if next_off is None:
                next_off = off
            break
        labels.append(data[off:off + ln].decode("utf-8", "ignore"))
        off += ln
    if next_off is None:
        next_off = off
    return ".".join(labels), next_off


def _mdns_classify(owner, target, rec):
    label = _service_label(owner.split(".")[0])
    if label:
        rec["services"].add(label)
    if target and "._" in target:
        inst = target.split("._")[0]
        if inst and not inst.startswith("_"):
            rec["instances"].add(inst.replace("\\032", " ").strip())


def _mdns_parse(data, src_ip, found):
    try:
        if len(data) < 12:
            return
        qd, an, ns, ar = struct.unpack(">HHHH", data[4:12])
        off = 12
        for _ in range(qd):
            _, off = _dns_read_name(data, off)
            off += 4
        rec = found.setdefault(src_ip, {"host": None, "services": set(), "instances": set(), "model": None})
        for _ in range(an + ns + ar):
            name, off = _dns_read_name(data, off)
            if off + 10 > len(data):
                break
            rtype, _rclass, _ttl, rdlen = struct.unpack(">HHIH", data[off:off + 10])
            off += 10
            rend = off + rdlen
            if rtype == 12:
                target, _ = _dns_read_name(data, off)
                _mdns_classify(name, target, rec)
            elif rtype == 33 and rdlen >= 6:
                target, _ = _dns_read_name(data, off + 6)
                if target.endswith(".local") and not rec["host"]:
                    rec["host"] = target[:-6]
            elif rtype == 1 and rdlen == 4:
                if name.endswith(".local") and not rec["host"]:
                    rec["host"] = name[:-6]
            elif rtype == 16 and rdlen > 0:
                _mdns_txt(data[off:off + rdlen], rec)
            off = rend
    except Exception:
        pass


def mdns_sweep(timeout=2.5):
    found = {}
    try:
        q = _mdns_build_query(MDNS_SERVICES)
    except Exception:
        return {}
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
        except Exception:
            pass
        bound = True
        try:
            s.bind(("", MDNS_PORT))
        except Exception:
            bound = False
            try:
                s.bind(("", 0))
            except Exception:
                pass
        try:
            s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)
        except Exception:
            pass
        if bound:
            try:
                mreq = socket.inet_aton(MDNS_ADDR) + socket.inet_aton("0.0.0.0")
                s.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
            except Exception:
                pass
        s.settimeout(0.4)
        s.sendto(q, (MDNS_ADDR, MDNS_PORT))
        end = time.time() + timeout
        while time.time() < end:
            try:
                data, addr = s.recvfrom(9000)
            except socket.timeout:
                continue
            except Exception:
                break
            _mdns_parse(data, addr[0], found)
    except Exception:
        pass
    finally:
        try:
            s.close()
        except Exception:
            pass
    out = {}
    for ip, rec in found.items():
        out[ip] = {"host": rec.get("host"), "services": sorted(rec["services"]),
                   "name": sorted(rec["instances"])[0] if rec["instances"] else None,
                   "model": rec.get("model")}
    return out


# --------------------------------------------------------------------------- #
# OUI vendor database
# --------------------------------------------------------------------------- #

_OUI_EXT = None
OUI_URLS = [
    "https://standards-oui.ieee.org/oui/oui.txt",
    "http://standards-oui.ieee.org/oui/oui.txt",
    "https://standards-oui.ieee.org/oui/oui.csv",
]


def _oui_search_paths():
    paths = []
    for d in (DATA_DIR, APP_DIR):
        for name in ("oui.csv", "oui.txt"):
            paths.append(os.path.join(d, name))
    return paths


def _load_oui_ext():
    global _OUI_EXT
    if _OUI_EXT is not None:
        return
    _OUI_EXT = {}
    for path in _oui_search_paths():
        if not os.path.exists(path):
            continue
        try:
            with open(path, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    m = re.search(
                        r"([0-9A-Fa-f]{2})[-:]?([0-9A-Fa-f]{2})[-:]?([0-9A-Fa-f]{2})"
                        r"[\s,\"]+(?:\(hex\))?\s*[,\t]*\s*(.+)", line)
                    if m:
                        key = (m.group(1) + m.group(2) + m.group(3)).upper()
                        vendor = m.group(4).strip().strip('"').strip()
                        if key and vendor and key not in _OUI_EXT:
                            _OUI_EXT[key] = vendor[:60]
        except Exception:
            pass
        break


def oui_vendor(mac):
    if not mac:
        return None
    _load_oui_ext()
    key = mac.replace(":", "").replace("-", "").upper()[:6]
    if key in OUI:
        return OUI[key]
    if _OUI_EXT and key in _OUI_EXT:
        return _OUI_EXT[key]
    return None


def oui_status():
    _load_oui_ext()
    path = None
    for p in _oui_search_paths():
        if os.path.exists(p):
            path = os.path.basename(p)
            break
    return {"builtin": len(OUI), "extended": len(_OUI_EXT or {}), "file": path}


def download_oui():
    global _OUI_EXT
    last_err = "no url reachable"
    for url in OUI_URLS:
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "Netryx/1.0"})
            with urllib.request.urlopen(req, timeout=90) as r:
                data = r.read()
            if not data or len(data) < 1000:
                last_err = "downloaded file looked empty"
                continue
            dest = os.path.join(DATA_DIR, "oui.csv" if url.endswith(".csv") else "oui.txt")
            with open(dest, "wb") as f:
                f.write(data)
            _OUI_EXT = None
            _load_oui_ext()
            return {"ok": True, "file": os.path.basename(dest),
                    "bytes": len(data), "entries": len(_OUI_EXT or {})}
        except Exception as e:
            last_err = str(e)
    return {"ok": False, "error": last_err}


# --------------------------------------------------------------------------- #
# Device-type heuristic
# --------------------------------------------------------------------------- #


# --------------------------------------------------------------------------- #
# Extra discovery probes (NetBIOS, SSDP/UPnP, HTTP title, TLS, presence, etc.)
# --------------------------------------------------------------------------- #

SNMP_SYSOBJECTID = "1.3.6.1.2.1.1.2.0"
SNMP_SYSUPTIME = "1.3.6.1.2.1.1.3.0"
SNMP_SYSCONTACT = "1.3.6.1.2.1.1.4.0"
SNMP_SYSLOCATION = "1.3.6.1.2.1.1.6.0"
PRESENCE_FILE = os.path.join(DATA_DIR, "presence.json")


def mac_is_random(mac):
    """True if the MAC is locally-administered (randomized/private, e.g. a phone)."""
    if not mac:
        return False
    try:
        first = int(mac.split(":")[0], 16)
        return bool(first & 0x02) and not bool(first & 0x01)
    except Exception:
        return False


def ttl_hops(ttl):
    if ttl is None:
        return None
    for base in (64, 128, 255):
        if ttl <= base:
            return base - ttl
    return None


def _fmt_uptime(ticks):
    secs = int(ticks) // 100
    d, h, m = secs // 86400, (secs % 86400) // 3600, (secs % 3600) // 60
    if d:
        return "%dd %dh" % (d, h)
    if h:
        return "%dh %dm" % (h, m)
    return "%dm" % m


# ---- NetBIOS (Windows name / workgroup) ----------------------------------- #

def _nb_encode(name16):
    enc = b""
    for ch in name16:
        enc += bytes([0x41 + ((ch >> 4) & 0xF), 0x41 + (ch & 0xF)])
    return bytes([0x20]) + enc + b"\x00"


def netbios_query(ip, timeout=0.7):
    tid = random.randint(0, 0xFFFF)
    header = struct.pack(">HHHHHH", tid, 0x0000, 1, 0, 0, 0)
    pkt = header + _nb_encode(b"*" + b"\x00" * 15) + struct.pack(">HH", 0x0021, 0x0001)
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(timeout)
    try:
        s.sendto(pkt, (ip, 137))
        data, _ = s.recvfrom(2048)
        return _parse_nbstat(data)
    except Exception:
        return None
    finally:
        try:
            s.close()
        except Exception:
            pass


def _parse_nbstat(data):
    try:
        qd = struct.unpack(">H", data[4:6])[0]
        i = 12
        for _ in range(qd):
            while i < len(data) and data[i] != 0:
                i += 1 + data[i]
            i += 1 + 4
        while i < len(data) and data[i] != 0:
            i += 1 + data[i]
        i += 1 + 8  # null + type(2)+class(2)+ttl(4)
        i += 2      # rdlength
        num = data[i]
        i += 1
        comp = wg = None
        for _ in range(num):
            nm = data[i:i + 15].decode("ascii", "ignore").strip()
            suffix = data[i + 15]
            flags = struct.unpack(">H", data[i + 16:i + 18])[0]
            i += 18
            grp = bool(flags & 0x8000)
            if suffix == 0x00 and not grp and not comp:
                comp = nm
            if suffix == 0x00 and grp and not wg:
                wg = nm
        if comp or wg:
            return {"name": comp, "group": wg}
    except Exception:
        pass
    return None


# ---- SSDP / UPnP ---------------------------------------------------------- #

def ssdp_sweep(timeout=3.0):
    msg = ("M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\n"
           "MAN: \"ssdp:discover\"\r\nMX: 2\r\nST: ssdp:all\r\n\r\n").encode()
    locations = {}
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
        except Exception:
            pass
        s.bind(("", 0))
        try:
            s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)
        except Exception:
            pass
        s.settimeout(0.5)
        s.sendto(msg, ("239.255.255.250", 1900))
        s.sendto(msg, ("239.255.255.250", 1900))
        end = time.time() + timeout
        while time.time() < end:
            try:
                data, addr = s.recvfrom(4096)
            except socket.timeout:
                continue
            except Exception:
                break
            m = re.search(r"LOCATION:\s*(\S+)", data.decode("utf-8", "ignore"), re.IGNORECASE)
            if m:
                locations.setdefault(addr[0], set()).add(m.group(1).strip())
    except Exception:
        pass
    finally:
        try:
            s.close()
        except Exception:
            pass

    out = {}

    def fetch(item):
        ip, urls = item
        for url in list(urls)[:1]:
            try:
                req = urllib.request.Request(url, headers={"User-Agent": "Netryx"})
                with urllib.request.urlopen(req, timeout=2.5) as r:
                    xml = r.read(16000).decode("utf-8", "ignore")
                info = {}
                for tag in ("friendlyName", "manufacturer", "modelName",
                            "modelNumber", "modelDescription", "deviceType"):
                    mm = re.search(r"<%s>([^<]+)</%s>" % (tag, tag), xml, re.IGNORECASE)
                    if mm:
                        info[tag] = mm.group(1).strip()[:80]
                if info:
                    return (ip, info)
            except Exception:
                continue
        return (ip, None)

    items = list(locations.items())
    if items:
        with ThreadPoolExecutor(max_workers=min(40, len(items))) as ex:
            for ip, info in ex.map(fetch, items):
                if info:
                    out[ip] = info
    return out


# ---- HTTP page title ------------------------------------------------------ #

def http_title(ip, port, timeout=1.5):
    scheme = "https" if port in WEB_PORTS_HTTPS else "http"
    url = "%s://%s:%d/" % (scheme, ip, port)
    ctx = None
    if scheme == "https":
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        except Exception:
            ctx = None
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "Netryx"})
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as r:
            html = r.read(8192).decode("utf-8", "ignore")
        m = re.search(r"<title[^>]*>([^<]+)</title>", html, re.IGNORECASE | re.DOTALL)
        if m:
            return re.sub(r"\s+", " ", m.group(1)).strip()[:80] or None
    except Exception:
        return None
    return None


# ---- TLS certificate ------------------------------------------------------ #

def _fmt_asn1_time(tag, body):
    s = body.decode("ascii", "ignore")
    try:
        if tag == 0x17 and len(s) >= 6:       # UTCTime YYMMDD...
            yy = int(s[0:2])
            year = 2000 + yy if yy < 50 else 1900 + yy
            return "%04d-%s-%s" % (year, s[2:4], s[4:6])
        if tag == 0x18 and len(s) >= 8:       # GeneralizedTime YYYYMMDD...
            return "%s-%s-%s" % (s[0:4], s[4:6], s[6:8])
    except Exception:
        pass
    return None


def _x509_find_cn(name_body):
    try:
        for _t, rdn in _ber_tlvs(name_body):          # RDN SET
            for _t2, atv in _ber_tlvs(rdn):            # AttributeTypeAndValue SEQ
                kv = _ber_tlvs(atv)
                if len(kv) >= 2 and kv[0][1] == b"\x55\x04\x03":   # OID 2.5.4.3 (CN)
                    return kv[1][1].decode("utf-8", "ignore")[:80]
    except Exception:
        pass
    return None


def _x509_cn_expiry(der):
    try:
        cert = _ber_tlvs(der)[0][1]
        tbs = _ber_tlvs(cert)[0][1]
        seqs = [b for (t, b) in _ber_tlvs(tbs) if t == 0x30]
        # seqs = [sigAlg, issuer, validity, subject, spki, ...]
        issuer_b, validity_b, subject_b = seqs[1], seqs[2], seqs[3]
        times = _ber_tlvs(validity_b)
        exp = _fmt_asn1_time(times[1][0], times[1][1]) if len(times) >= 2 else None
        cn = _x509_find_cn(subject_b)
        icn = _x509_find_cn(issuer_b)
        return cn, exp, bool(cn and cn == icn)
    except Exception:
        return None, None, False


def tls_info(ip, port, timeout=1.8):
    info = {}
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection((ip, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=ip) as ss:
                info["proto"] = ss.version()
                c = ss.cipher()
                if c:
                    info["cipher"] = c[0]
                der = ss.getpeercert(binary_form=True)
        if der:
            cn, exp, self_signed = _x509_cn_expiry(der)
            if cn:
                info["cn"] = cn
            if exp:
                info["expires"] = exp
            info["self_signed"] = self_signed
    except Exception:
        return None
    return info or None


# ---- DNS servers / presence ----------------------------------------------- #

def dns_servers():
    out = set()
    try:
        if IS_WINDOWS:
            txt = subprocess.run(["ipconfig", "/all"], capture_output=True, text=True,
                                 timeout=10, **SUBPROC_KW).stdout
            in_dns = False
            for line in txt.splitlines():
                if "DNS Servers" in line:
                    in_dns = True
                    m = re.search(r"(\d+\.\d+\.\d+\.\d+)", line)
                    if m:
                        out.add(m.group(1))
                    continue
                if in_dns:
                    if re.match(r"\s+\d+\.\d+\.\d+\.\d+\s*$", line):
                        out.add(line.strip())
                    else:
                        in_dns = False
        else:
            try:
                with open("/etc/resolv.conf") as f:
                    for line in f:
                        m = re.match(r"\s*nameserver\s+([\d.]+)", line)
                        if m:
                            out.add(m.group(1))
            except Exception:
                pass
    except Exception:
        pass
    return out


def update_presence(devices):
    now = int(time.time())
    pres = _load_json(PRESENCE_FILE, {})
    for d in devices:
        k = d.get("mac") or d.get("ip")
        if not k:
            continue
        e = pres.get(k, {})
        e["first"] = e.get("first", now)
        e["last"] = now
        e["count"] = e.get("count", 0) + 1
        pres[k] = e
        d["first_seen"] = e["first"]
        d["last_seen"] = e["last"]
        d["seen_count"] = e["count"]
    _save_json(PRESENCE_FILE, pres)


def enrich_web(alive, job):
    targets = []
    for d in alive:
        for p in d.get("ports", []):
            if p.get("url"):
                targets.append((d["ip"], p))
    if not targets:
        return
    job["phase"] = "Reading web titles & TLS certificates"

    def work(item):
        ip, p = item
        t = http_title(ip, p["port"])
        if t:
            p["title"] = t
        if p["port"] in WEB_PORTS_HTTPS:
            ti = tls_info(ip, p["port"])
            if ti:
                p["tls"] = ti
        return None

    run_bounded(work, targets, 40, job)




def _mdns_txt(txt, rec):
    i = 0
    while i < len(txt):
        ln = txt[i]
        i += 1
        kv = txt[i:i + ln].decode("utf-8", "ignore")
        i += ln
        if "=" in kv:
            k, v = kv.split("=", 1)
            if k.lower() in ("model", "md", "ty") and v and not rec.get("model"):
                rec["model"] = v[:60]


def guess_device_type(d):
    ports = {p["port"] for p in d.get("ports", [])}
    vendor = (d.get("vendor") or "").lower()
    services = [s.lower() for s in d.get("mdns_services", [])]
    descr = ((d.get("snmp") or {}).get("descr") or "").lower()
    dtype = ((d.get("upnp") or {}).get("deviceType") or "").lower()
    model = (d.get("model") or "").lower()
    if "internetgatewaydevice" in dtype or "wandevice" in dtype:
        return "Router / Gateway"
    if "mediarenderer" in dtype or "mediaserver" in dtype:
        return "Media / Streaming"
    if "printer" in dtype or "printer" in model:
        return "Printer"
    if d.get("is_gateway") or any(k in descr for k in ("router", "gateway")):
        return "Router / Gateway"
    if any(k in descr for k in ("switch", "access point", "wireless")) or "aruba" in vendor:
        return "Network device"
    if "chromecast" in services or "airplay" in services or "sonos" in services or "roku" in vendor or "sonos" in vendor:
        return "Media / Streaming"
    if 32400 in ports or "plex" in vendor:
        return "Media server (Plex)"
    if "printer" in services or "scanner" in services or ports & {9100, 515, 631} or "epson" in vendor or "printer" in descr:
        return "Printer"
    if "homekit" in services or 8123 in ports or 1883 in ports or "hue" in services or "philips" in vendor or "nest" in vendor:
        return "IoT / Smart home"
    if "camera" in services or "axis" in vendor:
        return "Camera"
    if 62078 in ports or "apple" in vendor or "apple device" in services:
        return "Apple device"
    if 5555 in ports:
        return "Android device"
    if "raspberry" in vendor:
        return "Raspberry Pi"
    if "synology" in vendor or "file share" in services or 2049 in ports:
        return "NAS / Storage"
    if ports & {3389, 445, 139} or "windows" in (d.get("os") or "").lower() or "microsoft" in vendor:
        return "Windows PC / Server"
    if ports & {22} and ports & {80, 443, 3306, 5432, 6379, 8080, 8443}:
        return "Server"
    if 22 in ports or "computer" in services:
        return "Computer"
    if ports & {80, 443}:
        return "Web-enabled device"
    return "Device"


# --------------------------------------------------------------------------- #
# Persistence
# --------------------------------------------------------------------------- #


def _load_json(path, default):
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return default


def _save_json(path, data):
    try:
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
        return True
    except Exception:
        return False


def load_devices_meta():
    return _load_json(DEVICES_FILE, {})


def save_device_meta(mac, name, notes):
    if not mac:
        return False
    meta = load_devices_meta()
    entry = meta.get(mac, {})
    if name is not None:
        entry["name"] = name
    if notes is not None:
        entry["notes"] = notes
    meta[mac] = entry
    return _save_json(DEVICES_FILE, meta)


def load_seen():
    return set(_load_json(SEEN_FILE, []))


def save_seen(seen):
    _save_json(SEEN_FILE, sorted(seen))


def save_history(subnet, devices):
    ts = int(time.time())
    _save_json(os.path.join(HISTORY_DIR, "scan_%d.json" % ts),
               {"time": ts, "subnet": subnet, "count": len(devices), "devices": devices})
    try:
        files = sorted(f for f in os.listdir(HISTORY_DIR) if f.startswith("scan_"))
        for old in files[:-50]:
            os.remove(os.path.join(HISTORY_DIR, old))
    except Exception:
        pass


def list_history():
    items = []
    try:
        for f in os.listdir(HISTORY_DIR):
            if f.startswith("scan_") and f.endswith(".json"):
                rec = _load_json(os.path.join(HISTORY_DIR, f), None)
                if rec:
                    items.append({"file": f, "time": rec.get("time"),
                                  "subnet": rec.get("subnet"), "count": rec.get("count")})
    except Exception:
        pass
    items.sort(key=lambda x: x.get("time") or 0, reverse=True)
    return items


# --------------------------------------------------------------------------- #
# Known-good baseline + proactive events (rogue / new-open-port detection)
#
# Approve the current network as a "baseline", then every later scan is diffed
# against it. The first sighting of an unapproved device or an unapproved open
# port becomes an event: logged locally and pushed to a webhook and/or MQTT.
# All optional and configured via environment variables.
# --------------------------------------------------------------------------- #

BASELINE_FILE = os.path.join(DATA_DIR, "baseline.json")
EVENTS_FILE = os.path.join(DATA_DIR, "events.json")
ALERTS_FILE = os.path.join(DATA_DIR, "alerts_seen.json")
EVENTS_MAX = 500
NETRYX_WEBHOOK = os.environ.get("NETRYX_WEBHOOK", "").strip()
NETRYX_MQTT = os.environ.get("NETRYX_MQTT", "").strip()          # host or host:port
NETRYX_MQTT_TOPIC = os.environ.get("NETRYX_MQTT_TOPIC", "netryx/events").strip()
NETRYX_MQTT_USER = os.environ.get("NETRYX_MQTT_USER", "").strip()
NETRYX_MQTT_PASS = os.environ.get("NETRYX_MQTT_PASS", "")


def _bkey(d):
    return d.get("mac") or d.get("ip")


def _baseline_entry(d, now):
    return {"ip": d.get("ip"), "mac": d.get("mac"),
            "name": d.get("name") or d.get("hostname") or d.get("mdns_name"),
            "ports": sorted({p.get("port") for p in d.get("ports", [])}),
            "approved": now}


def load_baseline():
    return _load_json(BASELINE_FILE, {"created": None, "updated": None, "devices": {}})


def save_baseline(b):
    _save_json(BASELINE_FILE, b)
    return b


def baseline_from_devices(devices):
    """Replace the baseline with the supplied devices (approve current state)."""
    now = time.time()
    b = load_baseline()
    b["created"] = b.get("created") or now
    b["updated"] = now
    b["devices"] = {_bkey(d): _baseline_entry(d, now) for d in devices if _bkey(d)}
    return save_baseline(b)


def approve_devices(keys, devices):
    """Add specific devices (by mac/ip key) to the existing baseline."""
    now = time.time()
    b = load_baseline()
    b["created"] = b.get("created") or now
    by = {_bkey(d): d for d in devices}
    for k in keys:
        if by.get(k):
            b["devices"][k] = _baseline_entry(by[k], now)
    b["updated"] = now
    return save_baseline(b)


def clear_baseline():
    return save_baseline({"created": None, "updated": None, "devices": {}})


def diff_against_baseline(devices, b=None):
    """Compare devices to the baseline: rogue (unapproved) devices, unapproved
    open ports on approved devices, and approved devices now missing."""
    b = b if b is not None else load_baseline()
    base = b.get("devices", {})
    rogue, new_ports, seen = [], [], set()
    for d in devices:
        k = _bkey(d)
        if not k:
            continue
        seen.add(k)
        if k not in base:
            rogue.append({"key": k, "ip": d.get("ip"), "mac": d.get("mac"),
                          "name": d.get("name") or d.get("hostname") or d.get("mdns_name"),
                          "vendor": d.get("vendor"), "device_type": d.get("device_type"),
                          "open_ports": [p.get("port") for p in d.get("ports", [])],
                          "risk": (d.get("risk") or risk_of(d)).get("tier")})
        else:
            approved = set(base[k].get("ports", []))
            for p in d.get("ports", []):
                if p.get("port") not in approved:
                    new_ports.append({"key": k, "ip": d.get("ip"), "port": p.get("port"),
                                      "service": p.get("service"), "url": p.get("url")})
    missing = [{"key": k, "ip": v.get("ip"), "mac": v.get("mac"), "name": v.get("name")}
               for k, v in base.items() if k not in seen]
    return {"rogue_devices": rogue, "new_ports": new_ports,
            "missing_devices": missing, "baseline_size": len(base)}


# ---- event hub: in-memory ring + ids + a condition for push (SSE / long-poll) ----
EVENT_SEVERITY = {
    "rogue_device": "critical", "new_open_port": "high", "exposure_alert": "high",
    "device_missing": "warning", "scan_complete": "info",
}
SEVERITY_RANK = {"info": 0, "warning": 1, "high": 2, "critical": 3}
EVENTS_LOCK = threading.Lock()
RECENT_EVENTS = []          # [{id,time,kind,severity,data}], newest last
_EVENT_SEQ = 0


class _EventHub:
    """Notify-on-new-event primitive for same-process SSE / long-poll waiters."""
    def __init__(self):
        self.cond = threading.Condition()
        self.seq = 0

    def publish(self):
        with self.cond:
            self.seq += 1
            self.cond.notify_all()

    def wait(self, last_seq, timeout):
        with self.cond:
            if self.seq <= last_seq:
                self.cond.wait(timeout)
            return self.seq


EVENT_HUB = _EventHub()


def _load_recent_events():
    global RECENT_EVENTS, _EVENT_SEQ
    evs = _load_json(EVENTS_FILE, []) or []
    seq = 0
    for e in evs:
        if not e.get("id"):
            seq += 1
            e["id"] = seq
        else:
            seq = max(seq, e["id"])
        e.setdefault("severity", EVENT_SEVERITY.get(e.get("kind"), "info"))
    RECENT_EVENTS = evs[-EVENTS_MAX:]
    _EVENT_SEQ = max([e.get("id", 0) for e in RECENT_EVENTS], default=0)
    EVENT_HUB.seq = _EVENT_SEQ


def list_events(limit=100):
    with EVENTS_LOCK:
        evs = list(RECENT_EVENTS)
    return (evs[-int(limit):] if limit else evs)[::-1]


def events_since(since):
    with EVENTS_LOCK:
        return [e for e in RECENT_EVENTS if e.get("id", 0) > since]


def record_event(kind, data):
    global _EVENT_SEQ
    with EVENTS_LOCK:
        _EVENT_SEQ += 1
        ev = {"id": _EVENT_SEQ, "time": time.time(), "kind": kind,
              "severity": EVENT_SEVERITY.get(kind, "info"), "data": data}
        RECENT_EVENTS.append(ev)
        if len(RECENT_EVENTS) > EVENTS_MAX:
            del RECENT_EVENTS[:-EVENTS_MAX]
        _save_json(EVENTS_FILE, RECENT_EVENTS)
    EVENT_HUB.publish()          # wake SSE / long-poll waiters (same process)
    return ev


def _sse_frame(e):
    return ("id: %d\nevent: %s\ndata: %s\n\n"
            % (e.get("id", 0), e.get("kind", "event"), json.dumps(e))).encode("utf-8")


try:
    _load_recent_events()
except Exception:
    pass


def _emit(events):
    """Best-effort delivery of fresh events to webhook + MQTT, off-thread."""
    if not events or not (NETRYX_WEBHOOK or NETRYX_MQTT):
        return
    payload = {"source": "netryx", "host": get_primary_ip(),
               "time": time.time(), "events": events}

    def worker():
        if NETRYX_WEBHOOK:
            try:
                req = urllib.request.Request(
                    NETRYX_WEBHOOK, data=json.dumps(payload).encode("utf-8"),
                    headers={"Content-Type": "application/json"})
                urllib.request.urlopen(req, timeout=5).read()
            except Exception:
                pass
        if NETRYX_MQTT:
            try:
                mqtt_publish(NETRYX_MQTT_TOPIC, json.dumps(payload))
            except Exception:
                pass

    threading.Thread(target=worker, daemon=True).start()


def evaluate_baseline(devices):
    """Diff a finished scan against the baseline and emit an event the first
    time each rogue device / unapproved open port is seen."""
    b = load_baseline()
    if not b.get("devices"):
        return None  # no baseline -> nothing to police
    diff = diff_against_baseline(devices, b)
    seen = set(_load_json(ALERTS_FILE, []))
    fresh = []
    for r in diff["rogue_devices"]:
        sig = "rogue:" + str(r["key"])
        if sig not in seen:
            seen.add(sig)
            fresh.append(record_event("rogue_device", r))
    for p in diff["new_ports"]:
        sig = "port:%s:%s" % (p["key"], p["port"])
        if sig not in seen:
            seen.add(sig)
            fresh.append(record_event("new_open_port", p))
    _save_json(ALERTS_FILE, sorted(seen))
    _emit(fresh)
    return diff


def _emit_scan_events(job, alive, subnet):
    """After a finished scan: critical-exposure alerts (deduped) + scan_complete."""
    fresh = []
    seen = set(_load_json(ALERTS_FILE, []))
    changed = False
    for d in alive:
        r = d.get("risk") or risk_of(d)
        if r.get("tier") == "critical":
            sig = "exp:" + str(_bkey(d))
            if sig not in seen:
                seen.add(sig)
                changed = True
                fresh.append(record_event("exposure_alert", {
                    "key": _bkey(d), "ip": d.get("ip"),
                    "name": d.get("name") or d.get("hostname") or d.get("mdns_name"),
                    "tier": r.get("tier"), "score": r.get("score"),
                    "reasons": r.get("reasons"),
                    "open_ports": [p.get("port") for p in d.get("ports", [])]}))
    if changed:
        _save_json(ALERTS_FILE, sorted(seen))
    fresh.append(record_event("scan_complete", {
        "subnet": subnet, "count": len(alive),
        "new_devices": len(job.get("new_devices") or []),
        "new_ports": job.get("new_ports", 0)}))
    _emit(fresh)


# ---- minimal MQTT 3.1.1 QoS0 publisher (stdlib sockets only) ----

def _mqtt_rl(n):
    out = bytearray()
    while True:
        byte = n % 128
        n //= 128
        if n > 0:
            byte |= 0x80
        out.append(byte)
        if n == 0:
            return bytes(out)


def _mqtt_str(text):
    raw = text.encode("utf-8")
    return struct.pack("!H", len(raw)) + raw


def mqtt_publish(topic, message, timeout=5):
    """Publish one QoS0 message to NETRYX_MQTT ('host' or 'host:port'),
    then disconnect. Returns True on success."""
    host, _, port = NETRYX_MQTT.partition(":")
    port = int(port) if port else 1883
    flags = 0x02  # clean session
    body = _mqtt_str("netryx-%d" % (os.getpid() & 0xFFFF))
    if NETRYX_MQTT_USER:
        flags |= 0x80
        body += _mqtt_str(NETRYX_MQTT_USER)
        if NETRYX_MQTT_PASS:
            flags |= 0x40
            body += _mqtt_str(NETRYX_MQTT_PASS)
    var = _mqtt_str("MQTT") + bytes([0x04, flags]) + struct.pack("!H", 60)
    connect = bytes([0x10]) + _mqtt_rl(len(var + body)) + var + body
    pub_var = _mqtt_str(topic)
    pub_pay = message.encode("utf-8")
    publish = bytes([0x30]) + _mqtt_rl(len(pub_var + pub_pay)) + pub_var + pub_pay
    sock = socket.create_connection((host, port), timeout=timeout)
    try:
        sock.sendall(connect)
        try:
            sock.recv(4)  # CONNACK (best-effort)
        except Exception:
            pass
        sock.sendall(publish)
        sock.sendall(bytes([0xE0, 0x00]))  # DISCONNECT
    finally:
        sock.close()
    return True


# --------------------------------------------------------------------------- #
# API tokens + access control
# --------------------------------------------------------------------------- #

def load_tokens():
    d = _load_json(TOKENS_FILE, {"tokens": []})
    if "tokens" not in d:
        d = {"tokens": []}
    return d


def save_tokens(d):
    _save_json(TOKENS_FILE, d)
    return d


def list_tokens():
    return load_tokens().get("tokens", [])


def create_token(name="token", expires_days=None):
    d = load_tokens()
    exp = None
    try:
        if expires_days not in (None, "", 0, "0"):
            exp = time.time() + float(expires_days) * 86400
    except Exception:
        exp = None
    rec = {"id": secrets.token_hex(5), "name": (str(name or "token"))[:60],
           "token": "nsk_" + secrets.token_urlsafe(32),
           "created": time.time(), "last_used": None, "expires": exp}
    d.setdefault("tokens", []).append(rec)
    save_tokens(d)
    return rec


def delete_token(tid):
    d = load_tokens()
    n0 = len(d.get("tokens", []))
    d["tokens"] = [t for t in d.get("tokens", []) if t.get("id") != tid]
    save_tokens(d)
    return len(d["tokens"]) != n0


def token_valid(value):
    if not value:
        return False
    if NETRYX_TOKEN and hmac.compare_digest(value, NETRYX_TOKEN):
        return True
    d = load_tokens()
    now = time.time()
    hit = None
    for t in d.get("tokens", []):
        if hmac.compare_digest(value, t.get("token", "")):
            if t.get("expires") and now > t["expires"]:
                return False
            hit = t
            break
    if hit:
        hit["last_used"] = now
        save_tokens(d)
        return True
    return False


PBKDF2_ITER = 200000


def _hash_pw(password, salt):
    return hashlib.pbkdf2_hmac("sha256", (password or "").encode("utf-8"), salt, PBKDF2_ITER).hex()


def set_admin(username, password):
    salt = secrets.token_bytes(16)
    a = {"username": (str(username or "admin").strip() or "admin"),
         "salt": salt.hex(), "hash": _hash_pw(password or "admin", salt),
         "algo": "pbkdf2_sha256", "iter": PBKDF2_ITER, "updated": time.time()}
    _save_json(AUTH_FILE, a)
    return a


def load_admin():
    a = _load_json(AUTH_FILE, None)
    if a and a.get("hash") and a.get("salt") and a.get("username"):
        return a
    # First launch: seed from env if a password was supplied, else default admin/admin.
    return set_admin(NETRYX_USER, NETRYX_PASS or "admin")


def verify_admin(username, password):
    a = load_admin()
    try:
        calc = _hash_pw(password, bytes.fromhex(a["salt"]))
    except Exception:
        return False
    if hmac.compare_digest(str(username or ""), a.get("username", "")) and \
            hmac.compare_digest(calc, a.get("hash", "")):
        return True
    # Env credentials always work too (recovery / ops override).
    if NETRYX_PASS and hmac.compare_digest(str(username or ""), NETRYX_USER) and \
            hmac.compare_digest(str(password or ""), NETRYX_PASS):
        return True
    return False


def is_default_admin():
    return verify_admin("admin", "admin")


def auth_configured():
    # Auth is on by default: a default admin/admin credential is always present.
    # Set NETRYX_OPEN=1 to run fully open on a trusted segment.
    return not NETRYX_OPEN


# ---- browser login sessions (cookie-based; in-memory) ----
SESSIONS = {}                # token -> expiry epoch
SESSIONS_LOCK = threading.Lock()
try:
    SESSION_TTL = max(1, int(os.environ.get("NETRYX_SESSION_DAYS", "30"))) * 86400
except Exception:
    SESSION_TTL = 30 * 86400


def new_session():
    tok = secrets.token_urlsafe(32)
    now = time.time()
    with SESSIONS_LOCK:
        for k in [k for k, v in SESSIONS.items() if v < now]:
            SESSIONS.pop(k, None)
        SESSIONS[tok] = now + SESSION_TTL
    return tok


def session_valid(tok):
    if not tok:
        return False
    with SESSIONS_LOCK:
        exp = SESSIONS.get(tok)
        if exp and exp > time.time():
            return True
        if exp:
            SESSIONS.pop(tok, None)
    return False


def drop_session(tok):
    with SESSIONS_LOCK:
        SESSIONS.pop(tok, None)


def login_page():
    hint = ('<div class="hint">Default login is <b>admin</b> / <b>admin</b> — change it after signing in.</div>'
            if is_default_admin() else '')
    return ("""<!DOCTYPE html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Netryx - Sign in</title>
<style>
:root{--bg:#0b0f17;--panel:#111726;--border:#1e2a40;--text:#e6edf3;--muted:#8aa0bd;--cyan:#49d8f2;--blue:#3b82f6;--red:#f0716b}
*{box-sizing:border-box}
body{margin:0;min-height:100vh;display:flex;align-items:center;justify-content:center;
  font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;color:var(--text);
  background:radial-gradient(1100px 700px at 50% -10%,#0e1a2c,var(--bg) 70%)}
.card{width:min(380px,92vw);background:linear-gradient(180deg,var(--panel),#0c111c);
  border:1px solid var(--border);border-radius:18px;padding:34px 30px;box-shadow:0 30px 80px rgba(0,0,0,.5)}
.brand{display:flex;flex-direction:column;align-items:center;text-align:center;margin-bottom:22px}
.brand h1{font-size:18px;letter-spacing:4px;margin:14px 0 2px;font-weight:700}
.brand .tag{font-size:10.5px;letter-spacing:3px;text-transform:uppercase;color:var(--muted);font-family:ui-monospace,monospace}
label{display:block;font-size:11px;text-transform:uppercase;letter-spacing:.6px;color:var(--muted);margin:14px 0 6px}
input{width:100%;background:#0a0f1a;border:1px solid var(--border);color:var(--text);
  border-radius:10px;padding:11px 13px;font-size:14px;outline:none}
input:focus{border-color:var(--cyan);box-shadow:0 0 0 3px rgba(73,216,242,.14)}
button{width:100%;margin-top:20px;border:none;border-radius:10px;padding:12px;font-size:14px;font-weight:700;
  color:#04121c;background:linear-gradient(135deg,var(--cyan),var(--blue));cursor:pointer}
button:active{transform:translateY(1px)}
.err{margin-top:14px;min-height:18px;color:var(--red);font-size:12.5px;text-align:center}
.hint{margin-top:18px;text-align:center;color:var(--muted);font-size:11px;font-family:ui-monospace,monospace}
.hint b{color:var(--cyan);font-weight:600}
</style></head><body>
<form class="card" id="f" onsubmit="return go(event)">
  <div class="brand">
    <svg width="46" height="46" viewBox="0 0 40 40" fill="none">
      <circle cx="20" cy="20" r="18" stroke="#203a5e"/><circle cx="20" cy="20" r="12" stroke="#203a5e"/>
      <circle cx="20" cy="20" r="6" stroke="#49d8f2"/><circle cx="20" cy="20" r="3" fill="#ecb24a"/>
      <circle cx="32" cy="20" r="1.7" fill="#49d8f2"/><circle cx="14" cy="8" r="1.7" fill="#49d8f2"/>
      <circle cx="9" cy="27" r="1.7" fill="#3b82f6"/><circle cx="28" cy="31" r="1.7" fill="#49d8f2"/></svg>
    <h1>NETRYX</h1><div class="tag">Signal Cartography</div>
  </div>
  <label for="u">Username</label>
  <input id="u" name="username" autocomplete="username" autofocus required>
  <label for="p">Password</label>
  <input id="p" name="password" type="password" autocomplete="current-password" required>
  <button type="submit">Sign in</button>
  <div class="err" id="err"></div>
  __HINT__
</form>
<script>
async function go(e){
  e.preventDefault();
  var err=document.getElementById('err'); err.textContent='';
  try{
    var r=await fetch('/api/login',{method:'POST',headers:{'Content-Type':'application/json'},
      body:JSON.stringify({username:document.getElementById('u').value,password:document.getElementById('p').value})});
    if(r.ok){location.href='/';}
    else{var d=await r.json().catch(function(){return {};}); err.textContent=d.error||'Sign in failed';}
  }catch(_){err.textContent='Could not reach the server';}
  return false;
}
</script></body></html>""").replace("__HINT__", hint)


# --------------------------------------------------------------------------- #
# Job manager
# --------------------------------------------------------------------------- #

JOBS = {}
JOBS_LOCK = threading.Lock()
JOB_COUNTER = 0
LAST_RESULTS = {"subnet": None, "devices": []}


def _restore_last_results():
    """On startup, repopulate LAST_RESULTS from the most recent saved scan so the
    dashboard, baseline diff and MCP reflect the previous run after a restart."""
    try:
        hist = list_history()
        if hist:
            rec = _load_json(os.path.join(HISTORY_DIR, hist[0]["file"]), None)
            if rec and rec.get("devices"):
                LAST_RESULTS["subnet"] = rec.get("subnet")
                LAST_RESULTS["devices"] = rec.get("devices", [])
    except Exception:
        pass


def new_job(jtype):
    global JOB_COUNTER
    with JOBS_LOCK:
        JOB_COUNTER += 1
        jid = str(JOB_COUNTER)
        JOBS[jid] = {"id": jid, "type": jtype, "status": "running", "phase": "Starting",
                     "total": 0, "done": 0, "devices": [], "result": None,
                     "error": None, "new_devices": [], "new_ports": 0,
                     "cancel": False, "stopped": False, "started": time.time()}
    return jid, JOBS[jid]


def run_bounded(fn, items, workers, job, on_result=None):
    """Run fn over items with bounded concurrency and cooperative cancellation.

    Keeps at most ~`workers` futures in flight (memory-safe even for a full
    65535-port sweep), and stops promptly when job['cancel'] is set.
    """
    it = iter(items)
    inflight = set()
    with ThreadPoolExecutor(max_workers=workers) as ex:
        try:
            for _ in range(workers):
                inflight.add(ex.submit(fn, next(it)))
        except StopIteration:
            pass
        while inflight:
            done, inflight = wait(inflight, timeout=0.5, return_when=FIRST_COMPLETED)
            inflight = set(inflight)
            for f in done:
                if on_result is not None:
                    try:
                        on_result(f.result())
                    except Exception:
                        pass
            if job.get("cancel"):
                for f in inflight:
                    f.cancel()
                break
            try:
                for _ in range(len(done)):
                    inflight.add(ex.submit(fn, next(it)))
            except StopIteration:
                pass


def start_job(jtype, fn, *args):
    jid, job = new_job(jtype)

    def wrap():
        try:
            fn(job, *args)
        except Exception as e:
            job["status"] = "error"
            job["error"] = str(e)

    threading.Thread(target=wrap, daemon=True).start()
    return jid


def compute_workers(profile, requested="auto"):
    """Pick a worker count. An explicit positive number wins; otherwise auto-scale
    from this machine's CPU count and the scan profile (I/O-bound, so generous)."""
    try:
        if requested not in (None, "", "auto", "Auto", "AUTO"):
            n = int(requested)
            if n > 0:
                return max(1, min(2000, n))
    except Exception:
        pass
    cpu = os.cpu_count() or 4
    if profile == "full":
        return max(200, min(1000, cpu * 128))
    if profile == "extended":
        return max(150, min(800, cpu * 96))
    return max(100, min(400, cpu * 64))


def parse_targets(text):
    """Expand a free-form list of CIDRs / IPs / ranges into a deduped host list.
    Accepts e.g. "192.168.1.0/24, 10.0.0.5, 10.20.1.1-50, 10.5.0.0/22".
    Returns (hosts, target_index_per_host, targets_meta, errors)."""
    toks = [t for t in re.split(r"[\s,;]+", (text or "").strip()) if t]
    specs, errors = [], []
    for t in toks:
        try:
            if "-" in t and "/" not in t:
                lo, hi = t.split("-", 1)
                lo_i = int(ipaddress.ip_address(lo.strip()))
                hs = hi.strip()
                hi_i = int(ipaddress.ip_address(hs)) if "." in hs \
                    else int(ipaddress.ip_address(lo.strip().rsplit(".", 1)[0] + "." + hs))
                if hi_i < lo_i:
                    lo_i, hi_i = hi_i, lo_i
                if hi_i - lo_i + 1 > 65536:
                    raise ValueError("range larger than a /16")
                specs.append((t, "range", lo_i, hi_i))
            elif "/" in t:
                _net = ipaddress.ip_network(t, strict=False)
                if _net.version == 4 and _net.prefixlen < 16:
                    raise ValueError("prefix broader than /16")
                specs.append((t, "net", _net))
            else:
                ipaddress.ip_address(t)
                specs.append((t, "ip", t))
        except Exception:
            errors.append(t)
    hosts, idx, targets, seen, LIMIT = [], [], [], set(), 65534
    for ti, spec in enumerate(specs):
        c0 = len(hosts)
        if spec[1] == "net":
            net = spec[2]
            gen = (str(h) for h in net.hosts()) if net.num_addresses > 2 else (str(a) for a in net)
            for ip in gen:
                if ip in seen:
                    continue
                seen.add(ip); hosts.append(ip); idx.append(ti)
                if len(hosts) >= LIMIT:
                    break
        elif spec[1] == "ip":
            if spec[2] not in seen:
                seen.add(spec[2]); hosts.append(spec[2]); idx.append(ti)
        else:
            for n in range(spec[2], spec[3] + 1):
                ip = str(ipaddress.ip_address(n))
                if ip in seen:
                    continue
                seen.add(ip); hosts.append(ip); idx.append(ti)
                if len(hosts) >= LIMIT:
                    break
        targets.append({"cidr": spec[0], "total": len(hosts) - c0, "done": 0, "found": 0})
        if len(hosts) >= LIMIT:
            break
    return hosts, idx, targets, errors


def _prev_snapshot(subnet):
    """Devices from the most recent prior scan of this subnet (for change detection)."""
    if LAST_RESULTS.get("subnet") == subnet and LAST_RESULTS.get("devices"):
        return LAST_RESULTS["devices"]
    for it in list_history():
        if it.get("subnet") == subnet:
            rec = _load_json(os.path.join(HISTORY_DIR, it["file"]), None)
            if rec:
                return rec.get("devices", [])
    return []


def _dkey(d):
    return d.get("mac") or d.get("ip")


def _finalize(job, alive, subnet, cancelled):
    alive.sort(key=lambda d: socket.inet_aton(d["ip"]))
    job["devices"] = alive
    if cancelled:
        job["stopped"] = True
        job["phase"] = "Stopped"
        job["status"] = "done"
        return
    job["phase"] = "Done"
    job["status"] = "done"
    LAST_RESULTS["subnet"] = subnet
    LAST_RESULTS["devices"] = alive
    save_history(subnet, alive)


def run_discovery(job, subnet, scan_ports=False, port_profile="quick",
                  use_mdns=True, use_snmp=True, req_workers="auto"):
    hosts, host_idx, targets, errors = parse_targets(subnet)
    if not hosts:
        job["status"] = "error"
        job["error"] = "No valid targets" + (": " + ", ".join(errors) if errors else "")
        return
    notes = []
    if errors:
        notes.append("ignored: " + ", ".join(errors[:6]))
    if len(hosts) >= 65534:
        notes.append("capped at 65534 hosts")
    if notes:
        job["note"] = " · ".join(notes)
    job["targets"] = targets
    subnet = " ".join(sorted(t for t in re.split(r"[\s,;]+", (subnet or "").strip()) if t))
    big = len(hosts) > 1024
    items = list(zip(hosts, host_idx))

    # snapshot of the previous scan, used to highlight new devices and new ports
    prev_devices = _prev_snapshot(subnet)
    have_prev = len(prev_devices) > 0
    prev_map = {_dkey(d): {p["port"] for p in d.get("ports", [])} for d in prev_devices}

    job["phase"] = "Discovering live hosts" + (" (fast TCP sweep)" if big else "")
    job["total"] = len(hosts)
    job["done"] = 0
    alive = []
    lock = threading.Lock()

    if big:
        def probe(item):
            ip, ti = item
            if job.get("cancel"):
                return
            up = host_alive_tcp(ip)
            with lock:
                job["done"] += 1
                targets[ti]["done"] += 1
                if up:
                    targets[ti]["found"] += 1
                    alive.append({"ip": ip, "ttl": None, "latency": None, "via": "tcp"})
        run_bounded(probe, items, compute_workers("full", req_workers), job)
        alive.sort(key=lambda d: socket.inet_aton(d["ip"]))
        job["devices"] = list(alive)
    else:
        def probe(item):
            ip, ti = item
            if job.get("cancel"):
                return
            r = probe_host(ip)
            with lock:
                job["done"] += 1
                targets[ti]["done"] += 1
                if r:
                    targets[ti]["found"] += 1
                    alive.append(r)
                    job["devices"] = sorted(alive, key=lambda d: socket.inet_aton(d["ip"]))
        run_bounded(probe, items, 160, job)
    if job.get("cancel"):
        for d in alive:
            d.setdefault("ports", [])
            d["device_type"] = "Device"
            d["new"] = False
        return _finalize(job, alive, subnet, True)

    job["phase"] = "Resolving names, vendors, mDNS & SNMP"
    job["total"] = 0
    arp = get_arp_table()
    gw = default_gateway()
    self_ip = get_primary_ip()
    dnssrv = dns_servers()
    meta = load_devices_meta()
    mdns_map, ssdp_map = {}, {}
    if not job.get("cancel"):
        with ThreadPoolExecutor(max_workers=2) as _ex:
            _fm = _ex.submit(mdns_sweep) if use_mdns else None
            _fs = _ex.submit(ssdp_sweep)
            try:
                mdns_map = _fm.result() if _fm else {}
            except Exception:
                mdns_map = {}
            try:
                ssdp_map = _fs.result()
            except Exception:
                ssdp_map = {}

    def enrich(d):
        ip = d["ip"]
        if big and d.get("ttl") is None and not job.get("cancel"):
            _al, _ttl, _lat = ping(ip)
            if _ttl is not None:
                d["ttl"] = _ttl
            if _lat is not None:
                d["latency"] = _lat
        mac = arp.get(ip)
        d["mac"] = mac
        d["vendor"] = oui_vendor(mac) if mac else None
        d["random_mac"] = mac_is_random(mac)
        d["hostname"] = reverse_dns(ip)
        d["os"] = os_from_ttl(d.get("ttl"))
        d["hops"] = ttl_hops(d.get("ttl"))
        d["detect"] = d.get("via")
        d["is_gateway"] = bool(gw and ip == gw)
        d["is_self"] = (ip == self_ip)
        d["is_dns"] = (ip in dnssrv)
        m = meta.get(mac) if mac else None
        d["name"] = (m or {}).get("name")
        d["notes"] = (m or {}).get("notes")
        md = mdns_map.get(ip)
        d["mdns_services"] = md.get("services", []) if md else []
        d["mdns_name"] = md.get("name") if md else None
        d["model"] = md.get("model") if md else None
        if md and not d["hostname"] and md.get("host"):
            d["hostname"] = md["host"] + ".local"
        sd = ssdp_map.get(ip)
        if sd:
            d["upnp"] = sd
            if not d["model"] and sd.get("modelName"):
                d["model"] = sd["modelName"] + (
                    " " + sd["modelNumber"] if sd.get("modelNumber") else "")
            if not d["mdns_name"] and sd.get("friendlyName"):
                d["mdns_name"] = sd["friendlyName"]
        if not job.get("cancel"):
            nb = netbios_query(ip)
            if nb:
                d["netbios"] = nb
                if not d["hostname"] and nb.get("name"):
                    d["hostname"] = nb["name"]
        if use_snmp and not job.get("cancel"):
            sn = snmp_probe(ip)
            if sn:
                d["snmp"] = sn
                if not d["hostname"] and sn.get("name"):
                    d["hostname"] = sn["name"]
        return d

    with ThreadPoolExecutor(max_workers=64) as ex:
        alive = list(ex.map(enrich, alive))

    if scan_ports and not job.get("cancel"):
        ports = get_ports(port_profile)
        pairs = [(d["ip"], p) for d in alive for p in ports]
        job["phase"] = "Scanning %d ports across %d hosts" % (len(ports), len(alive))
        job["total"] = max(1, len(pairs))
        job["done"] = 0
        results = {d["ip"]: [] for d in alive}
        timeout = 0.35 if port_profile == "full" else 0.5
        # I/O-bound connect scan: scale concurrency with the workload (bounded).
        workers = compute_workers(port_profile, req_workers)

        def scan_pair(pair):
            if job.get("cancel"):
                return None
            ip, p = pair
            ok = scan_port(ip, p, timeout)
            with lock:
                job["done"] += 1
            return (ip, p) if ok else None

        def collect(res):
            if res:
                results[res[0]].append(res[1])

        run_bounded(scan_pair, pairs, workers, job, on_result=collect)

        open_pairs = [(ip, p) for ip, ps in results.items() for p in ps]
        banners = {}
        if open_pairs and not job.get("cancel"):
            run_bounded(lambda t: (t[0], t[1], grab_banner(t[0], t[1])), open_pairs, 80, job,
                        on_result=lambda r: banners.__setitem__((r[0], r[1]), r[2]))
        for d in alive:
            ops = sorted(results.get(d["ip"], []))
            d["ports"] = [{"port": p, "service": COMMON_PORTS.get(p, "unknown"),
                           "banner": banners.get((d["ip"], p)), "url": web_url(d["ip"], p)}
                          for p in ops]
            d["device_type"] = guess_device_type(d)
    else:
        for d in alive:
            d.setdefault("ports", [])
            d["device_type"] = guess_device_type(d)

    # ---- change detection vs the previous scan ----
    new_devices, new_ports_total = [], 0
    for d in alive:
        k = _dkey(d)
        d["new"] = bool(have_prev and k not in prev_map)
        prevports = prev_map.get(k)
        changed = False
        for p in d.get("ports", []):
            isnew = bool(prevports is not None and p["port"] not in prevports)
            p["new"] = isnew
            if isnew:
                changed = True
                new_ports_total += 1
        d["changed"] = changed and not d["new"]
        d["risk"] = risk_of(d)
        if d["new"]:
            new_devices.append(k)
    job["new_devices"] = new_devices
    job["new_ports"] = new_ports_total

    if not job.get("cancel"):
        enrich_web(alive, job)
        update_presence(alive)
        try:
            evaluate_baseline(alive)
        except Exception:
            pass
        try:
            _emit_scan_events(job, alive, subnet)
        except Exception:
            pass

    _finalize(job, alive, subnet, bool(job.get("cancel")))


def run_portscan(job, ip, profile="extended", req_workers="auto"):
    ports = get_ports(profile)
    job["phase"] = "Scanning %d ports on %s" % (len(ports), ip)
    job["total"] = len(ports)
    job["done"] = 0
    lock = threading.Lock()
    found = []
    timeout = 0.35 if profile == "full" else 0.5

    def scan_one(p):
        if job.get("cancel"):
            return None
        ok = scan_port(ip, p, timeout)
        with lock:
            job["done"] += 1
        return p if ok else None

    run_bounded(scan_one, ports, compute_workers(profile, req_workers), job,
                on_result=lambda r: found.append(r) if r is not None else None)
    found.sort()
    open_ports = [{"port": p, "service": COMMON_PORTS.get(p, "unknown"),
                   "banner": grab_banner(ip, p), "url": web_url(ip, p)} for p in found]
    job["result"] = open_ports
    prev_ports = set()
    for d in LAST_RESULTS.get("devices", []):
        if d.get("ip") == ip:
            prev_ports = {p["port"] for p in d.get("ports", [])}
            for op in open_ports:
                op["new"] = op["port"] not in prev_ports
            d["ports"] = open_ports
            d["device_type"] = guess_device_type(d)
            d["risk"] = risk_of(d)
            break
    if job.get("cancel"):
        job["stopped"] = True
        job["phase"] = "Stopped"
    else:
        job["phase"] = "Done"
    job["status"] = "done"


def run_oui_download(job):
    job["phase"] = "Downloading IEEE OUI vendor database (~5 MB)"
    res = download_oui()
    if res.get("ok"):
        job["result"] = res
        job["phase"] = "Done"
        job["status"] = "done"
    else:
        job["status"] = "error"
        job["error"] = res.get("error", "download failed")


# --------------------------------------------------------------------------- #
# Synchronous API (used by the CLI and the MCP server)
# --------------------------------------------------------------------------- #


def discover(targets, scan_ports=False, port_profile="quick",
             use_mdns=True, use_snmp=True, req_workers="auto"):
    """Run one full discovery synchronously and return the result.

    This is the building block shared by the ``--scan`` CLI and the MCP server:
    it drives the same ``run_discovery`` pipeline the web UI uses, but in the
    caller's thread, and hands back a plain dict instead of a background job.

    Returns {"devices", "new_devices", "new_ports", "targets", "note", "error"}.
    """
    _jid, job = new_job("discovery")
    run_discovery(job, targets, bool(scan_ports), port_profile,
                  bool(use_mdns), bool(use_snmp), req_workers)
    return {
        "devices": job.get("devices", []),
        "new_devices": job.get("new_devices", []),
        "new_ports": job.get("new_ports", 0),
        "targets": job.get("targets", []),
        "note": job.get("note"),
        "error": job.get("error"),
    }


def _print_scan_table(res):
    """Human-readable summary of a discover() result for the CLI."""
    devs = res.get("devices", [])
    note = (" - " + res["note"]) if res.get("note") else ""
    print("Found %d device(s)%s\n" % (len(devs), note))
    hdr = "%-15s  %-17s  %-24s  %-8s  %s" % ("IP", "MAC", "NAME / HOSTNAME", "RISK", "OPEN PORTS")
    print(hdr)
    print("-" * len(hdr))
    for d in devs:
        ports = ",".join(str(p["port"]) for p in d.get("ports", []))
        risk = (d.get("risk") or {}).get("tier", "none")
        name = d.get("name") or d.get("hostname") or d.get("mdns_name") or ""
        flags = []
        if d.get("is_gateway"):
            flags.append("GW")
        if d.get("is_self"):
            flags.append("YOU")
        if d.get("new"):
            flags.append("NEW")
        nm = (name + (" [" + "/".join(flags) + "]" if flags else ""))[:24]
        print("%-15s  %-17s  %-24s  %-8s  %s" % (
            d.get("ip", ""), d.get("mac") or "-", nm, risk, ports or "-"))
    nd = res.get("new_devices") or []
    if nd:
        print("\nNew since last scan: %d device(s), %d new port(s)." % (
            len(nd), res.get("new_ports", 0)))


# --------------------------------------------------------------------------- #
# Export + UI loading
# --------------------------------------------------------------------------- #


def devices_to_csv(devices):
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["IP", "MAC", "Name", "Hostname", "Vendor", "OS", "Type",
                "Latency(ms)", "mDNS Services", "Open Ports", "Web URLs"])
    for d in devices:
        ports = "; ".join("%d/%s" % (p["port"], p["service"]) for p in d.get("ports", []))
        urls = "; ".join(p["url"] for p in d.get("ports", []) if p.get("url"))
        w.writerow([d.get("ip", ""), d.get("mac") or "", d.get("name") or "",
                    d.get("hostname") or "", d.get("vendor") or "", d.get("os") or "",
                    d.get("device_type") or "",
                    d.get("latency") if d.get("latency") is not None else "",
                    "; ".join(d.get("mdns_services", [])), ports, urls])
    return buf.getvalue()


OPENAPI_VERSION = "1.0.0"


def openapi_spec():
    """The OpenAPI 3.0 description of the HTTP API (single source of truth).

    Served as JSON at /openapi.json and as YAML at /openapi.yaml."""
    ok = {"description": "OK"}
    job = {"200": {"description": "Job accepted",
                   "content": {"application/json": {"schema": {"type": "object",
                               "properties": {"job_id": {"type": "string"}}}}}}}
    return {
        "openapi": "3.0.3",
        "info": {
            "title": "Netryx API",
            "version": OPENAPI_VERSION,
            "description": "Local network scanner & discovery engine. Discovers "
                           "devices, ports and services, assesses exposure, tracks a "
                           "known-good baseline, and exposes an MCP endpoint for AI agents. "
                           "All data stays on the host.",
            "license": {"name": "MIT"},
        },
        "servers": [{"url": "/", "description": "This Netryx instance"}],
        "tags": [
            {"name": "discovery", "description": "Scan the network and inspect results"},
            {"name": "devices", "description": "Per-device actions"},
            {"name": "security", "description": "Baseline & proactive events"},
            {"name": "system", "description": "Host info, vendor DB, export"},
            {"name": "agent", "description": "Model Context Protocol endpoint"},
        ],
        "components": {
            "securitySchemes": {
                "bearerAuth": {"type": "http", "scheme": "bearer",
                               "description": "An API token: Authorization: Bearer nsk_... (manage tokens in the dashboard)."},
                "basicAuth": {"type": "http", "scheme": "basic",
                              "description": "Admin username/password (NETRYX_USER / NETRYX_PASS)."}
            }
        },
        "security": [{"bearerAuth": []}, {"basicAuth": []}],
        "paths": {
            "/api/info": {"get": {"tags": ["system"], "summary": "Host & network context",
                "description": "Local IP, gateway, suggested subnet, platform, CPU count and OUI DB status.",
                "responses": {"200": ok}}},
            "/api/oui": {"get": {"tags": ["system"], "summary": "OUI vendor database status",
                "responses": {"200": ok}}},
            "/api/oui/download": {"post": {"tags": ["system"],
                "summary": "Download the full IEEE OUI database (background job)",
                "responses": job}},
            "/api/scan": {"post": {"tags": ["discovery"], "summary": "Start a discovery scan",
                "requestBody": {"required": True, "content": {"application/json": {"schema": {
                    "type": "object", "required": ["subnet"], "properties": {
                        "subnet": {"type": "string", "description": "CIDR/IP/range list, e.g. '192.168.1.0/24, 10.0.0.5'"},
                        "scan_ports": {"type": "boolean"},
                        "port_profile": {"type": "string", "enum": ["quick", "extended", "full"]},
                        "use_mdns": {"type": "boolean"},
                        "use_snmp": {"type": "boolean"},
                        "workers": {"type": "string", "description": "number or 'auto'"}}}}}},
                "responses": {"200": job["200"], "400": {"description": "subnet required"}}}},
            "/api/job": {"get": {"tags": ["discovery"], "summary": "Poll a running/finished job",
                "parameters": [{"name": "id", "in": "query", "required": True,
                                "schema": {"type": "string"}}],
                "responses": {"200": ok, "404": {"description": "no such job"}}}},
            "/api/job/stop": {"post": {"tags": ["discovery"], "summary": "Cancel a running job",
                "requestBody": {"required": True, "content": {"application/json": {"schema": {
                    "type": "object", "required": ["id"], "properties": {"id": {"type": "string"}}}}}},
                "responses": {"200": ok, "404": {"description": "no such job"}}}},
            "/api/portscan": {"post": {"tags": ["discovery"], "summary": "Scan ports on one host",
                "requestBody": {"required": True, "content": {"application/json": {"schema": {
                    "type": "object", "required": ["ip"], "properties": {
                        "ip": {"type": "string"},
                        "profile": {"type": "string", "enum": ["quick", "extended", "full"]},
                        "workers": {"type": "string"}}}}}},
                "responses": {"200": job["200"], "400": {"description": "ip required"}}}},
            "/api/history": {"get": {"tags": ["discovery"], "summary": "List scan snapshots, or fetch one",
                "parameters": [{"name": "file", "in": "query", "required": False,
                                "schema": {"type": "string"},
                                "description": "e.g. scan_1700000000.json; omit to list all"}],
                "responses": {"200": ok, "404": {"description": "not found"}}}},
            "/api/export": {"get": {"tags": ["system"], "summary": "Export the latest results",
                "parameters": [{"name": "format", "in": "query", "required": False,
                                "schema": {"type": "string", "enum": ["json", "csv"]}}],
                "responses": {"200": {"description": "File download (JSON or CSV)"}}}},
            "/api/snmp": {"post": {"tags": ["devices"],
                "summary": "Send an SNMP v2c GET or walk to a host",
                "requestBody": {"required": True, "content": {"application/json": {"schema": {
                    "type": "object", "required": ["ip"], "properties": {
                        "ip": {"type": "string"},
                        "oid": {"type": "string", "description": "Single OID (or subtree root when walk=true)"},
                        "oids": {"type": "array", "items": {"type": "string"}},
                        "community": {"type": "string", "description": "Default 'public'"},
                        "walk": {"type": "boolean", "description": "GETNEXT-walk the subtree under 'oid'"},
                        "max_rows": {"type": "integer", "description": "Walk row cap (default 256)"},
                        "timeout": {"type": "number"}, "port": {"type": "integer", "description": "Default 161"}}}}}},
                "responses": {"200": ok, "400": {"description": "ip / oid required"}}}},
            "/api/wol": {"post": {"tags": ["devices"], "summary": "Wake-on-LAN a MAC address",
                "requestBody": {"required": True, "content": {"application/json": {"schema": {
                    "type": "object", "required": ["mac"], "properties": {"mac": {"type": "string"}}}}}},
                "responses": {"200": ok, "400": {"description": "bad mac"}}}},
            "/api/device": {"post": {"tags": ["devices"], "summary": "Set a device name/notes (by MAC)",
                "requestBody": {"required": True, "content": {"application/json": {"schema": {
                    "type": "object", "required": ["mac"], "properties": {
                        "mac": {"type": "string"}, "name": {"type": "string"},
                        "notes": {"type": "string"}}}}}},
                "responses": {"200": ok, "400": {"description": "mac required"}}}},
            "/api/baseline": {
                "get": {"tags": ["security"], "summary": "Get the known-good baseline + live diff",
                        "responses": {"200": ok}},
                "post": {"tags": ["security"], "summary": "Manage the baseline",
                    "requestBody": {"required": True, "content": {"application/json": {"schema": {
                        "type": "object", "properties": {
                            "action": {"type": "string", "enum": ["set", "approve", "clear"]},
                            "keys": {"type": "array", "items": {"type": "string"}}}}}}},
                    "responses": {"200": ok, "400": {"description": "unknown action"}}}},
            "/api/events": {"get": {"tags": ["security"], "summary": "Recent proactive events",
                "parameters": [{"name": "limit", "in": "query", "required": False,
                                "schema": {"type": "integer", "default": 100}}],
                "responses": {"200": ok}}},
            "/api/events/poll": {"get": {"tags": ["security"],
                "summary": "Long-poll for events newer than 'since' (blocks up to 'timeout's)",
                "parameters": [
                    {"name": "since", "in": "query", "schema": {"type": "integer", "default": 0},
                     "description": "Return events with id greater than this"},
                    {"name": "timeout", "in": "query", "schema": {"type": "integer", "default": 25},
                     "description": "Seconds to block waiting for a new event (1-60)"}],
                "responses": {"200": ok}}},
            "/api/events/stream": {"get": {"tags": ["security"],
                "summary": "Server-Sent Events stream of live events (text/event-stream)",
                "parameters": [{"name": "since", "in": "query", "schema": {"type": "integer", "default": 0},
                                "description": "Replay events after this id before streaming live"}],
                "responses": {"200": {"description": "text/event-stream of event frames"}}}},
            "/api/tokens": {
                "get": {"tags": ["security"], "summary": "List API tokens (values are viewable)",
                        "responses": {"200": ok}},
                "post": {"tags": ["security"], "summary": "Create or delete an API token",
                    "requestBody": {"required": True, "content": {"application/json": {"schema": {
                        "type": "object", "properties": {
                            "action": {"type": "string", "enum": ["create", "delete"]},
                            "name": {"type": "string"},
                            "expires_days": {"type": "integer", "description": "Omit for a long-lived token"},
                            "id": {"type": "string"}}}}}},
                    "responses": {"200": ok, "400": {"description": "unknown action"}}}},
            "/api/credentials": {"post": {"tags": ["security"],
                "summary": "Change the admin username/password (persisted, hashed)",
                "requestBody": {"required": True, "content": {"application/json": {"schema": {
                    "type": "object", "required": ["password", "current_password"], "properties": {
                        "username": {"type": "string"},
                        "current_password": {"type": "string"},
                        "password": {"type": "string"}}}}}},
                "responses": {"200": ok, "400": {"description": "password required"},
                              "403": {"description": "current password incorrect"}}}},
            "/login": {"get": {"tags": ["system"], "summary": "Login page (HTML)",
                "security": [], "responses": {"200": ok}}},
            "/api/login": {"post": {"tags": ["security"], "summary": "Log in; sets a session cookie",
                "security": [],
                "requestBody": {"required": True, "content": {"application/json": {"schema": {
                    "type": "object", "required": ["username", "password"], "properties": {
                        "username": {"type": "string"}, "password": {"type": "string"}}}}}},
                "responses": {"200": ok, "401": {"description": "invalid username or password"}}}},
            "/api/logout": {"post": {"tags": ["security"], "summary": "Log out (clears the session)",
                "responses": {"200": ok}}},
            "/mcp": {"post": {"tags": ["agent"],
                "summary": "Model Context Protocol endpoint (JSON-RPC 2.0)",
                "description": "Streamable-HTTP MCP transport. Methods: initialize, "
                               "tools/list, tools/call, ping. Gated by NETRYX_TOKEN when set.",
                "security": [{"bearerAuth": []}],
                "requestBody": {"required": True, "content": {"application/json": {"schema": {
                    "type": "object", "properties": {
                        "jsonrpc": {"type": "string", "enum": ["2.0"]},
                        "id": {"type": ["integer", "string"]},
                        "method": {"type": "string"},
                        "params": {"type": "object"}}}}}},
                "responses": {"200": {"description": "JSON-RPC response"},
                              "202": {"description": "Accepted (notification, no body)"},
                              "401": {"description": "Unauthorized"}}}},
            "/openapi.json": {"get": {"tags": ["system"], "summary": "This spec as JSON",
                "responses": {"200": ok}}},
            "/openapi.yaml": {"get": {"tags": ["system"], "summary": "This spec as YAML",
                "responses": {"200": ok}}},
        },
    }


def _yaml_scalar(v):
    if v is None:
        return "null"
    if isinstance(v, bool):
        return "true" if v else "false"
    if isinstance(v, int):
        return str(v)
    if isinstance(v, float):
        return repr(v)
    return '"' + str(v).replace("\\", "\\\\").replace('"', '\\"') + '"'


_YAML_SPECIAL = set(" :/{}[]#,&*!|>%@`\"'")


def _yaml_key(k):
    sk = str(k)
    if (not sk) or sk.isdigit() or sk.lower() in ("true", "false", "null", "yes", "no", "on", "off") \
            or any(c in _YAML_SPECIAL for c in sk):
        return _yaml_scalar(k)
    return sk


def _yaml_dict(obj, indent):
    pad = "  " * indent
    out = []
    for k, v in obj.items():
        kk = _yaml_key(k)
        if isinstance(v, dict):
            out.append("%s%s:" % (pad, kk)) if v else out.append("%s%s: {}" % (pad, kk))
            if v:
                out += _yaml_dict(v, indent + 1)
        elif isinstance(v, list):
            out.append("%s%s:" % (pad, kk)) if v else out.append("%s%s: []" % (pad, kk))
            if v:
                out += _yaml_list(v, indent)
        else:
            out.append("%s%s: %s" % (pad, kk, _yaml_scalar(v)))
    return out


def _yaml_list(items, indent):
    pad = "  " * indent
    out = []
    for it in items:
        if isinstance(it, dict) and it:
            sub = _yaml_dict(it, indent + 1)
            out.append(pad + "- " + sub[0][len("  " * (indent + 1)):])
            out += sub[1:]
        elif isinstance(it, list) and it:
            sub = _yaml_list(it, indent + 1)
            out.append(pad + "- " + sub[0][len("  " * (indent + 1)):])
            out += sub[1:]
        else:
            out.append(pad + "- " + _yaml_scalar(it))
    return out


def openapi_yaml():
    return "\n".join(_yaml_dict(openapi_spec(), 0)) + "\n"


_UI_CACHE = None


def load_ui():
    global _UI_CACHE
    if _UI_CACHE is not None:
        return _UI_CACHE
    cands = []
    if getattr(sys, "frozen", False):
        cands.append(os.path.join(getattr(sys, "_MEIPASS", APP_DIR), "ui.html"))
    cands.append(os.path.join(APP_DIR, "ui.html"))
    for c in cands:
        try:
            if os.path.exists(c):
                with open(c, "r", encoding="utf-8") as f:
                    _UI_CACHE = f.read()
                    return _UI_CACHE
        except Exception:
            pass
    _UI_CACHE = ("<!DOCTYPE html><meta charset=utf-8><body style='font-family:sans-serif;"
                 "background:#0b0f17;color:#e6edf3;padding:40px'>"
                 "<h1>Netryx</h1><p>ui.html was not found next to the app. "
                 "Keep <code>ui.html</code> in the same folder as the program.</p></body>")
    return _UI_CACHE


# --------------------------------------------------------------------------- #
# HTTP handler
# --------------------------------------------------------------------------- #


class Handler(BaseHTTPRequestHandler):
    server_version = "Netryx/1.0"

    def log_message(self, *args):
        pass

    def _send(self, code, body, ctype="application/json", extra=None):
        if isinstance(body, (dict, list)):
            body = json.dumps(body).encode("utf-8")
        elif isinstance(body, str):
            body = body.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        if extra:
            for k, v in extra.items():
                self.send_header(k, v)
        self.end_headers()
        try:
            self.wfile.write(body)
        except Exception:
            pass

    def _body(self):
        try:
            length = int(self.headers.get("Content-Length", 0))
            return json.loads((self.rfile.read(length) if length else b"{}").decode("utf-8") or "{}")
        except Exception:
            return {}

    def _client_is_local(self):
        ip = self.client_address[0] if self.client_address else ""
        return ip in ("127.0.0.1", "::1", "::ffff:127.0.0.1")

    def _bearer(self):
        hdr = self.headers.get("Authorization", "")
        if hdr.startswith("Bearer "):
            return hdr[7:].strip()
        return (parse_qs(urlparse(self.path).query).get("token") or [""])[0]

    def _basic_ok(self):
        hdr = self.headers.get("Authorization", "")
        if not hdr.startswith("Basic "):
            return False
        try:
            user, _, pw = base64.b64decode(hdr[6:].strip()).decode("utf-8", "replace").partition(":")
        except Exception:
            return False
        return verify_admin(user, pw)

    def _cookie(self, name):
        for part in (self.headers.get("Cookie", "") or "").split(";"):
            k, _, v = part.strip().partition("=")
            if k == name:
                return v
        return ""

    def _auth_method(self):
        if NETRYX_OPEN:
            return "open"
        if NETRYX_TRUST_LOCALHOST and self._client_is_local():
            return "localhost"
        if session_valid(self._cookie("ns_session")):
            return "session"
        tok = self._bearer()
        if tok and token_valid(tok):
            return "token"
        if self._basic_ok():
            return "basic"
        return "none"

    def _authed(self):
        return self._auth_method() != "none"

    def _deny(self):
        # Browsers navigating to a page are redirected to the styled login screen;
        # API / fetch callers get a plain 401 (no WWW-Authenticate -> no browser popup).
        p = urlparse(self.path).path
        accept = self.headers.get("Accept", "")
        if self.command == "GET" and (p in ("/", "/index.html") or "text/html" in accept):
            return self._send(302, b"", extra={"Location": "/login"})
        return self._send(401, {"error": "unauthorized"})

    def do_GET(self):
        parsed = urlparse(self.path)
        path, qs = parsed.path, parse_qs(parsed.query)
        if path == "/login":
            return self._send(200, login_page(), "text/html; charset=utf-8",
                              extra={"Cache-Control": "no-store"})
        if path == "/logout":
            drop_session(self._cookie("ns_session"))
            return self._send(302, b"", extra={"Location": "/login",
                "Set-Cookie": "ns_session=; Path=/; Max-Age=0; HttpOnly; SameSite=Lax"})
        if not self._authed():
            return self._deny()
        if path in ("/", "/index.html"):
            return self._send(200, load_ui(), "text/html; charset=utf-8",
                              extra={"Cache-Control": "no-store"})
        if path == "/openapi.json":
            return self._send(200, json.dumps(openapi_spec(), indent=2), "application/json")
        if path in ("/openapi.yaml", "/openapi.yml"):
            return self._send(200, openapi_yaml(), "application/yaml; charset=utf-8")
        if path == "/api/info":
            return self._send(200, {
                "subnet": default_subnet(), "local_ip": get_primary_ip(),
                "gateway": default_gateway(), "cpu": os.cpu_count(),
                "platform": platform.system() + " " + platform.release(),
                "oui": oui_status(),
                "auth": {"enabled": auth_configured(),
                         "method": self._auth_method(),
                         "username": load_admin().get("username"),
                         "default_creds": is_default_admin(),
                         "trust_localhost": NETRYX_TRUST_LOCALHOST}})
        if path == "/api/oui":
            return self._send(200, oui_status())
        if path == "/api/job":
            job = JOBS.get((qs.get("id") or [None])[0])
            return self._send(200, job) if job else self._send(404, {"error": "no such job"})
        if path == "/api/history":
            f = (qs.get("file") or [None])[0]
            if f:
                if not re.match(r"^scan_\d+\.json$", f):
                    return self._send(400, {"error": "bad file"})
                rec = _load_json(os.path.join(HISTORY_DIR, f), None)
                return self._send(200, rec) if rec else self._send(404, {"error": "not found"})
            return self._send(200, list_history())
        if path == "/api/export":
            fmt = (qs.get("format") or ["json"])[0]
            devs = LAST_RESULTS.get("devices", [])
            if fmt == "csv":
                return self._send(200, devices_to_csv(devs), "text/csv",
                                  {"Content-Disposition": "attachment; filename=netryx.csv"})
            return self._send(200, json.dumps(devs, indent=2), "application/json",
                              {"Content-Disposition": "attachment; filename=netryx.json"})
        if path == "/api/baseline":
            b = load_baseline()
            diff = diff_against_baseline(LAST_RESULTS.get("devices", []), b) \
                if b.get("devices") else None
            return self._send(200, {
                "created": b.get("created"), "updated": b.get("updated"),
                "size": len(b.get("devices", {})),
                "devices": list(b.get("devices", {}).values()), "diff": diff})
        if path == "/api/events":
            try:
                limit = int((qs.get("limit") or ["100"])[0])
            except Exception:
                limit = 100
            return self._send(200, {"events": list_events(limit)})
        if path == "/api/events/poll":
            try:
                since = int((qs.get("since") or ["0"])[0])
            except Exception:
                since = 0
            try:
                timeout = max(1, min(60, int((qs.get("timeout") or ["25"])[0])))
            except Exception:
                timeout = 25
            EVENT_HUB.wait(since, timeout)
            return self._send(200, {"events": events_since(since), "seq": EVENT_HUB.seq})
        if path == "/api/events/stream":
            try:
                last = int((qs.get("since") or ["0"])[0])
            except Exception:
                last = 0
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream; charset=utf-8")
            self.send_header("Cache-Control", "no-store")
            self.send_header("Connection", "keep-alive")
            self.send_header("X-Accel-Buffering", "no")   # don't let nginx buffer SSE
            self.end_headers()
            try:
                self.wfile.write(b": connected\n\n")
                for e in events_since(last):
                    self.wfile.write(_sse_frame(e))
                    last = e["id"]
                self.wfile.flush()
                while True:
                    EVENT_HUB.wait(last, 20)
                    evs = events_since(last)
                    if evs:
                        for e in evs:
                            self.wfile.write(_sse_frame(e))
                            last = e["id"]
                    else:
                        self.wfile.write(b": keepalive\n\n")   # heartbeat
                    self.wfile.flush()
            except Exception:
                pass          # client disconnected
            return
        if path == "/api/tokens":
            return self._send(200, {"tokens": list_tokens(),
                                    "trust_localhost": NETRYX_TRUST_LOCALHOST,
                                    "admin": bool(NETRYX_PASS)})
        return self._send(404, {"error": "not found"})

    def do_POST(self):
        path = urlparse(self.path).path
        data = self._body()
        if path == "/api/login":
            if verify_admin((data.get("username") or "").strip(), data.get("password") or ""):
                tok = new_session()
                return self._send(200, {"ok": True}, extra={"Set-Cookie":
                    "ns_session=%s; Path=/; Max-Age=%d; HttpOnly; SameSite=Lax" % (tok, SESSION_TTL)})
            return self._send(401, {"error": "invalid username or password"})
        if path == "/api/logout":
            drop_session(self._cookie("ns_session"))
            return self._send(200, {"ok": True}, extra={"Set-Cookie":
                "ns_session=; Path=/; Max-Age=0; HttpOnly; SameSite=Lax"})
        if not self._authed():
            return self._deny()
        if path == "/mcp":
            try:
                import netryx_mcp as mcpmod
            except Exception as e:
                return self._send(500, {"error": "MCP module unavailable: %s" % e})
            # Bind the MCP tools to *this* running engine instance so /mcp sees
            # the same live scan results and jobs the web UI does.
            mcpmod.engine = sys.modules[__name__]
            items = data if isinstance(data, list) else [data]
            out = [r for r in (mcpmod.dispatch(it) for it in items) if r is not None]
            if not out:
                return self._send(202, b"")  # only notifications -> no body
            return self._send(200, out if isinstance(data, list) else out[0])
        if path == "/api/scan":
            subnet = (data.get("subnet") or "").strip()
            if not subnet:
                return self._send(400, {"error": "subnet required"})
            profile = data.get("port_profile", "quick")
            if profile not in PORT_PROFILES:
                profile = "quick"
            jid = start_job("discovery", run_discovery, subnet, bool(data.get("scan_ports")),
                            profile, bool(data.get("use_mdns", True)), bool(data.get("use_snmp", True)),
                            data.get("workers", "auto"))
            return self._send(200, {"job_id": jid})
        if path == "/api/portscan":
            ip = (data.get("ip") or "").strip()
            if not ip:
                return self._send(400, {"error": "ip required"})
            profile = data.get("profile", "extended")
            if profile not in PORT_PROFILES:
                profile = "extended"
            return self._send(200, {"job_id": start_job("portscan", run_portscan, ip, profile, data.get("workers", "auto"))})
        if path == "/api/oui/download":
            return self._send(200, {"job_id": start_job("oui", run_oui_download)})
        if path == "/api/job/stop":
            j = JOBS.get((data.get("id") or "").strip())
            if j:
                j["cancel"] = True
                return self._send(200, {"ok": True})
            return self._send(404, {"error": "no such job"})
        if path == "/api/wol":
            try:
                return self._send(200, {"ok": wake_on_lan((data.get("mac") or "").strip())})
            except Exception as e:
                return self._send(400, {"error": str(e)})
        if path == "/api/snmp":
            ip = (data.get("ip") or data.get("host") or "").strip()
            if not ip:
                return self._send(400, {"error": "ip (or host) required"})
            community = data.get("community") or "public"
            try:
                timeout = max(0.2, min(5.0, float(data.get("timeout", 1.5))))
            except Exception:
                timeout = 1.5
            try:
                port = int(data.get("port", 161))
            except Exception:
                port = 161
            if data.get("walk"):
                base = (data.get("oid") or "").strip()
                if not base and data.get("oids"):
                    base = str(data["oids"][0])
                if not base:
                    return self._send(400, {"error": "oid (subtree root) required for walk"})
                rows = snmp_walk(ip, base, community, timeout, data.get("max_rows", 256), port)
                return self._send(200, {"ip": ip, "walk": base, "community": community,
                                        "count": len(rows), "results": rows})
            oids = data.get("oids") or ([data.get("oid")] if data.get("oid") else [])
            if not oids:
                return self._send(400, {"error": "oid or oids required"})
            res = snmp_get(ip, oids, community, timeout, port)
            return self._send(200, {"ip": ip, "community": community, "results": res,
                "note": None if res else "no response (host unreachable, SNMP disabled, or wrong community)"})
        if path == "/api/device":
            mac = (data.get("mac") or "").strip().lower()
            if not mac:
                return self._send(400, {"error": "mac required"})
            ok = save_device_meta(mac, data.get("name"), data.get("notes"))
            for d in LAST_RESULTS.get("devices", []):
                if d.get("mac") == mac:
                    if data.get("name") is not None:
                        d["name"] = data.get("name")
                    if data.get("notes") is not None:
                        d["notes"] = data.get("notes")
            return self._send(200, {"ok": ok})
        if path == "/api/baseline":
            action = (data.get("action") or "set").strip().lower()
            devs = LAST_RESULTS.get("devices", [])
            if action == "set":
                b = baseline_from_devices(devs)
                _save_json(ALERTS_FILE, [])  # reset alert de-dup state
                return self._send(200, {"ok": True, "action": "set",
                                        "size": len(b.get("devices", {}))})
            if action == "clear":
                clear_baseline()
                _save_json(ALERTS_FILE, [])
                return self._send(200, {"ok": True, "action": "clear", "size": 0})
            if action == "approve":
                b = approve_devices(data.get("keys") or [], devs)
                return self._send(200, {"ok": True, "action": "approve",
                                        "size": len(b.get("devices", {}))})
            return self._send(400, {"error": "unknown action"})
        if path == "/api/tokens":
            action = (data.get("action") or "create").strip().lower()
            if action == "create":
                return self._send(200, {"ok": True,
                                        "token": create_token(data.get("name"), data.get("expires_days"))})
            if action == "delete":
                return self._send(200, {"ok": delete_token((data.get("id") or "").strip())})
            return self._send(400, {"error": "unknown action"})
        if path == "/api/credentials":
            newpw = data.get("password") or ""
            if not newpw:
                return self._send(400, {"error": "password required"})
            cur_user = load_admin().get("username")
            if not verify_admin(cur_user, data.get("current_password") or ""):
                return self._send(403, {"error": "current password incorrect"})
            a = set_admin(data.get("username") or cur_user, newpw)
            return self._send(200, {"ok": True, "username": a["username"]})
        return self._send(404, {"error": "not found"})


# --------------------------------------------------------------------------- #
# Entry point
# --------------------------------------------------------------------------- #


def find_free_port(preferred, host):
    for p in [preferred] + list(range(8765, 8820)):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind((host, p))
            s.close()
            return p
        except Exception:
            continue
    return preferred


def main():
    ap = argparse.ArgumentParser(description="Netryx - local network scanner web app")
    ap.add_argument("--host", default=os.environ.get("NETRYX_HOST", "127.0.0.1"))
    ap.add_argument("--port", type=int, default=int(os.environ.get("NETRYX_PORT", "8765")))
    ap.add_argument("--no-browser", action="store_true",
                    default=bool(os.environ.get("NETRYX_NO_BROWSER")))
    # One-shot CLI scan (no server) - handy for scripts, cron and AI agents.
    ap.add_argument("--scan", metavar="TARGETS",
                    help="Scan TARGETS (CIDR/IP/range list, e.g. '192.168.1.0/24') once and exit")
    ap.add_argument("--ports", action="store_true",
                    help="With --scan: also scan ports on each live host")
    ap.add_argument("--profile", default="quick", choices=list(PORT_PROFILES),
                    help="With --ports: port profile (default: quick)")
    ap.add_argument("--workers", default="auto",
                    help="Worker count or 'auto' (default: auto)")
    ap.add_argument("--no-mdns", action="store_true", help="With --scan: skip mDNS discovery")
    ap.add_argument("--no-snmp", action="store_true", help="With --scan: skip SNMP probing")
    ap.add_argument("--json", action="store_true",
                    help="With --scan: print the result as JSON instead of a table")
    args = ap.parse_args()

    if args.scan:
        res = discover(args.scan, scan_ports=args.ports, port_profile=args.profile,
                       use_mdns=not args.no_mdns, use_snmp=not args.no_snmp,
                       req_workers=args.workers)
        if res.get("error"):
            print(json.dumps({"error": res["error"]}) if args.json
                  else ("Error: " + res["error"]), file=sys.stderr)
            return 1
        if args.json:
            print(json.dumps(res, indent=2))
        else:
            _print_scan_table(res)
        return 0

    _restore_last_results()
    port = find_free_port(args.port, args.host)
    httpd = ThreadingHTTPServer((args.host, port), Handler)
    shown = "127.0.0.1" if args.host in ("0.0.0.0", "") else args.host
    url = "http://%s:%d" % (shown, port)

    print("=" * 64)
    print("  Netryx - Signal Cartography")
    print("  Open:  " + url)
    print("  Data:  " + DATA_DIR)
    print("  Press Ctrl+C to stop.")
    print("=" * 64)

    if not args.no_browser:
        threading.Timer(1.0, lambda: webbrowser.open(url)).start()
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nStopping Netryx...")
        httpd.shutdown()


if __name__ == "__main__":
    sys.exit(main() or 0)
