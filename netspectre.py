#!/usr/bin/env python3
# -*- coding: utf-8 -*-
r"""
  _____   ___  _____ _____ ___ ___    _   ___ ___ ___  _______  ___
 / __\ \ / / \|_   _|_   _|_ _/ __|  /_\ | _ \_ _|   \|_   _\ \/ /_
| (_ |\ V /|  \ || |  | |  | | (__  / _ \|  _/| || |) | | |  >  <| '_|
 \___| \_/ |_|\_\|_|  |_| |___\___|/_/ \_\_| |___|___/  |_| /_/\_\_|
                     ~ local network auditing toolkit ~

Authorized-use only. Run against networks you own or have permission to test.
"""

from __future__ import annotations

import argparse
import concurrent.futures as cf
import csv
import ipaddress
import json
import os
import platform
import re
import shutil
import signal
import socket
import struct
import subprocess
import sys
import time
from dataclasses import dataclass, field

__version__ = "1.0.0"
__author__ = "NetSpectre Team"

# ============================================================
#  ANSI visual layer
# ============================================================

_IS_WIN = platform.system() == "Windows"
if _IS_WIN:  # enable VT escape sequences on Windows 10+
    os.system("")  # noqa: S605 - side effect: enables ANSI on modern terminals


class Ansi:
    """Minimal ANSI profile with graceful degradation when colors are off."""

    def __init__(self, color: bool) -> None:
        self.ok = color

    def __getattr__(self, name: str) -> str:
        return _ANSI[name] if self.ok else ""

    def strip(self, text: str) -> str:
        return _ANSI_RE.sub("", text)


_ANSI = {
    "reset": "\033[0m",
    "bold": "\033[1m",
    "dim": "\033[2m",
    "italic": "\033[3m",
    "underline": "\033[4m",
    "red": "\033[31m",
    "green": "\033[32m",
    "yellow": "\033[33m",
    "blue": "\033[34m",
    "magenta": "\033[35m",
    "cyan": "\033[36m",
    "white": "\033[37m",
    "gray": "\033[90m",
    "bright_red": "\033[91m",
    "bright_green": "\033[92m",
    "bright_yellow": "\033[93m",
    "bright_blue": "\033[94m",
    "bright_magenta": "\033[95m",
    "bright_cyan": "\033[96m",
    # short aliases used across the UI layer (ansi.b_cyan, ansi.b_magenta, ...)
    "b_red": "\033[91m",
    "b_green": "\033[92m",
    "b_yellow": "\033[93m",
    "b_blue": "\033[94m",
    "b_magenta": "\033[95m",
    "b_cyan": "\033[96m",
}
_ANSI_RE = re.compile(r"\033\[[0-9;]*m")


def paint(ansi: Ansi, template: str, **kw: str) -> str:
    """template uses {bold}, {red}, ... and !r! to reset; kwargs fill plain values."""
    base = {k: getattr(ansi, v) for k, v in {
        "bold": "bold", "dim": "dim", "red": "red", "green": "green", "yellow": "yellow",
        "blue": "blue", "magenta": "magenta", "cyan": "cyan", "gray": "gray",
        "b_red": "bright_red", "b_green": "bright_green", "b_yellow": "bright_yellow",
        "b_blue": "bright_blue", "b_magenta": "bright_magenta", "b_cyan": "bright_cyan",
    }.items()}
    base["r"] = ansi.reset
    base.update(kw)
    return template.format(**base)


def c(ansi: Ansi, color: str, text: object) -> str:
    return (getattr(ansi, color) + str(text) + ansi.reset) if ansi.ok else str(text)


BANNER = r"""
   _   _    _ _____ _____ ____  _____   ____ ___  ____  _____
  | \ | |  / \|_   _|_   _/ ___||_   _| / ___/ _ \|  _ \| ____|
  |  \| | / _ \ | |   | | \___ \  | |  | |  | | | | |_) |  _|
  | |\  |/ ___ \| |   | |  ___) | | |  | |__| |_| |  _ <| |___
  |_| \_/_/   \_\_|   |_| |____/  |_|   \____\___/|_| \_\_____|
"""


def draw_banner(ansi: Ansi) -> None:
    print(c(ansi, "cyan", BANNER))
    print(
        f"        {ansi.bold}{ansi.b_magenta}NetSpectre{ansi.reset}"
        f" {ansi.gray}v{__version__}{ansi.reset}"
        f"  {ansi.dim}~{ansi.reset}  {ansi.gray}local network auditing toolkit{ansi.reset}\n"
    )
    print(c(ansi, "yellow", "  [!] Authorized-use only: audit networks you own or are permitted to test.\n"))


RULE = "─" * 78


def box_title(ansi: Ansi, text: str) -> str:
    inner = f" {text.upper()} "
    return f"{ansi.bold}{ansi.cyan}┌{inner.center(78, '─')}┐{ansi.reset}"


def info(ansi: Ansi, msg: str) -> None:
    print(f"  {ansi.cyan}[+]{ansi.reset} {msg}")


def warn(ansi: Ansi, msg: str) -> None:
    print(f"  {ansi.yellow}[!]{ansi.reset} {msg}")


def error(ansi: Ansi, msg: str) -> None:
    print(f"  {ansi.red}[x]{ansi.reset} {msg}")


def ok(ansi: Ansi, msg: str) -> None:
    print(f"  {ansi.green}[✓]{ansi.reset} {msg}")


def debug(ansi: Ansi, msg: str) -> None:
    print(f"  {ansi.gray}[·] {msg}{ansi.reset}")


# ============================================================
#  Models / state
# ============================================================

TOP_PORTS = [
    21, 22, 23, 25, 53, 80, 81, 110, 111, 135, 139, 143, 443, 445, 465, 587,
    593, 623, 631, 873, 990, 993, 995, 1080, 1194, 1433, 1521, 1723, 2049,
    2082, 2083, 2375, 2376, 3000, 3268, 3306, 3389, 4443, 5000, 5060, 5432,
    5555, 5900, 5901, 5984, 6379, 6443, 6667, 8000, 8008, 8080, 8081, 8443,
    8888, 9000, 9200, 9418, 11211, 161, 179, 500, 4500, 1719, 5061, 5038,
]

SERVICE_HINTS = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "domain", 80: "http",
    81: "http-alt", 110: "pop3", 111: "rpcbind", 135: "msrpc", 139: "netbios-ssn",
    143: "imap", 161: "snmp", 179: "bgp", 443: "https", 445: "microsoft-ds",
    500: "isakmp", 587: "submission", 623: "asf-rmcp", 631: "ipp", 1433: "ms-sql",
    1521: "oracle", 1723: "pptp", 2049: "nfs", 2375: "docker", 2376: "docker-tls",
    3000: "http-dev", 3306: "mysql", 3389: "ms-wbt", 5000: "upnp", 5060: "sip",
    5061: "sips", 5432: "postgresql", 5555: "adb", 5900: "vnc", 5901: "vnc-1",
    6379: "redis", 6443: "k8s-api", 8000: "http-alt", 8080: "http-proxy",
    8443: "https-alt", 9000: "cslistener", 9200: "elasticsearch", 11211: "memcached",
}

BANNER_PORTS = {21, 22, 25, 79, 110, 143, 587, 631, 993, 995, 5900, 8000, 8080}
HTTP_PORTS = {80, 81, 3000, 8000, 8008, 8080, 8081, 8888, 9000}  # plaintext only
TLS_PORTS = {443, 4443, 8443, 993, 995, 465}  # never send plaintext probes here

# ---------------------------------------------------------------------------
#  Risk catalog: services whose exposure deserves a warning in the audit.
#    port -> (level, tag, reason)
#    level: "high"   — service unauthenticated/unencrypted by design or a
#                      known attack vector; treat as critical on a LAN
#           "medium" — sensitive data plane or admin interface; verify exposure
# ---------------------------------------------------------------------------
RISK_PORTS: dict[int, tuple[str, str, str]] = {
    # -- high --
    23:   ("high", "telnet", "plaintext protocol: exposes credentials and the whole session"),
    5555: ("high", "adb", "Android Debug Bridge: frequently allows an unauthenticated shell"),
    623:  ("high", "ipmi", "IPMI/BMC: hash capture and default-credential abuse"),
    6379: ("high", "redis", "often deployed without auth (requirepass unset)"),
    11211:("high", "memcached", "unauthenticated memory dump; amplification-abuse vector"),
    2375: ("high", "docker", "Docker API in plaintext: full host takeover"),
    3389: ("high", "rdp", "exposed RDP: brute force and BlueKeep-style exploits"),
    5900: ("high", "vnc", "VNC: weak auth, no encryption by default"),
    5901: ("high", "vnc", "VNC: weak auth, no encryption by default"),
    445:  ("high", "smb", "SMB: EternalBlue/WannaCry vector; never expose beyond the host"),
    # -- medium --
    21:   ("medium", "ftp", "plaintext credentials; anonymous access is common"),
    139:  ("medium", "netbios", "legacy NetBIOS: leaks shares, users and machine info"),
    161:  ("medium", "snmp", "SNMPv1/v2c default communities leak device config"),
    1433: ("medium", "mssql", "database engine listening on the LAN"),
    3306: ("medium", "mysql", "database engine listening on the LAN"),
    5432: ("medium", "postgresql", "database engine listening on the LAN"),
    2049: ("medium", "nfs", "NFS exports may be world-readable/mountable"),
    5000: ("medium", "upnp", "UPnP: device control surface; check auth"),
    6443: ("medium", "k8s-api", "Kubernetes API: verify anonymous/RBAC access"),
    9200: ("medium", "elasticsearch", "cluster API without auth by default"),
}


# ---------------------------------------------------------------------------
#  UDP scanning: state semantics follow nmap conventions
#    open           — the service answered our probe with a valid response
#    open|filtered  — no answer and no ICMP error (typical for quiet services)
#    closed         — an ICMP "port unreachable" came back from the target
#    filtered       — another ICMP error (host/net unreachable, admin block…)
# ---------------------------------------------------------------------------
TOP_UDP_PORTS = [
    53, 67, 68, 69, 111, 123, 137, 138, 161, 162, 177, 500, 514, 520, 623,
    1194, 1900, 2049, 4500, 5060, 5353, 5355, 11211, 3702,
]

UDP_SERVICES = {
    53: "domain", 67: "dhcp-server", 68: "dhcp-client", 69: "tftp",
    111: "rpcbind", 123: "ntp", 137: "netbios-ns", 138: "netbios-dgm",
    161: "snmp", 162: "snmptrap", 177: "xdmcp", 500: "isakmp", 514: "syslog",
    520: "rip", 623: "asf-rmcp", 1194: "openvpn", 1900: "ssdp", 2049: "nfs",
    4500: "ipsec-nat-t", 5060: "sip", 5353: "mdns", 5355: "llmnr",
    11211: "memcached", 3702: "ws-discovery",
}

UDP_RISK: dict[int, tuple[str, str, str]] = {
    # -- high --
    69:   ("high", "tftp", "TFTP: no auth, no encryption — configs and firmware can be pulled"),
    623:  ("high", "ipmi", "IPMI/BMC over UDP RMCP: hash capture and default credentials"),
    # -- medium --
    123:  ("medium", "ntp", "NTP: monlist-style amplification if misconfigured"),
    137:  ("medium", "netbios", "NetBIOS name service: leaks machine and domain info"),
    138:  ("medium", "netbios", "NetBIOS datagram: leaks browsing/host info"),
    161:  ("medium", "snmp", "SNMPv1/v2c default communities leak device config"),
    162:  ("medium", "snmp", "SNMP traps: check community strings"),
    514:  ("medium", "syslog", "unencrypted logs: information leak, injection surface"),
    1900: ("medium", "ssdp", "SSDP/UPnP: device control surface; amplification vector"),
    2049: ("medium", "nfs", "NFS over UDP: exports may be world-mountable"),
    5060: ("medium", "sip", "SIP: enumeration and registration abuse on the LAN"),
    11211:("medium", "memcached", "UDP interface: amplification abuse; check exposure"),
}


# ---- protocol-aware payloads so real services actually answer -------------

def _ber_len(n: int) -> bytes:
    if n < 0x80:
        return bytes([n])
    out = b""
    while n:
        out = bytes([n & 0xFF]) + out
        n >>= 8
    return bytes([0x80 | len(out)]) + out


def _ber(tag: int, body: bytes) -> bytes:
    return bytes([tag]) + _ber_len(len(body)) + body


def _ber_oid(oid: str) -> bytes:
    nums = [int(x) for x in oid.split(".")]
    body = bytes([nums[0] * 40 + nums[1]])
    for n in nums[2:]:
        chunk = bytes([n & 0x7F])
        n >>= 7
        while n:
            chunk = bytes([(n & 0x7F) | 0x80]) + chunk
            n >>= 7
        body += chunk
    return _ber(0x06, body)


def _dns_query(name: str) -> bytes:
    """Minimal DNS/mDNS A-record query."""
    tid = os.urandom(2)
    header = tid + struct.pack("!HHHHH", 0x0100, 1, 0, 0, 0)  # RD=1, QD=1
    q = b"".join(bytes([len(p)]) + p.encode("ascii") for p in name.split(".") if p) + b"\x00"
    return header + q + struct.pack("!HH", 1, 1)  # type A, class IN


def _ntp_request() -> bytes:
    return bytes([0x23]) + b"\x00" * 47  # LI=0, VN=4, Mode=3 (client)


def _nbt_ns_query() -> bytes:
    """NetBIOS Name Service node-status request for wildcard name '*' (RFC 1002)."""
    tid = os.urandom(2)
    header = tid + struct.pack("!HHHHH", 0x0000, 1, 0, 0, 0)
    q = b"\x20" + b"CK" + b"A" * 30 + b"\x00" + struct.pack("!HH", 33, 1)  # NBSTAT, IN
    return header + q


def _snmp_v2c_get(community: str = "public", oid: str = "1.3.6.1.2.1.1.1.0") -> bytes:
    """SNMPv2c GET for sysDescr.0 — hand-rolled BER to stay stdlib-only."""
    varbind = _ber(0x30, _ber_oid(oid) + _ber(0x05, b""))
    varbinds = _ber(0x30, varbind)
    pdu = _ber(0xA0, _ber(0x02, b"\x01") + _ber(0x02, b"\x00") + _ber(0x02, b"\x00") + varbinds)
    return _ber(0x30, _ber(0x02, b"\x01") + _ber(0x04, community.encode()) + pdu)


def _ssdp_search() -> bytes:
    return (b"M-SEARCH * HTTP/1.1\r\nHost: 239.255.255.250:1900\r\n"
            b"Man: \"ssdp:discover\"\r\nMx: 1\r\nST: ssdp:all\r\n\r\n")


UDP_PAYLOAD_BUILDERS: dict[int, "callable[[], bytes]"] = {
    53: lambda: _dns_query("ns1.test"),
    123: _ntp_request,
    137: _nbt_ns_query,
    161: _snmp_v2c_get,
    5353: lambda: _dns_query("_services._dns-sd._udp.local"),
    1900: _ssdp_search,
}


def _classify_udp_response(port: int, data: bytes) -> str:
    """Human-readable description of a UDP service answer."""
    if not data:
        return "udp-response"
    try:
        if port in (53, 5353) and len(data) >= 12 and data[2] & 0x80:  # QR bit
            answers = struct.unpack("!H", data[6:8])[0]
            label = "mdns" if port == 5353 else "dns"
            return f"{label}-response ({answers} answer(s))"
        if port == 123 and len(data) >= 2 and (data[0] & 0x07) == 4:   # mode=server
            return f"ntp-response (stratum {data[1]})"
        if port == 137 and len(data) >= 4:
            return "netbios-response"
        if port == 161 and data[0] == 0x30:  # ASN.1 SEQUENCE
            return "snmp-response"
        if port == 1900 and data[:7] == b"HTTP/1.":
            return "ssdp-response"
    except (struct.error, IndexError):
        pass
    return f"udp-response ({len(data)}B)"


def risk_of(port: int) -> tuple[str, str, str] | None:
    """Return (level, tag, reason) for a port, or None if not catalogued."""
    return RISK_PORTS.get(port)


# ---------------------------------------------------------------------------
#  Hardening tips: one concrete remediation per risk tag. Shown in 'risks'
#  under each finding and exported in the JSON report as findings[].fix.
# ---------------------------------------------------------------------------
REMEDIATIONS: dict[str, str] = {
    "telnet": "disable the telnet daemon; use SSH with key-based auth instead",
    "adb": "keep ADB on USB only ('adb usb'); never listen on tcp/5555; firewall the port",
    "ipmi": "change default BMC credentials, enforce per-message auth, isolate in a management VLAN",
    "redis": "set 'requirepass', bind 127.0.0.1, enable ACLs and rename FLUSHALL/CONFIG",
    "memcached": "disable UDP (-U 0), bind to localhost/private VLAN, enable SASL auth",
    "docker": "use the unix socket only; if TCP is required, enable TLS with client certs",
    "rdp": "require NLA, enable account lockout + MFA/VPN, patch against BlueKeep",
    "vnc": "tunnel over SSH/VPN, set a strong password, disable plaintext auth",
    "smb": "disable SMBv1, keep patched, require signing, restrict with host firewall",
    "netbios": "disable NetBIOS over TCP/IP if unused; block 137-139 outbound/inbound",
    "snmp": "upgrade to SNMPv3 authPriv, remove public/private communities, ACL manager IPs",
    "mssql": "bind to localhost/private VLAN, dedicated least-privilege accounts, TLS, firewall",
    "mysql": "bind to localhost/private VLAN, dedicated least-privilege accounts, TLS, firewall",
    "postgresql": "bind to localhost/private VLAN, dedicated least-privilege accounts, TLS, firewall",
    "nfs": "prefer NFSv4+Kerberos, explicit exports (never *(rw)), root_squash enabled",
    "upnp": "disable UPnP on the gateway if not required; audit port mappings",
    "k8s-api": "enforce RBAC, disable anonymous auth, audit logging, expose via VPN/CA only",
    "elasticsearch": "enable x-pack security (auth + TLS), bind to private interfaces only",
    "ntp": "disable monlist ('restrict default noquery'), run a patched ntpd/chrony",
    "syslog": "use TLS transport (rsyslog/syslog-ng gtls), rate-limit, validate senders",
    "ssdp": "disable UPnP discovery; filter multicast 239.255.255.250:1900 at the switch",
    "sip": "use SIPS/TLS, fail2ban on registrations, hide topology from untrusted LANs",
    "tftp": "disable unless essential; chroot with read-only dirs; restrict source IPs",
    "ftp": "replace with SFTP/FTPS; disable anonymous login; enforce TLS",
}


def fix_for(tag: str) -> str:
    """Concrete hardening tip for a risk tag ('' if unknown)."""
    return REMEDIATIONS.get(tag, "")


def risk_badge(ansi: Ansi, port: int) -> str:
    """Colored badge like [RISK:redis] / [warn:ftp]; '' when the port is benign."""
    entry = RISK_PORTS.get(port) or UDP_RISK.get(port)
    if not entry:
        return ""
    level, tag = entry[0], entry[1]
    if level == "high":
        return f"{ansi.bold}{ansi.b_red}[RISK:{tag}]{ansi.reset}"
    return f"{ansi.yellow}[warn:{tag}]{ansi.reset}"


DEFAULT_HOST_TIMEOUT = 0.5
DEFAULT_PORT_TIMEOUT = 1.0
DEFAULT_HOST_WORKERS = 128
DEFAULT_PORT_WORKERS = 256
DEFAULT_UDP_TIMEOUT = 2.0
DEFAULT_UDP_WORKERS = 128


@dataclass
class PortResult:
    port: int
    state: str              # "open" | "closed" | "filtered"
    service: str
    banner: str = ""
    risk: str = ""          # risk tag when the service is catalogued ("redis", "smb"…)
    risk_level: str = ""    # "high" | "medium" | ""


@dataclass
class UdpResult:
    port: int
    state: str              # "open" | "open|filtered" | "closed" | "filtered"
    service: str
    response: str = ""
    risk: str = ""
    risk_level: str = ""


@dataclass
class HostRecord:
    ip: str
    hostname: str = ""
    mac: str = ""
    vendor: str = ""
    alive: bool = False
    ports: list[PortResult] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "ip": self.ip, "hostname": self.hostname, "mac": self.mac,
            "vendor": self.vendor, "alive": self.alive,
            "ports": [{"port": p.port, "state": p.state, "service": p.service,
                       "banner": p.banner, "risk": p.risk,
                       "risk_level": p.risk_level} for p in self.ports],
        }


class Session:
    """Runtime state of the interactive console."""

    def __init__(self, ansi: Ansi, color: bool, ping: bool) -> None:
        self.ansi = ansi
        self.color = color
        self.ping_sweep = ping
        self.subnet: str = detect_default_subnet()
        self.host_timeout: float = DEFAULT_HOST_TIMEOUT
        self.port_timeout: float = DEFAULT_PORT_TIMEOUT
        self.host_workers: int = DEFAULT_HOST_WORKERS
        self.port_workers: int = DEFAULT_PORT_WORKERS
        self.udp_timeout: float = DEFAULT_UDP_TIMEOUT
        self.udp_workers: int = DEFAULT_UDP_WORKERS
        self.max_high: int | None = None      # risk gate: fail if high findings exceed
        self.max_medium: int | None = None    # risk gate: fail if medium findings exceed
        self.target: str = ""
        self.port_range: str = "top100"
        self.history: list[str] = []
        self.log_path: str = ""
        self.ips_scanned: int = 0
        self.ports_tested: int = 0
        self.start_time: float = time.time()
        self.stop = False
        self.interrupted: bool = False
        self.quit: bool = False
        self.last_hosts: list[HostRecord] = []
        self.last_udp: dict[str, list[UdpResult]] = {}
        self.profile_name: str = ""

    # ---------- dynamic prompt ----------
    def prompt(self) -> str:
        a = self.ansi
        if a.ok:
            base = f"{a.bold}{a.b_magenta}netspectre{a.reset}"
            ctx = f"{a.gray}({a.reset}{a.cyan}{self.context()}{a.reset}{a.gray}){a.reset} "
            arrow = f"{a.bold}{a.b_magenta}>{a.reset} "
            return f"{base}{ctx}{arrow}"
        return f"netspectre ({self.context()}) > "

    def context(self) -> str:
        parts = [self.target] if self.target else []
        if self.port_range != "top100":
            parts.append(f"ports={self.port_range}")
        if self.profile_name:
            parts.append(f"@{self.profile_name}")
        return ":".join(parts) if parts else "no target"

    def uptime(self) -> str:
        secs = int(time.time() - self.start_time)
        h, rem = divmod(secs, 3600)
        m, s = divmod(rem, 60)
        return f"{h:02d}:{m:02d}:{s:02d}"

    def log(self, line: str) -> None:
        if self.log_path:
            try:
                with open(self.log_path, "a", encoding="utf-8", errors="replace") as fh:
                    fh.write(line.rstrip("\n") + "\n")
            except OSError as exc:
                error(self.ansi, f"log write failed: {exc}")


# ============================================================
#  Networking helpers
# ============================================================

def detect_local_ip() -> str:
    """Best-effort local address via a UDP socket (no packet is actually sent)."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.connect(("8.8.8.8", 80))  # just picks a route; UDP sends nothing here
            return s.getsockname()[0]
        finally:
            s.close()
    except OSError:
        return "127.0.0.1"


def detect_default_subnet() -> str:
    try:
        return str(ipaddress.ip_network(f"{detect_local_ip()}/24", strict=False))
    except (OSError, ValueError):
        return "192.168.1.0/24"


def local_ip() -> str:
    return detect_local_ip()


def resolve_ptr(ip: str, timeout: float = 0.4) -> str:
    try:
        return socket.gethostbyaddr(ip)[0]
    except (socket.herror, socket.gaierror, OSError):
        return ""


def tcp_probe(ip: str, port: int, timeout: float) -> bool:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            return s.connect_ex((ip, port)) == 0
    except OSError:
        return False


def _read_banner(sock: socket.socket) -> str:
    try:
        sock.settimeout(0.8)
        data = sock.recv(128)
        return data.decode("utf-8", errors="replace").strip()
    except (OSError, UnicodeDecodeError):
        return ""


def _http_probe(ip: str, port: int) -> str:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(1.2)
            s.connect((ip, port))
            s.sendall(b"HEAD / HTTP/1.0\r\nHost: netspectre\r\n\r\n")
            data = s.recv(256)
            return data.decode("utf-8", errors="replace").strip()
    except OSError:
        return ""


def audit_port(ip: str, port: int, timeout: float) -> PortResult:
    """Single-port TCP connect audit with service guess + banner grab."""
    risk = RISK_PORTS.get(port)
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            rc = s.connect_ex((ip, port))
            if rc == 0:
                banner = ""
                if port in TLS_PORTS:
                    banner = "(tls)"  # plaintext probes would mislead; port state is enough
                elif port in BANNER_PORTS:
                    banner = _read_banner(s)
                elif port in HTTP_PORTS:
                    banner = _http_probe(ip, port)
                first = banner.splitlines()[0].strip() if banner else ""
                return PortResult(port, "open", SERVICE_HINTS.get(port, "unknown"), first,
                                  risk[1] if risk else "", risk[0] if risk else "")
            if rc in (10061, 111, 146):  # ECONNREFUSED variants (win/linux)
                return PortResult(port, "closed", SERVICE_HINTS.get(port, "unknown"))
            return PortResult(port, "filtered", SERVICE_HINTS.get(port, "unknown"))
    except OSError:
        return PortResult(port, "filtered", SERVICE_HINTS.get(port, "unknown"))


def udp_probe(ip: str, port: int, timeout: float, retries: int = 2) -> UdpResult:
    """One UDP probe: send a service-aware payload, classify response or ICMP error."""
    """One UDP probe: send a service-aware payload, classify response or ICMP error."""
    service = UDP_SERVICES.get(port, f"udp/{port}")
    risk = UDP_RISK.get(port)
    payload = UDP_PAYLOAD_BUILDERS.get(port, lambda: b"x")()
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.settimeout(timeout)
            attempt = 0
            while True:
                s.sendto(payload, (ip, port))
                deadline = time.time() + timeout
                while True:
                    remaining = deadline - time.time()
                    if remaining <= 0:
                        break
                    s.settimeout(remaining)
                    try:
                        data, addr = s.recvfrom(4096)
                    except ConnectionRefusedError:
                        return UdpResult(port, "closed", service)
                    except (socket.timeout, TimeoutError):
                        break
                    except OSError:
                        return UdpResult(port, "filtered", service)
                    if addr[0] != ip:
                        continue  # answer from someone else — keep waiting
                    resp = _classify_udp_response(port, data)
                    return UdpResult(port, "open", service, resp,
                                     risk[1] if risk else "", risk[0] if risk else "")
                attempt += 1
                if attempt > retries:
                    return UdpResult(port, "open|filtered", service,
                                     "", risk[1] if risk else "", risk[0] if risk else "")
    except OSError:
        return UdpResult(port, "filtered", service)


def parse_ports(spec: str) -> list[int]:
    """Parse 'top100' | '80,443' | '20-25' | mixtures like '22,80,1000-2000'."""
    spec = spec.strip().lower()
    if spec in ("top100", "top", "default", ""):
        return TOP_PORTS
    if spec in ("all", "1-65535"):
        return list(range(1, 65536))
    ports: set[int] = set()
    for part in spec.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            lo, _, hi = part.partition("-")
            try:
                a, b = int(lo), int(hi)
            except ValueError:
                raise ValueError(f"invalid port range: {part!r}") from None
            if not (0 < a <= b <= 65535):
                raise ValueError(f"port range out of bounds: {part!r}")
            if b - a > 65535:
                raise ValueError(f"range too large: {part!r}")
            ports.update(range(a, b + 1))
        else:
            try:
                p = int(part)
            except ValueError:
                raise ValueError(f"invalid port: {part!r}") from None
            if not (1 <= p <= 65535):
                raise ValueError(f"port out of range: {p}")
            ports.add(p)
    if not ports:
        raise ValueError("no ports given")
    return sorted(ports)


# ---- ICMP ping (raw socket, platform-aware) ------------------------------

def _checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\x00"
    total = sum(struct.unpack("!%dH" % (len(data) // 2), data))
    total = (total >> 16) + (total & 0xFFFF)
    total += total >> 16
    return ~total & 0xFFFF


def icmp_ping(ip: str, timeout: float = 0.8) -> bool:
    """Send one ICMP echo; requires root/Administrator. Returns True on echo reply."""
    proto = socket.IPPROTO_ICMP
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_RAW, proto)
    except PermissionError:
        raise
    try:
        s.settimeout(timeout)
        ident = os.getpid() & 0xFFFF
        header = struct.pack("!BBHHH", 8, 0, 0, ident, 1)
        payload = b"netspectre-probe"
        packet = header + payload
        packet = packet[:2] + struct.pack("!H", _checksum(packet)) + packet[4:]
        s.sendto(packet, (ip, 0))
        deadline = time.time() + timeout
        while time.time() < deadline:
            remaining = max(0.0, deadline - time.time())
            s.settimeout(remaining)
            try:
                data, addr = s.recvfrom(1024)
            except socket.timeout:
                return False
            if addr[0] != ip or len(data) < 20:
                continue
            ihl = (data[0] & 0x0F) * 4
            icmp = data[ihl:]
            if len(icmp) >= 8 and icmp[0] == 0:
                rid = struct.unpack("!H", icmp[4:6])[0]
                if rid == ident:
                    return True
        return False
    finally:
        s.close()


def arp_table() -> dict[str, tuple[str, str]]:
    """Best-effort MAC/vendor from the local ARP cache (ip/arp across platforms)."""
    out: dict[str, tuple[str, str]] = {}
    try:
        if _IS_WIN:
            cmd = ["arp", "-a"]
        elif shutil.which("ip"):
            cmd = ["ip", "neigh"]
        else:
            cmd = ["arp", "-an"]
        res = subprocess.run(cmd, capture_output=True, text=True, timeout=6)  # noqa: S603
        text = res.stdout
    except (OSError, subprocess.SubprocessError):
        return out
    mac_re = re.compile(r"([0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){5}|[0-9A-Fa-f]{2}(?:-[0-9A-Fa-f]{2}){5})")
    for line in text.splitlines():
        ipm = re.search(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b", line)
        macm = mac_re.search(line)
        if ipm and macm:
            mac = macm.group(1).replace("-", ":").upper()
            vendor = OUI.get(mac[:8], "")
            out[ipm.group(1)] = (mac, vendor)
    return out


OUI = {
    "00:50:56": "VMware", "00:0C:29": "VMware", "00:1C:14": "VMware",
    "00:1A:11": "Google", "B8:27:EB": "Raspberry Pi", "DC:A6:32": "Raspberry Pi",
    "E4:5F:01": "Raspberry Pi", "00:1A:2B": "Ayecom", "00:1B:63": "Apple",
    "AC:DE:48": "Apple", "F0:18:98": "Apple", "3C:22:FB": "Apple",
    "00:1D:7E": "Cisco", "00:26:9E": "Cisco", "F8:66:C2": "TP-Link",
    "50:C7:BF": "TP-Link", "C0:25:E9": "TP-Link", "8C:85:90": "Apple",
    "00:17:88": "Signify (Philips Hue)", "00:1E:52": "Espressif",
    "24:0A:C4": "Espressif", "5C:CF:7F": "Espressif", "BC:DD:C2": "Espressif",
    "00:E0:4C": "Realtek", "52:54:00": "QEMU/KVM", "00:16:3E": "Xen",
    "00:03:93": "Parallels", "00:1C:42": "Parallels", "0A:00:27": "VirtualBox",
    "08:00:27": "VirtualBox", "00:15:5D": "Hyper-V", "00:1D:D8": "Microsoft",
}


# ============================================================
#  Scans
# ============================================================

def scan_hosts(session: Session, target: str) -> list[HostRecord]:
    a = session.ansi
    arp = arp_table()
    try:
        net = ipaddress.ip_network(target, strict=False)
    except ValueError as exc:
        error(a, f"invalid target: {exc}")
        return []
    if "/" not in target:
        addrs = [net.network_address]
    else:
        addrs = sorted(net.hosts(), key=lambda x: int(x))
    total = len(addrs)
    if total > 4096:
        warn(a, f"target spans {total} addresses; consider a tighter range")
    print()
    info(a, f"probing {total} host(s) on {c(a, 'white', target)} (tcp-probe)...")
    info(a, f"workers={session.host_workers} timeout={session.host_timeout}s "
            f"ping-sweep={'on' if session.ping_sweep else 'off'}")
    print()

    records: dict[str, HostRecord] = {str(ip): HostRecord(ip=str(ip)) for ip in addrs}
    started = time.time()
    stop = False

    def check(ip: str) -> str | None:
        if stop:
            return None
        ports = (80, 443, 22, 445) if not session.ping_sweep else (80,)
        if session.ping_sweep:
            try:
                if icmp_ping(ip, session.host_timeout):
                    return ip
            except PermissionError:
                warn(a, "raw sockets need root/administrator; falling back to TCP probe")
                session.ping_sweep = False
            except OSError:
                pass
        return ip if any(tcp_probe(ip, p, session.host_timeout) for p in ports) else None

    with cf.ThreadPoolExecutor(max_workers=session.host_workers) as pool:
        futs = {pool.submit(check, str(ip)): str(ip) for ip in addrs}
        done_count = 0
        for fut in cf.as_completed(futs):
            done_count += 1
            ip = futs[fut]
            session.ips_scanned += 1
            hit = None
            try:
                hit = fut.result()
            except Exception:  # noqa: BLE001 - individual probe failure is non-fatal
                pass
            if hit:
                rec = records[ip]
                rec.alive = True
                rec.hostname = resolve_ptr(ip)
                if ip in arp:
                    rec.mac, rec.vendor = arp[ip]
                tag = f"{c(a, 'b_green', 'up')}"
                extras = []
                if rec.hostname:
                    extras.append(rec.hostname)
                if rec.mac:
                    extras.append(rec.mac + (f" ({rec.vendor})" if rec.vendor else ""))
                suffix = f" {a.gray}— {' · '.join(extras)}{a.reset}" if extras else ""
                print(f"  {a.green}[✓]{a.reset} {c(a, 'white', ip):<16} {tag}{suffix}")
                session.log(f"HOST-UP {ip} {rec.hostname} {rec.mac}")
            if done_count % 64 == 0:
                up = sum(1 for r in records.values() if r.alive)
                pct = done_count * 100 // total
                print(f"\r  {a.gray}… {done_count}/{total} ({pct}%) · up={up}{a.reset}",
                      end="", flush=True)
    print("\r" + " " * 60 + "\r", end="")

    elapsed = time.time() - started
    alive = sorted((r for r in records.values() if r.alive), key=lambda r: ipaddress.ip_address(r.ip))
    print()
    info(a, f"scan complete in {elapsed:.1f}s — "
            f"{c(a, 'b_green', str(len(alive)))} host(s) up of {total}")
    session.last_hosts = alive
    if not alive:
        warn(a, "no live hosts found; try 'set ping_sweep on', raise timeouts, or check the subnet")
    return alive


def print_hosts_table(ansi: Ansi, hosts: list[HostRecord]) -> None:
    if not hosts:
        warn(ansi, "no host list in memory — run 'hosts' on a target first")
        return
    print()
    print(box_title(ansi, f"active hosts ({len(hosts)})"))
    print(f"  {ansi.bold}{'IP':<17} {'STATE':<7} {'HOSTNAME':<28} {'MAC':<18} {'VENDOR'}{ansi.reset}")
    print(f"  {ansi.gray}{RULE}{ansi.reset}")
    for h in hosts:
        state = c(ansi, "b_green", "up")
        print(f"  {h.ip:<17} {state:<7} {h.hostname[:27]:<28} {h.mac:<18} {h.vendor}")
    print(f"  {ansi.gray}{RULE}{ansi.reset}\n")


def scan_ports(session: Session, target: str, port_list: list[int]) -> dict[str, list[PortResult]]:
    a = session.ansi
    try:
        ipaddress.ip_network(target, strict=False)
    except ValueError:
        error(a, f"invalid target: {target!r}")
        return {}
    hosts = session.last_hosts
    if "/" not in target:
        ips = [target]
    else:
        if not hosts:
            warn(a, "no host list in memory for this subnet — running host discovery first")
            hosts = scan_hosts(session, target)
        ips = [h.ip for h in hosts]
    if not ips:
        warn(a, "no targets to audit")
        return {}
    print()
    info(a, f"auditing {len(ips)} host(s) × {len(port_list)} port(s) "
            f"= {c(a, 'white', str(len(ips) * len(port_list)))} probes "
            f"(workers={session.port_workers}, timeout={session.port_timeout}s)")
    print()
    results: dict[str, list[PortResult]] = {}
    started = time.time()
    stop = False

    with cf.ThreadPoolExecutor(max_workers=session.port_workers) as pool:
        for ip in ips:
            if stop:
                break
            futs = {pool.submit(audit_port, ip, p, session.port_timeout): p for p in port_list}
            open_ports: list[PortResult] = []
            for fut in cf.as_completed(futs):
                if stop:
                    break
                session.ports_tested += 1
                try:
                    res = fut.result()
                except Exception:  # noqa: BLE001
                    continue
                if res.state == "open":
                    open_ports.append(res)
                    line = f"  {a.green}[✓]{a.reset} {c(a, 'white', ip):<16} " \
                           f"{c(a, 'b_cyan', str(res.port) + '/tcp'):<10} " \
                           f"{c(a, 'magenta', res.service):<14}"
                    badge = risk_badge(a, res.port)
                    if badge:
                        line += f" {badge}"
                    if res.banner:
                        line += f" {a.gray}{res.banner[:44]}{a.reset}"
                    print(line)
                    session.log(f"PORT-OPEN {ip} {res.port} {res.service} "
                                f"{('RISK=' + res.risk) if res.risk else '-'} {res.banner}")
            open_ports.sort(key=lambda r: r.port)
            results[ip] = open_ports

    elapsed = time.time() - started
    total_open = sum(len(v) for v in results.values())
    print()
    info(a, f"port audit complete in {elapsed:.1f}s — "
            f"{c(a, 'b_cyan', str(total_open))} open port(s) across {len(ips)} host(s)")

    # ---- risk summary -------------------------------------------------
    findings = sorted(
        ((ip, p) for ip, lst in results.items() for p in lst if p.risk_level),
        key=lambda t: (0 if t[1].risk_level == "high" else 1, ipaddress.ip_address(t[0]), t[1].port),
    )
    if findings:
        high = [f for f in findings if f[1].risk_level == "high"]
        med = [f for f in findings if f[1].risk_level == "medium"]
        warn(a, f"{len(findings)} risky exposure(s): "
                f"{c(a, 'b_red', str(len(high)) + ' high')}{a.reset}, "
                f"{c(a, 'yellow', str(len(med)) + ' medium')}{a.reset}")
        for ip, p in findings[:8]:
            reason = RISK_PORTS[p.port][2]
            badge = risk_badge(a, p.port)
            print(f"      {badge} {ip:<15} {p.port}/tcp {p.service:<14} {a.gray}{reason}{a.reset}")
        if len(findings) > 8:
            print(f"      {a.gray}… and {len(findings) - 8} more — see the 'ports' table or 'save'{a.reset}")
    else:
        ok(a, "no catalogued risky services exposed")
    return results


def print_ports_table(ansi: Ansi, results: dict[str, list[PortResult]]) -> None:
    if not results:
        warn(ansi, "no port results in memory — run 'ports' first")
        return
    print()
    print(box_title(ansi, "open port matrix"))
    print(f"  {ansi.bold}{'HOST':<17} {'PORT/PROTO':<12} {'SERVICE':<16} {'RISK':<16} {'BANNER'}{ansi.reset}")
    print(f"  {ansi.gray}{RULE}{ansi.reset}")
    any_open = False
    for ip, ports in sorted(results.items(), key=lambda kv: ipaddress.ip_address(kv[0])):
        if not ports:
            continue
        any_open = True
        for p in ports:
            banner = (p.banner[:38] + "…") if len(p.banner) > 39 else p.banner
            if p.risk_level == "high":
                risk = f"{ansi.bold}{ansi.b_red}[RISK:{p.risk}]{ansi.reset}"
            elif p.risk_level == "medium":
                risk = f"{ansi.yellow}[warn:{p.risk}]{ansi.reset}"
            else:
                risk = f"{ansi.gray}-{ansi.reset}"
            print(f"  {ip:<17} {str(p.port) + '/tcp':<12} {p.service:<16} {risk:<16} "
                  f"{ansi.gray}{banner}{ansi.reset}")
    if not any_open:
        warn(ansi, "no open ports in the last audit")
    print(f"  {ansi.gray}{RULE}{ansi.reset}\n")


# ============================================================
#  UDP scan
# ============================================================

def scan_udp(session: Session, target: str, port_list: list[int]) -> dict[str, list[UdpResult]]:
    """UDP audit across one IP or the live hosts of a subnet."""
    a = session.ansi
    try:
        ipaddress.ip_network(target, strict=False)
    except ValueError:
        error(a, f"invalid target: {target!r}")
        return {}
    if "/" in target:
        hosts = session.last_hosts
        if not hosts:
            warn(a, "no host list in memory for this subnet — running host discovery first")
            hosts = scan_hosts(session, target)
        ips = [h.ip for h in hosts]
    else:
        ips = [target]
    if not ips:
        warn(a, "no targets to audit")
        return {}

    print()
    info(a, f"UDP audit: {len(ips)} host(s) × {len(port_list)} port(s) = "
            f"{c(a, 'white', str(len(ips) * len(port_list)))} datagram(s) "
            f"(workers={session.udp_workers}, timeout={session.udp_timeout}s)")
    warn(a, "UDP has no handshake: silence is reported as 'open|filtered' (nmap semantics)")
    print()

    results: dict[str, list[UdpResult]] = {}
    started = time.time()
    with cf.ThreadPoolExecutor(max_workers=session.udp_workers) as pool:
        for ip in ips:
            futs = {pool.submit(udp_probe, ip, p, session.udp_timeout, 1): p for p in port_list}
            hits: list[UdpResult] = []
            for fut in cf.as_completed(futs):
                session.ports_tested += 1
                try:
                    res = fut.result()
                except Exception:  # noqa: BLE001 - single probe failure is non-fatal
                    continue
                if res.state in ("open", "open|filtered"):
                    hits.append(res)
                    color = "b_green" if res.state == "open" else "yellow"
                    line = (f"  {a.green}[✓]{a.reset} {c(a, 'white', ip):<16} "
                            f"{c(a, color, str(res.port) + '/udp'):<11} "
                            f"{c(a, 'magenta', res.service):<14}")
                    badge = risk_badge(a, res.port)
                    if badge:
                        line += f" {badge}"
                    if res.response:
                        line += f" {a.gray}{res.response[:40]}{a.reset}"
                    print(line)
                    session.log(f"UDP-{res.state.upper()} {ip} {res.port} {res.service} {res.response}")
            hits.sort(key=lambda r: (r.state != "open", r.port))
            results[ip] = hits

    elapsed = time.time() - started
    opened = sum(1 for lst in results.values() for r in lst if r.state == "open")
    maybe = sum(1 for lst in results.values() for r in lst if r.state == "open|filtered")
    print()
    info(a, f"UDP audit complete in {elapsed:.1f}s — "
            f"{c(a, 'b_green', str(opened))} confirmed open, "
            f"{c(a, 'yellow', str(maybe))} open|filtered")

    findings = sorted(
        ((ip, r) for ip, lst in results.items() for r in lst if r.risk_level),
        key=lambda t: (0 if t[1].risk_level == "high" else 1, ipaddress.ip_address(t[0]), t[1].port),
    )
    if findings:
        high = sum(1 for _, r in findings if r.risk_level == "high")
        warn(a, f"{len(findings)} risky UDP exposure(s): "
                f"{c(a, 'b_red', str(high) + ' high')}{a.reset}, "
                f"{c(a, 'yellow', str(len(findings) - high) + ' medium')}{a.reset}")
        for ip, r in findings[:8]:
            reason = UDP_RISK[r.port][2]
            print(f"      {risk_badge(a, r.port)} {ip:<15} {r.port}/udp {r.service:<14} "
                  f"{a.gray}{reason}{a.reset}")
        if len(findings) > 8:
            print(f"      {a.gray}… and {len(findings) - 8} more — see the 'udp' table or 'save'{a.reset}")
    else:
        ok(a, "no catalogued risky UDP services exposed")
    return results


def print_udp_table(ansi: Ansi, results: dict[str, list[UdpResult]]) -> None:
    if not results:
        warn(ansi, "no UDP results in memory — run 'udp' first")
        return
    print()
    print(box_title(ansi, "udp findings"))
    print(f"  {ansi.bold}{'HOST':<17} {'PORT/PROTO':<12} {'SERVICE':<15} {'STATE':<15} {'RISK':<16} {'RESPONSE'}{ansi.reset}")
    print(f"  {ansi.gray}{RULE}{ansi.reset}")
    any_row = False
    for ip, ports in sorted(results.items(), key=lambda kv: ipaddress.ip_address(kv[0])):
        if not ports:
            continue
        any_row = True
        for r in ports:
            if r.risk_level == "high":
                risk = f"{ansi.bold}{ansi.b_red}[RISK:{r.risk}]{ansi.reset}"
            elif r.risk_level == "medium":
                risk = f"{ansi.yellow}[warn:{r.risk}]{ansi.reset}"
            else:
                risk = f"{ansi.gray}-{ansi.reset}"
            state = (c(ansi, "b_green", r.state) if r.state == "open"
                     else c(ansi, "yellow", r.state) if r.state == "open|filtered"
                     else r.state)
            resp = (r.response[:24] + "…") if len(r.response) > 25 else r.response
            print(f"  {ip:<17} {str(r.port) + '/udp':<12} {r.service:<15} {state:<15} {risk:<16} "
                  f"{ansi.gray}{resp}{ansi.reset}")
    if not any_row:
        warn(ansi, "no responsive UDP ports in the last audit")
    print(f"  {ansi.gray}{RULE}{ansi.reset}\n")


# ============================================================
#  Commands
# ============================================================

@dataclass
class Command:
    name: str
    help_text: str
    usage: str
    run: "callable[[Session, list[str]], None]"
    aliases: tuple[str, ...] = ()


def validate_target(ansi: Ansi, target: str):
    """Return an ip_network for the target or None after printing an error."""
    try:
        return ipaddress.ip_network(target, strict=False)
    except ValueError:
        error(ansi, f"invalid target: {target!r} — expected an IP or CIDR like 192.168.1.0/24")
        return None


def looks_like_port_spec(text: str) -> bool:
    t = text.strip().lower()
    if t in ("top100", "top", "default", "all", "1-65535"):
        return True
    return bool(re.fullmatch(r"\d{1,5}(?:-\d{1,5})?(?:,\d{1,5}(?:-\d{1,5})?)*", t))


def cmd_help(session: Session, args: list[str]) -> None:
    a = session.ansi
    if args:
        cmd = COMMANDS.get(args[0])
        if not cmd:
            error(a, f"unknown command: {args[0]!r} (try 'help' alone)")
            return
        print()
        info(a, f"{cmd.name} — {cmd.help_text}")
        print(f"      {a.gray}usage:{a.reset} {cmd.usage}")
        if cmd.aliases:
            print(f"      {a.gray}alias:{a.reset}  {', '.join(cmd.aliases)}")
        print()
        return
    print()
    print(box_title(a, "core commands"))
    groups: dict[str, list[Command]] = {"core": [], "discovery": [], "config": [], "output": []}
    seen: set[int] = set()
    for cmd in COMMANDS.values():          # aliases share the same object — dedupe
        if id(cmd) in seen:
            continue
        seen.add(id(cmd))
        groups[cmd.group].append(cmd)
    group_titles = {
        "core": "core", "discovery": "discovery & audit", "config": "configuration",
        "output": "output & history",
    }
    for key, title in group_titles.items():
        if not groups[key]:
            continue
        print(f"  {a.bold}{a.b_blue}{group_titles[key].upper()}{a.reset}")
        for cmd in groups[key]:
            aliases = f" {a.gray}({', '.join(cmd.aliases)}){a.reset}" if cmd.aliases else ""
            print(f"    {c(a, 'b_cyan', cmd.name):<12} {a.gray}{cmd.help_text}{a.reset}{aliases}")
        print()
    print(f"  {a.gray}type 'help <command>' for usage details{a.reset}\n")


# give Command a group field after all defs to keep dataclass simple
def _group(name: str):
    def deco(fn):
        fn.group = name
        return fn
    return deco


def apply_set(session: Session, key: str, value: str) -> str:
    """Validate and apply one session option. Returns a message; raises ValueError
    with a user-facing message on invalid input. Shared by 'set' and profiles."""
    key = key.lower()
    if key == "target":
        try:
            ipaddress.ip_network(value, strict=False)
        except ValueError:
            raise ValueError(f"invalid target: {value!r} — expected an IP or CIDR like 192.168.1.0/24") from None
        session.target = value
        return f"target => {value}"
    if key == "port_range":
        try:
            parse_ports(value)
        except ValueError as exc:
            raise ValueError(str(exc)) from None
        session.port_range = value
        return f"port_range => {value}"
    if key in ("host_timeout", "port_timeout", "udp_timeout"):
        limits = {"host_timeout": (0.05, 10), "port_timeout": (0.05, 10), "udp_timeout": (0.5, 15)}
        lo, hi = limits[key]
        try:
            v = float(value.rstrip("s"))
            if not (lo <= v <= hi):
                raise ValueError
        except ValueError:
            raise ValueError(f"{key} must be a number between {lo} and {hi} (seconds)") from None
        setattr(session, key, v)
        return f"{key} => {v}s"
    if key in ("workers", "port_workers", "udp_workers"):
        limits = {"workers": (1, 1024), "port_workers": (1, 2048), "udp_workers": (1, 1024)}
        lo, hi = limits[key]
        try:
            v = int(value)
            if not (lo <= v <= hi):
                raise ValueError
        except ValueError:
            raise ValueError(f"{key} must be an integer between {lo} and {hi}") from None
        attr = "host_workers" if key == "workers" else key
        setattr(session, attr, v)
        return f"{key} => {v}"
    if key == "udp_range":
        session.udp_range = value
        return f"udp_range => {value}"
    if key in ("max_high", "max_medium"):
        v = value.strip().lower()
        if v in ("off", "none", ""):
            setattr(session, key, None)
            return f"{key} => off"
        try:
            n = int(v)
            if n < 0:
                raise ValueError
        except ValueError:
            raise ValueError(f"{key} must be a non-negative integer or 'off'") from None
        setattr(session, key, n)
        return f"{key} => {n}"
    if key == "ping_sweep":
        if value.lower() in ("on", "true", "1", "yes"):
            session.ping_sweep = True
            return "ping_sweep => on (needs root/Administrator for raw ICMP)"
        if value.lower() in ("off", "false", "0", "no"):
            session.ping_sweep = False
            return "ping_sweep => off"
        raise ValueError("ping_sweep accepts on/off")
    raise ValueError(f"unknown option: {key!r} — run 'set' to list options")


@_group("config")
def cmd_set(session: Session, args: list[str]) -> None:
    a = session.ansi
    if not args:
        rows = [
            ("target", session.target or "(unset)", "CIDR / IP to audit, e.g. 192.168.1.0/24"),
            ("port_range", session.port_range, "'top100', 'all', '22,80,443' or '1000-2000'"),
            ("host_timeout", f"{session.host_timeout}s", "per-probe timeout for host discovery"),
            ("port_timeout", f"{session.port_timeout}s", "per-probe timeout for the port audit"),
            ("workers", str(session.host_workers), "threads for host discovery"),
            ("port_workers", str(session.port_workers), "threads for the port audit"),
            ("udp_timeout", f"{session.udp_timeout}s", "per-probe timeout for the UDP audit"),
            ("udp_workers", str(session.udp_workers), "threads for the UDP audit"),
            ("udp_range", getattr(session, "udp_range", "top"), "'top' (24 common), 'all' or a spec like '53,123,161'"),
            ("max_high", "off" if session.max_high is None else str(session.max_high), "CI gate: fail (--plain exit 1) if high findings exceed this"),
            ("max_medium", "off" if session.max_medium is None else str(session.max_medium), "CI gate: fail if medium findings exceed this"),
            ("ping_sweep", "on" if session.ping_sweep else "off", "ICMP sweep before TCP probe (root/admin)"),
        ]
        print()
        print(box_title(a, "session options"))
        print(f"  {a.bold}{'OPTION':<14} {'VALUE':<18} {'DESCRIPTION'}{a.reset}")
        print(f"  {a.gray}{RULE}{a.reset}")
        for k, v, d in rows:
            print(f"  {c(a, 'b_cyan', k):<14} {c(a, 'b_yellow', v):<18} {a.gray}{d}{a.reset}")
        print(f"  {a.gray}{RULE}{a.reset}")
        print(f"  {a.gray}usage: set <option> <value>{a.reset}\n")
        return
    if len(args) < 2:
        error(a, "usage: set <option> <value>")
        return
    try:
        msg = apply_set(session, args[0], args[1])
    except ValueError as exc:
        error(a, str(exc))
        return
    ok(a, msg)


@_group("discovery")
def cmd_hosts(session: Session, args: list[str]) -> None:
    a = session.ansi
    target = args[0] if args else session.target
    if not target:
        error(a, "no target set — usage: hosts <cidr|ip>  (or 'set target <cidr>' first)")
        return
    if validate_target(a, target) is None:
        return
    scan_hosts(session, target)
    print_hosts_table(a, session.last_hosts)


@_group("discovery")
def cmd_ports(session: Session, args: list[str]) -> None:
    a = session.ansi
    target, range_arg = "", ""
    for arg in args:
        if not target and not looks_like_port_spec(arg):
            target = arg
        elif not range_arg:
            range_arg = arg
    if not target:
        target = session.target
        if not target:
            error(a, "no target set — usage: ports <cidr|ip> [range]  (or 'set target <cidr>' first)")
            return
    if range_arg:
        session.port_range = range_arg
    if validate_target(a, target) is None:
        return
    try:
        port_list = parse_ports(session.port_range)
    except ValueError as exc:
        error(a, str(exc))
        return
    if session.target and target != session.target:
        session.last_hosts = []
    if "/" in target and target != session.target:
        session.target = target
    results = scan_ports(session, target, port_list)
    session.last_results = results
    print_ports_table(a, results)


def evaluate_risk_gate(session: Session) -> list[str]:
    """Check the severity thresholds; returns a list of breach descriptions."""
    if session.max_high is None and session.max_medium is None:
        return []
    findings = collect_findings(session)
    high = sum(1 for f in findings if f["level"] == "high")
    med = len(findings) - high
    breaches: list[str] = []
    if session.max_high is not None and high > session.max_high:
        breaches.append(f"high findings: {high} > limit {session.max_high}")
    if session.max_medium is not None and med > session.max_medium:
        breaches.append(f"medium findings: {med} > limit {session.max_medium}")
    return breaches


def collect_findings(session: Session) -> list[dict]:
    """Risk findings from the last TCP + UDP audits, sorted: high → medium, then IP/port."""
    rows: list[dict] = []
    for ip, ports in getattr(session, "last_results", {}).items():
        for p in ports:
            if p.risk_level:
                rows.append({"ip": ip, "port": p.port, "proto": "tcp",
                             "service": p.service, "level": p.risk_level, "tag": p.risk,
                             "detail": p.banner,
                             "reason": RISK_PORTS[p.port][2] if p.port in RISK_PORTS else "",
                             "fix": REMEDIATIONS.get(p.risk, "")})
    for ip, lst in getattr(session, "last_udp", {}).items():
        for r in lst:
            if r.risk_level:
                rows.append({"ip": ip, "port": r.port, "proto": "udp",
                             "service": r.service, "level": r.risk_level, "tag": r.risk,
                             "detail": r.response,
                             "reason": UDP_RISK[r.port][2] if r.port in UDP_RISK else "",
                             "fix": REMEDIATIONS.get(r.risk, "")})
    rows.sort(key=lambda x: (0 if x["level"] == "high" else 1,
                             ipaddress.ip_address(x["ip"]), x["port"]))
    return rows


RISK_FILTERS = ("all", "high", "medium")


def write_risks_markdown(session: Session, path: str, flt: str = "all") -> int:
    """Ticket-ready Markdown report; returns the number of findings written."""
    all_findings = collect_findings(session)
    high_total = sum(1 for f in all_findings if f["level"] == "high")
    findings = all_findings if flt == "all" else [f for f in all_findings if f["level"] == flt]
    lines: list[str] = [
        "# NetSpectre — Informe de riesgos",
        "",
        f"- **Generado:** {time.strftime('%Y-%m-%d %H:%M:%S')}",
        f"- **Objetivo:** {session.target or '(sin objetivo)'}",
        f"- **Filtro:** {flt}",
        f"- **Hallazgos en memoria:** {len(all_findings)} ({high_total} high, {high_total and len(all_findings) - high_total} medium)",
        f"- **Incluidos en este informe:** {len(findings)}",
        "",
    ]
    if findings:
        lines += [
            "| Sev | Host | Puerto | Servicio | Etiqueta |",
            "|-----|------|--------|----------|----------|",
        ]
        for f in findings:
            lines.append(f"| {f['level'].upper()} | {f['ip']} | {f['port']}/{f['proto']} | "
                         f"{f['service']} | {f['tag']} |")
        lines.append("")
        for f in findings:
            lines.append(f"## {f['level'].upper()} · {f['tag']} · {f['ip']}:{f['port']}/{f['proto']}")
            lines.append("")
            if f["reason"]:
                lines.append(f"- **Motivo:** {f['reason']}")
            if f["fix"]:
                lines.append(f"- **Remediación:** {f['fix']}")
            if f["detail"]:
                lines.append(f"- **Evidencia:** `{f['detail']}`")
            lines.append("- [ ] Remediado")
            lines.append("")
    try:
        with open(path, "w", encoding="utf-8") as fh:
            fh.write("\n".join(lines))
    except OSError as exc:
        raise ValueError(f"could not write {path!r}: {exc}") from None
    return len(findings)


def write_risks_csv(session: Session, path: str, flt: str = "all") -> int:
    """Spreadsheet/ticketing CSV; returns the number of data rows written."""
    all_findings = collect_findings(session)
    findings = all_findings if flt == "all" else [f for f in all_findings if f["level"] == flt]
    try:
        with open(path, "w", newline="", encoding="utf-8") as fh:
            w = csv.writer(fh)
            w.writerow(["severity", "ip", "port", "proto", "service", "tag",
                        "reason", "fix", "evidence"])
            for f in findings:
                w.writerow([f["level"].upper(), f["ip"], f["port"], f["proto"],
                            f["service"], f["tag"], f["reason"], f["fix"], f["detail"]])
    except OSError as exc:
        raise ValueError(f"could not write {path!r}: {exc}") from None
    return len(findings)


@_group("discovery")
def cmd_risks(session: Session, args: list[str]) -> None:
    """risks [all|high|medium] or risks md|csv [all|high|medium] [file] — report & export."""
    a = session.ansi

    # ---- export mode: md | csv (never collides with filter names) ----------
    if args and args[0].lower() in ("md", "csv"):
        fmt = args[0].lower()
        flt, fname = "all", None
        for arg in args[1:]:
            if arg.lower() in RISK_FILTERS:
                flt = arg.lower()
            else:
                fname = arg
        if not getattr(session, "last_results", {}) and not getattr(session, "last_udp", {}):
            warn(a, "no audit in memory — run 'ports' or 'udp' first")
            return
        ext = "md" if fmt == "md" else "csv"
        path = fname or f"netspectre-risks-{time.strftime('%Y%m%d-%H%M%S')}.{ext}"
        try:
            n = (write_risks_markdown if fmt == "md" else write_risks_csv)(session, path, flt)
        except ValueError as exc:
            error(a, str(exc))
            return
        ok(a, f"{n} finding(s) exported to {c(a, 'b_yellow', path)} "
              f"({fmt.upper()}, filtro={flt})")
        if fmt == "md":
            info(a, "includes per-finding checkboxes ready for ticket workflows")
        return

    # ---- interactive table mode -------------------------------------------
    flt = args[0].lower() if args else "all"
    if flt not in RISK_FILTERS:
        error(a, f"unknown filter or format {flt!r} — use all, high, medium, md or csv")
        return
    has_tcp = bool(getattr(session, "last_results", {}))
    has_udp = bool(getattr(session, "last_udp", {}))
    if not has_tcp and not has_udp:
        warn(a, "no audit in memory — run 'ports' or 'udp' first")
        return

    findings = collect_findings(session)
    high_n = sum(1 for f in findings if f["level"] == "high")
    med_n = len(findings) - high_n
    if flt != "all":
        findings = [f for f in findings if f["level"] == flt]

    print()
    print(box_title(a, f"risk report — {flt} ({len(findings)} finding(s))"))
    info(a, f"last audit: {c(a, 'b_red', str(high_n) + ' high')}{a.reset}, "
            f"{c(a, 'yellow', str(med_n) + ' medium')}{a.reset} across "
            f"{len(set(f['ip'] for f in findings))} host(s)")
    if not findings:
        ok(a, f"no {flt} risk findings — your exposure looks clean")
        print()
        return

    print(f"  {a.bold}{'SEV':<8} {'HOST':<17} {'PORT':<12} {'SERVICE':<15} REASON{a.reset}")
    print(f"  {a.gray}{RULE}{a.reset}")
    for f in findings:
        if f["level"] == "high":
            sev = f"{a.bold}{a.b_red}HIGH{a.reset}"
        else:
            sev = f"{a.yellow}MED{a.reset}"
        port = f"{f['port']}/{f['proto']}"
        reason = f["reason"] or f["detail"]
        print(f"  {sev:<8} {f['ip']:<17} {port:<12} {f['service']:<15} {a.gray}{reason}{a.reset}")
        if f["fix"]:
            print(f"  {'':<8} {a.cyan}↳ fix:{a.reset} {a.gray}{f['fix']}{a.reset}")
    print(f"  {a.gray}{RULE}{a.reset}")

    # most exposed host
    per_host: dict[str, int] = {}
    for f in findings:
        per_host[f["ip"]] = per_host.get(f["ip"], 0) + (2 if f["level"] == "high" else 1)
    worst = max(per_host.items(), key=lambda kv: kv[1])
    warn(a, f"most exposed host: {c(a, 'b_yellow', worst[0])} "
            f"(risk score {worst[1]}) — prioritize remediation there")
    print()


@_group("discovery")
def cmd_udp(session: Session, args: list[str]) -> None:
    """udp [cidr|ip] [top|all|spec] — audit common UDP service ports."""
    a = session.ansi
    target, range_arg = "", ""
    for arg in args:
        if not target and not looks_like_port_spec(arg):
            target = arg
        elif not range_arg:
            range_arg = arg
    if not target:
        target = session.target
        if not target:
            error(a, "no target set — usage: udp <cidr|ip> [range]  (or 'set target <cidr>' first)")
            return
    if range_arg:
        session.udp_range = range_arg
    if validate_target(a, target) is None:
        return
    spec = getattr(session, "udp_range", "top")
    port_list = TOP_UDP_PORTS if spec in ("top", "top100", "", "default") else None
    if port_list is None:
        if spec in ("all", "1-65535"):
            port_list = list(range(1, 65536))
            warn(a, "a full UDP sweep is very slow (mostly per-port timeouts)")
        else:
            try:
                port_list = parse_ports(spec)
            except ValueError as exc:
                error(a, str(exc))
                return
    if session.target and target != session.target:
        session.last_hosts = []
    if "/" in target and target != session.target:
        session.target = target
    results = scan_udp(session, target, port_list)
    session.last_udp = results
    print_udp_table(a, results)


# ============================================================
#  Session profiles (~/.netspectre/profiles/*.json)
# ============================================================

PROFILE_KEYS = [
    "target", "port_range", "host_timeout", "port_timeout", "workers",
    "port_workers", "udp_timeout", "udp_workers", "udp_range", "ping_sweep",
    "max_high", "max_medium",
]


def profile_dir() -> str:
    d = os.path.join(os.path.expanduser("~"), ".netspectre", "profiles")
    os.makedirs(d, exist_ok=True)
    return d


def profile_path(name: str) -> str:
    return os.path.join(profile_dir(), f"{name}.json")


def valid_profile_name(name: str) -> bool:
    return bool(re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}", name))


def list_profiles() -> list[dict]:
    """Saved profiles as [{name, saved, values}] sorted by name."""
    out = []
    try:
        files = sorted(os.listdir(profile_dir()))
    except OSError:
        return out
    for fn in files:
        if not fn.endswith(".json"):
            continue
        path = os.path.join(profile_dir(), fn)
        try:
            with open(path, encoding="utf-8") as fh:
                data = json.load(fh)
            out.append({"name": fn[:-5], "saved": data.get("saved", ""),
                        "values": data.get("values", {}), "note": data.get("note", "")})
        except (OSError, ValueError):
            continue  # unreadable profile — skip rather than break the listing
    return out


def load_profile(session: Session, name: str) -> int:
    """Apply a saved profile to the session; returns applied key count."""
    path = profile_path(name)
    try:
        with open(path, encoding="utf-8") as fh:
            data = json.load(fh)
    except FileNotFoundError:
        raise ValueError(f"profile {name!r} not found — run 'profile list'") from None
    except (OSError, ValueError) as exc:
        raise ValueError(f"cannot read profile {name!r}: {exc}") from None
    values = data.get("values", {})
    applied = 0
    errors: list[str] = []
    for key in PROFILE_KEYS:
        if key not in values:
            continue
        raw = values[key]
        if key == "ping_sweep":
            raw = "on" if raw else "off"
        if raw is None:
            raw = "off"          # e.g. max_high stored as null (gate disabled)
        if not isinstance(raw, str):
            raw = str(raw)
        try:
            apply_set(session, key, str(raw))
            applied += 1
        except ValueError as exc:
            errors.append(f"{key}: {exc}")
    if errors:  # partial loads are reported honestly
        warn(session.ansi, f"{len(errors)} value(s) in profile {name!r} failed validation: "
                           f"{'; '.join(errors)}")
    return applied


def save_profile(session: Session, name: str, note: str = "") -> None:
    values = {
        "target": session.target,
        "port_range": session.port_range,
        "host_timeout": session.host_timeout,
        "port_timeout": session.port_timeout,
        "workers": session.host_workers,
        "port_workers": session.port_workers,
        "udp_timeout": session.udp_timeout,
        "udp_workers": session.udp_workers,
        "udp_range": getattr(session, "udp_range", "top"),
        "ping_sweep": session.ping_sweep,
        "max_high": session.max_high,
        "max_medium": session.max_medium,
    }
    doc = {"tool": "NetSpectre", "version": __version__, "saved": time.strftime("%Y-%m-%d %H:%M:%S"),
           "note": note, "values": values}
    path = profile_path(name)
    try:
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(doc, fh, indent=2, ensure_ascii=False)
    except OSError as exc:
        raise ValueError(f"could not write profile {name!r}: {exc}") from None


def delete_profile(name: str) -> None:
    path = profile_path(name)
    if not os.path.isfile(path):
        raise ValueError(f"profile {name!r} not found — run 'profile list'")
    try:
        os.remove(path)
    except OSError as exc:
        raise ValueError(f"could not delete profile {name!r}: {exc}") from None


def print_profile_row(ansi: Ansi, name: str, saved: str, values: dict) -> None:
    tgt = values.get("target", "(unset)") or "(unset)"
    extras = []
    if values.get("port_range", "top100") != "top100":
        extras.append(f"ports={values['port_range']}")
    if values.get("udp_range", "top") not in ("top", None):
        extras.append(f"udp={values['udp_range']}")
    if values.get("ping_sweep"):
        extras.append("icmp")
    detail = " ".join(extras)
    print(f"  {c(ansi, 'b_cyan', name):<20} {ansi.gray}{saved:<20}{ansi.reset} "
          f"{tgt:<20} {ansi.gray}{detail}{ansi.reset}")


@_group("config")
def cmd_profile(session: Session, args: list[str]) -> None:
    """profile save|load|list|show|delete [name] [note] — persist session config."""
    a = session.ansi
    sub = args[0].lower() if args else "list"
    name = args[1] if len(args) > 1 else ""
    note = " ".join(args[2:]) if len(args) > 2 else ""

    if sub in ("list", "ls", ""):
        profiles = list_profiles()
        print()
        print(box_title(a, f"saved profiles ({len(profiles)})"))
        if not profiles:
            warn(a, "no profiles yet — create one with: profile save home")
        else:
            print(f"  {a.bold}{'NAME':<20} {'SAVED':<20} {'TARGET':<20} EXTRAS{a.reset}")
            print(f"  {a.gray}{RULE}{a.reset}")
            for p in profiles:
                print_profile_row(a, p["name"], p["saved"], p["values"])
            print(f"  {a.gray}{RULE}{a.reset}")
        print(f"  {a.gray}usage: profile save|load|show|delete <name> [note]{a.reset}\n")
        return

    if not name:
        error(a, f"usage: profile {sub} <name>" + (" [note]" if sub == "save" else ""))
        return
    if not valid_profile_name(name):
        error(a, "profile name must be 1-64 chars: letters, digits, '.', '_', '-'")
        return

    if sub in ("save", "store", "create"):
        try:
            save_profile(session, name, note)
        except ValueError as exc:
            error(a, str(exc))
            return
        ok(a, f"profile {c(a, 'b_yellow', name)} saved "
              f"(target={session.target or '(unset)'}) → {profile_path(name)}")
    elif sub in ("load", "restore", "use"):
        try:
            n = load_profile(session, name)
        except ValueError as exc:
            error(a, str(exc))
            return
        session.profile_name = name
        ok(a, f"profile {c(a, 'b_yellow', name)} loaded — {n} option(s) applied")
        info(a, f"target => {session.target or '(unset)'}")
    elif sub in ("show", "view", "cat"):
        profiles = {p["name"]: p for p in list_profiles()}
        if name not in profiles:
            error(a, f"profile {name!r} not found — run 'profile list'")
            return
        p = profiles[name]
        print()
        print(box_title(a, f"profile: {name}"))
        print(f"  {a.gray}saved:{a.reset} {p['saved']}    {a.gray}note:{a.reset} {p.get('note', '') or '-'}")
        for key in PROFILE_KEYS:
            if key in p["values"]:
                v = p["values"][key]
                v = "on" if v is True else "off" if v is False else str(v)
                print(f"  {c(a, 'b_cyan', key):<14} {c(a, 'b_yellow', v)}")
        print()
    elif sub in ("delete", "del", "rm", "remove"):
        try:
            delete_profile(name)
        except ValueError as exc:
            error(a, str(exc))
            return
        ok(a, f"profile {c(a, 'b_yellow', name)} deleted")
    else:
        error(a, f"unknown subcommand {sub!r} — use save, load, list, show or delete")


@_group("discovery")
def cmd_osint(session: Session, args: list[str]) -> None:
    """Local intelligence: public IP + interface info + ARP cache."""
    a = session.ansi
    print()
    print(box_title(a, "local intelligence"))
    info(a, f"host: {c(a, 'white', socket.gethostname())} · local IP: "
            f"{c(a, 'white', local_ip())}")
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("1.1.1.1", 53))
            info(a, f"detected egress route via {c(a, 'white', s.getsockname()[0])}")
    except OSError:
        pass
    info(a, f"platform: {c(a, 'gray', platform.platform())} · python {platform.python_version()}")
    arp = arp_table()
    if arp:
        info(a, f"ARP cache: {len(arp)} entr{'y' if len(arp) == 1 else 'ies'}")
        for ip, (mac, vendor) in sorted(arp.items(), key=lambda kv: ipaddress.ip_address(kv[0]))[:12]:
            v = f" {a.gray}({vendor}){a.reset}" if vendor else ""
            print(f"      {a.gray}·{a.reset} {ip:<16} {c(a, 'gray', mac)}{v}")
    else:
        warn(a, "ARP cache empty or unreadable on this platform")
    print()


@_group("core")
def cmd_status(session: Session, args: list[str]) -> None:
    a = session.ansi
    hosts = len(session.last_hosts)
    last_results = getattr(session, "last_results", {})
    open_ports = sum(len(p) for p in last_results.values())
    high_n = sum(1 for lst in last_results.values() for p in lst if p.risk_level == "high")
    med_n = sum(1 for lst in last_results.values() for p in lst if p.risk_level == "medium")
    print()
    print(box_title(a, "session status"))
    rows = [
        ("uptime", session.uptime()),
        ("target", session.target or "(unset)"),
        ("port_range", session.port_range),
        ("timeouts", f"host={session.host_timeout}s port={session.port_timeout}s udp={session.udp_timeout}s"),            ("workers", f"hosts={session.host_workers} ports={session.port_workers}"),
            ("ping_sweep", "on" if session.ping_sweep else "off"),
        ("last scan", f"{hosts} live host(s) in memory"),
        ("last audit", f"{open_ports} open port(s) in memory"),
        ("profile", session.profile_name or "(none)"),
            ("last udp", f"{sum(len(v) for v in session.last_udp.values())} responsive UDP port(s) in memory"),
        ("risk found", f"{high_n} high · {med_n} medium"),
        ("risk gate", f"high {'off' if session.max_high is None else chr(8804) + ' ' + str(session.max_high)} · "
                      f"medium {'off' if session.max_medium is None else chr(8804) + ' ' + str(session.max_medium)}"),
        ("probes sent", f"{session.ips_scanned} host-probe(s) · {session.ports_tested} port-probe(s)"),
        ("logging", session.log_path or "off"),
        ("colors", "on" if session.color else "off"),
    ]
    width = max(len(k) for k, _ in rows)
    for k, v in rows:
        print(f"  {c(a, 'b_cyan', k.ljust(width))} {a.gray}::{a.reset} {v}")
    print()


@_group("output")
def cmd_history(session: Session, args: list[str]) -> None:
    a = session.ansi
    if not session.history:
        info(a, "history is empty")
        return
    print()
    print(box_title(a, "command history"))
    for i, line in enumerate(session.history[-30:], start=max(1, len(session.history) - 29)):
        print(f"  {a.gray}{i:>4}{a.reset}  {line}")
    print()


@_group("output")
def build_report(session: Session) -> dict:
    """Assemble the full JSON report document (shared by 'save' and --json)."""
    results = getattr(session, "last_results", {})
    udp_results = getattr(session, "last_udp", {})
    findings = [
        {
            "ip": ip, "port": p.port, "service": p.service, "proto": "tcp",
            "level": p.risk_level, "tag": p.risk,
            "reason": RISK_PORTS[p.port][2] if p.port in RISK_PORTS else "",
            "fix": REMEDIATIONS.get(p.risk, ""),
        }
        for ip, ports in results.items() for p in ports if p.risk_level
    ] + [
        {
            "ip": ip, "port": r.port, "service": r.service, "proto": "udp",
            "level": r.risk_level, "tag": r.risk,
            "reason": UDP_RISK[r.port][2] if r.port in UDP_RISK else "",
            "fix": REMEDIATIONS.get(r.risk, ""),
        }
        for ip, lst in udp_results.items() for r in lst if r.risk_level
    ]
    return {
        "tool": "NetSpectre",
        "version": __version__,
        "generated": time.strftime("%Y-%m-%d %H:%M:%S"),
        "target": session.target,
        "hosts": [h.to_dict() for h in session.last_hosts],
        "open_ports": {ip: [p.__dict__ for p in ports] for ip, ports in results.items()},
        "udp": {ip: [r.__dict__ for r in lst] for ip, lst in udp_results.items()},
        "risk_summary": {
            "high": sum(1 for f in findings if f["level"] == "high"),
            "medium": sum(1 for f in findings if f["level"] == "medium"),
            "findings": findings,
        },
    }


def cmd_save(session: Session, args: list[str]) -> None:
    a = session.ansi
    path = args[0] if args else f"netspectre-report-{time.strftime('%Y%m%d-%H%M%S')}.json"
    hosts = session.last_hosts
    results = getattr(session, "last_results", {})
    udp_results = getattr(session, "last_udp", {})
    if not hosts and not results and not udp_results:
        warn(a, "nothing to save yet — run 'hosts', 'ports' or 'udp' first")
        return
    report = build_report(session)
    try:
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(report, fh, indent=2, ensure_ascii=False)
    except OSError as exc:
        error(a, f"could not write {path!r}: {exc}")
        return
    high = report["risk_summary"]["high"]
    med = report["risk_summary"]["medium"]
    findings = report["risk_summary"]["findings"]
    udp_rows = sum(len(v) for v in udp_results.values())
    ok(a, f"report saved to {c(a, 'b_yellow', path)} "
          f"({len(hosts)} host(s), {sum(len(v) for v in results.values())} tcp + {udp_rows} udp result(s))")
    if findings:
        warn(a, f"includes risk summary: {c(a, 'b_red', str(high) + ' high')}{a.reset}, "
                f"{c(a, 'yellow', str(med) + ' medium')}{a.reset} finding(s)")


@_group("output")
def cmd_clear(session: Session, args: list[str]) -> None:
    sys.stdout.write("\033[2J\033[H" if session.color else "\n" * 50)
    sys.stdout.flush()


@_group("core")
def cmd_exit(session: Session, args: list[str]) -> None:
    a = session.ansi
    print(f"\n  {a.magenta}[*]{a.reset} shutting down NetSpectre — happy hunting. "
          f"{a.gray}o/\n{a.reset}")
    session.quit = True


COMMANDS: dict[str, Command] = {}


def _register() -> None:
    def add(name, helptext, usage, fn, aliases=(), group="core"):
        cmd = Command(name, helptext, usage, fn, aliases)
        cmd.group = group  # type: ignore[attr-defined]
        COMMANDS[name] = cmd
        for al in aliases:
            COMMANDS[al] = cmd

    add("help", "show this help or details for a command", "help [command]", cmd_help, ("?", "h"))
    add("hosts", "discover active hosts on a subnet or single IP", "hosts [cidr|ip]", cmd_hosts, ("scan", "sweep"), "discovery")
    add("ports", "audit open TCP ports (optional range)", "ports [cidr|ip] [top100|all|spec]", cmd_ports, ("portscan", "audit"), "discovery")
    add("udp", "audit common UDP service ports (optional range)", "udp [cidr|ip] [top|all|spec]", cmd_udp, ("udpscan",), "discovery")
    add("risks", "risk findings table + md/csv export for ticketing", "risks [all|high|medium] | md|csv [filter] [file]", cmd_risks, ("risk", "vulns"), "discovery")
    add("osint", "local intel: host, egress route and ARP cache", "osint", cmd_osint, ("arp",), "discovery")
    add("set", "view or change session options", "set [option] [value]", cmd_set, ("config",), "config")
    add("profile", "save/load session configs between runs", "profile save|load|list|show|delete [name]", cmd_profile, ("profiles", "pf"), "config")
    add("status", "session summary and scan statistics", "status", cmd_status, ("st", "info"), "core")
    add("history", "show recent commands", "history", cmd_history, ("hist",), "output")
    add("save", "export last results to a JSON report", "save [file.json]", cmd_save, ("report", "export"), "output")
    add("clear", "clear the terminal screen", "clear", cmd_clear, ("cls",), "output")
    add("exit", "leave NetSpectre", "exit", cmd_exit, ("quit", "q"), "core")


_register()


# ============================================================
#  REPL loop
# ============================================================

def tokenize(line: str) -> list[str]:
    try:
        import shlex
        return shlex.split(line)
    except ValueError:
        return line.split()


def handler_sigint(signum: int, _frame: object) -> None:
    raise KeyboardInterrupt


def repl(session: Session) -> None:
    a = session.ansi
    signal.signal(signal.SIGINT, handler_sigint)
    history_file = os.path.join(os.path.expanduser("~"), ".netspectre_history")

    try:  # optional GNU history niceties when readline exists
        import readline  # noqa: F401
        try:
            readline.read_history_file(history_file)  # type: ignore[union-attr]
        except OSError:
            pass
    except ImportError:
        readline = None  # type: ignore[assignment]

    print(c(a, "gray", "  type 'help' for the command list, 'status' for session state.\n"))

    while not session.quit:
        try:
            line = input(session.prompt()).strip()
        except (EOFError, KeyboardInterrupt):
            print()
            cmd_exit(session, [])
            break

        if not line:
            continue
        session.history.append(line)
        if readline:
            try:
                readline.append_history_file(1, history_file)  # type: ignore[union-attr]
            except (OSError, AttributeError, FileNotFoundError):
                pass

        parts = tokenize(line)
        name, args = parts[0].lower(), parts[1:]
        cmd = COMMANDS.get(name)
        if not cmd:
            error(a, f"unknown command {name!r} — type {c(a, 'b_cyan', 'help')} "
                     f"to list available commands")
            continue
        try:
            cmd.run(session, args)
        except KeyboardInterrupt:
            print()
            warn(a, "operation cancelled by user (scan results so far kept in memory)")
        except Exception as exc:  # noqa: BLE001 - console must never crash
            error(a, f"unhandled error in '{name}': {exc}")

    if readline:
        try:
            readline.write_history_file(history_file)  # type: ignore[union-attr]
        except OSError:
            pass


def main() -> int:
    parser = argparse.ArgumentParser(
        prog="netspectre",
        description="NetSpectre — interactive local network auditing toolkit "
                    "(authorized use only).",
        epilog="example: python netspectre.py --target 192.168.1.0/24",
    )
    parser.add_argument("-t", "--target", help="default target CIDR/IP for the session")
    parser.add_argument("-p", "--profile", metavar="NAME", help="load a saved session profile at startup")
    parser.add_argument("--no-color", action="store_true", help="disable ANSI colors")
    parser.add_argument("--plain", action="store_true", help="non-interactive: run 'hosts' then 'ports' and exit")
    parser.add_argument("--ports", metavar="SPEC",
                        help="TCP port set: top100 | all | 22,80,443 | 1000-2000 (default: top100)")
    parser.add_argument("--udp", metavar="SPEC", nargs="?", const="top", default=None,
                        help="also run the UDP audit in --plain mode: top | all | 53,123,161 (bare --udp = top)")
    parser.add_argument("--max-high", type=int, default=None, metavar="N",
                        help="CI gate: exit 1 if high findings exceed N (overrides profile)")
    parser.add_argument("--max-medium", type=int, default=None, metavar="N",
                        help="CI gate: exit 1 if medium findings exceed N (overrides profile)")
    parser.add_argument("--json", action="store_true",
                        help="with --plain: JSON report to stdout (progress goes to stderr; pipe into jq)")
    parser.add_argument("--log", metavar="FILE", help="append scan events to FILE")
    parser.add_argument("-V", "--version", action="version", version=f"NetSpectre {__version__}")
    args = parser.parse_args()

    if args.json and not args.plain:
        parser.error("--json requires --plain (it controls the non-interactive report)")

    color = sys.stdout.isatty() and not args.no_color and os.environ.get("NO_COLOR") is None
    ansi = Ansi(color)
    session = Session(ansi, color, ping=False)
    if args.profile:
        try:
            n = load_profile(session, args.profile)
            session.profile_name = args.profile
        except ValueError as exc:
            error(ansi, str(exc))
    if args.ports:
        try:
            parse_ports(args.ports)  # fail fast with a clean CLI error
        except ValueError as exc:
            parser.error(f"--ports: {exc}")
        session.port_range = args.ports  # CLI flag wins over the profile
    if args.udp is not None and args.udp not in ("top", "top100"):
        try:
            parse_ports(args.udp)  # 'top' never reaches here; validate explicit specs only
        except ValueError as exc:
            parser.error(f"--udp: {exc}")
        session.udp_range = args.udp
    if args.target:
        session.target = args.target  # CLI flag wins over the profile
    for flag, attr in ((args.max_high, "max_high"), (args.max_medium, "max_medium")):
        if flag is not None:
            if flag < 0:
                parser.error(f"--{attr.replace('_', '-')} must be >= 0")
            setattr(session, attr, flag)  # CLI flags win over the profile
    if args.log:
        session.log_path = args.log

    real_stdout = sys.stdout
    if args.json:
        sys.stdout = sys.stderr  # every human-facing print must stay out of the pipe

    if sys.stdout.isatty():
        sys.stdout.write("\033[2J\033[H" if color else "\n" * 2)
    draw_banner(ansi)
    info(ansi, f"session started — {time.strftime('%Y-%m-%d %H:%M:%S')}")
    if session.profile_name:
        info(ansi, f"profile: {c(ansi, 'b_yellow', session.profile_name)} · target: "
                   f"{session.target or '(unset)'}")
    if args.ports:
        info(ansi, f"tcp port set: {c(ansi, 'b_yellow', args.ports)}")
    if args.udp is not None:
        info(ansi, f"udp audit enabled: {c(ansi, 'b_yellow', args.udp)}")
    info(ansi, f"local address: {local_ip()} · auto-detected subnet: {session.subnet}")
    warn(ansi, f"use only on networks you are authorized to test (e.g. your own LAN)\n")

    if args.plain:
        target = session.target or session.subnet
        cmd_hosts(session, [target])
        cmd_ports(session, [target])
        if args.udp is not None:
            cmd_udp(session, [target, args.udp])
        breaches = evaluate_risk_gate(session)
        if args.json:
            sys.stdout = real_stdout
            json.dump(build_report(session), sys.stdout, indent=2, ensure_ascii=False)
            sys.stdout.write("\n")
        if breaches:
            for b in breaches:
                error(ansi, f"risk gate FAILED — {b}")
            error(ansi, "audit does not pass the configured severity thresholds (exit 1)")
            return 1
        if session.max_high is not None or session.max_medium is not None:
            ok(ansi, "risk gate passed — findings within the configured thresholds")
        return 0

    sys.stdout = real_stdout  # defensive: --json implies --plain, but never leak the redirect
    repl(session)
    return 0


if __name__ == "__main__":
    sys.exit(main())
