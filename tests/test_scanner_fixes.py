"""Regression tests for the 2.0.1 fixes: real sockets on 127.0.0.1 only.

Each test pins down a bug that made the tool report wrong results:
HTTP banners never grabbed, closed UDP ports flagged as risky, hosts that
answer with a RST counted as down, host lists reused across subnets, wrong
'medium' totals in the Markdown export, and so on.
"""

import asyncio
import socket
import subprocess
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

import netspectre as ns

ROOT = Path(__file__).resolve().parents[1]


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------


def free_port(kind=socket.SOCK_STREAM):
    """A port nobody listens on right now (bind to 0, read it, release it)."""
    with socket.socket(socket.AF_INET, kind) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.fixture
def session():
    return ns.Session(ns.Ansi(False), False, ping=False)


@pytest.fixture
def http_server():
    class Handler(BaseHTTPRequestHandler):
        server_version = "LabServer/1.0"
        sys_version = ""

        def do_HEAD(self):
            self.send_response(200)
            self.end_headers()

        def log_message(self, *args):
            pass

    srv = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    yield srv.server_address[1]
    srv.shutdown()
    srv.server_close()


@pytest.fixture
def udp_echo():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("127.0.0.1", 0))
    stop = threading.Event()

    def loop():
        sock.settimeout(0.2)
        while not stop.is_set():
            try:
                data, addr = sock.recvfrom(4096)
            except OSError:
                continue
            sock.sendto(b"pong:" + data, addr)

    t = threading.Thread(target=loop, daemon=True)
    t.start()
    yield sock.getsockname()[1]
    stop.set()
    t.join(1)
    sock.close()


# ---------------------------------------------------------------------------
# TCP: banners and liveness
# ---------------------------------------------------------------------------


def test_http_ports_are_probed_as_http_not_as_talk_first_banners():
    # 8000/8080 used to sit in BANNER_PORTS, which is checked first: the tool
    # waited for the server to speak, got nothing and never sent HEAD /.
    assert 8000 in ns.HTTP_PORTS and 8080 in ns.HTTP_PORTS
    assert not ns.HTTP_PORTS & ns.BANNER_PORTS


def test_http_probe_returns_status_and_server_header(http_server):
    banner = ns._http_probe("127.0.0.1", http_server)
    assert banner.startswith("HTTP/1.")
    assert "200" in banner
    assert "LabServer/1.0" in banner


def test_audit_port_grabs_http_banner(monkeypatch, http_server):
    monkeypatch.setattr(ns, "HTTP_PORTS", {http_server})
    res = ns.audit_port("127.0.0.1", http_server, 1.0)
    assert res.state == "open"
    assert "LabServer/1.0" in res.banner


def test_audit_port_closed_is_reported_closed():
    res = ns.audit_port("127.0.0.1", free_port(), 1.0)
    assert res.state == "closed"


def test_tcp_alive_counts_a_refused_port_as_a_live_host():
    # a RST means somebody is there: the old probe only accepted open ports
    assert ns.tcp_alive("127.0.0.1", free_port(), 1.0) is True


def test_scan_hosts_finds_host_whose_probe_ports_are_all_closed(monkeypatch, session):
    monkeypatch.setattr(ns, "PROBE_PORTS", (free_port(),))
    hosts = ns.scan_hosts(session, "127.0.0.1")
    assert [h.ip for h in hosts] == ["127.0.0.1"]
    assert session.hosts_target == "127.0.0.1/32"


def test_scan_hosts_adds_firewalled_neighbours_seen_in_arp(monkeypatch, session):
    # nothing answers TCP; .2 appears in the ARP cache only after the sweep
    # (it answered ARP), .1 had an old STALE entry from before (ignored)
    calls = {"n": 0}

    def fake_arp():
        calls["n"] += 1
        if calls["n"] == 1:
            return [("127.0.0.1", "AA:AA:AA:AA:AA:AA", "STALE")]
        return [("127.0.0.1", "AA:AA:AA:AA:AA:AA", "DELAY"),
                ("127.0.0.2", "B8:27:EB:00:00:01", "REACHABLE")]

    monkeypatch.setattr(ns, "_arp_entries", fake_arp)
    monkeypatch.setattr(ns, "tcp_alive", lambda *a: False)
    monkeypatch.setattr(ns, "resolve_ptr", lambda ip, timeout=0.4: "")
    hosts = ns.scan_hosts(session, "127.0.0.0/30")
    assert [h.ip for h in hosts] == ["127.0.0.2"]
    assert hosts[0].vendor == "Raspberry Pi"


# ---------------------------------------------------------------------------
# ARP parsing across platforms
# ---------------------------------------------------------------------------


def _fake_run(stdout):
    return lambda *a, **k: subprocess.CompletedProcess(a, 0, stdout=stdout, stderr="")


def test_arp_entries_linux_ip_neigh(monkeypatch):
    monkeypatch.setattr(ns, "_IS_WIN", False)
    monkeypatch.setattr(ns.shutil, "which", lambda name: "/sbin/ip")
    monkeypatch.setattr(ns.subprocess, "run", _fake_run(
        "192.168.1.1 dev eth0 lladdr f8:66:c2:11:22:33 router REACHABLE\n"
        "192.168.1.30 dev eth0  FAILED\n"
        "fe80::1 dev eth0 lladdr f8:66:c2:11:22:33 router STALE\n"))
    assert ns._arp_entries() == [("192.168.1.1", "F8:66:C2:11:22:33", "REACHABLE")]


def test_arp_entries_macos_short_octets(monkeypatch):
    # macOS drops leading zeros: 0:1b:63:a:b:c
    monkeypatch.setattr(ns, "_IS_WIN", False)
    monkeypatch.setattr(ns.shutil, "which", lambda name: None)
    monkeypatch.setattr(ns.subprocess, "run", _fake_run(
        "? (192.168.1.20) at 0:1b:63:a:b:c on en0 ifscope [ethernet]\n"))
    assert ns.arp_table() == {"192.168.1.20": ("00:1B:63:0A:0B:0C", "Apple")}


def test_arp_entries_windows(monkeypatch):
    monkeypatch.setattr(ns, "_IS_WIN", True)
    monkeypatch.setattr(ns.subprocess, "run", _fake_run(
        "  192.168.1.1           f8-66-c2-11-22-33     dynamic\n"
        "  192.168.1.255         ff-ff-ff-ff-ff-ff     static\n"))
    assert ns.arp_table() == {"192.168.1.1": ("F8:66:C2:11:22:33", "TP-Link")}


# ---------------------------------------------------------------------------
# UDP: only real answers are open (and only those can be risks)
# ---------------------------------------------------------------------------


def test_udp_probe_closed_port_is_closed_not_open_filtered():
    res = ns.udp_probe("127.0.0.1", free_port(socket.SOCK_DGRAM), 1.0, retries=0)
    assert res.state == "closed"
    assert res.risk_level == ""


def test_udp_probe_answer_is_open_with_risk(monkeypatch, udp_echo):
    monkeypatch.setitem(ns.UDP_RISK, udp_echo, ("medium", "lab", "test service"))
    res = ns.udp_probe("127.0.0.1", udp_echo, 1.0, retries=0)
    assert res.state == "open"
    assert res.response.startswith("udp-response")
    assert (res.risk_level, res.risk) == ("medium", "lab")


def test_udp_probe_silence_is_open_filtered_without_risk(monkeypatch):
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as mute:   # bound, never answers
        mute.bind(("127.0.0.1", 0))
        port = mute.getsockname()[1]
        monkeypatch.setitem(ns.UDP_RISK, port, ("high", "lab", "test service"))
        res = ns.udp_probe("127.0.0.1", port, 0.2, retries=0)
    assert res.state == "open|filtered"
    assert res.risk_level == ""


def test_open_filtered_udp_never_becomes_a_finding(session):
    session.last_udp = {"127.0.0.1": [
        ns.UdpResult(161, "open|filtered", "snmp", risk="snmp", risk_level="medium"),
        ns.UdpResult(69, "open", "tftp", "tftp-response", risk="tftp", risk_level="high"),
    ]}
    findings = ns.collect_findings(session)
    assert [(f["port"], f["level"]) for f in findings] == [(69, "high")]


# ---------------------------------------------------------------------------
# session state: host lists belong to one network
# ---------------------------------------------------------------------------


def test_host_list_reused_only_for_the_same_network(monkeypatch, session):
    session.last_hosts = [ns.HostRecord("10.0.0.5", alive=True)]
    session.hosts_target = "10.0.0.0/24"
    discovered = []

    def fake_scan(sess, target):
        discovered.append(target)
        return [ns.HostRecord("192.168.7.9", alive=True)]

    monkeypatch.setattr(ns, "scan_hosts", fake_scan)
    assert ns._live_ips(session, "10.0.0.77/24") == ["10.0.0.5"]       # same net, any spelling
    assert ns._live_ips(session, "192.168.7.0/24") == ["192.168.7.9"]  # other net: rediscover
    assert discovered == ["192.168.7.0/24"]
    assert ns._live_ips(session, "10.0.0.9") == ["10.0.0.9"]           # single IP as-is


# ---------------------------------------------------------------------------
# reports and counters
# ---------------------------------------------------------------------------


def test_markdown_medium_count_with_zero_high(session, tmp_path):
    session.last_results = {"127.0.0.1": [
        ns.PortResult(21, "open", "ftp", risk="ftp", risk_level="medium")]}
    out = tmp_path / "r.md"
    assert ns.write_risks_markdown(session, str(out)) == 1
    assert "(0 high, 1 medium)" in out.read_text(encoding="utf-8")


def test_status_counts_udp_and_web_findings(session, capsys):
    session.last_udp = {"127.0.0.1": [
        ns.UdpResult(69, "open", "tftp", "x", risk="tftp", risk_level="high")]}
    session.last_fingerprints = {"127.0.0.1:8080": {
        "scheme": "http", "status_code": 200, "service": "OpenWrt LuCI", "title": "LuCI"}}
    ns.cmd_status(session, [])
    assert "1 high · 1 medium" in capsys.readouterr().out


def test_risk_export_works_with_fingerprints_only(session, tmp_path, capsys):
    session.last_fingerprints = {"10.0.0.1:80": {
        "scheme": "http", "status_code": 200, "service": "OpenWrt LuCI", "title": "LuCI"}}
    out = tmp_path / "r.csv"
    ns.cmd_risks(session, ["csv", str(out)])
    assert "web-luci" in out.read_text(encoding="utf-8")


def test_padding_ignores_ansi_codes():
    red = ns.Ansi(True).red + "abc" + ns.Ansi(True).reset
    assert ns.vlen(red) == 3
    assert ns.vlen(ns.pad(red, 8)) == 8


def test_json_mode_keeps_stdout_pure_json_when_the_gate_fails():
    driver = (
        "import sys; sys.argv = ['netspectre.py', '--plain', '--json', '--no-color',"
        "'--target', '127.0.0.1', '--ports', '1', '--max-high', '0'];"
        "import netspectre as ns;"
        "ns.cmd_hosts = lambda s, a: None;"
        "ns.cmd_ports = lambda s, a: setattr(s, 'last_results', {"
        "'127.0.0.1': [ns.PortResult(6379, 'open', 'redis', risk='redis',"
        "risk_level='high')]});"
        "sys.exit(ns.main())"
    )
    res = subprocess.run([sys.executable, "-c", driver], capture_output=True,
                         text=True, timeout=120, cwd=str(ROOT))
    assert res.returncode == 1
    import json
    report = json.loads(res.stdout)            # nothing but JSON on stdout
    assert report["risk_summary"]["high"] == 1
    assert "risk gate FAILED" in res.stderr


# ---------------------------------------------------------------------------
# async engine: no TaskGroup (3.11+), queued targets don't burn their timeout
# ---------------------------------------------------------------------------


def test_fingerprint_many_queue_does_not_time_out(monkeypatch):
    hfp = pytest.importorskip("http_fingerprinter")
    monkeypatch.delattr(asyncio, "TaskGroup", raising=False)   # behave like 3.8-3.10

    fp = hfp.HTTPFingerprinter(concurrency=1, overall_timeout=0.5)

    async def slow_probe(host, port, scheme, result):
        async with fp._semaphore():
            await asyncio.sleep(0.15)        # each target alone fits in the budget
        result.service = f"svc{port}"

    monkeypatch.setattr(fp, "_probe", slow_probe)
    targets = [("127.0.0.1", p) for p in (1, 2, 3, 4, 5)]  # 5 × 0.15 s > 0.5 s overall
    results = asyncio.run(fp.fingerprint_many(targets))
    assert [r.port for r in results] == [1, 2, 3, 4, 5]
    assert all(not r.error for r in results), [r.error for r in results]


# ---------------------------------------------------------------------------
# web demo / guide
# ---------------------------------------------------------------------------


def test_demo_has_no_python_only_string_methods():
    html = (ROOT / "index.html").read_text(encoding="utf-8")
    assert ".rsplit(" not in html          # JS has no rsplit: 'risks' crashed


def test_guide_links_point_to_the_demo_that_exists():
    html = (ROOT / "guide.html").read_text(encoding="utf-8")
    assert "demo.html" not in html
    assert (ROOT / "index.html").exists()
