"""CLI integration tests for netspectre.py: exit codes and runtime behaviour.

`main()` is invoked through subprocess so the real `sys.exit()` paths are
exercised; REPL flows run through stdin pipes exactly like a user would.
"""

import json
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "netspectre.py"


def run_cli(args, stdin=""):
    return subprocess.run(
        [sys.executable, str(SCRIPT), *args],
        input=stdin,
        capture_output=True,
        text=True,
        timeout=120,
    )


# ---------------------------------------------------------------------------
# Exit code 0 — clean runs
# ---------------------------------------------------------------------------


def test_version_flag_exits_zero_and_prints_version():
    res = run_cli(["--version"])
    assert res.returncode == 0
    assert "NetSpectre" in res.stdout


def test_help_flag_exits_zero():
    res = run_cli(["--help"])
    assert res.returncode == 0
    assert "netspectre" in res.stdout.lower()


def test_repl_session_status_then_exit_exits_zero():
    res = run_cli(["--no-color"], stdin="status\nexit\n")
    assert res.returncode == 0
    assert "session status" in res.stdout.lower()


def test_repl_quit_alias_exits_zero():
    res = run_cli(["--no-color"], stdin="quit\n")
    assert res.returncode == 0


# ---------------------------------------------------------------------------
# Exit code 2 — argparse misuse
# ---------------------------------------------------------------------------


def test_unknown_flag_exits_two():
    res = run_cli(["--no-such-flag"])
    assert res.returncode == 2
    assert "unrecognized arguments" in res.stderr


def test_json_requires_plain_exits_two():
    res = run_cli(["--json"])
    assert res.returncode == 2
    assert "--json requires --plain" in res.stderr


def test_invalid_ports_spec_exits_two():
    res = run_cli(["--plain", "--ports", "not-a-port"])
    assert res.returncode == 2
    assert "--ports" in res.stderr


def test_negative_max_high_exits_two():
    res = run_cli(["--plain", "--max-high", "-1"])
    assert res.returncode == 2


# ---------------------------------------------------------------------------
# Risk gate — exit 1 when severity thresholds are exceeded
# ---------------------------------------------------------------------------


def test_risk_gate_fails_with_exit_one_when_high_exceeds_limit():
    # Patch cmd_ports (not cmd_hosts) so scan results aren't overwritten.
    driver = (
        "import sys; sys.argv = ['netspectre.py', '--plain', '--no-color',"
        "'--target', '127.0.0.1', '--ports', '1', '--max-high', '0'];"
        "import netspectre as ns;"
        "ns.cmd_hosts = lambda s, a: None;"
        "ns.cmd_ports = lambda s, a: setattr(s, 'last_results', {"
        "'127.0.0.1': [ns.PortResult(6379, 'open', 'redis', risk='redis',"
        "risk_level='high'), ns.PortResult(445, 'open', 'microsoft-ds',"
        "risk='smb', risk_level='high')]});"
        "sys.exit(ns.main())"
    )
    res = subprocess.run(
        [sys.executable, "-c", driver], capture_output=True, text=True, timeout=120
    )
    assert res.returncode == 1, res.stdout + res.stderr
    assert "risk gate FAILED" in res.stdout
    assert "high findings: 2 > limit 0" in res.stdout


def test_risk_gate_passes_within_thresholds_exits_zero():
    driver = (
        "import sys; sys.argv = ['netspectre.py', '--plain', '--no-color',"
        "'--target', '127.0.0.1', '--ports', '1', '--max-high', '2'];"
        "import netspectre as ns;"
        "ns.cmd_hosts = lambda s, a: None;"
        "ns.cmd_ports = lambda s, a: setattr(s, 'last_results', {"
        "'127.0.0.1': [ns.PortResult(6379, 'open', 'redis', risk='redis',"
        "risk_level='high'), ns.PortResult(21, 'open', 'ftp', risk='ftp',"
        "risk_level='medium')]});"
        "sys.exit(ns.main())"
    )
    res = subprocess.run(
        [sys.executable, "-c", driver], capture_output=True, text=True, timeout=120
    )
    assert res.returncode == 0, res.stdout + res.stderr
    assert "risk gate passed" in res.stdout


def test_risk_gate_medium_only_breach_exits_one():
    driver = (
        "import sys; sys.argv = ['netspectre.py', '--plain', '--no-color',"
        "'--target', '127.0.0.1', '--ports', '1', '--max-medium', '0'];"
        "import netspectre as ns;"
        "ns.cmd_hosts = lambda s, a: None;"
        "ns.cmd_ports = lambda s, a: setattr(s, 'last_results', {"
        "'127.0.0.1': [ns.PortResult(21, 'open', 'ftp', risk='ftp',"
        "risk_level='medium')]});"
        "sys.exit(ns.main())"
    )
    res = subprocess.run(
        [sys.executable, "-c", driver], capture_output=True, text=True, timeout=120
    )
    assert res.returncode == 1
    assert "medium findings: 1 > limit 0" in res.stdout


def test_risk_gate_not_configured_always_exits_zero():
    # No thresholds set: findings are reported but the run still passes.
    driver = (
        "import sys; sys.argv = ['netspectre.py', '--plain', '--no-color',"
        "'--target', '127.0.0.1', '--ports', '1'];"
        "import netspectre as ns;"
        "ns.cmd_hosts = lambda s, a: None;"
        "ns.cmd_ports = lambda s, a: setattr(s, 'last_results', {"
        "'127.0.0.1': [ns.PortResult(6379, 'open', 'redis', risk='redis',"
        "risk_level='high')]});"
        "sys.exit(ns.main())"
    )
    res = subprocess.run(
        [sys.executable, "-c", driver], capture_output=True, text=True, timeout=120
    )
    assert res.returncode == 0


# ---------------------------------------------------------------------------
# --plain --json machine-readable report
# ---------------------------------------------------------------------------


def test_plain_json_report_is_valid_and_complete():
    res = run_cli(["--plain", "--json", "--no-color",
                   "--target", "127.0.0.1", "--ports", "1"])
    assert res.returncode == 0
    report = json.loads(res.stdout)
    assert report["version"] == "2.0.0"
    assert report["target"] == "127.0.0.1"
    assert "hosts" in report and "risk_summary" in report
    assert set(report["risk_summary"]) >= {"high", "medium", "findings"}


# ---------------------------------------------------------------------------
# REPL: unknown commands keep the session alive (console must never crash)
# ---------------------------------------------------------------------------


def test_repl_survives_unknown_command_and_exit_still_zero():
    res = run_cli(["--no-color"], stdin="bogus-command\nexit\n")
    assert res.returncode == 0
    assert "unknown" in res.stdout.lower() or "help" in res.stdout.lower()


def test_repl_help_lists_core_commands():
    res = run_cli(["--no-color"], stdin="help\nexit\n")
    assert res.returncode == 0
    for cmd in ("hosts", "ports", "udp", "fingerprint", "risks", "save"):
        assert cmd in res.stdout
