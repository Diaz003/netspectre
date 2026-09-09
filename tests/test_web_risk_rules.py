"""Unit tests for web-panel risk rules (WEB_PANEL_RULES, match_web_finding).

These rules turn HTTP fingerprints into actionable findings (tag + severity +
reason) for admin panels exposed on the LAN.
"""

import pytest

from netspectre import (
    REMEDIATIONS,
    WEB_PANEL_RULES,
    fix_for,
    match_web_finding,
)


def _fp(**overrides):
    base = {
        "service": "http",
        "title": "",
        "scheme": "http",
        "status_code": 200,
        "layers": {},
        "error": None,
    }
    base.update(overrides)
    return base


# ---------------------------------------------------------------------------
# WEB_PANEL_RULES catalog
# ---------------------------------------------------------------------------


def test_rule_catalog_shapes_and_unique_tags():
    tags = []
    for rule in WEB_PANEL_RULES:
        assert len(rule) == 4, rule
        level, tag, rx, reason = rule
        assert level in ("high", "medium"), rule
        assert tag.startswith("web-"), rule
        assert reason.strip(), rule
        tags.append(tag)
    assert len(tags) == len(set(tags)), "duplicate rule tags"


def test_every_web_tag_has_a_remediation():
    for _level, tag, _rx, _reason in WEB_PANEL_RULES:
        assert fix_for(tag), f"missing REMEDIATIONS entry for {tag!r}"
    assert REMEDIATIONS["web-plain-http"]


# ---------------------------------------------------------------------------
# Rule matching: HNAP (high), LuCI / WebFig (medium)
# ---------------------------------------------------------------------------


def test_hnap_is_high_finding():
    hit = match_web_finding(_fp(service="HNAP1", title="D-Link Router"))
    assert hit == ("high", "web-hnap", WEB_PANEL_RULES[0][3])


def test_hnap_matches_on_endpoint_layer():
    hit = match_web_finding(_fp(layers={"body": ["/HNAP1/ endpoint referenced"]}))
    assert hit and hit[0] == "high" and hit[1] == "web-hnap"


def test_luci_openwrt_is_medium_finding():
    hit = match_web_finding(_fp(title="LuCI - OpenWrt Administration"))
    assert hit == ("medium", "web-luci", WEB_PANEL_RULES[1][3])


def test_luci_matches_openwrt_variant():
    hit = match_web_finding(_fp(title="OpenWrt"))
    assert hit and hit[1] == "web-luci"


def test_mikrotik_webfig_is_medium_finding():
    for marker in ("WebFig", "RouterOS", "MikroTik"):
        hit = match_web_finding(_fp(title=f"{marker} admin"))
        assert hit and hit[1] == "web-webfig", marker


def test_rule_priority_hnap_beats_luci():
    # First matching rule in the catalog wins
    hit = match_web_finding(_fp(title="D-Link with LuCI mention"))
    assert hit[1] == "web-hnap"


# ---------------------------------------------------------------------------
# Generic cleartext management-UI rule (web-plain-http)
# ---------------------------------------------------------------------------


def test_plain_http_admin_title_is_medium_finding():
    hit = match_web_finding(_fp(title="Router Admin Login"))
    assert hit == ("medium", "web-plain-http",
                   "HTTP management interface without TLS on the LAN")


@pytest.mark.parametrize("title", ["admin", "Router", "Gateway", "Login",
                                   "management console", "Web Login Page"])
def test_plain_http_admin_title_variants(title):
    hit = match_web_finding(_fp(title=title))
    assert hit and hit[1] == "web-plain-http"


def test_plain_http_auth_wall_counts_even_without_title():
    hit = match_web_finding(
        _fp(title="", status_code=401, layers={"status": ["HTTP/1.1 401 + WWW-Authenticate"]})
    )
    assert hit and hit[1] == "web-plain-http"


def test_https_admin_panel_is_not_flagged():
    assert match_web_finding(_fp(title="Router Admin", scheme="https")) is None


def test_plain_http_without_admin_markers_is_not_flagged():
    assert match_web_finding(_fp(title="Welcome to nginx!")) is None


def test_error_fingerprint_never_matches():
    assert match_web_finding(_fp(error="timeout")) is None


def test_non_dict_input_is_rejected():
    assert match_web_finding(None) is None
    assert match_web_finding("http") is None


# ---------------------------------------------------------------------------
# fix_for() helper
# ---------------------------------------------------------------------------


def test_fix_for_known_and_unknown_tags():
    assert "LuCI" in fix_for("web-luci")
    assert fix_for("nonexistent-tag") == ""
