"""Unit tests for the async HTTP fingerprinting engine (http_fingerprinter.py).

The layer scoring math is pure logic — the tests drive `_score_*` +
`_finalize` directly with synthetic HTTP evidence, no network involved.
"""

import pytest

# The engine imports aiohttp at module load; without it (stdlib-only CI job)
# the whole module skips cleanly instead of erroring.
try:
    import http_fingerprinter as hfp
except ImportError:  # any flavour: ModuleNotFoundError or a broken install
    hfp = None

pytestmark = pytest.mark.skipif(
    hfp is None, reason="HTTP fingerprinting engine requires aiohttp"
)


@pytest.fixture
def fp():
    return hfp.HTTPFingerprinter()


@pytest.fixture
def result():
    return hfp.HTTPFingerprint(target="10.0.0.9", port=80, scheme="http")


# ---------------------------------------------------------------------------
# Module-level invariants
# ---------------------------------------------------------------------------


def test_layer_weights_sum_to_100():
    assert hfp.W_HEADERS + hfp.W_BODY + hfp.W_STATUS == 100


def test_weight_constants():
    assert hfp.W_HEADERS == 45
    assert hfp.W_BODY == 40
    assert hfp.W_STATUS == 15


# ---------------------------------------------------------------------------
# Layer 1 — HTTP headers (cap 45)
# ---------------------------------------------------------------------------


class FakeHeaders:
    """Duck-typed aiohttp CIMultiDict stand-in."""

    def __init__(self, pairs):
        self._pairs = pairs

    def get(self, name, default=None):
        return self._pairs.get(name, default)

    def getall(self, name, default=()):
        v = self._pairs.get(name)
        return [v] if v is not None else list(default)


def test_headers_server_apache_scores_30(fp, result):
    fp._score_headers(result, FakeHeaders({"Server": "Apache/2.4.41 (Unix)"}))
    assert result.server_header == "Apache/2.4.41 (Unix)"
    ev = result.layers["headers"]
    assert len(ev) == 1
    assert "→ Apache httpd (+30)" in ev[0]


def test_headers_single_layer_is_capped_at_weight(fp, result):
    # Apache (30) + PHP powered-by (10) = 40, still below the 45 cap
    fp._score_headers(
        result,
        FakeHeaders({"Server": "Apache", "X-Powered-By": "PHP/8.1"}),
    )
    assert "Apache httpd" in result.layers["headers"][0]
    fp._finalize(result)
    assert result.service == "Apache httpd"
    assert result.confidence_score == 40


def test_headers_cap_limits_score_to_45(fp, result):
    # Server(30) + PHP(10) + express(10) + cookie(20) > 45 → capped
    headers = FakeHeaders({
        "Server": "nginx",
        "Set-Cookie": "PHPSESSID=abc123",
        "X-Powered-By": "PHP/7.4 Express",
    })
    fp._score_headers(result, headers)
    fp._finalize(result)
    assert result.layers["__weights__"][0] == f"headers 45/{hfp.W_HEADERS}"


def test_headers_cookie_and_powered_evidence(fp, result):
    fp._score_headers(
        result, FakeHeaders({"Set-Cookie": "PHPSESSID=xyz", "X-Powered-By": "PHP/8.2"})
    )
    ev = result.layers["headers"]
    assert any("PHP application (+20)" in e for e in ev)
    assert any("PHP (+10)" in e for e in ev)


def test_headers_www_authenticate_basic_and_digest(fp, result):
    result.status_code = 401
    fp._score_headers(result, FakeHeaders({"WWW-Authenticate": 'Basic realm="x"'}))
    assert any("HTTP basic auth (+6)" in e for e in result.layers["headers"])

    result.status_code = 401
    result.layers.clear()
    fp._score_headers(result, FakeHeaders({"WWW-Authenticate": 'Digest realm="y"'}))
    assert any("HTTP digest auth (appliance) (+10)" in e for e in result.layers["headers"])


def test_headers_no_evidence_scores_zero(fp, result):
    fp._score_headers(result, FakeHeaders({}))
    fp._finalize(result)
    assert result.confidence_score == 0
    assert result.service == "unknown"


# ---------------------------------------------------------------------------
# Layer 2 — HTML body (cap 40)
# ---------------------------------------------------------------------------


def test_body_js_var_and_endpoint(fp, result):
    body = """
    <html><head><title>Router Admin</title></head><body>
    <script>var G_FEATURES = {"ipv6": 1};</script>
    <a href="/cgi-bin/luci/">login</a>
    </body></html>
    """
    fp._score_body(result, body)
    fp._finalize(result)
    assert result.title == "Router Admin"
    assert result.service == "Huawei ONT/router (G_FEATURES)"  # 22 pts beats 18
    assert result.confidence_score == 40  # 22 + 18, below the body cap


def test_body_body_cap_40_even_with_more_evidence(fp, result):
    body = (
        "<title>LuCI</title>"
        "<script>var LuCI = {}; var G_FEATURES = 1; var RouterOS = 1;</script>"
        "/cgi-bin/luci/ /webfig/ /ISAPI/ .php"
    )
    fp._score_body(result, body)
    fp._finalize(result)
    assert result.layers["__weights__"][1] == f"body 40/{hfp.W_BODY}"


def test_body_meta_generator_without_service(fp, result):
    fp._score_body(result, '<meta name="generator" content="MikroTik RouterOS 7.14">')
    assert any("(+12)" in e for e in result.layers["body"])


def test_body_extracts_hardware_metadata(fp, result):
    body = (
        "MAC: AA:BB:CC:DD:EE:FF and 11:22:33:44:55:66; "
        "Model: RT-AX55; Serial no: XYZ123456; HW: v2.1; Firmware: 3.0.0.4.386"
    )
    fp._score_body(result, body)
    assert result.extra_info["mac_addresses"] == ["11:22:33:44:55:66", "AA:BB:CC:DD:EE:FF"]
    assert result.extra_info["model"] == "RT-AX55"
    assert result.extra_info["serial"] == "XYZ123456"
    assert result.extra_info["hardware_version"] == "v2.1"
    assert result.extra_info["firmware"] == "3.0.0.4.386"


def test_body_without_title_leaves_it_none(fp, result):
    fp._score_body(result, "<html><body>plain page</body></html>")
    assert result.title is None


# ---------------------------------------------------------------------------
# Layer 3 — status codes / robots.txt (cap 15)
# ---------------------------------------------------------------------------


def test_status_hints_per_code(fp, result):
    for status, (hint, pts) in hfp.STATUS_CODE_HINTS.items():
        result.layers.clear()
        fp._score_status(result, status, "/", "")
        ev = result.layers["status"]
        assert len(ev) == 1
        assert f"status {status}" in ev[0]
        assert f"(+{pts})" in ev[0]


def test_status_unknown_code_scores_nothing(fp, result):
    fp._score_status(result, 500, "/", "")
    assert not result.layers.get("status")


def test_status_non_root_path_ignored_unless_robots(fp, result):
    fp._score_status(result, 200, "/webfig/", "")
    assert not result.layers.get("status")


def test_status_robots_wordpress_disallow(fp, result):
    robots = "User-agent: *\nDisallow: /wp-admin/\n"
    fp._score_status(result, 200, "/robots.txt", robots)
    assert any("WordPress (+10)" in e for e in result.layers["status"])


def test_status_robots_unrelated_disallow(fp, result):
    fp._score_status(result, 200, "/robots.txt", "Disallow: /private\n")
    assert not result.layers.get("status")


# ---------------------------------------------------------------------------
# _finalize — full-stack weighted confidence
# ---------------------------------------------------------------------------


def test_finalize_full_stack_weighted_sum(fp, result):
    # 30 (nginx header) + 40 (LuCI var + endpoint, body cap) + 3 (200 OK)
    fp._score_headers(result, FakeHeaders({"Server": "nginx"}))
    fp._score_body(result, "<script>var LuCI = {};</script>/cgi-bin/luci/")
    fp._score_status(result, 200, "/", "")
    fp._finalize(result)
    assert result.confidence_score == 73
    assert result.service == "nginx"  # highest single evidence wins
    assert result.layers["__weights__"] == [
        f"headers 30/{hfp.W_HEADERS}",
        f"body 40/{hfp.W_BODY}",
        f"status 3/{hfp.W_STATUS}",
    ]


def test_finalize_global_cap_never_exceeds_100(fp, result):
    # headers 30+20 → capped at 45; body 22+18 = 40; status 8+4+3 = 15
    fp._score_headers(result, FakeHeaders({"Server": "nginx",
                                           "Set-Cookie": "PHPSESSID=x"}))
    fp._score_body(result, "<script>var LuCI = {};</script>/cgi-bin/luci/")
    for status in (401, 403, 200):
        fp._score_status(result, status, "/", "")
    fp._finalize(result)
    assert result.confidence_score == 100
    assert result.layers["__weights__"] == [
        f"headers 45/{hfp.W_HEADERS}",
        f"body 40/{hfp.W_BODY}",
        f"status 15/{hfp.W_STATUS}",
    ]


def test_finalize_best_service_comes_from_highest_single_evidence(fp, result):
    # Headers 30 pts (Apache) vs body 22 pts (Huawei) → Apache wins the pick
    fp._score_headers(result, FakeHeaders({"Server": "Apache/2.4"}))
    fp._score_body(result, "<script>var G_FEATURES = 1;</script>")
    fp._finalize(result)
    assert result.service == "Apache httpd"
    assert result.confidence_score == 52  # 30 + 22


def test_finalize_empty_result_is_unknown_and_zero(fp, result):
    fp._finalize(result)
    assert result.service == "unknown"
    assert result.confidence_score == 0


def test_finalize_ignores_unknown_layers(fp, result):
    result.layers["mystery"] = ["weird evidence (+99)"]
    fp._finalize(result)
    assert result.confidence_score == 0
    assert "__weights__" in result.layers and "mystery" not in result.layers["__weights__"][0]


# ---------------------------------------------------------------------------
# Public API behaviour that does not touch the network
# ---------------------------------------------------------------------------


def test_normalize_host_accepts_bare_and_url_forms():
    assert hfp._normalize_host("192.168.1.1") == "192.168.1.1"
    assert hfp._normalize_host("http://192.168.1.1:8080/admin") == "192.168.1.1:8080"
    assert hfp._normalize_host("https://router.local/") == "router.local"
    with pytest.raises(ValueError):
        hfp._normalize_host("   ")


def test_fingerprint_rejects_empty_host_without_network(fp):
    result = hfp.HTTPFingerprinter().fingerprint.__wrapped__ if False else None
    # direct call: fingerprint() returns a result with .error set for a bad host
    res = asyncio_run_fp(fp)
    assert res.error == "empty target host"
    assert res.confidence_score == 0


def asyncio_run_fp(fp):
    import asyncio

    return asyncio.run(fp.fingerprint("   ", port=80))


def test_as_dict_round_trip(result):
    result.service = "nginx"
    result.confidence_score = 73
    result.layers["headers"] = ["Server: 'nginx' → nginx (+30)"]
    d = result.as_dict()
    assert d["service"] == "nginx"
    assert d["confidence_score"] == 73
    assert d["layers"]["headers"] == ["Server: 'nginx' → nginx (+30)"]
    assert d["error"] is None
    assert result.ok is True


def test_error_result_is_reported_not_raised(fp):
    import asyncio

    res = asyncio.run(fp.fingerprint("127.0.0.1", port=1))  # nothing listening
    assert res.error is not None
    assert res.ok is False
