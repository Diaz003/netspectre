#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
NetSpectre v2.0 — HTTPFingerprinter

Asynchronous HTTP service fingerprinting module.

  * asyncio + aiohttp (non-blocking, semaphore-limited concurrency)
  * all detection regexes precompiled at import time
  * multi-layer weighted confidence scoring (0-100):
      - layer 1: HTTP headers (Server, Set-Cookie, X-Powered-By, ...)
      - layer 2: JS variables / endpoints / meta tags inside the HTML body
      - layer 3: status codes and responses to fingerprint paths
  * robust: connect/read timeouts, TLS/SSL errors, redirect following
  * structured output: HTTPFingerprint dataclass

Free software, provided "AS-IS" with no warranty: the author is not liable for
misuse, damage or consequences. Run only against networks you are permitted to test.
"""

from __future__ import annotations

import asyncio
import re
import ssl
from dataclasses import dataclass, field
from typing import Any

import aiohttp

__all__ = [
    "HTTPFingerprint",
    "HTTPFingerprinter",
    "FingerprintError",
    "FingerprintTimeout",
    "FingerprintTLSError",
]

# ---------------------------------------------------------------------------
# Tunables
# ---------------------------------------------------------------------------

DEFAULT_TIMEOUT = 8.0          # seconds, total per request (connect + read)
DEFAULT_CONCURRENCY = 16       # max simultaneous requests per fingerprinter
MAX_REDIRECTS = 5
MAX_BODY_BYTES = 512 * 1024    # cap HTML download for regex analysis
MAX_SIDECAR_BYTES = 32 * 1024  # robots.txt etc.
DEFAULT_OVERALL_TIMEOUT = 25.0  # hard cap for the whole multi-path probe
DEFAULT_USER_AGENT = "NetSpectre/2.0 (+local network audit)"

# Layer weights (must sum to 100)
W_HEADERS = 45
W_BODY = 40
W_STATUS = 15

# ---------------------------------------------------------------------------
# Precompiled regexes — compiled ONCE at module load, never per request
# ---------------------------------------------------------------------------

# -- Layer 1a: Server header ------------------------------------------------
_RX_SERVER = {
    "Apache httpd": re.compile(r"\bapache\b", re.I),
    "nginx": re.compile(r"\bnginx\b", re.I),
    "Microsoft IIS": re.compile(r"\biis\b|internet information services", re.I),
    "lighttpd": re.compile(r"\blighttpd\b", re.I),
    "Apache Tomcat": re.compile(r"\btomcat\b|coyote", re.I),
    "OpenResty": re.compile(r"\bopenresty\b", re.I),
    "Caddy": re.compile(r"\bcaddy\b", re.I),
    "Mongoose/CivetWeb embedded": re.compile(r"\bmongoose\b|\bcivetweb\b", re.I),
    "BusyBox httpd": re.compile(r"\bbusybox\b", re.I),
    "Boa (embedded router)": re.compile(r"\bboa\b(?!rd)", re.I),
    "mini_httpd (embedded)": re.compile(r"\bmini_httpd\b", re.I),
    "Go http server": re.compile(r"\bgo http server\b|golang", re.I),
}

# -- Layer 1b: Set-Cookie ----------------------------------------------------
_RX_COOKIE = {
    "PHP application": re.compile(r"\bPHPSESSID=", re.I),
    "Java servlet container": re.compile(r"\bJSESSIONID=", re.I),
    "ASP.NET application": re.compile(r"\bASP\.NET_SessionId=|\.ASPXAUTH=", re.I),
    "Express (Node.js)": re.compile(r"\bconnect\.sid=", re.I),
    "Laravel framework": re.compile(r"\b(?:laravel_session|XSRF-TOKEN)=", re.I),
    "Django framework": re.compile(r"\b(?:sessionid|csrftoken)=", re.I),
    "MikroTik RouterOS": re.compile(r"\b(?:mt_session|routeros)=", re.I),
    "OpenWrt LuCI": re.compile(r"\bsysauth(?:_https)?=", re.I),
}

# -- Layer 1c: X-Powered-By / misc -------------------------------------------
_RX_POWERED = {
    "PHP": re.compile(r"\bphp(?:/[\d.]+)?\b", re.I),
    "ASP.NET": re.compile(r"\basp\.net\b", re.I),
    "Express (Node.js)": re.compile(r"\bexpress\b", re.I),
}
_RX_WWW_AUTH_DIGEST = re.compile(r"(?i)\bdigest\b")
_RX_WWW_AUTH_BASIC = re.compile(r"(?i)\bbasic\b")

# -- Layer 2a: JS variables / UI markers in the HTML body ---------------------
_RX_JS_VARS = {
    "Huawei ONT/router (G_FEATURES)": re.compile(r"\bG_FEATURES\s*=", re.I),
    "AVM FRITZ!Box": re.compile(r"\bWebCMDBase\b|\bJASON\b.*fritzbox", re.I | re.S),
    "OpenWrt (LuCI)": re.compile(r"\bLuCI\b", re.I),
    "OPNsense": re.compile(r"\bOPNsense\b", re.I),
    "pfSense": re.compile(r"\bpfSense\b", re.I),
    "MikroTik RouterOS/WebFig": re.compile(r"\bRouterOS\b|\bMikroTik\b|\bWebFig\b", re.I),
    "ASUSWRT": re.compile(r"\bASUSWRT\b|\bRT-[ACX]{1,2}[TE]?[CSU]?\d+", re.I),
    "NETGEAR Genie": re.compile(r"\bNETGEAR\s+Genie\b|\bgenie\.js\b", re.I),
    "TP-Link": re.compile(r"\bTP-Link\b|\btplink\b", re.I),
    "ZyXEL": re.compile(r"\bZyXEL\b", re.I),
    "D-Link": re.compile(r"\bD-Link\b", re.I),
    "Ubiquiti UniFi/EdgeOS": re.compile(r"\bUbiquiti\b|\bUniFi\b|\bEdgeOS\b", re.I),
    "Synology DSM": re.compile(r"\bSynology\b|\bDiskStation\b", re.I),
    "QNAP QTS": re.compile(r"\bQNAP\b", re.I),
    "HP printer": re.compile(r"\bHP\s+LaserJet\b|\bhp\s+printer\b", re.I),
    "Hikvision IP camera": re.compile(r"\bHikvision\b|\bWebComponents\b", re.I),
    "Dahua IP camera": re.compile(r"\bDahua\b", re.I),
    "Grafana": re.compile(r"\bgrafanaBootData\b|\bGrafana\b", re.I),
    "Jenkins CI": re.compile(r"\bJenkins\b", re.I),
    "phpMyAdmin": re.compile(r"\bphpMyAdmin\b", re.I),
    "WordPress": re.compile(r"\bwp-content\b|\bwp-includes\b", re.I),
}

# -- Layer 2b: endpoints referenced in the HTML -------------------------------
_RX_ENDPOINTS = {
    "OpenWrt LuCI (/cgi-bin/luci/)": re.compile(r"/cgi-bin/luci/", re.I),
    "D-Link HNAP SOAP (/HNAP1/)": re.compile(r"/HNAP1/?", re.I),
    "MikroTik WebFig (/webfig/)": re.compile(r"/webfig/", re.I),
    "Hikvision ISAPI": re.compile(r"/ISAPI/", re.I),
    "Synology webman/webapi": re.compile(r"/webman/index\.cgi|/webapi/", re.I),
    "TP-Link goform handler": re.compile(r"/goform/", re.I),
    "generic CGI (embedded)": re.compile(r"/cgi-bin/[\w./-]+", re.I),
    "PHP backend": re.compile(r"\.php(?:\?|\"|'|$)", re.I),
    "ASP.NET backend": re.compile(r"\.aspx?(?:\?|\"|'|$)", re.I),
    "JSP backend": re.compile(r"\.jsp(?:\?|\"|'|$)", re.I),
    "REST API": re.compile(r"/api/(?:v\d+/)?[\w/-]+", re.I),
}

_RX_META_GENERATOR = re.compile(
    r'<meta[^>]+name\s*=\s*["\']generator["\'][^>]+content\s*=\s*["\']([^"\']{1,120})["\']',
    re.I,
)
_RX_TITLE = re.compile(r"<title[^>]*>(.*?)</title>", re.I | re.S)

# -- Layer 3: status-code hints and path responses ----------------------------
STATUS_CODE_HINTS: dict[int, tuple[str, int]] = {
    401: ("auth required (WWW-Authenticate present)", 8),
    403: ("403 — hardened or filtered", 4),
    200: ("standard 200 OK", 3),
    302: ("redirecting frontend", 2),
}
_RX_ROBOTS_WP = re.compile(r"(?im)^\s*Disallow:\s*/wp-admin/?\s*$")

# -- Hardware / MAC metadata extraction (extra_info) ---------------------------
_RX_MAC = re.compile(r"\b(?:[0-9A-F]{2}:){5}[0-9A-F]{2}\b")
_RX_SERIAL = re.compile(r"(?i)\b(?:serial(?:\s*(?:no|number))?|sn)\s*[:=]\s*([A-Z0-9-]{4,32})")
_RX_MODEL = re.compile(r"(?i)\b(?:model|product)\s*[:=]\s*([A-Z0-9][A-Z0-9._ -]{2,40})")
_RX_HW_VERSION = re.compile(r"(?i)\bhw(?:\.|version)?\s*[:=]\s*(v?[\d.]+)")
_RX_FIRMWARE = re.compile(r"(?i)\b(?:firmware|fw)\s*[:=]\s*(v?[\d.]+)")

# Evidence-string parsing: every item ends with "→ service (+N)" or just "(+N)"
_RX_EV_POINTS = re.compile(r"\(\+(\d+)\)\s*$")
_RX_EV_SERVICE = re.compile(r"→\s*(.+?)\s*\(\+\d+\)\s*$")

# Layer 3 probing paths
FINGERPRINT_PATHS: tuple[str, ...] = (
    "/", "/robots.txt", "/favicon.ico",
    "/cgi-bin/luci/",        # OpenWrt
    "/webfig/",              # MikroTik
    "/HNAP1/",               # D-Link
    "/ISAPI/System/status",  # Hikvision
    "/webman/index.cgi",     # Synology
)

# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------


class FingerprintError(Exception):
    """Base error for the fingerprinter."""


class FingerprintTimeout(FingerprintError):
    """Request exceeded the configured timeout."""


class FingerprintTLSError(FingerprintError):
    """TLS/SSL handshake or certificate failure."""


# ---------------------------------------------------------------------------
# Output dataclass
# ---------------------------------------------------------------------------


@dataclass
class HTTPFingerprint:
    """Structured result of one HTTP fingerprint probe."""

    target: str                                   # host that was probed
    port: int
    scheme: str                                   # http / https
    service: str = "unknown"                      # best-guess product/service
    confidence_score: int = 0                     # 0-100
    server_header: str | None = None
    status_code: int | None = None
    title: str | None = None
    redirects: tuple[str, ...] = field(default_factory=tuple)
    extra_info: dict[str, Any] = field(default_factory=dict)
    layers: dict[str, list[str]] = field(default_factory=dict)
    error: str | None = None

    @property
    def ok(self) -> bool:
        return self.error is None

    def as_dict(self) -> dict[str, Any]:
        return {
            "target": self.target,
            "port": self.port,
            "scheme": self.scheme,
            "service": self.service,
            "confidence_score": self.confidence_score,
            "server_header": self.server_header,
            "status_code": self.status_code,
            "title": self.title,
            "redirects": list(self.redirects),
            "extra_info": dict(self.extra_info),
            "layers": {k: list(v) for k, v in self.layers.items()},
            "error": self.error,
        }


# ---------------------------------------------------------------------------
# The fingerprinter
# ---------------------------------------------------------------------------


class HTTPFingerprinter:
    """Asynchronous HTTP service fingerprinter.

    Usage::

        fp = HTTPFingerprinter()
        result = await fp.fingerprint("192.168.1.1", port=80)
        results = await fp.fingerprint_many([("10.0.0.5", 80), ("10.0.0.6", 443)])
    """

    def __init__(
        self,
        timeout: float = DEFAULT_TIMEOUT,
        concurrency: int = DEFAULT_CONCURRENCY,
        user_agent: str = DEFAULT_USER_AGENT,
        verify_tls: bool = False,   # LAN appliances rarely carry valid certs
        max_redirects: int = MAX_REDIRECTS,
        max_body_bytes: int = MAX_BODY_BYTES,
        overall_timeout: float = DEFAULT_OVERALL_TIMEOUT,
    ) -> None:
        self.timeout = timeout
        self.overall_timeout = overall_timeout
        self.user_agent = user_agent
        self.verify_tls = verify_tls
        self.max_redirects = max_redirects
        self.max_body_bytes = max_body_bytes
        self._sem = asyncio.Semaphore(max(1, concurrency))

    # -- public API ---------------------------------------------------------

    async def fingerprint(self, target: str, port: int = 80) -> HTTPFingerprint:
        """Fingerprint one HTTP(S) endpoint. Network failures are reported in
        `HTTPFingerprint.error` instead of raising."""
        scheme = "https" if port in (443, 8443, 8843, 9443) or target.lower().startswith("https://") else "http"
        try:
            host = _normalize_host(target)
        except ValueError as exc:
            result = HTTPFingerprint(target=target, port=port, scheme=scheme)
            result.error = str(exc)
            return result

        result = HTTPFingerprint(target=host, port=port, scheme=scheme)
        try:
            # hard cap over the whole multi-path probe (per-request timeouts stack)
            await asyncio.wait_for(
                self._probe(host, port, scheme, result), timeout=self.overall_timeout
            )
        except (asyncio.TimeoutError, TimeoutError) as exc:
            result.error = f"timeout after {self.timeout:.0f}s: {_short(exc)}"
        except aiohttp.ClientConnectorSSLError as exc:
            result.error = f"TLS/SSL handshake failed: {_short(exc)}"
        except aiohttp.ClientConnectorCertificateError as exc:
            result.error = f"TLS certificate rejected: {_short(exc)}"
        except ssl.SSLError as exc:
            result.error = f"TLS/SSL error: {_short(exc)}"
        except aiohttp.TooManyRedirects as exc:
            result.error = f"too many redirects (> {self.max_redirects}): {_short(exc)}"
        except aiohttp.ClientError as exc:
            result.error = f"http client error: {_short(exc)}"
        except OSError as exc:
            result.error = f"network error: {_short(exc)}"
        except Exception as exc:  # last-resort guard — never crash a scan loop
            result.error = f"unexpected error: {exc!r}"
        return result

    async def fingerprint_many(
        self, targets: list[tuple[str, int]]
    ) -> list[HTTPFingerprint]:
        """Fingerprint several (host, port) pairs concurrently (TaskGroup)."""
        async with asyncio.TaskGroup() as tg:
            tasks = [tg.create_task(self.fingerprint(h, p)) for h, p in targets]
        return [t.result() for t in tasks]

    # -- internals ----------------------------------------------------------

    async def _probe(self, host: str, port: int, scheme: str, result: HTTPFingerprint) -> None:
        timeout = aiohttp.ClientTimeout(total=self.timeout)
        connector = aiohttp.TCPConnector(
            ssl=_ssl_context(self.verify_tls), limit=32, enable_cleanup_closed=True
        )
        base = f"{scheme}://{host}" + (f":{port}" if port not in (80, 443) else "")
        headers = {"User-Agent": self.user_agent, "Accept": "*/*"}

        async with aiohttp.ClientSession(
            timeout=timeout, connector=connector, headers=headers
        ) as session:
            any_success = False
            robots_text = ""

            # ---- pass 1: layer-3 path probing, following redirects ----------
            for path in FINGERPRINT_PATHS:
                try:
                    async with self._sem, session.get(
                        base + path, allow_redirects=True, max_redirects=self.max_redirects
                    ) as resp:
                        any_success = True
                        if path == "/":
                            result.status_code = resp.status
                            result.server_header = resp.headers.get("Server")
                            result.redirects = tuple(str(h.url) for h in resp.history)
                            if resp.status in (401, 403):
                                self._score_auth(result, resp.headers.get("WWW-Authenticate", ""))
                            if resp.status == 200:
                                raw = await resp.content.read(self.max_body_bytes)
                                self._score_body(result, raw.decode("utf-8", errors="replace"))
                        elif path == "/robots.txt" and resp.status == 200:
                            raw = await resp.content.read(MAX_SIDECAR_BYTES)
                            robots_text = raw.decode("utf-8", errors="replace")
                        self._score_status(result, resp.status, path, robots_text)
                except (asyncio.TimeoutError, TimeoutError, aiohttp.ClientError, OSError, ssl.SSLError):
                    continue  # individual path failures are non-fatal

            if not any_success:
                raise aiohttp.ClientConnectionError(f"{scheme}://{host}:{port} unreachable")

            # ---- pass 2: layer-1 headers from the ORIGINAL (pre-redirect) response
            try:
                async with self._sem, session.get(base + "/", allow_redirects=False) as resp:
                    self._score_headers(result, resp.headers)
            except (asyncio.TimeoutError, TimeoutError, aiohttp.ClientError, OSError, ssl.SSLError):
                pass  # pass-1 evidence still stands

        self._finalize(result)

    # -- scoring helpers ----------------------------------------------------

    @staticmethod
    def _ev(evidence: list[str], note: str, service: str | None, pts: int) -> None:
        if service:
            evidence.append(f"{note} → {service} (+{pts})")
        else:
            evidence.append(f"{note} (+{pts})")

    def _score_headers(self, result: HTTPFingerprint, headers: Any) -> None:
        ev = result.layers.setdefault("headers", [])
        server = headers.get("Server")
        if server:
            result.server_header = server  # original (pre-redirect) header wins
            for service, rx in _RX_SERVER.items():
                if rx.search(server):
                    self._ev(ev, f"Server: '{_trim(server)}'", service, 30)
        cookies = "; ".join(headers.getall("Set-Cookie", [])) if hasattr(headers, "getall") else ""
        if cookies:
            for service, rx in _RX_COOKIE.items():
                if rx.search(cookies):
                    self._ev(ev, "Set-Cookie fingerprint", service, 20)
        powered = headers.get("X-Powered-By")
        if powered:
            for service, rx in _RX_POWERED.items():
                if rx.search(powered):
                    self._ev(ev, f"X-Powered-By: '{_trim(powered)}'", service, 10)
        if result.status_code in (401, 403):
            auth = headers.get("WWW-Authenticate", "")
            if _RX_WWW_AUTH_DIGEST.search(auth):
                self._ev(ev, "WWW-Authenticate digest", "HTTP digest auth (appliance)", 10)
            elif _RX_WWW_AUTH_BASIC.search(auth):
                self._ev(ev, "WWW-Authenticate basic", "HTTP basic auth", 6)

    def _score_auth(self, result: HTTPFingerprint, auth_header: str) -> None:
        # redirect-followed 401 evidence; pass 2 refines it with exact headers
        ev = result.layers.setdefault("status", [])
        if _RX_WWW_AUTH_DIGEST.search(auth_header):
            self._ev(ev, "WWW-Authenticate digest", "HTTP digest auth (appliance)", 10)
        elif _RX_WWW_AUTH_BASIC.search(auth_header):
            self._ev(ev, "WWW-Authenticate basic", "HTTP basic auth", 6)

    def _score_body(self, result: HTTPFingerprint, body: str) -> None:
        ev = result.layers.setdefault("body", [])
        m = _RX_META_GENERATOR.search(body)
        if m:
            self._ev(ev, f"<meta generator>: '{_trim(m.group(1))}'", None, 12)
        t = _RX_TITLE.search(body)
        if t:
            result.title = _trim(t.group(1).strip())
        for service, rx in _RX_JS_VARS.items():
            if rx.search(body):
                self._ev(ev, "JS variable / UI marker in HTML", service, 22)
        for service, rx in _RX_ENDPOINTS.items():
            if rx.search(body):
                self._ev(ev, "endpoint referenced in HTML", service, 18)
        self._extract_metadata(result, body)

    def _score_status(self, result: HTTPFingerprint, status: int, path: str, robots_text: str) -> None:
        ev = result.layers.setdefault("status", [])
        if path == "/":
            hint = STATUS_CODE_HINTS.get(status)
            if hint:
                self._ev(ev, f"status {status}: {hint[0]}", None, hint[1])
        elif path == "/robots.txt" and status == 200 and robots_text:
            if _RX_ROBOTS_WP.search(robots_text):
                self._ev(ev, "robots.txt disallows /wp-admin", "WordPress", 10)

    def _extract_metadata(self, result: HTTPFingerprint, body: str) -> None:
        info = result.extra_info
        macs = sorted(set(_RX_MAC.findall(body)))
        if macs:
            info["mac_addresses"] = macs[:4]
        for rx, key in (
            (_RX_SERIAL, "serial"),
            (_RX_MODEL, "model"),
            (_RX_HW_VERSION, "hardware_version"),
            (_RX_FIRMWARE, "firmware"),
        ):
            m = rx.search(body)
            if m:
                info.setdefault(key, _trim(m.group(1), 60))

    def _finalize(self, result: HTTPFingerprint) -> None:
        """Weighted confidence (0-100) and best service guess from evidence."""
        scores: dict[str, int] = {}
        caps = {"headers": W_HEADERS, "body": W_BODY, "status": W_STATUS}
        best_service, best_pts = "unknown", 0
        for layer, items in result.layers.items():
            cap = caps.get(layer)
            if cap is None:
                continue
            layer_score, layer_best_pts, layer_best_svc = 0, 0, None
            for item in items:
                pts_m = _RX_EV_POINTS.search(item)
                pts = int(pts_m.group(1)) if pts_m else 0
                layer_score = min(layer_score + pts, cap)
                svc_m = _RX_EV_SERVICE.search(item)
                if svc_m and pts > layer_best_pts:
                    layer_best_pts, layer_best_svc = pts, svc_m.group(1).strip()
            scores[layer] = layer_score
            if layer_best_svc and layer_best_pts > best_pts:
                best_pts, best_service = layer_best_pts, layer_best_svc
        result.service = best_service
        result.confidence_score = min(sum(scores.values()), 100)
        result.layers["__weights__"] = [
            f"headers {scores.get('headers', 0)}/{W_HEADERS}",
            f"body {scores.get('body', 0)}/{W_BODY}",
            f"status {scores.get('status', 0)}/{W_STATUS}",
        ]


# ---------------------------------------------------------------------------
# Small helpers
# ---------------------------------------------------------------------------


def _normalize_host(target: str) -> str:
    """Accept a bare host/IP or a full URL; return just the host part."""
    t = target.strip()
    if "://" in t:
        t = t.split("://", 1)[1]
    t = t.split("/", 1)[0]
    if not t:
        raise ValueError("empty target host")
    return t


def _ssl_context(verify: bool) -> ssl.SSLContext:
    ctx = ssl.create_default_context()
    if not verify:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    return ctx


def _short(exc: BaseException) -> str:
    s = str(exc).strip()
    return s if len(s) <= 160 else s[:157] + "..."


def _trim(s: str, n: int = 80) -> str:
    return s if len(s) <= n else s[: n - 3] + "..."


# ---------------------------------------------------------------------------
# CLI smoke test:  python3 http_fingerprinter.py <host> [port]
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import json as _json
    import sys

    if len(sys.argv) < 2:
        print("usage: python3 http_fingerprinter.py <host> [port]")
        raise SystemExit(2)

    _host_arg = sys.argv[1]
    _port_arg = int(sys.argv[2]) if len(sys.argv) > 2 else 80

    async def _main() -> None:
        fp = HTTPFingerprinter()
        _res = await fp.fingerprint(_host_arg, _port_arg)
        print(_json.dumps(_res.as_dict(), indent=2, ensure_ascii=False))

    asyncio.run(_main())
