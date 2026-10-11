"""The real urllib transport against a local HTTP server (no fake transport).

FakeTransport hands fetch() a ready-made Response, so it can't catch problems
inside urllib's own response handling. These tests send real requests.
"""

from __future__ import annotations

import http.server
import json
import threading

import pytest

from conftest import fixture_text
from poppy_validator.fetch import Response, UrllibTransport, fetch
from poppy_validator.rules import Severity
from poppy_validator.validator import validate_url

WK = "https://example.com/.well-known/poppy.json"

ROUTES = {
    "/.well-known/poppy.json": (302, {"Location": "https://["}, b""),  # audit round 3, N1
    "/good-redirect": (302, {"Location": "https://example.com/doc"}, b""),
    "/doc": (200, {"Content-Type": "application/json", "Cache-Control": "max-age=60"}, None),
}


class _Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        status, headers, body = ROUTES.get(self.path, (404, {}, b""))
        body = fixture_text("valid/example.com.poppy.json").encode() if body is None else body
        self.send_response(status)
        for name, value in headers.items():
            self.send_header(name, value)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


@pytest.fixture(scope="module")
def server():
    srv = http.server.HTTPServer(("127.0.0.1", 0), _Handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{srv.server_port}"
    srv.shutdown()
    srv.server_close()


class _LocalRouter:
    """The real UrllibTransport, with https://example.com rewritten to the local server.

    Only the host changes: the request, the 3xx handling, and the Response all
    come from urllib.
    """

    def __init__(self, base: str) -> None:
        self.base = base
        self.real = UrllibTransport(timeout=5)
        self.requested: list[str] = []

    def get(self, url: str) -> Response:
        self.requested.append(url)
        resp = self.real.get(url.replace("https://example.com", self.base, 1))
        return Response(resp.status, url, resp.body, resp.headers)


def test_urllib_returns_a_malformed_location_instead_of_raising(server):
    resp = UrllibTransport(timeout=5).get(f"{server}/.well-known/poppy.json")
    assert resp.status == 302 and resp.header("location") == "https://["


def test_malformed_location_through_urllib_stops_with_a_redirect_problem(server):
    url = f"{server}/.well-known/poppy.json"
    result = fetch(url, UrllibTransport(timeout=5))
    assert result.problem == "malformed_redirect"
    assert result.final_url == url and result.hops == []
    assert "isn't a parseable URL" in result.message


def test_malformed_location_through_urllib_is_a_t002_finding(server):
    transport = _LocalRouter(server)
    report = validate_url("example.com", transport=transport)
    assert report.rule_ids() == {"T002"}
    assert report.rule_ids(Severity.ERROR) == {"T002"}
    assert report.final_url == WK  # the chain stops at the sending URL
    assert transport.requested == [WK]
    assert report.checks == {"transport": "failed", "document": "skipped", "oauth": "skipped"}
    data = report.to_dict()
    assert data["valid"] is False and data["findings"][0]["message"].startswith(f"{WK} redirects (HTTP 302) to 'https://['")


def test_valid_redirect_still_works_through_urllib(server):
    transport = _LocalRouter(server)
    result = fetch("https://example.com/good-redirect", transport)
    assert result.problem is None and result.hops == [(302, "https://example.com/doc")]
    assert json.loads(result.response.body)["organization"]["domain"] == "example.com"
