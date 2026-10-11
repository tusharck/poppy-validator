from __future__ import annotations

import json
from pathlib import Path

import pytest

from poppy_validator.fetch import Response, TransportError

FIXTURES = Path(__file__).parent / "fixtures"


def fixture_text(relpath: str) -> str:
    return (FIXTURES / relpath).read_text()


def fixture_json(relpath: str):
    return json.loads(fixture_text(relpath))


class FakeTransport:
    """Serves canned responses by URL. Unknown URLs fail like DNS would."""

    def __init__(self, routes: dict[str, Response | Exception] | None = None) -> None:
        self.routes = dict(routes or {})
        self.requested: list[str] = []

    def json(self, url: str, body, status: int = 200, headers: dict | None = None) -> "FakeTransport":
        text = body if isinstance(body, str) else json.dumps(body)
        hdrs = {"content-type": "application/json", "cache-control": "max-age=300", **(headers or {})}
        self.routes[url] = Response(status, url, text.encode(), {k.lower(): v for k, v in hdrs.items()})
        return self

    def redirect(self, url: str, location: str, status: int = 301) -> "FakeTransport":
        self.routes[url] = Response(status, url, b"", {"location": location})
        return self

    def get(self, url: str) -> Response:
        self.requested.append(url)
        route = self.routes.get(url)
        if route is None:
            raise TransportError(f"no route to {url}")
        if isinstance(route, Exception):
            raise route
        return route


@pytest.fixture
def example_doc():
    return fixture_json("valid/example.com.poppy.json")


@pytest.fixture
def example_meta():
    return fixture_json("oauth/example.com.json")


@pytest.fixture
def live_example(example_doc, example_meta) -> FakeTransport:
    """example.com serving the spec's document and metadata, as the spec shows them."""
    return (
        FakeTransport()
        .json("https://example.com/.well-known/poppy.json", example_doc)
        .json("https://auth.example.com/.well-known/oauth-authorization-server", example_meta)
    )
