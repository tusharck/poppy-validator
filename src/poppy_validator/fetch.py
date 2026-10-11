"""HTTP fetching with redirects followed by hand, so every hop can be checked.

The transport does one request and never follows redirects itself. Tests swap
in a fake transport; the CLI uses ``UrllibTransport``.
"""

from __future__ import annotations

import urllib.error
import urllib.request
from dataclasses import dataclass, field
from typing import Protocol
from urllib.parse import urljoin, urlsplit

from poppy_validator import __version__

# Section 3 sets no redirect limit. This cap only stops the validator chasing an
# endless chain; it matches the WHATWG Fetch limit browsers use. Hitting it means
# "not checked", never "invalid" (see T007).
MAX_REDIRECTS = 20
MAX_BYTES = 1_000_000
REDIRECT_CODES = {301, 302, 303, 307, 308}


class TransportError(Exception):
    """The request couldn't be made: DNS, TLS, timeout, refused connection."""


@dataclass
class Response:
    status: int
    url: str
    body: bytes = b""
    headers: dict[str, str] = field(default_factory=dict)

    def header(self, name: str) -> str | None:
        return self.headers.get(name.lower())


class Transport(Protocol):
    def get(self, url: str) -> Response: ...


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Hand every 3xx back as an HTTPError, untouched.

    HTTPRedirectHandler parses the Location header before redirect_request runs,
    so a malformed one (``https://[``) raised ValueError there and looked like a
    network failure. fetch() resolves and checks Location itself (T002).
    """

    def http_error_302(self, req, fp, code, msg, headers):
        return None  # the default error handler then raises HTTPError with the 3xx

    http_error_301 = http_error_303 = http_error_307 = http_error_308 = http_error_302


class UrllibTransport:
    def __init__(self, timeout: float = 10.0) -> None:
        self.timeout = timeout
        self._opener = urllib.request.build_opener(_NoRedirect())

    def get(self, url: str) -> Response:
        request = urllib.request.Request(
            url,
            headers={"Accept": "application/json", "User-Agent": f"poppy-validator/{__version__}"},
        )
        try:
            with self._opener.open(request, timeout=self.timeout) as resp:
                return Response(resp.status, url, resp.read(MAX_BYTES), _lower(resp.headers))
        except urllib.error.HTTPError as err:  # 3xx (redirects disabled), 4xx, 5xx
            body = err.read(MAX_BYTES) if err.fp else b""
            return Response(err.code, url, body, _lower(err.headers))
        except (urllib.error.URLError, OSError, ValueError) as err:
            reason = getattr(err, "reason", err)
            raise TransportError(str(reason)) from err


def _lower(headers) -> dict[str, str]:
    return {k.lower(): v for k, v in headers.items()} if headers else {}


@dataclass
class FetchResult:
    response: Response | None
    final_url: str
    hops: list[tuple[int, str]]  # (status, location) for each redirect followed
    problem: str | None = None  # "fetch" | "insecure_redirect" | "malformed_redirect" | "redirect_loop" | "redirect_cap"
    message: str | None = None


def fetch(url: str, transport: Transport) -> FetchResult:
    """GET ``url``, following redirects only to HTTPS URLs, as section 3 requires."""
    hops: list[tuple[int, str]] = []
    seen = {url}
    current = url
    while True:
        try:
            resp = transport.get(current)
        except TransportError as err:
            return FetchResult(None, current, hops, "fetch", f"could not fetch {current}: {err}")
        if resp.status in REDIRECT_CODES:
            location = resp.header("location")
            if not location:
                return FetchResult(
                    None, current, hops, "fetch", f"{current} answered HTTP {resp.status} without a Location header"
                )
            try:
                target = urljoin(current, location)
                parts = urlsplit(target)
                parts.port  # raises for a non-numeric or out-of-range port
            except ValueError as err:
                return FetchResult(
                    None,
                    current,
                    hops,
                    "malformed_redirect",
                    f"{current} redirects (HTTP {resp.status}) to {location!r}, which isn't a parseable URL "
                    f"({err}); every redirect MUST be to an HTTPS URL, so Personal Agents stop here",
                )
            if parts.scheme != "https":
                return FetchResult(
                    None,
                    current,
                    hops,
                    "insecure_redirect",
                    f"{current} redirects (HTTP {resp.status}) to {target}, which is not HTTPS; "
                    "every redirect MUST be to an HTTPS URL, so Personal Agents stop here",
                )
            if target in seen:
                return FetchResult(None, current, hops, "redirect_loop", f"redirect loop: {current} -> {target}")
            if len(hops) == MAX_REDIRECTS:
                # final_url stays the last URL actually fetched; target was never requested.
                return FetchResult(
                    None,
                    current,
                    hops,
                    "redirect_cap",
                    f"followed {len(hops)} redirects from {url} without reaching a document; the last URL "
                    f"fetched, {current}, redirects again (HTTP {resp.status}) to {target}, which was not "
                    "requested. The spec sets no limit, so this is the validator's own safeguard and the "
                    "chain may still end",
                )
            hops.append((resp.status, target))
            seen.add(target)
            current = target
            continue
        if not 200 <= resp.status < 300:
            return FetchResult(resp, current, hops, "fetch", f"{current} answered HTTP {resp.status}")
        return FetchResult(resp, current, hops)
