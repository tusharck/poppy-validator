"""Entry points: validate a document from a file, text, or a live domain/URL."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from poppy_validator.checks import check_document, is_hostname
from poppy_validator.fetch import Transport, UrllibTransport, fetch
from poppy_validator.oauth import cross_check
from poppy_validator.report import Report

WELL_KNOWN_PATH = "/.well-known/poppy.json"
CACHE_HEADERS = ("cache-control", "expires", "etag", "last-modified")

# Returned by _parse when the text isn't JSON. JSON null parses to None, which is
# a real (invalid) document, so None can't double as the failure signal.
PARSE_FAILED = object()


def _parse(text: str | bytes, report: Report, source: str) -> Any:
    try:
        return json.loads(text)
    except (ValueError, UnicodeDecodeError) as err:
        report.add("J001", f"{source} is not valid JSON: {err}")
        return PARSE_FAILED


def _finish(
    doc: Any,
    report: Report,
    requested_host: str | None,
    oauth: bool,
    transport: Transport | None,
    oauth_skip_reason: str,
) -> Report:
    before = report.errors
    check_document(doc, report, requested_host)
    report.checks["document"] = "failed" if report.errors > before else "passed"
    if not isinstance(doc, dict):
        report.checks["oauth"] = "skipped"
    elif oauth:
        cross_check(doc, report, transport or UrllibTransport())
    else:
        report.add("OA10", f"OAuth cross-check skipped: {oauth_skip_reason}")
        report.checks["oauth"] = "skipped"
    return report


def validate_text(
    text: str | bytes,
    *,
    target: str = "<stdin>",
    domain: str | None = None,
    oauth: bool = False,
    transport: Transport | None = None,
) -> Report:
    """Validate a document's text. ``domain`` stands in for the requested host."""
    report = Report(target=target, mode="file")
    report.checks["transport"] = "skipped"
    doc = _parse(text, report, target)
    if doc is PARSE_FAILED:
        report.checks["document"] = "failed"
        report.checks["oauth"] = "skipped"
        return report
    return _finish(doc, report, domain, oauth, transport, "local file (pass --check-oauth to run it)")


def validate_file(path: str | Path, **kwargs) -> Report:
    path = Path(path)
    return validate_text(path.read_bytes(), target=str(path), **kwargs)


def well_known_url(target: str) -> tuple[str, bool]:
    """Turn a domain or URL into the URL to fetch. Returns (url, is_well_known)."""
    if "://" not in target:
        return f"https://{target.strip().rstrip('/')}{WELL_KNOWN_PATH}", True
    try:
        parts = urlsplit(target)
    except ValueError:
        return target, False  # validate_url reports it as T001
    if parts.path in ("", "/") and not parts.query:
        return f"{parts.scheme}://{parts.netloc}{WELL_KNOWN_PATH}", True
    return target, parts.path == WELL_KNOWN_PATH and not parts.query


def validate_url(
    target: str,
    *,
    domain: str | None = None,
    oauth: bool = True,
    transport: Transport | None = None,
) -> Report:
    """Fetch and validate a live document. ``target`` is a domain or URL."""
    transport = transport or UrllibTransport()
    url, is_well_known = well_known_url(target)
    report = Report(target=target, mode="url", requested_url=url)
    try:
        parts = urlsplit(url)
        port = parts.port  # raises for a non-numeric or out-of-range port
    except ValueError as err:
        report.add(
            "T001",
            f"{url} isn't a parseable URL ({err}); the document MUST be served at "
            f"https://{{domain}}{WELL_KNOWN_PATH}",
        )
        report.checks.update(transport="failed", document="skipped", oauth="skipped")
        return report
    host = parts.hostname or ""

    if parts.scheme != "https":
        report.add("T001", f"{url} is not HTTPS; the document MUST be served over HTTPS")
    if port is not None and port != 443:
        report.add("T001", f"{url} uses port {port}; the well-known URL is https://{{domain}}{WELL_KNOWN_PATH}")
    if not is_well_known:
        report.add(
            "T006",
            f"{url} is not a well-known location, so it is checked as a document only; Personal Agents "
            f"look at https://{host}{WELL_KNOWN_PATH} (pass --domain to check organization.domain)",
        )

    result = fetch(url, transport)
    report.final_url = result.final_url
    if result.problem == "redirect_cap":
        report.add("T007", result.message)
        report.checks.update(transport="incomplete", document="skipped", oauth="skipped")
        return report
    if result.problem:
        rule = {
            "fetch": "T001", "insecure_redirect": "T002", "malformed_redirect": "T002", "redirect_loop": "T003",
        }[result.problem]
        report.add(rule, result.message)
        report.checks.update(transport="failed", document="skipped", oauth="skipped")
        return report
    report.checks["transport"] = "failed" if report.errors else "passed"

    if result.hops:
        chain = " -> ".join([url] + [loc for _, loc in result.hops])
        report.add(
            "T004",
            f"followed {len(result.hops)} redirect(s): {chain}; organization.domain is checked against "
            f"{host!r}, the host that was requested",
        )
    if not any(result.response.header(h) for h in CACHE_HEADERS):
        report.add(
            "T005",
            "deployment advice, not a spec violation: the response has no Cache-Control, Expires, ETag, or "
            "Last-Modified header. The spec asks Personal Agents to cache by these headers, so without them "
            "each agent picks its own refresh policy",
        )

    doc = _parse(result.response.body, report, result.final_url)
    if doc is PARSE_FAILED:
        report.checks.update(document="failed", oauth="skipped")
        return report
    requested_host = host if is_well_known else domain
    return _finish(doc, report, requested_host, oauth, transport, "--no-network")


def looks_like_domain(value: str) -> bool:
    return is_hostname(value, need_dot=True)
