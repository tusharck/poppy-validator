"""Section 3.2: cross-check poppy.json against the issuer's RFC 8414 metadata."""

from __future__ import annotations

import json
from urllib.parse import urlsplit

from poppy_validator.checks import is_https_url, normalize_host
from poppy_validator.fetch import Transport, fetch
from poppy_validator.report import Report

WELL_KNOWN = "/.well-known/oauth-authorization-server"
ENDPOINTS = ("token_endpoint", "revocation_endpoint", "authorization_endpoint", "device_authorization_endpoint")


def metadata_urls(issuer: str) -> tuple[str, str]:
    """Return (RFC 8414 URL, appended URL).

    RFC 8414 section 3.1 inserts the well-known segment between the host and
    any issuer path. For an issuer without a path, both forms are the same.
    """
    parts = urlsplit(issuer)
    path = parts.path.rstrip("/")
    rfc = f"https://{parts.netloc}{WELL_KNOWN}{path}"
    appended = issuer.rstrip("/") + WELL_KNOWN
    return rfc, appended


def cross_check(doc: dict, report: Report, transport: Transport) -> None:
    auth = doc.get("auth")
    if not isinstance(auth, dict):
        report.add("OA10", "OAuth cross-check skipped: the document has no auth")
        report.checks["oauth"] = "skipped"
        return
    issuer = auth.get("issuer")
    if not is_https_url(issuer):
        # The document checks already report this as A001/A002, an error. Without a
        # usable issuer the cross-check can't pass, so it fails rather than reporting
        # an OA10 skip that would read as "not checked" instead of "broken".
        report.checks["oauth"] = "failed"
        return

    before = report.errors
    parts = urlsplit(issuer)
    if parts.query or parts.fragment:
        # Section 3.2 requires RFC 8414 metadata, and RFC 8414 section 2 defines the issuer
        # identifier as an https URL with no query or fragment. Metadata that echoes such an
        # issuer can't conform, even when it matches exactly. The rest of the check still runs.
        report.add(
            "OA11",
            f"auth.issuer {issuer!r} has a {'query' if parts.query else 'fragment'}; an RFC 8414 issuer "
            "identifier has no query or fragment (RFC 8414 section 2), so no conforming metadata can "
            "name it. Use the issuer without it",
            "/auth/issuer",
        )
    rfc_url, appended_url = metadata_urls(issuer)
    result = fetch(rfc_url, transport)
    if result.problem == "redirect_cap":
        report.add("T007", f"OAuth metadata: {result.message}", "/auth/issuer")
        report.checks["oauth"] = "incomplete"
        return
    if result.problem and appended_url != rfc_url:
        fallback = fetch(appended_url, transport)
        if not fallback.problem:
            # Publication at the wrong place doesn't meet the section 3.2 MUST, so this
            # is still OA01. The rest of the cross-check runs on the misplaced copy, so
            # the fix list is complete after one run.
            report.add("OA01", f"auth.issuer MUST publish RFC 8414 metadata: {result.message}", "/auth/issuer")
            report.add(
                "OA09",
                f"metadata was found at {appended_url}, which appends the well-known segment to the issuer "
                f"path; RFC 8414 inserts it before the path, so clients look at {rfc_url}. Serve it there "
                "(the checks below use the misplaced copy)",
                "/auth/issuer",
            )
            result = fallback
    if result.problem:
        report.add("OA01", f"auth.issuer MUST publish RFC 8414 metadata: {result.message}", "/auth/issuer")
        report.checks["oauth"] = "failed"
        return

    try:
        meta = json.loads(result.response.body)
    except (ValueError, UnicodeDecodeError) as err:
        report.add("OA01", f"metadata at {result.final_url} is not valid JSON: {err}", "/auth/issuer")
        report.checks["oauth"] = "failed"
        return
    if not isinstance(meta, dict):
        report.add("OA01", f"metadata at {result.final_url} is not a JSON object", "/auth/issuer")
        report.checks["oauth"] = "failed"
        return

    if meta.get("issuer") != issuer:
        report.add(
            "OA02",
            f"metadata issuer is {meta.get('issuer')!r} but auth.issuer is {issuer!r}; they MUST match exactly",
            "/auth/issuer",
        )

    org = doc.get("organization")
    domain = org.get("domain") if isinstance(org, dict) else None
    domains = meta.get("poppy_domains")
    if not isinstance(domains, list):
        report.add(
            "OA03",
            f"metadata at {result.final_url} has no poppy_domains list; it MUST list every domain whose "
            "poppy.json names this issuer",
            "/organization/domain",
        )
    elif isinstance(domain, str):
        # Same comparison as O002: case-insensitive, ignoring a trailing dot and a leading www.
        listed = {normalize_host(d) for d in domains if isinstance(d, str)}
        if normalize_host(domain) not in listed:
            report.add(
                "OA03",
                f"metadata poppy_domains {domains!r} doesn't include organization.domain {domain!r}; "
                "otherwise any domain could claim this issuer",
                "/organization/domain",
            )

    required = {"token_endpoint": ("OA04", None), "revocation_endpoint": ("OA05", None)}
    if "direct" in auth:
        required["authorization_endpoint"] = ("OA06", "auth.direct is present")
    if "device" in auth:
        required["device_authorization_endpoint"] = ("OA07", "auth.device is present")
    for key, (rule, why) in required.items():
        if not isinstance(meta.get(key), str) or not meta[key]:
            reason = f" because {why}" if why else ""
            report.add(rule, f"metadata has no {key}{reason}", "/auth")

    for key in ENDPOINTS:
        value = meta.get(key)
        if isinstance(value, str) and value and not is_https_url(value):
            report.add("OA08", f"metadata {key} {value!r} is not an HTTPS URL", "/auth")

    report.checks["oauth"] = "failed" if report.errors > before else "passed"
