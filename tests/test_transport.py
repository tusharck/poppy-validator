"""Section 3: location, HTTPS, and redirects (fetch mode, with a fake transport)."""

from __future__ import annotations

import pytest

from conftest import FakeTransport
from poppy_validator.fetch import MAX_REDIRECTS, Response
from poppy_validator.output import render
from poppy_validator.rules import Severity
from poppy_validator.validator import validate_url, well_known_url

WK = "https://example.com/.well-known/poppy.json"
META = "https://auth.example.com/.well-known/oauth-authorization-server"
ERROR, WARNING, INFO = Severity.ERROR, Severity.WARNING, Severity.INFO


def test_live_spec_example_passes_everything(live_example):
    report = validate_url("example.com", transport=live_example)
    assert report.passed(strict=True), [f.to_dict() for f in report.findings]
    assert report.checks == {"transport": "passed", "document": "passed", "oauth": "passed"}
    assert live_example.requested == [WK, "https://auth.example.com/.well-known/oauth-authorization-server"]


def test_domain_and_urls_map_to_the_well_known_location():
    assert well_known_url("example.com") == (WK, True)
    assert well_known_url("https://example.com") == (WK, True)
    assert well_known_url("https://example.com/") == (WK, True)
    assert well_known_url(WK) == (WK, True)
    assert well_known_url("https://cdn.example.net/poppy.json") == ("https://cdn.example.net/poppy.json", False)


def test_https_redirects_are_followed_and_domain_uses_requested_host(example_doc, example_meta):
    hosted = "https://poppy-host.example.net/sites/example/poppy.json"
    transport = (
        FakeTransport()
        .redirect(WK, "https://www.example.com/.well-known/poppy.json", 301)
        .redirect("https://www.example.com/.well-known/poppy.json", hosted, 302)
        .json(hosted, example_doc)
        .json("https://auth.example.com/.well-known/oauth-authorization-server", example_meta)
    )
    report = validate_url("example.com", transport=transport)
    assert report.passed()
    assert report.final_url == hosted
    assert "T004" in report.rule_ids(INFO)
    assert "O002" not in report.rule_ids()  # served from poppy-host.example.net, but requested example.com


def test_relative_redirect_is_resolved(example_doc):
    transport = FakeTransport().redirect(WK, "/poppy/v1.json", 308).json("https://example.com/poppy/v1.json", example_doc)
    report = validate_url("example.com", oauth=False, transport=transport)
    assert report.passed()


def test_redirect_to_http_is_an_error(example_doc):
    transport = (
        FakeTransport()
        .redirect(WK, "http://example.com/poppy.json", 302)
        .json("http://example.com/poppy.json", example_doc)
    )
    report = validate_url("example.com", transport=transport)
    assert "T002" in report.rule_ids(ERROR)
    assert transport.requested == [WK]  # Personal Agents MUST NOT follow it, so neither do we
    assert report.checks["transport"] == "failed"


def test_later_redirect_hop_to_http_is_an_error(example_doc):
    transport = (
        FakeTransport()
        .redirect(WK, "https://cdn.example.net/poppy.json")
        .redirect("https://cdn.example.net/poppy.json", "http://cdn.example.net/poppy.json")
    )
    report = validate_url("example.com", transport=transport)
    assert "T002" in report.rule_ids(ERROR)


def test_redirect_loop_is_an_error():
    transport = FakeTransport().redirect(WK, "https://www.example.com/x").redirect("https://www.example.com/x", WK)
    report = validate_url("example.com", transport=transport)
    assert "T003" in report.rule_ids(ERROR)


def chain(transport: FakeTransport, hops: int) -> str:
    """WK -> hop0 -> hop1 ... over HTTPS; returns the last URL."""
    url = WK
    for i in range(hops):
        nxt = f"https://cdn.example.net/hop{i}"
        transport.redirect(url, nxt)
        url = nxt
    return url


def test_eleven_https_redirects_are_followed(example_doc, example_meta):
    # audit F1 (eleven-redirects): section 3 sets no hop limit, so this is not an error
    transport = FakeTransport().json(META, example_meta)
    transport.json(chain(transport, 11), example_doc)
    report = validate_url("example.com", transport=transport)
    assert report.passed(strict=True), [f.to_dict() for f in report.findings]
    assert report.complete
    assert report.rule_ids() == {"T004"}


def test_hop_safeguard_reports_incomplete_not_invalid():
    transport = FakeTransport()
    chain(transport, MAX_REDIRECTS + 5)
    report = validate_url("example.com", transport=transport)
    assert report.rule_ids() == {"T007"}
    assert report.rule_ids(WARNING) == {"T007"}
    assert report.checks == {"transport": "incomplete", "document": "skipped", "oauth": "skipped"}
    assert report.passed() and not report.passed(strict=True)
    assert report.complete is False
    assert report.to_dict()["complete"] is False
    assert "▲ incomplete" in render(report, color=False)


def test_hop_safeguard_reports_the_last_url_actually_fetched():
    # audit round 2, N4: 21 redirects; the 21st destination is never requested, so it isn't final_url
    transport = FakeTransport()
    chain(transport, MAX_REDIRECTS + 1)
    report = validate_url("example.com", transport=transport)
    last_fetched = f"https://cdn.example.net/hop{MAX_REDIRECTS - 1}"
    unrequested = f"https://cdn.example.net/hop{MAX_REDIRECTS}"
    assert len(transport.requested) == MAX_REDIRECTS + 1  # the well-known URL plus 20 redirects
    assert transport.requested[-1] == last_fetched and unrequested not in transport.requested
    assert report.final_url == last_fetched
    (t007,) = report.findings
    assert f"followed {MAX_REDIRECTS} redirects" in t007.message
    assert f"{unrequested}, which was not requested" in t007.message
    text = render(report, color=False)
    assert f"halted at  {last_fetched}" in text and "served by" not in text


def test_twenty_redirects_still_reach_the_document(example_doc):
    transport = FakeTransport()
    transport.json(chain(transport, MAX_REDIRECTS), example_doc)
    report = validate_url("example.com", oauth=False, transport=transport)
    assert report.complete and report.passed()
    assert "served by" in render(report, color=False)


def test_failed_redirect_chain_is_not_labelled_served_by():
    transport = FakeTransport().redirect(WK, "http://cdn.example.net/poppy.json")
    text = render(validate_url("example.com", transport=transport), color=False)
    assert "served by" not in text


def test_hop_safeguard_on_metadata_is_incomplete_too(example_doc):
    transport = FakeTransport().json(WK, example_doc)
    url = META
    for i in range(MAX_REDIRECTS + 1):
        nxt = f"https://auth.example.com/hop{i}"
        transport.redirect(url, nxt)
        url = nxt
    report = validate_url("example.com", transport=transport)
    assert report.rule_ids(ERROR) == set()
    assert "T007" in report.rule_ids(WARNING)
    assert report.checks["oauth"] == "incomplete"


# audit round 2, N1: malformed URLs become findings, never tracebacks
MALFORMED_TARGETS = ["https://[", "https://example.com:bad", "https://example.com:65536/"]


@pytest.mark.parametrize("target", MALFORMED_TARGETS)
def test_malformed_target_is_a_t001_finding(target):
    transport = FakeTransport()
    report = validate_url(target, transport=transport)
    assert report.rule_ids() == {"T001"}
    assert "isn't a parseable URL" in report.findings[0].message
    assert report.checks == {"transport": "failed", "document": "skipped", "oauth": "skipped"}
    assert report.passed() is False
    assert transport.requested == []


@pytest.mark.parametrize("location", ["https://[", "https://cdn.example.net:bad/poppy.json"])
def test_malformed_redirect_location_is_a_t002_finding(location):
    transport = FakeTransport().redirect(WK, location, 302)
    report = validate_url("example.com", transport=transport)
    assert report.rule_ids() == {"T002"}
    assert "isn't a parseable URL" in report.findings[0].message
    assert report.checks == {"transport": "failed", "document": "skipped", "oauth": "skipped"}
    assert report.final_url == WK
    assert transport.requested == [WK]  # the chain stops; nothing past the bad Location is fetched


def test_malformed_redirect_on_metadata_is_an_oauth_failure(example_doc):
    transport = FakeTransport().json(WK, example_doc).redirect(META, "https://[")
    report = validate_url("example.com", transport=transport)
    assert report.rule_ids(ERROR) == {"OA01"}
    assert report.checks["oauth"] == "failed"


def test_404_is_an_error():
    transport = FakeTransport().json(WK, {"error": "not found"}, status=404)
    report = validate_url("example.com", transport=transport)
    assert "T001" in report.rule_ids(ERROR)
    assert report.checks["document"] == "skipped"


def test_unreachable_host_is_an_error():
    report = validate_url("example.com", transport=FakeTransport())
    assert "T001" in report.rule_ids(ERROR)


def test_redirect_without_location_is_an_error():
    transport = FakeTransport({WK: Response(302, WK, b"", {})})
    report = validate_url("example.com", transport=transport)
    assert "T001" in report.rule_ids(ERROR)


def test_plain_http_url_is_an_error(example_doc):
    transport = FakeTransport().json("http://example.com/.well-known/poppy.json", example_doc)
    report = validate_url("http://example.com/.well-known/poppy.json", oauth=False, transport=transport)
    assert "T001" in report.rule_ids(ERROR)


def test_non_json_body_is_an_error():
    transport = FakeTransport().json(WK, "<html>hello</html>")
    report = validate_url("example.com", transport=transport)
    assert "J001" in report.rule_ids(ERROR)


def test_live_json_null_is_an_error():
    # audit F2 (live-null): the server answers 200 with the JSON literal null
    transport = FakeTransport().json(WK, "null")
    report = validate_url("example.com", transport=transport)
    assert report.rule_ids(ERROR) == {"J001"}
    assert report.checks == {"transport": "passed", "document": "failed", "oauth": "skipped"}
    assert report.passed() is False


def test_domain_mismatch_on_live_fetch(example_doc):
    transport = FakeTransport().json("https://example.org/.well-known/poppy.json", example_doc)
    report = validate_url("example.org", oauth=False, transport=transport)
    assert "O002" in report.rule_ids(ERROR)


def test_www_host_matches_bare_domain(example_doc):
    transport = FakeTransport().json("https://www.example.com/.well-known/poppy.json", example_doc)
    report = validate_url("www.example.com", oauth=False, transport=transport)
    assert "O002" not in report.rule_ids()


def test_missing_cache_headers_is_deployment_advice(example_doc):
    # audit F8: the caching SHOULD binds Personal Agents, so this is not a Company-side violation
    transport = FakeTransport().json(WK, example_doc, headers={"cache-control": ""})
    report = validate_url("example.com", oauth=False, transport=transport)
    (finding,) = [f for f in report.findings if f.rule.id == "T005"]
    assert finding.severity is INFO and finding.rule.basis == "context"
    assert finding.message.startswith("deployment advice, not a spec violation")
    assert "SHOULD" not in finding.message and "SHOULD" not in finding.rule.title
    assert report.passed(strict=True)


def test_non_well_known_url_checks_document_only(example_doc):
    url = "https://staging.example.net/poppy.json"
    transport = FakeTransport().json(url, example_doc)
    report = validate_url(url, oauth=False, transport=transport)
    assert "T006" in report.rule_ids(INFO)
    assert "O005" in report.rule_ids(INFO)  # no requested host to compare with
    report = validate_url(url, domain="example.org", oauth=False, transport=transport)
    assert "O002" in report.rule_ids(ERROR)


def test_no_network_skips_oauth(live_example):
    report = validate_url("example.com", oauth=False, transport=live_example)
    assert report.checks["oauth"] == "skipped"
    assert "OA10" in report.rule_ids(INFO)
    assert len(live_example.requested) == 1
