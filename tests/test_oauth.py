"""Section 3.2: the OAuth server metadata cross-check."""

from __future__ import annotations

import json

import pytest

from conftest import FakeTransport, fixture_json
from poppy_validator.oauth import metadata_urls
from poppy_validator.rules import Severity
from poppy_validator.validator import validate_text, validate_url

WK = "https://example.com/.well-known/poppy.json"
META = "https://auth.example.com/.well-known/oauth-authorization-server"
ERROR, WARNING = Severity.ERROR, Severity.WARNING


def run(doc, meta, **routes):
    transport = FakeTransport().json(WK, doc)
    if meta is not None:
        transport.json(META, meta)
    return validate_url("example.com", transport=transport)


@pytest.mark.parametrize(
    "fixture, rule",
    [
        ("issuer-mismatch", "OA02"),
        ("domain-not-listed", "OA03"),
        ("no-poppy-domains", "OA03"),
        ("no-token-endpoint", "OA04"),
        ("no-revocation-endpoint", "OA05"),
        ("no-authorization-endpoint", "OA06"),
        ("no-device-endpoint", "OA07"),
    ],
)
def test_metadata_fixture_errors(example_doc, fixture, rule):
    report = run(example_doc, fixture_json(f"oauth/{fixture}.json"))
    assert rule in report.rule_ids(ERROR), [f.to_dict() for f in report.findings]
    assert report.rule_ids(ERROR) == {rule}
    assert report.checks["oauth"] == "failed"


@pytest.mark.parametrize("fixture, suffix", [("issuer-with-query", "?x=1"), ("issuer-with-fragment", "#x")])
def test_issuer_with_query_or_fragment_fails_the_cross_check(example_doc, fixture, suffix):
    # audit round 2, N2: document and metadata issuers match exactly, but neither is an RFC 8414 issuer
    example_doc["auth"]["issuer"] += suffix
    meta = fixture_json(f"oauth/{fixture}.json")
    assert meta["issuer"] == example_doc["auth"]["issuer"]
    report = run(example_doc, meta)
    assert report.rule_ids(ERROR) == {"OA11"}
    assert "OA02" not in report.rule_ids()  # the issuers do match; that isn't the problem
    assert report.checks["oauth"] == "failed" and report.passed() is False
    (a003,) = [f for f in report.findings if f.rule.id == "A003"]
    assert "can't match" not in a003.message and "isn't a conforming RFC 8414 issuer" in a003.message


def test_issuer_query_is_advisory_only_without_the_cross_check(example_doc):
    # local-file mode keeps A003 as advisory info; OA11 needs the cross-check
    example_doc["auth"]["issuer"] += "?x=1"
    report = validate_text(json.dumps(example_doc), domain="example.com")
    assert "A003" in report.rule_ids(Severity.INFO) and "OA11" not in report.rule_ids()
    assert report.passed() and not report.passed(strict=True)


def test_issuer_query_with_check_oauth_on_a_file_is_an_error(example_doc):
    example_doc["auth"]["issuer"] += "?x=1"
    meta = fixture_json("oauth/issuer-with-query.json")
    transport = FakeTransport().json(META, meta)
    report = validate_text(json.dumps(example_doc), domain="example.com", oauth=True, transport=transport)
    assert report.rule_ids(ERROR) == {"OA11"} and report.checks["oauth"] == "failed"


def test_issuer_trailing_slash_is_not_an_exact_match(example_doc):
    report = run(example_doc, fixture_json("oauth/issuer-mismatch.json"))
    (finding,) = [f for f in report.findings if f.rule.id == "OA02"]
    assert "'https://auth.example.com/'" in finding.message


def test_direct_sign_in_without_authorization_endpoint(example_doc, example_meta):
    del example_meta["authorization_endpoint"]
    assert "OA06" in run(example_doc, example_meta).rule_ids(ERROR)
    # Without auth.direct, the endpoint isn't required.
    del example_doc["auth"]["direct"]
    example_doc["auth"]["custom_scopes"] = {}
    assert "OA06" not in run(example_doc, example_meta).rule_ids()


def test_device_endpoint_only_required_with_device_sign_in(example_doc, example_meta):
    del example_meta["device_authorization_endpoint"]
    del example_doc["auth"]["device"]
    assert run(example_doc, example_meta).passed()


def test_http_metadata_endpoint_is_advisory(example_doc):
    report = run(example_doc, fixture_json("oauth/http-endpoint.json"))
    assert "OA08" in report.rule_ids(Severity.INFO)
    assert report.passed() and not report.passed(strict=True)


def test_missing_metadata_is_an_error(example_doc):
    report = run(example_doc, None)
    assert "OA01" in report.rule_ids(ERROR)


def test_metadata_not_json_is_an_error(example_doc):
    report = run(example_doc, "not json")
    assert "OA01" in report.rule_ids(ERROR)


def test_metadata_redirect_to_http_is_an_error(example_doc):
    transport = FakeTransport().json(WK, example_doc).redirect(META, "http://auth.example.com/meta")
    report = validate_url("example.com", transport=transport)
    assert "OA01" in report.rule_ids(ERROR)


def test_poppy_domains_compare_case_insensitively(example_doc, example_meta):
    example_meta["poppy_domains"] = ["EXAMPLE.COM"]
    assert "OA03" not in run(example_doc, example_meta).rule_ids()


@pytest.mark.parametrize(
    "org_domain, listed",
    [("example.com", ["www.example.com"]), ("www.example.com", ["example.com"]), ("example.com", ["Example.COM."])],
)
def test_poppy_domains_ignore_leading_www_like_o002(example_doc, example_meta, org_domain, listed):
    example_doc["organization"]["domain"] = org_domain
    example_meta["poppy_domains"] = listed
    report = run(example_doc, example_meta)
    assert "OA03" not in report.rule_ids() and "O002" not in report.rule_ids()


def test_poppy_domains_subdomain_is_still_a_different_domain(example_doc, example_meta):
    example_meta["poppy_domains"] = ["shop.example.com"]
    assert "OA03" in run(example_doc, example_meta).rule_ids(ERROR)


def test_metadata_urls_follow_rfc_8414():
    assert metadata_urls("https://auth.example.com") == (META, META)
    rfc, appended = metadata_urls("https://example.com/tenants/acme")
    assert rfc == "https://example.com/.well-known/oauth-authorization-server/tenants/acme"
    assert appended == "https://example.com/tenants/acme/.well-known/oauth-authorization-server"


def path_issuer(doc, meta, issuer="https://auth.example.com/tenant"):
    doc["auth"]["issuer"] = issuer
    meta["issuer"] = issuer
    return issuer


def test_metadata_only_at_appended_location_is_an_error(example_doc, example_meta):
    # audit F5 (metadata-wrong-location): publication is a section 3.2 MUST
    issuer = path_issuer(example_doc, example_meta)
    transport = FakeTransport().json(WK, example_doc).json(issuer + "/.well-known/oauth-authorization-server", example_meta)
    report = validate_url("example.com", transport=transport)
    assert report.rule_ids(ERROR) == {"OA01"}
    (note,) = [f for f in report.findings if f.rule.id == "OA09"]
    assert note.severity is Severity.INFO
    assert "https://auth.example.com/.well-known/oauth-authorization-server/tenant" in note.message
    assert report.checks["oauth"] == "failed"
    assert report.passed() is False


def test_misplaced_metadata_is_still_cross_checked(example_doc, example_meta):
    issuer = path_issuer(example_doc, example_meta)
    example_meta["poppy_domains"] = ["example.org"]
    transport = FakeTransport().json(WK, example_doc).json(issuer + "/.well-known/oauth-authorization-server", example_meta)
    assert validate_url("example.com", transport=transport).rule_ids(ERROR) == {"OA01", "OA03"}


def test_path_issuer_at_rfc_8414_location_passes(example_doc, example_meta):
    path_issuer(example_doc, example_meta)
    rfc = "https://auth.example.com/.well-known/oauth-authorization-server/tenant"
    transport = FakeTransport().json(WK, example_doc).json(rfc, example_meta)
    report = validate_url("example.com", transport=transport)
    assert report.passed(strict=True), [f.to_dict() for f in report.findings]
    assert report.checks["oauth"] == "passed"


def test_local_file_can_opt_in_to_oauth(example_doc, live_example):
    report = validate_text(json.dumps(example_doc), domain="example.com", oauth=True, transport=live_example)
    assert report.checks["oauth"] == "passed"
    assert live_example.requested == [META]


def test_unparseable_issuer_fails_instead_of_skipping(example_doc):
    # audit F3 (issuer-invalid-bracket-live): this used to be an OA10 skip and exit 0
    example_doc["auth"]["issuer"] = "https://["
    transport = FakeTransport().json(WK, example_doc)
    report = validate_url("example.com", transport=transport)
    assert report.rule_ids(ERROR) == {"A002"}
    assert "OA10" not in report.rule_ids()
    assert report.checks["oauth"] == "failed"
    assert transport.requested == [WK]
    assert report.passed() is False


def test_no_auth_skips_cross_check():
    doc = fixture_json("valid/web-only-no-auth.json")
    transport = FakeTransport().json("https://brochure.example/.well-known/poppy.json", doc)
    report = validate_url("brochure.example", transport=transport)
    assert report.checks["oauth"] == "skipped"
    assert report.passed()
