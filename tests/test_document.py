"""Document rules (spec sections 3.1, 3.3, 4.4, 6, 7.1) against local fixtures."""

from __future__ import annotations

import json
from importlib import resources

import pytest

from conftest import FIXTURES, fixture_text
from poppy_validator.rules import RULES, Severity
from poppy_validator.validator import validate_file, validate_text

ERROR, WARNING, INFO = Severity.ERROR, Severity.WARNING, Severity.INFO

# audit F7: no uppercase SHOULD or MUST backs these, so they are advisory info
ADVISORY = {"S001", "S005", "G004", "O004", "A007", "P003", "W002", "A008", "O006", "P004", "S002", "S006", "E004",
            "OA08", "A003"}

# fixture name -> (rule that must fire, its severity, document still valid?)
INVALID = {
    # 3.1 protocol_version
    "missing-protocol-version": ("V001", ERROR),
    "malformed-protocol-version": ("V001", ERROR),
    "numeric-protocol-version": ("V001", ERROR),
    "protocol-version-trailing-newline": ("V001", ERROR),  # audit F6 (version-newline)
    "major-version-1": ("V002", ERROR),
    # 3.1 organization
    "missing-organization": ("O001", ERROR),
    "missing-org-domain": ("O001", ERROR),
    "org-domain-is-url": ("O003", ERROR),
    "org-domain-unparseable-url": ("O003", ERROR),  # audit F4: hint parsing must not crash
    "org-domain-uppercase": ("O004", INFO),
    "org-name-blank": ("O006", INFO),
    # 3.1 presence
    "no-agent-apis-or-web": ("R001", ERROR),
    "auth-missing-with-agent": ("R002", ERROR),
    "auth-missing-with-browser-session": ("R002", ERROR),
    # auth
    "auth-missing-issuer": ("A001", ERROR),
    "auth-issuer-http": ("A002", ERROR),
    "auth-issuer-unparseable": ("A002", ERROR),  # audit F3: https://[ passes the regex, not the parser
    "auth-issuer-invalid-host": ("A002", ERROR),  # audit F3 (issuer-invalid-host): https://.
    "auth-issuer-query": ("A003", INFO),
    "direct-without-scopes": ("A004", ERROR),
    "mediated-missing-fields": ("A005", ERROR),
    "mediated-field-secret-not-bool": ("A006", ERROR),
    "mediated-endpoint-http": ("A007", INFO),
    "mediated-duplicate-field": ("A008", INFO),
    # scopes (4.4)
    "custom-scope-undescribed": ("S001", INFO),
    "reserved-poppy-scope": ("S002", INFO),
    "custom-scopes-non-string": ("S004", ERROR),
    "empty-scopes": ("S005", INFO),
    "scope-with-space": ("S006", INFO),
    # agent
    "agent-empty-protocols": ("G001", ERROR),
    "agent-endpoint-http": ("G002", ERROR),
    "agent-endpoint-unparseable": ("G002", ERROR),  # audit F3
    "agent-no-poppy-protocol": ("G004", INFO),
    # apis
    "api-missing-description": ("P001", ERROR),
    "api-unknown-type": ("P002", ERROR),
    "api-url-http": ("P003", INFO),
    "api-description-blank": ("P004", INFO),
    "mcp-resource-mismatch": ("P005", INFO),
    # resource (MAY)
    "resource-unparseable": ("M001", INFO),  # audit F4 (malformed-resource): no traceback
    # web
    "browser-session-endpoint-http": ("W002", INFO),
    # extensions (3.3)
    "extension-without-domain-prefix": ("E002", ERROR),
    "extension-bad-domain-prefix": ("E002", ERROR),
    "extension-missing-version": ("E003", ERROR),
    "extension-minor-version": ("E004", INFO),
    # parsing
    "not-an-object": ("J001", ERROR),
    "not-json": ("J001", ERROR),
    "null": ("J001", ERROR),  # audit F2: JSON null parses, so it must not look like a parse failure
}


def test_every_invalid_fixture_is_listed():
    on_disk = {p.stem for p in (FIXTURES / "invalid").glob("*.json")}
    assert on_disk == set(INVALID)


@pytest.mark.parametrize("name", sorted(INVALID))
def test_invalid_fixture_triggers_its_rule(name):
    rule_id, severity = INVALID[name]
    assert RULES[rule_id].severity is severity
    report = validate_file(FIXTURES / "invalid" / f"{name}.json", domain="example.com")
    assert rule_id in report.rule_ids(severity), [f.to_dict() for f in report.findings]
    # Each fixture is the spec example with one mutation: nothing else should fail.
    assert report.rule_ids(ERROR) <= {rule_id}
    assert report.passed() is (severity is not ERROR)
    # Advisory rules (audit F7) are info by default but fail --strict; context info never does.
    assert report.passed(strict=True) is (severity is not ERROR and RULES[rule_id].basis != "advisory")


def test_json_null_is_a_document_error_not_a_silent_pass():
    report = validate_file(FIXTURES / "invalid/null.json")
    (finding,) = [f for f in report.findings if f.rule.id == "J001"]
    assert "got null" in finding.message
    assert report.checks["document"] == "failed"
    assert report.passed() is False


def test_advisory_rules_are_exactly_the_audited_set():
    assert {r.id for r in RULES.values() if r.basis == "advisory"} == ADVISORY
    assert all(RULES[r].severity is INFO for r in ADVISORY)
    # No document rule is a warning any more: only T007 (incomplete check) is.
    assert {r.id for r in RULES.values() if r.severity is WARNING} == {"T007"}


def test_every_document_advisory_rule_has_a_fixture():
    covered = {rule for rule, _ in INVALID.values()}
    assert ADVISORY - {"OA08"} <= covered  # OA08 needs live metadata: tests/test_oauth.py


def test_spec_example_is_valid_and_clean():
    report = validate_file(FIXTURES / "valid/example.com.poppy.json", domain="example.com")
    assert report.passed(strict=True)
    assert report.rule_ids() == {"OA10"}  # only "OAuth check skipped for a local file"


def test_valid_fixture_matches_packaged_spec_example():
    packaged = resources.files("poppy_validator").joinpath("data/example.com.poppy.json").read_text()
    assert json.loads(packaged) == json.loads(fixture_text("valid/example.com.poppy.json"))


def test_web_only_document_needs_no_auth():
    report = validate_file(FIXTURES / "valid/web-only-no-auth.json", domain="brochure.example")
    assert report.passed(strict=True)
    assert "W003" in report.rule_ids(INFO)


def test_unknown_fields_are_info_not_errors():
    report = validate_file(FIXTURES / "valid/unknown-fields.json", domain="example.com")
    assert report.passed(strict=True)
    paths = {f.path for f in report.findings if f.rule.id == "U001"}
    assert paths == {"/support_email", "/organization/logo", "/apis/0/x-rate-limit"}


def test_spec_and_domain_prefixed_extensions_are_valid():
    report = validate_file(FIXTURES / "valid/with-extensions.json", domain="example.com")
    assert report.passed(strict=True)
    assert not any(f.rule.id.startswith("E") for f in report.findings)


def test_extension_fields_are_not_reported_as_unknown():
    report = validate_file(FIXTURES / "valid/with-extensions.json", domain="example.com")
    assert "U001" not in report.rule_ids()


def test_domain_mismatch_with_domain_flag(example_doc):
    report = validate_text(json.dumps(example_doc), domain="example.org")
    assert "O002" in report.rule_ids(ERROR)


@pytest.mark.parametrize("host", ["www.example.com", "EXAMPLE.com", "example.com."])
def test_domain_match_ignores_leading_www_and_case(example_doc, host):
    report = validate_text(json.dumps(example_doc), domain=host)
    assert "O002" not in report.rule_ids()


def test_domain_match_strips_www_from_document_too(example_doc):
    example_doc["organization"]["domain"] = "www.example.com"
    report = validate_text(json.dumps(example_doc), domain="example.com")
    assert "O002" not in report.rule_ids()


def test_subdomain_is_not_the_same_domain(example_doc):
    report = validate_text(json.dumps(example_doc), domain="shop.example.com")
    assert "O002" in report.rule_ids(ERROR)


def test_without_domain_the_match_is_context_info(example_doc):
    report = validate_text(json.dumps(example_doc))
    assert "O005" in report.rule_ids(INFO)
    assert report.passed(strict=True)


def test_newer_minor_version_is_info_and_unknown_api_type_softens(example_doc):
    example_doc["protocol_version"] = "0.2"
    example_doc["apis"][0]["type"] = "graphql"
    report = validate_text(json.dumps(example_doc), domain="example.com")
    assert "P002" not in report.rule_ids()
    assert "V003" in report.rule_ids(INFO)
    assert report.passed()


def test_custom_scope_that_no_type_grants_is_info(example_doc):
    example_doc["auth"]["custom_scopes"]["gift_cards"] = "Use gift card balance"
    report = validate_text(json.dumps(example_doc), domain="example.com")
    assert "S003" in report.rule_ids(INFO)


def test_custom_scopes_cannot_redefine_reserved_names(example_doc):
    example_doc["auth"]["custom_scopes"]["poppy:read"] = "Read things"
    report = validate_text(json.dumps(example_doc), domain="example.com")
    assert "S002" in report.rule_ids(INFO)


def test_company_may_offer_only_custom_scopes(example_doc):
    # 4.4: a Company MAY leave out poppy:read and poppy:write.
    example_doc["auth"]["direct"]["scopes"] = ["addresses"]
    del example_doc["auth"]["device"], example_doc["auth"]["mediated"]
    report = validate_text(json.dumps(example_doc), domain="example.com")
    assert report.passed(strict=True)


def test_auth_without_sign_in_types_is_info(example_doc):
    example_doc["auth"] = {"issuer": "https://auth.example.com"}
    report = validate_text(json.dumps(example_doc), domain="example.com")
    assert "A009" in report.rule_ids(INFO)
    assert report.passed(strict=True)


def test_resource_misuse_is_info(example_doc):
    example_doc["agent"]["protocols"][0]["resource"] = "not a uri"
    example_doc["apis"][0]["resource"] = 42
    report = validate_text(json.dumps(example_doc), domain="example.com")
    hits = [f for f in report.findings if f.rule.id == "M001"]
    assert len(hits) == 2 and all(f.severity is INFO for f in hits)
    assert report.passed(strict=True)


def test_unparseable_urls_become_findings_not_tracebacks():
    report = validate_file(FIXTURES / "invalid/resource-unparseable.json", domain="example.com")
    (m001,) = [f for f in report.findings if f.rule.id == "M001"]
    assert m001.path == "/agent/protocols/0/resource" and "parseable" in m001.message
    report = validate_file(FIXTURES / "invalid/org-domain-unparseable-url.json", domain="example.com")
    (o003,) = [f for f in report.findings if f.rule.id == "O003"]
    assert o003.path == "/organization/domain" and "did you mean" not in o003.message


@pytest.mark.parametrize(
    "bad", ["https://[", "https://example.com:abc/", "https://example.com:99999", "https://.", "https://a..b/", "https://-x.com/"]
)
def test_required_https_urls_must_parse(example_doc, bad):
    example_doc["auth"]["issuer"] = bad
    example_doc["agent"]["protocols"][0]["endpoint"] = bad
    report = validate_text(json.dumps(example_doc), domain="example.com")
    assert report.rule_ids(ERROR) == {"A002", "G002"}
    assert len([f for f in report.findings if f.rule.id in ("A002", "G002")]) == 2  # reported once each


@pytest.mark.parametrize("version", ["0.1\n", "0.1\n\n", " 0.1", "0.1 "])
def test_protocol_version_must_match_over_the_whole_value(example_doc, version):
    example_doc["protocol_version"] = version
    report = validate_text(json.dumps(example_doc), domain="example.com")
    assert report.rule_ids(ERROR) == {"V001"}


def test_trailing_newlines_do_not_slip_past_other_patterns(example_doc):
    example_doc["auth"]["custom_scopes"]["loyalty\n"] = "Loyalty points"
    example_doc["auth"]["direct"]["scopes"].append("loyalty\n")
    example_doc["extensions"] = {"operations": {"version": "1\n"}, "example.com\n/x": {"version": "1"}}
    example_doc["agent"]["protocols"][0]["endpoint"] = "https://api.example.com/poppy\n"
    report = validate_text(json.dumps(example_doc), domain="example.com")
    assert {"S006", "E004", "E002", "G002"} <= report.rule_ids()


@pytest.mark.parametrize("good", ["https://[::1]/poppy", "https://127.0.0.1", "https://bücher.example", "https://localhost:8443/x"])
def test_ip_literal_and_idn_https_urls_are_accepted(example_doc, good):
    example_doc["agent"]["protocols"][0]["endpoint"] = good
    report = validate_text(json.dumps(example_doc), domain="example.com")
    assert "G002" not in report.rule_ids()


def test_extension_integer_version_is_accepted(example_doc):
    example_doc["extensions"] = {"operations": {"version": 1}}
    report = validate_text(json.dumps(example_doc), domain="example.com")
    assert not any(f.rule.id.startswith("E") for f in report.findings)


def test_extension_boolean_version_is_an_error(example_doc):
    example_doc["extensions"] = {"operations": {"version": True}}
    report = validate_text(json.dumps(example_doc), domain="example.com")
    assert "E003" in report.rule_ids(ERROR)


def test_findings_are_reported_once(example_doc):
    example_doc["auth"]["direct"]["scopes"].append("loyalty")
    example_doc["auth"]["device"]["scopes"].append("loyalty")
    report = validate_text(json.dumps(example_doc), domain="example.com")
    s001 = [f for f in report.findings if f.rule.id == "S001"]
    assert {f.path for f in s001} == {"/auth/direct/scopes/3", "/auth/device/scopes/2"}
