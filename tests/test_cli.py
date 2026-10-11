"""The command line: exit codes, output formats, and the example/rules commands."""

from __future__ import annotations

import io
import json
import re
import subprocess
import sys
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator

from conftest import FIXTURES, fixture_json
from poppy_validator import cli
from poppy_validator.rules import RULES
from poppy_validator.schema import load_schema

ROOT = Path(__file__).parent.parent


def run(capsys, *argv):
    code = cli.main(list(argv))
    out, err = capsys.readouterr()
    return code, out, err


def test_example_prints_the_spec_document(capsys):
    code, out, _ = run(capsys, "example")
    assert code == 0
    assert json.loads(out) == fixture_json("valid/example.com.poppy.json")


def test_example_oauth_metadata(capsys):
    code, out, _ = run(capsys, "example", "--oauth-metadata")
    assert json.loads(out)["poppy_domains"] == ["example.com", "example.co.uk"]


def test_valid_file_exits_zero(capsys):
    code, out, _ = run(capsys, "validate", str(FIXTURES / "valid/example.com.poppy.json"), "--color", "never")
    assert code == 0
    assert "✔ valid" in out
    assert "\033[" not in out


def test_invalid_file_exits_one(capsys):
    code, out, _ = run(capsys, "validate", str(FIXTURES / "invalid/missing-org-domain.json"), "--color", "never")
    assert code == 1
    assert "Errors (1)" in out and "O001" in out


ADVISORY_FIXTURES = {
    "O004": "org-domain-uppercase", "O006": "org-name-blank", "A003": "auth-issuer-query",
    "A007": "mediated-endpoint-http", "A008": "mediated-duplicate-field", "S001": "custom-scope-undescribed",
    "S002": "reserved-poppy-scope", "S005": "empty-scopes", "S006": "scope-with-space",
    "G004": "agent-no-poppy-protocol", "P003": "api-url-http", "P004": "api-description-blank",
    "W002": "browser-session-endpoint-http", "E004": "extension-minor-version",
}


@pytest.mark.parametrize("rule_id", sorted(ADVISORY_FIXTURES))
def test_advisory_findings_are_info_and_fail_only_strict(capsys, rule_id):
    # audit F7: info severity, exit 0 by default, exit 1 under --strict
    path = str(FIXTURES / "invalid" / f"{ADVISORY_FIXTURES[rule_id]}.json")
    code, out, _ = run(capsys, "validate", path, "--domain", "example.com", "--json")
    data = json.loads(out)
    hit = [f for f in data["findings"] if f["rule"] == rule_id]
    assert code == 0 and data["valid"] is True
    assert hit and all(f["severity"] == "info" and f["basis"] == "advisory" for f in hit)
    code, out, _ = run(capsys, "validate", path, "--domain", "example.com", "--json", "--strict")
    assert code == 1 and json.loads(out)["valid"] is False


def test_strict_does_not_fail_on_context_info(capsys):
    # unknown fields and "check skipped" findings are info but not advisory
    path = str(FIXTURES / "valid/unknown-fields.json")
    assert run(capsys, "validate", path, "--domain", "example.com", "--strict")[0] == 0


def test_quiet_keeps_advisory_info(capsys):
    path = str(FIXTURES / "invalid/custom-scope-undescribed.json")
    _, out, _ = run(capsys, "validate", path, "-q", "--color", "never")
    assert "S001" in out and "OA10" not in out


def test_json_output_shape(capsys):
    code, out, _ = run(capsys, "validate", str(FIXTURES / "invalid/extension-without-domain-prefix.json"), "--json")
    data = json.loads(out)
    assert code == 1 and data["valid"] is False
    assert data["spec"] == {"version": "0.1", "url": "https://personalagentprotocol.org/spec", "status": "draft"}
    assert data["counts"]["error"] == 1
    (err,) = [f for f in data["findings"] if f["severity"] == "error"]
    assert err["rule"] == "E002" and err["section"] == "3.3" and err["path"] == "/extensions/gift-wrap"


def test_json_null_exits_one_with_valid_false(capsys):
    code, out, _ = run(capsys, "validate", str(FIXTURES / "invalid/null.json"), "--json")
    data = json.loads(out)
    assert code == 1 and data["valid"] is False and data["counts"]["error"] == 1
    assert data["findings"][0]["rule"] == "J001"


def test_unparseable_resource_still_prints_a_json_report(capsys):
    # audit F4: this used to raise ValueError and print a traceback with empty stdout
    path = str(FIXTURES / "invalid/resource-unparseable.json")
    code, out, _ = run(capsys, "validate", path, "--domain", "example.com", "--json")
    data = json.loads(out)
    assert code == 0 and data["valid"] is True
    assert {"rule": "M001", "path": "/agent/protocols/0/resource"}.items() <= data["findings"][0].items()


@pytest.mark.parametrize("target", ["https://[", "https://example.com:bad"])
def test_malformed_target_prints_a_json_report(target):
    # audit round 2, N1: a real CLI process, as the audit ran it; no traceback, JSON on stdout
    proc = subprocess.run(
        [sys.executable, "-m", "poppy_validator", "validate", target, "--json"], capture_output=True, text=True
    )
    assert proc.returncode == 1 and "Traceback" not in proc.stderr
    data = json.loads(proc.stdout)
    assert data["valid"] is False and [f["rule"] for f in data["findings"]] == ["T001"]
    assert data["checks"]["transport"] == "failed"


def test_stdin(capsys, monkeypatch):
    doc = (FIXTURES / "valid/example.com.poppy.json").read_bytes()
    monkeypatch.setattr("sys.stdin", io.TextIOWrapper(io.BytesIO(doc)))
    code, out, _ = run(capsys, "validate", "-", "--domain", "example.com", "--json")
    assert code == 0 and json.loads(out)["valid"] is True


def test_quiet_hides_context_info(capsys):
    _, out, _ = run(capsys, "validate", str(FIXTURES / "valid/example.com.poppy.json"), "-q", "--color", "never")
    assert "Info (" not in out


def test_color_always_emits_ansi(capsys):
    _, out, _ = run(capsys, "validate", str(FIXTURES / "invalid/missing-org-domain.json"), "--color", "always")
    assert "\033[31" in out


def test_garbage_target_is_a_usage_error(capsys):
    code, _, err = run(capsys, "validate", "not a domain!")
    assert code == 2 and "not a file" in err


def test_domain_target_uses_the_network_path(capsys, monkeypatch, live_example):
    monkeypatch.setattr(cli, "UrllibTransport", lambda timeout: live_example)
    code, out, _ = run(capsys, "validate", "example.com", "--json")
    data = json.loads(out)
    assert code == 0 and data["checks"]["oauth"] == "passed"
    assert data["requested_url"] == "https://example.com/.well-known/poppy.json"


def test_no_network_flag(capsys, monkeypatch, live_example):
    monkeypatch.setattr(cli, "UrllibTransport", lambda timeout: live_example)
    _, out, _ = run(capsys, "validate", "example.com", "--no-network", "--json")
    assert json.loads(out)["checks"]["oauth"] == "skipped"
    assert len(live_example.requested) == 1


def test_three_severities_only(capsys):
    # audit F9: no separate "note" level; human and JSON output use the same three names
    from poppy_validator.rules import Severity

    assert [s.value for s in Severity] == ["error", "warning", "info"]
    assert {r.basis for r in RULES.values()} <= {"must", "shape", "should", "advisory", "context", "tool"}
    path = str(FIXTURES / "valid/unknown-fields.json")
    _, out, _ = run(capsys, "validate", path, "--domain", "example.com", "--color", "never")
    assert "Info (" in out and "info" in out.splitlines()[-2] and "note" not in out.lower()
    _, out, _ = run(capsys, "validate", path, "--domain", "example.com", "--json")
    data = json.loads(out)
    assert set(data["counts"]) == {"error", "warning", "info"}
    assert {f["severity"] for f in data["findings"]} == {"info"}
    assert "advisory" not in {f["basis"] for f in data["findings"]}  # U001 is basis "must": agents MUST ignore


def test_rules_command_lists_every_rule(capsys):
    code, out, _ = run(capsys, "rules", "--json")
    assert code == 0
    assert [r["id"] for r in json.loads(out)] == list(RULES)


def test_schema_is_valid_draft_2020_12():
    schema = load_schema()
    assert schema["$schema"] == "https://json-schema.org/draft/2020-12/schema"
    Draft202012Validator.check_schema(schema)


def test_every_schema_rule_exists_in_the_catalogue():
    text = json.dumps(load_schema())
    for rule_id in re.findall(r'"x-[a-zA-Z-]*rules?": "([A-Z0-9]+)"', text):
        assert rule_id in RULES


@pytest.mark.parametrize("rule_id", list(RULES))
def test_readme_documents_every_rule(rule_id):
    readme = (ROOT / "README.md").read_text()
    assert f"`{rule_id}`" in readme


README_LEVEL = {"error": "🔴 error", "warning": "🟡 warning", "info": "🔵 info"}
README_BASIS = {"must": "MUST", "shape": "field table", "should": "SHOULD",
                "advisory": "advisory", "context": "context", "tool": "tool limit"}


def test_readme_rule_tables_match_the_catalogue():
    readme = (ROOT / "README.md").read_text()
    rows = dict(re.findall(r"^\| `([A-Z][A-Z0-9]{3})` \| (.+) \|$", readme, re.MULTILINE))
    assert set(rows) == set(RULES)
    for rule in RULES.values():
        level, section, basis, title = rows[rule.id].split(" | ", 3)
        assert (level, section, basis, title) == (
            README_LEVEL[rule.severity.value], f"§{rule.section}", README_BASIS[rule.basis], rule.title
        ), rule.id


def test_readme_strict_table_covers_every_info_basis():
    # audit round 2, N3: the README must say which info findings --strict fails, for every basis in use
    from poppy_validator.report import Report
    from poppy_validator.rules import Severity

    readme = (ROOT / "README.md").read_text()
    table = dict(re.findall(r"^\| `([a-z]+)` \| (Yes|No) \|", readme, re.MULTILINE))
    info_bases = {r.basis for r in RULES.values() if r.severity is Severity.INFO}
    assert set(table) == info_bases
    for basis, verdict in table.items():
        rule = next(r for r in RULES.values() if r.severity is Severity.INFO and r.basis == basis)
        report = Report(target="t", mode="file")
        report.add(rule.id, "probe")
        assert report.passed(strict=True) is (verdict == "No"), basis
    assert "`--strict` fails an info finding only when its `basis` is `advisory`" in readme


def test_readme_rule_counts_match_the_catalogue():
    readme = (ROOT / "README.md").read_text()
    assert f"*{len(RULES)} rules ·" in readme
    assert f"badge/rules-{len(RULES)}-" in readme
