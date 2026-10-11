"""Findings and the report that collects them."""

from __future__ import annotations

from dataclasses import dataclass, field

from poppy_validator import SPEC_URL, SPEC_VERSION, __version__
from poppy_validator.rules import RULES, Rule, Severity, area_of


@dataclass(frozen=True)
class Finding:
    rule: Rule
    message: str
    path: str = ""  # JSON Pointer into the document ("" = whole document)

    @property
    def severity(self) -> Severity:
        return self.rule.severity

    def to_dict(self) -> dict:
        return {
            "rule": self.rule.id,
            "severity": self.severity.value,
            "area": area_of(self.rule.id),
            "section": self.rule.section,
            "basis": self.rule.basis,
            "path": self.path,
            "message": self.message,
        }


@dataclass
class Report:
    target: str
    mode: str  # "file" or "url"
    requested_url: str | None = None
    final_url: str | None = None
    checks: dict[str, str] = field(default_factory=dict)
    findings: list[Finding] = field(default_factory=list)

    def add(self, rule_id: str, message: str, path: str = "") -> None:
        finding = Finding(RULES[rule_id], message, path)
        if finding not in self.findings:
            self.findings.append(finding)

    def count(self, severity: Severity) -> int:
        return sum(1 for f in self.findings if f.severity is severity)

    @property
    def errors(self) -> int:
        return self.count(Severity.ERROR)

    @property
    def warnings(self) -> int:
        return self.count(Severity.WARNING)

    @property
    def advisories(self) -> int:
        """Advisory findings: info by default, failures under --strict."""
        return sum(1 for f in self.findings if f.rule.basis == "advisory")

    def rule_ids(self, severity: Severity | None = None) -> set[str]:
        return {f.rule.id for f in self.findings if severity is None or f.severity is severity}

    @property
    def complete(self) -> bool:
        """False when a validator safeguard stopped a check before it finished."""
        return "incomplete" not in self.checks.values()

    def passed(self, strict: bool = False) -> bool:
        return self.errors == 0 and (not strict or (self.warnings == 0 and self.advisories == 0))

    def sorted_findings(self) -> list[Finding]:
        return sorted(self.findings, key=lambda f: (f.severity.rank, f.rule.id, f.path))

    def to_dict(self, strict: bool = False) -> dict:
        return {
            "validator": {"name": "poppy-validator", "version": __version__},
            "spec": {"version": SPEC_VERSION, "url": SPEC_URL, "status": "draft"},
            "target": self.target,
            "mode": self.mode,
            "requested_url": self.requested_url,
            "final_url": self.final_url,
            "strict": strict,
            "valid": self.passed(strict),
            "complete": self.complete,
            "counts": {s.value: self.count(s) for s in Severity},
            "checks": self.checks,
            "findings": [f.to_dict() for f in self.sorted_findings()],
        }
