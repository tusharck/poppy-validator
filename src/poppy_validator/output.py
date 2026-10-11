"""Human-readable rendering: findings grouped by severity, colored when useful."""

from __future__ import annotations

import os
import sys
import textwrap
from typing import TextIO

from poppy_validator import SPEC_URL, SPEC_VERSION
from poppy_validator.report import Report
from poppy_validator.rules import RULES, Severity, area_of

_CODES = {
    "red": "31", "yellow": "33", "blue": "34", "green": "32",
    "dim": "2", "bold": "1", "cyan": "36", "magenta": "35",
}

_GROUPS = {
    Severity.ERROR: ("Errors", "MUST", "✖", "red"),
    Severity.WARNING: ("Warnings", "SHOULD / incomplete check", "▲", "yellow"),
    Severity.INFO: ("Info", "advisory (fails --strict) / MAY / context", "•", "blue"),
}

_CHECK_ICONS = {
    "passed": ("✔", "green"), "failed": ("✖", "red"), "skipped": ("–", "dim"), "incomplete": ("…", "yellow"),
}


def use_color(mode: str, stream: TextIO) -> bool:
    if mode == "always":
        return True
    if mode == "never" or os.environ.get("NO_COLOR"):
        return False
    return hasattr(stream, "isatty") and stream.isatty() and os.environ.get("TERM") != "dumb"


class Painter:
    def __init__(self, enabled: bool) -> None:
        self.enabled = enabled

    def __call__(self, text: str, *styles: str) -> str:
        if not self.enabled or not styles:
            return text
        codes = ";".join(_CODES[s] for s in styles)
        return f"\033[{codes}m{text}\033[0m"


def _plural(n: int, word: str) -> str:
    return f"{n} {word}{'' if n == 1 else 's'}"


def render(report: Report, *, color: bool, strict: bool = False, quiet: bool = False, width: int = 100) -> str:
    p = Painter(color)
    lines: list[str] = []

    lines.append(p("poppy validate ", "bold") + p(report.target, "cyan"))
    if report.requested_url:
        lines.append(p(f"  requested  {report.requested_url}", "dim"))
        if report.final_url and report.final_url != report.requested_url:
            # "served by" only when a document came back; otherwise it's where the chain stopped.
            served = report.checks.get("document") not in (None, "skipped")
            lines.append(p(f"  {'served by' if served else 'halted at'}  {report.final_url}", "dim"))
    lines.append(p(f"  spec       Personal Agent Protocol draft {SPEC_VERSION} · {SPEC_URL}", "dim"))

    if report.checks:
        parts = []
        for name in ("transport", "document", "oauth"):
            state = report.checks.get(name)
            if state:
                icon, tone = _CHECK_ICONS[state]
                parts.append(p(f"{icon} {name}", tone))
        lines.append("  checks     " + "   ".join(parts))
    lines.append("")

    findings = report.sorted_findings()
    for severity, (title, keyword, icon, tone) in _GROUPS.items():
        group = [f for f in findings if f.severity is severity]
        if quiet and severity is Severity.INFO:
            group = [f for f in group if f.rule.basis == "advisory"]  # they can still fail --strict
        if not group:
            continue
        lines.append(p(f"{title} ({len(group)})", tone, "bold") + p(f"  {keyword}", "dim"))
        for f in group:
            head = f"  {p(icon, tone)} {p(f.rule.id, tone, 'bold')}  "
            meta = f"§{f.rule.section} · {area_of(f.rule.id)}" + (f" · {f.path}" if f.path else "")
            if f.rule.basis == "advisory":
                meta += " · advisory"
            wrapped = textwrap.wrap(f.message, width=max(40, width - 10)) or [""]
            lines.append(head + wrapped[0])
            for extra in wrapped[1:]:
                lines.append("         " + extra)
            lines.append("         " + p(meta, "dim"))
        lines.append("")

    errors, warnings, infos = (report.count(s) for s in Severity)
    summary = ", ".join([_plural(errors, "error"), _plural(warnings, "warning"), f"{infos} info"])
    if report.passed(strict) and not report.complete:
        verdict = p("▲ incomplete", "yellow", "bold") + p("  (no errors found, but not every check ran)", "dim")
    elif report.passed(strict):
        verdict = p("✔ valid", "green", "bold")
        if warnings or report.advisories:
            verdict += p("  (warnings and advisory info fail only with --strict)", "dim")
    elif errors:
        verdict = p("✖ invalid", "red", "bold")
    else:
        verdict = p("✖ failed (--strict: warnings and advisory info count)", "red", "bold")
    lines.append(f"{verdict}  {summary}")
    lines.append(p("Draft 0.1: the spec and these rules will change. Not an official conformance tool.", "dim"))
    return "\n".join(lines)


def render_rules(color: bool) -> str:
    p = Painter(color)
    lines = []
    current = None
    for rule in RULES.values():
        area = area_of(rule.id)
        if area != current:
            current = area
            lines.append("")
            lines.append(p(area, "bold"))
        _, _, icon, tone = _GROUPS[rule.severity]
        lines.append(
            f"  {p(icon, tone)} {p(rule.id, tone, 'bold')}  {rule.title}  "
            + p(f"§{rule.section} · {rule.severity.value} · {rule.basis}", "dim")
        )
    return "\n".join(lines).lstrip("\n")


def stdout_width() -> int:
    try:
        return min(os.get_terminal_size(sys.stdout.fileno()).columns, 120)
    except OSError:
        return 100
