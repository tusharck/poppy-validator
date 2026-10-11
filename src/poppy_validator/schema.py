"""Structural validation with the hand-authored JSON Schema.

Each schema node carries an ``x-rule`` annotation (and optionally
``x-message``). A failure is attributed to the nearest annotated node on its
schema path, so the catalogue in ``rules.py`` stays the single source of truth
for severity and spec section.
"""

from __future__ import annotations

import json
import re
from collections.abc import Iterator
from functools import cache
from importlib import resources
from typing import Any

from jsonschema import Draft202012Validator, ValidationError

from poppy_validator.report import Report

_REQUIRED_RE = re.compile(r"^'(.+)' is a required property$")
_TYPE_NAMES = {
    "object": "an object",
    "array": "an array",
    "string": "a string",
    "boolean": "a boolean (true or false)",
    "integer": "an integer",
    "number": "a number",
}


@cache
def load_schema() -> dict[str, Any]:
    text = resources.files("poppy_validator").joinpath("data/poppy-0.1.schema.json").read_text("utf-8")
    return json.loads(text)


@cache
def https_url_pattern() -> re.Pattern[str]:
    """The schema's httpsUrl pattern, compiled, so checks.py can tell which values it accepted."""
    return re.compile(load_schema()["$defs"]["httpsUrl"]["pattern"])


@cache
def _validator() -> Draft202012Validator:
    schema = load_schema()
    Draft202012Validator.check_schema(schema)
    return Draft202012Validator(schema)


def pointer(parts) -> str:
    return "".join("/" + str(p).replace("~", "~0").replace("/", "~1") for p in parts)


def _resolve_local(ref: str) -> dict[str, Any]:
    node: Any = load_schema()
    for part in ref.removeprefix("#/").split("/"):
        node = node[part]
    return node


def _walk(error: ValidationError) -> Iterator[dict[str, Any]]:
    """Yield every schema dict on the error's path, root first, following $refs.

    jsonschema leaves ``$ref`` out of error paths, so when the next key isn't
    on the current node we step through its ``$ref`` first. The last node
    yielded is the one holding the failing keyword.
    """
    node: Any = load_schema()
    path = list(error.absolute_schema_path)
    for i, key in enumerate(path):
        while isinstance(node, dict) and key not in node and "$ref" in node:
            yield node
            node = _resolve_local(node["$ref"])
        if isinstance(node, dict):
            yield node
        if i == len(path) - 1:
            return
        node = node[key]


def _attribute(error: ValidationError) -> tuple[str, str | None]:
    """Return (rule_id, custom message) for a schema error."""
    rule_id, message = "J001", None
    nodes = list(_walk(error))
    for node in nodes:
        if "x-rule" in node:
            rule_id, message = node["x-rule"], node.get("x-message")
    holder = nodes[-1] if nodes else {}
    if error.validator == "required":
        match = _REQUIRED_RE.match(error.message)
        if match and match.group(1) in holder.get("x-required-rules", {}):
            rule_id = holder["x-required-rules"][match.group(1)]
            message = None
    keyword_rule = holder.get(f"x-{error.validator}-rule")
    if keyword_rule:
        rule_id, message = keyword_rule, holder.get(f"x-{error.validator}-message")
    return rule_id, message


def _describe(error: ValidationError, where: str) -> str:
    v = error.validator
    label = f"`{where}`" if where else "the document"
    if v == "required":
        match = _REQUIRED_RE.match(error.message)
        field = match.group(1) if match else "?"
        return f"missing required field `{(where + '.' if where else '') + field}`"
    if v == "type":
        expected = error.validator_value
        names = [expected] if isinstance(expected, str) else expected
        return f"{label} must be " + " or ".join(_TYPE_NAMES.get(n, n) for n in names)
    if v == "minItems":
        return f"{label} must not be empty"
    if v == "minLength":
        return f"{label} must not be an empty string"
    if v == "pattern":
        return f"{label} has an invalid format: {error.instance!r}"
    return f"{label}: {error.message}"


def dotted(parts) -> str:
    out = ""
    for p in parts:
        out += f"[{p}]" if isinstance(p, int) else (f".{p}" if out else str(p))
    return out


def validate_structure(doc: Any, report: Report) -> None:
    for error in sorted(_validator().iter_errors(doc), key=lambda e: list(e.absolute_path)):
        if error.validator in {"if", "allOf", "$ref"}:
            continue
        rule_id, custom = _attribute(error)
        parts = list(error.absolute_path)
        path = pointer(parts)
        if error.validator == "required":
            match = _REQUIRED_RE.match(error.message)
            if match:
                path = pointer(parts + [match.group(1)])
        message = custom or _describe(error, dotted(parts))
        report.add(rule_id, message, path)
