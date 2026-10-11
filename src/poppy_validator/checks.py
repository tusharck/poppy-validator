"""Document-level checks that a JSON Schema can't express on its own.

Structural failures (missing fields, wrong types) come from ``schema.py``.
These checks skip anything malformed, so one problem is reported once.
"""

from __future__ import annotations

import ipaddress
import re
from collections import Counter
from typing import Any
from urllib.parse import urlsplit

from poppy_validator.report import Report
from poppy_validator.schema import https_url_pattern, pointer, validate_structure

STANDARD_SCOPES = {"poppy:read", "poppy:write"}
SIGN_IN_TYPES = ("direct", "device", "mediated")
API_TYPES = {"openapi", "mcp"}  # section 6
CONVERSATION_PROTOCOLS = {"poppy"}  # section 7.1
SPEC_EXTENSIONS = {"operations"}  # personalagentprotocol.org/docs/extensions

# \Z, not $: in Python, $ also matches before a trailing newline, so "0.1\n" would pass.
_VERSION_RE = re.compile(r"^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\Z")
_MAJOR_RE = re.compile(r"^(0|[1-9][0-9]*)\Z")
_LABEL_RE = re.compile(r"^(?!-)[a-z0-9-]{1,63}(?<!-)\Z", re.IGNORECASE)
# RFC 6749 section 3.3: scope-token = 1*( %x21 / %x23-5B / %x5D-7E )
_SCOPE_TOKEN_RE = re.compile(r"^[\x21\x23-\x5B\x5D-\x7E]+\Z")

KNOWN_FIELDS = {
    "": {"protocol_version", "organization", "auth", "agent", "apis", "web", "extensions"},
    "organization": {"name", "domain"},
    "auth": {"issuer", "direct", "device", "mediated", "custom_scopes"},
    "sign_in": {"scopes"},
    "mediated": {"endpoint", "fields", "scopes"},
    "mediated_field": {"name", "label", "secret"},
    "agent": {"protocols"},
    "protocol": {"type", "endpoint", "resource"},
    "api": {"type", "url", "description", "resource"},
    "web": {"browser_session_endpoint"},
}


def is_https_url(value: Any) -> bool:
    if not isinstance(value, str) or any(c.isspace() for c in value):
        return False
    try:
        parts = urlsplit(value)
        parts.port  # raises ValueError for a non-numeric or out-of-range port
        return parts.scheme == "https" and _is_url_host(parts.hostname)
    except ValueError:
        return False


def _is_url_host(host: str | None) -> bool:
    """A DNS name (internationalized names included) or an IP literal."""
    if not host:
        return False
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        pass
    try:
        return is_hostname(host.encode("idna").decode("ascii"))
    except UnicodeError:
        return False


def is_malformed_https_url(value: Any) -> bool:
    """True for a string that passes the schema's httpsUrl pattern but doesn't parse
    as a usable HTTPS URL (``https://[``, ``https://host:abc``). The schema has
    already reported anything that fails the pattern, so this never double-reports."""
    return isinstance(value, str) and bool(https_url_pattern().match(value)) and not is_https_url(value)


def json_type(value: Any) -> str:
    """The JSON name for a parsed value's type, for messages."""
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "boolean"
    if isinstance(value, (int, float)):
        return "number"
    return {str: "string", list: "array", dict: "object"}.get(type(value), type(value).__name__)


def is_hostname(value: str, *, need_dot: bool = False) -> bool:
    host = value.rstrip(".")
    if not host or len(host) > 253:
        return False
    labels = host.split(".")
    if need_dot and len(labels) < 2:
        return False
    return all(_LABEL_RE.match(label) for label in labels)


def normalize_host(host: str) -> str:
    host = host.lower().rstrip(".")
    return host.removeprefix("www.")


def parse_version(value: Any) -> tuple[int, int] | None:
    if isinstance(value, str) and (m := _VERSION_RE.match(value)):
        return int(m.group(1)), int(m.group(2))
    return None


def check_document(doc: Any, report: Report, requested_host: str | None = None) -> None:
    """Run every document check. ``requested_host`` enables the domain match (O002)."""
    if not isinstance(doc, dict):
        report.add("J001", f"the document must be a JSON object, got {json_type(doc)}")
        return
    validate_structure(doc, report)
    minor = _check_version(doc, report)
    _check_organization(doc, report, requested_host)
    _check_auth(doc, report)
    _check_agent(doc, report)
    _check_apis(doc, report, minor)
    _check_web(doc, report)
    _check_extensions(doc, report)
    _check_unknown_fields(doc, report)


def _check_version(doc: dict, report: Report) -> int | None:
    version = parse_version(doc.get("protocol_version"))
    if version is None:
        return None  # V001 already reported by the schema
    major, minor = version
    if major != 0:
        report.add(
            "V002",
            f"protocol_version {doc['protocol_version']!r} has major version {major}; "
            "Personal Agents MUST NOT use a document whose major version they don't support, "
            "and this validator supports only major version 0",
            "/protocol_version",
        )
        return None
    if minor > 1:
        report.add(
            "V003",
            f"protocol_version {doc['protocol_version']!r} is newer than 0.1; it is checked against "
            "0.1 rules, and fields added later are reported as unrecognized",
            "/protocol_version",
        )
    return minor


def _check_organization(doc: dict, report: Report, requested_host: str | None) -> None:
    org = doc.get("organization")
    if not isinstance(org, dict):
        return
    name = org.get("name")
    if isinstance(name, str) and not name.strip():
        report.add("O006", "organization.name is blank; Personal Agents show it as the display name", "/organization/name")

    domain = org.get("domain")
    if not isinstance(domain, str) or not domain:
        return
    if not is_hostname(domain):
        hint = ""
        if "://" in domain or "/" in domain:
            try:
                parsed = urlsplit(domain if "://" in domain else "//" + domain)
                if parsed.hostname:
                    hint = f" (did you mean {parsed.hostname!r}?)"
            except ValueError:
                pass  # not even a parseable URL; the plain O003 message still applies
        report.add(
            "O003",
            f"organization.domain must be a bare hostname such as example.com, got {domain!r}{hint}",
            "/organization/domain",
        )
        return
    if domain != domain.lower() or domain.endswith("."):
        report.add(
            "O004",
            f"organization.domain {domain!r} should be written lowercase without a trailing dot "
            f"({domain.lower().rstrip('.')!r}); hosts compare case-insensitively, but other checks "
            "such as poppy_domains may not",
            "/organization/domain",
        )
    if requested_host is None:
        report.add(
            "O005",
            "organization.domain was not compared with a requested host; pass --domain, "
            "or validate the live URL, to check it",
            "/organization/domain",
        )
    elif normalize_host(domain) != normalize_host(requested_host):
        report.add(
            "O002",
            f"organization.domain is {domain!r} but the well-known URL was requested from "
            f"{requested_host!r}; they MUST match, ignoring a leading www.",
            "/organization/domain",
        )


def _check_auth(doc: dict, report: Report) -> None:
    auth = doc.get("auth")
    if not isinstance(auth, dict):
        return

    issuer = auth.get("issuer")
    if is_malformed_https_url(issuer):
        report.add(
            "A002",
            f"auth.issuer {issuer!r} looks like an HTTPS URL but doesn't parse as one; it must be a usable "
            "HTTPS URL, and the OAuth cross-check can't run without it",
            "/auth/issuer",
        )
    elif is_https_url(issuer):
        parts = urlsplit(issuer)
        if parts.query or parts.fragment:
            report.add(
                "A003",
                f"auth.issuer {issuer!r} has a query or fragment, so it isn't a conforming RFC 8414 issuer "
                "identifier (RFC 8414 section 2: an https URL with no query or fragment); the live OAuth "
                "cross-check fails it as OA11",
                "/auth/issuer",
            )

    if not any(k in auth for k in SIGN_IN_TYPES):
        report.add(
            "A009",
            "auth lists none of direct, device, or mediated, so the Company offers only signed-out Sessions",
            "/auth",
        )

    mediated = auth.get("mediated")
    if isinstance(mediated, dict):
        endpoint = mediated.get("endpoint")
        if isinstance(endpoint, str) and not is_https_url(endpoint):
            report.add(
                "A007",
                f"auth.mediated.endpoint {endpoint!r} is not an HTTPS URL; Personal Agents send the "
                "User's credentials there (advisory: the spec doesn't state HTTPS for this field)",
                "/auth/mediated/endpoint",
            )
        fields = mediated.get("fields")
        if isinstance(fields, list):
            names = [f.get("name") for f in fields if isinstance(f, dict) and isinstance(f.get("name"), str)]
            for name, n in Counter(names).items():
                if n > 1:
                    report.add(
                        "A008",
                        f"auth.mediated.fields lists name {name!r} {n} times; each name is a key in the "
                        "credentials object, so duplicates collide",
                        "/auth/mediated/fields",
                    )

    _check_scopes(auth, report)


def _check_scopes(auth: dict, report: Report) -> None:
    custom = auth.get("custom_scopes")
    described = set(custom) if isinstance(custom, dict) else set()
    used: set[str] = set()

    for kind in SIGN_IN_TYPES:
        section = auth.get(kind)
        if not isinstance(section, dict) or not isinstance(section.get("scopes"), list):
            continue
        scopes = section["scopes"]
        base = f"/auth/{kind}/scopes"
        if not scopes:
            report.add("S005", f"auth.{kind}.scopes is empty, so {kind} sign-in can't grant anything", base)
        strings = [s for s in scopes if isinstance(s, str)]
        for scope, n in Counter(strings).items():
            if n > 1:
                report.add("S007", f"auth.{kind}.scopes lists {scope!r} {n} times", base)
        for i, scope in enumerate(scopes):
            if not isinstance(scope, str):
                continue
            used.add(scope)
            path = f"{base}/{i}"
            if not _SCOPE_TOKEN_RE.match(scope):
                report.add(
                    "S006",
                    f"scope {scope!r} in auth.{kind}.scopes isn't a valid OAuth scope token "
                    "(sign-in requests send scopes as a space-separated string)",
                    path,
                )
            if scope in STANDARD_SCOPES:
                continue
            if scope.startswith("poppy:"):
                report.add(
                    "S002",
                    f"scope {scope!r} in auth.{kind}.scopes uses the reserved poppy: prefix, but draft 0.1 "
                    "defines only poppy:read and poppy:write",
                    path,
                )
            elif scope not in described:
                report.add(
                    "S001",
                    f"custom scope {scope!r} is used in auth.{kind}.scopes but not described in "
                    "auth.custom_scopes (advisory: the spec asks Companies to describe each one, without a MUST or SHOULD)",
                    path,
                )

    for name in sorted(described):
        path = pointer(["auth", "custom_scopes", name])
        if name.startswith("poppy:"):
            report.add(
                "S002",
                f"auth.custom_scopes defines {name!r}, but names starting with poppy: are reserved for the "
                "protocol; custom_scopes describes scopes beyond poppy:read and poppy:write",
                path,
            )
            continue
        if not _SCOPE_TOKEN_RE.match(name):
            report.add("S006", f"custom scope name {name!r} isn't a valid OAuth scope token", path)
        if name not in used:
            report.add("S003", f"auth.custom_scopes describes {name!r}, but no sign-in type lists it in scopes", path)


def _check_resource(entry: dict, where: str, path: str, report: Report) -> None:
    if "resource" not in entry:
        return
    resource = entry["resource"]
    if not isinstance(resource, str):
        report.add("M001", f"{where}.resource should be a URI string, got {type(resource).__name__}", path + "/resource")
        return
    try:
        parts = urlsplit(resource)
    except ValueError as err:
        report.add("M001", f"{where}.resource {resource!r} isn't a parseable URI ({err})", path + "/resource")
        return
    if not parts.scheme or not (parts.netloc or parts.path) or parts.fragment:
        report.add(
            "M001",
            f"{where}.resource {resource!r} should be an absolute URI without a fragment (RFC 8707)",
            path + "/resource",
        )


def _check_agent(doc: dict, report: Report) -> None:
    agent = doc.get("agent")
    if not isinstance(agent, dict) or not isinstance(agent.get("protocols"), list):
        return
    types = []
    for i, entry in enumerate(agent["protocols"]):
        if not isinstance(entry, dict):
            continue
        path = f"/agent/protocols/{i}"
        if is_malformed_https_url(entry.get("endpoint")):
            report.add(
                "G002",
                f"agent.protocols[{i}].endpoint {entry['endpoint']!r} looks like an HTTPS URL but doesn't "
                "parse as one; it must be a usable HTTPS URL",
                path + "/endpoint",
            )
        kind = entry.get("type")
        if isinstance(kind, str) and kind:
            types.append(kind)
            if kind not in CONVERSATION_PROTOCOLS:
                report.add(
                    "G003",
                    f"agent.protocols[{i}].type {kind!r} isn't defined in draft 0.1 (only 'poppy'); "
                    "Personal Agents skip unfamiliar types",
                    path + "/type",
                )
        _check_resource(entry, f"agent.protocols[{i}]", path, report)
    if types and not CONVERSATION_PROTOCOLS.intersection(types):
        report.add(
            "G004",
            "agent.protocols has no entry of type 'poppy', so a draft 0.1 Personal Agent can't start a "
            "conversation with the Company Agent",
            "/agent/protocols",
        )


def _check_apis(doc: dict, report: Report, minor: int | None) -> None:
    apis = doc.get("apis")
    if not isinstance(apis, list):
        return
    if not apis:
        report.add("P004", "apis is an empty list; leave it out, or list at least one API", "/apis")
    for i, entry in enumerate(apis):
        if not isinstance(entry, dict):
            continue
        path = f"/apis/{i}"
        kind, url = entry.get("type"), entry.get("url")
        if isinstance(kind, str) and kind not in API_TYPES:
            if minor is not None and minor > 1:
                report.add(
                    "V003",
                    f"apis[{i}].type {kind!r} isn't defined in 0.1; the document declares a newer minor "
                    "version, which may define it",
                    path + "/type",
                )
            else:
                report.add(
                    "P002",
                    f"apis[{i}].type is {kind!r}; it MUST be one of: {', '.join(sorted(API_TYPES))}",
                    path + "/type",
                )
        if isinstance(url, str) and url and not is_https_url(url):
            report.add(
                "P003",
                f"apis[{i}].url {url!r} is not an HTTPS URL; Session Tokens are sent to it "
                "(advisory: the spec doesn't state HTTPS for this field)",
                path + "/url",
            )
        description = entry.get("description")
        if isinstance(description, str) and not description.strip():
            report.add(
                "P004",
                f"apis[{i}].description is blank; it helps the Personal Agent pick the right API",
                path + "/description",
            )
        _check_resource(entry, f"apis[{i}]", path, report)
        resource = entry.get("resource")
        if kind == "mcp" and isinstance(resource, str) and isinstance(url, str) and resource != url:
            report.add(
                "P005",
                f"apis[{i}] is an MCP server with resource {resource!r}, but MCP Bearer tokens are "
                f"requested with resource set to its url {url!r} (4.3)",
                path + "/resource",
            )


def _check_web(doc: dict, report: Report) -> None:
    web = doc.get("web")
    if not isinstance(web, dict):
        return
    if "browser_session_endpoint" not in web:
        report.add(
            "W003",
            "web has no browser_session_endpoint, so Personal Agents browse as ordinary signed-out visitors",
            "/web",
        )
        return
    endpoint = web["browser_session_endpoint"]
    if isinstance(endpoint, str) and not is_https_url(endpoint):
        report.add(
            "W002",
            f"web.browser_session_endpoint {endpoint!r} is not an HTTPS URL (advisory: the spec doesn't "
            "state HTTPS for this field)",
            "/web/browser_session_endpoint",
        )


def _check_extensions(doc: dict, report: Report) -> None:
    extensions = doc.get("extensions")
    if not isinstance(extensions, dict):
        return
    for name, entry in extensions.items():
        path = pointer(["extensions", name])
        if "/" in name:
            prefix, _, rest = name.partition("/")
            if not is_hostname(prefix, need_dot=True) or not rest:
                report.add(
                    "E002",
                    f"extension {name!r} must start with a domain its author controls, such as "
                    f"example.com/{rest or 'name'}; {prefix!r} is not a domain",
                    path,
                )
        elif name not in SPEC_EXTENSIONS:
            report.add(
                "E002",
                f"extension {name!r} isn't defined by the spec (known: {', '.join(sorted(SPEC_EXTENSIONS))}); "
                f"other extensions MUST be named with a domain prefix, such as example.com/{name}",
                path,
            )
        if isinstance(entry, dict) and "version" in entry:
            version = entry["version"]
            ok = (isinstance(version, str) and _MAJOR_RE.match(version)) or (type(version) is int and version >= 0)
            if (isinstance(version, str) or type(version) is int) and not ok:
                report.add(
                    "E004",
                    f"extensions[{name!r}].version is {version!r}; it should be the extension's major "
                    "version only, such as \"1\"",
                    path + "/version",
                )


def _unknown(obj: dict, kind: str, path_parts: list, report: Report) -> None:
    for key in obj:
        if key not in KNOWN_FIELDS[kind]:
            where = ".".join(str(p) for p in path_parts) or "the top level"
            report.add(
                "U001",
                f"unrecognized field {key!r} in {where}; Personal Agents ignore it",
                pointer(path_parts + [key]),
            )


def _check_unknown_fields(doc: dict, report: Report) -> None:
    _unknown(doc, "", [], report)
    for key in ("organization", "agent", "web"):
        if isinstance(doc.get(key), dict):
            _unknown(doc[key], key, [key], report)
    auth = doc.get("auth")
    if isinstance(auth, dict):
        _unknown(auth, "auth", ["auth"], report)
        for kind in SIGN_IN_TYPES:
            section = auth.get(kind)
            if isinstance(section, dict):
                _unknown(section, "mediated" if kind == "mediated" else "sign_in", ["auth", kind], report)
        mediated = auth.get("mediated")
        if isinstance(mediated, dict) and isinstance(mediated.get("fields"), list):
            for i, f in enumerate(mediated["fields"]):
                if isinstance(f, dict):
                    _unknown(f, "mediated_field", ["auth", "mediated", "fields", i], report)
    agent = doc.get("agent")
    if isinstance(agent, dict) and isinstance(agent.get("protocols"), list):
        for i, entry in enumerate(agent["protocols"]):
            if isinstance(entry, dict):
                _unknown(entry, "protocol", ["agent", "protocols", i], report)
    if isinstance(doc.get("apis"), list):
        for i, entry in enumerate(doc["apis"]):
            if isinstance(entry, dict):
                _unknown(entry, "api", ["apis", i], report)
