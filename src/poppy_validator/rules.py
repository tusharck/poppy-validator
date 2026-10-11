"""The rule catalogue: every check this validator runs, with its spec reference.

Severity follows the spec's RFC 2119 keywords. Everything else is advisory.
There are three severities and no others; ``basis`` tells advisory info from context.

* ``error``   - a MUST / MUST NOT (or a required field) is violated. Exit code 1.
* ``warning`` - a SHOULD is violated, or a validator safeguard left a check
                incomplete. Exit code 0 (1 with ``--strict``).
* ``info``    - advisory best practice, MAY misuse, unknown fields, and context.
                Exit code 0; only ``advisory`` findings fail ``--strict``.

``basis`` records *why* a rule has its severity:

* ``must``     - the spec uses MUST / MUST NOT in capitals.
* ``shape``    - the spec's field table or field description defines the shape
                 ("Req. Yes", "each with a type and HTTPS endpoint", ...).
* ``should``   - the spec uses SHOULD.
* ``advisory`` - best practice the spec supports in prose but with no uppercase
                 MUST or SHOULD. Reported as info; ``--strict`` promotes it.
* ``context``  - context only. Never fails, even with ``--strict``.
* ``tool``     - a limit of this validator, not of the spec; the check is incomplete.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class Severity(str, Enum):
    ERROR = "error"
    WARNING = "warning"
    INFO = "info"

    @property
    def rank(self) -> int:
        return {"error": 0, "warning": 1, "info": 2}[self.value]


@dataclass(frozen=True)
class Rule:
    id: str
    severity: Severity
    section: str
    basis: str
    title: str


E, W, I = Severity.ERROR, Severity.WARNING, Severity.INFO

_RULES = [
    # 3. Discovery: location and transport (fetch mode)
    Rule("T001", E, "3", "must", "Document is served at https://{domain}/.well-known/poppy.json over HTTPS with a 2xx response"),
    Rule("T002", E, "3", "must", "Every redirect from the well-known URL goes to an HTTPS URL"),
    Rule("T003", E, "3", "must", "Redirects don't loop (a loop never reaches a document)"),
    Rule("T004", I, "3", "context", "Well-known URL redirected; domain checks use the requested host, not the serving host"),
    Rule("T005", I, "3", "context", "Deployment advice: send HTTP caching headers; Personal Agents cache by them (not a Company requirement)"),
    Rule("T006", I, "3", "context", "URL is not a well-known location; it is checked as a document only"),
    Rule("T007", W, "3", "tool", "Validation incomplete: a redirect chain hit the validator's 20-hop safeguard (not a spec limit)"),
    # Parsing
    Rule("J001", E, "3", "shape", "Document is a JSON object"),
    # 3.1 protocol_version
    Rule("V001", E, "3.1", "shape", "protocol_version is present and a \"major.minor\" string"),
    Rule("V002", E, "3.1", "must", "protocol_version major version is 0 (the only major this validator supports)"),
    Rule("V003", I, "3.1", "context", "protocol_version is a newer 0.x minor; only 0.1 rules are checked"),
    # 3.1 organization
    Rule("O001", E, "3.1", "shape", "organization is an object with string name and domain"),
    Rule("O002", E, "3.1", "must", "organization.domain matches the requested well-known host, ignoring a leading www."),
    Rule("O003", E, "3.1", "shape", "organization.domain is a bare hostname (no scheme, path, port, or userinfo)"),
    Rule("O004", I, "3.1", "advisory", "organization.domain is lowercase without a trailing dot"),
    Rule("O005", I, "3.1", "context", "Domain match not checked (local file without --domain)"),
    Rule("O006", I, "3.1", "advisory", "organization.name is not empty"),
    # 3.1 presence rules
    Rule("R001", E, "3.1", "shape", "At least one of agent, apis, or web is present"),
    Rule("R002", E, "3.1", "shape", "auth is present when agent, apis, or web.browser_session_endpoint is present"),
    # 3.1 / 3.2 / 4.4 auth
    Rule("A001", E, "3.1", "shape", "auth is an object with an issuer"),
    Rule("A002", E, "3.1", "shape", "auth.issuer is an HTTPS URL"),
    Rule("A003", I, "3.2", "advisory", "auth.issuer has no query or fragment (RFC 8414 issuer identifier)"),
    Rule("A004", E, "3.1", "shape", "auth.direct / auth.device are objects with a scopes array of strings"),
    Rule("A005", E, "3.1", "shape", "auth.mediated has endpoint, fields, and scopes"),
    Rule("A006", E, "4.7", "shape", "Each auth.mediated.fields entry has string name, string label, boolean secret"),
    Rule("A007", I, "4.7", "advisory", "auth.mediated.endpoint is an HTTPS URL"),
    Rule("A008", I, "4.7", "advisory", "auth.mediated.fields names are unique (they become keys in credentials)"),
    Rule("A009", I, "4.4", "context", "auth lists no sign-in type; only signed-out Sessions are offered"),
    # 4.4 scopes
    Rule("S001", I, "3.1, 4.4", "advisory", "Every custom scope used in a scopes array is described in auth.custom_scopes"),
    Rule("S002", I, "4.4", "advisory", "Scope names starting with poppy: are reserved; only poppy:read and poppy:write exist in 0.1"),
    Rule("S003", I, "4.4", "context", "auth.custom_scopes describes a scope no sign-in type grants"),
    Rule("S004", E, "3.1", "shape", "auth.custom_scopes is an object mapping scope names to string descriptions"),
    Rule("S005", I, "4.4", "advisory", "A sign-in type's scopes array is not empty"),
    Rule("S006", I, "4.4", "advisory", "Scope names follow OAuth scope-token syntax (RFC 6749 3.3: no spaces, quotes, or backslashes)"),
    Rule("S007", I, "4.4", "context", "A scopes array lists the same scope more than once"),
    # 3.1 / 7.1 agent
    Rule("G001", E, "3.1, 7.1", "shape", "agent is an object with a non-empty protocols array"),
    Rule("G002", E, "3.1", "shape", "Each agent.protocols entry has a string type and an HTTPS endpoint"),
    Rule("G003", I, "7.1", "context", "agent.protocols entry has a type not defined in 0.1 (Personal Agents skip it)"),
    Rule("G004", I, "7.1", "advisory", "agent.protocols includes at least one type defined in 0.1 (poppy)"),
    # 3.1 / 6 apis
    Rule("P001", E, "3.1", "shape", "apis is an array; each entry has string type, url, and description"),
    Rule("P002", E, "6", "must", "Each apis entry's type is one defined in section 6 (openapi, mcp)"),
    Rule("P003", I, "6", "advisory", "Each apis entry's url is an HTTPS URL"),
    Rule("P004", I, "3.1", "advisory", "apis is not empty and each description is not blank"),
    Rule("P005", I, "4.3", "context", "MCP entry has a resource that differs from its url (MCP tokens are issued for the url)"),
    # MAY: resource
    Rule("M001", I, "3.1, 4.3", "context", "resource (MAY) is an absolute URI without a fragment (RFC 8707)"),
    # 3.1 / 5 web
    Rule("W001", E, "3.1", "shape", "web is an object; browser_session_endpoint, if present, is a string"),
    Rule("W002", I, "5", "advisory", "web.browser_session_endpoint is an HTTPS URL"),
    Rule("W003", I, "3.1", "context", "web has no browser_session_endpoint; agents browse as signed-out visitors"),
    # 3.3 extensions
    Rule("E001", E, "3.3", "shape", "extensions is an object whose entries are objects"),
    Rule("E002", E, "3.3", "must", "Extensions not defined by the spec are named with a domain prefix (example.com/name)"),
    Rule("E003", E, "3.3", "shape", "Each extension entry has a version (string or integer)"),
    Rule("E004", I, "3.3", "advisory", "Extension version is a major version only (e.g. \"1\", not \"1.2\" or \"v1\")"),
    # 3.2 OAuth server cross-check (fetch mode)
    Rule("OA01", E, "3.2", "must", "auth.issuer publishes RFC 8414 metadata at its well-known URL"),
    Rule("OA02", E, "3.2", "must", "Metadata issuer exactly matches auth.issuer"),
    Rule("OA03", E, "3.2", "must", "Metadata poppy_domains includes organization.domain"),
    Rule("OA04", E, "3.2", "shape", "Metadata has token_endpoint"),
    Rule("OA05", E, "3.2", "shape", "Metadata has revocation_endpoint"),
    Rule("OA06", E, "3.2", "shape", "Metadata has authorization_endpoint when auth.direct is present"),
    Rule("OA07", E, "3.2", "shape", "Metadata has device_authorization_endpoint when auth.device is present"),
    Rule("OA08", I, "3.2", "advisory", "Metadata endpoints are HTTPS URLs"),
    Rule("OA09", I, "3.2", "context", "Diagnostic for OA01: metadata exists only at {issuer}/.well-known/..., not the RFC 8414 location"),
    Rule("OA10", I, "3.2", "context", "OAuth cross-check skipped"),
    Rule("OA11", E, "3.2", "must", "auth.issuer is an RFC 8414 issuer identifier: no query or fragment (RFC 8414 section 2)"),
    # Unknown fields
    Rule("U001", I, "3.3", "must", "Unrecognized field (Personal Agents MUST ignore it, so it is not an error)"),
]

RULES: dict[str, Rule] = {r.id: r for r in _RULES}

AREAS = {
    "T": "Transport",
    "J": "Document",
    "V": "protocol_version",
    "O": "organization",
    "R": "Required members",
    "A": "auth",
    "S": "Scopes",
    "G": "agent",
    "P": "apis",
    "M": "resource (MAY)",
    "W": "web",
    "E": "extensions",
    "U": "Unknown fields",
}


def area_of(rule_id: str) -> str:
    if rule_id.startswith("OA"):
        return "OAuth server"
    return AREAS[rule_id[0]]
