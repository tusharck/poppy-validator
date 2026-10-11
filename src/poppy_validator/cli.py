"""Command line: ``poppy validate``, ``poppy example``, ``poppy rules``."""

from __future__ import annotations

import argparse
import json
import os
import sys
from dataclasses import asdict
from importlib import resources

from poppy_validator import SPEC_URL, SPEC_VERSION, __version__
from poppy_validator.fetch import UrllibTransport
from poppy_validator.output import render, render_rules, stdout_width, use_color
from poppy_validator.rules import RULES
from poppy_validator.validator import looks_like_domain, validate_file, validate_text, validate_url

EXIT_OK, EXIT_INVALID, EXIT_USAGE = 0, 1, 2


def _data(name: str) -> str:
    return resources.files("poppy_validator").joinpath(f"data/{name}").read_text("utf-8")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="poppy",
        description=f"Validate poppy.json discovery files against Personal Agent Protocol draft {SPEC_VERSION} "
        f"({SPEC_URL}). Draft spec: rules will change.",
    )
    parser.add_argument("--version", action="version", version=f"poppy-validator {__version__} (spec draft {SPEC_VERSION})")
    sub = parser.add_subparsers(dest="command", required=True, metavar="COMMAND")

    v = sub.add_parser(
        "validate",
        help="validate a local file, a domain, or a URL",
        description="Validate a poppy.json. TARGET is a local file, '-' for stdin, a domain "
        "(fetches https://DOMAIN/.well-known/poppy.json), or a URL.",
    )
    v.add_argument("target", metavar="TARGET", help="file path, '-', domain, or URL")
    v.add_argument(
        "--domain",
        help="the domain the document is published for; enables the organization.domain match "
        "for local files and non-well-known URLs",
    )
    v.add_argument(
        "--no-network",
        action="store_true",
        help="for a domain or URL: fetch only the poppy.json itself and skip the live OAuth server "
        "cross-check (section 3.2)",
    )
    v.add_argument(
        "--check-oauth",
        action="store_true",
        help="for a local file: also run the live OAuth server cross-check against auth.issuer",
    )
    v.add_argument("--json", action="store_true", help="print a machine-readable JSON report (for CI)")
    v.add_argument(
        "--strict",
        action="store_true",
        help="also exit 1 on warnings and advisory best-practice findings, not just MUST errors",
    )
    v.add_argument("-q", "--quiet", action="store_true", help="hide context info in human output (advisory info stays)")
    v.add_argument("--color", choices=["auto", "always", "never"], default="auto", help="colorize output (default: auto)")
    v.add_argument("--timeout", type=float, default=10.0, help="network timeout in seconds (default: 10)")

    e = sub.add_parser("example", help="print the spec's example.com poppy.json")
    e.add_argument(
        "--oauth-metadata",
        action="store_true",
        help="print the spec's example OAuth server metadata (section 3.2) instead",
    )

    r = sub.add_parser("rules", help="list every rule this validator checks")
    r.add_argument("--json", action="store_true", help="print the rule catalogue as JSON")
    r.add_argument("--color", choices=["auto", "always", "never"], default="auto")
    return parser


def _validate(args: argparse.Namespace) -> int:
    target = args.target
    transport = UrllibTransport(timeout=args.timeout)
    if target == "-":
        report = validate_text(sys.stdin.buffer.read(), domain=args.domain, oauth=args.check_oauth, transport=transport)
    elif os.path.isfile(target):
        report = validate_file(target, domain=args.domain, oauth=args.check_oauth, transport=transport)
    elif "://" in target or looks_like_domain(target.rstrip("/")):
        if args.check_oauth:
            print("poppy: --check-oauth applies to local files; domains and URLs run it unless --no-network", file=sys.stderr)
        report = validate_url(target, domain=args.domain, oauth=not args.no_network, transport=transport)
    else:
        print(f"poppy: {target!r} is not a file, a domain, or a URL", file=sys.stderr)
        return EXIT_USAGE

    if args.json:
        print(json.dumps(report.to_dict(strict=args.strict), indent=2))
    else:
        print(render(report, color=use_color(args.color, sys.stdout), strict=args.strict,
                     quiet=args.quiet, width=stdout_width()))
    return EXIT_OK if report.passed(args.strict) else EXIT_INVALID


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.command == "validate":
        return _validate(args)
    if args.command == "example":
        sys.stdout.write(_data("example.com.oauth-metadata.json" if args.oauth_metadata else "example.com.poppy.json"))
        return EXIT_OK
    if args.command == "rules":
        if args.json:
            rules = [dict(asdict(r), severity=r.severity.value) for r in RULES.values()]
            print(json.dumps(rules, indent=2))
        else:
            print(render_rules(use_color(args.color, sys.stdout)))
        return EXIT_OK
    return EXIT_USAGE
