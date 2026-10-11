"""Render the README's terminal images from real poppy-validator output.

    uv run python scripts/render_readme_svgs.py

The "live" runs use canned responses (the spec's example documents) instead
of the network, so the images are reproducible. Everything printed is the
validator's real output, converted from ANSI colors to SVG.
"""

from __future__ import annotations

import copy
import json
import re
import sys
from html import escape
from pathlib import Path

from poppy_validator.fetch import Response, TransportError
from poppy_validator.output import render
from poppy_validator.validator import validate_url

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "docs" / "assets"
DATA = ROOT / "src" / "poppy_validator" / "data"

CW, LH, FS, PAD, BAR = 7.8, 20, 13, 20, 34
FONT = "ui-monospace, 'SF Mono', SFMono-Regular, Menlo, Consolas, 'Liberation Mono', monospace"
PALETTE = {
    "bg": "#15151b", "bar": "#22222b", "fg": "#d7d7de", "dim": "#7c7c8a",
    "31": "#ec6f7a", "32": "#8fcf7a", "33": "#e8c06c", "34": "#6fa8f5", "35": "#c792ea", "36": "#5fc4d4",
}
SGR = re.compile(r"\033\[([0-9;]*)m")
NB = "\u00a0"  # keeps runs of spaces in every SVG renderer


class Canned:
    def __init__(self, routes):
        self.routes = routes

    def get(self, url):
        if url not in self.routes:
            raise TransportError("no route")
        body, status, headers = self.routes[url]
        if isinstance(body, (dict, list)):
            body = json.dumps(body)
        return Response(status, url, body.encode(), headers)


def ansi_rows(text: str):
    """Split ANSI text into rows of (text, color, bold, dim) spans."""
    rows = []
    for line in text.split("\n"):
        spans, color, bold, dim, pos = [], "fg", False, False, 0
        for m in SGR.finditer(line):
            if m.start() > pos:
                spans.append((line[pos:m.start()], color, bold, dim))
            for code in (m.group(1) or "0").split(";"):
                if code == "0":
                    color, bold, dim = "fg", False, False
                elif code == "1":
                    bold = True
                elif code == "2":
                    dim = True
                elif code in PALETTE:
                    color = code
            pos = m.end()
        if pos < len(line):
            spans.append((line[pos:], color, bold, dim))
        rows.append(spans)
    return rows


def terminal_svg(command: str, output: str, title: str, cols: int = 100) -> str:
    rows = [[("$ ", "32", True, False), (command, "fg", True, False)], []] + ansi_rows(output)
    width = PAD * 2 + cols * CW
    height = BAR + PAD + len(rows) * LH + PAD - 6
    out = [
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{width:.0f}" height="{height:.0f}" '
        f'viewBox="0 0 {width:.0f} {height:.0f}" role="img" aria-label="{escape(title)}">',
        f'<title>{escape(title)}</title>',
        f'<rect width="100%" height="100%" rx="10" fill="{PALETTE["bg"]}"/>',
        f'<path d="M0 10 a10 10 0 0 1 10 -10 h{width - 20:.0f} a10 10 0 0 1 10 10 v{BAR - 10} h-{width:.0f} z" fill="{PALETTE["bar"]}"/>',
    ]
    for i, c in enumerate(("#ec6f7a", "#e8c06c", "#8fcf7a")):
        out.append(f'<circle cx="{PAD + i * 18}" cy="{BAR / 2}" r="5.5" fill="{c}"/>')
    out.append(
        f'<text x="{width / 2:.0f}" y="{BAR / 2 + 4.5}" fill="{PALETTE["dim"]}" font-family="{FONT}" '
        f'font-size="12" text-anchor="middle">{escape(title)}</text>'
    )
    out.append(f'<g font-family="{FONT}" font-size="{FS}" xml:space="preserve">')
    y = BAR + PAD + 8
    for row in rows:
        tspans = []
        for text, color, bold, dim in row:
            fill = PALETTE["dim"] if dim and color == "fg" else PALETTE.get(color, PALETTE["fg"])
            attrs = f'fill="{fill}"' + (' font-weight="700"' if bold else "") + (' opacity="0.75"' if dim and color != "fg" else "")
            tspans.append(f"<tspan {attrs}>{escape(text).replace(' ', NB)}</tspan>")
        if tspans:
            out.append(f'<text x="{PAD}" y="{y}">{"".join(tspans)}</text>')
        y += LH
    out.append("</g></svg>")
    return "\n".join(out)


def main() -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    doc = json.loads((DATA / "example.com.poppy.json").read_text())
    meta = json.loads((DATA / "example.com.oauth-metadata.json").read_text())
    cache = {"content-type": "application/json", "cache-control": "max-age=3600"}

    # 1. The spec's own example, served live: every check passes.
    ok = Canned({
        "https://example.com/.well-known/poppy.json": (doc, 200, cache),
        "https://auth.example.com/.well-known/oauth-authorization-server": (meta, 200, cache),
    })
    report = validate_url("example.com", transport=ok)
    text = render(report, color=True, width=94)
    (OUT / "terminal-pass.svg").write_text(terminal_svg("poppy validate example.com", text, "poppy-validator · passing"))

    # 2. A broken document behind a redirect: errors and info findings.
    bad = copy.deepcopy(doc)
    bad["organization"]["domain"] = "example-shop.com"
    bad["auth"]["device"]["scopes"].append("loyalty_points")
    bad["extensions"] = {"gift-wrap": {"version": "1"}}
    bad["support_phone"] = "+1 555 0100"
    bad_meta = copy.deepcopy(meta)
    del bad_meta["authorization_endpoint"]
    hosted = "https://cdn.example.net/example.com/poppy.json"
    broken = Canned({
        "https://example.com/.well-known/poppy.json": ("", 302, {"location": hosted}),
        hosted: (bad, 200, cache),
        "https://auth.example.com/.well-known/oauth-authorization-server": (bad_meta, 200, cache),
    })
    report = validate_url("example.com", transport=broken)
    text = render(report, color=True, width=94)
    (OUT / "terminal-fail.svg").write_text(terminal_svg("poppy validate example.com", text, "poppy-validator · failing"))

    # 3. JSON for CI, trimmed to the first finding.
    data = report.to_dict()
    data["findings"] = data["findings"][:1]
    data["findings"][0]["message"] = data["findings"][0]["message"][:48] + "..."
    for key in ("validator", "requested_url", "final_url", "strict"):
        data.pop(key)
    pretty = json.dumps(data, indent=2)
    colored = re.sub(r'("[^"]+")(:)', "\033[36m\\1\033[0m\\2", pretty)
    colored = re.sub(r'(: )("[^"]*")', "\\1\033[32m\\2\033[0m", colored)
    colored = re.sub(r"(: )(true|false|\d+)", "\\1\033[33m\\2\033[0m", colored)
    (OUT / "terminal-json.svg").write_text(
        terminal_svg("poppy validate example.com --json", colored, "poppy-validator · --json (trimmed)", cols=86)
    )
    print("wrote", *sorted(p.name for p in OUT.glob("terminal-*.svg")), file=sys.stderr)


if __name__ == "__main__":
    main()
