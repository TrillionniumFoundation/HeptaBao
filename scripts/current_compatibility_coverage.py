#!/usr/bin/env python3
"""Derive documentation counts from corpus rows, not copied summary constants."""
from __future__ import annotations

import argparse
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
GUIDE = "docs/modules/heptabao-compatibility.md"
CORPUS = "qa/openbao-acceptance/complete_surface_corpus_v1.json"
BEGIN = "<!-- BEGIN CURRENT COMPATIBILITY COVERAGE -->"
END = "<!-- END CURRENT COMPATIBILITY COVERAGE -->"


def render(root: Path = ROOT) -> str:
    corpus = json.loads((root / CORPUS).read_text(encoding="utf-8"))
    rows = corpus["surfaces"]
    ids = [row["surface_id"] for row in rows]
    cases = [case for row in rows for case in row["fixture_case_ids"]]
    if not ids or len(ids) != len(set(ids)) or len(cases) != len(set(cases)):
        raise ValueError("duplicate or empty compatibility inventory")
    states = [row["fixture_state"] for row in rows]
    if set(states) - {"IMPLEMENTED_SCOPED", "DEFINED_NOT_IMPLEMENTED"}:
        raise ValueError("unrecognized fixture state")
    # Independent observations are deliberately not inferred from row counts.
    # The separate corpus/admission validators own authenticated evidence.
    return "\n".join([
        BEGIN,
        "| Source-derived coverage metric | Count |",
        "|---|---:|",
        f"| Inventoried surfaces | {len(rows)} |",
        f"| Surfaces with scoped fixtures | {states.count('IMPLEMENTED_SCOPED')} |",
        f"| Surfaces without implemented fixtures | {states.count('DEFINED_NOT_IMPLEMENTED')} |",
        f"| Scoped fixture cases | {len(cases)} |",
        "",
        "Scoped fixtures are not full behavior coverage or independent compatibility admission.",
        "The counts above are regenerated from corpus rows; they are not test-pass receipts.",
        END,
    ])


def validate(root: Path = ROOT) -> list[str]:
    try:
        text = (root / GUIDE).read_text(encoding="utf-8")
        if text.count(BEGIN) != 1 or text.count(END) != 1:
            return ["compatibility guide needs exactly one current coverage projection"]
        start, end = text.index(BEGIN), text.index(END) + len(END)
        if end <= start or text[start:end] != render(root):
            return ["current compatibility documentation coverage drift"]
        return []
    except (OSError, ValueError, KeyError, TypeError) as error:
        return [f"compatibility documentation coverage: {error}"]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--write", action="store_true")
    args = parser.parse_args()
    if args.write:
        path = ROOT / GUIDE
        text = path.read_text(encoding="utf-8")
        if text.count(BEGIN) != 1 or text.count(END) != 1 or text.index(END) < text.index(BEGIN):
            raise SystemExit("missing, reversed or duplicate coverage markers")
        path.write_text(text[:text.index(BEGIN)] + render() + text[text.index(END) + len(END):], encoding="utf-8")
    errors = validate()
    for error in errors:
        print(error)
    if not errors:
        print("compatibility-documentation: PASS (source projection, not compatibility)")
    return int(bool(errors))


if __name__ == "__main__":
    raise SystemExit(main())
