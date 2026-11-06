#!/usr/bin/env python3
"""Prepare a source-only repair for two observed Mac AuthBus QA managers.

This command never imports a manager, contacts launchd, starts a service, or
changes the input file. It requires a current complete source hash and a
create-only output path. The parser-only change grants no retry or admission
for an earlier operation whose registration or lineage outcome is unknown.
"""
from __future__ import annotations

import argparse
import ast
import hashlib
import json
from pathlib import Path
import re
import sys


OBSERVED_PARSER_SHA256 = frozenset({
    "b62e41cd834b925ea44027df403b48531b68ea7c7aaa8d706a6a4f8394540db4",
    "9e73938b04176a7baabd123a4245604bb9bc0a89022cec607b916bcd619f7c99",
})
PLAIN_INTEGERS = """    for name in ('pid','runs','last exit code'):
        if name in fields:
            need(re.fullmatch(r'-?[0-9]{1,10}',fields[name]) is not None,'typed_launchctl_integer')
            fields[name]=int(fields[name])
"""
R2_INTEGERS = """    for name in ('pid','runs','last exit code'):
        if name in fields:
            typed_value=fields[name]
            if name=='last exit code' and typed_value=='78: EX_CONFIG':
                typed_value='78'
            need(re.fullmatch(r'-?[0-9]{1,10}',typed_value) is not None,'typed_launchctl_integer')
            fields[name]=int(typed_value)
"""
FIXED_INTEGERS = """    for name in ('pid','runs','last exit code'):
        if name in fields:
            typed_value=fields[name]
            if name=='last exit code' and typed_value=='(never exited)':
                # An unexited registration has no successful exit observation.
                # Keep None so actual_launchd_phase_exit_zero still rejects it.
                fields[name]=None
                continue
            if name=='last exit code' and typed_value=='78: EX_CONFIG':
                typed_value='78'
            need(re.fullmatch(r'-?[0-9]{1,10}',typed_value) is not None,'typed_launchctl_integer')
            fields[name]=int(typed_value)
"""


class PatchRefused(ValueError):
    """Only fixed reason codes are exposed; raw source is never printed."""


def build_patch(raw: bytes, expected_sha256: str) -> bytes:
    if not isinstance(raw, bytes) or not 1 <= len(raw) <= 1024 * 1024:
        raise PatchRefused("bounded_complete_manager_source")
    if not isinstance(expected_sha256, str) or re.fullmatch(r"[0-9a-f]{64}", expected_sha256) is None:
        raise PatchRefused("typed_expected_source_hash")
    if hashlib.sha256(raw).hexdigest() != expected_sha256:
        raise PatchRefused("source_hash_changed")
    try:
        source = raw.decode("utf-8", "strict")
        tree = ast.parse(source)
    except (UnicodeError, SyntaxError):
        raise PatchRefused("valid_utf8_python_source") from None
    nodes = [n for n in tree.body if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))
             and n.name == "parse_print"]
    if len(nodes) != 1 or not isinstance(nodes[0], ast.FunctionDef):
        raise PatchRefused("one_top_level_parse_print")
    node = nodes[0]
    lines = source.splitlines(keepends=True)
    fragment = "".join(lines[node.lineno - 1:node.end_lineno])
    if hashlib.sha256(fragment.encode("utf-8")).hexdigest() not in OBSERVED_PARSER_SHA256:
        raise PatchRefused("unobserved_parser_source")
    matches = [block for block in (PLAIN_INTEGERS, R2_INTEGERS) if fragment.count(block) == 1]
    if len(matches) != 1:
        raise PatchRefused("one_observed_integer_block")
    patched = fragment.replace(matches[0], FIXED_INTEGERS, 1)
    result = "".join(lines[:node.lineno - 1]) + patched + "".join(lines[node.end_lineno:])
    ast.parse(result)
    return result.encode("utf-8")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", required=True, type=Path)
    parser.add_argument("--source-sha256", required=True)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args(argv)
    try:
        if args.source.resolve() == args.output.resolve():
            raise PatchRefused("distinct_create_only_output")
        with args.source.open("rb") as input_source:
            raw = input_source.read(1024 * 1024 + 1)
        result = build_patch(raw, args.source_sha256)
        with args.output.open("xb") as output:
            output.write(result)
    except PatchRefused as error:
        print(json.dumps({"ok": False, "errorCode": str(error)}), file=sys.stderr)
        return 1
    except OSError as error:
        print(json.dumps({"ok": False, "errorType": type(error).__name__}), file=sys.stderr)
        return 1
    print(json.dumps({"ok": True, "sourceBytes": len(raw), "outputBytes": len(result),
                      "sourceSha256": hashlib.sha256(raw).hexdigest(),
                      "outputSha256": hashlib.sha256(result).hexdigest(),
                      "scope": "parser-only source artifact", "executedManager": False,
                      "modifiedSource": False, "reconciledPriorOutcome": False}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
