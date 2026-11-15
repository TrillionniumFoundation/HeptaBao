#!/usr/bin/env python3
"""Prepare the exact signed-UID repair for a fresh Mac AuthBus QA manager.

Only the source artifact is changed. This command does not import the manager,
query processes, dispatch commands, reconcile an earlier outcome, or grant a
new deadline. The input must be the already repaired never-exited R2 source.
"""
from __future__ import annotations

import argparse
import ast
import hashlib
import json
from pathlib import Path
import re
import sys

EXPECTED_MANAGER_SHA256 = "59aa264489cc8ebea2943a0a7bab68c419da52d645532391ec369b973d555941"
OBSERVED_ROWS = """    def _rows(self,groups,*,until=None,cleanup=False):
        row,out,err=self._call('owned-launchd-group-observation',
            ['/bin/ps','-axo','pid=,ppid=,pgid=,uid=,stat='],until=until,cleanup=cleanup,ps=True)
        need(row['exitCode']==0 and not err,'complete_group_observation')
        values=[]
        for line in out.decode('ascii','strict').splitlines():
            fields=line.split()
            need(len(fields)==5 and all(x.isdecimal() for x in fields[:4]),'typed_process_row')
            pid,ppid,pgid,uid=map(int,fields[:4])
            if pgid in groups:values.append({'pid':pid,'ppid':ppid,'pgid':pgid,'uid':uid,'state':fields[4]})
        return values
"""
OLD_CHECK = "            need(len(fields)==5 and all(x.isdecimal() for x in fields[:4]),'typed_process_row')\n"
NEW_CHECK = """            need(len(fields)==5 and all(x.isdecimal() for x in fields[:3])
                 and (fields[3].isdecimal() or fields[3]=='-2'),'typed_process_row')
"""


class PatchRefused(ValueError):
    """Fixed reason codes only; no raw source or process output is printed."""


def build_patch(raw: bytes, expected_sha256: str) -> bytes:
    if not isinstance(raw, bytes) or not 1 <= len(raw) <= 1024 * 1024:
        raise PatchRefused("bounded_complete_manager_source")
    if not isinstance(expected_sha256, str) or re.fullmatch(r"[0-9a-f]{64}", expected_sha256) is None:
        raise PatchRefused("typed_expected_source_hash")
    if expected_sha256 != EXPECTED_MANAGER_SHA256:
        raise PatchRefused("never_exited_fixed_r2_source_required")
    if hashlib.sha256(raw).hexdigest() != expected_sha256:
        raise PatchRefused("source_hash_changed")
    try:
        source = raw.decode("utf-8", "strict")
        tree = ast.parse(source)
    except (UnicodeError, SyntaxError):
        raise PatchRefused("valid_utf8_python_source") from None
    owners = [n for n in tree.body if isinstance(n, ast.ClassDef) and n.name == "OwnedLaunchd"]
    if len(owners) != 1:
        raise PatchRefused("one_owned_launchd_class")
    methods = [n for n in owners[0].body if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))
               and n.name == "_rows"]
    if len(methods) != 1 or not isinstance(methods[0], ast.FunctionDef):
        raise PatchRefused("one_owned_rows_method")
    node = methods[0]
    lines = source.splitlines(keepends=True)
    fragment = "".join(lines[node.lineno - 1:node.end_lineno])
    if fragment != OBSERVED_ROWS:
        raise PatchRefused("exact_observed_rows_source")
    if fragment.count(OLD_CHECK) != 1:
        raise PatchRefused("one_observed_integer_check")
    patched = fragment.replace(OLD_CHECK, NEW_CHECK, 1)
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
        with args.source.open("rb") as source:
            raw = source.read(1024 * 1024 + 1)
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
                      "scope": "exact UID-minus-two parser source artifact",
                      "executedManager": False, "queriedProcesses": False,
                      "modifiedSource": False, "reconciledPriorOutcome": False,
                      "grantedNewDeadline": False}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
