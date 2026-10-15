#!/usr/bin/env python3
"""Summarize V6 fixture strace syscall durations without exposing syscall arguments.

Parse only existing strace -f/-ff -ttt -T logs. This utility never executes,
attaches to, or signals a process, and never reads secrets from syscall args.
Summed syscall duration across threads is NOT elapsed wall time.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
from pathlib import Path

OPS = frozenset({
    "open", "openat", "openat2", "close", "fsync", "fdatasync", "syncfs",
    "link", "linkat", "unlink", "unlinkat", "rename", "renameat", "renameat2",
    "fstat", "newfstatat", "statx", "pread64", "pwrite64", "read", "write",
})
# Bucket ceilings in milliseconds. Percentiles are upper bounds, not exact
# percentiles, and remain bounded regardless of the input's syscall count.
BUCKET_UPPER_MS = (0.01, 0.1, 1.0, 10.0, 100.0, 1000.0, 10000.0)
END_TIME = re.compile(r"<(?P<seconds>\d+(?:\.\d+)?)>\s*$")
OP_CALL = re.compile(r"(?<![A-Za-z_])(?P<op>[a-z][a-z0-9_]*)\(")
OP_RESUMED = re.compile(r"<\.\.\.\s*(?P<op>[a-z][a-z0-9_]*)\s+resumed>")
ERRNO = re.compile(r"\s=\s-1\s+(?P<errno>[A-Z][A-Z0-9_]*)\b")
PHASE = re.compile(r"HBV6-SNAPSHOT-PHASE\s+phase=(?P<phase>[a-z][a-z-]*)\s+elapsed_ms=(?P<ms>\d+)")
STAGE = re.compile(r"HBV6-RESTORE-STAGE\s+objects=(?P<objects>\d+)\s+elapsed_ms=(?P<ms>\d+)")
MAX_SINGLE_FILE_BYTES = 256 * 1024 * 1024


def _bucket(milliseconds: float) -> int:
    for index, upper in enumerate(BUCKET_UPPER_MS):
        if milliseconds <= upper:
            return index
    return len(BUCKET_UPPER_MS)


def _quantile_upper(buckets: list[int], count: int, numerator: int) -> float | None:
    if not count:
        return None
    # ceil(count * percentile), with no floating-point rank error.
    rank = (count * numerator + 99) // 100
    seen = 0
    for index, total in enumerate(buckets):
        seen += total
        if seen >= rank:
            return BUCKET_UPPER_MS[index] if index < len(BUCKET_UPPER_MS) else None
    raise AssertionError("bucket accounting mismatch")


def _empty_op() -> dict:
    return {"count": 0, "errors": 0, "duration_ms": 0.0,
            "max_ms": 0.0, "buckets": [0] * (len(BUCKET_UPPER_MS) + 1),
            "errno_counts": {}}


def parse_trace(paths: list[Path]) -> dict:
    if not paths:
        raise ValueError("at least one trace file is required")
    stats: dict[str, dict] = {}
    total_bytes = total_lines = incomplete = ignored = 0
    hashes = []
    for path in paths:
        if not path.is_file() or path.is_symlink():
            raise ValueError("each trace must be an existing regular, non-symlink file")
        size = path.stat().st_size
        if size > MAX_SINGLE_FILE_BYTES:
            raise ValueError("trace exceeds the maximum allowed file size")
        total_bytes += size
        digest = hashlib.sha256()
        with path.open("rb") as stream:
            for raw in stream:
                digest.update(raw)
                total_lines += 1
                # strace may log arguments with user data. Never retain or
                # serialize raw lines, only matching operation/timing fields.
                line = raw.decode("utf-8", errors="replace")
                end = END_TIME.search(line)
                if not end:
                    if "<unfinished ...>" in line or "resumed>" in line:
                        incomplete += 1
                    else:
                        ignored += 1
                    continue
                resumed = OP_RESUMED.search(line)
                op_match = resumed or OP_CALL.search(line)
                if not op_match or op_match.group("op") not in OPS:
                    ignored += 1
                    continue
                op = op_match.group("op")
                duration_ms = float(end.group("seconds")) * 1000.0
                state = stats.setdefault(op, _empty_op())
                state["count"] += 1
                state["duration_ms"] += duration_ms
                state["max_ms"] = max(state["max_ms"], duration_ms)
                state["buckets"][_bucket(duration_ms)] += 1
                err = ERRNO.search(line[:end.start()])
                if err:
                    state["errors"] += 1
                    code = err.group("errno")
                    state["errno_counts"][code] = state["errno_counts"].get(code, 0) + 1
        hashes.append(digest.hexdigest())
    if not stats:
        raise ValueError("no completed supported strace syscall with -T timing was found")
    output_ops = {}
    for name in sorted(stats):
        s = stats[name]
        output_ops[name] = {
            "count": s["count"],
            "error_count": s["errors"],
            "errno_counts": dict(sorted(s["errno_counts"].items())),
            "cumulative_thread_ms": round(s["duration_ms"], 3),
            "max_single_call_ms": round(s["max_ms"], 3),
            "p50_upper_bound_ms": _quantile_upper(s["buckets"], s["count"], 50),
            "p95_upper_bound_ms": _quantile_upper(s["buckets"], s["count"], 95),
            "p99_upper_bound_ms": _quantile_upper(s["buckets"], s["count"], 99),
            "histogram_counts": s["buckets"],
        }
    return {
        "schema": "heptabao.v6.fixture-strace-redacted.v1",
        "trace_file_count": len(paths),
        "input_total_bytes": total_bytes,
        "input_sha256_in_input_order": hashes,
        "observed_lines": total_lines,
        "unfinished_or_resumed_without_timing": incomplete,
        "other_lines": ignored,
        "histogram_bucket_upper_bounds_ms": list(BUCKET_UPPER_MS),
        "operations": output_ops,
        "limitations": [
            "Summed syscall durations across concurrent threads are not wall time.",
            "Histogram percentiles are bucket upper bounds; null means above 10000 ms.",
            "Only complete supported syscalls with strace -T timings count.",
            "This output is not evidence of a committed V6 root or migration success.",
        ],
        "production_changed": False,
        "qualified_for_v6_ha": False,
    }


def parse_phase_logs(paths: list[Path]) -> dict:
    phases = []
    checkpoints = []
    for path in paths:
        if not path.is_file() or path.is_symlink():
            raise ValueError("each service log must be a regular non-symlink file")
        if path.stat().st_size > MAX_SINGLE_FILE_BYTES:
            raise ValueError("service log exceeds the maximum allowed file size")
        with path.open("r", encoding="utf-8", errors="replace") as stream:
            for line in stream:
                phase = PHASE.search(line)
                if phase:
                    phases.append({"phase": phase.group("phase"),
                                   "elapsed_ms": int(phase.group("ms"))})
                stage = STAGE.search(line)
                if stage:
                    checkpoints.append({"objects": int(stage.group("objects")),
                                        "elapsed_ms": int(stage.group("ms"))})
    return {"phase_durations": phases, "staged_object_checkpoints": checkpoints}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--trace", type=Path, action="append", required=True,
                        help="existing strace -f/-ff -ttt -T file; repeat for each PID")
    parser.add_argument("--server-log", type=Path, action="append", default=[],
                        help="optional existing fixture server log; only redacted phase timings are parsed")
    parser.add_argument("--output", type=Path,
                        help="create a new private JSON file; existing files are never overwritten")
    args = parser.parse_args()
    os.umask(0o077)
    try:
        report = parse_trace(args.trace)
        report.update(parse_phase_logs(args.server_log))
        serialized = json.dumps(report, indent=2, sort_keys=True) + "\n"
        if args.output:
            with args.output.open("x", encoding="utf-8") as handle:
                handle.write(serialized)
        else:
            print(serialized, end="")
        return 0
    except (OSError, ValueError):
        # Never interpolate filenames, syscall arguments or secret content in
        # error output; these can themselves contain credential-like material.
        parser.exit(status=2, message="Invalid or unsupported trace/log input.\n")
    raise AssertionError("unreachable")


if __name__ == "__main__":
    raise SystemExit(main())
