#!/usr/bin/env python3
"""Bounded lexical integrity checks for Rust sources when rustc is unavailable.

This is development evidence only. It never represents formatting, compilation,
Clippy, execution, qualification, compatibility or authority evidence.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any

DELIMITER_PAIRS = {"(": ")", "[": "]", "{": "}"}
CLOSERS = set(DELIMITER_PAIRS.values())
FORBIDDEN_NON_TEST = (
    re.compile(r"\.unwrap\s*\("),
    re.compile(r"\.expect\s*\("),
    re.compile(r"\bpanic!\s*\("),
    re.compile(r"\btodo!\s*\("),
    re.compile(r"\bunimplemented!\s*\("),
)


class RustSurfaceError(RuntimeError):
    pass


def _raw_string_start(text: str, index: int) -> tuple[int, str] | None:
    """Return (content-start, terminator) for r/raw byte string prefixes."""
    for prefix in ("br", "rb", "r"):
        if not text.startswith(prefix, index):
            continue
        cursor = index + len(prefix)
        hashes = 0
        while cursor < len(text) and text[cursor] == "#":
            hashes += 1
            cursor += 1
        if cursor < len(text) and text[cursor] == '"':
            return cursor + 1, '"' + ("#" * hashes)
    return None


def strip_comments_and_literals(text: str) -> str:
    output = list(text)
    index = 0
    length = len(text)
    while index < length:
        if text.startswith("//", index):
            end = text.find("\n", index + 2)
            if end < 0:
                end = length
            for pos in range(index, end):
                output[pos] = " "
            index = end
            continue
        if text.startswith("/*", index):
            depth = 1
            cursor = index + 2
            while cursor < length and depth:
                if text.startswith("/*", cursor):
                    depth += 1
                    cursor += 2
                elif text.startswith("*/", cursor):
                    depth -= 1
                    cursor += 2
                else:
                    cursor += 1
            if depth:
                raise RustSurfaceError("unterminated block comment")
            for pos in range(index, cursor):
                if output[pos] != "\n":
                    output[pos] = " "
            index = cursor
            continue
        raw = _raw_string_start(text, index)
        if raw is not None:
            content_start, terminator = raw
            end = text.find(terminator, content_start)
            if end < 0:
                raise RustSurfaceError("unterminated raw string")
            cursor = end + len(terminator)
            for pos in range(index, cursor):
                if output[pos] != "\n":
                    output[pos] = " "
            index = cursor
            continue
        string_prefix = 1 if text.startswith('b"', index) else 0
        if text[index] == '"' or string_prefix:
            cursor = index + string_prefix + 1
            escaped = False
            while cursor < length:
                char = text[cursor]
                if escaped:
                    escaped = False
                elif char == "\\":
                    escaped = True
                elif char == '"':
                    cursor += 1
                    break
                cursor += 1
            else:
                raise RustSurfaceError("unterminated string literal")
            for pos in range(index, cursor):
                if output[pos] != "\n":
                    output[pos] = " "
            index = cursor
            continue
        if text[index] == "'":
            # Lifetimes such as 'a do not have a closing quote. Treat only a
            # bounded Rust character literal as a literal.
            cursor = index + 1
            if cursor < length and text[cursor] == "\\":
                cursor += 2
                if cursor < length and text[cursor] == "'":
                    cursor += 1
                else:
                    index += 1
                    continue
            elif cursor + 1 < length and text[cursor + 1] == "'":
                cursor += 2
            else:
                index += 1
                continue
            for pos in range(index, cursor):
                output[pos] = " "
            index = cursor
            continue
        index += 1
    return "".join(output)


def validate_text(text: str, *, path: str = "<memory>") -> dict[str, Any]:
    stripped = strip_comments_and_literals(text)
    stack: list[tuple[str, int]] = []
    for index, char in enumerate(stripped):
        if char in DELIMITER_PAIRS:
            stack.append((char, index))
        elif char in CLOSERS:
            if not stack:
                raise RustSurfaceError(f"{path}: unexpected closing delimiter {char!r}")
            opener, position = stack.pop()
            if DELIMITER_PAIRS[opener] != char:
                raise RustSurfaceError(
                    f"{path}: delimiter mismatch {opener!r} at {position} with {char!r} at {index}"
                )
    if stack:
        opener, position = stack[-1]
        raise RustSurfaceError(f"{path}: unclosed delimiter {opener!r} at {position}")
    if "#![forbid(unsafe_code)]" not in text:
        raise RustSurfaceError(f"{path}: missing #![forbid(unsafe_code)]")
    non_test = stripped.split("#[cfg(test)]", 1)[0]
    for pattern in FORBIDDEN_NON_TEST:
        if pattern.search(non_test):
            raise RustSurfaceError(f"{path}: forbidden fail-open macro/method: {pattern.pattern}")
    if re.search(r"(?<!forbid\()\bunsafe\s*(?:\{|fn\b|impl\b|trait\b)", non_test):
        raise RustSurfaceError(f"{path}: unsafe surface found")
    return {
        "path": path,
        "line_count": text.count("\n") + 1,
        "byte_count": len(text.encode("utf-8")),
        "balanced": True,
        "unsafe_forbidden": True,
        "forbidden_non_test_macros": 0,
    }


def validate_file(path: Path) -> dict[str, Any]:
    return validate_text(path.read_text(encoding="utf-8"), path=str(path))


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("paths", nargs="+")
    parser.add_argument("--output")
    args = parser.parse_args()
    try:
        results = [validate_file(Path(value)) for value in args.paths]
    except (OSError, UnicodeError, RustSurfaceError) as error:
        print(f"Rust source surface validation FAILED: {error}", file=sys.stderr)
        return 1
    report = {
        "schema": "heptabao.rust-source-surface-report.v1",
        "classification": "LEXICAL_DEVELOPMENT_EVIDENCE_NOT_COMPILATION",
        "files": results,
        "file_count": len(results),
        "qualification": False,
        "authority_effect": "NONE",
    }
    encoded = json.dumps(report, indent=2, sort_keys=True) + "\n"
    if args.output:
        Path(args.output).write_text(encoded, encoding="utf-8")
    print(encoded, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
