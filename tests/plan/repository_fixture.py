"""Shared repository copies and mutations for plan regression tests."""
from __future__ import annotations

from pathlib import Path
import shutil
import tempfile


def temporary_repository(source: Path, name: str):
    temporary = tempfile.TemporaryDirectory()
    root = Path(temporary.name) / name
    shutil.copytree(
        source,
        root,
        ignore=shutil.ignore_patterns(".git", "target", "__pycache__", "*.pyc"),
    )
    return temporary, root


def temporary_surface(source: Path, required_paths):
    temporary = tempfile.TemporaryDirectory()
    root = Path(temporary.name)
    for relative in required_paths:
        target = root / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source / relative, target)
    return temporary, root


def assert_mutation_rejected(test, candidate, validate, path, mutate, expected_error=None):
    temporary, root = candidate()
    try:
        test.assertEqual(validate(root), [])
        target = root / path
        mutate(target)
        errors = validate(root)
        test.assertTrue(errors)
        if expected_error is not None:
            test.assertTrue(any(expected_error in error for error in errors), errors)
    finally:
        temporary.cleanup()


def replace_text(root: Path, relative: str, old: str, new: str) -> None:
    path = root / relative
    text = path.read_text(encoding="utf-8")
    if old not in text:
        raise AssertionError(f"mutation marker not found in {relative}: {old}")
    path.write_text(text.replace(old, new, 1), encoding="utf-8")
