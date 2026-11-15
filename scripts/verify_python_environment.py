#!/usr/bin/env python3
"""Read-only exact direct Python prerequisite check; never installs or changes pins."""
from __future__ import annotations
import importlib.metadata
import json
from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parents[1]
MINIMUM_RUNTIME = (3, 11)


def required(path: Path) -> dict[str, str]:
    result = {}
    for line in path.read_text().splitlines():
        line = line.split('#', 1)[0].strip()
        if not line:
            continue
        match = re.fullmatch(r'([A-Za-z][A-Za-z0-9_.-]*)==([0-9][A-Za-z0-9_.+-]*)', line)
        if not match:
            raise ValueError('direct prerequisite must have one exact version')
        name, version = match.groups()
        key = re.sub('[-_.]+', '-', name).lower()
        if key in result:
            raise ValueError('duplicate direct prerequisite')
        result[key] = version
    if not result:
        raise ValueError('empty direct prerequisite set')
    return result


def inspect(path: Path = ROOT / 'requirements-plan.txt', version=importlib.metadata.version,
            runtime=None) -> dict:
    pins = required(path)
    installed = {}
    for name in pins:
        try:
            installed[name] = version(name)
        except importlib.metadata.PackageNotFoundError:
            installed[name] = None
    runtime = tuple(sys.version_info[:3] if runtime is None else runtime)
    return {'schema':'heptabao.python-environment.v1', 'required':pins, 'installed':installed,
            'python_runtime':'.'.join(str(part) for part in runtime),
            'minimum_python_runtime':'.'.join(str(part) for part in MINIMUM_RUNTIME),
            'runtime_supported':runtime[:2] >= MINIMUM_RUNTIME,
            'exact_direct_pins':installed == pins, 'transitive_dependency_lock':False,
            'qualification':False}


def main() -> int:
    result = inspect()
    print(json.dumps(result, sort_keys=True))
    return 0 if result['runtime_supported'] and result['exact_direct_pins'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
