#!/usr/bin/env python3
"""Local Linux validation only; never opens any installed user's database."""
import ast
import json
import os
from pathlib import Path
import resource
import sqlite3
import sys
import tempfile
import time

from qualify_whole_sqlite_streaming_r1 import run_qualification

HERE = Path(__file__).resolve().parent
os.umask(0o077)
tree = ast.parse((HERE.parent / "mac-whole-sqlite-r2-work/launch_mac_whole_sqlite_qualification_r2.py").read_text())
payload = ast.literal_eval(next(node.value for node in tree.body if isinstance(node, ast.Assign)
    and any(isinstance(target, ast.Name) and target.id == "PAYLOAD" for target in node.targets)))
parent = Path(tempfile.mkdtemp(prefix="local-six-", dir=HERE))
result = run_qualification(parent / "fixture", payload["schemas"]["agent"], payload["schemas"]["state"],
                           until=time.monotonic() + 30, source_vfs="unix")
result["runtime"] = {"platform": sys.platform, "python": sys.version, "sqlite": sqlite3.sqlite_version}
result["isMacQualification"] = False
result["processMaximumRssBytes"] = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss * 1024
raw = json.dumps(result, sort_keys=True, separators=(",", ":")) + "\n"
(parent / "result.public.json").write_text(raw)
(HERE / "local-six-result.original.json").write_text(raw)
print(raw, end="")
raise SystemExit(0 if result["ok"] else 1)
