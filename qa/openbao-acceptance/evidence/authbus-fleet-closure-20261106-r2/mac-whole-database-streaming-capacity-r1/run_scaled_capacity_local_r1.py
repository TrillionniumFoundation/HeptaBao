#!/usr/bin/env python3
"""Exercise new large-fixture paths at 8 MiB locally; this is not capacity proof."""
import ast
import hashlib
import json
import os
from pathlib import Path
import sys
import tempfile
import time

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
os.umask(0o077)
source = (HERE / "qualify_whole_sqlite_capacity_r1.py").read_text()
assert source.count("MINIMUM_PRIMARY_BYTES = 2469126144") == 1
variant = source.replace("MINIMUM_PRIMARY_BYTES = 2469126144", "MINIMUM_PRIMARY_BYTES = 8388608")
scope = {"__name__": "capacity_scaled_local_only", "__file__": str(HERE / "scaled-local-only.py")}
exec(compile(variant, "scaled-local-only.py", "exec"), scope)
launcher = (HERE / "launch_mac_whole_sqlite_capacity_r1.py").read_text()
payload = ast.literal_eval(next(node.value for node in ast.parse(launcher).body
    if isinstance(node, ast.Assign) and any(isinstance(target, ast.Name) and target.id == "PAYLOAD"
                                           for target in node.targets)))
directory = Path(tempfile.mkdtemp(prefix="scaled-local-", dir=HERE))
result = scope["run_capacity_qualification"](directory / "fixture", payload["schemas"]["agent"],
    payload["schemas"]["state"], until=time.monotonic() + 60, source_vfs="unix")
report = {"schema": "heptabao.capacity-paths-scaled-local-qualification.r1",
    "localOnly": True, "macExecuted": False, "actualCapacityQualified": False,
    "originalSourceSha256": hashlib.sha256(source.encode()).hexdigest(),
    "localVariantSha256": hashlib.sha256(variant.encode()).hexdigest(),
    "onlyRuntimeFixtureScaleChange": {"originalMinimumBytes": 2469126144, "localMinimumBytes": 8388608},
    "coreSha256": hashlib.sha256((HERE / "whole_sqlite_streaming_r1.py").read_bytes()).hexdigest(),
    "result": result}
raw = json.dumps(report, sort_keys=True, separators=(",", ":")) + "\n"
(HERE / "scaled-capacity-local.original.json").write_text(raw)
print(raw, end="")
raise SystemExit(0 if result["ok"] and len(result["cases"]) == 17 else 1)
