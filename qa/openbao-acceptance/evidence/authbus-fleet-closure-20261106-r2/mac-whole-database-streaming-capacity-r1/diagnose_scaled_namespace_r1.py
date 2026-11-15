#!/usr/bin/env python3
"""One local synthetic diagnostic; never changes a source identity predicate."""
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
import whole_sqlite_streaming_r1 as core

original_namespace = core.WholeStore.namespace
seen = {}
observations = []
fields = ("device", "inode", "uid", "gid", "mode", "nlink", "size", "mtimeNs", "ctimeNs")


def observed_namespace(self, path):
    result = original_namespace(self, path)
    key = str(path)
    if key in seen and seen[key] != result:
        changes = []
        for suffix in ("", "-wal", "-shm", "-journal"):
            before, after = seen[key][suffix], result[suffix]
            if before != after:
                changes.append({"suffix": suffix, "presenceChanged": (before is None) != (after is None),
                    "changedFields": [name for number, name in enumerate(fields)
                        if before is not None and after is not None and before[number] != after[number]]})
        observations.append({"slotOrdinal": list(seen).index(key), "changes": changes})
    seen[key] = result
    return result


core.WholeStore.namespace = observed_namespace
source = (HERE / "qualify_whole_sqlite_capacity_r1.py").read_text()
assert source.count("MINIMUM_PRIMARY_BYTES = 2469126144") == 1
variant = source.replace("MINIMUM_PRIMARY_BYTES = 2469126144", "MINIMUM_PRIMARY_BYTES = 8388608")
scope = {"__name__": "scaled_namespace_diagnostic_only", "__file__": str(HERE / "diagnostic-local-only.py")}
exec(compile(variant, "diagnostic-local-only.py", "exec"), scope)
launcher = (HERE / "launch_mac_whole_sqlite_capacity_r1.py").read_text()
payload = ast.literal_eval(next(node.value for node in ast.parse(launcher).body
    if isinstance(node, ast.Assign) and any(isinstance(target, ast.Name) and target.id == "PAYLOAD"
                                           for target in node.targets)))
directory = Path(tempfile.mkdtemp(prefix="namespace-diagnostic-local-", dir=HERE))
try:
    result = scope["run_capacity_qualification"](directory / "fixture", payload["schemas"]["agent"],
        payload["schemas"]["state"], until=time.monotonic() + 60, source_vfs="unix")
finally:
    core.WholeStore.namespace = original_namespace
report = {"schema": "heptabao.capacity-namespace-local-diagnostic.r1", "localOnly": True,
    "macExecuted": False, "sourcePredicateChanged": False, "smallCoreSourceUnchanged": True,
    "coreSha256": hashlib.sha256((HERE / "whole_sqlite_streaming_r1.py").read_bytes()).hexdigest(),
    "result": result, "changes": observations}
raw = json.dumps(report, sort_keys=True, separators=(",", ":")) + "\n"
(HERE / "scaled-namespace-diagnostic.original.json").write_text(raw)
print(raw, end="")
