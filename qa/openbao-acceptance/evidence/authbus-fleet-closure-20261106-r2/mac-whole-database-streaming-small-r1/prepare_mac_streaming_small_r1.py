#!/usr/bin/env python3
"""Prepare the new small Mac qualification without dispatching anything."""
import ast
import difflib
import hashlib
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
OLD = HERE.parent / "mac-whole-sqlite-r2-work"
OLD_ROOT = "heptabao-authbus-whole-database-qualification-20261106-r2"
NEW_ROOT = "heptabao-authbus-whole-database-streaming-small-20261106-r1"
NAMES = {"whole_sqlite_bundle_r2": "whole_sqlite_streaming_r1",
         "qualify_whole_sqlite_bundle_r2": "qualify_whole_sqlite_streaming_r1",
         "mac_whole_sqlite_worker_r2": "mac_whole_sqlite_streaming_worker_r1",
         "launch_mac_whole_sqlite_qualification_r2": "launch_mac_whole_sqlite_streaming_small_r1"}


def base(source):
    source = source.replace(OLD_ROOT, NEW_ROOT).replace("67108864", "4294967296")
    for old, new in NAMES.items():
        source = source.replace(old, new)
    return source


worker = base((OLD / "mac_whole_sqlite_worker_r2.py").read_text())
worker = worker.replace("import socket\n", "import socket\nimport resource\n")
worker = worker.replace("from qualify_whole_sqlite_streaming_r1 import run_qualification",
                        "from qualify_whole_sqlite_streaming_r1 import run_qualification, run_snapshot_mechanism")
worker = worker.replace("qualification-worker.r2", "qualification-worker.streaming.r1")
worker = worker.replace("whole-sqlite-plan.r2", "whole-sqlite-plan.streaming.r1")
before = '    report["qualification"] = result\n'
assert worker.count(before) == 1
worker = worker.replace(before, before + '''    need(result["ok"] and all(result["resources"][name] for name in (
        "allFileDescriptorsClosedOnce", "allSqliteHandlesClosedOnce", "allExplicitCursorsClosed")),
        "whole_streaming_six_bundle_original_known_complete")
    mechanism = run_snapshot_mechanism(ROOT / "output/snapshot-mechanism", until=UNTIL,
                                       source_vfs="unix-posix")
    report["snapshotMechanism"] = mechanism
    need(mechanism["ok"] and len(mechanism["cases"]) == 5,
         "whole_streaming_snapshot_mechanism_complete")
    report["processMaximumRssBytes"] = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    report["memoryBudgetBytes"] = 512 * 1048576
    need(type(report["processMaximumRssBytes"]) is int
         and 0 < report["processMaximumRssBytes"] <= report["memoryBudgetBytes"],
         "actual_darwin_streaming_process_memory_budget")
''')

template = base((OLD / "launch_mac_whole_sqlite_qualification_r2.template.py").read_text())
template = template.replace("qualification-launch.r2", "qualification-launch.streaming.r1")
template = template.replace("whole-sqlite-plan.r2", "whole-sqlite-plan.streaming.r1")
template = template.replace("len(qualified['cases'])==13", "len(qualified['cases'])==14")
before = "   and qualified['resources']['allDarwinXattrQueriesClosedAndAbsent']\n"
assert template.count(before) == 1
template = template.replace(before, before + '''   and qualified['resources']['allStreamOperationsCompleteAndClosed']
   and qualified['resources']['allOriginalBackupsCompleted']
   and qualified['resources']['databaseSerializeCalls']==0
   and qualified['resources']['backupCalls']==24
   and value['snapshotMechanism']['ok'] and len(value['snapshotMechanism']['cases'])==5
   and all(value['snapshotMechanism']['resources'][k] for k in ('allFileDescriptorsClosedOnce',
    'allSqliteHandlesClosedOnce','allExplicitCursorsClosed'))
   and 0<value['processMaximumRssBytes']<=value['memoryBudgetBytes']==536870912
''')
template = template.replace("'maximumDatabaseBytes':4294967296,", "'maximumDatabaseBytes':4294967296,\n 'largeDatabaseCapacityQualified':False,")

for name, source in (("mac_whole_sqlite_streaming_worker_r1.py", worker),
                     ("launch_mac_whole_sqlite_streaming_small_r1.template.py", template)):
    compile(source, name, "exec")
    (HERE / name).write_text(source)

old = ast.literal_eval(next(node.value for node in ast.parse(
    (OLD / "launch_mac_whole_sqlite_qualification_r2.py").read_text()).body
    if isinstance(node, ast.Assign) and any(isinstance(target, ast.Name)
        and target.id == "PAYLOAD" for target in node.targets)))
source_names = ("whole_sqlite_streaming_r1.py", "qualify_whole_sqlite_streaming_r1.py",
                "mac_whole_sqlite_streaming_worker_r1.py")
sources = {name: (HERE / name).read_text() for name in source_names}
for name, source in sources.items():
    tree = ast.parse(source)
    for node in ast.walk(tree):
        assert not (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
                    and node.func.attr in ("serialize", "deserialize")), (name, "materialization")
        if isinstance(node, ast.ImportFrom) and node.module and "whole_sqlite" in node.module:
            assert node.module + ".py" in source_names, (name, node.module)
sha = lambda raw: hashlib.sha256(raw).hexdigest()
payload = {key: old[key] for key in ("schemas", "schemaPins", "installedSchemaSourcePins",
                                    "custodyQualificationAuthority")}
payload.update(sources=sources, sourcePins={name: sha(source.encode()) for name, source in sources.items()})
assert template.count("# PAYLOAD_PLACEHOLDER") == 1
assembled = template.replace("# PAYLOAD_PLACEHOLDER", "PAYLOAD=" + repr(payload))
compile(assembled, "launch_mac_whole_sqlite_streaming_small_r1.py", "exec")
decoded = ast.literal_eval(next(node.value for node in ast.parse(assembled).body
    if isinstance(node, ast.Assign) and any(isinstance(target, ast.Name)
        and target.id == "PAYLOAD" for target in node.targets)))
assert decoded == payload
(HERE / "launch_mac_whole_sqlite_streaming_small_r1.py").write_text(assembled)
manifest = {"schema": "heptabao.whole-sqlite-streaming-small-mac-preparation.r1",
    "sourcePins": payload["sourcePins"], "schemaPins": payload["schemaPins"],
    "installedSchemaSourcePins": payload["installedSchemaSourcePins"],
    "launcherBytes": len(assembled.encode()), "launcherSha256": sha(assembled.encode()),
    "root": "/Users/qianqi/" + NEW_ROOT, "sourceVfs": "unix-posix",
    "sharedSeconds": 45, "workerSeconds": 30, "supervisorSeconds": 70,
    "wholeBundleCases": 14, "snapshotMechanismCases": 5, "databaseByteLimit": 4294967296,
    "streamBlockBytes": 1048576, "sqliteHeapLimitBytes": 268435456,
    "maximumProcessRssBytes": 536870912, "largeDatabaseCapacityQualified": False,
    "directSourcePageOracleClaimed": False, "productionSourceReads": 0,
    "productionWrites": 0, "productionRollbackQualified": False}
(HERE / "streaming-small-mac-manifest.public.json").write_text(json.dumps(manifest, sort_keys=True, indent=2) + "\n")
parts = []
for old_name, new_name in [(key + ".py", value + ".py") for key, value in list(NAMES.items())[:3]]:
    parts.extend(difflib.unified_diff((OLD / old_name).read_text().splitlines(True),
                 (HERE / new_name).read_text().splitlines(True), fromfile="original-r2/" + old_name,
                 tofile="streaming-r1/" + new_name))
parts.extend(difflib.unified_diff((OLD / "launch_mac_whole_sqlite_qualification_r2.template.py").read_text().splitlines(True),
    template.splitlines(True), fromfile="original-r2/launcher.template.py", tofile="streaming-r1/launcher.template.py"))
(HERE / "whole-r2-to-streaming-r1.diff").write_text("".join(parts))
print(json.dumps(manifest, sort_keys=True))
