#!/usr/bin/env python3
"""Assemble only public code/schemas and original public qualification authority."""
import ast
import hashlib
import json
from pathlib import Path
import re

HERE = Path(__file__).resolve().parent
AUDIT = HERE.parent / "authbus-refresh-work"
sha = lambda value: hashlib.sha256(value).hexdigest()
tree = ast.parse((AUDIT / "launch_wal_keeper_lifecycle_r1.py").read_bytes())
prior = ast.literal_eval(next(node.value for node in tree.body if isinstance(node, ast.Assign)
    and any(isinstance(target, ast.Name) and target.id == "PAYLOAD" for target in node.targets)))
names = ("whole_sqlite_bundle_r2.py", "qualify_whole_sqlite_bundle_r2.py", "mac_whole_sqlite_worker_r2.py")
sources = {name: (HERE / name).read_text() for name in names}
local_modules = {Path(name).stem for name in names}
for name, source in sources.items():
    parsed = ast.parse(source, filename=name)
    for node in ast.walk(parsed):
        if isinstance(node, ast.ImportFrom) and node.module and "whole_sqlite" in node.module:
            assert node.module in local_modules, (name, node.module)
        if isinstance(node, ast.Import):
            for alias in node.names:
                if "whole_sqlite" in alias.name:
                    assert alias.name in local_modules, (name, alias.name)
schemas, installed_pins = {}, {}
for kind, filename, constant in (
    ("agent", "openclaw-agent-db-DKpxi-Ll.js", "OPENCLAW_AGENT_SCHEMA_SQL"),
    ("state", "openclaw-state-db-DzSsA9Ji.js", "OPENCLAW_STATE_SCHEMA_SQL")):
    source = (AUDIT / "reference" / filename).read_bytes()
    parts = re.findall(r"const " + constant + r" = `([\s\S]*?)`;", source.decode())
    assert len(parts) == 1 and "${" not in parts[0] and "\\" not in parts[0].replace("\\n", "")
    schemas[kind] = parts[0].replace("\\n", "\n")
    installed_pins["dist/" + filename] = sha(source)
payload = {"sources": sources, "sourcePins": {name: sha(text.encode()) for name, text in sources.items()},
           "schemas": schemas, "schemaPins": {name: sha(text.encode()) for name, text in schemas.items()},
           "installedSchemaSourcePins": installed_pins,
           "custodyQualificationAuthority": prior["custodyQualificationAuthority"]}
template = (HERE / "launch_mac_whole_sqlite_qualification_r2.template.py").read_text()
assert template.count("# PAYLOAD_PLACEHOLDER") == 1
assembled = template.replace("# PAYLOAD_PLACEHOLDER", "PAYLOAD=" + repr(payload))
compile(assembled, "launch_mac_whole_sqlite_qualification_r2.py", "exec")
loaded_payload = ast.literal_eval(next(node.value for node in ast.parse(assembled).body
    if isinstance(node, ast.Assign) and any(isinstance(target, ast.Name)
        and target.id == "PAYLOAD" for target in node.targets)))
assert loaded_payload == payload
(HERE / "launch_mac_whole_sqlite_qualification_r2.py").write_text(assembled)
manifest = {"schema": "heptabao.whole-sqlite-mac-preparation.r2", "sourcePins": payload["sourcePins"],
            "schemaPins": payload["schemaPins"], "installedSchemaSourcePins": installed_pins,
            "launcherBytes": len(assembled.encode()), "launcherSha256": sha(assembled.encode()),
            "root": "/Users/qianqi/heptabao-authbus-whole-database-qualification-20261106-r2",
            "sourceVfs": "unix-posix", "sharedSeconds": 45, "workerSeconds": 30, "supervisorSeconds": 70,
            "maximumDatabaseBytes": 67108864, "productionDatabaseSizesQualified": False,
            "productionReadAuthorized": False, "productionWriteAuthorized": False}
(HERE / "whole-mac-manifest.public.json").write_text(json.dumps(manifest, sort_keys=True, indent=2) + "\n")
print(json.dumps(manifest, sort_keys=True))
