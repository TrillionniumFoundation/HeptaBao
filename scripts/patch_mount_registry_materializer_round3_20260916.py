#!/usr/bin/env python3
from pathlib import Path

path = Path("scripts/materialize_mount_registry_local_closure_20260916.py")
text = path.read_text(encoding="utf-8")
old = '''    assert!(matches!(\n        restored.handle("", "GET", "archive/data/app", &json!({}), 108)?,\n        Some(response) if response.status == 404\n    ));\n'''
new = '''    assert_eq!(\n        restored\n            .handle("", "GET", "archive/data/app", &json!({}), 108)\n            .err()\n            .map(|error| error.status),\n        Some(404)\n    );\n'''
if text.count(old) != 1:
    raise SystemExit(f"round3 expected-404 anchor count={text.count(old)}")
path.write_text(text.replace(old, new, 1), encoding="utf-8")
