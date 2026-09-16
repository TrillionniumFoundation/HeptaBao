#!/usr/bin/env python3
from pathlib import Path

path = Path("scripts/materialize_mount_registry_local_closure_20260916.py")
text = path.read_text(encoding="utf-8")

old = '''    let requested = canonical_secret_mount(requested)?;\n    if requested == "cubbyhole" && method == "GET" {\n        return Ok(ok(cubbyhole_descriptor(), false));\n    }\n'''
new = '''    if requested == "cubbyhole" {\n        if method == "GET" {\n            return Ok(ok(cubbyhole_descriptor(), false));\n        }\n        return Err(bad("reserved mount path"));\n    }\n    let requested = canonical_secret_mount(requested)?;\n'''
if text.count(old) != 1:
    raise SystemExit(f"cubbyhole patch anchor count={text.count(old)}")
text = text.replace(old, new, 1)

old = '''    assert_eq!(\n        request(\n            &mut restored,\n            "",\n            "GET",\n            "archive/data/app",\n            json!({}),\n            108,\n        )?\n        .status,\n        404\n    );\n'''
new = '''    assert!(matches!(\n        restored.handle("", "GET", "archive/data/app", &json!({}), 108)?,\n        Some(response) if response.status == 404\n    ));\n'''
if text.count(old) != 1:
    raise SystemExit(f"missing-value test patch anchor count={text.count(old)}")
text = text.replace(old, new, 1)

path.write_text(text, encoding="utf-8")
