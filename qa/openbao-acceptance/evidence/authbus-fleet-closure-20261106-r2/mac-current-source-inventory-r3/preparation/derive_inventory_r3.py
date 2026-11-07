#!/usr/bin/env python3
"""Create the next immutable inventory preparation from the failed R2 source."""
import ast
import difflib
import hashlib
from pathlib import Path

HERE = Path(__file__).resolve().parent
PRIOR = HERE.parent / "mac-current-inventory-r2-work"


def replace_once(source, before, after):
    assert source.count(before) == 1, before
    return source.replace(before, after)


helper = '''def close_guard_resources(items, attempts):
    """Attempt every original guard close before any public projection.

    A failed close call consumes this caller's slot. Original per-handle
    ledgers remain authoritative; no uncertain close is repeated here.
    """
    for current in items:
        token = id(current)
        if token in attempts:
            continue
        row = {"closeCallAttempts": 1, "closeCallReturned": False}
        attempts[token] = row
        try:
            current.close()
            row["closeCallReturned"] = True
        except BaseException:
            row["closeErrorCode"] = "inventory_guard_close_unconfirmed"
    resources = []
    boolean_keys = (
        "allOwnedDescriptorsClosed", "allHeldDescriptorsClosed", "allReturnedConnectionsClosed",
        "allExplicitCursorsClosed", "allPublicCodeDescriptorsClosed")
    vector_fields = (("connectionAttemptCount", "connect_attempts"),
                     ("returnedConnectionCount", "connections"),
                     ("cursorCount", "cursors"), ("queryCount", "queries"))
    safe_errors = {"OSError", "ValueError", "RuntimeError", "PermissionError", "FileNotFoundError",
                   "TimeoutError", "OperationalError", "DatabaseError", "ProgrammingError",
                   "KeyboardInterrupt", "SystemExit"}
    for ordinal, current in enumerate(items, 1):
        row = {"ordinal": ordinal, **attempts[id(current)], "projectionComplete": False,
               "allOwnedDescriptorsClosed": False}
        try:
            value = current.public()
            need(type(value) is dict, "inventory_resource_public_dictionary")
            selected = {key: value[key] for key in boolean_keys}
            need(all(type(item) is bool for item in selected.values()),
                 "inventory_resource_closure_booleans")
            errors = value["closeErrors"]
            need(type(errors) is list and all(type(item) is str for item in errors),
                 "inventory_resource_close_errors_vector")
            selected["closeErrors"] = [item if item in safe_errors else "OtherError" for item in errors]
            for public_name, attribute in vector_fields:
                vector = getattr(current, attribute)
                need(type(vector) is list and all(type(item) is dict for item in vector),
                     "inventory_original_resource_vector_type")
                selected[public_name] = len(vector)
            row.update(selected, projectionComplete=True)
        except BaseException:
            row["projectionErrorCode"] = "inventory_guard_resource_projection_refused"
        resources.append(row)
    return resources


def public_database_kind_and_mode(result, primary, registry):
    # The fixed query already reads this PRAGMA. No extra SQL or auth data.
    mode = result["pragmas"]["journal_mode"]
    need(type(mode) is str and mode in ("delete", "truncate", "persist", "memory", "wal", "off"),
         "inventory_closed_journal_mode_enum")
    return {"journalMode": mode, "databaseKind": "shared-state" if registry else "agent",
            "configuredPrimaryAgentSlot": primary,
            "credentialOwnerRevalidatedByThisInventory": False}


'''

source = (PRIOR / "capture_current_database_inventory_r2.py").read_text()
source = source.replace("production-source-inventory-20261106-r2", "production-source-inventory-20261106-r3")
source = replace_once(source, 'source-inventory.public.r2', 'source-inventory.public.r3')
source = replace_once(source, 'codes, guards, held = set(), [], []',
                      'codes, guards, held = set(), [], []\nguard_close_attempts = {}')
source = replace_once(source, 'def remaining():\n', helper + 'def remaining():\n')
source = replace_once(source, '                                               **public_database_sizes(bundle),\n                                               **inventory.public_inventory_counts(result)})',
    '                                               **public_database_sizes(bundle),\n                                               **inventory.public_inventory_counts(result),\n                                               **public_database_kind_and_mode(result, ordinal == 0, False)})')
source = replace_once(source, 'report["databaseObservations"].append({"ordinal": 6, **public_database_sizes(bundle),\n                                           **inventory.public_inventory_counts(result)})',
    'report["databaseObservations"].append({"ordinal": 6, **public_database_sizes(bundle),\n                                           **inventory.public_inventory_counts(result),\n                                           **public_database_kind_and_mode(result, False, True)})')
source = replace_once(source, '''    for current in guards:
        current.verify()
        current.close()
        need(current.public()["allOwnedDescriptorsClosed"], "inventory_original_resources_closed")
''', '''    for current in guards:
        current.verify()
    closed_resources = close_guard_resources(guards, guard_close_attempts)
    need(all(item["closeCallReturned"] and item["projectionComplete"]
             and item["allOwnedDescriptorsClosed"] for item in closed_resources),
         "inventory_original_resources_closed")
''')
source = replace_once(source, '''    resources = []
    for current in guards:
        current.close()
        value = current.public()
        resources.append({key: value[key] for key in (
            "allOwnedDescriptorsClosed", "allHeldDescriptorsClosed", "allReturnedConnectionsClosed",
            "allExplicitCursorsClosed", "allPublicCodeDescriptorsClosed", "closeErrors",
            "connectionAttemptCount", "returnedConnectionCount", "cursorCount", "queryCount")})
''', '''    resources = close_guard_resources(guards, guard_close_attempts)
''')
source = replace_once(source, '''report["allOwnedResourcesClosed"] = (all(item["allOwnedDescriptorsClosed"] for item in resources)
''', '''report["allOwnedResourcesClosed"] = (all(item["closeCallReturned"] and item["projectionComplete"]
        and item["allOwnedDescriptorsClosed"] for item in resources)
''')

files = {"capture_current_database_inventory_r3.py": source,
         "mac_current_database_inventory_r1.py": (PRIOR / "mac_current_database_inventory_r1.py").read_text()}
for old in ("launch_current_database_inventory_r2.template.py", "assemble_current_database_inventory_r2.py"):
    value = (PRIOR / old).read_text()
    value = value.replace("production-source-inventory-20261106-r2", "production-source-inventory-20261106-r3")
    value = value.replace("current_database_inventory_r2", "current_database_inventory_r3")
    value = value.replace("launch.public.r2", "launch.public.r3").replace("preparation.public.r2", "preparation.public.r3")
    files[old.replace("_r2", "_r3")] = value
patches = []
for name, value in files.items():
    ast.parse(value)
    path = HERE / name
    assert not path.exists(), name
    path.write_text(value)
    prior_name = name.replace("_r3", "_r2") if name != "mac_current_database_inventory_r1.py" else name
    patches.append("".join(difflib.unified_diff((PRIOR / prior_name).read_text().splitlines(True),
                                              value.splitlines(True), fromfile="r2/" + prior_name,
                                              tofile="r3/" + name)))
(HERE / "inventory-r2-to-r3-minimal.diff").write_text("".join(patches))
print({"sourceFiles": len(files), "captureSha256": hashlib.sha256(source.encode()).hexdigest()})
