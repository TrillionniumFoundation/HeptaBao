# Current Mac source inventory R1 — retained failure

Original job `1a1b31ea42f-fc05-80ab` completed with exit 1. Its complete stdout is 2,535 bytes. The failure is `inventory_exact_qualified_pure_definition_ast`, before any original command, inventory child, SQL connection, current configuration or plist observation. All 55 parent file descriptors closed once. This attempt is not a production inventory success.

The follow-up diagnostic `1a1b321058b-fc05-80b1` only read two already staged public sources and the Python executable. It completed with exit 0 and 1,283 bytes of stdout. Actual Python 3.14.3's default AST representation differs from the reviewed representation. Explicit `ast.dump(..., show_empty=True, include_attributes=False)` reproduces both original reviewed AST pins, with unchanged whole-source pins. Three original file descriptors closed. It performed no child execution, SQL, current private source read, service action or provider call.

R2 is a distinct root and operation key with the explicit AST option. Neither the original R1 result nor its source is modified. A later successful attempt does not turn this original failure into a success.

Only public sources, public observations and original runtime receipts are archived here. Configuration, credential values and their digests, private metadata mappings, database bytes and restore packets remain on the Mac.
