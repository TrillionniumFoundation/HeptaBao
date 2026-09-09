#!/usr/bin/env python3
from pathlib import Path

path = Path("crates/heptabao-operation-ledger/src/lib.rs")
value = path.read_text(encoding="utf-8")
old = """                                    intent.next(
                                        OperationPhase::Reconciled,
                                        None,
                                        None,
                                        None,
                                        reconcile_detail,
                                    ),
"""
new = """                                    intent.next(
                                        OperationPhase::Reconciled,
                                        intent.state(),
                                        None,
                                        None,
                                        reconcile_detail,
                                    ),
"""
count = value.count(old)
if count != 1:
    raise SystemExit(f"expected one durable generic-reconcile hostile assertion, found {count}")
path.write_text(value.replace(old, new, 1), encoding="utf-8")
print("V1.4.6 operation hostile-test fix applied")
