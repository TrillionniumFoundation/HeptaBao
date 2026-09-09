#!/usr/bin/env python3
from pathlib import Path

path = Path("scripts/apply_v1_4_6_operation_recovery.py")
value = path.read_text(encoding="utf-8")
old = '''replace(
    "crates/heptabao-journaled-core/src/lib.rs",
    """            if expected_current != self.current {
                return Err(MemoryStoreError::Conflict);
            }
            let committed = match self.current {
""",
    """            if expected_current != self.current {
                return Err(MemoryStoreError::Conflict);
            }
            if self.fail_commit_before_mutation {
                self.fail_commit_before_mutation = false;
                return Err(MemoryStoreError::Conflict);
            }
            let committed = match self.current {
""",
    expected=1,
)
'''
new = '''replace(
    "crates/heptabao-journaled-core/src/lib.rs",
    """        fn commit(
            &mut self,
            expected_current: Option<Generation>,
            candidate: OpaqueState,
        ) -> Result<CommitReceipt, Self::Error> {
            if expected_current != self.current {
                return Err(MemoryStoreError::Conflict);
            }
            let committed = match self.current {
""",
    """        fn commit(
            &mut self,
            expected_current: Option<Generation>,
            candidate: OpaqueState,
        ) -> Result<CommitReceipt, Self::Error> {
            if expected_current != self.current {
                return Err(MemoryStoreError::Conflict);
            }
            if self.fail_commit_before_mutation {
                self.fail_commit_before_mutation = false;
                return Err(MemoryStoreError::Conflict);
            }
            let committed = match self.current {
""",
)
'''
count = value.count(old)
if count != 1:
    raise SystemExit(f"expected one ambiguous materializer block, found {count}")
path.write_text(value.replace(old, new, 1), encoding="utf-8")
print("V1.4.6 operation materializer matcher constrained")
