# Explicit refusal for new native snapshot admission

This source-only successor closes 24 old exhaustive matches after the frozen 8c95 candidate introduced NativeSnapshotAdmission::Forward. Every change is one feature-gated error arm. The original match arms, assertions, test declarations, budgets, and HTTP forwarding implementation remain byte-identical.

The finite read covered all 906 Rust files under the server source directory at canonical tree f412f1524e08a56e23374897d329bfcf6295f4fe: 20,918,237 bytes, 33 matching files, and 151 lexical references. All matching files are included whole; the remaining files have their canonical whole identities in the 906-entry inventory. This is a specific enum-use review, not a Rust compilation result.

The initial subset had eight missing arms. The complete finite scan identified sixteen more in controlgroups, native File/GC, import/mount/witness, PKI/SSH archives, migration, and quota fixtures. Existing wildcard/let-else cases already refuse Forward and are unchanged. The single non-test filename change is inside the existing cfg(all(test,target_os="linux")) fixture impl.

No Rust compiler, formatter, test, host command, product request, or candidate checkout was run or modified for this patch. The 23 snapshot components, C's 149 unique / 166 profile selections, the prior CLI failures, and all original unknown observations retain their prior status. The four actual Service restore/audit regressions are a separate pending source task.
