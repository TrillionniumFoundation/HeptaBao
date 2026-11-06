# Two fixed public JSON inputs for the owner repair

This is a source proposal, with zero Runtime calls. The complete historical receipt `79471a511eb665193c2dbc05607298e96ac6fa7d` was reverified at 51,466 bytes / SHA256 `6caa9ebfc2a3bf3ae637676a8055022817ec0efa85b09c6ffc304ac854ca6236`. Its `sourcePins` explicitly contains both paths and hashes in the contract. No path is guessed from a plugin name, and no old execution qualification is transferred.

The proposed order is two exact metadata operations, then two conditional exact-version body operations. Metadata hashes the full target; the 65,536-byte limit is an admission limit for each subsequent body, not a claimed bound on file_info hash work. Any metadata error, mismatch, symlink refusal, non-single-link observation, excess size, version drift, or unclosed original operation stops the sequence. The pure derivation helper has no I/O and grants no execution permission. Each actual derived request and its external intent must be saved before admission.

The previous public-source body accounting remains 8 files / 11 chunks / 353,689 bytes. This independent proposal adds at most 2 files / 2 chunks / 131,072 bytes, for a maximum cumulative 484,761 bytes. It does not reuse unused limits from earlier windows or alter any current fixture budget.

These bodies will establish the manifest id and declared module entry needed by the concrete Inputs/materializer/worker repair. They do not prove a current selected owner or current entry-file content. Any necessary declared entry read must be precisely sourced from the whole public declaration and separately bounded; no SDK imports, private capsule read, factory, refresh, provider call or business replay is included.
