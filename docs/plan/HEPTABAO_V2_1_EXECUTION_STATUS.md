# HeptaBao V2.1 execution status

This file is intentionally non-authoritative. Canonical capability and blocker truth remains in the machine-readable planning files.

The V2.1 branch targets `main`, carries the reviewed V2 source tree, adds the restart-safe `heptabao-durable-service` candidate, and keeps all legal, production, compatibility, migration, and release authority fail-closed pending authentic evidence.

For the current runnable assembly, see `docs/architecture/HEPTABAO_CURRENT_RUNTIME_ARCHITECTURE.md` and `docs/modules/CURRENT_RUNTIME_MAP.md`: the workspace has 46 packages and five runtime dependencies including the server itself. The server now composes persisted private auth/ACL, engines, authenticated audit rotation, maintenance and optional per-process HA. The earlier paragraph records the original durable-service increment, not the entire present implementation. Named historical test receipts remain in `docs/plan/HEPTABAO_SINGLE_NODE_EXECUTION_STATUS.md`; current source/guide digests and fresh validation are separate.
