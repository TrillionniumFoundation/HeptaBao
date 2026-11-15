# Native mount initialization

Normal Service initialization stores an explicit empty root engine namespace. A newly created namespace stores its own explicit empty engine entry in the same authorized publication. Secret engines are enabled through `sys/mounts/<path>`; enabling an existing path continues to fail. The public mount registry always describes the virtual `cubbyhole/`, `identity/`, and `sys/` mounts. The system and identity descriptors share the UI projection helper.

The serialized shape and supported state formats remain unchanged. `EngineState::default` and the missing-namespace fallback retain the historical implicit `secret/` KV2 and `transit/` mounts for pre-existing graphs. An existing explicit entry with an empty mount map is never replaced with those legacy defaults. Admission does not remove persisted mounts or change a protected format floor.

Pristine explicit entries can be deleted together with the authorized namespace catalog owner. Any remaining mount, mount incarnation tombstone, allocated identity frontier or identity index, or external-key configuration prevents this cleanup. Root protection and the existing auth, database, namespace workflow, and child-owner checks remain in force.

Tests that need secret engines provision their fixtures explicitly. Initial-owner, first-dispatch, and historical-codec tests use the unmounted initializer and construct the specific supported predecessor they test; they do not change the production defaults or authorize a current writer to downgrade. Historical codec construction is distinct from an actual previous executable's read/write qualification.

This increment addresses normal initialization and registered new namespaces. It does not claim complete development-mode bootstrap, every virtual descriptor field, or full OpenBao replacement. Existing live runners that assumed implicit mounts need explicit setup and their own new source/binary qualification.
