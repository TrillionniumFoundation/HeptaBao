# Native macOS and Linux HA fixture

The manual synthetic `ha_multihost_live.py` lifecycle can use a separately built
native artifact for an individual voter. Every artifact is bound to its expected
SHA-256 and the same frozen source commit and tree. The original single-binary
Linux invocation remains supported, and the baseline denominator remains 54.
The composed 24 MiB KV1 denominator remains 69. These profiles exercise the V5
application writer and cannot qualify the closed V6 production writer.

Provide an override with:

```
--node-binary node-alias,source-alias:/canonical/native/binary,SHA256,COMMIT,TREE
```

The node alias must name exactly one configured node. Duplicate node overrides,
unknown nodes, noncanonical source paths, malformed hashes, and different source
freezes are rejected before any remote process starts. Source build receipts
must independently establish that each supplied hash was built from the stated
freeze; passing command-line metadata alone is not a build attestation.

A Mac node root and its native binary source use the existing `/Volumes/T5/`
storage admission. Select its actual RFC1918 LAN address and an unused permitted
API/Raft port pair. HTTPS requests and Raft peer addresses use those actual LAN
addresses. SSH transfers fixture assets and manages its private processes; SSH
forwarding does not stand in for LAN connectivity.

The target launches a real detached process with Python `start_new_session`.
The fixture PID and initial process identity are stored in owner-only files.
Before SIGKILL, Linux checks executable, exact fixture arguments, start ticks and
session ownership. macOS checks BSD `ps` executable, exact arguments, start time
and session ownership. A stale identity or a PID belonging to another fixture is
rejected. macOS cannot provide an atomic PID-reuse exclusion through BSD `ps`;
the report states that limitation. Only the recorded fixture PID is signaled.
No firewall, operating-system service, permission, or production data changes
are part of this profile.

After each check or event the controller saves an independently redacted,
fsynced phase JSON under `WORK_ROOT/phases/`. Intermediate snapshots retain
`status: failed` until final qualification completes. They cannot convert a
partial run into a passed profile. The final summary compares each node against
its own expected binary hash and reports actual host platforms. Different native
ABIs are never required to have the same binary hash.

The native process identity test uses a real C process on the executing platform
and proves that stale start identity and another fixture PID are denied before
kill, followed by legitimate termination and idempotent no-process cleanup.
Existing fixed denominator, read frontier, strict certificate and KV1 profile
checks remain required. Actual mixed Mac/Linux lifecycle evidence is necessary
in addition to these controller tests.
