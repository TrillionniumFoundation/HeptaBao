# HeptaBao Observability Catalog V1

This catalog defines bounded event names. Audit records remain a separate mandatory security record.

| Event | Required labels | Meaning |
|---|---|---|
| `request_completed` | `operation`, `outcome` | request completed or returned an unknown-after-entry outcome |
| `namespace_created` | `outcome`, `generation_bucket` | namespace administrative transition |
| `mount_state_changed` | `backend`, `state` | mount enable/disable transition |
| `plugin_state_changed` | `kind`, `state` | plugin lifecycle transition |
| `backup_state_changed` | `state`, `outcome` | backup lifecycle transition |
| `operation_readback` | `operation`, `outcome` | reconciliation readback classification |

Allowed label keys are implemented by `heptabao-telemetry`. Label values must be bounded identifiers. Tokens, secrets, keys, unseal material, credentials, request bodies, full secret paths, raw error strings and user-provided arbitrary text are forbidden.

Cardinality budgets, exporter configuration, sampling and SLO thresholds remain deployment-specific and require environment qualification.
