# Native OpenBao 2.7.1 quota profile (bounded, not admitted as full replacement)

This implementation closes the native root-namespace AppRole rate-limit slice. It does not close the complete resource-quota admission gate. The original global path="" counterexample remains outside this profile and is rejected with HTTP 400.

Supported: policy-authorized root-namespace `sys/quotas/config` GET/POST; named `sys/quotas/rate-limit` GET/POST/PUT/DELETE and collection LIST; actual native AppRole default or custom mount paths, a whole-mount rule with empty role (including administrative requests), an exact login suffix without a role, or a mount-level role rule. Role rules resolve the actual role_id against the live mounted native backend before SecretID verification. A valid role_id with an invalid SecretID still spends quota. JSON and form login share the same pre-business quota gate. Client keys come from the observed transport peer, never X-Forwarded-For or logical headers.

Definitions and configuration live in the encrypted Auth owner and require sticky state schema 134. Clearing the final rule retains the reader floor. Node-local counters are excluded from serialization and restart/owner reconstruction reset them. Updates receive a new durable revision even when supplied values are unchanged. Native storage/publisher integration must independently rerun its Auth-owner closure tests after merging.

Rate accepts finite numbers greater than zero up to 1,000,000; the effective burst rounds the rate and has a minimum of one, following the pinned upstream limiter dependency. Interval is an integer duration from 1 second to 30 days (zero defaults to one second); block_interval is zero to 30 days. The bucket fully refills at anchored interval ticks. Idle limiter sweeping is separate from the independent block owner, so sweeping cannot shorten a configured block. A 429 never enters native login or consumes a SecretID; it returns Retry-After.

Unsupported operations fail closed: global/namespace/non-AppRole quotas, inherited quotas, arbitrary suffix or glob rules, quota role changes, quota-bearing mount remount, quota audit-device and response-header options enabled, and ingress-node quota admission on HA. Matching requests on HA return 503; this is not claimed as per-node HA compatibility. Root-namespace administration uses normal ACL capabilities; no extra sudo authority is invented. Configuration accepts bounded canonical exempt paths and false audit/header flags.

Evidence must bind an immutable clean source HEAD/tree/content and binary to the exact official 2.7.1 oracle. The common 81-case real-TLS profile covers AppRole role rules, expiry/refill/block, spoof-header rejection, held single-use SID survival, same-value update reset, and restart definition persistence. Passing that profile does not imply support for the unsupported scopes above.

Primary references:

- https://openbao.org/docs/api/system/rate-limit-quotas/
- https://openbao.org/docs/api/system/quotas-config/
- https://openbao.org/docs/concepts/resource-quotas/
- https://github.com/openbao/openbao/blob/v2.7.1/internal/vault/logical_system_quotas.go
- https://github.com/openbao/openbao/blob/v2.7.1/internal/vault/quotas/quotas_rate_limit.go
- https://github.com/openbao/openbao/blob/v2.7.1/internal/vault/quotas/quotas.go
- https://github.com/openbao/openbao/blob/v2.7.1/internal/builtin/credential/approle/path_login.go
- https://github.com/sethvargo/go-limiter/blob/v1.2.0/memorystore/store.go
