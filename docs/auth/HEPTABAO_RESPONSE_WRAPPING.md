# Response wrapping: current runtime contract

Owner: the existing `heptabao-server` Service transaction and AuthState writer.
Source: `crates/heptabao-server/src/auth_wrapping.rs`, `service.rs`, `http.rs`,
`ha_forward.rs`. This is an implementation guide, not a compatibility or release
receipt. The canonical OpenBao denominator and external admission remain unchanged.

## API and supported profile

The TLS API accepts `X-Vault-Wrap-TTL` for successful transactional auth/engine
responses. Supported durations are nonnegative integer seconds or integer `h`,
`m`, `s` components. Zero disables wrapping; positive TTL must not exceed 32 days.
A successful wrapped response exposes `wrap_info` with an opaque token, accessor,
original creation path, creation time and TTL. It does not expose the captured
`data` or `auth` envelope. Auth responses can also identify the wrapped accessor.
`X-Vault-Wrap-Format: uuid` selects the supported opaque-token profile; the token
is not a promise of UUID byte syntax. JWT-format wrapping fails explicitly.

`POST sys/wrapping/wrap` requires positive wrapping TTL and wraps an arbitrary
bounded JSON object. `POST sys/wrapping/unwrap` accepts either the wrapping token
as the sole request bearer or a body `token` with a distinct authorized ordinary
bearer. `GET/POST sys/wrapping/lookup` proves possession and returns creation
metadata without consuming the token. `POST sys/wrapping/rewrap` needs an ordinary
caller explicitly authorized for that path and a body token; it preserves payload,
origin and original TTL while destroying the old wrapping capability.

The built-in default policy allows wrap, unwrap and lookup, not rewrap. A wrapper
itself has no general token or secret privileges and cannot authorize rewrap.
Reusing an invalid/consumed self-unwrapping token returns 400. Supplying the same
wrapper in header and body is rejected as ambiguous input; this bounded 400 is
not a claim to reproduce every upstream internal-error response.

The public Rust `ServiceRequest` carries borrowed method/path/namespace/bearer,
owned JSON body, and `wrap_ttl_seconds: Option<u64>`. `handle_request` uses the
host clock; `handle_request_at` is for trusted embedding/tests. Existing `handle`
and `handle_at` remain non-wrapping entry points. Untrusted callers must not set
server time. The adapter cannot manufacture an authenticated Principal.

## State, confidentiality and concurrency

The existing encrypted service snapshot stores a wrapper record inside its
hashed bearer-token entry. Records own the response, original creation path and
TTL, and optional wrapped accessor. The raw wrapping token is never the store
key. At most 256 live records and 64 KiB of encoded response per record are
allowed; the service-wide 768 KiB state ceiling can reject sooner. All bounds
reject, rather than evicting live credentials. Owned response values are erased
on Drop, including unsuccessful candidates; this does not certify whole-process
memory erasure or external swap protection.

The Service mutex and current HA ReadIndex snapshot serialize mutation. For
self unwrap, authentication first commits the last-use decrement and destruction
of the stored response; the non-cloneable request Principal alone retains the
final-use view. Body-token unwrap changes the isolated domain candidate and
commits consumption before releasing its result. New capture or rewrap publishes
its token only after the same authoritative transaction commits.

An observed clock frontier and expiry invalidation persist before rejected
wrapping operations. Previously observed expiration cannot be undone by restart
or a later clock rollback. This is not an external trusted-time provider or a
hardware anti-rollback anchor. Expired records are reclaimed on relevant requests,
not by a newly claimed background scheduler.

## Failure and recovery

Before-entry audit failure prevents dispatch. State capacity or wrapper capture
failure does not publish the underlying domain candidate and never falls back to
returning raw content; a finite bearer use already durably admitted remains used.
Unknown persistence or result-audit failure withholds all captured/unwrap content
and fences the service. An interrupted self unwrap may consume a token without
successfully delivering its response: the contract is at-most-once secret release,
not guaranteed delivery or a retryable mailbox.

Use metadata lookup and the existing operator recovery boundary to investigate
uncertainty. Do not automatically retry unwrap or rewrap after a lost response.
A second unwrap must not be used as an availability probe.

## HA and versioning

Normal forwarding remains `HBFQ1`. Requests with wrapping options use `HBFQ2`,
binding TTL inside the authenticated, length-bounded peer frame. Older peers fail
closed on that frame rather than silently dropping the option and returning raw
content. Outbound request frames use zeroizing buffers. Same-version process
failover is tested separately from rolling protocol-version upgrades.

Service state schema 3 protects this runtime increment. Schema 1/2 can be read
only under their original field constraints; ordinary reads do not rewrite old
state. An actual mutation upgrades through the existing durable commit. Schema-2
binaries reject schema 3. Downgrading the schema number, deleting fields or
restoring an older authorization snapshot is not a rollback procedure.

## Verification and remaining boundaries

`cargo test --locked -p heptabao-server wrapping_` covers replay/restart, concurrency,
namespace isolation, mutation rollback, audit failure, schema fencing and bounds.
`response_wrapping.py` is an actual selected official-binary comparison, not full
surface coverage. `wrapping_ha.py` covers forwarding, leader loss, quorum fencing
and restart; `wrapping_upgrade.py` exercises two real binaries and old-reader
rejection. Both use isolated synthetic state and publish no live credential.

HEAD/DELETE and nontransactional health/leader, initialization, seal/unseal, rekey, snapshot and
operator recovery requests with a positive wrapping option fail explicitly before
the effect. JWT wrapping, arbitrary duration precision, all parameter-constrained
ACL/minimum-maximum wrapping policies, full upstream error equivalence, multi-host
destructive runs and mixed-version upgrades remain unqualified. A passing local
profile does not change independent, production, migration or release authority.
