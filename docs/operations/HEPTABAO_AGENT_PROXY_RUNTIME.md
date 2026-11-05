# Actual local Agent and Proxy owners

`clients/python/heptabao/agent.py` and `proxy.py` are the executable owners,
registered as `heptabao-agent` and `heptabao-proxy` by the client wheel. The Rust
crates with those names remain contract models. The Python distribution requires
Python 3.11 or later. No production configuration is changed by these features.

Both owners can serve an optional TLS listener bound to a literal loopback IP.
The listener requires a client certificate from the explicitly configured CA;
its private key remains in an owner-only file. The existing Proxy Unix listener
continues to require a same-UID kernel peer and an owner-only socket directory.
Upstream HTTPS origin, CA, namespace and current token come from the admitted
AppRole Agent configuration; requests cannot supply credentials or a namespace.
All product routes remain explicit finite allowlists, including explicit
`allow_effects` admission for effectful GET endpoints such as database issuance.

The optional Agent `listener` object contains `address`, `tls_cert_file`,
`tls_key_file`, `tls_client_ca_file`, `routes`, `allow_effects`, and bounded
`timeout`, `max_requests`, `max_runtime_seconds` settings. Proxy accepts the same
optional `listener`; its product routes and resource bounds come from the Proxy
configuration. The Agent's existing durable sink binding excludes the new
listener object, preserving legacy auto-auth binding bytes. Listener use with
Agent `--once` is rejected. TLS replaces the Unix listener in that Proxy process;
it does not start a second listener implicitly.

`require_request_header=true` checks `X-Vault-Request` before routing and control
effects. Header names are case-insensitive. Exactly one value, equal to `true`,
is required; missing, duplicate, incorrectly cased or wrong values return 412.
TLS listeners default this setting to true; existing Unix configurations retain
their prior false default. Valid optional whitespace around the value is allowed.
Incoming authority headers with an admitted request header remain rejected.

`enable_quit` defaults to false. Disabled `/agent/v1/quit` or `/proxy/v1/quit`
returns 404. Enabled POST sends an empty 200 response, sets that actual owner's
stop event, joins its listener and exits. Other methods return 405. Agent shutdown
invalidates its token sink in an independent finally block, including listener
cleanup failures. This local invalidation is not remote token revocation.

Actual owner HTTPS operations retain the existing Client wire codec inside a
finite, cancellable request owner. An absolute deadline closes owned sockets;
a connect completing after cancellation cannot send an application request.
Uncompleted OS connect/DNS work runs in a daemon worker, with at most two such
workers per process. A fixed 0.25 second write-only cleanup budget may send a
static 503 response after expiry. It never admits auth, wrapping, caching,
another upstream operation or a retry. It does not reset the request deadline.
Deadline transport failures remain outcome-unknown, including GET, which can
issue credentials or consume a finite token. Bounded socket cancellation is not
an atomic proof that the clock and an already entered send cannot race.

`cache_enabled` defaults to false. `/agent/v1/cache-clear` and
`/proxy/v1/cache-clear` return an empty 200 no-op without a cache, including
non-JSON input. With a cache, POST/PUT support `all`, `request_path` (namespace
and path prefix), `lease`, `token`, and `token_accessor`. Other methods are 200
no-ops. Invalid JSON/type is 400; a known selective type with no value is 500,
matching the pinned OpenBao 2.7.1 handler's behavior. Request framing, maximum
body size, canonical JSON and finite header policies remain bounded.

The optional cache stores only successful, unwrapped, renewable leased responses
obtained with the currently admitted auto-auth token. Keys include token digest,
namespace, method, path, payload digest and consistency metadata. Every hit reads
the current sink and validates the token against the live upstream. A revoked
token or unavailable upstream cannot authorize cached data. Expiry uses the
request start time, both wall and monotonic clocks, and the earlier lease/token
deadline. Hits reduce advertised TTL; token renewal cannot extend an old cache
record. Memory has entry and byte limits, and no cache is persisted to disk.
Before the extra lookup, caching requires the actual Agent's independently
admitted `token_num_uses=0` checkpoint marker. Finite or legacy snapshots lacking
that marker skip caching and perform a single upstream request. A cache never
looks up a finite token merely to discover that the lookup consumed a use.

This is an online, bounded lease-response cache. It does not implement OpenBao's
managed lease renewal, offline cache, cache persistence/import, static-secret
watchers, complete listener configuration, templating or complete Agent feature
parity. Those boundaries remain open and must not be counted as full replacement.

`qa/openbao-acceptance/agent_proxy_runtime_live.py` starts the actual Python
executables against pinned OpenBao 2.7.1 or a separately identified candidate
Rust server. It creates its own PostgreSQL 17 TLS/SCRAM cluster and verifies real
dynamic credentials, cache hits without another database identity, clear-induced
new identities, selective invalidation, lease expiry, remote token revocation,
normal forwards, header failures, both default-disabled quit owners, incomplete
request termination, Unix socket controls, process exits and socket removal.
Receipts identify the Python owner commit separately from the upstream server
binary hash and remove all private fixtures. No token, SecretID, key or database
credential is written to an evidence receipt.

The runner can explicitly use `--skip-postgres` for platform-only process,
header, normal-forward, Unix control and slow-upstream shutdown evidence. That
mode does not qualify database or lease-cache functionality. With an official
backend it also starts the pinned official Agent and Proxy processes to verify
the independent no-cache header/quit control contract.
