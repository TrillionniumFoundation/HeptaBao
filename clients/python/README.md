# HeptaBao Python HTTPS client and explicit CLI

This installable, standard-library-only package provides real network requests;
it is not the standalone Rust client/CLI contract models and is not a complete
OpenBao CLI, Agent or Proxy. Python >=3.11 is required. Qualified local execution
uses Python 3.13 on Linux; the private-file CLI requires POSIX descriptor flags.

## Install and invoke

From a trusted checkout, install `clients/python` into a dedicated environment,
or install the exact reviewed `heptabao_client` wheel with `pip --no-deps`.
The entry point is `heptabao` (equivalently `python -m heptabao`). No external
runtime dependency, Oracle executable or QA code is packaged.

Example for isolated development, with existing owner-only credential files:

```sh
umask 077
mkdir -m 700 /tmp/heptabao-client-responses
heptabao --address https://localhost:8200 --ca-file /private/ca.crt \
  --token-file /private/scoped.token \
  --output /tmp/heptabao-client-responses/read.json \
  read secret/data/example
```

The paths and address above are placeholders, not production defaults. The
response can contain a secret, so it goes to the specified new private file, not
stdout. The response directory must already be caller-owned with mode 0700 and
the destination must not exist. Credentials are supplied by an owner-only file,
never a raw `--token` argument. No implicit environment bearer fallback is used
by the legacy CLI mode. Reads using finite-use credentials can still consume their use count.

## Commands and semantics

`read`, `list`, `write`, `delete`, `capabilities`, `wrap`, `unwrap`, `rewrap` and
`wrapping-lookup` issue explicit HTTPS requests. Mutating commands, and reads that
request wrapping, require `--allow-write`. JSON input is a private file supplied
with `--input`, or piped stdin with `--input -`; interactive secret entry and
arbitrary key=value argv parsing are absent from these legacy commands. `read`/`write` accept
`--wrap-ttl`; `wrap` requires `--ttl`. Global options precede the subcommand.

Self `unwrap` and `wrapping-lookup` take a wrapping-token file and reject a second
bearer. `rewrap` instead requires an ordinary explicitly authorized caller plus a
wrapping-token file. `capabilities` supports self inspection or an explicit target
bearer/accessor file; the selector does not itself authorize inspection. Existing
credential/lease APIs can be called with `write` using reviewed private JSON.

## OpenBao-style KV entry point

`heptabao kv <command> [flags] <path> [data]` (or `python -m heptabao kv`)
adds actual KV v1/v2 operations through the same HTTPS Client. This entry point
prints the requested value to stdout; keep the receiving terminal or pipe private.
Do not collect secret stdout, argv, credentials or response bodies in receipts.
The nine legacy commands above keep their private-file output, write-admission
and original exit behavior.

```sh
heptabao kv get -address=https://localhost:8200 -ca-cert=/private/ca.crt \
  -token-file=/private/scoped.token -mount=secret -field=value example
heptabao kv put -address=https://localhost:8200 -ca-cert=/private/ca.crt \
  -token-file=/private/scoped.token -mount=secret -cas=0 example @/private/data.json
```

Supported operations are `get`, `put`, `patch`, `list`, `delete`, `undelete`,
`destroy`, `rollback`, and `metadata get|put|delete`. Mount discovery calls the
public `sys/internal/ui/mounts/<path>` preflight and validates its KV type, mount
boundary and version before any data request. A failed discovery never guesses
v1 or falls back to privileged `sys/mounts`. `-mount` separates the mount and key;
without it, the mount may contain multiple path segments. `list` accepts a folder
ending in one slash, or an empty folder with an explicit mount.

`get -version=N` reads that version. A KV v2 deleted/destroyed version's 404
response with valid returned metadata is printed successfully when no field is
requested, matching the pinned CLI. A selected field or genuinely missing key
retains the API error exit 2; no data value is invented. `put -cas=0` creates only; positive CAS
values require that current version. `patch -method=patch` uses merge-patch;
`patch -method=rw` reads once, updates in memory and writes with the observed CAS.
The default patch method falls back to the CAS-protected read/write method only
on a known HTTP 403 policy refusal. A timeout, disconnect, 5xx or explicit
`-method=patch` never triggers fallback. Repeated `-remove-data=key` removes keys,
including a removal-only patch. `delete -versions=1,2`, `undelete -versions=N`
and `destroy -versions=N` operate on exact versions. `rollback -version=N`
reads current and historical values and writes the historical value as a new
CAS-protected version; an unreadable/deleted current value is refused.

Metadata put preserves omitted settings. It accepts `-max-versions`,
`-cas-required[=true|false]`, `-delete-version-after`, and repeated
`-custom-metadata=key=value`. This scope does not implement metadata patch.
`-format=table|json|yaml` selects output except `metadata delete`, which refuses
that flag and ignores the format environment, matching the pinned command help. JSON preserves the response envelope
except list, which prints its keys array. YAML quotes strings and map keys to
preserve JSON types. `-field` on get/put/patch/delete selects the data field before formatting.
Default/table prints the raw value without a newline; JSON prints the typed
JSON value without a trailing newline, and YAML prints a typed scalar with a
newline. This reflects the pinned 2.7.0 executable's field/format observations.

Data arguments accept literal `key=value`, a private JSON object file `@file`,
JSON from piped `-`, or exact UTF-8 `key=@file` / `key=-`. Prefer private files or
stdin for secrets; literal values in argv can be visible in shell history and
process listings. Token arguments always reference an owner-only, no-follow file,
never a raw bearer value. The new KV mode also accepts `BAO_TOKEN` or
`VAULT_TOKEN` from an explicitly configured process environment. Do not log that
environment. `-token-file` overrides environment credentials; `BAO_TOKEN_FILE`
(`VAULT_TOKEN_FILE`) is the private-file extension, and `BAO_TOKEN_PATH`
(`VAULT_TOKEN_PATH`) is used when no token value/file is selected. There is no
implicit home token helper, login, shell or credential cache.

The flags `-address`, `-ca-cert`, `-namespace`, `-format` and `-timeout` override
`BAO_ADDR`, `BAO_CACERT`, `BAO_NAMESPACE`, `BAO_FORMAT` and
`BAO_CLIENT_TIMEOUT`, respectively. Nonempty `BAO_` values precede `VAULT_`
fallbacks. Explicit empty `-namespace=` selects the root namespace. A CA and
HTTPS origin remain required. Timeout accepts seconds, `ms`, `s` or `m`, with
the shared finite maximum of 60 seconds; KV defaults to 60s. Namespace canonical
validation, TLS hostname checking, disabled redirects and disabled ambient proxies
are unchanged. This CLI retains the shared per-socket deadline limitation.

KV exit 0 means the operation succeeded and output was written; local input or
selection failures exit 1, and HTTP/TLS/transport failures exit 2, following the
public OpenBao command convention. Errors print fixed diagnostic codes and status
metadata only. No error body, input, bearer or target is printed. Unknown write
outcomes must be reconciled before another invocation. Full table byte layout,
wrap flags, client TLS certificates, TLS name overrides, proxy/discovery settings,
MFA and policy-output flags, enable-versioning, token helpers and the remaining
bao command tree remain open. Unsupported flags are refused before transport.
See the [scoped command matrix and provenance](../../docs/compatibility/HEPTABAO_PYTHON_KV_CLI_270.md).

## SDK boundary

```python
from heptabao import Client

# Obtain these variables from a trusted host configuration/credential channel.
client = Client(address, ca_file, bearer, namespace="", timeout=15)
response = client.request("GET", "/v1/secret/data/example", wrap_ttl="60s")
# Handle response.body in the dedicated consumer, not ordinary logs.
```

The SDK must receive a bearer value, but does not log it or expose it in repr.
`Response.status` and `.body` belong to the caller. The package exports `BaoError`,
`Client` and `Response`; private-file helpers remain implementation details.
The optional SDK `from_env` is an explicit call by an embedding host, not an
automatic CLI credential source. A host must review its own environment policy.

TLS uses an explicit CA with minimum TLS 1.2. Origins reject embedded credentials,
paths/query/fragment; redirects and ambient proxies are disabled. Request methods,
paths, header values, timeout and bounded JSON are validated, including duplicate
object-member rejection and explicit rejection of ambiguous namespace slashes.
Private token/input files are opened nonblocking before checking regular-file type,
so a FIFO cannot stall admission waiting for a writer. The configured socket timeout is not a proof of an
end-to-end deadline across every OS resolver or hostile transport behavior.

## Output, uncertainty and recovery

Private-file preflight occurs before dispatch; publication then uses an exclusive,
owner-bound, no-follow descriptor and atomic publication. The output is 0600.
A race or disk failure can still occur after a remote effect: diagnostics report
request/response progress but cannot certify whether that remote effect committed.
No command retries automatically, follows leader redirects, caches secrets or
starts a shell. Call the appropriate server recovery/metadata boundary before
making an explicit new mutating attempt. Do not retry OTP verification or unwrap
to test availability.

Exit 0 means an HTTP 2xx response was received and privately stored; exit 1 means
a received non-2xx response was privately stored; exit 2 means parsing, transport
or publication failed. Neither 0 nor receipt of a lease proves host SSH login,
external-provider success, production acceptance or complete compatibility.
In the legacy mode, only fixed safe codes/status metadata appear on stdout/stderr.
The separate KV mode prints the requested data described above. Python immutable
strings and interpreter copies are not guaranteed to be memory-zeroized; deployment
must account for process isolation, dumps and swap separately.

## Development and verification

```sh
python -m unittest discover -s clients/python/tests -p 'test_*.py' -v
python -m unittest discover -s qa/openbao-acceptance/tests -p 'test_*.py' -v
python qa/openbao-acceptance/client_live.py --binary /absolute/heptabao-server \
  --output /private/evidence/client-live.json
```

`client_live.py` launches fresh synthetic TLS state and real CLI subprocesses,
checks private outputs and secret-free diagnostics, and removes generated state.
QA's `bao_http.py` reuses the product transport rather than shipping QA in the
product. Package/wheel tests must bind the installed source files to this exact
checkout. Network SDK existence is not full SDK ecosystem parity. Full Agent method/template/cache/sink coverage, full Proxy compatibility, complete CLI flags/output modes,
Windows protected files, upstream plugin workflows and independent operational
qualification remain separate implementation work.

## Executable operational profiles (client package 0.2.0)

The wheel also installs `heptabao-agent`, `heptabao-proxy` and `heptabao-ssh-helper`.
These are actual processes, not full upstream replacements. Read the detailed
[configuration, state machine and recovery contract](../../docs/operations/HEPTABAO_AGENT_PROXY_HELPER.md)
before use. AppRole login and renewal have a durable pending checkpoint and a
single private token sink; unknown outcomes block retry. The proxy has a fixed
HTTPS origin/namespace and finite route allowlist on a Linux same-UID Unix socket.
The helper reads OTP only from stdin and checks the returned host/user/role binding.
It does not configure PAM or sshd. Pending checkpoints and stale sockets require
operator reconciliation rather than an unconditional cleanup/restart loop.

```sh
heptabao-agent --help
heptabao-proxy --help
heptabao-ssh-helper --help
```

The real-process fixture supports both source imports and an installed wheel via
`--client-python /absolute/venv/bin/python`. `--oracle` runs these same clients
against the pinned official OpenBao service; that proves only the selected workflow,
not general Agent/Proxy compatibility. Python memory copies are not zeroization
claims. Linux x86_64 execution cannot establish other-platform qualification.

## Explicit Transit re-encryption

The separately opted-in `qa/openbao-acceptance/migrate_transit.py` CLI and
`clients/python/heptabao/transit_migration.py` implement real source decrypt /
destination encrypt / decrypt-readback with descriptor-locked private checkpoints.
See `docs/migration/HEPTABAO_TRANSIT_REENCRYPTION.md` for its exact configuration,
unknown-outcome behavior, output retrieval, plaintext-memory limitations and
operator-owned cutover. This does not convert the original ciphertext in place
or provide key import, raw snapshots or full-instance migration.

## Native OIDC callback login

`heptabao-oidc-login` (also `python -m heptabao.oidc_login`) is an executable
S256 code-flow consumer for an already enrolled confidential issuer/client and
exact loopback redirect. It reserves a private output inode before login, keeps
the independent client proof out of the browser URL, enforces absolute callback
deadlines and exact Host/state/query, and never prints a bearer token. It does
not automatically retry failed/uncertain login; an incomplete reserved file is
preserved after failure. `--display-auth-url` explicitly exposes only the temporary
authorization URL to a trusted terminal; do not capture it in shared logs.
`--open-browser` is the alternative explicit local browser launch. Read
`docs/auth/HEPTABAO_ONLINE_AUTHENTICATION.md` from the repository root for commands,
all protocol/state limits and the distinction from a complete bao CLI or web UI.

Implementation owner: `heptabao/oidc_login.py`; tests: `tests/test_oidc_login.py`.

## Explicit OpenBao 2.7 consistency metadata

`Client.request(..., consistency_index=index, inconsistent=("await-state", "fail"))`
transmits one bounded `X-Vault-Index` and two separate ordered
`X-Vault-Inconsistent` fields. Supported sequences are absent, `fail`,
`forward-active-node`, `await-state`, or `await-state` followed by one of the
first two. Comma-separated, duplicate and reversed pairs fail before network
dispatch. No arbitrary header or bearer forwarding API is added.

`Response.consistency_index` preserves received bytes. Absence is `None`, not
proof of replica progress. Duplicate or malformed response metadata yields
`None` and `consistency_valid=False` without changing the acknowledged status
or body: never replay a mutation because its optional metadata is unusable.
Do not send a dependent request requiring a prerequisite without a usable index.
Indices are never implicitly carried between requests, persisted, combined, or
interpreted as authentication or read authority. The caller chooses the intended
same origin and namespace for dependent requests.

`Response.retry_after_seconds` retains bounded delta-seconds values, not HTTP-date
values. Neither it nor a 429 triggers a retry or sleep. The configured TLS roots,
hostname verification, namespace binding, no redirects, and timeout contract are
unchanged. Python's immutable metadata is not a memory-zeroization claim.

The Linux Unix-socket proxy admits only these additional prerequisite fields and
preserves ordered policy headers. Valid response indices and bounded Retry-After
are returned; invalid indices are withheld. Incoming tokens, namespaces, wrap TTL,
and unlisted routes remain forbidden. A prerequisite cannot change the configured
bearer or origin. The CLI has no new index flags/files; full CLI parity is open.

With the verified 2.7 archive and binary environment, run:

```sh
python qa/openbao-acceptance/client_consistency_live.py \
  --binary /absolute/heptabao-server --oracle-version 2.7.0 \
  --output /private/evidence/client-consistency.json
```

The runner uses independent candidate, PebbleDB and Raft reference processes,
the existing 28-case Raft lifecycle through the product Client, and a real proxy
subprocess against a three-node candidate. The proxy fixture supplies an admitted
synthetic sink; it does not claim Agent login/renewal-loop execution. Local input
refusals are distinguished from HTTP observations. Failed runs remain evidence.
