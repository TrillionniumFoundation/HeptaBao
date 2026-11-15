# Python KV command scope for the 2.7.0 target

The executable product is `clients/python/heptabao/kv_cli.py`, reached by the
installed `heptabao kv` command or `python -m heptabao kv`. It does not call a bao
binary, package QA code or translate upstream implementation source. The legacy
private-output entry point remains in `heptabao/cli.py`; the Rust CLI contract
crate is a separate model. No manifest, runtime dependency or admission status
changes for this increment.

## Runtime capability matrix

| Command | Actual behavior | Guards and bounded differences |
| --- | --- | --- |
| get | KV v1/v2 data, selected version, field or formatted response | KV v2 version metadata stays distinct from secret data; missing healthy field is exit 1; deleted/destroyed no-field reads print returned metadata |
| put | KV v1 replacement or new KV v2 version | Optional exact CAS; CAS 0 remains distinguishable from omitted CAS |
| patch | Merge PATCH, or explicit local read/write with observed CAS | PATCH CAS 0 is omitted, positive CAS is exact; default policy-only 403 fallback and explicit read/write ignore supplied CAS and use the read version; no unknown-result/5xx replay; removal-only and repeated remove-data flags |
| list | KV v1 path or KV v2 metadata enumeration | JSON/YAML prints keys only; a listing supplies no data-read authority |
| delete | Latest value or selected KV v2 versions | Selected-version operation is rejected on v1; latest v2 deletion does not destroy history |
| undelete | Restore selected soft-deleted versions | Requires nonempty positive versions and discovered v2 |
| destroy | Destroy selected versions | Requires nonempty positive versions and discovered v2; no automatic retry |
| metadata get | Complete version/configuration response | Discovered v2 only; table includes each version |
| metadata put | Update only explicitly selected configuration/custom metadata | Boolean setting is tri-state; private credential and data files keep owner/no-follow checks |
| metadata delete | Delete all versions and metadata | Explicit command is mutation authorization intent; server ACL remains authoritative |
| rollback | Copy a selected historical value into a new version | Latest read anchors CAS; failed/unreadable latest or historical read prevents write |

Common implemented options are `-address`, `-ca-cert`, `-token-file`,
`-namespace`, `-format`, `-timeout`, `-mount`, and supported-command `-field`.
`--address`, `--ca-file`, `--token-file`, `--namespace`, `--format`, `--timeout`,
`--mount` and `--field` aliases are accepted. Version/CAS flags are command
specific. `metadata delete` does not support format flags and ignores the format
environment; its ordinary success output is a fixed message. Input supports key-value strings, private `@file` JSON objects, piped
JSON `-` and exact text `key=@file`/`key=-`. Files keep the existing private-file
boundary; credentials never enter argv. Explicit environment credentials and
BAO-to-VAULT option fallback apply only to the new KV mode. There is no automatic
home-file token lookup. User-requested secret stdout belongs to the consumer;
logs and evidence must record only case labels, statuses and predicates.

## Ordering and uncertainty

Validate grammar, canonical paths, numeric bounds, complete input, credential
permissions and output selection before discovery. The shared Client validates
TLS and the configured namespace. Discovery must return a canonical matching
mount path, KV type and version 1 or 2; unknown or failed results stop the command.
No privileged mount-list fallback or guessed KV version is admitted. Discovery
metadata does not grant data authorization. Each business request still carries
the caller's exact credential and namespace, and server admission controls its
finite uses and ACL.

A normal write is sent once. Explicit read/write patch and rollback each anchor
the final write to an observed current version; a conflict fails, with no fresh
read/retry loop. Only omitted-method PATCH with an actual 403 refusal may proceed
to the documented read/write policy fallback. TLS failures, redirects, timeouts,
other statuses and unknown outcomes cannot enter that fallback. Local parsing
errors exit 1; API/TLS/transport errors exit 2. Error diagnostics never echo input,
paths, environment, response errors or credential bytes.

## Provenance and test boundary

The implementation uses existing original Python transport code and public
product documentation: [KV get](https://openbao.org/docs/commands/kv/get/),
[put](https://openbao.org/docs/commands/kv/put/),
[patch](https://openbao.org/docs/commands/kv/patch/),
[delete](https://openbao.org/docs/commands/kv/delete/),
[metadata](https://openbao.org/docs/commands/kv/metadata/),
[rollback](https://openbao.org/docs/commands/kv/rollback/), and the
[CLI environment/input/exit contract](https://openbao.org/docs/commands/).
The [public mount-preflight contract](https://openbao.org/docs/api/system/internal-ui-mounts/)
is internal/unstable upstream and therefore must be rechecked against the pinned
binary for a future version. No restricted Go source or copied upstream tests
were accessed.

The SHA-256-pinned 2.7.0 Linux executable
`9403c2b121e13fe79b3182051320d2096d10519b597ee587e322dab5e359c51e`
provided twelve public `kv ... -h` outputs without any HTTP requests. Its help
confirms repeated `-remove-data` and the default policy PATCH-to-read/write
fallback, and a three-state metadata `-cas-required` flag. Help/units are contract
observations; they are not a passing native/oracle comparison. A separate
8-observation public executable probe of KV v1/v2 confirms that field selection
still honors JSON/YAML formatting: default/table emits raw values without a
newline, JSON emits a typed value without a newline, and YAML emits a typed
scalar with a newline. The initial runner's failed prefix is retained; it must
not be relabeled as a complete interface after this correction. Probe receipts
contain only exit/status/shape predicates, never requested stdout or value hashes.
A separate 12-observation pinned public probe distinguishes deleted/destroyed KV
v2 reads: the API returns 404 with null data and version metadata, but the CLI
prints that metadata with exit 0 when no field is selected. Selecting a field
still returns exit 2. A genuinely missing key has no version metadata and keeps
exit 2. Only this exact GET/404/null-data/valid-metadata shape is admitted by the
Python CLI; no blanket treatment of 404 as success is added. The runner now adds
two metadata predicates to retain both deletion and destruction assertions.

Original units exercise command semantics, path/namespace isolation, private
inputs, permission failures, stale-CAS refusal, read-before-write failure,
unknown-after-entry outcomes, no retries, fixed diagnostic errors and requested
output. Original HTTPS subprocess tests check shared TLS verification, disabled
ambient proxies, redirect refusal and one write effect after a disconnected
reply. Fixtures use only synthetic credentials and capture positive stdout in
memory; no user-requested output or credential enters a proof receipt.

The `qa/openbao-acceptance/python_kv_cli_live.py` runner starts fresh synthetic
TLS services and runs the real Python product CLI and pinned official bao CLI
independently on each. Its fixed operation list requires 68 complete predicates
per interface (272 for candidate+oracle, 136 for explicitly selected
oracle-only). No receipt stores stdout, stderr, payloads or value digests.
Candidate execution requires an immutable successful build custody receipt;
its source identity is distinct from the Python/QA checkout. Reports bind both
identities, exact executable/launcher/client hashes and process cleanup. Matching
failed prefixes and an oracle-only run cannot qualify the candidate. The
historical oracle-version default remains 2.6.2; 2.7.0 must be selected explicitly.
The fixed PATCH trace includes positive CAS and removal-only PATCH with CAS 0.
Its version and readback checks reject a zero-CAS request that fails to publish.
Source existence and unit success do not mean this runner has passed live.

## Open replacement boundaries

Full bao command-tree coverage, enable-versioning, metadata patch, exact table
spacing, all wrapping/HTTP flags, TLS client certificates/name overrides, CA
directories, Agent/proxy endpoint selection, MFA, unlock/policy-override flags,
cURL/policy-print modes, shell completion and token helpers remain open.
Unsupported flags fail closed instead of being ignored. The shared Client keeps
HTTPS-only origins, explicit CA, no redirects, disabled proxies and its bounded
socket-timeout semantics. A later whole CLI/Agent/Proxy qualification must retain
these deliberate boundaries or implement and review an explicit replacement.
This scope does not grant full compatibility, production authority, migration
admission, independent security qualification or release authority.
