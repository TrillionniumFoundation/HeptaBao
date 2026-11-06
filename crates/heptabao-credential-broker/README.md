# Synthetic credential broker candidate

This Rust library and executable provide an actually executable **synthetic-only**
credential-use slice. The supported HTTP target is a canonical numeric loopback
HTTP origin, an exact method and a fixed ASCII path. The signing target is an
explicit `git:repository-id` policy with Ed25519 OpenSSH SSHSIG namespace `git`.
It does not support arbitrary URLs, DNS, HTTPS, redirects, SSH login, passkeys or
live credential adoption. A returned HTTP status proves a response was observed;
it does not prove the application operation succeeded or constrain what a logged
in remote account may do.

## Trust boundary

A trusted local owner initializes a private directory from bounded JSON on stdin,
then issues HMAC-SHA256 grants. Every grant binds the broker identity, immutable
credential policy, task ID, run ID, operation ID, exact target/method/path and
request body digest with an expiry of at most one hour. The owner must resolve
and authorize those task labels. They are **not a cryptographically verified
HeptaRuntime workload identity**. The runtime adapter, separate OS principals and
real HTTPS target qualification remain HOLD.

The OS account owning the private directory is trusted. Root and malicious
processes of that same account can read its synthetic secret store. The agent
protocol has no API to retrieve the credential, but this alone is not an OS
sandbox. The `synthetic_only: true` flag is mandatory, cannot distinguish a user
mislabeling a real credential, and is not a production security certification.

The initializer keeps synthetic secrets and its owner MAC key in private files;
it is **not** an end-to-end encrypted personal vault. Individual API secrets must
not be placed in command arguments, environment variables, repository files or
model-visible logs. Bootstrap material arrives on stdin. Grants and operation
files are private files; they contain no upstream bearer token.

## Executable workflow

All paths must be absolute. Create a private request directory (`0700`) outside
the broker directory. Use `0600` operation and grant files. The root must not
already exist. Bootstrap JSON contains `synthetic_only: true` and `credentials`,
whose entries have `id`, `kind`, `target`, `method`, `path`, and `secret`.

```
heptabao-credential-broker init /private/broker < /private/input/bootstrap.json
heptabao-credential-broker issue /private/broker /private/input/operation.json /private/input/grant.json 60
heptabao-credential-broker serve /private/broker 100
heptabao-credential-broker execute /private/broker /private/input/operation.json /private/input/grant.json
heptabao-credential-broker status /private/broker /private/input/operation.json /private/input/grant.json
heptabao-credential-broker revoke /private/broker /private/input/grant.json
```

The SDK is the same `Operation`, `SignedGrant`, `Request`, and `call` API used by
the executable. Operation JSON has `operation_id`, `task_id`, `run_id`,
`credential_id`, `target`, `method`, `path`, and `body_base64` (canonical URL-safe
base64 without padding). The owner issuer and broker both enforce the policy.

For Git signing use `kind: "git_sshsig"`, `target: "git:<repository-id>"`,
`method: "SIGN"`, `path: "git"`, and an owner-provided synthetic unencrypted
Ed25519 OpenSSH key. The body is the exact Git commit or tag signing payload.
The result contains a standard SSHSIG PEM and public key suitable for independent
`ssh-keygen -Y verify -n git`. Native `SSH_AUTH_SOCK` authentication is not
implemented by this candidate.

### Git commit signing adapter

`tools/heptabao_git_signer.py` is a Python 3 `gpg.ssh.program` adapter for an
owner-authorized **exact commit payload**. It only accepts the Git SSH signing
invocation `-Y sign -n git -f PUBLIC_KEY FILE`; it refuses all other modes,
including SSH-agent (`-U`) requests. It calls only `broker execute`, never
`issue`, and never reads the broker's credential configuration or owner key.

The trusted owner prepares the unsigned commit payload (for example with
`git commit-tree` and `git cat-file commit`) with explicit author, committer,
dates, tree, parent and message, then issues the operation grant. The exact same
bytes must be presented by the real `git commit -S` invocation. Changed bytes,
an uncompleted broker result or a mismatched public key are refused.

`HEPTABAO_GIT_SIGNER_CONFIG` names a `0600` configuration file in a `0700`
owner-private directory. Its exact fields are:

| Field | Owner-provided value |
| --- | --- |
| `schema` | Integer `1` |
| `root` | Absolute broker directory |
| `op`, `grant` | Absolute private files outside the broker directory |
| `broker_executable` | Absolute path to the pinned broker executable |
| `expected_repository` | Absolute owner-private repository directory |
| `expected_repository_identity` | `device`, `inode` from repository `stat`, and `git_device`, `git_inode` from its `.git` directory `stat` |
| `expected_tree` | The exact lowercase tree object ID in the approved commit payload |

The adapter verifies the invocation's current directory, actual Git repository
context, owner-recorded directory identities, expected tree and full payload.
The supported checkout has a real `.git` directory. Bare repositories, linked
worktrees, symlink paths and tag signing are outside this adapter's scope.
Git's `TMPDIR` must be a `0700` owner-private directory; Git creates its temporary
payload there. Config, operation, grant and payload files must be owner-private
regular files without hard links. The public key may be readable by others but
must be owner-owned, not writable by others and stored in a private parent.

Set `gpg.format=ssh`, `gpg.ssh.program` to the executable adapter, and
`user.signingkey` to the synthetic public-key file. The adapter creates the
standard `FILE.sig` output only after a completed broker receipt, with no
overwrite. Use OpenSSH explicitly for independent verification because the
adapter accepts signing only:

```
git -c gpg.ssh.program=ssh-keygen verify-commit HEAD
```

Configure `gpg.ssh.allowedSignersFile` with the expected public key/principal.
The test suite runs actual `git commit -S` and `git verify-commit`, rejects the
same draft in another checkout, and rejects a subsequent changed payload.
This is a local invocation binding controlled by the trusted owner. SSHSIG and
Git objects can be copied and verified in other repositories; they do not
provide cryptographic prevention of cross-repository replay. The OS-account
trust boundary and runtime-attestation HOLD still apply.

## Persistence and rejection

An exclusive existing `heptabao-filesystem-guard` directory owner serializes
state publication. Before contacting a target the exact operation is durably
written as `outcome_unknown`. After a bounded attempt the sanitized receipt is
atomically published and fsynced. A crash, lost ACK, timeout or incomplete write
never authorizes resending. An exact duplicate returns the recorded receipt;
changed bytes under the same ID are refused. Ledger capacity is 4096 entries,
with no automatic eviction. External reconciliation of unknown effects is not
implemented; those operations stay unknown and require owner investigation.

Revocation is authenticated by a separate domain-specific owner MAC, persisted,
and checked before each request. Expired and revoked grants cannot read receipts
or execute. Backward wall time is refused using both retained wall observations
and a monotonic process clock. This does not defeat restoring an entire old
machine snapshot; hardware anti-rollback and production recovery are HOLD.

Only HTTP status and `http_success` are released, never upstream bodies,
headers, errors or secret material. `http_success` is true for 2xx and false for
3xx/4xx/5xx. A 3xx response is recorded without following it. HTTP completed means
status-line observation; even a 2xx is not proof of application-level success.
The client deliberately does not expose the body.
Malformed or slow peers produce durable unknown outcomes. Signature outputs are
public cryptographic artifacts; their original request binding is retained.

CLI `execute` exits nonzero for broker denials, unknown outcomes and non-2xx
HTTP receipts. It retains the fixed error code or durable receipt as JSON on
stdout. Local input/transport failures use a fixed JSON error on stderr. A
nonzero exit never grants permission to repeat an uncertain external effect.
An exact repeat retrieves the prior receipt without dispatch. `status` exits
successfully when an authorized query finds the recorded receipt, including a
failed HTTP response or unknown outcome; inspect its fields to assess the result.

## Qualification

Run the integration tests, which use fresh private directories, synthetic tokens,
a loopback HTTP server, independent broker processes, process kill/restart,
revocation, forgery, expiry, replay and SSHSIG verification:

```
cargo test -p heptabao-credential-broker
```

No production qualification, runtime task attestation, multiuser isolation,
SSH login, or long-term stability claim is implied by these tests.
