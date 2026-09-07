# Live OpenBao acceptance and controlled KV-v2 transfer

These Python standard-library tools act on real HTTPS APIs. Their unit tests use
explicit fault-injection doubles to test tool safety; those doubles are never an
OpenBao Oracle, a compatibility corpus, or evidence of a deployed service.

| Entry point | Purpose | Default effect |
|---|---|---|
| `acceptance.py` | 38 synthetic KV-v2/token/Transit black-box cases, optional independent OpenBao comparison | No writes without `--allow-test-writes` |
| `migrate_kv2.py` | Explicitly selected KV-v2 histories, direct transfer or private export/import | Read-only dry-run |
| `ha_acceptance.py` | Three-or-more-node observation and controlled external failover/readback phases | Observation only; missing nodes are `not_run` |
| `live_migration_rehearsal.py` | Start a supplied verified Oracle and real candidate in one network context; rehearse copy, SIGKILL, acknowledgement loss and resume | Explicit invocation creates synthetic test resources |
| `bao_http.py` | Verified HTTPS, private files, bounded JSON, identity checks | No insecure TLS or bearer-token redirect |

Python 3.10+ and POSIX descriptor/ownership semantics are required for private
files and migration locks. No third-party Python dependency is required. The
service endpoints, CA certificates and provisioned tokens are external inputs.
No token, unseal key, private key, secret value or response body belongs in argv,
test fixtures, result files, logs or the repository.

For every endpoint prefix, configure `PREFIX_ADDR`, `PREFIX_CACERT`, and exactly
one of `PREFIX_TOKEN_FILE` or `PREFIX_TOKEN`. The file option is preferred: it
requires a regular file owned by the effective user with no group/other access,
and rejects symlinks. An optional `PREFIX_NAMESPACE` selects an already-created
namespace; the tools do not create namespaces. Set tokens through an approved
credential source, never a shell command containing a literal secret.

```sh
export HB_CANDIDATE_ADDR=https://candidate.example:8200
export HB_CANDIDATE_CACERT=/secure/qa/candidate-ca.pem
export HB_CANDIDATE_TOKEN_FILE=/secure/qa/candidate.token
python qa/openbao-acceptance/acceptance.py --candidate-only --allow-test-writes
```

Do not disable TLS verification to make this pass. HTTP, user-info URLs,
cross-origin redirects, implicit proxy environment variables and unbounded
responses are rejected. Existing administrative tokens can enable and remove
synthetic mounts and ACL policies; use a dedicated test deployment or an
explicitly delegated test namespace.

Results use bounded classifications and booleans. The acceptance output includes
the observed version, endpoint origin, hashed cluster identity, tool source
digest, case method/path template, HTTP status and asserted side effects. It does
not include token values, KV values, ciphertext, key material or raw errors.
Result files and checkpoints require an existing owner-only directory, normally
mode `0700`, and are atomically published as mode `0600`.

```sh
python -m unittest discover -s qa/openbao-acceptance/tests -p 'test_*.py' -v
python qa/openbao-acceptance/ha_acceptance.py
```

The second command deliberately exits nonzero with `status=not_run`: a local
unit-test pass or an absent HA deployment must never become an HA pass.

Detailed operating contracts and examples:

- `docs/compatibility/HEPTABAO_SINGLE_NODE_ACCEPTANCE.md`
- `docs/migration/HEPTABAO_OPENBAO_MIGRATION.md`

`evidence/live-migration-20260908.json` records the actual scoped migration
rehearsal against the named OpenBao2.6.2 and candidate binary digests. It is not a
receipt for future binaries or full-format migration. Archive additional actual
execution receipts and bind each to the tested deployment and immutable candidate
source identity before making a scoped claim. No live HA pass is bundled.
