# Live metadata migration preflight

Current plan: `HEPTABAO-PLAN-2026-09-07-V2.1`. The real command is
`qa/openbao-acceptance/migration_preflight.py`; it is not a replacement migration
engine or an independent admission mechanism.

## Inputs, authority and output

Use one owner-only JSON configuration file with exactly `source`, `target` and
`planned_additional_bytes`. Each endpoint object contains exactly `address`,
`ca_file`, `token_file` and `namespace`. Addresses must be HTTPS origins; token
and CA files must be absolute, owner-only regular files without symlink path
components. The exact CA bytes are loaded once into the TLS verifier. Do not put
tokens, DSNs, unseal material or private keys in arguments. The optional capacity
estimate is null or an integer from zero through 2^63-1; it is not a guaranteed
serialized state size or a reservation.

```bash
python qa/openbao-acceptance/migration_preflight.py \
  --config /private/preflight-config.json \
  --output /private/new-preflight.json --allow-read
```

The caller must explicitly authorize metadata reads. A pre-existing output,
symlinked parent or group/world-readable parent is rejected before networking.
Publication uses the existing private 0600 create-only output function. This
command loads no direct bearer tokens or routing settings from environment.

The source must report OpenBao 2.6.2, the target must report HeptaBao and its
recognized bounded capacity profile. Equal endpoints or cluster identities are
rejected. Version text plus TLS is an observation, not a binary attestation;
actual acceptance additionally uses the pinned official binary launcher.

The command issues a fixed number of GET/LIST calls: health, source mounts,
auth methods, policies, entity/group IDs, token accessors, top-level lease
prefixes/namespaces, and target `sys/internal/capacity`. No recursive secret read,
mutating HTTP verb, token lookup-by-accessor, source freeze, target copy, lease
revocation or cutover is performed. GET/LIST still writes audit events and may
consume finite token uses; “read methods only” must not mean “no side effects.”

## Conservative inventory and capacity semantics

HTTP 403/404/5xx remains **unobserved**, never an invented empty collection.
Malformed successful objects, missing types/keys, duplicate keys and oversized
catalogs reject execution. Collections are limited to 10,000 items, under the
existing 16 MiB response limit. Only fixed family labels, known provider-type
counts, status codes and numerical capacity are reported. Mount paths, accessors,
policy names, descriptions and unknown plugin names are not emitted.

The report binds endpoint, namespace, health identity and version using separate
source/target digests. It compares the optional additional-byte estimate with
current target headroom and rejects known exhausted operation identity budgets.
Source Transit, PKI, SSH, database, TOTP or unknown providers are explicitly
marked as requiring separately qualified asset adapters.

The inventory is deliberately **incomplete** even if all eight catalogs return
200: it has not traversed assets, acquired a stable point-in-time snapshot or
converted any data. `status=blocked_full_instance_migration` and exit **3** mean
that observations were collected but the migration is not admitted. Exit **2**
means preflight itself failed. There is no successful-cutover exit or switch to
assert an independent review, production readiness or Hepta consumer approval.
A missing capacity endpoint on an older candidate is a blocker, not permission
to guess its limit. An estimate that fits does not imply that the copy will fit.

## Actual verification and remaining exits

`tests/test_capacity_preflight.py` exercises malformed/bool counters, missing or
ambiguous inventories, custom-name redaction, wrong clusters, output admission
and non-mutation. `migration_preflight_live.py` runs the actual private-file CLI
against a new checksum-pinned official OpenBao process and a new HeptaBao TLS
process. It verifies detected Transit, real capacity refusal, withheld cutover
claims, denied credentials and unchanged fixture mount/generation counters. The
fixture uses only generated synthetic credentials and deletes its private roots.
Its pass is a pass of **preflight behavior**, not a pass of migration.

After this preflight, the existing `live_migration_rehearsal.py` separately tests
its bounded readable KV v2 history transfer. Full replacement still needs complete
asset and version enumeration; source freeze/single-writer proof; typed adapters
for auth/identity/policy, keys/ciphertexts, PKI, active leases and provider effects;
verified cutover and rollback; and independent migration admission. In particular,
OpenBao snapshots are not current HeptaBao backups, and the shared `vault:vN:`
prefix does not make Transit domains interchangeable.

Hepta's external consumer pin stays unchanged until the real consumer and proposed
server exact commits/binaries pass their own authorization, replay, signature,
restart and denial fixtures, with deployment and operator admission handled
separately. A source-tree import or this report grants no consumer enrollment.
