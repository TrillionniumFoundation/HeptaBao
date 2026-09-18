# OpenBao SSH OTP role migration

This is a bounded logical migration adapter subordinate to the current V2.1 plan.
It transfers **configuration only** for SSH roles whose source semantics fit the
HeptaBao OTP profile. It does not transfer an issued OTP, lease, CA issuer/key,
zero-address registration, host/PAM configuration, token authority, cutover
permission, or rollback authority.

## Supported source profile

`qa/openbao-acceptance/migrate_ssh_roles.py` inventories one explicitly selected
source SSH mount with `LIST <mount>/roles`, reads every named role twice around the
inventory snapshot, and accepts only `key_type=otp` with bounded `default_user`,
`allowed_users`, `cidr_list`, `exclude_cidr_list`, and `port`. Any non-default
source field outside that target profile is rejected instead of being silently
lost. CA roles, identity templates, non-default role TTL, issuer binding, domain
rules and certificate options are therefore not converted by this adapter.

The target SSH mount must already be deliberately created. This adapter does not
silently create/move mounts, because mount incarnation and lease ownership are a
separate migration asset. Target role names must be absent unless the adapter's
private checkpoint already owns the exact source digest for that role.

## Effect ordering and restart behavior

Apply mode requires all three operator inputs: a new owner-only checkpoint,
`--source-writes-frozen`, and `--target-exclusive`. For every role the adapter
persists a `write_inflight` intent before the target API call, performs the write,
reads the role back through the target API, and only then records `complete`.

After a lost acknowledgement, restart never blindly writes the role again. A
`write_inflight` checkpoint requires authoritative target readback: exact content
promotes the record to complete, absence remains an ambiguous pending write, and
a mismatch is a conflict. A completed checkpoint is also re-read every run; target
drift or source-digest rebinding fails closed.

The checkpoint binds source and target cluster identity, versions, namespaces,
mount paths and the immutable inventory digest. It cannot be reused to redirect a
migration to another cluster, namespace, mount, or changed role inventory.

## Authority intentionally not migrated

Issued OTPs and the associated lease/revocation state remain source-local
ephemeral authority. The live rehearsal issues an OTP on the official OpenBao
source before role transfer and proves the same OTP is rejected by the HeptaBao
target after transfer. The adapter never calls the credential-issuance endpoint,
never reads source lease records, and never synthesizes a target lease.

This is deliberate: moving role configuration does not make an already issued
credential fresh authority on the new cluster. Cutover must separately fence the
source, expire/revoke outstanding credentials according to the migration plan,
and re-authenticate/reissue after the target becomes authoritative.

## Executable evidence

- `qa/openbao-acceptance/tests/test_ssh_role_migration.py` tests supported-field
  normalization, unsafe source semantics, checkpoint rebinding and record digests.
- `qa/openbao-acceptance/ssh_role_migration_live.py` launches the checksum-pinned
  official OpenBao 2.6.2 binary and a real HeptaBao process, creates synthetic OTP
  roles, performs dry-run/apply/repeat/restart flows, verifies exact target/source
  readback, and proves a source-issued OTP is not transferred.

Passing this profile closes only the bounded SSH OTP **role configuration** adapter.
Full SSH migration still requires inventory of every SSH mount, explicit handling
of unsupported CA/issuer state, source credential drain, mount-incarnation-safe
cutover, host/PAM transition and independently controlled production rehearsal.
