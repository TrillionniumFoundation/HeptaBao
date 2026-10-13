# OpenBao 2.7.1 → HeptaBao: scoped migration execution contract

**Status: NOT_ADMITTED.** This file does not authorize source quiescence, target
cutover, rollback, token transfer, HA metadata import, production use, or release.

## Exact source and fixture custody

The source version is selected explicitly with `--oracle-version 2.7.1` in
the migration QA runners and the normal bounded official comparison runner.
The historical 2.6.2 default and each profile's existing case denominator are
unchanged. Release selection alone grants no compatibility or migration admission.

For the Linux amd64 official 2.7.1 release, the launcher requires all of:
* Archive `openbao_2.7.1_linux_amd64.tar.gz`, SHA-256
  `0e2f1ce10d124e03112b50dd2fbec6b78003783253bc3a91587938f39d1e2243`.
* The unique regular `bao` archive member and local executable must both hash
  `535cf827b13753046757f5ec8b97ae0ef21f10a40ffe673f0d5e75616170f5ea`.
* The published 2.7.1 `checksums.txt` hashes
  `95ad62d532df64dea20463ce513f0a56f792530bbefeb4e89525bc1eb773b750`.
* Real non-dev HTTPS with a private, isolated TLS CA; verified source health
  `version=2.7.1`, unique source/target cluster identities and matched fixture
  receipt. The default non-HA 2.7.1 storage profile is PebbleDB; Raft is
  available only through an explicit fixture flag.

Unsupported platforms, unverified assets, source-dev versions and conflicting
identities are rejected before any import.

## Bounded operations only

KV2 readable contiguous histories, user ACL policies, internal Identity
entities/groups, selected auth-mount metadata, SSH OTP role configurations,
and Transit ciphertext re-encryption each retain their existing strict
allowlists and separate apply conditions. They are **not** a complete asset
migration and do not preserve OpenBao barrier/Raft bytes, provider-side lease
state, live tokens, wrapped authority, external groups, source auth accessors,
unknown PKI private keys or revoked/destroyed KV2 history.

Any mutation is explicitly selected, uses a private checkpoint and exact
source inventory binding, requires source freeze and exclusive target ownership,
and is not blindly retried after an unknown write acknowledgement. A source
token must never authenticate against the target. A source snapshot must not
be imported as a HeptaBao native format.

## Required additional release evidence

Scoped unit/QA tests and synthetic source→target exercise are prerequisites
only. Before the `full_asset_migration` admission gate can close, an independent
operator must inventory all 2.7.1 mounts/namespaces/versions/providers, prove
absence of omitted/revoked assets, rehearse complete consumer cutover and safe
rollback with lease/token revocation, and verify actual destination state and
external effects on distinct hosts after restart and HA failure. The legacy
2.6.2 ledger in `planning/HEPTABAO_OPENBAO_ASSET_MIGRATION_V1.json`
remains frozen at version 2.6.2 and cannot self-qualify 2.7.1.
