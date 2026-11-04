# Current Mac credential staging, 2026-11-03

The fresh Mac test read only primary rows from `auth_profile_store` and `auth_profile_state` in the five currently configured agents' SQLite databases. It did not reuse a historical backup. All source credentials stayed on the Mac, in memory or owner-only files on T5. The checked-in receipts contain counts, fixed assertions, paths and digests only.

The test used the real c0d8 HeptaBao candidate binary (SHA-256 `d1b06034512e7532b2658c8dc56ffe7cc725cdf893de3696344ac50989b844bc`) and its ordinary `--config` service path, explicitly selecting `native_v6_file` and activating the formal V6 service endpoint. The server's format 2 capacity was confirmed. The current installed OpenClaw package and actual store/SQLite module hashes are pinned in the receipt. The host-bound fresh gateway entry observation resolved that installation before this test.

All 50 driver checks and 30 child-client checks passed in 4.7 seconds. Five per-agent AppRole policies admitted only the assigned key. TLS CA and exact leaf pin, exact credential-document reads, cross-agent denial, and confirmed self-revocation passed both before and after actual server SIGKILL/cold start/unseal. Separate offline processes running the current installed SDK read baseline, migrated and auth-only rollback databases with identical effective profile/store digests. Network and child-process APIs were blocked in those SDK readers. Re-reading the original production rows at the end confirmed both credential rows and auth state were unchanged.

There were 12 stored OAuth profile rows and 24 nonempty literal credential fields; all 12 stored access credentials were already expired. There were no future-dated OAuth profiles. This proves current-source custody and lossless staging/recovery, **not current provider validity or that these rows are the active inference credential source**. Refresh tokens were not exercised. No provider request, J3160 request, production traffic cutover, production gateway restart, or production traffic rollback occurred. The auth-only rollback is a reconstruction of two auth tables, not a complete OpenClaw database restoration.

A separate post-run custody check found no source credential plaintext in 52 encrypted service data files (544,440 bytes) or 13 diagnostic files, verified 36 sensitive files were owner-only 0600 single-link files, and confirmed no owned staging server remained. The source data and plaintext private recovery copies are intentionally excluded from Git.

## Reproduction

Driver: `qa/openbao-acceptance/authbus_current_credential_stage.py`.
Child SDK reader: `tools/authbus/production-transport/tests/current-sdk-read.mjs`.
Child TLS client: `tools/authbus/production-transport/tests/current-stage-read.mjs`.

The driver requires explicit absolute paths for a new private work directory, current `.openclaw` source, installed SDK root, server binary and QA source root, the two child readers, patched transport modules, Node executable, and expected binary/config SHA-256. The driver currently deliberately binds the five observed Mac agents and installed store-module filenames. A changed configuration, custody, source identity or pinned binary is refused. Do not point it at a staged copy and claim that copy is a current provider authority.

Dependencies already in this repository: `native_v6_authbus_client_live.py`, `cert_auth_live.py`, `qa/single-node/smoke.py`, `owned_process.py`, `fixture_mounts.py`, and the production transport package. Python stdlib, Node with `node:sqlite`, OpenSSL, and the actual installed SDK are required.

Original Mac receipt: `/Volumes/T5/hepta-vnext-recovery-20261013/authbus-mac-current-stage-20261103-r1/validation-r1/result.public.json`, SHA-256 `ea6e4cbd9d2e43978b86beece6420b6a6db4a481993064e06f4ab16227652059`.
Custody receipt SHA-256: `6c5cc2280ad78abb0c4363e6eaf48c53f286ff2340b00eaf52037789409a4320`.
