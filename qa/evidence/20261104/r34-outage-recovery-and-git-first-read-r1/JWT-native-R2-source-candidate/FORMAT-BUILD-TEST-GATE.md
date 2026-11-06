# Proposed source-only build and behavioral gates

This file authorizes no execution. Freeze source commit e3afc157447d35c861f275a761b29da3e42aff8e,
its nine exact files, actual repository format config, workspace Cargo manifest,
Cargo.lock and toolchain identity in a fresh isolated root. The canonical server
Cargo.toml is blob666dc6d056a8f653bb86ca5ba7ed89b229dfe228 (4796 bytes), default
native-v6-storage + native-v6-ha. No old retained artifact is changed.

1. Real pinned formatter: preserve all nine before/after files and strict
   diffs, tool/config before/after, original child/FD closure. The previous
   four-file formatter request does not authorize this larger input. Actual
   new payload size, root and custody request need separate root admission.
2. Ordinary wrapper compile:
   cargo check --locked -p heptabao-server --no-default-features
3. File V6 test compile:
   cargo test --locked -p heptabao-server --lib --no-default-features --features native-v6-storage --no-run
4. Default storage+HA feature test compile:
   cargo test --locked -p heptabao-server --lib --no-run
5. Exact actual libtest inventory for service::native_auth::jwt_tests:::
   all fifteen names in REGRESSIONS.public.json, no extra/duplicate/ignored
   names or replacement denominator. Record binary and actual list pins.
6. Execute that exact fifteen-test inventory under the admitted original
   custody/deadline request. Archive names, failures, original streams,
   authority and all child/FD closure; do not change an assertion or budget
   merely to make a failure pass.
7. Same-source adjacent regression gate: select exact existing native
   Userpass, TokenApi batch lifecycle, Identity and legacy JWT tests from
   pinned source plus the built libtest's actual list. No guessed count.
8. Actual repository fmt check and strict lint for admitted feature sets.

The source fixture retains each original 15-second request scope and the
unchanged shorter negative deadline/expiry tests. No cap is increased or
reset here. Exact execution keys, current tool/root/target/flock identities
and outer caps remain unresolved until a concrete later reviewed request.
An isolated source commit is not formatter, compile or runtime success.

Separately, use pinned official OpenBao2.7.1 and a successfully built new
HeptaBao candidate in fresh owned TLS fixtures, real non-root policy tokens
and mutually accepted LOCAL PEM configuration. First confirm both parsers'
shared config/role syntax. Observe named DELETE with delete-only versus
update+sudo (and negative update-only/no-capability controls), and collection
bare GET, GET?list=true and LIST with read/list policies. Include role/config
POST sudo differences only after valid shared bodies are pinned. Capture raw
HTTP status and before/after role state, not normalized status or a 69 rerun.
This ACL gate is SOURCE only; its binary pins/setup/requests are not yet frozen.

After any formatter or ACL semantic successor, qualify that actual source
and binary on the changed File/HA paths; current4e808 results stay attached to
their actual binaries. Production or remote-provider integration is outside
this local slice. No Runtime, provider, fresh auth capsule or deployment is
authorized by this plan.
