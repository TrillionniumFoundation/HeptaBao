# Genuine Transit StageB functional handoff

This increment implements the previously missing production CommandSandboxRunner
receiver. It is a trusted sealed-FD executor, not an OS sandbox. StageA's genuine
92-case result remains separate and grants no StageB qualification.

The chain to test is HeptaBao production HTTPS -> original Service plan and
External Keys grant -> CommandSandboxRunner -> heptabao-kms-sealed-exec ->
digest-pinned genuine KMS bridge -> digest-pinned maintained Transit provider ->
fresh official 2.7.0 HTTPS Transit. A second fresh official external-key consumer
supplies cross-decryption and signature compatibility observations.

## Deployment contract

Use an original production heptabao-server --config <absolute JSON> artifact
built from this new child, plus a separately retained
heptabao-kms-sealed-exec artifact built from the same child. Neither exists in
this SourceOnly increment. A producer receipt/current whole for e2b8 or an
earlier head cannot authorize this child.

The existing external_kms entry has these unchanged closed fields:

- id: transit.
- command/command_sha256: original genuine bridge custody.
- sandbox_provider_id: sealed_exec_adapter.
- sandbox_command/sandbox_command_sha256: this new adapter's future custody,
  never a shell/Python wrapper.
- sandbox_profile_id: kms_sealed_exec_v1.
- deployment_file/deployment_sha256: fresh mode-0600 operator JSON whose image
  is the existing maintained provider with its exact checksum, implementation
  opaque-kms-v1, provider transit, and empty args/libraries.
- owned_temp: fresh mode-0700 same-UID absolute socket directory, path <=60 bytes.
- timeout_ms: 5000; maximum_request_bytes: 262144;
  maximum_response_bytes: 1048576; enabled: true.

Provider HTTP config and token remain in the existing root-authorized External
Keys registry, never executable argv or public report. The config has the exact
fresh HTTPS address/public CA. The functional profile supplies no OS egress
policy. OS containment/network/resource isolation remain separate unclosed
admissions. No service field, durable schema or crypto primitive is added.
Selection must never fall back around a disabled/revoked registered KMS owner.

## Finite business contract

StageB retains StageA's 360-second absolute entry budget, five-second maximum
individual HTTP/RPC/owned-command scope, and original owned wait/cleanup
semantics. Startup, pins, business, every stop and final guards share the same
deadline. No mutation is retried after entry/unknown outcome. Maintained SDK
static retry behavior is not declared absent: actual remote counts are required.

Use fresh non-dev HTTPS processes and explicitly enable mounts. Config/key
verify:true results are parameter-resolution observations only, never crypto
success. Successful candidate AES encrypt/decrypt/sign/verify require exactly
one remote HTTP request. ACL/namespace/revoked-mount-grant denials require zero.
Unexpected counts fail the scope.

Mandatory crypto observations cover AES-GCM v1/v2, AAD readback/negative AAD,
candidate->official and official->candidate decryption, exact local/reference
rotation and old-v1 readback; Ed25519 v1/v2 candidate/official signatures,
maintained independent verification against each actually read remote public
key, and one-byte tamper rejection. A descriptor bit or Open/GetKey ack cannot
replace any of these.

Production external-key Transit descriptors contain references, not public
SPKI. Exercise ExportPublic through the existing genuine PKI root path:
actual ExportPublic plus root/full-CRL/delta-CRL signatures. The issued
certificate's maintained parsed SPKI must equal the requested remote Ed25519
version and its actual self-signature verify. There is no invented Transit SPKI
endpoint. Require one remote public-key GET and three sign calls.

Restart reuses only this campaign's encrypted data/config and requires original
candidate stop/wait, original-key unseal, actual v1 plaintext readback and
certificate public-key binding. Existing original actor/ACL/mount/namespace,
deadline, StateIdentity, PublicationGeneration, deployment/host fences remain.

Each candidate success passes the pinned genuine bridge nonce/framing/lifecycle
decoder (provider original wait=0, no forced/identity/signal gap). HTTP does not
export independent NewKey/Close counters. Report candidate decode enforcement
against the actually pinned genuine binary, and independent Close counters
false. Do not substitute StageA lifecycle observations for new runtime evidence.

## Outstanding gates

All implementation and Rust tests remain SourceOnly: no Cargo, adapter execution,
provider/candidate HTTP or release artifact. The /usr/bin/true ELF test proves
only executable capability handoff, not KMS/crypto. Functional StageB PASS cannot
qualify OS isolation, escaped descendant removal, loaders/kernel or all-chain
absence of nested forced cleanup. Full replacement requires each separately.
