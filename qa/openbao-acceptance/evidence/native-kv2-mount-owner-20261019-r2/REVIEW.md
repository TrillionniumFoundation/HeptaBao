# Native mount terminal observation delta

This is an incremental candidate on the immutable native KV2 mount R1 overlay `cde8d6f77ce1614c390a95a82dfc3a4f4a8a9dc0fee41168a9c38acbeaedd797`, whose underlying source is `b24c6de7831a7389e39ac069277a9e85e858ef98` / tree `3356f0a94616e9e1804f497239f33546e16db577`. Apply R1 first, then this exact three-Rust-file delta. Neither the signed-zero R2 nor R6's LAN permissions change is included here.

## Concrete R1 defect found in source review

The existing terminal writer can advance both the Auth token clock and a retained `Engines.kubernetes_artifact_clock`. A retained clock alone is sufficient, including after the last opaque Kubernetes artifact has been retired. R1 checked the whole installed engine metadata against its pre-terminal digest and permitted only an Auth owner difference in the typed root. In this admitted mixed state, its own legitimate terminal observation would make an already committed mount request return 503.

That unconditional Auth-owner allowance also did not prove that an Auth-only publication after audit belonged to this request. R2 removes that allowance rather than extending it to all Engine changes.

The exact existing writer reviewed is `service_token_precision.rs`, Git blob `6220e98d3f5e4094e3db0993483a6ee08718d483`. Its affine receipt remains private to the real terminal writer; this patch neither changes it nor constructs one in a test.

## Exact state transition

A local mount request now uses the established native delivery checkpoint path: retain the actual post-operation root identity and publication generation, check that checkpoint before the terminal write, consume the one actual `TerminalClockReceipt`, and match its successor to the installed identity and generation. Only that same request's before-audit successor may update the mount constraint. A missing receipt requires the original checkpoint to remain unchanged.

The independent mount owner then requires engine metadata equality after normalizing only the pre-existing Kubernetes clock field to its prior value. The actual field cannot disappear or decrease, and cannot appear without pre-existing opaque artifact state. The typed root must preserve all payload graphs, mount incarnations, unrelated owners, epoch and other reader floors. The receipt's original writer separately validates the exact Auth/time delta. No response audit has happened yet at this point.

After this one transition, `check_installed` requires the full expected root and engine metadata to match. It no longer masks Auth. The capsule also requires the exact selected generation/checkpoint. A later policy update therefore cannot be mistaken for this request's terminal observation, even if the Actor, unseal nonce and mount all remain valid. No checkpoint or generation is recaptured after audit.

The original local Auth path with no mount owner retains its existing behavior. HA Auth still uses its existing affine checkpoint and sole real ReadIndex proof. This patch does not admit HA mount management and does not add a new proof or read on the local mount route. The original request deadline now explicitly scopes the local mount terminal writer, exactly as it already scopes the HA terminal writer. It is not refreshed.

## Regression changes

The same three new Service function names from R1 remain the complete mount group; no fourth test or change to the original 55/31 count is introduced.

The first case now seeds valid historical retained-clock metadata using a timestamp observed from the real clock, publishes it through the actual legacy State writer, and activates that actual store normally. This fixture does not claim Kubernetes provider coverage or replace any operation's Actor, clock, receipt or publication result. The mount creation must succeed while an actual engine clock advance occurs. The existing exact KV payload hashes, wide integer/decimal API projection, soft deletion, tune, real archive restore, delete/recreate and repeated cold reopen assertions remain. New assertions require the retained clock to survive cold reopen and not decrease during snapshot restore.

The post-audit seal case also performs a distinct real Policy write in a one-shot hook after a later mount read's mandatory audit. The new Policy must actually commit, while the old mount response must return 503 with no data. Fresh reads then confirm both the Policy and the original mount remain available. This proves rejection of an unrelated Auth-only publication without changing or revoking the Actor and without replaying a mutation.

All requests keep the original fixed 15-second scope. The three exact commands should use the existing source manifest, target lock, feature profile, single test thread and 1800-second command budget. Native-service-only compilation is still necessary because the added code is gated by `fixture-native-v6-service` without requiring the HA feature.

## Validation status

Only local source inspection, exact base-file identities, frozen-R1 immutability and unchanged test-name/deadline checks have been performed. This workspace has no Cargo or Rustfmt. R1 and R2 have not yet been formatted, compiled or executed on a host. Earlier physical and CI 55/55, full34 31/31, and AuthBus results belong to their earlier pinned source and do not qualify this candidate. The raw failure evidence and R1 overlay remain unchanged.
