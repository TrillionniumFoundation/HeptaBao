# HeptaBao unified candidate: exact recovery checkpoint

This branch preserves evidence and reviewed recovery inputs after the local executor became unavailable. It does not update PR 152 or qualify a replacement release.

The actual ROG source is `3961275d27e4a4e64e2d28619ef3b1b8d76e9980`, tree `d6dffaf4627ac16961e67c94b99f84122adc2e1d`. Its format gate passed. Strict Clippy then reached the server test build and reported two E0277 errors, two E0063 errors and one int_plus_one lint. The complete 6,112-byte stderr is retained. No runtime regression was executed on this candidate.

The next four-file test-only correction is fully preserved. The two Response unwrap sites print only an HTTP status on unexpected failure; Response does not gain Debug. Two older HaProcess fixtures explicitly initialize the new handler to None and do not fabricate a Service receipt. The bounded prefetch assertion uses the equivalent strict comparison. These changes were not applied: r4 refused an unknown builder before source mutation.

The exact live cgroup identified r9 job `1a1a7738839-fc05-2b7f`. It held shared Cargo cache and original target locks. It was left running. This blocker is distinct from the earlier, independently isolated external build and is not covered by that compile exception.

## Recoverable materials

`source/input-r1.tar.gz` contains all 56 integrated input files. Overlay the 14 exact formatted files in `source/r3-formatted-source-packet.json.gz`, then validate every SHA256 and Git blob in `r3/frozen-source-r3.public.json` and the full tree. The reviewed r4 files and exact original process-start request, argv script and stdin are included. The request SHA256 matches the file created before the environment interruption, not merely a semantic reconstruction.

The request's original r4 idempotency key is already bound to a terminal admission refusal. It cannot be reused to execute a new attempt. Check the original monotonic deadline and boot identity, verify the actual pinned clean source and absent next run directory, wait for resource release, and record a distinct reviewed readmission key before launching unchanged code. Do not infer job identity from time or proximity.

## Evidence scope

Both f913 head and prospective merge completed the full Rust workspace: each had 67 top-level groups, 4,721 passes, zero failures and nine explicit ignored cases. Both overall CI jobs failed later at strict Clippy. Their complete raw logs are preserved; nested filesystem guard child summaries are not added to the totals.

The current unified candidate has no strict-green result, normal production binary, complete workspace run, production HTTPS qualification, physical three-machine HA result, X230 qualification, traffic cutover or retirement authorization. The four known semantic gaps remain listed in CHECKPOINT.public.json. All earlier red observations remain red.
