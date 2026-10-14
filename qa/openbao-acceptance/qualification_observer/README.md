# PKCS#11 executable observation qualification

This is a Linux QA observer, not a production server change or an OpenBao replacement release. The caller must independently verify the current case descendant owner chain after obtaining the image witness. No arguments after argv[0], environment, configuration contents, or secrets are read.

## Verified failure and correction

The old observer applied F_GET_SEALS to the producer fd number named in argv[0]. A producer can close and reuse that fd after exec while the child still executes the original sealed image. The real X230 run failed with errno 22 at producer_descriptor_get_seals. Kernel controls reproduce that failure. Real corrected trials retain positive held-child executable witnesses while also observing reused producer slots.

The new observer opens /proc/PID/exe once, pins that descriptor, and verifies its identity, UID, SHA-256, and all four required seals. It rechecks child and producer start times and the live executable binding. The producer slot is metadata-only diagnostics, never executable authority. A permission error from a live task still fails. Only a bound kernel pidfd reporting process exit can discard a transient sample, and discarded samples never count as positive evidence.

## Actual qualification

The server/libtest source is frozen at b9befa33dadc7bac0a9e9c8ffe33ff946207d577, tree e565658e3e8f2541a8046cb79ffc591997112392. This QA commit does not change or replace those server binaries.

| X230 profile | Previously passed ordinary tests | Newly executed genuine tests | Exact frozen-name union |
|---|---:|---:|---:|
| default | 2779 | 8 | 2787 |
| native-fixture | 2784 | 8 | 2792 |
| native-v6-service | 2791 | 8 | 2799 |

The eight original ignored names were executed explicitly against each exact frozen native binary with a real copied SoftHSM/PKCS#11 provider, not a mock or a new provider initialized per case. Original seed custody, immutable key objects, source/binary hashes, native exit statuses, deadlines, process-owner evidence and cleanup were checked. The union is by exact test name, not an arithmetic total across overlapping configurations. The original ordinary receipts retain their eight ignored entries; supplemental genuine receipts cover those names.

The helper has 13 kernel/identity control tests on X230. Controls include producer fd reuse, wrong digest, unsealed image, reused child or producer identity, foreign descriptor, live permission rejection, process exit, and same-UID disk executable rejection. The initial extra disk-image control correctly hit a UID rejection before the intended seal check; its failed receipt was retained and the corrected control uses a same-UID owned copy.

Failed R05 and R06 observations were not relabelled PASS. An independent late check only establishes that their observed original process identities are gone. The full qualified receipts are retained in the private operator evidence directory on X230 and mirrored to the Mac external drive. The public receipt is a projection that omits private host paths and process IDs. No production provider, token, endpoint, or service was changed.

## Reproduction and limitations

Run `python3 -m unittest discover -s qa/openbao-acceptance/qualification_observer -p test_wrapper_image_observer_v2_r2.py -v`. Kernel controls require Linux with procfs, pidfd, MFD_EXEC, sealing support, Python 3.11+ and the sleep utility. Linux-specific controls skip on Mac; that is not Mac PKCS#11 runtime qualification.

The machine-specific accepted runner and fixture preparer are evidence artifacts, not portable deployment entry points. The observer API alone is insufficient without the caller owner-chain and custody checks.

Full OpenBao 2.7.1 replacement remains HOLD: newer integrated source qualification, active scalable KV2 cutover, full API/provider parity, authoritative production recovery/migration, and long-duration mixed-platform HA are not established by these tests.
