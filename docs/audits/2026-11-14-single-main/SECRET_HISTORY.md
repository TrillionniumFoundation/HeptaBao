# Historical secret-pattern audit

The complete initial branch graph was included in an official Gitleaks 8.30.1 scan using `--all`. The release archive was checked against its official SHA256. Explicit configuration selected the tool's default rules; repository ignore files and inline allow comments did not suppress findings. The scanner reported **4,277 commits and 899,879,108 bytes of text/diff input**, with **4,128 matched occurrences** across **1,178 paths** and **168 commits containing findings**. A post-fix rescan returned the same complete finding-location set.

The scanner correctly exits 1 when it reports matches. Those matches are not automatically 4,128 leaked credentials. Every occurrence has a recorded disposition; no classification remains unresolved. No matched value or raw credential is included in the public location index.

## Dispositions

Of 4,114 generic-rule matches, 2,955 are hexadecimal content/file identities in explicitly named digest, source or file-identity fields; 379 are request-deduplication identifiers; and 16 explicitly declare publicly known synthetic derived keys. The other 764 occurrences received contextual review against their original Git source.

The contextual review includes 409 credential-content SHA256 observations. Eleven original receipts bind their consumer to an actual source SHA256, and that source maps credential contents through SHA256; these are not the raw credentials or merely assumed binary hashes. Other groups include file/configuration digests, Git objects, APK public-certificate origins, archive references, source expressions, serialized source and non-authorizing labels. Five TOTP test seeds, three explicit synthetic credential fixtures and one historical loopback-only development unseal fixture remain identified as public test material, not mislabeled as hashes.

All nine JWT matches repeat one upstream `testJWT` used for expected signature-failure JWKS checks; they are historical source archives, not captured user sessions. The five private-key matches consist of three invalid synthetic PEM fixtures/negative tests and two matches spanning PEM marker/encoding source. The corresponding exact source and current-head checks are recorded individually.

## Evidence

- [Summary, counts, provenance and limits](secret-history-summary.json).
- [Complete indexed location/disposition matrix](secret-history-locations.json): `columns` documents the six fields, and integer values select entries from the rule/file/commit/disposition arrays. Original files remain reachable using their recorded Git commits.
- [Fourteen JWT/private-key occurrence reviews](secret-history-high-signal.json).
- [764 contextual reviews, gzip-compressed JSON](secret-history-context.json.gz); the summary binds both compressed and uncompressed SHA256 values.
- [Original scanner summary log](logs/secret-history-scan.log).

This is a secret-pattern audit of the recorded text/diff scope, not proof that every possible encoding, binary or archive is secret-free. Fixed public test credentials are still credentials for those deliberately local test fixtures. No external credential validity checks or target contacts were attempted. The source review did not identify a matched external production credential requiring rotation or history rewriting; that scoped conclusion is not a production security certification.
