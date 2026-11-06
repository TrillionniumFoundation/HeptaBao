# Failed candidate: two read-only reconciliations

These are separate bounded diagnostic jobs after the first manager/init failed. They did not retry bootstrap or initialization. Each retained its original 52-second work boundary and 60-second native cap. No child process, manager/log query, service mutation, private key content read or business-source read was performed.

- r1 job `1a1b286bcbf-fc05-7e6a` failed at the exact base-launcher versus controller-venv path equality assertion. It closed 23 original FDs, made no HTTP connection and created no diagnostic output directory. The original terminal and full 1150-byte stdout are retained. This exposed a distinct launch-binding role mismatch; it was not reclassified as success.
- r2 job `1a1b28aaaf3-fc05-7e83` completed the read-only observation. It independently verified the real base launcher's full public binary hash and identity, while retaining the mismatch as false/unresolved. It rechecked the original empty data inode, five absent nonce/root/share leaves, exact initial archive/current binding bytes, installed plist and guard/config/binary/certificate identities. Its two strict-TLS connection attempts were refused before HTTP was sent. All 35 original FDs closed, zero child processes were created.

Neither result proves that the manager can start, that initialization happened, or that formal KV2 is qualified. The actual macOS removable-volume TCC denial is preserved separately in tree `993d0390a13bd86824cadf53e1aed1c5a55f35c9`. It is not bypassed by this observation.

The published controller files are exact public templates with the private native closure pin masked. Their hashes are template hashes, not a claim to publish the full private dispatch. The exact mixed stdin/request and native launch envelope remain private. Launch fields are explicit safe projections; request digests/fingerprints are excluded. The original terminal text and stdout bytes are preserved without JSON reserialization.
