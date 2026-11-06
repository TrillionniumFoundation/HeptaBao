# Precise PKI lease lookup status — SOURCE only

The old 69-case result remains unchanged: 67 exact numeric comparisons and two normalized rejection classes. This candidate changes only the PKI lease lookup error status, adds two File V6 regression cases, and removes those two acceptance normalizations. No binary has been built or run from this packet.

OpenBao 2.7.1's lease lookup handler returns an invalid-request error when the lease entry is absent; the HTTP adapter maps that error to 400. HeptaBao retains certificate records for certificate/CRL duties and currently returns 404 when that retained record is expired or revoked. The candidate returns 400 with an invalid-lease error for that lease-only query. Certificate retrieval paths and lease revocation side effects are unchanged by the source diff.

The added tests require a real issued synthetic lease and a successful precondition lookup, then exact 400 before and after reopening normal File V6 storage. They also verify that the corresponding certificate and the unrelated KV sentinel remain available. The tests use the existing controlled request clock; they are not live HTTPS or distributed tests.

The acceptance edit keeps the original two-second lease and 2.3-second wait, records actual numeric statuses, and requires 400. A future narrowly selected PKI-module probe must use a fresh owned fixture and a newly bound candidate binary. OpenBao expiration scheduling is still a live observation gate; a late 200 must not be normalized or hidden by retries.

This packet is an uncompiled candidate based on e3afc157 and has not been integrated into the formatter successor or a runtime checkout. No source or test qualification is claimed. PLAN.public.json contains the exact before/after/diff and primary-source identities.
