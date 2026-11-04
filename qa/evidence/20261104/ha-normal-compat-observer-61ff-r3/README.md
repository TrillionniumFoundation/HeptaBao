# Normal-binary standby compatibility observer r3

This is a newly reconstructed candidate. It uses the recovered original Mac normal observer and the exact executed OpenBao 2.7.1 policy oracle; it does not claim to recover the unavailable earlier observer r2 hash.

A fresh, private three-process TLS fixture uses a real normal HeptaBao binary and independently pinned build receipts. The original fresh V5 seed, cold cloning, native V6 activation, actual TLS leaves, source/tree checks, HTTP/election deadlines and unknown-outcome prohibition remain. Node 3 adds the actual missing-header-forward listener setting. Only setup and role controls use the explicit inconsistent-request fail header; all business calls retain their recorded reference headers.

The 34 expected status cases cover non-root snapshot read/update policies, default-standby TTL reads, finite-use snapshot redirects without token consumption, and consistency-header precedence. The 30 policy cases were independently compared with the exact d1f40 reference wire. Four additional cases retain the earlier fixed token-oracle reference 070f72. Actual token creation, policy authentication, uses lookup, write effects and revocation are separate real operations.

Every completed business case is retained before subsequent checks. Finish always attempts to save these observations and always performs owned-process cleanup even if that save fails. Complete HTTP responses, definite preconnect failures and unknown outcomes are separate counts. Coverage reports missing, duplicate and unexpected labels. Exit 0 means the complete observation ended cleanly; a distinct scoped compatibility field requires all 34 cases exactly once and no status differences. Full replacement remains false. Archive checks establish only bounded shape, not restore or cross-format compatibility.

This candidate has not yet passed Python syntax validation or run against the new binary. It must be reviewed and executed only after the actual Mac normal build receipts exist. No product service was started by preparing these files.
