# Same-budget Mac snapshot integration resume

This is a new source revision and fresh output/control directory within the original 2400-second attempt. It does not extend the original absolute deadline (2026-11-04 20:53:48 UTC, also bounded by the original monotonic deadline). Prior exact 14-test result remains 5 passed and 9 failed, with no production link.

Three changes address actual findings: set the accepted Darwin socket to blocking mode before its existing DeadlineStream; synchronize the standby before checking its installed native root; use an actual non-snapshot ACL actor in the retained old HTTP denial test. All original assertions for denial, seal, archive refusal, no data loss and cleanup remain. Other named tests still prove non-root authorized reads independently. No outcome is assumed.

The short Darwin probe proves only actual socket flags. It does not prove Rust TLS behavior. The resume repeats strict normal Clippy, compiles the new exact libtest artifact, executes each of the 14 named cases once, and links production binaries only if every case passes. All steps share the original deadline. Full workspace, production HTTPS, physical-host HA and full replacement remain unqualified. Ordinary KV clock and AuthBus work are not implemented by this change.
