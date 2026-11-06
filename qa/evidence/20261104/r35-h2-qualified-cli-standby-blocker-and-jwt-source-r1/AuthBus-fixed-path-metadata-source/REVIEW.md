# Fixed-path launchd startup metadata proposal

Status: SOURCE ONLY. No Native, Python module, SDK, fixture, service mutation, cleanup or product execution performed.

The original 17 arguments, working directory, stdio paths and three environment fields are recorded in CONFIG. The original launchd alias differs from the already observed regular executable used to run the successful capture/controller and both diagnostics. This distinction is a testable input; it is not yet the startup cause.

The new source observes exactly 18 directory components, 4 regular leaves and the one original interpreter alias. It opens no file body, uses no application child/network calls and makes no service change. Parent and leaf descriptors are tracked until once-close. Each path and permission observation concerns the diagnostic process, not launchd's privacy authorization context. The full9 regular-interpreter expectation comes from exact prior public metadata aa9a0a5b4a421c6e55dd4a303e52b0ca59bb056c; no current hash is inferred from it.

The alias explicitly uses two follow-stat calls on that one fixed name to compare the kernel's resolved object against the held known regular interpreter. It does not follow returned path strings, open new targets or authorize a fallback. Readlink text is bounded and never published or hashed. The original guard and manager are unchanged.

The successful observation path costs 115 counted stat/fstat calls, 23 access checks and at most 2 readlinks; source caps are 256/24/2, 22 application FDs, 5 seconds shared and 60 outer. A synchronous call can return late and is then rejected. Python-internal descriptors are outside the explicit application FD ledger.

Log inspection is a separate unbound proposal. Original ACK creation at 1793925918877 and terminal publication at 1793925920735 give a conservative 3-second UTC envelope 2026-11-06T00:45:18.000Z to 2026-11-06T00:45:21.000Z. No local ps timezone is inferred. Installed log path/pin/help/schema remain unobserved; a broader log query or raw export is not proposed.

Validation here is the included finite V8 data/text check only. Python compile/execute has not occurred. All original failed worker, diagnostics and paused Git mutation evidence remain immutable.
