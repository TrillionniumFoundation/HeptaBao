# Public Node literal-root read comparison — SOURCE only

## Narrow hypothesis

The existing public Node --version comparisons observed a known SIGABRT under the original profile and v25.9.0 without that test profile. Appending a bounded executable-map rule did not fix the restricted outcome. The later live log experiment completed with two unknown rows and zero admitted denial events; it did not establish absence of denial.

This proposal tests one new source-backed hypothesis. anthropics/sandbox-runtime commit 27fce0dbd58925061c57eb8b38707b9a98349dad contains a maintained policy implementation and a macOS regression which connect denial of the root directory inode to dyld aborts. The policy re-allows file-read* on the literal root directory. This is primary evidence of that project's implementation and intended regression coverage, not an Apple implementation contract, an execution of its tests here, or proof of this host's exact libignition failure.

Both complete source files, the fixed commit response, exact URLs, hashes and relevant line windows are included. The implementation distinguishes root directory entry names from recursive subtree access. The regression includes an allowed carve-out and a check that an outside file remains unreadable.

## Sole policy delta

The profile is the exact original 6,909 bytes followed by 33 ASCII bytes:

    (allow file-read* (literal "/"))

The appended newline is included in the 33 bytes. The result is 6,942 bytes, SHA256 33723469d1cbd03a04c6832b5d16ec55814103eeeb29ba6cb75014a83304d50e.

No executable-map rule from the failed experiment is retained. No new recursive root read, write, network, Mach or JIT rule is added. The new literal rule can expose root directory entry names; this is an explicit read-permission change, not merely a metadata check. The controller does not list root contents. Existing profiles and private data are not opened or modified.

## Same public two-arm mechanism

The fixed observed Node executable is /opt/homebrew/Cellar/node/25.9.0_1/bin/node. Both arms request only --version. No JavaScript entry, eval, preload, SDK import, provider or credential is supplied.

The restricted arm uses the one new public profile. The second arm runs the same executable without the test profile. Both use the same exclusive-create empty HOME/cwd/TMPDIR and the same closed five-field environment; no environment is inherited. New roots are:

- /Users/qianqi/heptabao-public-node-root-read-version-20261106-r1-control
- /Users/qianqi/heptabao-public-node-root-read-version-20261106-r1-empty

Runtime must prove absence and exclusive-create them through the unchanged HomeControl mechanism. This SOURCE does not claim they already exist or that absence has been observed. An existing root causes refusal, with no fallback, deletion or changed key.

Commands differs from the prior two-arm controller only in those two fixed path strings. Its full Popen, UID/PPID/PGID custody, WNOWAIT, output handling, once-only cleanup and success/refusal guards are otherwise byte-identical. Unreaped and HomeControl modules, four executable full9/hash pins, alias check, InputAudit, the entire two-arm work loop and entire finally block are unchanged.

All non-profile budgets remain: 35-second shared work, 45-second closure deadline, 60-second Native timeout, up to two primary Node children, at most ten seconds per arm, original TERM1/wait5/group3 cleanup reservation and ps4 limit. Four input and ten HOME returned descriptors are covered. The public profile read/write limits decrease by 69 bytes relative to the failed mapping experiment; they are 33 bytes above the original unmodified-profile fixture. No time or child budget is increased.

A known nonzero outcome may be compared with the baseline only after the original first-child known-reaped/group-empty gate passes. Any UNKNOWN retains the original stop/no-replay rules.

## Exact controls and original history

The request uses stdin, the fixed regular Python and original wrapper arguments. The journal changes only its fresh slot, exact request pin and observer prefix. It is not initialized. Native submission count is zero. Parent exact GO and an assigned lane remain required before its independent arm/dispatch boundary.

Strict forward and inverse patches are included: source 6/6 hunks, Commands 1/1, original-profile addition 1/1, replacement of the failed mapping suffix 1/1, journal 2/2. The R2 live actual and failed mapping actual remain original bytes; R5 root review still has path qualification and cause proof false. No old process or registration is operated on.

One local verifier-assembly attempt failed at JavaScript parsing before any action because a quoted backtick ended an outer template. The exact error boundary is recorded. The candidate source, request, journal and profile did not change. The actual saved verifier uses a directly defined pure JavaScript function.

## Verification and limits of a positive result

The actual pure V8 verifier passed 97 checks, including strict bidirectional reconstruction, unchanged modules/work loop/finally, profile prefix and one suffix, exact request/journal, fixed-commit primary files, and preserved prior observations. No Python, Node, upstream regression, component or Native call was executed by these checks.

If both arms succeed, the literal-root addition is sufficient for this fresh public --version invocation under its fixed conditions. That still does not qualify SDK imports, active-registry owner selection, isolation against credentials, or the full AuthBus AppRole/TLS/KV/Policy/renew/revoke/restart/rollback flow. It does not rewrite earlier abort causes or historical UNKNOWNs. Any business profile repair must be separately bound and reviewed.

If the restricted arm still fails, preserve the negative result and stop; no second rule is appended automatically. Current Linux candidate/artifact/issuer slots remain separate and unfilled by this Mac public test.

Interface: load pure-helper.original.js and strict-diff-helper.original.js, then verifier.public.js; call verifyRootLiteralVersionSource(files), where files maps every packet path to full text. The verifier performs no I/O.
