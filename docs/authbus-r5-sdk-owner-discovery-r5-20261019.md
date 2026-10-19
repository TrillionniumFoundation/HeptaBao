# AuthBus R5: owned SDK package discovery fixture

This revision changes only the actual SDK caller fixture's package discovery
context. The admission registry, durable refresh coordinator, SQLite commit
bridge, SDK hooks, original 11 scenarios, request leases and deadlines are
unchanged from owner R4.

## Actual owner R4 result retained

The main host ran the frozen R4 packet with Node 22.23.3 and SDK 2026.7.1-2.
All 11 scenarios completed and 124 checks passed. The real SDK manager used
the scoped SQLite owner, performed one loopback HTTPS refresh only after the
durable UNKNOWN acknowledgement, committed and independently reread the SDK
credential before publication, and rejected old-wire successor reuse, missing
scope, a claimed unmanaged provider, SQLite abort, changed custody, duplicate
send, late continuation and retry from a new coordinator.

The run still failed its final zero-home-read assertion. Six denied reads were
`package.json` metadata probes from the SDK's channel catalog and alias package
discovery. The read guard denied every attempt; external network, external
process and outside-fixture write attempts were zero. These were additional
package discovery callers after the narrower R4 bundled-directory repair.

The original receipt is retained byte for byte as
`qa/openbao-acceptance/authbus/refresh-r5-owner-r4-actual-main-20261019.json`
(SHA-256 `26df147c07788658fc94adffa10f07f0947930222f1815311b628197b1176418`).
The original owned-launch controller receipt is retained as
`qa/openbao-acceptance/authbus/refresh-r5-owner-r4-actual-main-controller-20261019.json`
(SHA-256 `a7920487d952e0ede35b12426796b304e66910aefc4d7f8a6a22ced06bd755fc`).
The SDK child was PID 1597306 and was waited/reaped with exit code 1. The
installed SDK and all 13 fixture source files were unchanged after execution.

These results concern the actual SDK and actual SQLite, synthetic credentials,
an owned HTTPS provider fixture and an fsynced TLS control emulator. They do
not qualify a native HeptaBao backend, a real external OAuth provider, a cold
SDK process, production credential rotation or traffic cutover.

## Narrow R5 correction

The SDK package-root resolver derives candidates from `argv[1]` and `cwd`.
The exact channel-catalog caller first probes `process.cwd()` even when its
module belongs to the SDK. The exact alias caller captures `STARTUP_ARGV1`
and probes that hint even when its module directory already resolves to the
SDK. An external QA script and working directory therefore produce the
observed parent searches. An argument-only repair would leave the channel
catalog failure unresolved.

Before importing SDK modules, the fixture reads the selected SDK's own
`package.json` and validates `name`, the exact supported version and
`bin.openclaw`. The observed package has name `openclaw`, version `2026.7.1-2`,
bin `openclaw.mjs`, and a 116,017-byte manifest. The selector requires a relative
package-internal path, rejects parent traversal and symlink components, and
opens the package and entrypoint with `O_NOFOLLOW`. It accepts only regular
nonempty files of at most 256 KiB each, uses a bounded read with one extra byte
to detect growth, and verifies the descriptor identity and timestamps after
reading. It records both content hashes.

The isolated process then sets `process.argv[1]` to that declared, validated
entrypoint and sets its working directory to the selected SDK package solely
as package discovery context. It continues executing the same already-loaded
QA module; it does not invoke the SDK CLI. CLI fixture arguments were parsed
before this change, and the state, configuration, stores and evidence paths
remain absolute paths inside the fixture work directory. At completion the
fixture rechecks both source identities and both context values, and restores
the original argument and working directory in its `finally` block.

The production-validated bundled-plugin directory override remains. Plugin
activation and package ownership checks still run in the SDK. No home path
allowlist is added, and the final zero-home-read assertion remains unchanged.
Any other attempted home read still fails the run.

## Local verification and actual rerun

The selector is exercised against the exact fetched SDK package resolver
`dist/openclaw-root-_Kkan8Lf.js`, SHA-256
`b38ffc9ed9d1de4b79213bf9aab474985ae62127ba5f148b14433d8cbb51b7b9`.
The test executes that original resolver and the exact original catalog/alias
caller function bodies over a temporary synthetic package tree. The catalog
and alias input patterns each reproduce denied parent metadata probes despite
an owned module hint; both repaired context values resolve the correct package
with zero outside reads. Manifest reading and string normalization dependencies
in this fragment test operate on synthetic package data. It also checks
stable/replaced identities and rejects wrong package/version, missing or
escaping bins, symlink traversal and an oversized package before content
parsing. All 19 local checks passed. This is execution of fetched source in a
synthetic tree, not an installed-SDK refresh run.

The standalone test accepts the candidate runner and exact resolver, catalog
and alias sources as its four positional arguments. A new actual run must use a new fixture work
directory and the complete 13-module packet plus its pinned source manifest.
The original R4 failing work directory and receipts must remain untouched.

This revision is a candidate until that actual rerun passes every original
scenario, the unchanged zero-home-read assertion and the added package identity
recheck. Native backend integration is the next qualification boundary after
the actual SDK fixture passes in full.
