# Bounded executable-mapping hypothesis — SOURCE only

The completed original comparison (actual tree 3504e0990166a307f38a749c0e868ee117287e2d) used the same observed Node binary, explicit environment and cwd. The original restricted invocation aborted with -6 and no output; the no-test-profile baseline returned v25.9.0 and exit 0. Both were known and closed. This identifies an association with that test-profile invocation. It does not identify which operation was denied or establish the cause/progress of the older private runtime.

## Concrete next diagnostic
The proposed new generation uses two fresh create-only public roots, the same two exact --version argv forms, and the unchanged owner/cleanup protocol. The restricted arm's profile is the original 6,909 bytes followed by this one 102-byte rule:

```scheme
(allow file-map-executable (subpath "/System") (subpath "/usr/lib") (subpath "/opt/homebrew/Cellar"))
```

The addition changes one operation class over three bounded public code roots. All three lie within existing read roots; it adds no file-read, write, network, Mach, sysctl or JIT permission. It does not change an existing profile or service. Original profile paths, including the old public experiment's literal paths, remain as bytes in the new copy; this controller does not read those old paths. The baseline never qualifies SDK execution.

Both arms retain the same new HOME/TMPDIR/cwd, fixed five-key environment, real Node --version and original input full9/SHA gates. No Node compatibility flags, JavaScript, imports, SDK, config, credentials, providers or business operations are requested. No new port or label is created.

Fresh roots:
- /Users/qianqi/heptabao-public-node-map-version-20261106-r1-control
- /Users/qianqi/heptabao-public-node-map-version-20261106-r1-empty

Existing roots cause refusal without fallback or deletion. No Native slot has been initialized or request submitted.

## Primary-source basis and its limits
[Apple DyldDelegates.cpp](https://github.com/apple-oss-distributions/dyld/blob/main/dyld/DyldDelegates.cpp), lines 992–1014, uses different sandbox operation names for executable mapping, data open and metadata stat. [Apple Loader.cpp](https://github.com/apple-oss-distributions/dyld/blob/main/dyld/Loader.cpp), lines 1699–1707, diagnoses a mapping sandbox refusal only after mmap actually returns EPERM and the matching sandbox check succeeds. That branch is not claimed to be the source of the previously observed libignition stack.

[Apple-authored WebKit policy](https://github.com/WebKit/WebKit/blob/main/Source/WebKit/WebProcess/com.apple.WebProcess.sb.in), lines 93–123, grants system reads and executable mappings separately. Its [common.sb](https://github.com/WebKit/WebKit/blob/main/Source/WebKit/Shared/Sandbox/common.sb) has conditional version 1/3 branches, which are retained in the source evidence; no claim is made that a WebKit build's policy equals this host's shipped policy.

[Node v25.9.0 node.cc](https://github.com/nodejs/node/blob/v25.9.0/src/node.cc), lines 1062–1097, reaches a version-output early return before the later V8 initialization at 1239. Loader/platform initialization can still occur before the version print. This is a reason to test a loader permission rather than add JIT or Node compatibility flags.

The whole official source bytes, URLs and hashes are included. Apple main is not matched to macOS 25G83; no local sandbox denial rule/path has been observed. LIBIGNITION code 2 remains uninterpreted as errno. This is a falsifiable permission hypothesis, not a proved repair.

## Exact retained limits
The 35-second work, 45-second final closure and 60-second Native budgets are unchanged. At most two primary Node children are admitted; each has at most 10 seconds and must leave the original TERM1/wait5/group3 reserve. Unknown stops the next arm. Custody, strict PPID/PGID/UID, WNOWAIT, once cleanup and stream closure are unchanged.

The 14-application-FD ceiling, fixed executable input bytes/calls, metadata caps, process-read 16 KiB, immutable page 8 KiB, observer limits and public output caps are unchanged. The only byte-budget increase is the fixed profile: write/read 6,909→7,011 bytes and EOF-inclusive read request 6,910→7,012, exactly +102. It is explicitly new public-profile I/O, not a reset of any historical budget.

## Mechanical review
The executed pure V8 verifier passed 78 checks. Strict forward/inverse differences are source 6/6 hunks, command constants 1/1, profile 1/1 and journal 2/2. The embedded HomeControl and WNOWAIT helpers are byte-identical. Commands differs only by the two fresh root literals; every owner/exit/cleanup method is identical. InputAudit, the two-arm work loop, all final closure code, and twelve named helper functions are unchanged.

The verifier only compares public source and captured evidence; it does not run Python, Node, a module or a fixture. Its interface is verifyBoundedMappingVersionSource(files) after loading pure-helper.original.js and strict-diff-helper.original.js. files maps this tree's exact flat names to UTF-8 text.

## Interpretation and next gate
A matching version with known closure would show that this particular bounded addition permits this public version experiment. It still would not qualify SDK/provider code, identify the exact path denied before, or change historical UNKNOWN. Continued known abort with a successful baseline would refute sufficiency of this addition, without proving another rule. Any baseline failure or UNKNOWN remains separately visible and does not authorize another attempt.

Root exact GO is required before this new request. The 576 Linux release-phase declaration remains separate: the whole build is reported failed, and actual final report/full9/version/issuer qualification remain null or false. No credential or production binding is inherited.
