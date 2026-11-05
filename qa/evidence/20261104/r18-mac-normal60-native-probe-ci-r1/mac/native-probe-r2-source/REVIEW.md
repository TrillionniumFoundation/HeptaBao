# Public native probe R2: exact ancestor read and bounded diagnostics

This is a new source-only request. The R1 job1a1a9ffb40d-fc05-3af8 remains a known failure, and none of its files or results is overwritten. Its complete actual packet is83c0d88327a8ad5bfee5ae8a8c55dea4fea6f1eb. The older PID11754 unknown remains unchanged.

## Actual evidence and the narrow source finding

R1 actually loaded the fixed native libraries, observed Darwin25.6.0/build25G83, passed the full136-byte ABI/self identity checks and completed one native-owned diskutil with WNOWAIT retention, empty group and final reap. All3 outer/nested groups were closed, with zero unknown. The child then reported PermissionError errno1 in owned_write_sidecar_loopback_refusals. It did not record a source line or a completed four-check report, so this is not full probe qualification.

The first expression in kernel_refusals is guard.read(main,4096). HeldT5.read enters HeldT5.parent; its first component under /Volumes/T5 is hepta-vnext-recovery-20261013. The existing parent implementation opens each component O_RDONLY|O_DIRECTORY|O_NOFOLLOW at source line136 after validating directory type/owner/device/mode.

The original capture_profile explicitly permits /Volumes/T5 and ROOT but omits ROOT.parent, /Volumes/T5/hepta-vnext-recovery-20261013. Its other ancestor expansion applies to LIVE private paths, not the T5 owned root. Earlier public source reads opened full paths directly, and HeldT5 construction opened only /, /Volumes and /Volumes/T5. This source gap explains why the earlier gates could pass before the first held-parent read, but the old runtime report cannot prove a unique dynamic failing instruction.

## Explicit new permission

R2 adds one73-byte rule:

`(allow file-read* (literal "/Volumes/T5/hepta-vnext-recovery-20261013"))`

This is an actual added permission beyond the previously reviewed /dev/null rule. Both reports and typed admission say so. It applies only to the exact ancestor directory. It grants no descendant subpath, additional private-file literal, write or network rule. The fixed code does not list that directory; it performs the original held-parent directory open and preserves its named/FD/type/owner/device/mode checks.

After normalizing only the new fresh-root binding, removing this one line from the R2 patched profile yields the R1 patched profile byte-for-byte. The new root is native-proc-sandbox-probe-r2. The old root is not reused. The original capture_profile function, all four kernel refusal bodies and the three native modules remain exact bytes.

## Bounded failure diagnostics

safe_error now publishes at most16 source-label/line pairs for the fixed pinned probe, HeldT5, original outer helpers and three native helpers. Unknown filenames, function locals, exception messages and child stderr are not copied. Omitted frames are counted within the bound; a separate boolean reports further truncation. This reads only an existing exception traceback and adds no filesystem/process/network operation.

The typed child gate requires the new permission flag, exact literal directory and exact rule SHA. All old success conditions remain: actual complete authority, known child exits, every FD/group/stream closure, actual native self/ABI/library observations, all four kernel refusals and the original final45-second gate.

## Source verification and retained verifier failure

The complete new probe was AST parsed and compiled without executing its module. Three native module payloads are exact. Seventeen definitions including the class and four-refusal function remain exact; only safe_error, profiles, typed_child and main differ. Original45/4/30/60 and all read/result/cleanup bounds remain.

The first local verifier failed because ast.literal_eval cannot evaluate the unchanged arithmetic expression8*1024*1024. That script and its original executor output are retained. The corrected verifier compares the bound AST directly; it does not alter the candidate. It then passed exact profile comparison and three selected fake traceback cases. It only read public local source and wrote the two local policy artifacts; it did not run a candidate main, Darwin API, host job, process or network call. The existing27 native components were not rerun.

Only a separate exact GO can submit dispatch/request.public.json once. Success would qualify this public probe scope, not current credential capture or a five-agent service run. Those require a new reviewed candidate bound to actual complete df026 normal artifacts and the actual public probe terminal.
