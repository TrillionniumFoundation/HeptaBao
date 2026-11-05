# Mac native process custody: new public probe, revision 1

This packet is SOURCE ONLY. No request in this packet has been submitted. The Mac normal build currently owns the host window; this probe requires root review and one explicit scheduling decision.

The immediate question is whether the existing patched capture sandbox permits a fixed Darwin numeric process API to establish the original retained-child custody contract. The previous system-ps comparison completed as a known failure: original /bin/ps Popen returned errno 1, while the identical owned copy started and exited -9. Those facts do not identify a unique setuid, signature or spawn cause. The earlier PID 11754 custody/exit unknown remains unchanged.

## Read order

1. CONTRACT.public.json fixes scope, deadlines, fresh path, proposed key, success gates and limitations.
2. source/mac_darwin_owned_projection_r1.py defines the fixed ABI, library observations and scoped numeric API.
3. diffs/custody.review.diff shows the replacement of process text projection only in a new isolated adapter. The old helper is retained in references/qa.
4. diffs/commands.review.diff is the sole import change to the unchanged command lifecycle.
5. source/native_proc_sandbox_probe_r1.py contains the complete parent/sandbox-child path, the embedded three modules and final original-deadline gate.
6. dispatch/request.public.json contains the exact loader and whole source stdin. Its presence is not execution authority.

## The complete planned path

The parent keeps the already reviewed ps-based custody. It verifies original public QA/tool bytes, holds the exact T5 anchors, obtains the same diskutil UUID, then checks that the new native-proc-sandbox-probe-r1 directory is absent twice. It creates only that new owned directory and public probe material. Nothing is written into an old capture or probe.

The one sandbox child first reads the pinned new modules, then qualifies its actual native ABI, system build, loaded symbol images and independent self PID/PPID/PGID/UID. Only after that gate does it bind the new projection and start one diskutil child. The same Commands class body still owns the Popen and invokes a once-only cleanup. WNOWAIT retains the child until the live group is empty; the first reap follows, and subsequent group observations never authorize a signal.

After real diskutil completion, the child repeats its self birth/group check, obtains the T5 UUID and performs the four original owned main-write, WAL-create, SHM-create and loopback-connect refusal checks. The parent accepts only typed exact child output, successful authoritative exits, complete cleanup, unchanged source/tool/file fences and the original shared 45-second completion gate. The external supervisor cap remains 60 seconds.

## Permission and ownership boundaries

The capture_profile, profiles and kernel_refusals functions are exact original bytes. The original profile is relocated to the new owned root in the same three positions; its existing patched version differs only by the already reviewed 41-byte /dev/null read literal. There is no additional policy permission, no no-sandbox fallback, no system-tool copy, no chmod of a system file and no code signing.

The probe does not open current databases, credentials, SDKs, consumers or providers. It does not replace the mainline QA helper, alter a service or contact J3160. It reads only its closed public source/tool inputs and newly owned probe material. The policy still contains the inherited capture read rules; this probe's fixed code does not use them to read private data.

## Evidence already obtained

The local selected-definition component run passed 27 cases: numeric ABI and refusal behavior plus six retained-custody branches. The selected candidate routines used no native library, Darwin API, real process/descriptor or network operation. The local harness itself read the public source files. The original result's real_descriptors=0 field has this selected-routine scope; it does not claim that reading the harness inputs required no filesystem descriptors. Four complete candidate sources were AST parsed and compiled without importing or running their modules. The source verifier also checked the exact embedded payloads, import-only Commands change, 16 unchanged functions and the sole 41-byte permission delta.

The component executor envelope is an exact capture of the displayed structured result, with its stdout preserved verbatim; it is not described as transport wire bytes. No tests were rerun to recover the envelope. The verifier envelope was retained directly. See verification/components.provenance.public.json.

## What remains unqualified

Apple main is bound to exact commits as reference ABI only. The installed Darwin behavior, fixed install-name loading and self identity checks must succeed inside the actual existing sandbox. dladdr names are observable identity, not whole-image or dependency hashes. A synchronous syscall can return after a deadline; the code rejects that result but has no extra killable worker.

The public probe plans natural completion of one diskutil child. Selected fake tests cover TERM/KILL branches but do not claim new physical signal-path qualification. Any incomplete child custody, nonempty group, unstable source, short native return, capped PID buffer, permission refusal or late result stops the chain. An unknown outcome is retained without replay.
