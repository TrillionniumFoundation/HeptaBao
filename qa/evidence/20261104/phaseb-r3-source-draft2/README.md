# Official OpenBao 2.7.1 CLI / real native archive — NEW Phase B R3

## Status and identity

This is a new implementation, not a byte reconstruction of the unavailable R2
main, binding or evidence module. The former R2 main identity
50762 B / 493cde7c2cb72bd43db0bc150d8b701c98666f2e287531a9f149095385fabd87
and its source review are retained as historical facts; no R2 execution occurred
and no approval or test result is transferred to this R3 implementation.

This is draft 2 of NEW R3. The first complete draft tree remains unchanged at
871a3242c38f48484145fd48b72a16e49795ee94. Its source reviews and the precise
incremental reviews accompany this draft; they are not runtime results.

The five source files are frozen by this tree's manifest. Three modules are new.
Two exact references were recovered and whole-hash verified:

* native reference: 68149 B, SHA-256
  a0bac9972fbb9d65ed3edf537f732a08b5177864516b33ada0a6e98c4c6a0416;
  reconstructed only by applying the full published three-hunk R8 binding diff
  to the full published 68078 B R7 source, with every context and hunk count
  checked and the final original whole SHA equal.
* official CLI lifecycle reference: 46586 B, SHA-256
  18318841d3538e60fddf951708055a206402f5bf1ecdacc2bfceabec4f998dd9,
  fetched whole from the published validation blob.

All draft objects are unreferenced. This package creates no commit, branch,
service, process, provider request or production write. The local execution
environment is unavailable: Python parsing and the supplied synthetic component
script have NOT been executed by this draft publisher. Source review must be
followed by actual parsing/components, resolved binding, a fresh read-only
prepare receipt, and separate runtime authorization.

## Product and artifact admission

The only candidate allowed is canonical R10:

* commit 49503322c7f446e5eb41e7744f1fdbd7f1192ecc
* tree 1d4211f91e1b34a2ed087a3bbef2e2884bac88e9

R10 differs from R9 only in the NoForward test witness. The four real product
archive/audit files are read whole and checked against both Git blob and SHA-256.
No product implementation is modified by this package.

The unresolved template deliberately fails admission. It must be filled from
actual R10 artifacts and physical host observations, not from R9 or R8 hashes.
Admission requires the actual normal server, native build receipt, normal release
receipt, and the original 44-test combined terminal result. All six original
groups, exact group-file hash, source commit/tree, default feature set,
debug/overflow checks, native ABI, owned-process cleanup and complete passing
group results must agree. A successful release build alone is insufficient.

The official oracle is the exact Linux OpenBao 2.7.1 binary:
181760103 B, SHA-256
535cf827b13753046757f5ec8b97ae0ef21f10a40ffe673f0d5e75616170f5ea.
Its known source commit is a5db72cef75c24b920ade02065b18dd8eb666bac.

The concrete input binding is a whole-hash pinned external file. It pins the
five QA files, artifacts/receipts, actual Python/Git/OpenSSL executables, the
finite old evidence fence list, UID and physical machine ID hash. Executed
modules are compiled from the already-hashed source bytes. No pycache is written.
The complete source must be clean at the canonical commit/tree before and after.

## The five CLI windows

| Window | Actual command and target | Required independent evidence |
|---|---|---|
| B01 | Official CLI save, actual current leader, archive A | Normal native HA startup; complete official CLI process; all-node audit delta; actual file is one complete native gzip/tar archive with exact members and clear sums |
| B02 | Single CAS 2 write creates distinct version 3, then official CLI restore A to leader | Original archive A unchanged; terminal audit and CLI outcome; actual versions 1/2, entire KV2 metadata and version 3 absence on all nodes; permitted cold restart only after a known business terminal; exact data after cold |
| B03 | Independent official CLI save to actual leader, archive B | A new save command and new output file after B02; complete valid native envelope; never substitute B04's output |
| B04 | Official CLI save to an actual standby with default CLI behavior | No controller redirect or retry; preserve complete known business failure; archive/file outcome separately from exit code |
| B05 | Second distinct CAS 2 write creates version 3, then official CLI restore B to actual standby | Verified independent B archive; no controller replay; actual data and known server outcome; cold verification only after known terminal, with successful restore and known rejection reported separately |

The two version-3 mutations use different synthetic marker values. The inherited
seed has two distinct version values. API comparisons preserve the complete
version data/metadata projection and the whole metadata response data object;
request IDs and unrelated response envelopes are not compared as state.

B01 and B02 are mandatory positive controls. A failed leader positive control
stops later mutation windows. B04 may be a known complete business failure and
B05 can still observe the independent archive B. A successful CLI process is
never sufficient to classify restore success. A known rejected B05 may retain
the mutated version 3 and still receive a cold persistence regression, but the
restore qualification remains false.

All five cases are observation boundaries, not five guaranteed passes. The final
report distinguishes complete observations with compatibility failures from a
fully passed five-case contract. Both report full replacement qualification false.

## Real normal startup and reference reuse

Only the reference fixture's real setup and strict HTTP transport are reused.
The setup function keeps its original code, defaults, closure and other globals.
A scoped FunctionType copy replaces only its one stop_owned global with a router
for the exact new seed Popen and captured identity. That router calls the original
native stop function through the same explicit-stop ledger used by cold restart
and final collection. Neither reference file nor its module globals is changed.
The new fixture creates its own stopped V5 seed, cold-copies that new seed into
the other two new node roots, starts the normal binary with
storage.native_v6_raft, then calls sys/storage/native-v6/activate once.

No fixture feature flag, old node data, existing seal, or production credential
is used. Seed state is generated by normal init/unseal/KV2 API calls. The TLS CA,
three pinned member certificates and replication key are generated in the new
owned root. All addresses are loopback. API ports remain 48630/48632/48634 and
Raft ports are API + 1. Port checking is an availability observation, not a lease.

The new controller does not call either reference's old main, artifact stager,
old negative wire matrix, Phase A synthetic peer server, or synthetic archive.
Official CLI reference reuse is limited to exact child ownership, exec visibility,
bounded process captures and cleanup. The new owner bypasses Phase A construction
so that no Phase A token, archive or network peer is created.

## Deadlines and ownership

The original numeric limits are preserved:

| Boundary | Limit |
|---|---:|
| Official CLI command, including any internal redirect | 15 s absolute |
| Each controller HTTP exchange | 15 s, clamped to parent action |
| Each setup or B01–B05 action | 300 s absolute |
| Readiness | 45 s, requests clamped to action |
| Stable election | 60 s, requests clamped to action |
| Stable observed leader | 2.2 s |
| HA peer timeout | 1500 ms |
| HA forward timeout | 8000 ms |
| Explicit normal stop / final cleanup TERM then KILL wait | one 5 s / 5 s allocation per owned Popen |
| Inherited request/CLI deadline emergency SIGKILL wait | original separate 5 s |

No nested request creates a fresh business deadline after the original parent
deadline expires. Cold restart belongs to the existing restore action. Final
read-only input/audit checks have a separate bounded 300 s evidence envelope;
they cannot authorize any new upload, new product process or business mutation.

Popen is registered provisionally before a deferred Python signal can throw.
Actual executable, argv, PID, parent, PGID and start time are checked. The exact
existing empty-cmdline visibility rule only observes that same child inside its
original deadline; nonempty wrong argv is rejected. The original process is
never respawned to obtain a better observation. All reaped groups are observed,
not signaled by recycled numeric PGID. Cleanup continues across per-child errors
and an unconfirmed stop prevents a successful result.

The shared stop ledger is specifically for explicit seed/cold normal stops and
final cleanup collection. It reserves the original 5 s TERM / 5 s KILL allocation
before dispatch, retains the original outcome or exception, and prevents a later
collection from allocating that same normal stop budget again. A new child gets
its own first allocation. A failed strict seed/cold stop propagates and makes the
fixture unknown before any restart.

The exact reference request and CLI timeout handlers retain their original,
independent emergency SIGKILL followed by a 5 s wait. After that emergency stage,
final collection may use its one original 5+5 s normal cleanup allocation. This
package does not claim that every first signal globally forbids that inherited
separate stage. A timeout still means unknown and forbids new CLI commands,
mutations, uploads and cold restarts. The reference bytes and these two existing
budget stages are unchanged by R3.

All normal server configurations, member TLS inputs, replication files and
bootstrap material receive immutable file fences before CLI and cold actions.
Cold restart uses only the same fresh fixture data and unchanged configurations;
it never repeats activation or an archive upload.

## Unknown outcomes

A CLI intent is durable before the single process dispatch. Missing process
terminal, timeout, unexpected exit, surviving child group, malformed/missing
audit pair, historical delivery veto, unresolved server failure/conflict,
unknown transport error, changed archive input or unaccounted restore state
ends the experiment.

After an unknown outcome only read-only evidence capture and owned-process
cleanup are allowed. The controller cannot issue another upload, CAS write,
unseal, service start, or cold restart. It does not retry the old generation.

The audit window contains no other controller HTTP calls. It reads all three
actual audit files before and after the CLI command, checks same inode and
unchanged prefix, exact schema 2 nesting, u64 time/sequence, previous-MAC
continuity and request/response matching within each node. Pairing associates
the quiet window, not a decoded route. The observer does not authenticate audit
MACs, reverse HMAC fingerprints, or infer complete client HTTP framing.

A recognized complete CLI save business failure such as the known official
incomplete-snapshot result remains an observed failed save. Its server audit
terminal is distinct from proof that the CLI consumed a complete response body.
A historical restore 5xx, 202, conflict, delivery veto or unexplained state is
conservatively unknown even if the CLI exits zero.

## Archive contract and secrets

The evidence module validates one complete gzip member, no concatenation or
trailing compressed bytes, fixed canonical regular tar headers, member order
meta.json/state.bin/SHA256SUMS/SHA256SUMS.sealed, exact padding and 1024-byte
termination, native HA metadata and HBV6HA01 state magic, exact state length and
clear checksums. Its 16 MiB compressed / 32 MiB expanded bounds are scope limits
for this small synthetic archive fixture, not product storage limits.

Sealed checksums are only checked for bounded nonempty presence. The observer
cannot authenticate them or decrypt state. Actual product restore and post-cold
API state are the independent authority for the successful native restoration
claim. No OpenBao state.bin/seal-wrapper compatibility is claimed.

Raw stdout/stderr, HTTP bodies/heads, archives, bootstrap values, CA/member
private keys and replication key remain in new 0700 directories and 0600 files.
Public outputs contain fixed labels, process/file identities, hashes, counts and
booleans. Before public publication the final report and all public members are
scanned for captured actual fixture token/key literals plus raw, hex, base64,
JSON-escaped UTF-8 and sufficiently long PEM payload-line variants. This is a
finite actual-literal scan, not a claim of universal secret detection.

## Review and execution order

1. Review all new three modules and exact reference reuse; parse under Python
   without executing the target controller.
2. After source review, run the independently pinned offline stdin wrapper once.
   It compiles all seven verified Python sources, keeps both reference helpers
   and binding compile-only, and exercises only new controller/evidence methods
   with synthetic dependencies in memory. The audit guard denies file/process/
   network operations after stdlib preload. Its result is parser/component
   evidence, not actual native archive, process cleanup or runtime qualification.
3. Resolve and review the actual R10 binding and finite host/source/artifact
   transport. Keep the unresolved template as a non-executable planning artifact.
4. Create-only stage the files and run one fresh read-only prepare. It performs
   exact file/source/receipt checks and owns its few Git metadata processes; it
   starts no HeptaBao or official snapshot CLI command.
5. Root reviews the complete prepare receipt and authoritative terminal.
6. Only then run one fresh live root with the exact prepare-result SHA.
7. Preserve any failure/unknown root, public receipts and private recovery data.
   Do not change acceptance criteria or restart a failed generation.

No production cutover, hold-marker release, service installation, J3160 request,
provider refresh, backup deletion or old-asset cleanup is part of this fixture.
