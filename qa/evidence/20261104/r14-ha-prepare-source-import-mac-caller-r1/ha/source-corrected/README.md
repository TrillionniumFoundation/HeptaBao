# B R2 launcher entry correction — source only

This new immutable package corrects the root-detected top-level launcher identity assertion. The blocked draft tree `25525f6aa7ea8c6de5b09a82433053f6d90101d3` and root rejection `686a2da94c8c1a93fd7b1f17433e56f1bd49901f` remain unchanged.

The only launcher code edit is `launch_normal_r10_pocket_postrecovery_cold_r1.py` → `launch_normal_r10_pocket_postrecovery_cold_r2.py` in the actual `assert Path(__file__).resolve(strict=True) == CONTROL / ...` statement. The strict resolution and full control-directory equality remain. The other eight candidate sources, witness once/CAS0/delete logic, original higher-term function, strict same-leader branch, 28 evidence fences, original 98 checks, separate postcold 12 checks and all deadlines are unchanged.

The carrier, candidate pins, nine-file stdin and proposed dispatch only receive the corresponding whole-file digest and provenance updates. Proposed keys are newly bound to launcher SHA prefix `515bc76f`; no dispatch in this or the blocked source packet has been submitted. All authorization fields remain false and the live prepared digest remains null.

## Actual offline checks

The new component executes only the actual extracted AST assertion with an explicit in-memory path adapter. It reproduces the blocked draft rejecting the real r2 dispatch path, accepts the corrected exact r2 path, and rejects the old basename, different control parent, different resolved destination and strict missing-path case. It also checks the nine actual payload bytes, all SHA/Git pins, both dispatch entry paths, unchanged eight files and exact carrier-only hash delta. All 22 recorded predicates passed with local Python 3.12.14; no complete QA module, network request, subprocess or host operation ran. The two entry-count records concern the old and new assertion separately. Filesystem resolution is a model adapter, not evidence about a remote filesystem.

The previous 130 component record is retained under its original tree and is not rewritten as though it had covered this missing entry check. Its tested witness and helper bodies are unchanged. The original failed B runtime remains 83/98 observed and postcold 0/12; this source edit does not alter that evidence.

Four exact unified diffs and old/new complete binding files allow strict reconstruction. The unchanged original design/caller documentation and R1→R2 semantic diffs remain in the blocked tree; this packet supersedes only the launcher entry identity and its derived bindings. Runtime still requires root review, create-only inert staging, exact prepare terminal and a separate explicit live window.
