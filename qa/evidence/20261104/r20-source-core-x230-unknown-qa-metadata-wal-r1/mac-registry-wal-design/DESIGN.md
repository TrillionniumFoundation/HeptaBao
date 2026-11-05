# Mac registry readonly-WAL observation — design R1

Status: SOURCE DESIGN ONLY. No implementation, host dispatch, private read, SQL execution, service action or retry is authorized by this document. The completed metadata observation and old failed capture remain separate.

## 1. Decision and exact scope

Add one explicit, versioned named-WAL reader for the single fixed registry database:
`/Users/qianqi/.openclaw/state/openclaw.sqlite`.
Use the existing fixed registry key `installed-plugin-index` and its actual, validated 13-column schema. Keep the five agent databases on the existing zero-WAL/held-main path. A nonempty WAL on any of those five remains a refusal; the new route is not selected dynamically after an immutable query fails.

The proposed named URI is exactly the percent-encoded fixed canonical registry name plus:
`?mode=ro&cache=private&vfs=unix-posix&readonly_shm=1`.
It has no `immutable`, `nolock`, read/write mode, named-to-FD fallback, second VFS, alternate path, application retry, checkpoint, recovery command, journal conversion or service stop. Missing `unix-posix` or an unsupported installed runtime refuses admission. The public synthetic route uses only a distinct owned fixture path with the same query parameters.

This is a new acceptance contract for the registry, not a deletion of the old maximum-zero WAL check. The old database() and immutable_query() bodies remain frozen references. A new registry_wal_database()/readonly_wal_query() pair owns the new path. Private capture cannot use it until the exact new source, installed-runtime synthetic proof, caller and sandbox have all been reviewed and bound.

The two existing auth SELECTs remain fixed to primary keys; no nonprimary auth rows are collected. The registry SELECT preserves its actual 13 named columns and LIMIT 2, with exactly one row required. No whole database copy or hash, backup API, full data-table scan, or export of WAL/SHM bytes is allowed.

## 2. Actual evidence and what it does not establish

The finite metadata run was job `1a1aa3a3d6c-fc05-3f7d`, authority exit 0, full/durable, 0.0027581253089010715 seconds. Its complete packet is `d851530bf16d6bde7ef4c8c0246009b2d46428ad`; root review is `49a0bfa8265d634b393670a908e26116df438a52`. All 46 leaves, 22 parents, 354 actual metadata observations and 46 once-closed descriptors were independently checked.

The registry main was 202,899,456 bytes, WAL 5,969,912 bytes, SHM 32,768 bytes; journal was absent. Those are one bounded observation, not permanently frozen current state. The main database has no original maximum; neither its size nor the approximately 2.47 GB main-agent database authorizes full copying. Only registry WAL violated the old zero maximum in that observation.

The earlier capture job `1a1aa2ac597-fc05-3e8f` is permanently exit 1 / current_input_size_bound / observation UNKNOWN. Its exact triggering leaf was not recorded. The later WAL observation does not identify that old leaf retrospectively, and does not fill the old library failure-path ledger gap.

The old successful seven-case synthetic proof recorded Python 3.14.3 and SQLite 3.53.4. It qualified immutable handling only. Its stdout blob is `781d085d4fdc52ada91ea796572099137c87cd55` (16,228 bytes / SHA256 `6c14a7f95e4f059090da2e88a3fff80eac79c1d83ef58a29df3cc67a610cd8f5`). It is a runtime identity source, not readonly-WAL behavior evidence.

## 3. Reference source and installed-runtime gate

Reference: official SQLite mirror tag version-3.53.4, commit
`b09c88c14082339b66c7b7158d609a771e64ca69`, Fossil manifest UUID
`bf7c7f30031888f4e796e429ab3978879485813aaca6f641c7b33e4e09459bcc`.
The package contains full os_unix.c, wal.c, walro.test, walro2.test, VERSION and manifest.uuid, with individual SHA256/Git hashes and exact URLs in reference-index.public.json.

The installed Python and _sqlite3 pins proposed for the public proof are exactly the previously observed ones:

| Object | Exact path | Bytes | SHA256 |
| --- | --- | ---: | --- |
| Python | /opt/homebrew/Cellar/python@3.14/3.14.3_1/Frameworks/Python.framework/Versions/3.14/bin/python3.14 | 34640 | cebfcc4ac431ff7a2179bc6eff7e5c6bdae48b564eeab2d504bef6173a2cfc13 |
| _sqlite3 | /opt/homebrew/Cellar/python@3.14/3.14.3_1/Frameworks/Python.framework/Versions/3.14/lib/python3.14/lib-dynload/_sqlite3.cpython-314-darwin.so | 165632 | 8b751990131722185775f5d532c89d4588285c88b23112d2758a4594721aa3ac |

At actual synthetic admission these public files need stable held reads/whole hashes and full identities before and after, the original Python version string, SQLite 3.53.4, and an actual sqlite_source_id() whose source UUID matches the reviewed reference. An unexpected source ID stops the proof instead of treating the tag as installed source. Record the actual source ID and relevant fixed compile-option booleans; do not publish arbitrary environment values. This is not a full dylib/dependency closure.

The exact named URI must work under the actual reader sandbox and actual runtime. Unknown SQLite URI parameters can be silently ignored, so source ID/version and a successful connection are not sufficient evidence by themselves. The finite behavior cases below are required. An absent VFS or incompatible read-only SHM behavior fails; no fallback is attempted.

## 4. Read-only means denied writes, not zero write attempts

Reference os_unix.c directly opens existing SHM O_RDONLY|O_NOFOLLOW and maps PROT_READ when readonly_shm=1. It still takes read locks. Missing/unreliable SHM or unavailable read marks may refuse or require a read-only heap WAL-index reconstruction.

Reference wal.c initially requests WAL READWRITE|CREATE. The Unix VFS can then downgrade to O_RDONLY after that request is denied. Therefore the report must not say that mode=ro/readonly_shm caused no write-capable open attempt. The safety contract is that the reader sandbox denies every write to the main database, existing WAL/SHM, absent sidecars and their parent; only the fresh public output directory and /dev/null retain the original write exceptions.

No permission is added for database writes, SHM writes, mmap writes, checkpointing, file creation under the input parent or networking. The only future private read paths are the same fixed files already listed by capture_profile(). The new synthetic policy maps those paths to owned files and grants no current private input access. Every policy change/mapping must be a complete reviewed diff.

An actual WAL-only sentinel proves that the SQLite query read committed content not present in the checkpointed main file. An additional negative reader with only SHM read access removed verifies the engine's SHM dependency under the installed runtime. That control is labelled separately from the guarded production-query path. Existing-file write-open refusals and the original four kernel refusals are recorded with fixed operation labels and numeric errno only. No statement will infer the absence of attempted writes from unchanged hashes alone.

## 5. Named-path custody and interval fences

Before SQLite receives the name, hold each canonical parent with O_DIRECTORY|O_NOFOLLOW and each main/WAL/SHM file with O_RDONLY|O_NOFOLLOW, using the held parent descriptor. Require regular files, UID 501, GID 20, mode 0600, nlink 1, stable full nine-field identities and fixed canonical names. Journal must be absent with two ENOENT observations and stable held/named parents.

For the first new registry-only route, propose an explicit WAL admission ceiling of **5,969,912 bytes**, the actual observed size, with a minimum valid-header size of 32 bytes. This is a NEW bounded eligibility rule requiring root acceptance, not an increase to the original max=0 path or the row/aggregate budgets. No larger automatic ceiling is proposed. WAL growth beyond it refuses before SQL. Main retains its original minimum 512 and no maximum; SHM retains the existing 8 MiB maximum and additionally must be present and nonempty. The program does not read the whole WAL into a Python buffer.

Use full nine-field parent and leaf observations across this one registry query interval: immediately before connect, after opening/establishing the read transaction, before and after the fixed row read, after ROLLBACK/connection close, and at final library verification. All held-versus-named comparisons must agree; any main, WAL, SHM or parent drift refuses the whole observation and discards private results. Never refresh the baseline mid-query.

Do not close a held descriptor for the same main/WAL/SHM inode while its SQLite connection is open: closing an unrelated descriptor for the inode can affect process-wide POSIX locks. Connection close precedes those held descriptor closes; its failure cannot be hidden by continuing the normal path.

SQLite opens the canonical name independently of the held descriptors. Before/after checks do not make that reopening atomic or defeat every possible ABA replacement. Reports must retain this sequential-observation limitation. The SQLite read transaction provides the engine's per-database read semantics, conditional on those named-path checks; it is not a simultaneous snapshot of six databases, an archive, a backup, or proof against an adversarial same-UID actor.

## 6. Fixed SQL, caps and deadlines

Preserve:
- returned row cap 1,048,576 bytes;
- total explicit small-file and returned-row accounting 8,388,608 bytes;
- each query's original absolute 3 seconds;
- the capture's original absolute 45 seconds;
- fixed two auth primary keys / one registry key / 13 registry columns;
- original outer current 900, phase 120, manager 600, native 15/8/3 and supervisor 1080, if a later current candidate is separately approved.

The 8 MiB counter has always measured explicit small-file reads and serialized returned data; it is not a meter for SQLite page I/O. This fact remains explicit. SQLite can inspect/rebuild a WAL index internally. No whole private database/WAL hashing or Python copy is introduced to work around the accounting.

For the new named connection: uri=True, timeout=0, isolation_level=None, extension loading disabled, existing SQLite length/SQL limits, query_only=ON checked, temp_store=MEMORY, BEGIN, fixed callback, ROLLBACK, once close. Use a strict authorizer for the finite table/columns and transaction operations; deny writes, ATTACH, arbitrary functions, schema changes and other pragmas. Runtime identity uses a separate owned/in-memory connection before private query admission and is also in the ledger.

Before each data SELECT, EXPLAIN QUERY PLAN on the exact statement/arguments must show the expected fixed-key SEARCH and no data-table SCAN. Bound the plan rows/bytes, include them in the same 8 MiB accounting, and do not run the SELECT if this condition fails. Schema discovery remains the one named schema row and bounded table_info; no unbounded enumeration of data or indexes. The 13-column cardinality and fixed WHERE/LIMIT remain unchanged. The implementation must define the exact accepted plan grammar against the installed 3.53.4 behavior and reject other forms, not rewrite SQL or create an index.

The same until=min(capture_until, query_started+3) spans connect, schema/plan/key read, ROLLBACK, connection close, that query's closure ledger and final deadline check. Progress callbacks and before/after checks retain the original deadline. A single completion-time sample after closure determines success; it cannot acquire a new budget.

SQLite's internal WAL retries and synchronous filesystem calls are not independently hard-preemptible by timeout=0 or the VM progress handler. A late return is always failure and never publishes or continues business. No new thread, kill wrapper, application retry or extra query budget is introduced. The existing outer global retirement remains responsible for its owned process. The public synthetic's own absolute 45 seconds covers setup, all cases, cleanup and publication; its supervisor is 60 seconds.

## 7. Failure receipt and actual closure

Fix the original gap in the new library generation: construct a public attempt envelope on both success and failure, after the final explicit cleanup, rather than allowing an exception to bypass FixedInputs.public().

The envelope has fixed schema, phase and error-code enums; exact source/runtime bindings; query deadline/completion facts; and separate ledgers for:
1. every held OS descriptor, including acquisition/registration, close-attempt consumed before close, close result and fixed error type;
2. every SQLite connect attempt, whether a handle returned, every returned connection handle, close attempted once and observed return/exception;
3. any explicit cursor handles used by the new finite query;
4. final named/held verification, original deadline and public-receipt construction.

Keep strong references until the attempt concludes. No explicit close retry follows an uncertain close. On SQL/query/fence/cancellation failure, close all acquired resources once and preserve the first failure plus cleanup failures. Any failed close, unreturned/unavailable ledger or unconfirmed connection result means observation UNKNOWN, ok=false, privateResult=null. Known refusal with confirmed closure remains a failed observation, not a retry opportunity. The private entry retains conservative observationUnknown=true for an incomplete capture. A public synthetic case may separately qualify that an expected refusal and its cleanup occurred; that does not turn the refused library observation into success. Unexpected or unconfirmed cleanup stops the synthetic run.

A failed connect without a returned Python handle is recorded as such. The library cannot enumerate or prove all internal SQLite descriptors from that fact alone; do not call it an individually observed internal-FD close. The parent requires authoritative child retirement as well. The public envelope distinguishes held-descriptor closure from returned connection-handle closure and internal engine resources.

Entry must receive/validate this envelope even when the library raises/refuses, set captureLibraryReturned/failureLedgerAvailable truthfully, and include it in final public stdout. The outer acceptance gate remains the conjunction of exact public result, exact raw stdout, authoritative exit 0/full/durable, original deadline, native identity, all child/stream/FD closure and unchanged current-input fences. No early result file alone can grant success. The old UNKNOWN attempt's ledger is never filled in retroactively.

## 8. Finite owned synthetic proof

Proposed fresh root:
`/Volumes/T5/hepta-vnext-recovery-20261013/mac-current-registry-readonly-wal-synthetic-r1`.
It must be absent at admission. Nothing under old captures/before, old synthetic roots or live .openclaw is changed or used as data input. All fixture rows are fixed public synthetic values. No current credential/config/database/cache content is read.

The actual writer and sandbox reader must be different processes. The parent may own the fixture writer connection; the reader is a fresh retained direct child for each case. This follows the reference test's explicit exclusion of same-process multi-connection qualification, which could otherwise reuse writable shared-memory state.

For each positive/concurrency fixture, the owned writer:
- creates a fixed 13-column registry with a primary-key index;
- establishes a checkpointed baseline on its own newly created file;
- disables automatic checkpointing in that owned fixture only;
- commits a known different sentinel to the WAL and keeps its connection open;
- supplies only fixed public synchronization events, not private row data.

The reader uses the exact candidate library query and same installed Python/_sqlite3, the reviewed native WNOWAIT custody and fixed sandbox. For drift cases, two bounded anonymous pipes coordinate one fixed mutation after the real query read and before final query verification; no sleeps, random timing, network, dynamic path or command input. The reader keeps one original query deadline. Parent and reader each close/register their pipe ends once. The private caller contains no such mutation hook.

Exact proposed denominator: ten cases, not the previous seven immutable cases and not a rerun of the failed current capture.

| ID | Fixture/operation | Required result |
| --- | --- | --- |
| W01 | Existing main+WAL+SHM, WAL-only committed sentinel, exact fixed query | Exact sentinel, fixed-key SEARCH, 1 MiB/8 MiB/3s intact; main/WAL/SHM/full-parent fences and owned whole hashes unchanged; actual six kernel checks (original four plus existing WAL/SHM write opens) denied |
| W02 | Required SHM absent | Refusal before the named connection attempt; no sidecar created, full returned failure ledger |
| W03 | Separate public engine control, same URI, profile adds only SHM read denial | Connection/query cannot produce the row, fixed SQLite error/phase; actual failed engine dependency distinguished from a guard refusal; no retry or access grant |
| W04 | Journal exists | Refusal before SQL; full failure ledger; no cleanup deletes the fixture to make it pass |
| W05 | Writer commits a second public value while reader interval is open | SQLite may return its own transaction's prior value, but whole observation must refuse on real WAL/SHM/parent drift; no private result |
| W06 | Owned writer changes main metadata during the guarded interval | Full-nine-field main drift refuses; no corrupt private database is involved |
| W07 | Owned writer changes SHM metadata during the guarded interval | Full-nine-field SHM drift refuses |
| W08 | Owned writer adds one fixed sibling entry to the input parent during the interval | Full-nine-field parent drift refuses, even if dev/ino/uid/gid/mode remain equal |
| W09 | Same 13 columns and fixed key, but no usable key index | EXPLAIN reports SCAN and the data SELECT is never dispatched; no full-table scan is used to obtain a result |
| W10 | Fixed indexed registry row exceeds the original 1 MiB return cap | Refusal with returned connection/descriptor closure ledger; no cap increase |

W03's extra rule is strictly subtractive and public-only. It is not part of future production policy. The production-policy mapping, original four kernel body preservation and two new existing-sidecar denial operations will be shown as exact diffs.

Only four selected pure components are proposed for the new failure envelope: connect fails without handle, close exception consumes its once marker, a late completion fails, and one changed identity field cannot compare equal. They do not simulate successful SQLite/WAL runtime or replace the ten actual cases. Existing 7/13/27 component suites are not replayed.

No actual test is currently dispatched. Final source must fix exact case ordering, object/FD counts, source pins, public byte caps, retained-child cleanup and single idempotency key before root review. Any case unknown stops remaining cases; expected known refusals are part of this one finite synthetic run, not business retries.

## 9. Minimal source delta and acceptance sequence

Only the following production-facing pieces need a new candidate:
- capture library: explicit registry-WAL admission/query, key-search precondition and failure envelope;
- capture entry: import/bind new library and consume the typed failure envelope;
- outer: bind exact new source/proof/schema and keep every existing business parameter, current path guard, native/public qualification and cleanup budget;
- candidate/source manifests and create-only carrier pins derived from those complete sources.

No other native/custody/phase/model/raw-CAS/cache-CAS/launchd implementation changes are proposed. The old 21 sources and failed run remain unchanged. New files/root/key receive new identities.

Sequence:
1. Review this design, specifically the new fixed registry WAL ceiling and installed VFS/readonly_shm qualification.
2. Freeze the minimal implementation, complete synthetic controller/policy/fixtures, exact create-only inert and synthetic requests. Both ready flags are false until exact source/payload/request hashes exist.
3. Root may authorize only the owned public inert and, after actual closure, one owned synthetic run.
4. Preserve every original ACK/status/raw stdout/stderr/child receipt and verify authority+byte/identity/closure/deadline; root independently reviews the proof.
5. Only then bind a new complete current candidate and request a separate one-time private capture/consumer window. A public synthetic PASS is not that authorization.

## 10. Explicit limits

This design qualifies neither production cutover nor service-manager migration, provider refresh, J3160, all clients, all databases, backup/restore, or cross-agent atomicity. It cannot retrospectively identify the old failed capture leaf. It cannot infer no attempted write from mode=ro, or zero internal SQLite page I/O from the 8 MiB returned-data counter. Missing/unsupported SHM, VFS, source ID, key index, stable parents, exact runtime proof or complete failure ledger is a refusal, not a reason to relax policy.
