# Fresh public Node startup/import SOURCE

This proposal is not submitted. It introduces one new create-only T5 public scope, one original owned diskutil check, and one retained direct sandbox-exec → exact Node child. It does not run the cycle, SDK, CAS functions, database operations, credentials, provider calls, launchd, or any old PID operation.

## Why this is the next bounded observation

The current public consumer result records cycle exitCode = finalReturnCode = -6, a retained/reaped direct child, empty stdout/stderr, and worker_report_unavailable. These facts do not identify the native abort cause. The phase source launches sandbox-exec → Node with an explicit isolated environment and phase cwd. Its launchd WorkingDirectory is separately HOME, but the wrapper performs held fchdir and the child Popen uses the T5 phase path.

The exact cycle has static imports before report initialization and its try/finally. The rows CAS statically imports node:sqlite; both CAS modules contain only definitions/constant setup at module scope, with no database method invocation there. The new entry has no static imports and awaits a fixed public entry marker, then each before/import/after marker. This makes a fresh missing marker or import boundary observable without exposing exception text or changing sandbox permissions. Absence of the entry marker is not proof that no JS instruction executed.

## Preserved implementation

The original WNOWAIT/capture/once-cleanup contract is reused. The capture function changes only its two public output limits (4 KiB / 64 KiB), checked by the original capture-sink after termination. These are not kernel file-size limits. The original Commands, unreaped, and process-observer modules are exact whole bytes; the observer is imported for the unchanged capture function but not instantiated. HeldT5 changes only its fixed root literal. The parent retains explicit construction/operation pending flags so an incomplete helper registration cannot produce known closure. The five public input FDs reuse the reviewed pending/registrationUnknown/once-close code.

New root: /Volumes/T5/hepta-vnext-recovery-20261013/mac-authbus-public-node-startup-20261106-r1

Work / final closure / Native: 35 / 45 / 60 seconds. Node allocation: 10 seconds. The two cleanup paths each retain the original TERM1/wait5/group3 contract and every original identity check. No new owner framework or relaxed UID rule is introduced.

## Policy and context boundary

The consumer_profile function is copied byte-exact from 198feabe7aef20b302e5989fd72e99e0bc0d36c3. The new policy uses the same operation categories, public code subtrees, current-phase write scope, and old public localhost:63611 literal. No listener or connection is requested; that permission is not a port reservation or availability fact. Its three new-root credential literals point to files never created. The 40 public aliases contain one redundant .bin/codex literal inside the already allowed CODEX root. Omitted per-phase native config and copied-plugin literals are already covered by their unchanged subtree rules. This proves the limited semantic mapping; the old generated consumer.sb was not recovered and is not claimed byte-identical.

This diagnostic has a foreground parent. It does not claim to reproduce the original launchd parent, old cwd descriptor, old environment inheritance, or a historical crash. It cannot qualify AuthBus, current credentials, or the combined 02b binary.

## Public output and historical facts

Only the exact ordered marker sequence, its closed failure marker, byte counts, child custody/terminal facts, known input pins, and own closure are public. Unknown stdout/stderr text or hashes are not output. The old ps effective-UID/setuid compatibility issue is separate and unchanged. No original managed UNKNOWN or failed custody is upgraded.

All source-only mechanical checks are offline V8 comparisons. No Python/Node candidate, component, SDK, host probe, or new service has been executed.
