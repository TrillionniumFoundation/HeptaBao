# R4 original null-code failure: limited source diagnosis

Scope: already returned R4 public stdout and exact frozen source only. No Native call, process, file read on Mac, SDK execution, mutation, retry or replay was performed for this analysis.

The original job mac/1a1afc5dbd9-fc05-6b85 is exit 1 with full durable stdout 18,131 bytes and empty stderr. Its last stage is home_ready; observationComplete=false, executionSucceeded=false, outcomeUnknown=true. The new launchd registration and managed process closure remain unproved. Five direct helpers and 33 FixedIO plus three original T5 descriptors closed; those facts do not close the managed registration.

## Exact source defect in error visibility

Controller fb453c023c1de1299e1875078ae8720b20a441de line 33 defines PUBLIC_ERROR_CODES. The original buildProbe parts array gathers common, child body, parent body, original module sources and ProcessReader source, but not the independently inserted parse_print function. Consequently every one of parse_print's eleven literal need codes is absent from the public error-code set. error_projection at lines 59–68 changes any unlisted code to null. The underlying parser and guards still refuse; this defect hides which fixed refusal fired.

| Fixed refusal | Controller line | In original public set |
|---|---:|---|
| bounded_launchctl_print | 365 | false |
| exact_launchctl_target | 367 | false |
| plain_fixed_launchctl_argument | 376 | false |
| bounded_launchctl_arguments | 378 | false |
| one_launchctl_arguments_block | 381 | false |
| unique_launchctl_field | 386 | false |
| balanced_launchctl_print | 388 | false |
| one_complete_launchctl_record | 390 | false |
| complete_launchctl_arguments | 391 | false |
| typed_launchctl_integer | 397 | false |
| actual_launchctl_pid | 399 | false |

## Original sequence and limits of localization

bind_ready calls query at line 548 after ready marker/body checks and validate_process; identity is assigned only after query and the following PID/birth tests. query runs fixed launchctl print, requires known exit 0/empty stderr, calls parse_print at line 501, then checks the fixed registration and state before assigning last_state at line 507. cleanup_once starts its own query at line 639, before reaching any PID wait, birth checks or bootout. Both observed post-bootstrap prints returned known exit 0, empty stderr and 2,276 bytes with identical SHA-256 cf4058a9e244a5bc5e07d3434b25dadf5c70786b5a442609a0b8fdbb75681e71. Both surfaced ProbeRefused with null code and last_state stayed null. Surrounding query guard codes are present in the public set. These source facts localize the suppressed refusal family to parse_print, but do not identify its particular predicate or original field value. The bounded bytes predicate is satisfied by the original Commands byte-output contract and observed size; the remaining syntax/value checks still cannot be retrospectively evaluated from a hash.

The original raw 2,276-byte print body was not published or archived by this probe. No old print field is reconstructed. In particular there is no claim that the field was a never-exited sentinel, that EX_CONFIG recurred, or that current later output equals the old body.

## Minimal next SOURCE scope

A separate, fresh read-only diagnostic may bind only this new label and its actual public child source, plan and plist pins; read the already created ready/terminal public files under strict bounded schemas; and make bounded current print observations. It must include all eleven fixed parser refusal codes in its closed error projection and publish only fixed field presence/count/type predicates, exact expected-path/argv equality and explicitly admitted numeric/enum values. No environment values, arbitrary text or unknown-text hashes may leave the process. Current observations are separate from the historical print. No bootstrap, bootout, admission-file write, new root, T5 sentinel read, SDK, credential or old-label action is authorized by this document. Any current PID evidence requires the exact ready identity and original read-only custody protocol; future cleanup needs separate concrete authorization.

## Pure reader history

The first local pure source reader attempted JSON.parse on the Python frozenset(...) wrapper and raised SyntaxError. It performed no Native or candidate action. A corrected literal selector reads only the bracketed JSON list. An initial broad string-literal scan also listed the decode option 'strict'; the final eleven-code list uses the already frozen need/require-call extractor and excludes that non-refusal argument. Neither change modifies the candidate or its actual record.
