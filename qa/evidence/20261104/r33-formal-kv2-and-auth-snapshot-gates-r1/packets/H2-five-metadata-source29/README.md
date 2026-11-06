# H2 instrument incoming: five fixed metadata proposals

SOURCE only. No Runtime calls, new observations, or authorization are represented by this packet.

The five requests observe only the existing desktop incoming roles 7–11. Each asks the native file_info operation for full-file hash, version and metadata; none reads a returned body, enumerates directories, starts a process or publishes the H2 stage. The expected receiver pins are historical constraints, not a claim that these five independent observations have already happened. All H2 target identities remain unobserved.

The seven accepted independent observations remain separate from these five proposals. The old direct file_info calls for roles 6 and 7 timed out without an operation ID or idempotency key. The separate index6 operation_start lost its ACK; its same-key reconciliation returned reused=false and a new returned observer later closed. Neither event proves the older unknown observations closed. All those original requests/errors/ACKs are preserved unchanged.

The exact old index6 request and the role table supply the key family and typed request shape. The earlier unsubmitted serialized proposals for indices7–11 were not recovered. This packet therefore states the new exact source proposals explicitly; it does not claim byte identity with an unseen prior plan or rebind any historical UNKNOWN key.

After separate root authorization, use one native future at a time, preserve each original SDK before isError/parse, close the same returned operation ID and obtain its complete immutable payload before proceeding. Compare full metadata, hash and version to the frozen receiver. Any error or mismatch stops new admissions. No automatic retries, key changes, fallback reads or process actions are authorized here.
