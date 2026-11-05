# Retained df026 helper: narrow cancellation and closure checks

This immutable addendum keeps the rejected draft and the final candidate separate. It runs only four AST-selected definitions under fake Path, OS, clock and descriptor objects; it executes neither runner module nor any real filesystem, child, remote host, Rust, Cargo or product operation. Python sys.settrace injects the exact signal-handler call at the old unprotected transition and at the final candidate's protected close transition.

The old draft reproduces opened=1 / close-attempts=0 / failed. The new candidate preserves failure on cancellation while closing once. Thirteen checks include the old negative, new positive, open/read/mode/hash/named/held/deadline/close negatives, cancellation during open/read and the corrected transition. A close error remains failed with all_opened_descriptors_closed=false; it is never retried. Existing normal test helpers and budgets are unchanged. The complete same helper body is present in the Mac runner; the executed selected-function cases use the ROG candidate source identity.

This addendum does not authorize or qualify any host build. The core tree cd6ff4842444908d68226151d7b480244505bff4 remains byte-identical; its statement that components were pending describes the core's earlier freeze time.
