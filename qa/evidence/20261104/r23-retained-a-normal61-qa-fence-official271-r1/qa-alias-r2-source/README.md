# Fixed failed QA Cargo alias observer — R2 SOURCE

This successor fixes only resource accounting and returned-byte accounting in the
unexecuted R1 observer. It does not change the failed QA R2 build or retry Cargo.

`Signals`, `protected_call`, `public_errno` and the four FD/iterator ownership
methods are copied byte-for-byte from reviewed locator source b28c4b68. The main
function protects the entire resource lifetime before installing handlers, keeps
it protected through the one cleanup attempt, and responds to pending signals at
explicit checkpoints. Acquisition/registration uncertainty and uncertain close
results remain in the public ledger and prevent success. No uncertain descriptor
number or iterator receives a second close attempt.

The two bodies remain limited to 9,233,152 returned bytes. Two separate one-byte
EOF probes add at most 2 returned bytes, making the total observation bound
9,233,154. Successful EOF probes return zero bytes. Every returned byte, including
an unexpected tail byte, is counted before acceptance checks. The code checks the
remaining byte and time allowance before each read. The 15-second deadline is a
soft whole-operation deadline; it does not claim to interrupt a blocked kernel
filesystem call. The separate proposed outer supervisor remains 45 seconds.

The original eight component names and negative checks remain, with only ledger
field adaptations. Ten new selected-method synthetic cases cover cancellation,
registration uncertainty, once-close behavior, and body/EOF accounting. They do
not install real signal handlers, call main, access the actual target or establish
the actual hardlink alias set. Original R1 source, tests and results are retained.

The fixed target, metadata, 2-link census, held/named identities and both whole
hashes remain unchanged. The future artifact-specific retained-copy change is a
separate source and execution gate; this observer performs no write or execution.
