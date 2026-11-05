# QA R3 Cargo artifact retention — source draft

The failed R2 run remains failed. Its complete Cargo command succeeded, then the
generic single-link reader rejected the declared executable. A later native
file-info observation showed a regular mode-0700 file with two links. The fixed
alias observer has since actually returned exit 0 with both names/full9/whole
hashes equal and all 9 FDs plus the iterator closed; its full packet is linked
in PLAN. This does not change the failed R2 result or qualify a new build.

This draft adds a reader only for the Cargo-declared normal QA executable at the
exact bound target/release path. It requires a complete two-name, same-full9
hardlink set under the held target/release/deps directory, reads and hashes both
aliases with bounded byte accounting, and returns verified bytes. The existing
create-only retained write, chmod, and generic single-link readback then apply.
The generic reader, original owner/CLI references, command lifecycle and test
executable path are unchanged. A future unexpected test-artifact link count
remains a refusal; this draft does not invent its metadata.

The new reader temporarily owns SIGTERM/SIGINT only while synchronous file
observation is in progress. It records registration/close uncertainty, attempts
each close once, restores the original owner handlers after cleanup, and sets
the builder's existing global FD failure flag if closure cannot be proved.

All original 600/180/180/30/15/20/5+5 budgets and the separate 660-second outer
supervisor remain. The binary's actual size/SHA/inode are captured anew after
the new Cargo command, not copied from R2. Both alias bodies have the original
per-artifact 128 MiB bound; the new explicit combined read allowance is twice
the captured size plus two one-byte EOF probes, within the unchanged total
time budget. Only one body's bytes are retained in memory.

Eight selected-method fake-OS cases exercise positive alias capture, excess
aliases, full9 drift, wrong link count, unexpected tail, cancellation, once-close
failure, and unexpected cleanup failure. No main/Cargo/product/target access or
real signal delivery occurred. These checks do not prove actual Cargo aliases or
the six Rust components. Whole inverse source checks prove every previous byte
outside the added reader, normal-read callsite, fresh roots and schema remains.

The future binding now resolves the existing exact inputs and new r3 paths. The
inert carrier and dispatch are proposals for root review, not authorization to
execute. Root has independently accepted the complete actual alias packet. This full
source and each exact new inert/Cargo step still require separate root approval. Canonical df026 and failed R2 roots are not
modified.
