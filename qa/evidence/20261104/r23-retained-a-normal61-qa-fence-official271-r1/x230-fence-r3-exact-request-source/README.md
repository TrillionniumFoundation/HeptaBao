# Shared-parent fence R3: exact request proposal

SOURCE ONLY. This package has not submitted a host call and does not authorize one.

The complete inline carrier is candidate/x230_original_relay_effect_fence_r3.py, exactly the candidate in source tree 1789e362da46e998d3c7a7ba6eaf1e654628d828. The proposed process_start JSON embeds its whole UTF-8 text and SHA256. There is no separate transport, wrapper, dynamic source read or stdin payload.

Relative to original request fb197792ced7efbd7c60da559514b9209e1affd4, only args[4] (whole corrected source), args[5] (its SHA256) and idempotency_key change. Removing these three replacements reconstructs every original byte and field order. The complete one-hunk JSON diff is retained; it is long because the complete escaped source occupies one JSON line.

Fixed host: desktop. Executable: /usr/bin/python3. Arguments: -I -S -B -c <exact source> <exact SHA256>. Cwd: /home/qian-qi/heptabao-ha-closure-20261103-r1. Source deadline: original 15 seconds; supervisor: original 60 seconds. All original caps and create-only mutation boundaries remain.

Proposed new fence key: heptabao-x230-original-relay-effect-fence-r3-4b4026a6.

This is a new fence candidate for independent root review. It is not a replay of either prior failed fence, and never launches the UNKNOWN original relay. Its only possible future mutations are the original exclusive reservation of the exact old relay root and create-only public tombstone. Any existing entry or competing mkdir failure remains rejection. Original relay job 1a1aa57458d-fc05-4156 remains UNKNOWN regardless of this proposal, its source review, or any future reservation result.

Before any actual call, root must issue an exact new GO, and a separate external execution intent must be completed. ACK loss is reconciled on the same job/key without submitting a new operation. This source packet is not that execution intent.
