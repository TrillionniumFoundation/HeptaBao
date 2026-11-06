# Independent SOURCE peer — public home-to-T5 probe R3

## Decision and exact scope

No remaining SOURCE blocker was found in the three specifically identified descriptor-lifetime corrections or their final carrier binding. This is a finite source review, not execution approval, a fault-injection result, or a claim that any host descriptor has been opened or closed.

The final packet is c680477cae4fc6dd01077b01de6c349e9fea3055: all 31 leaves / 613,156 bytes and its Merkle root were independently checked. The independent verifier completed 150 checks. The earlier R1 source38 and peer120 are preserved, as is never-submitted R2. I did not execute the author's R1 73, R2 58, R3 36, any Python module, any component, any signal, or any Runtime operation.

## Final carried identities

| Role | Whole Git blob | Bytes | SHA-256 |
| --- | --- | ---: | --- |
| FixedIO R3 | f1c2ecbe3857e8144f48225adbd12b199284f0ec | 15107 | 0f25ec43e70cba94783d3a3171b265f5b0eb809c46346e727793b2829c4bfb43 |
| Parent core R3 | 8ee0b29ea750d1b752b8ab26e27914a377dc61dd | 31586 | 473fbf2898fe10a0b8ffc199807639000a7d0f2b2e4569eb9d367d01a692716e |
| Full controller | bf69252fe9a2431ccf09740d5e5bed7eb6231248 | 168464 | 8cfa410c8fbe2234191b84b70d5d8b04f9aba01e7f4b5ae2c0d76ecfcd3865cb |
| Managed child | 2649636d559f401a5068de2b92ed3bf7d6db7d72 | 36358 | d96a769dbfc630237d6481e698704fdcc9fb0a315ae5f9e6c33ab5b976401873 |
| Proposed request | 62be5766699e67a41ab9d6072db8aa8e35c8abbb | 170588 | af2247dd1a780773aa754f90db1c6a1aa8f6d1965eb1792036177916d347ee17 |
| Journal | 4d5e2545cf1bed8f1951103a543529545026a374 | 19039 | d049e8818317d1a1a319de940bcce360c9a31d9a1ae341b3fa943adef08863ae |

## Three resolved source findings

1. **Returned-FD registration failure.** Acquisition increments attempts and pending before the one os.open expression, inside the existing critical section. The OSError handler covers that expression only and records a known no-return error. Row creation, append, registered count, and pending decrement are a separate protected transfer. A registration exception leaves pending and/or registrationUnknown; it does not guess a descriptor, retry, or blind-close. Public allClosed additionally requires balanced attempts, registered = row count, pending = 0, and unknown = false. The exact child-terminal parser requires the same ledger before accepting a known observation. The original 64 bound also bounds open attempts.

2. **Cancellation between closes.** FixedIO.close now protects the complete reverse iteration. The original close_one body is byte-identical: each recorded FD is attempted once and any close error remains recorded. Pending cancellation therefore cannot interrupt between two rows while the new outer critical section is active. The original signal restoration and final pending checks remain; this review does not claim an executed signal test.

3. **Incomplete HeldT5 construction.** The parent arms guard_init_started before __new__, and sets guard_init_complete only after __init__ returns normally. Both final volume_closed and volume qualification require completed construction once started. Thus an incomplete constructor cannot turn an empty or partial registered-row list into allReturnedControllerFdsClosed=true; volume_closed=false enters outcomeUnknown. Both flags are public. A failure before an actual FD is returned may conservatively remain unknown. The original HeldT5 helper is unchanged, and any registered partial rows still follow its original one-attempt close path. This is conservative accounting, not a claim to recover an unregistered descriptor.

## Exact integration checks

R1-to-R2 common/parent 3 + 2 hunks and R2-to-R3 common/parent 1 + 3 hunks reconstructed both directions exactly. Direct R1-to-R3 common/parent diffs are 3 + 5 hunks; adjacent close/public changes merge into one common hunk. The journal's two hunks only rebind its slot, request pin, and derived observer-key prefix.

The full R3 controller was reconstructed from the whole R2 controller by replacing only the reviewed common and parent cores and the three child-derived literals. The full child was reconstructed by replacing only its common source; child_main remained byte-identical to original R1. The original embedded HeldT5, Commands, ProcessReader, Signals dependencies and public anchor bytes remain exact. Request stdin is the complete controller. All typed request fields except stdin and the successor key match the original request, including mac, regular Python, -I/-S/-B/-, /Users/qianqi, and outer 60.

The shared 45 seconds, child 25-second window, command admission at 35, original direct-helper term/wait/group/ps caps, fixed paths, handshake/identity rules, and old UNKNOWN semantics remain. Non-child launchd processes still are not reaped or numerically signalled. A known diagnostic observation remains distinct from successful T5 access or full AuthBus qualification. Root's separate exact GO remains necessary.

## Verifier correction retained

The first independent checker incorrectly expected four hunks in the direct R1-to-R3 common diff. Strict forward/reverse reconstruction had already succeeded; the actual diff contains three because close/public contexts coalesce. That failed verifier and its error are retained. The successor changes only that expected hunk-count literal from four to three. No candidate bytes, source predicates, request, or execution scope changed.

## Limits

This review adds no Python compilation, fault injection, host observation, process qualification, credential access, product action, or launch permission. The previous private capsule, old launchd label, and prior unknown operations remain outside this new public probe.
