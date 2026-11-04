# NEW Phase B R3: original live-r1 failure

This packet preserves a single actual run. It does not qualify native archive save or restore, production cutover, or full OpenBao replacement.

- Candidate: 49503322c7f446e5eb41e7744f1fdbd7f1192ecc, tree 1d4211f91e1b34a2ed087a3bbef2e2884bac88e9.
- Job: 1a1a8177aec-fc05-2da5; stable key: heptabao-phaseb-r3-live-10816-20261104-r1.
- Authoritative terminal: exit 1; not timed out or cancelled; complete durable stdout/stderr.
- Controller: 61210 bytes / 10816d06fd5ad59175872ccb7db1337d7677e92405a26a7ab1cae2796ee0a86c.
- Concrete binding: 6366 bytes / 8e73ca7f0ed52056035ed82878b5f5c200e50013bfc36f1ad3dd647879043736.
- Prior prepare: 22852 bytes / 97b21460b67f2ef14f2edf8573a22f4ba7ac82c1a8d5a44e9d246675b5cb87ee.

## Actual result

Normal native setup completed. B01 leader save was the only CLI case attempted. The official CLI exited 2, no archive was created, and the single server audit pair had response status 503. The controller retained unknown_cli_or_server_boundary_no_replay. It did not execute B02 through B05, any restore, or a cold restart. Audit is not proof of response framing, route authentication, or an authenticated audit MAC.

The final input comparison separately recorded input_fence_changed_after_run. A lossless comparison of the original result's serialized before/after inputs finds every value identical. Frozen source shows that the prepared JSON turns integer port-map keys into strings, while the fresh Binding.verify result retains integer keys. The source-derived diagnosis is preserved separately; the original error and B01 unknown are not rewritten.

All 81 original cleanup rows report stopped=true, direct_child_reaped=true, empty remaining groups, and no cleanup errors. The desktop test window was released after this check. Unknown state, generated credentials and original files remain in the owned live root. Nothing was replayed or promoted to production.

## Exact owned paths

Root: /home/qian-qi/heptabao-ha-closure-20261103-r1/official271-native-cli-phaseb-r3-live-r1

- result.public.json: original full result, in this packet.
- cases/B01/intent.public.json and cases/B01/outcome.public.json: actual per-case source paths, embedded as objects in the full result; individual bytes not yet collected.
- private/0008-B01-official-cli.stderr: 178 bytes / bce4e0993df8aa57859efc05b509ad6ea36d8f2d0df9dd23d63ae3640e537df8; not read or included here.
- private/B01.snapshot: original outcome records absence.
- node1/audit.jsonl, node2/audit.jsonl, node3/audit.jsonl: source-defined owned audit paths; exact window observations embedded in the full result, raw files not downloaded.

## Packet boundaries

The complete 270785-byte result was read as five version-pinned chunks, independently hashed and reassembled, checked against the announced whole SHA, UTF-8 round-tripped, persisted as a Git blob and independently fetched back. Original tool JSON is preserved without parse-and-reserialize so large integers remain intact. The independent review is explicitly derived.

The controller's original public literal scan covered 144 public members against 9 actual fixture secret inputs and 129 captured encoding variants, with zero hits. It makes no universal-secret-detection claim. This packet does not contain private captures or all 144 individual public members.

Budgets remain the original per-stage 300 seconds, CLI/HTTP 15 seconds, ready/election 45/60 seconds, forward 8 seconds, and explicit/final cleanup 5+5 seconds. The NEW outer live envelope is 3000 seconds. The references' separate original deadline-kill wait of 5 seconds remains distinct from the one final cleanup budget.
