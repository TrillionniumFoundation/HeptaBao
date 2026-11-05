# Fresh Phase B launch source after the actual 3cb source import

This is the concrete source packet for the next isolated Phase B fixture. The local-stage process request is fully expanded in `requests/local-stage.request.json`. It has not been dispatched. The controller, input carrier, partial binding and five QA source files are byte-identical to their frozen versions in tree `38520c8c2fc5545bd608fefa29e37535a086e443`; this update supplies actual provenance and executable dispatch metadata, not new business logic.

## Actual inputs now available

| Input | Exact current evidence | Status and next check |
| --- | --- | --- |
| Canonical diagnostic source | Commit `3cb873919170cc77101b27f6a3ab9e98f41f8d93`, tree `7f4d48a647a81ca96e8a24a0a057c2c829459060`; source import core `147fa49bb3013691b9612d98fc362d0543554265`, root review `314c5a9d4941d3ffcffc154d5ea34ecd4fe08f9e` | Independent local source, full fsck / 3,755 commits / all 3,911 materialized blob bytes verified. Local stage checks fixed source files; readonly prepare independently checks clean HEAD/tree. |
| Normal server and original receipts | Incoming transfer tree `bd70028b078c7c009762e8aacd7cb184f2925235` | Server 109,074,848 B / `437723d2…`, native receipt 794 B / `51d0d839…`, release receipt 3,200 B / `6313b4ea…`. Local stage creates new copies after exact hash and FD identity checks. Full values are in the provenance file and partial binding. |
| Normal qualification | Build tree `cc9bf4ebfa811284520b76d93fba9759692b5637`, root review `cff97c2f0e3c845d64c7f1c28277ba4ff748c1c2` | Original 44 and separate 7 passed; exact original combined result and group bytes are in the carrier. This is not snapshot runtime qualification. |
| Five QA source files | Main 61,210 B / `10816d06…`, binder 23,664 B / `73736dbc…`, evidence 15,201 B, original native and CLI reference helpers | All five full sources are included unchanged. Binder retains the reviewed string-key observation correction, concrete 3cb source pins and original 44 plus separate 7 verification. |
| Official OpenBao 2.7.1 CLI and utilities | Existing fixed desktop paths and original expected CLI hash `535cf827…` | Not freshly re-read by this source-only update. The authorized local stage will hash the entire CLI, capture the fixed local utility identities and bind those observations. |
| New control/work namespaces | `official271-native-cli-phaseb-r3-control-r2` and `official271-native-cli-phaseb-r3-live-r2` | No stage or product run has been dispatched. Actual absence must pass the existing lstat guards; an existing entry causes refusal, not deletion or reuse. |

The new source import's authoritative exit is zero. Its complete core records 21 reaped and empty Git process groups, all eight long-held descriptors closed, no errors, and 35.39883295306936 seconds within the original 300-second deadline. The separate 21 command records and stdout/stderr files have not yet been retrieved. The core packet explicitly preserves that remaining archive work; this source packet does not relabel it as complete.

## The exact next dispatch

The fully expanded request blob contains the retained 23,279-byte local stager and the complete 273,490-byte eight-member carrier. It selects desktop `/usr/bin/python3 -I -S -B -c`, stable key `heptabao-phaseb-3cb-local-inputs-4c9a4755-20261105-r1`, the original internal 300-second limit and the separate 330-second outer limit. It creates only the new control directory, five QA files, five artifact files and `binding.private.json`; it neither imports/runs the QA modules nor spawns a child or product.

The new key denotes this never-dispatched local-stage action. It does not retry the old B01 request or reuse any prior product fixture. Root review and a separate exact stage GO are still required. All host access is currently held for the separately scheduled HA window.

## Values that cannot exist before the next stages

Two future hashes remain deliberately unresolved: the actual newly-created `binding.private.json` SHA, and the actual successful readonly-prepare receipt SHA. The former depends on the local stage's current tool observations and fsynced output; the latter depends on a future independent prepare result. The dispatch document supplies the exact fixed argv layouts and stable keys for both later actions, but does not invent their hashes or authorize either action.

After local stage, preserve its authority, full stdout (including post-close deadline/FD closure), durable stage receipt, actual binding and original SDK. Root will verify these before the exact prepare request is filled. Prepare uses the bound Python executable, original 300-second action budget and 330-second outer budget. Live uses the same accepted binding and actual prepare hash, with the previously reviewed separate 3,000-second aggregate outer envelope.

## Original runtime contract remains intact

The main still creates new synthetic state, TLS materials, root tokens and archives in the new work root. B01–B05 retain the leader positive control, real native archives, distinct CAS changes, API state verification and cold regression. CLI exit zero alone remains insufficient to establish restore success. Any unknown/partial mutation stops further CLI, upload, CAS and cold activity; only bounded owned cleanup and evidence preservation may follow.

HTTP and CLI remain 15 seconds, each action 300, readiness 45, election 60, peer timeout 1,500 ms and forwarding 8,000 ms. Normal explicit stop and final cleanup share the reviewed once-only TERM 5 / KILL 5 ledger; the retained reference deadline path's separate SIGKILL-and-wait-5 phase remains its original contract. No timeout was lengthened.

The old unknown B01 result is an exact protected fence. It is neither overwritten nor replayed. No production config, hold marker, provider credential, OAuth refresh or old service is touched. The seed binary remains provenance only and is not added to the main's invocation set. Full OpenBao 2.7.1 replacement qualification remains false.

## Review order

1. Read `DISPATCH.public.json`, `provenance/actual-inputs.public.json` and the exact request.
2. Review retained `source/stage_phaseb_r3_local_inputs_r2.py` and the original-to-current narrow stager diff.
3. Check the carrier members against the five QA files, original build receipts/groups and non-admissible partial binding.
4. Use `review/source-consistency.public.json` for the 16 exact source/request comparisons. These are source checks, not host or product tests.
5. Preserve the previous source plan/dispatch/manifest under `reference/`; no prior object is changed.

No new source implementation or helper is introduced in this launch update.
