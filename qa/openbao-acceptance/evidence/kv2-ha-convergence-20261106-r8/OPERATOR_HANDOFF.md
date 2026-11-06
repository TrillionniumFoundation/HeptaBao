# Mac managed-service authorization and resume boundary

## Concrete blocked action

The prepared normal KV2 candidate is the LaunchAgent `gui/501/org.heptabao.kv2`. Its installed plist is `/Users/qianqi/Library/LaunchAgents/org.heptabao.kv2.plist`. The intended API is `https://127.0.0.1:18240`. The first actual bootstrap did not produce a reachable endpoint and never issued init.

The actual macOS kernel log denied `xpcproxy` opening the candidate stdout file under `/Volumes/T5/hepta-vnext-recovery-20261013/heptabao-production-20261104-r1/formal-kv2-current-20261106-r1/logs/stdout.log`, naming `kTCCServiceSystemPolicyRemovableVolumes`.

A user or administrator able to operate this Mac must resolve the responsible launch identity and grant the necessary removable-volume access using supported macOS privacy controls or an approved managed policy. The evidence does not establish which app row appears in Settings. It does not authorize a blanket grant to xpcproxy or assert that enabling Terminal access necessarily grants this LaunchAgent access.

Apple documents user control of Files and Folders access, including removable volumes, and the distinction between privacy access and ordinary Unix permissions. General background: https://support.apple.com/en-ie/guide/mac-help/mchld5a35146/27/mac/27 and https://support.apple.com/en-mide/guide/security-pdf/secddd1d86a6/1/web/1 . These sources explain the control; the actual blocker is established by the retained Mac kernel output.

## State preserved before handoff

- Exact new candidate booted out; subsequent query observed exit 113/no such service.
- Base Python binding repaired with old and initial copies preserved, independent readback completed.
- Data directory empty at the actual reconciliation; root token, nonce, and three unseal-share files absent.
- Normal binaries, config, certificates, guard, plist, failed receipts, and separate backup material retained.
- No persistent `launchctl disable` performed; the plist still has RunAtLoad/KeepAlive. Future session activity can change launchd state and must be reconciled.
- No old service removal or real traffic cutover occurred. Successful preparation does not establish AuthBus or HA acceptance.

## Accepted projection input

The r3 projection is complete and independently reconciled: five agents, nine database families, five auth-store rows and four auth-state rows. Its private output is `/Users/qianqi/heptabao-formal-kv2-current-20261106-r1/projections/formal-kv2-current-r3/projection.private.json`, bound by the private `projection-binding.private.json` and retained native metadata. These rows have not been written through the product API. The baseline starts new version history; it does not reconstruct unavailable OpenBao versions.

## After legitimate authorization

Do not replay `manager_start_init.py` or its original idempotency key. Its create-only assertions and failure receipt path describe a generation that already exists. A new existing-candidate admission/resume entry is required. It must consume the actual repaired binding instead of rebuilding the old venv Python role, preserve the original failed attempt, and write into a new private attempt directory.

Before any new bootstrap/init, re-admit current exact service absence and original pins, empty data and all five absent init materials. Reconcile any unexpected existing service or initialized data instead of starting a second attempt. Keep the original ownership checks, deadline bounds, single init delivery, private output custody, TLS negative checks and root/share publication gates. A permission change alone is not permission to skip these gates.

The resume implementation and actual service acceptance remain incomplete. The source-audit plan identifies the required differences; it is not an executed or ready-to-run initializer.
