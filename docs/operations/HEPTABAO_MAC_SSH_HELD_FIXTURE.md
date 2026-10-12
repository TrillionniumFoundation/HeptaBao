# Mac SSH-held HA fixture (QA only)

Scope: synthetic, isolated HeptaBao cross-architecture HA experiments on Mac,
ROG and Pocket4. This helper is **not** a launchd service, unattended
production supervisor, TCC fix, or release admission.

## Motivation

R566 local and independent physical LAN runs each completed 55/55 checks with
the Mac process held under its SSH parent, including leader SIGKILL, quorum
re-election, catch-up and exact fixture stop. R568 detached nohup run
stopped after 20 checks with ha_leader_forwarding_failed and Mac outbound
EHOSTUNREACH (Darwin 65). Different elected leaders prevent a single-cause
attribution to SSH/TCC. Those outcomes must remain distinct.

## Controller invariants

qa/openbao-acceptance/macos_ssh_parent.py validates an exact SSH alias,
pinned candidate digest and private fixture path, launches at most one
fixture through bash -s, retains the original SSH process, and requires
a remote PID/PPID observation. Final settle_after_verified_remote_stop
**must** only be called after the caller verifies and stops precisely its
own fixture PID by executable, config and path identity. A lost SSH parent
does not count as proven remote cleanup. No privilege elevation, secret
migration, network policy changes or retry of application mutations occur.

For any launch failure or parent loss the caller must independently verify
that the fixture process has stopped before declaring cleanup, and refuse
deployment if that cannot be established.

## Tests

python3 -m unittest discover -s tests/repository -p test_macos_ssh_parent.py -v
: 8 matched, 8 passed, 0 failed on Mac.

A separate 4060-to-Mac R575 fixture-only smoke run verified actual
child/parent identity, exact stop, SSH process settlement, and removal
of its private test directory. Receipt:
qian-qi:/home/qian-qi/work/heptabao-r207-multihost-20261011/
r575-held-parent-probe/receipt.json.

## Production gates deliberately not met

Reliable detached/macOS launchd context and local-network authorization,
full OpenBao 2.7.1 parity, scalable integrated KV2 V6, J3160 secret
reissuance, four real OpenClaw client read/renew/revoke/restart/rollback
proofs and final no-dependency deletion audit are still required. Keep
old provider and production OpenClaw configs unchanged until then.
