# macOS cross-architecture LAN HA: fixture process ancestry (2026-10-12)

**Status:** synthetic qualification **PASS** under a held SSH parent;
unattended macOS service qualification **OPEN**. These are different gates.
This procedure neither grants macOS Local Network access nor changes TCC,
VPN routing, firewall rules, production service identity, or authentication.

## Exact evidence

Three distinct devices: Mac ARM64 (192.168.0.7), ROG Linux x86-64
(192.168.0.10), Pocket4 Linux x86-64 (192.168.0.9). The original 55 checks
include HTTPS/mTLS, leader election, replication, standby forwarding,
snapshot/catch-up, SIGKILL leader failover, step-down, quorum loss,
no-effect rejected write, recovery, cleanup, identity and digest checks.

- Candidate Linux source commit: `6ce7a46b40d22941d9d512a49acf8b728ecefdce`;
  tree: `a5dbf75f98764eb77cf91fb4f9c30c22148b2bd5`.
- Linux binary SHA-256:
  `735d5cb960f4d272225c80b92f54c6b5ea2fd10fa75557a3174e86954976433d`.
- Mac diagnostic source commit: `2002a090b8364147c393265bcd41ed3c7ddbd71d`.
- Mac binary SHA-256:
  `5dde30cc2cc156e072335163cbf06b979e1883ad7e593e7b701edcb6387573ae`.
- R555: the Mac process was launched using `nohup ... &` and detached
  from the SSH session. It failed with 20/55 checks at
  `readback_timeout_ha_leader_forwarding_failed`; the Mac's outbound
  connection to Pocket4 yielded `EHOSTUNREACH` (Darwin errno 65).
  Independent macOS Python and Rust clients could connect on the LAN.
- R565: same binaries; Mac remains a live child of the original SSH
  session. **55/55 PASS**, leader order 1→3→1, no request mutation retries,
  synthetic cleanup verified. Report SHA-256:
  `2aa9fbb8cd2372c2ef156ea1d336b993e699b42deb69230ac7262972d5109520`.
- R566: fresh roots and ports, otherwise same fixture and binaries.
  **55/55 PASS**, leader order 1→3→1, report SHA-256:
  `ca91e606f3a44f9d359606a3e32db23b17947149f4e79fc0f9cca5b965bf4314`.
- R571: uses the reusable `macos_ssh_parent.py` QA module, independently
  pinned at SHA-256
  `7f52a4d94d16760dedd2d9ece3ec3e43d59fc26bafa6a0aa713099199fe57b73`.
  **55/55 PASS**, leader order 1→2→1. Report SHA-256:
  `4d64278b23fab2045cb9336f3b166881e284b69595118069449420a366181c16`.
- R570 QA module: 8 negative/lifecycle unit tests PASS; full repository
  Python discovery **284 PASS**, exit 0.

The reports and their exact test-runner identities are retained under
`/home/qian-qi/work/heptabao-r207-multihost-20261011/` in the
`r565-sshparent-evidence`, `r566-sshparent-evidence`, and
`r571-modular-evidence` folders. The immutable evidence manifest is
copied to Mac T5 only after cross-host digest verification.

## Why the fixture has a held SSH process

Apple TN3179 describes distinct macOS Local Network privacy behavior for
SSH-launched CLI tools versus launchd *agents*. In the original R555, the
SSH command returned immediately, leaving an orphaned Mac binary. In R565
and R566, the original SSH session and bash parent remained alive until
the fixture-owned service PID was explicitly stopped. R571 confirms that a
standalone, fail-closed QA helper reproduces this behavior.

The controlled A/B evidence supports a **launch-context-dependent**
failure. It does **not** conclusively attribute the cause to TCC, hide.me,
a network extension, or any particular macOS consent decision.
Reference: https://developer.apple.com/documentation/Technotes/tn3179-understanding-local-network-privacy

## Security and release boundary

The helper only admits the named Mac SSH alias, a private T5 HeptaBao
fixture directory, and an exact SHA-256. It validates the child/parent
relationship, holds the original SSH process, delegates PID termination
to the existing exact executable/config identity check, and waits for
that same SSH process. Missing owners, duplicate starts, wrong inputs,
failed parent confirmation, and incomplete cleanup are errors. The
fixture does not change cluster authorization or replay deadlines.

**Do not claim** a supported unattended launchd service, production
custody, unrestricted macOS Local Network permission, completed KV2
V6 migration, or full OpenBao 2.7.1 parity from these passing tests.
The 11 replacement gates remain OPEN until their independent receipts
are supplied.
