# Native LAN TCP diagnostic: original 0f1c cohort

This controller prepares one new owned diagnostic on Mac, ROG and Pocket4. It observes the original native executable's pre-TLS connection path and two Python TCP controls. It does not initialize, unseal or activate HeptaBao and does not read or modify the original data/raft directories. There is no production authority and no HA acceptance claim. The actual original LAN result remains **36/98**.

## Actual evidence motivating this diagnostic

The three original HA configurations have exactly equal peer maps. Mac node 1 targets ROG `192.168.0.10:46231` and Pocket4 `192.168.0.9:46231`; local Mac is `192.168.0.7:46231`. API listeners use port 46230. All three maps carry the same node names, SNI names and pinned peer leaf digests. The independently projected actual configuration/log evidence is in `evidence/native-lan98-network-review-20261019.json`.

Mac's original log contains 269 `tcp_connect/Transport/HostUnreachable` events. The native transport calls `TcpStream::connect_timeout` with the literal address from that peer map before it creates the TLS client/stream; these particular failures therefore precede certificate validation. Its final reason digest is SHA256(`HA peer transport failed`), the generic transport error, rather than a separately meaningful policy-denial code. Earlier Mac log entries reached a TLS frame write and timed out; the evidence does not show that the original executable could never connect.

The actual read-only Mac network receipt reports en0 routes to both peers and permission for incoming connections to the exact original executable. The log query found no actual denial event. These observations do not establish a TCC, firewall, routing or product cause. Original run peer probes came from Python, which is a distinct process path.

## Exact product and executable identity

The product commit is `0f1c996136aae94e99c2b709a5797ffea479f6cd`, tree `8befd5cedfb7ccafee5f707e5985d49eeb78fb60`. This diagnostic intentionally investigates the original failed run and does not substitute a newer product build.

The Mac executable is opened at its original path:

```text
/Volumes/T5/hepta-vnext-recovery-20261013/continuation-20261018/native-lan98-0f1c-20261019-r1/heptabao-server
```

Its required SHA256 is `228bafc8cacc99c5a161f3a3b9892ead6839a65fd524765e1db384130c30abb7`. It is neither copied into a new executable identity nor re-signed. The controller pins the original HA/server JSON digests, copies only that owner's synthetic TLS/replication material into the new Mac root without exporting it, and replaces the new configuration's data, raft, audit and TLS paths. The cluster UUID is new. It verifies the original binary/configuration/copied inputs again after observation. It does not claim a full original-directory byte census.

The driver and remote agent are separately hashed. Their new Git/source identity is distinct from the investigated product's 0f1c identity.

## One-shot input and execution

The supplied `NATIVE_LAN_TCP_DIAGNOSTIC_20261019.template.json` contains concrete proposed fresh roots, original product pins, exact aliases and a run ID. No actual PID or completed-run fact is prefilled. Each root must be absent; a root created by an unknown previous submission is preserved and causes refusal. The permitted root parents and actual hostnames are closed in the agent:

| Alias | Actual hostname | Endpoint | New-root parent |
|---|---|---|---|
| macbook-pro | MacBook-Pro.local | 192.168.0.7 | /Volumes/T5/hepta-vnext-recovery-20261013/continuation-20261018 |
| rog | qian-qi-ROG-Flow-Z13-GZ302EA-GZ302EA | 192.168.0.10 | /home/qian-qi |
| pocket4 | alex-G1628-04 | 192.168.0.9 | /home/alex |

On the actual `qian-qi` Linux controller, with both Python files adjacent and the template copied to a reviewed input path:

```bash
python3 -B /ABSOLUTE/QA/native_lan_tcp_diagnostic.py \
  --input /ABSOLUTE/OWNED/native-tcp-input.json \
  --output /ABSOLUTE/OWNED/native-tcp-controller-r1
```

`/ABSOLUTE/QA` and the main output/input paths must be supplied from the actual installed diagnostic source. They are not product binary paths. Root owns the actual Runtime/SSH invocation.

The controller first makes one bounded prepare submission to each host. Prepare checks that the fixture ports have no listener with read-only `ss`/`lsof`, creates a private task root, writes the pinned agent and prepares the new Mac configuration. The active phase starts only after all prepare results are known successful. Each start then creates `active-once.json` exclusively; no restart or network-connect retry is supported.

ROG/Pocket4 listen only on their exact port 46231, accept and immediately close. They do not parse or read any payload. Their hard original lifetime is 25 seconds, with half a second reserved for socket close and final projection; a terminal observation after 25 seconds fails its deadline predicate. They never start a Linux HeptaBao server or touch another application's state.

The Mac watchdog starts the original binary once, with the new `server.json`, new `ha.json`, and original `--experimental-native-v6-ha` flag. It observes at most 10 seconds, reserving the remainder of its 12-second hard ceiling for exact owned-session cleanup. It performs no HTTP request. After its native group is stopped, it makes one TCP connection attempt to each Linux endpoint, each with the original two-second per-control ceiling and no retry.

The controller requires Linux readiness within its original three-second readiness window and records whether the Mac result arrived before the conservative 23-second active boundary. Its complete active supervisor ceiling is 35 seconds. These are independent diagnostic limits; no LAN98, product HTTP, peer or original 55-test deadline is changed.

## Ownership, unknown outcomes and projection

Every local SSH and native `Popen` uses a new session. PID/PPID/PGID/SID/UID/start identity are recorded. The native and SSH leaders are not polled/reaped before final group signals: the unreaped leader reserves the exact group identity while TERM and, if necessary, KILL close its own group. The receipt distinguishes `leader_reaped` from `owned_live_group_empty`. An already reaped or changed leader refuses a numeric group signal. It does not kill by executable name or scan unrelated command lines.

Remote listener processes have no spawned application children and close their sockets before their final summary. Read-only collection independently observes that each exact watchdog identity is gone or a zombie. On an unknown SSH outcome, the controller records failure and collects only; it does not rerun preparation, start, activation or a connect. The remote active agents have their own absolute lifetimes, independent of controller output delivery.

Only public counts, errors/stages, configuration/source digests and ownership metadata are projected. No credential, private key, replication key, request body or received payload is printed. The native process log remains in its new owner root; the controller receives only its SHA256, byte length and a closed stage-count projection.

Successful dummy accept-only connections will cause expected TLS EOF/failure in the native peer protocol. They prove neither TLS peer authentication nor forwarding nor HA durability. Python controls are matched to actual listener observations using the observed TCP source port. Other accepts are identified as originating from the Mac IP, without pretending that IP identity is native PID attribution.

This run keeps its SSH/Python watchdog alive. The original daemon-style launcher could let its parent exit. Parent lifetime, ancestry and session setup are therefore independent experimental variables: a TCP success here cannot establish that the original launcher or product is fixed. Both native and watchdog parent chains are retained without command arguments or environment. A later explicitly selected experiment can vary only that lifecycle if these results justify it; this controller does not make that change automatically.

## Local verification and remaining actual execution

`tests/native_lan_tcp_diagnostic_local_test.py` exercises four real local ownership cases: a running owned session, an exited leader with a TERM-resistant same-group child, refusal after leader reap, and refusal for a mismatched start identity. The consistent local PID/procfs run passed all four. The initial tool-sandbox attempt failed because its `os.getpid()` namespace and procfs namespace differed; that failure is retained in the local receipt. No identity check was relaxed.

The independent local test command is:

```bash
python3 -B /ABSOLUTE/QA/tests/native_lan_tcp_diagnostic_local_test.py
```

No actual Mac/ROG/Pocket4 diagnostic has been run by the author of this overlay. Only a subsequent root-owned actual run and its collected receipts can establish the observed TCP behavior. This overlay neither changes nor reclassifies the original 36/98 failure or the separate 53/55 candidate results.
