# Mac five-agent fixture — worker implementation draft 1

This is a new source implementation against the exact recovered Mac and Pocket
QA bases. It has not been installed, parsed by a remote interpreter, executed,
or qualified. The original plan tree 0461891c5a95d3d7f56c763756ad7037c214801f
and all historical results remain unchanged.

## Implemented scope

- One AuthBus cycle processes the complete five-agent owned state with the
  original captured configuration. Only the four connection fields differ
  from the original AuthBus configuration. publishNew and its proposals are
  not disabled. The worker cannot POST a manifest or grant a new identity.
- The actual five-agent local/effective stores, primary auth rows and six cache
  bytes/absences are captured before the cycle. No quota or cooldown is reset.
  Both exact managed credential generations are checked against actual current
  identity digests. Every unmanaged profile, including profile3, and the complete
  noncredential store state are compared with the actual baseline.
- Five separate Node workers call the installed registry/default selector and
  actual native factory once each. They do not repeat the AuthBus cycle, supply
  a preferred profile, or require the SDK to select managed1/2. A natural
  profile3 selection is observed; no provider refresh is attempted to make it
  succeed. The old unconditional ten-minute JWT-future predicate is removed;
  the actual JWT/account identity and actual local RPC result remain mandatory.
- The unchanged Mac observer verifies one real wrapper -> Node -> managed
  launcher -> native lineage over its own anonymous pipes and nonce. The Node
  worker's actual observer function and spawn guard remain intact. Each worker
  starts with nativeSpawned=0 and permits exactly one factory. No shared
  verified flag can authorize another agent.
- The launchd phase wrapper truly owns these Popen children. The future outer
  manager owns only the exact launchd registration and wrapper identity; it
  cannot impersonate the observer or claim Node as its direct child.
- A single original monotonic 120-second phase deadline covers volume guard,
  current source checks, cycle, five workers, observer handshakes and normal
  progression. Native local caps are 15/8/3 seconds, shortened by each allocated
  remaining budget. The wrapper retains the authoritative original deadline
  across all workers and cancels/marks failure at it. A child allocation does
  not claim cross-language monotonic epoch equivalence.
- The existing native child cleanup contract is retained: TERM observation 1s,
  KILL followed by wait 5s, final group observation 3s, with the original fixed
  ps helper cap 4s. Cleanup can record failure after the business deadline; it
  cannot make a late phase succeed or start another worker.
- T5 UUID is checked by an owned diskutil operation, capped at the existing
  30s and the same phase deadline, before the wrapper opens a phase plan or
  writes any T5 output. The actual phase device must equal the captured mounted
  device. No path is created as a fallback for a missing/replaced volume.

## Corrected inverse semantics

The prior plan's phrase “restore local+effective first” is superseded by this
precise implementation: only the actually captured persistent local SDK store
is a write input. CAS verifies all five complete candidate local/effective/raw
states and all six caches before mutation. The installed SDK restores local
state, then primary raw rows (including updated_at and absence) are restored.
Only after every relevant local/raw store is back does the actual SDK recompute
effective state and compare it with the baseline. trnm's inherited profiles are
never written into its originally profile-free primary row.

The once marker is create-only and both the marker file and containing directory
are fsynced. A conflict consumes that operation; there is no retry. Six caches
are restored last with the unchanged reviewed cache CAS helper. Initial and cold
use independent state roots, baseline files, candidate checkpoints and inverse
markers. The four distinct externally owned phases are initial, cold-new-process,
initial-inverse and cold-new-process-inverse. The two inverses check all five
agents but do not launch native factories or issue HTTP requests.

## Current observed Mac baseline

The actual finite read on 2026-11-04 is preserved in tree
92eb2881f894ee0df757107715da8b419768ad32. It is KNOWN INCOMPLETE because only
/etc/crontab was blocked by the /etc symlink guard. It is not a complete backup
or service-dependency inventory.

The observed config hash is
ca2dd7d7879fa901dfb24e00837b56a4e0fd230600d7ed1e3086eda194187d4d.
Its agent order is main, trnm, hepta-ui, hepta, hepta-backend. Actual flags remain
hostId=mac, leader=false, publishNew=true, manageOrder=true, releaseGeneration=200,
pollIntervalMs=15000, refreshMarginMs=900000, maxRefreshesPerCycle=1. Scheduler
mode and exclusions are absent in the config, not injected by this harness.
All five configured model primaries are openai/gpt-5.6-sol.

The production gateway and four relay registrations were observed running.
They are not stopped, loaded, edited or used to dispatch this fixture. Their
argument dependencies remain unresolved; executable-only public projections do
not claim full wrapper/config analysis.

## Still being implemented before a runnable complete fixture

This packet supplies the executable worker/phase-owner layer only. It does not
supply a ready private input bundle or an outer live driver. The fixed launchd
manager operation graph, guarded live capture/materialization and the owned
normal-server integration are separate source components still being authored.
There is no runtime GO in this packet.

The manager will use immutable generation-specific plists and one exact consumer
label, requiring known absence before bootstrap and a verified bootout/empty
owned process tree before the next generation. Each unsafe dispatch records its
own durable intent before the command. An ambiguous bootstrap/bootout permits
read-only reconciliation and one owned cleanup, never a new business generation.
The separate server label must have its own real registration/PID/ready/stop
proof. KeepAlive=false prevents a harness retry and does not qualify the
production KeepAlive=true policy.

The future capture must privately validate all five current auth primary rows,
the actual local/effective distinction, six cache files, registry row and full
source pins. When absent SQLite sidecars prevent safe readonly access, any
bounded stable-copy branch must be separately explicit; opening a production
database must not create SHM. Private credential acquisition is not performed
by this source-only packet.

## Review and validation status

No host command, provider request, SDK import, product process or compiler was
run to author this packet. Whole Git blobs and exact diffs are the current
evidence. Source review, syntax checks and meaningful lifecycle/CAS failure
components are pending. Actual factory and real launchd claims require the
later full owned run; neither code presence nor a component result substitutes
for those observations.
