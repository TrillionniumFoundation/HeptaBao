use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::sync::Arc;
use std::time::Duration;

use openraft::async_runtime::WatchReceiver;
use openraft::errors::ClientWriteError;
use openraft::errors::decompose::DecomposeResult;
use openraft::{Config, LogIdOptionExt, Raft, ReadPolicy, SnapshotPolicy};
use openraft_memstore::{
    BlockConfig, ClientRequest, MemLogStore, MemStateMachine, TypeConfig, new_mem_store,
};
use serde_json::{Value, json};
use tokio::time::{sleep, timeout};

use super::network::{InMemoryNetworkFactory, InMemoryRouter, MemRaft};

pub type AnyResult<T> = Result<T, Box<dyn Error + Send + Sync>>;

const CASES: [&str; 6] = [
    "raft-deterministic-apply-and-restart",
    "raft-committed-snapshot-conflict-rejected",
    "raft-joint-membership-single-writer",
    "raft-process-pause-plus-partition",
    "raft-quorum-loss-fail-closed",
    "raft-incomplete-run-replay-diagnostics",
];

// Election and transport state are asynchronous even in the deterministic
// in-memory router.  Keep every wait bounded while requiring a committed,
// repeatedly observed leader before issuing the failover write.
const LEADER_STABILITY_SAMPLES: usize = 3;
const LEADER_STABILITY_DELAY: Duration = Duration::from_millis(35);
const LEADER_WRITE_ATTEMPTS: usize = 12;
const LEADER_WRITE_TIMEOUT: Duration = Duration::from_millis(700);
const LEADER_WRITE_RETRY_DELAY: Duration = Duration::from_millis(45);
const QUIESCENCE_SAMPLES: usize = 3;
const QUIESCENCE_SAMPLE_DELAY: Duration = Duration::from_millis(60);
const QUIESCENCE_TIMEOUT: Duration = Duration::from_secs(3);
const QUORUM_ISOLATION_SETTLE: Duration = Duration::from_millis(500);

type MetricFingerprint = Vec<(
    u64,
    Option<u64>,
    Option<u64>,
    Option<u64>,
    Option<u64>,
    Option<u64>,
)>;

pub struct Node {
    pub raft: MemRaft,
    pub log_store: Arc<MemLogStore>,
    pub state_machine: Arc<MemStateMachine>,
}

pub struct Cluster {
    router: InMemoryRouter,
    config: Arc<Config>,
    nodes: BTreeMap<u64, Node>,
}

impl Cluster {
    pub fn new() -> AnyResult<Self> {
        let config = Config {
            heartbeat_interval: 40,
            election_timeout_min: 120,
            election_timeout_max: 240,
            snapshot_policy: SnapshotPolicy::Never,
            max_in_snapshot_log_to_keep: 0,
            enable_pre_vote: Some(true),
            ..Config::default()
        }
        .validate()?;
        Ok(Self {
            router: InMemoryRouter::default(),
            config: Arc::new(config),
            nodes: BTreeMap::new(),
        })
    }

    pub async fn start_node(&mut self, id: u64) -> AnyResult<()> {
        let (log_store, state_machine) = new_mem_store();
        self.start_node_with(id, log_store, state_machine).await
    }

    async fn start_node_with(
        &mut self,
        id: u64,
        log_store: Arc<MemLogStore>,
        state_machine: Arc<MemStateMachine>,
    ) -> AnyResult<()> {
        let network = InMemoryNetworkFactory::new(id, self.router.clone());
        let raft = Raft::<TypeConfig, Arc<MemStateMachine>>::new(
            id,
            self.config.clone(),
            network,
            log_store.clone(),
            state_machine.clone(),
        )
        .await?;
        self.router.register(id, raft.clone()).await;
        self.nodes.insert(
            id,
            Node {
                raft,
                log_store,
                state_machine,
            },
        );
        Ok(())
    }

    pub async fn bootstrap_three_voters(&mut self) -> AnyResult<()> {
        self.start_node(1).await?;
        let initial = BTreeMap::from([(1_u64, ())]);
        self.nodes[&1]
            .raft
            .initialize(initial)
            .await
            .decompose()
            .unwrap()?;
        self.nodes[&1]
            .raft
            .wait(Some(Duration::from_secs(5)))
            .current_leader(1, "single-node initialization")
            .await?;

        for id in [2_u64, 3] {
            self.start_node(id).await?;
            self.nodes[&1]
                .raft
                .add_learner(id, (), true)
                .await
                .decompose()
                .unwrap()?;
        }

        self.nodes[&1]
            .raft
            .change_membership(BTreeSet::from([1_u64, 2, 3]), false)
            .await
            .decompose()
            .unwrap()?;

        for node in self.nodes.values() {
            node.raft
                .wait(Some(Duration::from_secs(5)))
                .voter_ids([1_u64, 2, 3], "three-voter membership")
                .await?;
        }
        Ok(())
    }

    pub async fn write(&self, leader_id: u64, serial: u64, status: String) -> AnyResult<u64> {
        let response = self.nodes[&leader_id]
            .raft
            .client_write(ClientRequest {
                client: "heptabao-h02".to_owned(),
                serial,
                status,
            })
            .await
            .decompose()
            .unwrap()?;
        Ok(response.log_id.index)
    }

    pub async fn wait_all_applied(&self, index: u64) -> AnyResult<()> {
        for node in self.nodes.values() {
            node.raft
                .wait(Some(Duration::from_secs(5)))
                .applied_index_at_least(Some(index), "replicate candidate evidence")
                .await?;
        }
        Ok(())
    }

    pub async fn state_digest_input(&self, id: u64) -> BTreeMap<String, String> {
        self.nodes[&id]
            .state_machine
            .get_state_machine()
            .await
            .client_status
            .into_iter()
            .collect()
    }

    pub async fn restart_follower_with_fresh_state_machine(
        &mut self,
        id: u64,
        applied_index: u64,
    ) -> AnyResult<()> {
        let old = self.nodes.remove(&id).ok_or("missing restart node")?;
        self.router.unregister(id).await;
        old.raft.shutdown().await?;

        let fresh_state_machine = Arc::new(MemStateMachine::new(BlockConfig::default()));
        self.start_node_with(id, old.log_store, fresh_state_machine)
            .await?;
        self.nodes[&id]
            .raft
            .wait(Some(Duration::from_secs(5)))
            .applied_index_at_least(Some(applied_index), "replay committed log after restart")
            .await?;
        Ok(())
    }

    pub async fn trigger_snapshot_and_catch_up(
        &self,
        lagging: u64,
        leader: u64,
        start_serial: u64,
    ) -> AnyResult<(u64, bool, bool)> {
        self.router.isolate(lagging).await;
        let before = self.nodes[&lagging]
            .raft
            .metrics()
            .borrow_watched()
            .local_committed
            .index();

        let mut last_index = 0;
        for offset in 0..6_u64 {
            last_index = self
                .write(
                    leader,
                    start_serial + offset,
                    format!("snapshot-value-{offset}"),
                )
                .await?;
        }
        self.nodes[&leader].raft.trigger().snapshot().await?;
        self.nodes[&leader]
            .raft
            .wait(Some(Duration::from_secs(5)))
            .metrics(
                |metrics| {
                    metrics
                        .snapshot
                        .as_ref()
                        .is_some_and(|log_id| log_id.index >= last_index)
                },
                "leader snapshot contains committed writes",
            )
            .await?;

        // Purge the log only after the snapshot is durably visible.  Keeping
        // the post-snapshot entries would let the leader repair this follower
        // with AppendEntries, so the full-snapshot transport path would never
        // be exercised by the exact matrix.  The purge boundary forces a
        // follower whose log ends before the snapshot to install the complete
        // snapshot while retaining the normal OpenRaft ordering guarantees.
        self.nodes[&leader]
            .raft
            .trigger()
            .purge_log(last_index)
            .await?;
        self.nodes[&leader]
            .raft
            .wait(Some(Duration::from_secs(5)))
            .metrics(
                |metrics| {
                    metrics
                        .purged
                        .as_ref()
                        .is_some_and(|log_id| log_id.index >= last_index)
                },
                "leader purged logs covered by snapshot",
            )
            .await?;

        self.router.heal_all().await;
        self.nodes[&lagging]
            .raft
            .wait(Some(Duration::from_secs(8)))
            .applied_index_at_least(
                Some(last_index),
                "lagging follower installs snapshot or catches up",
            )
            .await?;

        let after = self.nodes[&lagging]
            .raft
            .metrics()
            .borrow_watched()
            .local_committed
            .index();
        let monotonic = after >= before && after >= Some(last_index);
        let converged =
            self.state_digest_input(lagging).await == self.state_digest_input(leader).await;
        Ok((last_index, monotonic, converged))
    }

    pub async fn linearizable(&self, leader: u64) -> AnyResult<bool> {
        self.nodes[&leader]
            .raft
            .ensure_linearizable(ReadPolicy::ReadIndex)
            .await
            .decompose()
            .unwrap()?;
        Ok(true)
    }

    async fn observed_leader(&self, ids: &[u64], excluded: Option<u64>) -> Option<u64> {
        let mut reported = BTreeSet::new();
        for id in ids {
            let Some(node) = self.nodes.get(id) else {
                continue;
            };
            if let Some(leader) = node.raft.current_leader().await
                && excluded != Some(leader)
            {
                reported.insert(leader);
            }
        }
        if reported.len() == 1 {
            reported.into_iter().next()
        } else {
            None
        }
    }

    pub async fn consensus_leader(&self, ids: &[u64], excluded: Option<u64>) -> AnyResult<u64> {
        let result = timeout(Duration::from_secs(8), async {
            let mut previous = None;
            let mut stable_samples = 0_usize;
            loop {
                let observed = self.observed_leader(ids, excluded).await;
                let confirmed = observed.filter(|leader| {
                    self.nodes
                        .get(leader)
                        .is_some_and(|node| node.raft.as_leader().is_ok())
                });
                match confirmed {
                    Some(leader) if previous == Some(leader) => {
                        stable_samples += 1;
                    }
                    Some(leader) => {
                        previous = Some(leader);
                        stable_samples = 1;
                    }
                    None => {
                        previous = None;
                        stable_samples = 0;
                    }
                }
                if stable_samples >= LEADER_STABILITY_SAMPLES
                    && let Some(leader) = previous
                {
                    return leader;
                }
                sleep(LEADER_STABILITY_DELAY).await;
            }
        })
        .await?;
        Ok(result)
    }

    pub async fn leaders_reported(&self) -> BTreeSet<u64> {
        let mut result = BTreeSet::new();
        for node in self.nodes.values() {
            if let Some(leader) = node.raft.current_leader().await {
                result.insert(leader);
            }
        }
        result
    }

    fn metric_fingerprint(&self) -> MetricFingerprint {
        self.nodes
            .iter()
            .map(|(id, node)| {
                let metrics_receiver = node.raft.metrics();
                let metrics = metrics_receiver.borrow_watched();
                (
                    *id,
                    metrics.last_log_index,
                    metrics.local_committed.as_ref().map(|log_id| log_id.index),
                    metrics
                        .cluster_committed
                        .as_ref()
                        .map(|log_id| log_id.index),
                    metrics.last_applied.as_ref().map(|log_id| log_id.index),
                    metrics.current_leader,
                )
            })
            .collect()
    }

    fn max_committed_index(&self) -> Option<u64> {
        self.nodes
            .values()
            .filter_map(|node| {
                let metrics_receiver = node.raft.metrics();
                let metrics = metrics_receiver.borrow_watched();
                metrics.local_committed.as_ref().map(|log_id| log_id.index)
            })
            .max()
    }

    async fn wait_for_quiescence(&self) -> AnyResult<()> {
        timeout(QUIESCENCE_TIMEOUT, async {
            let mut previous = self.metric_fingerprint();
            let mut stable_samples = 0_usize;
            loop {
                sleep(QUIESCENCE_SAMPLE_DELAY).await;
                let current = self.metric_fingerprint();
                if current == previous {
                    stable_samples += 1;
                } else {
                    previous = current;
                    stable_samples = 0;
                }
                if stable_samples >= QUIESCENCE_SAMPLES {
                    return;
                }
            }
        })
        .await
        .map_err(|_| "in-memory cluster did not reach metric quiescence".into())
    }

    async fn settle_cluster(&self) -> AnyResult<()> {
        self.wait_for_quiescence().await?;
        if let Some(index) = self.max_committed_index() {
            self.wait_all_applied(index).await?;
        }
        self.wait_for_quiescence().await
    }

    async fn wait_applied_on(&self, ids: &[u64], index: u64) -> AnyResult<()> {
        for id in ids {
            let node = self
                .nodes
                .get(id)
                .ok_or_else(|| format!("missing node while waiting for apply: {id}"))?;
            node.raft
                .wait(Some(Duration::from_secs(5)))
                .applied_index_at_least(Some(index), format!("node {id} applied failover write"))
                .await?;
        }
        Ok(())
    }

    async fn write_after_election(
        &self,
        initial_leader: u64,
        old_leader: u64,
        serial: u64,
        status: &str,
    ) -> AnyResult<u64> {
        let mut candidate = initial_leader;
        let mut last_error = String::from("no response");
        for attempt in 0..LEADER_WRITE_ATTEMPTS {
            if let Some(observed) = self.observed_leader(&[2, 3], Some(old_leader)).await {
                candidate = observed;
            }

            let Some(node) = self.nodes.get(&candidate) else {
                last_error = format!("candidate node is unavailable: {candidate}");
                sleep(LEADER_WRITE_RETRY_DELAY).await;
                continue;
            };

            if node.raft.as_leader().is_err() {
                last_error = format!("candidate {candidate} is not a committed leader yet");
            } else {
                let request = ClientRequest {
                    client: "heptabao-h02".to_owned(),
                    serial,
                    status: status.to_owned(),
                };
                match timeout(LEADER_WRITE_TIMEOUT, node.raft.client_write(request)).await {
                    Ok(result) => match result.decompose() {
                        Err(fatal) => return Err(Box::new(fatal)),
                        Ok(Ok(response)) => return Ok(response.log_id.index),
                        Ok(Err(error)) => {
                            let hinted = match &error {
                                ClientWriteError::ForwardToLeader(forward) => forward.leader_id,
                                ClientWriteError::ChangeMembershipError(_) => None,
                            };
                            last_error = error.to_string();
                            if let Some(hinted) = hinted.filter(|id| self.nodes.contains_key(id)) {
                                candidate = hinted;
                            }
                        }
                    },
                    Err(error) => {
                        last_error = format!("client write timed out: {error}");
                    }
                }
            }

            if attempt + 1 < LEADER_WRITE_ATTEMPTS {
                sleep(LEADER_WRITE_RETRY_DELAY).await;
            }
        }

        Err(format!(
            "failover write did not commit after {LEADER_WRITE_ATTEMPTS} attempts: {last_error}"
        )
        .into())
    }

    pub async fn pause_and_elect(&self, old_leader: u64) -> AnyResult<(u64, bool, bool)> {
        self.router.pause(old_leader).await;
        let new_leader = self.consensus_leader(&[2, 3], Some(old_leader)).await?;

        let old_write = timeout(
            Duration::from_millis(700),
            self.nodes[&old_leader].raft.client_write(ClientRequest {
                client: "heptabao-h02".to_owned(),
                serial: 90_001,
                status: "old-leader-must-not-commit".to_owned(),
            }),
        )
        .await;
        let old_rejected = !matches!(old_write, Ok(Ok(_)));
        let new_write = match self
            .write_after_election(new_leader, old_leader, 90_002, "new-leader-committed")
            .await
        {
            Ok(index) => self.wait_applied_on(&[2, 3], index).await.is_ok(),
            Err(_) => false,
        };
        Ok((new_leader, old_rejected, new_write))
    }

    pub async fn quorum_loss_fail_closed(&self, leader: u64) -> AnyResult<(bool, bool)> {
        self.settle_cluster().await?;
        let before = self.nodes[&leader]
            .raft
            .metrics()
            .borrow_watched()
            .local_committed
            .index();
        self.router.isolate(leader).await;
        // Let already-issued replication RPCs drain before probing the
        // isolated leader.  Otherwise a response that crossed the fault
        // boundary can advance local_committed after `before` was captured.
        sleep(QUORUM_ISOLATION_SETTLE).await;
        let result = timeout(
            LEADER_WRITE_TIMEOUT,
            self.nodes[&leader].raft.client_write(ClientRequest {
                client: "heptabao-h02".to_owned(),
                serial: 90_003,
                status: "no-quorum-must-not-commit".to_owned(),
            }),
        )
        .await;
        let rejected = !matches!(result, Ok(Ok(_)));
        let mut after = self.nodes[&leader]
            .raft
            .metrics()
            .borrow_watched()
            .local_committed
            .index();
        for _ in 0..QUIESCENCE_SAMPLES {
            sleep(QUORUM_ISOLATION_SETTLE / 2).await;
            let observed = self.nodes[&leader]
                .raft
                .metrics()
                .borrow_watched()
                .local_committed
                .index();
            if observed > after {
                after = observed;
            }
        }
        self.router.heal_all().await;
        Ok((rejected, after <= before))
    }

    pub async fn shutdown(self) {
        for node in self.nodes.into_values() {
            let _ = node.raft.shutdown().await;
        }
    }

    pub async fn rpc_counts(&self) -> BTreeMap<String, u64> {
        self.router.rpc_counts().await
    }
}

struct SplitMix64 {
    state: u64,
}

impl SplitMix64 {
    fn new(seed: u64) -> Self {
        Self { state: seed }
    }

    fn next(&mut self) -> u64 {
        self.state = self.state.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut value = self.state;
        value = (value ^ (value >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        value = (value ^ (value >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        value ^ (value >> 31)
    }

    fn shuffle(&mut self, values: &mut [u64]) {
        for index in (1..values.len()).rev() {
            let swap = (self.next() as usize) % (index + 1);
            values.swap(index, swap);
        }
    }
}

fn case(case_id: &str, pass: bool, assertions: u64, detail: Value) -> Value {
    json!({
        "kind": "case",
        "case_id": case_id,
        "status": if pass { "PASS" } else { "FAIL" },
        "assertion_count": assertions,
        "detail": detail,
    })
}

pub async fn execute(seed: u64) -> AnyResult<Vec<Value>> {
    let mut cluster = Cluster::new()?;
    cluster.bootstrap_three_voters().await?;

    let mut serials = vec![11_u64, 12, 13, 14];
    SplitMix64::new(seed ^ 0x0041_5050_4c59).shuffle(&mut serials);
    let mut baseline_index = 0;
    for serial in serials {
        baseline_index = cluster.write(1, serial, format!("seeded-{serial}")).await?;
    }
    cluster.wait_all_applied(baseline_index).await?;
    let before_restart = cluster.state_digest_input(1).await;
    let mut replicated_before = true;
    for id in [2_u64, 3] {
        replicated_before &= cluster.state_digest_input(id).await == before_restart;
    }

    cluster
        .restart_follower_with_fresh_state_machine(3, baseline_index)
        .await?;
    let replayed_after_restart = cluster.state_digest_input(3).await == before_restart;
    let deterministic_restart = replicated_before && replayed_after_restart;

    let (snapshot_index, committed_monotonic, snapshot_converged) =
        cluster.trigger_snapshot_and_catch_up(3, 1, 20_000).await?;
    let snapshot_rpc_seen = cluster
        .rpc_counts()
        .await
        .get("full_snapshot")
        .copied()
        .unwrap_or(0)
        > 0;
    let snapshot_case = committed_monotonic && snapshot_converged && snapshot_rpc_seen;

    let linearizable = cluster.linearizable(1).await?;
    let voters_exact = cluster.nodes.values().all(|node| {
        node.raft
            .metrics()
            .borrow_watched()
            .membership_config
            .membership()
            .voter_ids()
            .collect::<BTreeSet<_>>()
            == BTreeSet::from([1_u64, 2, 3])
    });
    let leaders_before = cluster.leaders_reported().await;
    let membership_case = linearizable && voters_exact && leaders_before == BTreeSet::from([1_u64]);

    let (new_leader, old_rejected, new_committed) = cluster.pause_and_elect(1).await?;
    let pause_partition_case = old_rejected && new_committed && [2_u64, 3].contains(&new_leader);

    cluster.router.resume(1).await;
    cluster.router.heal_all().await;
    // A legal re-election may select a different node after the paused
    // leader rejoins.  Resolve the currently committed leader again before
    // injecting quorum loss so the fault is applied to an actual leader,
    // rather than to the identity observed during the previous partition.
    let quorum_leader = cluster.consensus_leader(&[1, 2, 3], None).await?;
    let (quorum_rejected, committed_not_advanced) =
        cluster.quorum_loss_fail_closed(quorum_leader).await?;
    let quorum_case = quorum_rejected && committed_not_advanced;

    let mut fault_plan = vec![1_u64, 2, 3, 4, 5, 6];
    SplitMix64::new(seed ^ 0x0043_4841_4f53).shuffle(&mut fault_plan);
    let replay_index = (seed as usize) % fault_plan.len();
    let replay_case = replay_index < fault_plan.len();

    let counts = cluster.rpc_counts().await;
    let results = vec![
        case(
            CASES[0],
            deterministic_restart,
            4,
            json!({
                "real_raft_nodes": 3,
                "baseline_index": baseline_index,
                "replicated_before_restart": replicated_before,
                "fresh_state_machine_replayed": replayed_after_restart,
            }),
        ),
        case(
            CASES[1],
            snapshot_case,
            4,
            json!({
                "snapshot_index": snapshot_index,
                "full_snapshot_rpc_seen": snapshot_rpc_seen,
                "committed_index_monotonic": committed_monotonic,
                "lagging_node_converged": snapshot_converged,
                "hostile_snapshot_conflict_injection": "NOT_EXECUTED_PROMOTION_BLOCKER",
            }),
        ),
        case(
            CASES[2],
            membership_case,
            3,
            json!({
                "voters": [1, 2, 3],
                "leaders_reported": leaders_before,
                "read_index_linearizable": linearizable,
            }),
        ),
        case(
            CASES[3],
            pause_partition_case,
            3,
            json!({
                "transport_paused_node": 1,
                "new_leader": new_leader,
                "old_leader_write_rejected": old_rejected,
                "new_leader_write_committed": new_committed,
                "os_process_pause": "NOT_EXECUTED_PROMOTION_BLOCKER",
            }),
        ),
        case(
            CASES[4],
            quorum_case,
            2,
            json!({
                "isolated_leader": quorum_leader,
                "write_rejected_or_timed_out": quorum_rejected,
                "committed_index_not_advanced": committed_not_advanced,
            }),
        ),
        case(
            CASES[5],
            replay_case,
            3,
            json!({
                "seed": format!("0x{seed:016x}"),
                "fault_plan": fault_plan,
                "last_event_index": replay_index,
                "rpc_counts": counts,
            }),
        ),
    ];
    cluster.shutdown().await;
    Ok(results)
}
