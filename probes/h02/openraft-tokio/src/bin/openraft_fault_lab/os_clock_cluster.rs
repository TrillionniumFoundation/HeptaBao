use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use openraft::{Config, Raft, ReadPolicy, SnapshotPolicy};
use openraft_memstore::{ClientRequest, MemLogStore, MemStateMachine, TypeConfig, new_mem_store};
use serde_json::{Value, json};
use tokio::time::{sleep, timeout};

use super::network::{InMemoryNetworkFactory, InMemoryRouter, MemRaft};

pub type AnyResult<T> = Result<T, Box<dyn Error + Send + Sync>>;

const REGISTER_KEY: &str = "heptabao-h02-os-clock-register";

struct Node {
    raft: MemRaft,
    log_store: Arc<MemLogStore>,
    state_machine: Arc<MemStateMachine>,
}

struct Cluster {
    router: InMemoryRouter,
    config: Arc<Config>,
    nodes: BTreeMap<u64, Node>,
}

impl Cluster {
    fn new() -> AnyResult<Self> {
        let config = Config {
            heartbeat_interval: 40,
            election_timeout_min: 120,
            election_timeout_max: 240,
            snapshot_policy: SnapshotPolicy::LogsSinceLast(8),
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

    async fn start_node(&mut self, id: u64) -> AnyResult<()> {
        let (log_store, state_machine) = new_mem_store();
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

    async fn wait_membership_committed(&self, context: &str) -> AnyResult<()> {
        for node in self.nodes.values() {
            node.raft
                .wait(Some(Duration::from_secs(8)))
                .metrics(
                    |metrics| metrics.membership_config == metrics.committed_membership_config,
                    context,
                )
                .await?;
        }
        Ok(())
    }

    async fn bootstrap_three_voters(&mut self) -> AnyResult<()> {
        self.start_node(1).await?;
        self.nodes[&1]
            .raft
            .initialize(BTreeMap::from([(1_u64, ())]))
            .await?;
        self.nodes[&1]
            .raft
            .wait(Some(Duration::from_secs(5)))
            .current_leader(1, "os-clock single-node initialization")
            .await?;
        self.wait_membership_committed("os-clock initial membership committed")
            .await?;
        for id in [2_u64, 3] {
            self.start_node(id).await?;
            self.nodes[&1].raft.add_learner(id, (), true).await?;
            self.wait_membership_committed("os-clock learner membership committed")
                .await?;
        }
        self.nodes[&1]
            .raft
            .change_membership(BTreeSet::from([1_u64, 2, 3]), false)
            .await?;
        self.wait_membership_committed("os-clock voter membership committed")
            .await?;
        for node in self.nodes.values() {
            node.raft
                .wait(Some(Duration::from_secs(5)))
                .voter_ids([1_u64, 2, 3], "os-clock three-voter membership")
                .await?;
        }
        Ok(())
    }

    async fn consensus_leader(&self) -> AnyResult<u64> {
        let leader = timeout(Duration::from_secs(20), async {
            loop {
                let mut reported = BTreeSet::new();
                for node in self.nodes.values() {
                    if let Some(leader) = node.raft.current_leader().await {
                        reported.insert(leader);
                    }
                }
                if reported.len() == 1
                    && let Some(leader) = reported.iter().next().copied()
                    && self.nodes.contains_key(&leader)
                {
                    return leader;
                }
                sleep(Duration::from_millis(25)).await;
            }
        })
        .await
        .map_err(|_| "timed out waiting for one post-resume consensus leader")?;
        Ok(leader)
    }

    async fn write_and_read_once(
        &self,
        serial: u64,
        value: &str,
    ) -> AnyResult<(u64, Option<String>, u64)> {
        let leader = self.consensus_leader().await?;
        let node = self
            .nodes
            .get(&leader)
            .ok_or("consensus leader is not a local node")?;
        let response = node
            .raft
            .client_write(ClientRequest {
                client: REGISTER_KEY.to_owned(),
                serial,
                status: value.to_owned(),
            })
            .await?;
        node.raft
            .wait(Some(Duration::from_secs(10)))
            .applied_index_at_least(Some(response.log_id.index), "os-clock write applied")
            .await?;
        node.raft.ensure_linearizable(ReadPolicy::ReadIndex).await?;
        let observed = node
            .state_machine
            .get_state_machine()
            .await
            .client_status
            .get(REGISTER_KEY)
            .cloned();
        Ok((response.log_id.index, observed, leader))
    }

    /// Retry a post-suspend write/read while OpenRaft settles a legal leader
    /// election.  SIGSTOP advances the monotonic clock while all three
    /// in-process nodes are paused, so the first request after SIGCONT can
    /// legitimately observe a stale leader (or a forwarding target of
    /// `None`).  The retry is deliberately bounded and keeps the original
    /// serial/value pair so a committed request remains idempotent.  A
    /// permanent failure is returned with the final diagnostic instead of
    /// being converted into a pass.
    async fn write_and_read(
        &self,
        serial: u64,
        value: String,
    ) -> AnyResult<(u64, Option<String>, u64)> {
        const RETRY_WINDOW: Duration = Duration::from_secs(10);
        const RETRY_DELAY: Duration = Duration::from_millis(50);

        let deadline = Instant::now() + RETRY_WINDOW;
        let mut attempts = 0_u32;
        let mut last_error = "no attempt completed".to_owned();

        loop {
            let now = Instant::now();
            if now >= deadline {
                break;
            }
            let remaining = deadline.duration_since(now);
            attempts = attempts.saturating_add(1);
            match timeout(remaining, self.write_and_read_once(serial, &value)).await {
                Ok(Ok(result)) => return Ok(result),
                Ok(Err(error)) => last_error = error.to_string(),
                Err(_) => {
                    last_error = format!(
                        "write/read attempt timed out after {} ms",
                        remaining.as_millis()
                    );
                }
            }

            let now = Instant::now();
            if now >= deadline {
                break;
            }
            let remaining = deadline.duration_since(now);
            if remaining <= RETRY_DELAY {
                break;
            }
            sleep(RETRY_DELAY).await;
        }

        Err(format!(
            "bounded post-resume write/read retry exhausted after {attempts} attempts: {last_error}"
        )
        .into())
    }

    async fn shutdown(self) {
        for node in self.nodes.into_values() {
            let _ = node.raft.shutdown().await;
            drop(node.log_store);
        }
    }
}

fn write_json_atomic(path: &Path, value: &Value) -> io::Result<()> {
    let temporary = path.with_extension("tmp");
    let bytes = serde_json::to_vec(value)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
    {
        let mut file = OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .open(&temporary)?;
        file.write_all(&bytes)?;
        file.flush()?;
        file.sync_all()?;
    }
    fs::rename(&temporary, path)?;
    if let Some(parent) = path.parent() {
        File::open(parent)?.sync_all()?;
    }
    Ok(())
}

pub async fn execute_os_suspend_child(seed: u64, work_dir: &Path) -> AnyResult<()> {
    fs::create_dir_all(work_dir)?;
    let mut cluster = Cluster::new()?;
    cluster.bootstrap_three_voters().await?;

    write_json_atomic(
        &work_dir.join("ready.json"),
        &json!({
            "kind": "ready",
            "real_openraft_nodes": 3,
            "candidate_id": "HB-DEP-RAFT-OPENRAFT",
            "version": "0.10.0-alpha.33",
            "seed": format!("0x{seed:016x}"),
            "qualification": false,
            "selection_effect": "NONE",
            "authority_effect": "NONE"
        }),
    )?;

    for step in 1_u64..=100_000 {
        let value = format!("os-resume-{step}-{seed:016x}");
        let (committed_index, observed, current_leader) = cluster
            .write_and_read(300_000 + step, value.clone())
            .await?;
        let progress = json!({
            "kind": "progress",
            "step": step,
            "committed_index": committed_index,
            "expected": value,
            "observed": observed,
            "read_index_ok": observed.as_deref() == Some(value.as_str()),
            "current_leader": current_leader,
            "pid": std::process::id(),
            "qualification": false,
            "selection_effect": "NONE",
            "authority_effect": "NONE"
        });
        write_json_atomic(&work_dir.join("progress.json"), &progress)?;
        println!("{progress}");
        io::stdout().flush()?;
        sleep(Duration::from_millis(40)).await;
    }

    cluster.shutdown().await;
    Ok(())
}

fn projected_wall_seconds(offset_seconds: i64) -> AnyResult<i128> {
    let now = SystemTime::now();
    let projected = if offset_seconds >= 0 {
        now.checked_add(Duration::from_secs(offset_seconds as u64))
            .ok_or("positive wall-clock projection overflow")?
    } else {
        now.checked_sub(Duration::from_secs(offset_seconds.unsigned_abs()))
            .ok_or("negative wall-clock projection overflow")?
    };
    match projected.duration_since(UNIX_EPOCH) {
        Ok(duration) => Ok(i128::from(duration.as_secs())),
        Err(error) => Ok(-i128::from(error.duration().as_secs())),
    }
}

pub async fn execute_clock_faults(seed: u64) -> AnyResult<Value> {
    let mut cluster = Cluster::new()?;
    cluster.bootstrap_three_voters().await?;
    let offsets = [-31_536_000_i64, -86_400, 86_400, 31_536_000];
    let mut cases = Vec::new();
    let mut all_pass = true;

    for (ordinal, offset) in offsets.into_iter().enumerate() {
        let projected_before = projected_wall_seconds(offset)?;
        let started = Instant::now();
        let expected = format!("clock-{ordinal}-{offset}-{seed:016x}");
        let (committed_index, observed, current_leader) = cluster
            .write_and_read(400_000 + ordinal as u64, expected.clone())
            .await?;
        let monotonic_elapsed_ms = started.elapsed().as_millis();
        let projected_after = projected_wall_seconds(offset)?;
        let pass = observed.as_deref() == Some(expected.as_str())
            && cluster.nodes.contains_key(&current_leader)
            && projected_after >= projected_before
            && monotonic_elapsed_ms < 5_000;
        all_pass &= pass;
        cases.push(json!({
            "offset_seconds": offset,
            "projected_wall_before": projected_before.to_string(),
            "projected_wall_after": projected_after.to_string(),
            "monotonic_elapsed_ms": monotonic_elapsed_ms,
            "committed_index": committed_index,
            "observed": observed,
            "current_leader": current_leader,
            "status": if pass { "PASS" } else { "FAIL" }
        }));
    }

    let rpc_counts = cluster.router.rpc_counts().await;
    cluster.shutdown().await;
    Ok(json!({
        "schema": "heptabao.h02-clock-fault-result.v1",
        "candidate_id": "HB-DEP-RAFT-OPENRAFT",
        "version": "0.10.0-alpha.33",
        "seed": format!("0x{seed:016x}"),
        "status": if all_pass { "EXECUTED_PASS" } else { "EXECUTED_FAIL" },
        "cases": cases,
        "scope": {
            "real_openraft_nodes": 3,
            "real_client_write": true,
            "real_read_index": true,
            "wall_clock_fault_kind": "INJECTED_APPLICATION_WALL_CLOCK_PROJECTION",
            "candidate_runtime_timer_kind": "MONOTONIC_TOKIO_INSTANT",
            "kernel_wall_clock_changed": false,
            "per_node_clock_skew": false,
            "rpc_counts": rpc_counts
        },
        "promotion_effect": "BLOCK_PENDING_KERNEL_TIME_NAMESPACE_AND_PER_NODE_CLOCK_SKEW_REPRODUCTION",
        "qualification": false,
        "selection_effect": "NONE",
        "authority_effect": "NONE"
    }))
}
