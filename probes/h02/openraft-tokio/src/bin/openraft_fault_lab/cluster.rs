use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::io::{self, Write};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use openraft::alias::LogIdOf;
use openraft::async_runtime::WatchReceiver;
use openraft::{Config, Raft, ReadPolicy, SnapshotPolicy};
use openraft_memstore::{ClientRequest, MemLogStore, MemStateMachine, TypeConfig, new_mem_store};
use serde_json::{Value, json};
use tokio::sync::Barrier;
use tokio::time::{sleep, timeout};

use super::network::{InMemoryNetworkFactory, InMemoryRouter, MemRaft};

pub type AnyResult<T> = Result<T, Box<dyn Error + Send + Sync>>;

const REGISTER_KEY: &str = "heptabao-h02-linearizable-register";
const HOSTILE_PHASE: &str = "ABOUT_TO_INSTALL_STALE_COMMITTED_SNAPSHOT";

struct Node {
    raft: MemRaft,
    log_store: Arc<MemLogStore>,
    state_machine: Arc<MemStateMachine>,
}

struct FaultCluster {
    router: InMemoryRouter,
    config: Arc<Config>,
    nodes: BTreeMap<u64, Node>,
}

impl FaultCluster {
    fn new() -> AnyResult<Self> {
        let config = Config {
            heartbeat_interval: 40,
            election_timeout_min: 120,
            election_timeout_max: 240,
            snapshot_policy: SnapshotPolicy::LogsSinceLast(3),
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

    async fn bootstrap_three_voters(&mut self) -> AnyResult<()> {
        self.start_node(1).await?;
        self.nodes[&1]
            .raft
            .initialize(BTreeMap::from([(1_u64, ())]))
            .await?;
        self.nodes[&1]
            .raft
            .wait(Some(Duration::from_secs(5)))
            .current_leader(1, "fault-lab single-node initialization")
            .await?;

        for id in [2_u64, 3] {
            self.start_node(id).await?;
            self.nodes[&1].raft.add_learner(id, (), true).await?;
        }

        self.nodes[&1]
            .raft
            .change_membership(BTreeSet::from([1_u64, 2, 3]), false)
            .await?;
        for node in self.nodes.values() {
            node.raft
                .wait(Some(Duration::from_secs(5)))
                .voter_ids([1_u64, 2, 3], "fault-lab three-voter membership")
                .await?;
        }
        Ok(())
    }

    async fn write_log_id(&self, serial: u64, value: String) -> AnyResult<LogIdOf<TypeConfig>> {
        let response = self.nodes[&1]
            .raft
            .client_write(ClientRequest {
                client: REGISTER_KEY.to_owned(),
                serial,
                status: value,
            })
            .await?;
        Ok(response.log_id)
    }

    async fn wait_all_applied(&self, index: u64) -> AnyResult<()> {
        for node in self.nodes.values() {
            node.raft
                .wait(Some(Duration::from_secs(5)))
                .applied_index_at_least(Some(index), "fault-lab replication")
                .await?;
        }
        Ok(())
    }

    async fn trigger_snapshot(&self, leader: u64, at_least: u64) -> AnyResult<()> {
        self.nodes[&leader].raft.trigger().snapshot().await?;
        self.nodes[&leader]
            .raft
            .wait(Some(Duration::from_secs(5)))
            .metrics(
                |metrics| {
                    metrics
                        .snapshot
                        .as_ref()
                        .is_some_and(|log_id| log_id.index >= at_least)
                },
                "fault-lab snapshot contains committed writes",
            )
            .await?;
        Ok(())
    }

    async fn shutdown(self) {
        for node in self.nodes.into_values() {
            let _ = node.raft.shutdown().await;
            drop(node.log_store);
        }
    }
}

fn operation_delay(seed: u64, salt: u32) -> Duration {
    Duration::from_millis(seed.rotate_left(salt) % 11)
}

struct WriteOperation {
    operation_id: &'static str,
    actor: &'static str,
    serial: u64,
    value: String,
    delay: Duration,
}

async fn record_write(
    operation: WriteOperation,
    raft: MemRaft,
    barrier: Arc<Barrier>,
    clock: Arc<AtomicU64>,
) -> Value {
    let WriteOperation {
        operation_id,
        actor,
        serial,
        value,
        delay,
    } = operation;
    let invoke = clock.fetch_add(1, Ordering::SeqCst) + 1;
    barrier.wait().await;
    sleep(delay).await;

    let (status, error) = match raft
        .client_write(ClientRequest {
            client: REGISTER_KEY.to_owned(),
            serial,
            status: value.clone(),
        })
        .await
    {
        Ok(_) => ("ok", None),
        Err(error) => ("failed", Some(error.to_string())),
    };
    let complete = clock.fetch_add(1, Ordering::SeqCst) + 1;
    json!({
        "id": operation_id,
        "client": actor,
        "kind": "write",
        "invoke": invoke,
        "complete": complete,
        "input": value,
        "output": Value::Null,
        "status": status,
        "node_id": 1,
        "error": error,
    })
}

async fn record_read(
    operation_id: &'static str,
    actor: &'static str,
    raft: MemRaft,
    state_machine: Arc<MemStateMachine>,
    barrier: Option<Arc<Barrier>>,
    clock: Arc<AtomicU64>,
    delay: Duration,
) -> Value {
    let invoke = clock.fetch_add(1, Ordering::SeqCst) + 1;
    if let Some(barrier) = barrier {
        barrier.wait().await;
    }
    sleep(delay).await;

    let (status, output, error) = match raft.ensure_linearizable(ReadPolicy::ReadIndex).await {
        Ok(_) => {
            let value = state_machine
                .get_state_machine()
                .await
                .client_status
                .get(REGISTER_KEY)
                .cloned();
            ("ok", value, None)
        }
        Err(error) => ("failed", None, Some(error.to_string())),
    };
    let complete = clock.fetch_add(1, Ordering::SeqCst) + 1;
    json!({
        "id": operation_id,
        "client": actor,
        "kind": "read",
        "invoke": invoke,
        "complete": complete,
        "input": Value::Null,
        "output": output,
        "status": status,
        "node_id": 1,
        "error": error,
    })
}

pub async fn execute_linearizability_history(seed: u64) -> AnyResult<Value> {
    let mut cluster = FaultCluster::new()?;
    cluster.bootstrap_three_voters().await?;

    let clock = Arc::new(AtomicU64::new(0));
    let barrier = Arc::new(Barrier::new(4));
    let value_a = format!("value-a-{seed:016x}");
    let value_b = format!("value-b-{seed:016x}");

    let write_a = tokio::spawn(record_write(
        WriteOperation {
            operation_id: "write-a",
            actor: "writer-a",
            serial: 100_001,
            value: value_a,
            delay: operation_delay(seed, 7),
        },
        cluster.nodes[&1].raft.clone(),
        barrier.clone(),
        clock.clone(),
    ));
    let write_b = tokio::spawn(record_write(
        WriteOperation {
            operation_id: "write-b",
            actor: "writer-b",
            serial: 100_002,
            value: value_b,
            delay: operation_delay(seed, 19),
        },
        cluster.nodes[&1].raft.clone(),
        barrier.clone(),
        clock.clone(),
    ));
    let read_overlap = tokio::spawn(record_read(
        "read-overlap",
        "reader-overlap",
        cluster.nodes[&1].raft.clone(),
        cluster.nodes[&1].state_machine.clone(),
        Some(barrier.clone()),
        clock.clone(),
        operation_delay(seed, 31),
    ));

    barrier.wait().await;

    let mut operations = vec![write_a.await?, write_b.await?, read_overlap.await?];
    operations.push(
        record_read(
            "read-final",
            "reader-final",
            cluster.nodes[&1].raft.clone(),
            cluster.nodes[&1].state_machine.clone(),
            None,
            clock,
            Duration::ZERO,
        )
        .await,
    );
    operations.sort_by_key(|operation| operation["invoke"].as_u64().unwrap_or(u64::MAX));

    let rpc_counts = cluster.router.rpc_counts().await;
    let history = json!({
        "schema": "heptabao.h02-linearizability-history.v1",
        "model": "single-register-v1",
        "candidate_id": "HB-DEP-RAFT-OPENRAFT",
        "version": "0.10.0-alpha.33",
        "profile_id": "HB-H02-FAULT-LAB-OPENRAFT-0_10_0_ALPHA_33",
        "seed": format!("0x{seed:016x}"),
        "initial_value": Value::Null,
        "operations": operations,
        "execution_scope": "REAL_OPENRAFT_READINDEX_SINGLE_REGISTER_HISTORY",
        "durability_class": "TEST_ONLY_IN_MEMORY_NO_PRODUCTION_CLAIM",
        "qualification": false,
        "selection_effect": "NONE",
        "authority_effect": "NONE",
        "metadata": {
            "real_raft_nodes": 3,
            "read_policy": "ReadIndex",
            "register_key": REGISTER_KEY,
            "rpc_counts": rpc_counts,
            "logical_clock": "process-local-monotonic-sequence",
            "history_checker_location": "scripts/h02_linearizability_checker_v1.py",
        },
    });
    cluster.shutdown().await;
    Ok(history)
}
