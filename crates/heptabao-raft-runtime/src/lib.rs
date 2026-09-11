#![forbid(unsafe_code)]

//! Durable three-voter OpenRaft consensus core for HeptaBao.
//!
//! The public façade accepts only bounded opaque sealed envelopes. Network RPC
//! transport and the server composition boundary remain separate work; the
//! in-process router is retained for deterministic consensus and fault tests.

// The imported OpenRaft API uses a non-panicking `DecomposeResult::unwrap` and
// a single-element set assertion in the bounded bootstrap helper. Keep the
// lint exception scoped to this private qualification module.
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod cluster;
mod network;
mod process;
// Historical hostile store tests use `expect` for fixture construction only;
// production store code remains under the workspace lint policy.
#[allow(clippy::expect_used)]
mod store;

use std::collections::BTreeMap;
use std::error::Error;
use std::fmt;
use std::path::Path;

use cluster::DurableCluster;

pub use process::{
    ProcessRaftNode, RaftPeerRpc, RaftRpcKind, RaftRpcService, RemoteNetworkFactory,
    RemoteRaftError,
};

const MAX_OPERATION_ID_BYTES: usize = 128;
const MAX_SEALED_ENVELOPE_BYTES: usize = 1024 * 1024;

#[derive(Clone, Eq, PartialEq)]
pub struct ReplicatedEnvelope {
    operation_id: String,
    digest: [u8; 32],
    sealed: Vec<u8>,
}

impl ReplicatedEnvelope {
    pub fn new(
        operation_id: impl Into<String>,
        digest: [u8; 32],
        sealed: Vec<u8>,
    ) -> Result<Self, RaftRuntimeError> {
        let operation_id = operation_id.into();
        if operation_id.is_empty()
            || operation_id.len() > MAX_OPERATION_ID_BYTES
            || !operation_id.bytes().all(|byte| {
                byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':')
            })
            || digest == [0; 32]
            || sealed.is_empty()
            || sealed.len() > MAX_SEALED_ENVELOPE_BYTES
        {
            return Err(RaftRuntimeError::InvalidEnvelope);
        }
        Ok(Self {
            operation_id,
            digest,
            sealed,
        })
    }

    fn encoded_status(&self) -> String {
        let mut encoded = String::with_capacity(
            8 + self.operation_id.len() + self.digest.len() * 2 + self.sealed.len() * 2,
        );
        encoded.push_str("hbr1:");
        encoded.push_str(&self.operation_id);
        encoded.push(':');
        append_hex(&mut encoded, &self.digest);
        encoded.push(':');
        append_hex(&mut encoded, &self.sealed);
        encoded
    }
}

impl fmt::Debug for ReplicatedEnvelope {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ReplicatedEnvelope")
            .field("operation_id", &"[REDACTED]")
            .field("digest", &"[REDACTED]")
            .field("sealed_bytes", &self.sealed.len())
            .finish()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CommitReceipt {
    pub leader_id: u64,
    pub log_index: u64,
    pub envelope_digest: [u8; 32],
}

#[derive(Debug, Eq, PartialEq)]
pub enum RaftRuntimeError {
    InvalidEnvelope,
    InvalidSerial,
    Shutdown,
    Consensus(String),
}

impl fmt::Display for RaftRuntimeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidEnvelope => {
                formatter.write_str("replicated envelope is invalid or unbounded")
            }
            Self::InvalidSerial => formatter.write_str("client serial must be nonzero"),
            Self::Shutdown => formatter.write_str("Raft runtime is shut down"),
            Self::Consensus(message) => write!(formatter, "Raft consensus failed: {message}"),
        }
    }
}

impl Error for RaftRuntimeError {}

pub struct RaftRuntime {
    cluster: Option<DurableCluster>,
}

impl fmt::Debug for RaftRuntime {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RaftRuntime")
            .field("running", &self.cluster.is_some())
            .finish()
    }
}

impl RaftRuntime {
    pub async fn bootstrap(root: impl AsRef<Path>) -> Result<Self, RaftRuntimeError> {
        let mut cluster = DurableCluster::new(root).map_err(consensus_error)?;
        cluster
            .bootstrap_three_voters()
            .await
            .map_err(consensus_error)?;
        Ok(Self {
            cluster: Some(cluster),
        })
    }

    pub async fn reopen(root: impl AsRef<Path>) -> Result<Self, RaftRuntimeError> {
        let mut cluster = DurableCluster::new(root).map_err(consensus_error)?;
        cluster
            .reopen_three_voters()
            .await
            .map_err(consensus_error)?;
        Ok(Self {
            cluster: Some(cluster),
        })
    }

    pub async fn leader(&self) -> Result<u64, RaftRuntimeError> {
        self.cluster()?
            .consensus_leader()
            .await
            .map_err(consensus_error)
    }

    pub async fn replicate(
        &self,
        client_serial: u64,
        envelope: &ReplicatedEnvelope,
    ) -> Result<CommitReceipt, RaftRuntimeError> {
        if client_serial == 0 {
            return Err(RaftRuntimeError::InvalidSerial);
        }
        let cluster = self.cluster()?;
        let leader = cluster.consensus_leader().await.map_err(consensus_error)?;
        let log_index = cluster
            .write(leader, client_serial, envelope.encoded_status())
            .await
            .map_err(consensus_error)?;
        cluster
            .wait_all_applied(log_index)
            .await
            .map_err(consensus_error)?;
        Ok(CommitReceipt {
            leader_id: cluster.consensus_leader().await.map_err(consensus_error)?,
            log_index,
            envelope_digest: envelope.digest,
        })
    }

    pub async fn ensure_linearizable(&self) -> Result<u64, RaftRuntimeError> {
        let cluster = self.cluster()?;
        let leader = cluster.consensus_leader().await.map_err(consensus_error)?;
        cluster.read_index(leader).await.map_err(consensus_error)?;
        Ok(leader)
    }

    pub async fn trigger_snapshot(&self, minimum_index: u64) -> Result<(), RaftRuntimeError> {
        let cluster = self.cluster()?;
        let leader = cluster.consensus_leader().await.map_err(consensus_error)?;
        cluster
            .trigger_snapshot(leader, minimum_index)
            .await
            .map_err(consensus_error)
    }

    pub async fn snapshot_status(&self) -> Result<BTreeMap<u64, (bool, u64)>, RaftRuntimeError> {
        Ok(self.cluster()?.snapshot_status().await)
    }

    pub async fn states_converged(&self) -> Result<bool, RaftRuntimeError> {
        Ok(self.cluster()?.all_states_equal().await)
    }

    pub async fn shutdown(mut self) -> Result<(), RaftRuntimeError> {
        let cluster = self.cluster.take().ok_or(RaftRuntimeError::Shutdown)?;
        cluster.shutdown().await.map_err(consensus_error)
    }

    fn cluster(&self) -> Result<&DurableCluster, RaftRuntimeError> {
        self.cluster.as_ref().ok_or(RaftRuntimeError::Shutdown)
    }
}

fn consensus_error(error: impl fmt::Display) -> RaftRuntimeError {
    RaftRuntimeError::Consensus(error.to_string())
}

fn append_hex(output: &mut String, bytes: &[u8]) {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    for byte in bytes {
        output.push(char::from(HEX[usize::from(byte >> 4)]));
        output.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::sync::atomic::{AtomicU64, Ordering};

    static TEST_SEQUENCE: AtomicU64 = AtomicU64::new(1);

    struct Root(std::path::PathBuf);

    impl Root {
        fn new() -> Self {
            Self(std::env::temp_dir().join(format!(
                "heptabao-raft-runtime-{}-{}",
                std::process::id(),
                TEST_SEQUENCE.fetch_add(1, Ordering::Relaxed)
            )))
        }
    }

    impl Drop for Root {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[tokio::test]
    async fn durable_three_node_restart_read_index_and_quorum_loss()
    -> Result<(), Box<dyn Error + Send + Sync>> {
        let root = Root::new();
        let runtime = RaftRuntime::bootstrap(&root.0).await?;
        let envelope = ReplicatedEnvelope::new(
            "operation-1",
            [7; 32],
            b"HBA1-synthetic-sealed-envelope".to_vec(),
        )?;
        let receipt = runtime.replicate(1, &envelope).await?;
        assert!(receipt.log_index > 0);
        assert!(runtime.states_converged().await?);
        runtime.trigger_snapshot(receipt.log_index).await?;
        let snapshot_status = runtime.snapshot_status().await?;
        assert_eq!(snapshot_status.len(), 3);
        assert!(
            snapshot_status
                .values()
                .all(|(present, generation)| *present && *generation > 0)
        );
        let artifacts = runtime.cluster()?.artifact_paths();
        assert_eq!(artifacts.len(), 9);
        assert!(artifacts.values().all(|path| path.is_file()));
        let rpc_counts = runtime.cluster()?.rpc_counts().await;
        assert!(rpc_counts.values().copied().sum::<u64>() > 0);
        let leader = runtime.ensure_linearizable().await?;
        let (rejected, committed_not_advanced) =
            runtime.cluster()?.exercise_partition(leader).await?;
        assert!(rejected);
        assert!(committed_not_advanced);
        runtime.shutdown().await?;

        let reopened = RaftRuntime::reopen(&root.0).await?;
        reopened.ensure_linearizable().await?;
        assert!(reopened.states_converged().await?);
        reopened.shutdown().await?;
        Ok(())
    }
}
