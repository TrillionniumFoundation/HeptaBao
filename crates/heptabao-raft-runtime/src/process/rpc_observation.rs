//! Payload-free, rate-limited diagnostics for failed Raft RPC attempts.
//! Observations never change consensus state, retry policy or authority.
use super::network::RaftRpcKind;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

pub(super) enum Stage {
    Transport,
    Decode,
    RemoteRaft,
}

pub(super) struct RpcAttempt {
    pub source: u64,
    pub target: u64,
    pub kind: RaftRpcKind,
    pub bytes: usize,
    pub budget: Duration,
    pub started: Instant,
}

impl RpcAttempt {
    pub fn failed(&self, stage: Stage) {
        static ORIGIN: OnceLock<Instant> = OnceLock::new();
        static LAST: [AtomicU64; 5] = [const { AtomicU64::new(u64::MAX) }; 5];
        let (slot, kind) = match self.kind {
            RaftRpcKind::AppendEntries => (0, "append"),
            RaftRpcKind::Vote => (1, "vote"),
            RaftRpcKind::PreVote => (2, "pre_vote"),
            RaftRpcKind::SnapshotChunk => (3, "snapshot"),
            RaftRpcKind::TransferLeader => (4, "transfer"),
        };
        let bucket = ORIGIN.get_or_init(Instant::now).elapsed().as_secs();
        let previous = LAST[slot].load(Ordering::Relaxed);
        if previous != u64::MAX && bucket <= previous
            || LAST[slot]
                .compare_exchange(previous, bucket, Ordering::Relaxed, Ordering::Relaxed)
                .is_err()
        {
            return;
        }
        let stage = match stage {
            Stage::Transport => "transport",
            Stage::Decode => "decode",
            Stage::RemoteRaft => "remote_raft",
        };
        // No error strings, payloads, paths or credentials enter this format.
        eprintln!(
            "heptabao-raft-rpc: kind={kind} source={} target={} bytes={} budget_ms={} elapsed_ms={} stage={stage}",
            self.source,
            self.target,
            self.bytes,
            self.budget.as_millis(),
            self.started.elapsed().as_millis()
        );
    }
}
