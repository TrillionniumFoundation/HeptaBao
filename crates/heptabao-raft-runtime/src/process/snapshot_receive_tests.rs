//! Receive-prefix lifetime tests. No prefix is a durable snapshot or an
//! applied-log observation; the real install path is covered by replication_tests.
use super::snapshot::{SnapshotChunkAck, SnapshotChunkWire, crc32, snapshot_transfer_id};
use super::*;
use futures::future::BoxFuture;
use std::collections::BTreeSet;
use std::sync::Arc;
use std::time::Duration;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

#[derive(Debug)]
struct NoNetwork;
impl RaftPeerRpc for NoNetwork {
    fn exchange(
        &self,
        _source: u64,
        _target: u64,
        _kind: RaftRpcKind,
        _payload: Vec<u8>,
        _timeout: Duration,
    ) -> BoxFuture<'static, Result<Vec<u8>, RemoteRaftError>> {
        Box::pin(async { Err(RemoteRaftError::InvalidTopology) })
    }
}

fn part(
    source: u64,
    term: u64,
    index: u64,
    fill: u8,
    ordinal: u32,
) -> TestResult<SnapshotChunkWire> {
    let vote = openraft::Vote::new_committed(term, source);
    let meta = openraft::SnapshotMeta {
        last_log_id: Some(serde_json::from_value(serde_json::json!({
            "leader_id": { "term": term, "node_id": source }, "index": index,
        }))?),
        last_membership: Default::default(),
    };
    Ok(SnapshotChunkWire {
        transfer_id: snapshot_transfer_id(
            &serde_json::to_vec(&meta)?,
            &serde_json::to_vec(&vote)?,
            96,
        ),
        ordinal,
        total_chunks: 3,
        vote: (ordinal == 0).then_some(vote),
        meta: (ordinal == 0).then_some(meta),
        total_bytes: 96,
        whole_crc32: crc32(&[fill; 96]),
        chunk_crc32: crc32(&[fill; 32]),
        chunk: vec![fill; 32],
    })
}

async fn receiver(label: &str) -> TestResult<(std::path::PathBuf, ProcessRaftNode)> {
    let path = std::env::temp_dir().join(format!(
        "heptabao-snapshot-receive-{label}-{}",
        std::process::id(),
    ));
    let factory = RemoteNetworkFactory::new(12, BTreeSet::from_iter(1..=12), Arc::new(NoNetwork))?;
    let node = ProcessRaftNode::create(&path, 12, factory).await?;
    Ok((path, node))
}

async fn send(
    service: &RaftRpcService,
    source: u64,
    request: SnapshotChunkWire,
) -> TestResult<SnapshotChunkAck> {
    let bytes = service
        .handle(
            source,
            RaftRpcKind::SnapshotChunk,
            serde_json::to_vec(&request)?,
        )
        .await?;
    Ok(serde_json::from_slice(&bytes)?)
}

#[tokio::test]
async fn rejected_snapshot_prefixes_preserve_admitted_progress() -> TestResult {
    let (path, node) = receiver("rejections").await?;
    let service = node.rpc_service();
    let result = async {
        assert_eq!(
            send(&service, 1, part(1, 4, 20, 8, 0)?).await?.next_ordinal,
            1
        );
        let mut malformed = vec![
            part(2, 4, 21, 9, 0)?, // Wrong authenticated sender.
            part(1, 3, 99, 7, 0)?, // Older vote, even with a larger index.
            part(1, 4, 19, 7, 0)?, // Older snapshot from the same leader.
            part(1, 4, 20, 9, 0)?, // Same metadata, conflicting whole content.
        ];
        let mut bad_id = part(1, 4, 21, 9, 0)?;
        bad_id.transfer_id = "not-bound-to-metadata".into();
        malformed.push(bad_id);
        let mut oversized = part(1, 4, 20, 8, 0)?;
        oversized.chunk = vec![8; 97];
        oversized.chunk_crc32 = crc32(&oversized.chunk);
        malformed.push(oversized);
        let mut missing_meta = part(1, 4, 20, 8, 0)?;
        missing_meta.meta = None;
        malformed.push(missing_meta);
        let mut truncated = part(1, 4, 20, 8, 0)?;
        truncated.total_chunks = 1;
        malformed.push(truncated);
        let mut uncommitted = part(1, 5, 21, 9, 0)?;
        uncommitted.vote = Some(openraft::Vote::new(5, 1));
        uncommitted.transfer_id = snapshot_transfer_id(
            &serde_json::to_vec(uncommitted.meta.as_ref().ok_or("metadata")?)?,
            &serde_json::to_vec(uncommitted.vote.as_ref().ok_or("vote")?)?,
            96,
        );
        malformed.push(uncommitted);
        for (case, request) in malformed.into_iter().enumerate() {
            assert!(
                send(&service, 1, request).await.is_err(),
                "malformed prefix {case}"
            );
        }
        let ack = send(&service, 1, part(1, 4, 20, 8, 1)?).await?;
        assert_eq!(ack.next_ordinal, 2);
        assert!(!ack.complete && ack.result.is_none());
        assert_eq!(node.local_leader_observation()?.applied_index, None);
        Ok(())
    }
    .await;
    node.shutdown().await?;
    std::fs::remove_dir_all(path)?;
    result
}

#[tokio::test]
async fn newer_leader_reclaims_incomplete_snapshot_slots_and_fences_old_chunks() -> TestResult {
    let (path, node) = receiver("leader-change").await?;
    let service = node.rpc_service();
    let result = async {
        for source in 1..=10_u64 {
            let fill = u8::try_from(source)?;
            let ack = send(&service, source, part(source, source, source + 4, fill, 0)?).await?;
            assert_eq!(ack.next_ordinal, 1);
            assert!(!ack.complete && ack.result.is_none());
            if source > 1 {
                let old = source - 1;
                assert!(
                    send(&service, old, part(old, old, old + 4, fill - 1, 1)?)
                        .await
                        .is_err()
                );
                assert!(
                    send(&service, old, part(old, old, 1000, fill - 1, 0)?)
                        .await
                        .is_err()
                );
            }
        }
        let ack = send(&service, 10, part(10, 10, 14, 10, 1)?).await?;
        assert_eq!(ack.next_ordinal, 2);
        assert!(!ack.complete && ack.result.is_none());
        assert_eq!(node.local_leader_observation()?.applied_index, None);
        Ok(())
    }
    .await;
    node.shutdown().await?;
    std::fs::remove_dir_all(path)?;
    result
}

#[tokio::test]
async fn identical_snapshot_restarts_after_lost_ack_without_installing_a_prefix() -> TestResult {
    let (path, node) = receiver("lost-ack").await?;
    let service = node.rpc_service();
    let result = async {
        for _ in 0..12 {
            assert_eq!(
                send(&service, 1, part(1, 1, 8, 5, 0)?).await?.next_ordinal,
                1
            );
            let ack = send(&service, 1, part(1, 1, 8, 5, 1)?).await?;
            assert_eq!(ack.next_ordinal, 2);
            assert!(!ack.complete && ack.result.is_none());
        }
        assert_eq!(node.local_leader_observation()?.applied_index, None);
        Ok(())
    }
    .await;
    node.shutdown().await?;
    std::fs::remove_dir_all(path)?;
    result
}
