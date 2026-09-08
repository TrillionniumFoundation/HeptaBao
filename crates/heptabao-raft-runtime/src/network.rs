use std::collections::{BTreeMap, BTreeSet};
use std::future::Future;
use std::io::{self, Cursor};
use std::sync::Arc;

use openraft::OptionalSend;
use openraft::Raft;
use openraft::errors::{NetworkError, RPCError, ReplicationClosed, StreamingError, Unreachable};
use openraft::network::v2::RaftNetworkV2;
use openraft::network::{RPCOption, RaftNetworkFactory};
use openraft::raft::{
    AppendEntriesRequest, AppendEntriesResponse, SnapshotResponse, VoteRequest, VoteResponse,
};
use openraft::type_config::alias::{SnapshotOf, VoteOf};
use openraft_memstore::TypeConfig;
use tokio::sync::RwLock;

use super::store::DurableStateMachine;

pub type DurableRaft = Raft<TypeConfig, DurableStateMachine>;

#[derive(Clone, Default)]
pub struct DurableRouter {
    inner: Arc<RouterState>,
}

#[derive(Default)]
struct RouterState {
    nodes: RwLock<BTreeMap<u64, DurableRaft>>,
    blocked: RwLock<BTreeSet<(u64, u64)>>,
    paused: RwLock<BTreeSet<u64>>,
    rpc_counts: RwLock<BTreeMap<String, u64>>,
}

impl DurableRouter {
    pub async fn register(&self, id: u64, raft: DurableRaft) {
        self.inner.nodes.write().await.insert(id, raft);
    }

    pub async fn unregister(&self, id: u64) {
        self.inner.nodes.write().await.remove(&id);
    }

    pub async fn isolate(&self, id: u64) {
        let ids = self
            .inner
            .nodes
            .read()
            .await
            .keys()
            .copied()
            .collect::<Vec<_>>();
        let mut blocked = self.inner.blocked.write().await;
        for other in ids {
            if other != id {
                blocked.insert((id, other));
                blocked.insert((other, id));
            }
        }
    }

    pub async fn pause(&self, id: u64) {
        self.inner.paused.write().await.insert(id);
    }

    pub async fn resume(&self, id: u64) {
        self.inner.paused.write().await.remove(&id);
    }

    pub async fn heal_all(&self) {
        self.inner.blocked.write().await.clear();
        self.inner.paused.write().await.clear();
    }

    pub async fn rpc_counts(&self) -> BTreeMap<String, u64> {
        self.inner.rpc_counts.read().await.clone()
    }

    async fn count(&self, kind: &str) {
        let mut counts = self.inner.rpc_counts.write().await;
        *counts.entry(kind.to_owned()).or_default() += 1;
    }

    async fn target(&self, source: u64, target: u64) -> Result<DurableRaft, RPCError<TypeConfig>> {
        let paused = self.inner.paused.read().await;
        if paused.contains(&source) || paused.contains(&target) {
            return Err(unreachable(format!("node paused: {source}->{target}")));
        }
        drop(paused);

        if self.inner.blocked.read().await.contains(&(source, target)) {
            return Err(unreachable(format!("link blocked: {source}->{target}")));
        }

        self.inner
            .nodes
            .read()
            .await
            .get(&target)
            .cloned()
            .ok_or_else(|| unreachable(format!("unknown target node: {target}")))
    }
}

fn unreachable(message: String) -> RPCError<TypeConfig> {
    let error = io::Error::new(io::ErrorKind::ConnectionRefused, message);
    RPCError::Unreachable(Unreachable::new(&error))
}

#[derive(Clone)]
pub struct DurableNetworkFactory {
    source: u64,
    router: DurableRouter,
}

impl DurableNetworkFactory {
    pub fn new(source: u64, router: DurableRouter) -> Self {
        Self { source, router }
    }
}

impl RaftNetworkFactory<TypeConfig> for DurableNetworkFactory {
    type Network = DurableNetwork;

    async fn new_client(&mut self, target: u64, _node: &()) -> Self::Network {
        DurableNetwork {
            source: self.source,
            target,
            router: self.router.clone(),
        }
    }
}

pub struct DurableNetwork {
    source: u64,
    target: u64,
    router: DurableRouter,
}

impl DurableNetwork {
    async fn target(&self, rpc_kind: &str) -> Result<DurableRaft, RPCError<TypeConfig>> {
        self.router.count(rpc_kind).await;
        self.router.target(self.source, self.target).await
    }
}

impl RaftNetworkV2<TypeConfig> for DurableNetwork {
    type SnapshotData = Cursor<Vec<u8>>;

    async fn append_entries(
        &mut self,
        request: AppendEntriesRequest<TypeConfig>,
        _option: RPCOption,
    ) -> Result<AppendEntriesResponse<TypeConfig>, RPCError<TypeConfig>> {
        let target = self.target("append_entries").await?;
        target
            .append_entries(request)
            .await
            .map_err(|error| RPCError::Unreachable(Unreachable::new(&error)))
    }

    async fn vote(
        &mut self,
        request: VoteRequest<TypeConfig>,
        _option: RPCOption,
    ) -> Result<VoteResponse<TypeConfig>, RPCError<TypeConfig>> {
        let target = self.target("vote").await?;
        target
            .vote(request)
            .await
            .map_err(|error| RPCError::Unreachable(Unreachable::new(&error)))
    }

    async fn pre_vote(
        &mut self,
        request: VoteRequest<TypeConfig>,
        _option: RPCOption,
    ) -> Result<VoteResponse<TypeConfig>, RPCError<TypeConfig>> {
        let target = self.target("pre_vote").await?;
        target
            .pre_vote(request)
            .await
            .map_err(|error| RPCError::Unreachable(Unreachable::new(&error)))
    }

    async fn full_snapshot(
        &mut self,
        vote: VoteOf<TypeConfig>,
        snapshot: SnapshotOf<TypeConfig, Self::SnapshotData>,
        cancel: impl Future<Output = ReplicationClosed> + OptionalSend + 'static,
        _option: RPCOption,
    ) -> Result<SnapshotResponse<TypeConfig>, StreamingError<TypeConfig>> {
        self.router.count("full_snapshot").await;
        let target = self
            .router
            .target(self.source, self.target)
            .await
            .map_err(StreamingError::from)?;
        tokio::pin!(cancel);
        tokio::select! {
            closed = &mut cancel => Err(StreamingError::Closed(closed)),
            result = target.install_full_snapshot(vote, snapshot) => {
                result.map_err(|error| StreamingError::Network(NetworkError::new(&error)))
            }
        }
    }
}
