use std::error::Error;
use std::sync::Arc;

use openraft::{Config, Raft};
use openraft_memstore::{MemLogStore, MemStateMachine, TypeConfig, new_mem_store};

use super::network::{InMemoryNetworkFactory, InMemoryRouter, MemRaft};

pub(super) struct Node {
    pub raft: MemRaft,
    pub log_store: Arc<MemLogStore>,
    pub state_machine: Arc<MemStateMachine>,
}

impl Node {
    pub async fn start(
        id: u64,
        config: Arc<Config>,
        router: &InMemoryRouter,
    ) -> Result<Self, Box<dyn Error + Send + Sync>> {
        let (log_store, state_machine) = new_mem_store();
        let network = InMemoryNetworkFactory::new(id, router.clone());
        let raft = Raft::<TypeConfig, Arc<MemStateMachine>>::new(
            id,
            config,
            network,
            log_store.clone(),
            state_machine.clone(),
        )
        .await?;
        router.register(id, raft.clone()).await;
        Ok(Self {
            raft,
            log_store,
            state_machine,
        })
    }
}
