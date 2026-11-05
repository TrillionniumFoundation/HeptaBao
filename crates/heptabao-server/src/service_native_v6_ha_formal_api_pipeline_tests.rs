//! Actual API origins for the formal three-voter component tests.
//! Every configured origin comes from a live, separately bound API TLS socket.
//! The same real Service/Raft owner handles its requests. Cold restart rebinds
//! that exact API endpoint; a missing-origin negative retains the old fixture.
use super::*;
use crate::http::formal_api_fixture::FormalApiListener;
use std::net::SocketAddr;
use std::ops::{Deref, DerefMut};

pub(super) struct FormalApiPipeline {
    inner: Pipeline,
    apis: Vec<Option<FormalApiListener>>,
    addresses: Vec<SocketAddr>,
}
impl Deref for FormalApiPipeline {
    type Target = Pipeline;
    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}
impl DerefMut for FormalApiPipeline {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.inner
    }
}
impl Drop for FormalApiPipeline {
    fn drop(&mut self) {
        // No per-request worker survives exchange(). Close public listeners
        // before Pipeline drops Services and then the actual Raft owners.
        for api in &mut self.apis {
            drop(api.take());
        }
    }
}
impl FormalApiPipeline {
    pub(super) fn exchange(
        &self,
        index: usize,
        bytes: &[u8],
        deadline: Instant,
        missing_forward: bool,
    ) -> TestResult<Zeroizing<Vec<u8>>> {
        let api = self
            .apis
            .get(index)
            .and_then(Option::as_ref)
            .ok_or("formal API listener is not running")?;
        let service = self
            .inner
            .services
            .get(index)
            .and_then(Option::as_ref)
            .ok_or("formal API Service is not running")?;
        api.exchange(service, bytes, deadline, missing_forward)
    }
    pub(super) fn stop_process(&mut self, index: usize) -> TestResult {
        drop(
            self.apis
                .get_mut(index)
                .ok_or("formal API node index")?
                .take(),
        );
        self.inner.stop_process(index)
    }
    pub(super) fn start_formal_process(&mut self, index: usize) -> TestResult {
        if self
            .apis
            .get(index)
            .ok_or("formal API node index")?
            .is_some()
        {
            return Err("formal API listener already running".into());
        }
        let api = FormalApiListener::bind(
            &self.inner.files.path,
            u64::try_from(index + 1)?,
            Some(self.addresses[index]),
        )?;
        verify_actual_origin(&self.inner.configs, index, &api)?;
        // Rebind before this node's actual HA owner starts, using its unchanged
        // cold configuration and the original disposable PKI.
        start_formal_process(&mut self.inner, index)?;
        self.apis[index] = Some(api);
        Ok(())
    }
}

fn verify_actual_origin(
    configs: &[HaProcessConfig],
    index: usize,
    api: &FormalApiListener,
) -> TestResult {
    let id = u64::try_from(index + 1)?;
    let origin = api.origin()?;
    let pin = hex(&api.leaf_sha256());
    for config in configs {
        let peer = config.peers.get(&id).ok_or("formal API peer is absent")?;
        assert_eq!(peer.api_address.as_deref(), Some(origin.as_str()));
        assert_eq!(peer.certificate_sha256, pin);
        assert_ne!(
            peer.address,
            api.address()?,
            "API and Raft own separate listeners"
        );
    }
    Ok(())
}

pub(super) fn formal_api_source() -> TestResult<FormalApiPipeline> {
    let mut files = Root::new();
    private_directory(&files.path)?;
    files.path = fs::canonicalize(&files.path)?;
    let mut service = Service::new(files.path.join("data"), &files.path.join("audit.jsonl"))?;
    let (key, admin) = {
        let _scope = scope();
        crate::service::tests::bootstrap_unmounted(&mut service)?
    };
    let key = Zeroizing::new(key);
    let admin = Zeroizing::new(admin);
    for (path, body, status) in [
        ("sys/init/ack", json!({}), 204),
        (
            "sys/mounts/secret",
            json!({"type":"kv","options":{"version":"2"},"description":"Versioned secrets"}),
            204,
        ),
        (
            "secret/data/pipeline/history",
            json!({"options":{"cas":0},"data":{"value":"seed-v5"}}),
            200,
        ),
    ] {
        let _scope = scope();
        expect(
            service.handle("POST", path, "", &admin, body),
            status,
            "formal-cold-seed",
        )?;
    }
    let state = service.state.as_ref().ok_or("formal cold seed state")?;
    assert!(state.engines.supports_native_v6_root_storage());
    assert!(state.auth.supports_native_v6_root_storage());
    assert!(!initialization_recovery_pending(&service.data_dir)?);
    let cluster_id = state.cluster_id.clone();
    let seed_identity = service
        .current_state_identity()
        .map_err(|_| "formal cold seed identity")?;
    assert!(matches!(seed_identity, StateIdentity::RecordsV5(_)));
    drop(service);
    recovered_api_pipeline(
        &files.path.join("data"),
        &cluster_id,
        key,
        admin,
        seed_identity,
    )
}

fn recovered_api_pipeline(
    seed: &Path,
    cluster_id: &str,
    key: Zeroizing<String>,
    admin: Zeroizing<String>,
    seed_identity: StateIdentity,
) -> TestResult<FormalApiPipeline> {
    let mut files = Root::new();
    private_directory(&files.path)?;
    files.path = fs::canonicalize(&files.path)?;
    for id in 1..=3 {
        let directory = files.path.join(format!("service-{id}"));
        private_directory(&directory)?;
        copy_cold_directory(seed, &directory.join("data"))?;
    }
    let pins = certificates(&files.path)?;
    let mut apis = Vec::new();
    for id in 1..=3 {
        let api = FormalApiListener::bind(&files.path, id, None)?;
        assert_eq!(api.leaf_sha256(), pins[&id]);
        apis.push(Some(api));
    }
    let mut configs = configurations(&files.path, cluster_id, &pins)?;
    let mut addresses = Vec::new();
    for (index, api) in apis.iter().enumerate() {
        let api = api.as_ref().ok_or("new formal API listener absent")?;
        let id = u64::try_from(index + 1)?;
        let origin = api.origin()?;
        addresses.push(api.address()?);
        for config in &mut configs {
            config
                .peers
                .get_mut(&id)
                .ok_or("new formal API peer absent")?
                .api_address = Some(origin.clone());
        }
        verify_actual_origin(&configs, index, api)?;
    }
    let mut pipeline = FormalApiPipeline {
        inner: Pipeline {
            configured_native_storage: false,
            files,
            configs,
            processes: vec![None, None, None],
            services: vec![None, None, None],
            key,
            admin,
            seed_identity,
        },
        apis,
        addresses,
    };
    // All three API origins have already been bound and pinned. Start the real
    // HA listeners with the same bootstrap order as recovered_pipeline().
    for index in [1, 2, 0] {
        start_formal_process(&mut pipeline.inner, index)?;
    }
    let leader = pipeline.ready_leader()?;
    for index in std::iter::once(leader).chain((0..3).filter(|index| *index != leader)) {
        pipeline.unseal(index)?;
    }
    for index in 0..3 {
        pipeline.with_service(index, |service| {
            assert!(service.native_candidate_profile.is_none());
            assert_eq!(
                service
                    .current_state_identity()
                    .map_err(|_| "new cold API seed identity")?,
                seed_identity
            );
            assert!(service.native_root.is_none());
            Ok(())
        })?;
    }
    Ok(pipeline)
}
