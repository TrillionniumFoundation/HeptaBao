//! Normal NativeV6Raft wrapping: actual three-node OpenRaft, peer TLS,
//! forwarding, persisted consumption and cold reopen. These process-local tests
//! do not claim a public HTTPS socket or physical-host SIGKILL qualification.
use super::*;
use crate::configuration::NativeStorageProfile;
use std::ops::{Deref, DerefMut};

#[path = "service_native_response_wrapping_ha_tests.rs"]
mod composition_tests;

// Observation belongs to this test fixture and shares its sole authenticated
// handler registration. It receives only an immutable request reference.
type WrappingForwardObserver =
    Arc<dyn Fn(&crate::ha_forward::ForwardRequest) -> Option<Response> + Send + Sync>;

struct WrappingPipeline {
    inner: Pipeline,
    servers: Vec<crate::http::Config>,
    forward_observer: Option<WrappingForwardObserver>,
}

impl WrappingPipeline {
    #[allow(clippy::too_many_arguments)]
    fn wrapped_call(
        &self,
        index: usize,
        method: &str,
        path: &str,
        token: &str,
        body: Value,
        ttl: Option<u64>,
    ) -> TestResult<Response> {
        let started = Instant::now();
        let until = started + REQUEST_BUDGET;
        let _scope = RequestDeadlineScope::enter(until);
        let service = self.services[index]
            .as_ref()
            .ok_or("formal wrapping Service absent")?;
        let mut writer =
            lock_until(service, until).map_err(|_| "formal wrapping Service lock deadline")?;
        let ingress = crypto::random::<16>().map_err(std::io::Error::other)?;
        let _ingress = crate::auth::IngressReplyScope::listener(&ingress);
        let execution = writer.begin_request_before(
            ServiceRequest {
                method,
                path,
                namespace: "",
                token,
                body,
                wrap_ttl_seconds: ttl,
                origin_peer: None,
                client_certificates: None,
            },
            until,
            // This is the original public client ingress on any node. Only
            // the authenticated peer handler below is already forwarded.
            false,
        );
        let response = writer.finish_synchronous_request(execution);
        errors_only(path, &response);
        if started.elapsed() >= REQUEST_BUDGET {
            return Err("formal wrapping original 15-second request exceeded".into());
        }
        assert!(writer.pending_native_auth_delivery.is_none());
        assert!(writer.pending_ordinary_kv_authority.is_none());
        Ok(response)
    }
    fn wrap(&self, index: usize) -> TestResult<Zeroizing<String>> {
        let mut response = expect(
            self.wrapped_call(
                index,
                "POST",
                "sys/wrapping/wrap",
                self.admin(),
                json!({"value":"formal-ha-wrapping-private-value"}),
                Some(120),
            )?,
            200,
            "formal-HA-original-wrap",
        )?;
        assert!(response.body["data"].is_null());
        assert!(
            !response
                .body
                .to_string()
                .contains("formal-ha-wrapping-private-value")
        );
        secret_field(&mut response, "/wrap_info/token")
    }
}

#[test]
fn formal_native_wrapping_ha_forwarded_rewrap_election_cold_and_single_unwrap() -> TestResult {
    let mut pipeline = WrappingPipeline::start()?;
    let first = pipeline.ready_leader()?;
    let follower = (first + 1) % 3;
    let token = pipeline.wrap(follower)?;
    let initial = expect(
        pipeline.call(follower, "GET", "sys/wrapping/lookup", &token, json!({}))?,
        200,
        "formal-HA-ordinary-lookup",
    )?;
    assert_eq!(initial.body["data"]["creation_path"], "sys/wrapping/wrap");
    assert_eq!(initial.body["data"]["creation_ttl"], 120);
    pipeline.stop_process(first)?;
    let next = pipeline.ready_leader()?;
    assert_ne!(next, first);
    let mut rewrapped = expect(
        pipeline.call(
            next,
            "POST",
            "sys/wrapping/rewrap",
            pipeline.admin(),
            json!({"token":token.as_str()}),
        )?,
        200,
        "formal-HA-actual-rewrap-after-election",
    )?;
    assert_eq!(
        rewrapped.body["wrap_info"]["creation_path"],
        "sys/wrapping/wrap"
    );
    assert_eq!(rewrapped.body["wrap_info"]["ttl"], 120);
    let replacement = secret_field(&mut rewrapped, "/wrap_info/token")?;
    assert!(token.as_str() != replacement.as_str());
    expect(
        pipeline.call(next, "GET", "sys/wrapping/lookup", &token, json!({}))?,
        400,
        "formal-HA-old-ordinary-wrapper-is-spent",
    )?;
    pipeline.start_formal_process(first)?;
    pipeline.wait_cold_native_readindex_ready(first)?;
    pipeline.unseal(first)?;
    let unwrapped = expect(
        pipeline.call(
            first,
            "POST",
            "sys/wrapping/unwrap",
            &replacement,
            json!({}),
        )?,
        200,
        "formal-HA-cold-actual-self-unwrap",
    )?;
    assert_eq!(
        unwrapped.body["data"]["value"],
        "formal-ha-wrapping-private-value"
    );
    assert!(unwrapped.unwrapped_json.is_some());
    pipeline.stop_process(first)?;
    pipeline.start_formal_process(first)?;
    pipeline.wait_cold_native_readindex_ready(first)?;
    pipeline.unseal(first)?;
    let denied = expect(
        pipeline.call(
            first,
            "POST",
            "sys/wrapping/unwrap",
            &replacement,
            json!({}),
        )?,
        400,
        "formal-HA-cold-once-use-cannot-replay",
    )?;
    assert!(denied.body.get("data").is_none());
    assert!(denied.unwrapped_json.is_none());
    pipeline.with_service(first, |service| {
        assert!(service.native_root.is_some() && service.record_root.is_none());
        assert!(service.native_candidate_profile.is_none());
        let auth = &service.state.as_ref().ok_or("formal wrapping state")?.auth;
        assert!(auth.validate_wrapping_state().is_ok());
        assert!(auth.supports_native_v6_root_storage());
        Ok(())
    })?;
    pipeline.assert_history(first, &[(1, "seed-v5")])?;
    Ok(())
}

#[test]
fn formal_native_wrapping_ha_lost_actual_quorum_neither_issues_nor_consumes() -> TestResult {
    let mut pipeline = WrappingPipeline::start()?;
    let leader = pipeline.ready_leader()?;
    let token = pipeline.wrap(leader)?;
    let before = pipeline.with_service(leader, |service| {
        service
            .current_state_identity()
            .map_err(|_| "formal wrapping identity".into())
    })?;
    for node in (0..3).filter(|node| *node != leader) {
        pipeline.stop_process(node)?;
    }
    let denied = expect(
        pipeline.wrapped_call(
            leader,
            "POST",
            "sys/wrapping/wrap",
            pipeline.admin(),
            json!({"value":"must-not-be-published"}),
            Some(120),
        )?,
        503,
        "formal-HA-no-quorum-original-wrapper-issuance",
    )?;
    assert!(denied.body.get("wrap_info").is_none());
    assert!(denied.body.get("data").is_none());
    let denied = expect(
        pipeline.call(leader, "POST", "sys/wrapping/unwrap", &token, json!({}))?,
        503,
        "formal-HA-no-quorum-original-wrapper-consumption",
    )?;
    assert!(denied.body.get("data").is_none());
    assert!(denied.unwrapped_json.is_none());
    pipeline.with_service(leader, |service| {
        assert!(service.current_state_identity().map_err(|_| "identity")? == before);
        assert!(service.pending_native_auth_delivery.is_none());
        Ok(())
    })?;
    for node in (0..3).filter(|node| *node != leader) {
        pipeline.start_formal_process(node)?;
        pipeline.wait_cold_native_readindex_ready(node)?;
        pipeline.unseal(node)?;
    }
    let available = pipeline.ready_leader()?;
    expect(
        pipeline.call(available, "GET", "sys/wrapping/lookup", &token, json!({}))?,
        200,
        "formal-HA-uncommitted-unwrap-retains-original-target",
    )?;
    let released = expect(
        pipeline.call(available, "POST", "sys/wrapping/unwrap", &token, json!({}))?,
        200,
        "formal-HA-restored-quorum-ordinary-once-use",
    )?;
    assert_eq!(
        released.body["data"]["value"],
        "formal-ha-wrapping-private-value"
    );
    pipeline.assert_history(available, &[(1, "seed-v5")])?;
    Ok(())
}

impl Deref for WrappingPipeline {
    type Target = Pipeline;
    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl DerefMut for WrappingPipeline {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.inner
    }
}

impl WrappingPipeline {
    fn start() -> TestResult<Self> {
        Self::start_with_seed_history(true)
    }

    fn start_empty() -> TestResult<Self> {
        Self::start_with_seed_history(false)
    }

    fn start_with_seed_history(seed_history: bool) -> TestResult<Self> {
        Self::start_with_seed_history_and_observer(seed_history, None)
    }

    fn start_empty_with_observer(observer: WrappingForwardObserver) -> TestResult<Self> {
        Self::start_with_seed_history_and_observer(false, Some(observer))
    }

    fn start_with_seed_history_and_observer(
        seed_history: bool,
        forward_observer: Option<WrappingForwardObserver>,
    ) -> TestResult<Self> {
        let mut files = Root::new();
        private_directory(&files.path)?;
        files.path = fs::canonicalize(&files.path)?;
        let seed = files.path.join("formal-seed");
        private_directory(&seed)?;
        let mut service = Service::new(seed.join("data"), &seed.join("audit.jsonl"))?;
        service.configure_native_v6_storage(NativeStorageProfile::File)?;
        let (key, admin) = {
            let _scope = scope();
            let mut initialized = expect(
                service.handle(
                    "POST",
                    "sys/init",
                    "",
                    "",
                    json!({
                        "secret_shares":1,"secret_threshold":1
                    }),
                ),
                200,
                "formal-raft-real-Shamir-init",
            )?;
            let key = secret_field(&mut initialized, "/keys/0")?;
            let admin = secret_field(&mut initialized, "/root_token")?;
            erase_json(&mut initialized.body);
            expect(
                service.handle("POST", "sys/unseal", "", "", json!({"key":key.as_str()})),
                200,
                "formal-raft-real-Shamir-unseal",
            )?;
            expect(
                service.handle("POST", "sys/init/ack", "", &admin, json!({})),
                204,
                "formal-raft-init-ack",
            )?;
            expect(
                service.handle(
                    "POST",
                    "sys/mounts/secret",
                    "",
                    &admin,
                    json!({"type":"kv","options":{"version":"2"}}),
                ),
                204,
                "formal-raft-seed-KV2-mount",
            )?;
            if seed_history {
                expect(
                    service.handle(
                        "POST",
                        "secret/data/pipeline/history",
                        "",
                        &admin,
                        json!({"options":{"cas":0},"data":{"value":"seed-v5"}}),
                    ),
                    200,
                    "formal-raft-seed-history",
                )?;
            }
            (key, admin)
        };
        let cluster_id = service
            .state
            .as_ref()
            .ok_or("formal seed state")?
            .cluster_id
            .clone();
        let seed_identity = service
            .current_state_identity()
            .map_err(|_| "formal seed identity")?;
        assert!(matches!(
            seed_identity,
            crate::state_record_root::StateIdentity::RecordsV5(_)
        ));
        assert!(!initialization_recovery_pending(&service.data_dir)?);
        drop(service);
        for id in 1..=3 {
            let directory = files.path.join(format!("service-{id}"));
            private_directory(&directory)?;
            copy_cold_directory(&seed.join("data"), &directory.join("state"))?;
        }
        let pins = certificates(&files.path)?;
        let mut configs = configurations(&files.path, &cluster_id, &pins)?;
        let listeners = (0..3)
            .map(|_| TcpListener::bind("127.0.0.1:0"))
            .collect::<Result<Vec<_>, _>>()?;
        let api_addresses = listeners
            .iter()
            .map(TcpListener::local_addr)
            .collect::<Result<Vec<_>, _>>()?;
        for (index, config) in configs.iter_mut().enumerate() {
            config.raft_dir = files
                .path
                .join(format!("service-{}", index + 1))
                .join("raft");
            for (id, peer) in &mut config.peers {
                peer.cluster_address = Some(format!("https://{}", peer.address));
                peer.api_address = Some(format!("https://{}", api_addresses[(*id - 1) as usize]));
            }
        }
        let servers = configs
            .iter()
            .enumerate()
            .map(|(index, config)| {
                let directory = files.path.join(format!("service-{}", index + 1));
                let peer = config
                    .peers
                    .get(&config.node_id)
                    .ok_or("formal local peer")?;
                let bytes = serde_json::to_vec(&json!({
                    "listen":api_addresses[index],
                    "data_dir":directory.join("state"),
                    "audit_file":directory.join("audit.jsonl"),
                    "tls_cert_file":config.cert_file,
                    "tls_key_file":config.key_file,
                    "storage":{"native_v6_raft":{
                        "path":directory,
                        "node_id":peer.node_name,
                        "cluster_addr":peer.cluster_address,
                        "api_addr":peer.api_address
                    }}
                }))?;
                let server = crate::configuration::parse_server(&bytes)?;
                crate::configuration::validate_storage(&server, Some(config))?;
                Ok(server)
            })
            .collect::<TestResult<Vec<_>>>()?;
        drop(listeners);
        let mut pipeline = Self {
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
            servers,
            forward_observer,
        };
        for index in [1, 2, 0] {
            pipeline.start_formal_process(index)?;
        }
        let leader = pipeline.ready_leader()?;
        for index in std::iter::once(leader).chain((0..3).filter(|index| *index != leader)) {
            pipeline.unseal(index)?;
        }
        expect(
            pipeline.call(
                leader,
                "POST",
                native_storage::ACTIVATE_PATH,
                pipeline.admin(),
                json!({}),
            )?,
            204,
            "formal-raft-public-activation",
        )?;
        for index in 0..3 {
            if seed_history {
                pipeline.assert_history(index, &[(1, "seed-v5")])?;
            } else {
                expect(
                    pipeline.call(
                        index,
                        "GET",
                        "secret/metadata/pipeline/history",
                        pipeline.admin(),
                        json!({}),
                    )?,
                    404,
                    "formal-raft-empty-history",
                )?;
            }
            pipeline.with_service(index, |service| {
                if !seed_history {
                    assert!(
                        !service
                            .state
                            .as_ref()
                            .ok_or("formal empty seed state")?
                            .engines
                            .has_kv2_lossless_state()
                    );
                }
                assert!(matches!(
                    service.native_storage_profile,
                    Some(NativeStorageProfile::Raft)
                ));
                assert!(service.native_candidate_profile.is_none());
                assert!(service.native_root.is_some() && service.record_root.is_none());
                Ok(())
            })?;
        }
        Ok(pipeline)
    }

    fn start_formal_process(&mut self, index: usize) -> TestResult {
        if self.processes[index].is_some() || self.services[index].is_some() {
            return Err("formal pipeline process or Service already owned".into());
        }
        let process = Arc::new(Mutex::new(HaProcess::start_with_storage(
            self.configs[index].clone(),
            &self.servers[index],
        )?));
        let server = &self.servers[index];
        let mut service =
            Service::new_with_ha(server.data_dir.clone(), &server.audit_file, process.clone())?;
        service.configure_native_v6_storage(NativeStorageProfile::Raft)?;
        let service = Arc::new(Mutex::new(service));
        let weak = Arc::downgrade(&service);
        let forward_observer = self.forward_observer.clone();
        process
            .lock()
            .map_err(|_| "formal process poisoned")?
            .register_forward_handler(Arc::new(move |mut request| {
                let Some(service) = weak.upgrade() else {
                    return Response::error(503, "native pipeline forwarded owner closed");
                };
                let Some(deadline) = crate::ha_forward_completion::CompletionScope::deadline()
                else {
                    return Response::error(
                        503,
                        "native pipeline original forward deadline absent",
                    );
                };
                let _scope = RequestDeadlineScope::enter(deadline);
                let Ok(mut writer) = lock_until(&service, deadline) else {
                    return Response::error(503, "native pipeline forwarded owner unavailable");
                };
                if let Some(response) = forward_observer
                    .as_ref()
                    .and_then(|observer| observer(&request))
                {
                    return response;
                }
                let execution = writer.begin_request_before(
                    ServiceRequest {
                        method: &request.method,
                        path: &request.path,
                        namespace: &request.namespace,
                        token: &request.token,
                        body: std::mem::take(&mut request.body),
                        wrap_ttl_seconds: request.wrap_ttl_seconds,
                        origin_peer: request.origin_peer,
                        client_certificates: request.client_certificates.take(),
                    },
                    deadline,
                    true,
                );
                let response = writer.finish_synchronous_request(execution);
                writer.seal_forward_completion(&response);
                request.token.zeroize();
                response
            }))?;
        self.processes[index] = Some(process);
        self.services[index] = Some(service);
        Ok(())
    }
}

#[path = "service_native_controlgroups_271_namespace_ha_tests.rs"]
mod controlgroups_namespace_tests;

#[path = "service_native_empty_snapshot_floor_ha_tests.rs"]
mod empty_snapshot_floor_tests;

#[path = "service_native_kv2_write_forward_ha_tests.rs"]
mod kv2_write_forward_tests;

#[path = "service_native_remount_ha_tests.rs"]
mod native_remount_tests;
