//! Shared formal three-node NativeV6Raft fixture for native service HA suites.
//! Each call owns fresh files, TLS peers, services and Raft processes. The inner
//! Pipeline retains its original service-before-process Drop cleanup order.
use super::*;
use crate::configuration::NativeStorageProfile;
use std::ops::{Deref, DerefMut};

pub(super) struct FormalPipeline {
    inner: Pipeline,
    servers: Vec<crate::http::Config>,
}

impl Deref for FormalPipeline {
    type Target = Pipeline;
    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl DerefMut for FormalPipeline {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.inner
    }
}

impl FormalPipeline {
    pub(super) fn start() -> TestResult<Self> {
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
            pipeline.assert_history(index, &[(1, "seed-v5")])?;
            pipeline.with_service(index, |service| {
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

    pub(super) fn start_formal_process(&mut self, index: usize) -> TestResult {
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
