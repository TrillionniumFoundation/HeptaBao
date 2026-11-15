//! Normal NativeV6Raft startup, actual three-node OpenRaft and pinned peer TLS.
//! Service::handle is the public dispatcher; no public HTTPS listener or
//! physical-host failure qualification is claimed by these process-local tests.
use super::*;
use crate::configuration::NativeStorageProfile;
use crate::service::native_raft_observation::tests::AuditFault;
use std::ops::{Deref, DerefMut};

const READS: [&str; 5] = [
    "sys/storage/raft/configuration",
    "sys/storage/raft/snapshot-status",
    "sys/storage/raft/linearizable-read",
    "sys/storage/raft/autopilot/state",
    "sys/storage/raft/autopilot/configuration",
];

struct FormalPipeline {
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
    fn start() -> TestResult<Self> {
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

    fn token(
        &self,
        index: usize,
        name: &str,
        capabilities: &str,
        ttl: &str,
    ) -> TestResult<Zeroizing<String>> {
        let policy = format!("path \"sys/storage/raft/*\" {{ capabilities = [{capabilities}] }}");
        expect(
            self.call(
                index,
                "PUT",
                &format!("sys/policies/acl/{name}"),
                self.admin(),
                json!({"policy":policy}),
            )?,
            204,
            "formal-Raft-read-policy",
        )?;
        let mut issued = expect(self.call(index, "POST", "auth/token/create", self.admin(),
            json!({"policies":[name],"no_default_policy":true,"ttl":ttl,"explicit_max_ttl":ttl}))?,
            200, "formal-Raft-scoped-token")?;
        let token = secret_field(&mut issued, "/auth/client_token")?;
        erase_json(&mut issued.body);
        Ok(token)
    }

    fn read_all(&self, index: usize, leader: usize, token: &str) -> TestResult {
        let before = self.with_service(index, |service| {
            Ok(service.native_root.as_ref().ok_or("native root")?.clone())
        })?;
        for path in READS {
            let response = expect(self.call(index, "GET", path, token, json!({}))?, 200, path)?;
            assert!(response.body["data"].is_object(), "{path}");
            assert!(response.body.get("auth").is_none());
            match path {
                "sys/storage/raft/configuration" => {
                    let config = &response.body["data"]["config"];
                    assert_eq!(config["committed"], true);
                    assert_eq!(config["joint"], false);
                    assert!(config["index"].as_u64().is_some_and(|index| index > 0));
                    let servers = config["servers"]
                        .as_array()
                        .ok_or("configuration servers")?;
                    assert_eq!(servers.len(), 3);
                    for (node, server) in servers.iter().enumerate() {
                        assert_eq!(server["node_id"], (node + 1).to_string());
                        assert_eq!(server["leader"], node == leader);
                        assert_eq!(server["voter"], true);
                        assert_eq!(server["enrolled"], true);
                    }
                }
                "sys/storage/raft/linearizable-read" => {
                    assert_eq!(response.body["data"]["linearizable"], true);
                    assert_eq!(response.body["data"]["leader"], (leader + 1) as u64);
                    assert_eq!(
                        response.body["data"]["observation_scope"],
                        "native-raft-ReadIndex"
                    );
                    for field in ["term", "applied_index", "membership_index"] {
                        assert!(
                            response.body["data"][field]
                                .as_u64()
                                .is_some_and(|value| value > 0)
                        );
                    }
                }
                "sys/storage/raft/snapshot-status" => {
                    for field in ["applied_index", "membership_index"] {
                        assert!(
                            response.body["data"][field]
                                .as_u64()
                                .is_some_and(|value| value > 0)
                        );
                    }
                    for field in ["snapshot_index", "purged_index"] {
                        assert!(response.body["data"].get(field).is_some());
                    }
                }
                "sys/storage/raft/autopilot/state" => {
                    assert_eq!(response.body["data"]["committed"], true);
                    assert_eq!(response.body["data"]["joint"], false);
                    assert_eq!(response.body["data"]["voters"], json!(["1", "2", "3"]));
                    assert_eq!(response.body["data"]["leader"], (leader + 1).to_string());
                    assert_eq!(
                        response.body["data"]["servers"]
                            .as_object()
                            .ok_or("autopilot servers")?
                            .len(),
                        3
                    );
                }
                "sys/storage/raft/autopilot/configuration" => {
                    assert_eq!(
                        response.body["data"],
                        json!({
                            "cleanup_dead_servers":false,"last_contact_threshold":"10s",
                            "dead_server_last_contact_threshold":"86400s","max_trailing_logs":1000,
                            "min_quorum":3,"server_stabilization_time":"10s"
                        })
                    );
                }
                _ => return Err("unexpected Raft observation route".into()),
            }
        }
        self.with_service(index, |service| {
            native_auth::auth_only_root_change(
                &before,
                service.native_root.as_ref().ok_or("native root")?,
                false,
            )
            .map_err(|_| "Raft observation mutated a business owner")?;
            assert!(
                service
                    .state
                    .as_ref()
                    .ok_or("state")?
                    .raft_admin
                    .is_default()
            );
            assert!(service.pending_native_auth_delivery.is_none());
            assert!(!service.recovery_required);
            Ok(())
        })
    }
}

#[test]
fn formal_native_raft_five_reads_survive_forwarding_election_and_cold_rejoin() -> TestResult {
    let mut pipeline = FormalPipeline::start()?;
    let first = pipeline.ready_leader()?;
    for index in 0..3 {
        pipeline.read_all(index, first, pipeline.admin())?;
    }
    pipeline.stop_process(first)?;
    let next = pipeline.ready_leader()?;
    assert_ne!(next, first);
    pipeline.read_all(next, next, pipeline.admin())?;
    pipeline.assert_history(next, &[(1, "seed-v5")])?;
    pipeline.start_formal_process(first)?;
    pipeline.wait_cold_native_readindex_ready(first)?;
    pipeline.unseal(first)?;
    let current = pipeline.ready_leader()?;
    pipeline.read_all(first, current, pipeline.admin())?;
    pipeline.assert_history(first, &[(1, "seed-v5")])?;
    Ok(())
}

#[test]
fn formal_native_raft_read_acl_shape_and_clock_delivery_keep_all_writers_closed() -> TestResult {
    let pipeline = FormalPipeline::start()?;
    let leader = pipeline.ready_leader()?;
    let read = pipeline.token(leader, "raft-read-only", "\"read\"", "300s")?;
    let sudo = pipeline.token(leader, "raft-sudo-only", "\"sudo\"", "300s")?;
    let both = pipeline.token(leader, "raft-read-and-sudo", "\"read\",\"sudo\"", "300s")?;
    for path in READS {
        for token in ["", read.as_str(), sudo.as_str()] {
            let response = expect(
                pipeline.call(leader, "GET", path, token, json!({}))?,
                403,
                "read-and-sudo-required",
            )?;
            assert!(response.body.get("data").is_none());
        }
        for body in [json!({"unexpected":true}), json!("not-an-object")] {
            let response = expect(
                pipeline.call(leader, "GET", path, &both, body)?,
                400,
                "read-shape",
            )?;
            assert!(response.body.get("data").is_none());
        }
        for method in ["POST", "PUT"] {
            let response = expect(
                pipeline.call(leader, method, path, pipeline.admin(), json!({}))?,
                501,
                "no-Raft-writer-grant",
            )?;
            assert!(response.body.get("data").is_none());
        }
    }
    // A bounded actor drives the real terminal clock observation. Repeated
    // successful reads must retain business roots while consuming only that
    // actual Auth receipt; a fabricated generation is never supplied.
    pipeline.read_all(leader, leader, &both)?;
    pipeline.read_all(leader, leader, &both)?;
    let until = Instant::now() + REQUEST_BUDGET;
    let _scope = RequestDeadlineScope::enter(until);
    let mut writer = lock_until(pipeline.services[leader].as_ref().ok_or("service")?, until)
        .map_err(|_| "wrapped observation lock")?;
    let mut request = ServiceRequest::new("GET", READS[0], "", &both, json!({}));
    request.wrap_ttl_seconds = Some(30);
    let response = writer.handle_request(request);
    assert_eq!(response.status, 501);
    assert!(response.body.get("data").is_none() && response.body.get("wrap_info").is_none());
    Ok(())
}

#[test]
fn formal_native_raft_read_cannot_return_after_original_deadline_expires_at_audit() -> TestResult {
    let pipeline = FormalPipeline::start()?;
    let leader = pipeline.ready_leader()?;
    let fault = AuditFault::install(|_| {
        let until = crate::request_deadline::current();
        assert!(until.is_some(), "original request deadline");
        if let Some(until) = until {
            thread::sleep(
                until.saturating_duration_since(Instant::now()) + Duration::from_millis(20),
            );
        }
    });
    let until = Instant::now() + REQUEST_BUDGET;
    let _scope = RequestDeadlineScope::enter(until);
    let mut writer = lock_until(pipeline.services[leader].as_ref().ok_or("service")?, until)
        .map_err(|_| "deadline observation lock")?;
    let response = writer.handle("GET", READS[0], "", pipeline.admin(), json!({}));
    assert!(
        fault.reached(),
        "the actual successful response audit must precede expiry"
    );
    assert_eq!(response.status, 503);
    assert!(response.body.get("data").is_none());
    assert!(response.consistency_index.is_none());
    assert!(writer.pending_native_auth_delivery.is_none());
    Ok(())
}

#[test]
fn formal_native_raft_read_rechecks_original_actor_after_actual_audit() -> TestResult {
    let pipeline = FormalPipeline::start()?;
    let leader = pipeline.ready_leader()?;
    let token = pipeline.token(leader, "raft-expiring-read", "\"read\",\"sudo\"", "2s")?;
    let fault = AuditFault::install(|_| thread::sleep(Duration::from_millis(2100)));
    let response = pipeline.call(leader, "GET", READS[2], &token, json!({}))?;
    assert!(
        fault.reached(),
        "the actor must survive through the actual response audit"
    );
    assert_eq!(response.status, 403);
    assert!(response.body.get("data").is_none());
    assert!(response.consistency_index.is_none());
    Ok(())
}

#[test]
fn formal_native_raft_read_vetoes_warm_policy_tampering_after_actual_audit() -> TestResult {
    fn change_min_quorum(service: &mut Service) -> TestResult {
        let state = service.state.as_mut().ok_or("installed state")?;
        let mut policy = serde_json::to_value(&state.raft_admin)?;
        policy["config"]["min_quorum"] = json!(4);
        state.raft_admin = serde_json::from_value::<raft_admin::RaftAdminState>(policy)?.into();
        Ok(())
    }
    let pipeline = FormalPipeline::start()?;
    let leader = pipeline.ready_leader()?;
    let fault = AuditFault::install(|service| {
        assert!(
            change_min_quorum(service).is_ok(),
            "valid synthetic policy mutation"
        );
    });
    let response = pipeline.call(leader, "GET", READS[4], pipeline.admin(), json!({}))?;
    assert!(fault.reached());
    assert_eq!(response.status, 503);
    assert!(response.body.get("data").is_none());
    assert!(response.consistency_index.is_none());
    Ok(())
}

#[test]
fn formal_native_raft_five_reads_reject_actual_lost_quorum() -> TestResult {
    let mut pipeline = FormalPipeline::start()?;
    let leader = pipeline.ready_leader()?;
    pipeline.read_all(leader, leader, pipeline.admin())?;
    for index in (0..3).filter(|index| *index != leader) {
        pipeline.stop_process(index)?;
    }
    for path in READS {
        let response = expect(
            pipeline.call(leader, "GET", path, pipeline.admin(), json!({}))?,
            503,
            "actual-quorum-lost",
        )?;
        assert!(response.body.get("data").is_none());
        assert!(response.consistency_index.is_none());
    }
    Ok(())
}

#[test]
fn formal_native_raft_audited_reply_status_tampering_cannot_bypass_delivery_custody() -> TestResult
{
    let pipeline = FormalPipeline::start()?;
    let leader = pipeline.ready_leader()?;
    let fault = AuditFault::install_reply(|response| {
        // This is the original successful response after its actual mandatory
        // audit. Change only its status; retaining data must never make an
        // error-shaped reply eligible for the unowned early-return exception.
        assert_eq!(response.status, 200);
        assert!(response.body.get("data").is_some());
        response.status = 503;
    });
    let response = pipeline.call(leader, "GET", READS[0], pipeline.admin(), json!({}))?;
    assert!(fault.reached());
    assert_eq!(response.status, 503);
    assert!(response.body.get("data").is_none());
    assert!(response.consistency_index.is_none());
    pipeline.with_service(leader, |service| {
        assert!(service.pending_native_auth_delivery.is_none());
        assert!(!service.recovery_required);
        Ok(())
    })?;
    Ok(())
}
