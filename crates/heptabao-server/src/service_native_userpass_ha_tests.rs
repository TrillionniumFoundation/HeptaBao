//! Normal NativeV6Raft Userpass, actual three-node OpenRaft and pinned peer TLS.
//! Service::handle is the public dispatcher; no public HTTPS listener or
//! physical-host failure qualification is claimed by these process-local tests.
use super::*;
use crate::configuration::NativeStorageProfile;
use std::ops::{Deref, DerefMut};

struct UserpassPipeline {
    inner: Pipeline,
    servers: Vec<crate::http::Config>,
}

fn userpass_account(pipeline: &UserpassPipeline, node: usize) -> TestResult {
    expect(
        pipeline.call(
            node,
            "POST",
            "sys/auth/up",
            pipeline.admin(),
            json!({"type":"userpass"}),
        )?,
        204,
        "formal-HA-Userpass-mount",
    )?;
    expect(
        pipeline.call(
            node,
            "POST",
            "sys/policies/acl/ha-up",
            pipeline.admin(),
            json!({"policy":"path \"secret/data/pipeline/history\" { capabilities = [\"read\"] }"}),
        )?,
        204,
        "formal-HA-Userpass-policy",
    )?;
    expect(
        pipeline.call(
            node,
            "POST",
            "auth/up/users/alice",
            pipeline.admin(),
            json!({
                "password":"ha-native-userpass-synthetic-password", "policies":["ha-up"],
                "token_ttl":120,"token_max_ttl":600,
            }),
        )?,
        204,
        "formal-HA-Userpass-account",
    )?;
    Ok(())
}

fn userpass_login(pipeline: &UserpassPipeline, node: usize) -> TestResult<Zeroizing<String>> {
    let mut response = expect(
        pipeline.call(
            node,
            "POST",
            "auth/up/login/alice",
            "",
            json!({
                "password":"ha-native-userpass-synthetic-password",
            }),
        )?,
        200,
        "formal-HA-actual-Userpass-login",
    )?;
    assert_eq!(response.body["auth"]["metadata"]["username"], "alice");
    let token = secret_field(&mut response, "/auth/client_token")?;
    erase_json(&mut response.body);
    Ok(token)
}

fn userpass_read(pipeline: &UserpassPipeline, node: usize, token: &str) -> TestResult {
    let response = expect(
        pipeline.call(
            node,
            "GET",
            "secret/data/pipeline/history",
            token,
            json!({"version":1}),
        )?,
        200,
        "formal-HA-Userpass-authorized-read",
    )?;
    assert_eq!(response.body["data"]["metadata"]["version"], 1);
    assert!(response.body["data"]["data"]["value"].as_str() == Some("seed-v5"));
    let denied = expect(
        pipeline.call(
            node,
            "POST",
            "secret/data/pipeline/history",
            token,
            json!({"options":{"cas":1},"data":{"value":"must-not-write"}}),
        )?,
        403,
        "formal-HA-Userpass-ACL-stays-read-only",
    )?;
    assert!(denied.body.get("data").is_none());
    Ok(())
}

#[test]
fn formal_native_userpass_ha_forwarded_issuance_election_cold_provenance_and_revoke() -> TestResult
{
    let mut pipeline = UserpassPipeline::start()?;
    let first = pipeline.ready_leader()?;
    let follower = (first + 1) % 3;
    userpass_account(&pipeline, follower)?;
    let token = userpass_login(&pipeline, follower)?;
    let first_lookup = expect(
        pipeline.call(follower, "GET", "auth/token/lookup-self", &token, json!({}))?,
        200,
        "formal-HA-Userpass-first-provenance",
    )?;
    assert_eq!(first_lookup.body["data"]["meta"]["username"], "alice");
    assert_eq!(first_lookup.body["data"]["creation_ttl"], 120);
    let creation_time = first_lookup.body["data"]["creation_time"]
        .as_u64()
        .ok_or("HA Userpass creation time")?;
    userpass_read(&pipeline, follower, &token)?;

    pipeline.stop_process(first)?;
    let next = pipeline.ready_leader()?;
    assert_ne!(next, first);
    let renewed = expect(
        pipeline.call(
            next,
            "POST",
            "auth/token/renew-self",
            &token,
            json!({"increment":"180s"}),
        )?,
        200,
        "formal-HA-Userpass-renew-on-new-leader",
    )?;
    assert!(renewed.body["auth"]["client_token"].as_str() == Some(token.as_str()));
    pipeline.start_formal_process(first)?;
    pipeline.wait_cold_native_readindex_ready(first)?;
    pipeline.unseal(first)?;
    userpass_read(&pipeline, first, &token)?;
    let cold = expect(
        pipeline.call(first, "GET", "auth/token/lookup-self", &token, json!({}))?,
        200,
        "formal-HA-Userpass-cold-provenance",
    )?;
    assert_eq!(cold.body["data"]["meta"]["username"], "alice");
    assert_eq!(cold.body["data"]["creation_ttl"], 120);
    assert_eq!(cold.body["data"]["creation_time"], creation_time);
    pipeline.with_service(first, |service| {
        assert!(service.native_root.is_some() && service.record_root.is_none());
        assert!(service.native_candidate_profile.is_none());
        let auth = &service.state.as_ref().ok_or("HA Userpass state")?.auth;
        assert!(auth.has_userpass_issuance_state());
        assert!(auth.validate_userpass_native_tokens().is_ok());
        Ok(())
    })?;
    expect(
        pipeline.call(first, "POST", "auth/token/revoke-self", &token, json!({}))?,
        204,
        "formal-HA-Userpass-actual-forwarded-revocation",
    )?;
    pipeline.stop_process(first)?;
    pipeline.start_formal_process(first)?;
    pipeline.wait_cold_native_readindex_ready(first)?;
    pipeline.unseal(first)?;
    let denied = expect(
        pipeline.call(
            first,
            "GET",
            "secret/data/pipeline/history",
            &token,
            json!({}),
        )?,
        403,
        "formal-HA-cold-Userpass-token-stays-revoked",
    )?;
    assert!(denied.body.get("data").is_none());
    pipeline.assert_history(first, &[(1, "seed-v5")])?;
    Ok(())
}

#[test]
fn formal_native_userpass_ha_lost_actual_quorum_cannot_issue_a_credential() -> TestResult {
    let mut pipeline = UserpassPipeline::start()?;
    let leader = pipeline.ready_leader()?;
    userpass_account(&pipeline, leader)?;
    let token = userpass_login(&pipeline, leader)?;
    userpass_read(&pipeline, leader, &token)?;
    let before = pipeline.with_service(leader, |service| {
        service
            .current_state_identity()
            .map_err(|_| "HA Userpass identity".into())
    })?;
    for index in (0..3).filter(|index| *index != leader) {
        pipeline.stop_process(index)?;
    }
    let denied = expect(
        pipeline.call(
            leader,
            "POST",
            "auth/up/login/alice",
            "",
            json!({
                "password":"ha-native-userpass-synthetic-password",
            }),
        )?,
        503,
        "formal-HA-no-quorum-Userpass-issuance-veto",
    )?;
    assert!(denied.body.get("auth").is_none());
    assert!(denied.body.get("data").is_none());
    assert!(denied.consistency_index.is_none());
    pipeline.with_service(leader, |service| {
        assert!(service.current_state_identity().map_err(|_| "identity")? == before);
        assert!(service.pending_native_auth_delivery.is_none());
        Ok(())
    })?;
    Ok(())
}

impl Deref for UserpassPipeline {
    type Target = Pipeline;
    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl DerefMut for UserpassPipeline {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.inner
    }
}

impl UserpassPipeline {
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
}

#[path = "service_native_userpass_batch_ha_tests.rs"]
mod batch_tests;

#[path = "service_native_batch_issuer_ha_tests.rs"]
mod batch_issuer_tests;
