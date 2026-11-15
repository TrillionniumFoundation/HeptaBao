//! Normal native_v6_raft configuration, three real Raft nodes and pinned TLS.
//! A negative route owns a current catalog/root observation through mandatory
//! audit; process-local tests do not supply physical-host or public HTTPS gates.
use super::*;
use crate::configuration::NativeStorageProfile;
use std::ops::{Deref, DerefMut};

struct MissingRoutePipeline {
    inner: Pipeline,
    servers: Vec<crate::http::Config>,
}

fn selection(pipeline: &Pipeline, index: usize) -> TestResult<(u64, [u8; 32], u64)> {
    let _scope = scope();
    let process = pipeline.processes[index]
        .as_ref()
        .ok_or("missing-route Raft process")?
        .lock_for_request()
        .map_err(|_| "missing-route ReadIndex lock")?;
    let actual = process
        .native_v6_committed_read(OriginalDeadline::capture()?)?
        .ok_or("missing-route native committed root")?;
    process.verify_native_v6_committed_read(&actual)?;
    Ok((
        actual.published().generation(),
        actual.published().root_digest(),
        actual.published().publication_log_id().index,
    ))
}

fn negative(response: Response) -> TestResult {
    let response = expect(response, 404, "formal-HA-original-absent-mount-dispatcher")?;
    assert!(response.body == json!({"errors":["unsupported path"]}));
    assert!(response.unwrapped_json.is_none() && response.response_headers.is_empty());
    Ok(())
}

#[test]
fn native_missing_route_formal_ha_readindex_forwarding_election_and_cold_rejoin() -> TestResult {
    let mut pipeline = MissingRoutePipeline::start()?;
    let first = pipeline.ready_leader()?;
    let standby = (first + 1) % 3;
    let before = selection(&pipeline, first)?;
    let graphs = pipeline.with_service(first, |service| {
        Ok(service
            .native_root
            .as_ref()
            .ok_or("negative-route KV graph")?
            .kv2
            .clone())
    })?;
    negative(pipeline.call(
        standby,
        "GET",
        "hbqa-absent/route",
        pipeline.admin(),
        json!({}),
    )?)?;
    for index in 0..3 {
        negative(pipeline.call(
            index,
            "LIST",
            "hbqa-absent/route",
            pipeline.admin(),
            json!({}),
        )?)?;
        assert_eq!(selection(&pipeline, index)?, before);
        pipeline.with_service(index, |service| {
            assert!(
                service
                    .native_root
                    .as_ref()
                    .ok_or("negative-route KV graph")?
                    .kv2
                    == graphs
            );
            assert!(service.pending_native_auth_delivery.is_none());
            assert!(matches!(
                service.native_storage_profile,
                Some(NativeStorageProfile::Raft)
            ));
            assert!(service.native_candidate_profile.is_none());
            Ok(())
        })?;
    }
    pipeline.stop_process(first)?;
    let next = pipeline.ready_leader()?;
    assert_ne!(first, next);
    negative(pipeline.call(
        next,
        "GET",
        "hbqa-absent/route",
        pipeline.admin(),
        json!({}),
    )?)?;
    assert_eq!(selection(&pipeline, next)?, before);
    pipeline.start_formal_process(first)?;
    pipeline.wait_cold_native_readindex_ready(first)?;
    pipeline.unseal(first)?;
    negative(pipeline.call(
        first,
        "GET",
        "hbqa-absent/route",
        pipeline.admin(),
        json!({}),
    )?)?;
    assert_eq!(selection(&pipeline, first)?, before);
    // Restart all three actual owners from their independent durable stores.
    // No reconstructed root, local receipt or ciphertext is installed here.
    for index in 0..3 {
        pipeline.stop_process(index)?;
    }
    for index in [1, 2, 0] {
        pipeline.start_formal_process(index)?;
    }
    let leader = pipeline.ready_leader()?;
    for index in std::iter::once(leader).chain((0..3).filter(|index| *index != leader)) {
        pipeline.unseal(index)?;
    }
    for index in 0..3 {
        negative(pipeline.call(
            index,
            "GET",
            "hbqa-absent/route",
            pipeline.admin(),
            json!({}),
        )?)?;
        assert_eq!(selection(&pipeline, index)?, before);
        pipeline.assert_history(index, &[(1, "seed-v5")])?;
    }
    Ok(())
}

#[test]
fn native_missing_route_formal_ha_actual_post_audit_publication_vetoes_stale_absence() -> TestResult
{
    let pipeline = MissingRoutePipeline::start()?;
    let leader = pipeline.ready_leader()?;
    let before = selection(&pipeline, leader)?;
    let writer = pipeline.admin.clone();
    let observed = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let hook_observed = Arc::clone(&observed);
    let _hook =
        crate::service::native_auth::missing_route_tests::after_audit(move |service, response| {
            assert!(
                response.status == 404 && response.body == json!({"errors":["unsupported path"]})
            );
            hook_observed.store(true, std::sync::atomic::Ordering::SeqCst);
            // A real new mount publication changes the exact absence statement.
            // The original operation cannot recapture its proof after this audit.
            let mounted = service.handle(
                "POST",
                "sys/mounts/late",
                "",
                &writer,
                json!({"type":"kv","options":{"version":"2"},"cas_revision":0}),
            );
            assert_eq!(mounted.status, 204);
            let written = service.handle(
                "POST",
                "late/data/value",
                "",
                &writer,
                json!({"options":{"cas":0},"data":{"value":"owned-after-audit"}}),
            );
            assert_eq!(written.status, 200);
        })?;
    let refused = expect(
        pipeline.call(
            leader,
            "GET",
            "late/data/value",
            pipeline.admin(),
            json!({}),
        )?,
        503,
        "formal-HA-absence-proof-after-real-publication",
    )?;
    assert!(observed.load(std::sync::atomic::Ordering::SeqCst));
    assert!(refused.body.get("data").is_none());
    assert!(refused.unwrapped_json.is_none() && refused.response_headers.is_empty());
    let after = selection(&pipeline, leader)?;
    assert!(after.0 > before.0 && after.2 > before.2 && after.1 != before.1);
    for index in 0..3 {
        let read = expect(
            pipeline.call(index, "GET", "late/data/value", pipeline.admin(), json!({}))?,
            200,
            "formal-HA-new-actual-owner",
        )?;
        assert!(read.body["data"]["data"] == json!({"value":"owned-after-audit"}));
        assert_eq!(selection(&pipeline, index)?, after);
        pipeline.assert_history(index, &[(1, "seed-v5")])?;
    }
    Ok(())
}

#[test]
fn native_missing_route_formal_ha_actual_actor_expiry_after_audit_withholds_404() -> TestResult {
    const ACTOR_TTL_SECONDS: u64 = 5;
    let pipeline = MissingRoutePipeline::start()?;
    let leader = pipeline.ready_leader()?;
    expect(
        pipeline.call(
            leader,
            "PUT",
            "sys/policies/acl/absence-expiring",
            pipeline.admin(),
            json!({"policy":"path \"hbqa-absent/*\" { capabilities=[\"read\"] }"}),
        )?,
        204,
        "formal-HA-absence-expiring-policy",
    )?;
    let mut issued = expect(
        pipeline.call(
            leader,
            "POST",
            "auth/token/create",
            pipeline.admin(),
            json!({"policies":["absence-expiring"],"no_default_policy":true,"ttl":"5s"}),
        )?,
        200,
        "formal-HA-absence-expiring-actor",
    )?;
    assert_eq!(
        issued.body["auth"]["lease_duration"].as_u64(),
        Some(ACTOR_TTL_SECONDS),
    );
    // Issuance and its real HA publication precede this observation. Waiting
    // one full granted lease from here is a conservative real-expiry bound;
    // it does not move the token's grant, Actor or trusted request clock.
    let expired_by =
        Instant::now() + Duration::from_secs(ACTOR_TTL_SECONDS) + Duration::from_millis(100);
    let actor = secret_field(&mut issued, "/auth/client_token")?;
    let observed = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let hook_observed = Arc::clone(&observed);
    let _hook = crate::service::native_auth::missing_route_tests::after_audit(
        move |_service, response| {
            assert!(response.status == 404);
            let original_deadline = crate::request_deadline::current();
            assert!(
                original_deadline.is_some(),
                "missing-route expiry hook retains the original request deadline",
            );
            assert!(
                original_deadline.is_some_and(|deadline| expired_by < deadline),
                "real actor expiry must fit inside the original 15-second request",
            );
            hook_observed.store(true, std::sync::atomic::Ordering::SeqCst);
            // Wait only inside the original post-audit boundary. Real admission
            // and terminal persistence may consume part of the five-second
            // lease, so wait to the one captured bound instead of resetting it.
            thread::sleep(expired_by.saturating_duration_since(Instant::now()));
            assert!(
                original_deadline.is_some_and(|deadline| Instant::now() < deadline),
                "original request deadline remains after real actor expiry",
            );
        },
    )?;
    let refused = expect(
        pipeline.call(leader, "GET", "hbqa-absent/route", &actor, json!({}))?,
        503,
        "formal-HA-negative-reply-original-actor-expired",
    )?;
    assert!(observed.load(std::sync::atomic::Ordering::SeqCst));
    assert!(refused.body.get("data").is_none());
    expect(
        pipeline.call(leader, "GET", "hbqa-absent/route", &actor, json!({}))?,
        403,
        "formal-HA-expired-actor-remains-denied",
    )?;
    pipeline.assert_history(leader, &[(1, "seed-v5")])?;
    Ok(())
}

impl Deref for MissingRoutePipeline {
    type Target = Pipeline;
    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl DerefMut for MissingRoutePipeline {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.inner
    }
}

impl MissingRoutePipeline {
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

#[path = "service_native_capabilities_ha_tests.rs"]
mod capabilities;

#[path = "service_native_missing_route_namespace_ha_tests.rs"]
mod namespace_tests;
