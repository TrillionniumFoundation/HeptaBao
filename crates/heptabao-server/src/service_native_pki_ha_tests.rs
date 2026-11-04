//! Normal NativeV6Raft, actual three-node OpenRaft and pinned peer TLS.
//! No public HTTPS or physical-machine qualification is implied by this suite.
use super::*;
use crate::configuration::NativeStorageProfile;
use openssl::x509::{X509, X509Crl};
use std::ops::{Deref, DerefMut};

struct PkiPipeline {
    inner: Pipeline,
    servers: Vec<crate::http::Config>,
}

fn pki_setup(pipeline: &PkiPipeline, node: usize) -> TestResult {
    for (path, body, status) in [
        ("sys/mounts/pki", json!({"type":"pki"}), 204),
        (
            "pki/root/generate/internal",
            json!({"common_name":"ca.example.test",
            "key_type":"ec","key_bits":256,"ttl":"48h"}),
            200,
        ),
        (
            "pki/roles/web",
            json!({"allowed_domains":["example.test"],"allow_subdomains":true,
            "key_type":"ec","key_bits":256,"max_ttl":"2h","generate_lease":true}),
            200,
        ),
    ] {
        expect(
            pipeline.call(node, "POST", path, pipeline.admin(), body)?,
            status,
            "formal-HA-local-PKI-setup",
        )?;
    }
    Ok(())
}
fn pki_text(response: &Response, pointer: &str) -> TestResult<String> {
    response
        .body
        .pointer(pointer)
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
        .ok_or_else(|| "HA PKI synthetic response field absent".into())
}
fn pki_issued(
    pipeline: &PkiPipeline,
    node: usize,
    actor: &str,
) -> TestResult<(String, String, String, X509, X509)> {
    let mut response = expect(
        pipeline.call(
            node,
            "POST",
            "pki/issue/web",
            actor,
            json!({"common_name":"ha.example.test","ttl":"1h"}),
        )?,
        200,
        "formal-HA-actual-PKI-issuance",
    )?;
    let certificate = pki_text(&response, "/data/certificate")?;
    let leaf = X509::from_pem(certificate.as_bytes())?;
    let issuer = X509::from_pem(pki_text(&response, "/data/issuing_ca")?.as_bytes())?;
    let issuer_key = issuer.public_key()?;
    assert!(leaf.verify(&issuer_key)?);
    let lease = pki_text(&response, "/lease_id")?;
    let serial = pki_text(&response, "/data/serial_number")?;
    assert_eq!(response.body["renewable"], false);
    assert!(response.body["data"]["private_key"].is_string());
    erase_json(&mut response.body);
    Ok((lease, serial, certificate, leaf, issuer))
}
fn pki_cold_public(
    pipeline: &PkiPipeline,
    node: usize,
    serial: &str,
    certificate: &str,
    revoked: bool,
) -> TestResult {
    let response = expect(
        pipeline.call(node, "GET", &format!("pki/cert/{serial}"), "", json!({}))?,
        200,
        "formal-HA-public-certificate-through-real-ReadIndex",
    )?;
    assert_eq!(response.body["data"]["certificate"], certificate);
    let at = response.body["data"]["revocation_time"]
        .as_u64()
        .ok_or("HA PKI revocation time")?;
    assert_eq!(at > 0, revoked);
    pipeline.with_service(node, |service| {
        assert!(matches!(
            service.native_storage_profile,
            Some(NativeStorageProfile::Raft)
        ));
        assert!(service.native_candidate_profile.is_none());
        assert!(service.native_root.is_some() && service.record_root.is_none());
        assert!(service.pending_native_auth_delivery.is_none());
        Ok(())
    })?;
    pipeline.assert_history(node, &[(1, "seed-v5")])
}
fn pki_revoked_crl(pipeline: &PkiPipeline, node: usize, leaf: &X509, issuer: &X509) -> TestResult {
    let response = expect(
        pipeline.call(node, "GET", "pki/cert/crl", "", json!({}))?,
        200,
        "formal-HA-actual-durable-CRL",
    )?;
    let crl = X509Crl::from_pem(pki_text(&response, "/data/certificate")?.as_bytes())?;
    let key = issuer.public_key()?;
    assert!(crl.verify(&key)?);
    let target = leaf.serial_number().to_bn()?.to_vec();
    let mut found = false;
    if let Some(revoked) = crl.get_revoked() {
        for entry in revoked {
            found |= entry.serial_number().to_bn()?.to_vec() == target;
        }
    }
    assert!(found, "real HA CRL must contain the actual issued serial");
    Ok(())
}

#[test]
fn formal_native_pki_ha_forwarded_signing_election_cold_and_actual_crl() -> TestResult {
    let mut pipeline = PkiPipeline::start()?;
    let first = pipeline.ready_leader()?;
    let follower = (first + 1) % 3;
    pki_setup(&pipeline, follower)?;
    let (lease, serial, certificate, leaf, issuer) =
        pki_issued(&pipeline, follower, pipeline.admin())?;
    pki_cold_public(&pipeline, follower, &serial, &certificate, false)?;
    pipeline.stop_process(first)?;
    let next = pipeline.ready_leader()?;
    assert_ne!(next, first);
    expect(
        pipeline.call(
            next,
            "POST",
            "sys/leases/lookup",
            pipeline.admin(),
            json!({"lease_id":lease}),
        )?,
        200,
        "formal-HA-new-leader-PKI-lease",
    )?;
    pki_cold_public(&pipeline, next, &serial, &certificate, false)?;
    expect(
        pipeline.call(
            next,
            "POST",
            "sys/leases/revoke",
            pipeline.admin(),
            json!({"lease_id":lease}),
        )?,
        204,
        "formal-HA-original-lease-revocation",
    )?;
    pipeline.start_formal_process(first)?;
    pipeline.wait_cold_native_readindex_ready(first)?;
    pipeline.unseal(first)?;
    pki_cold_public(&pipeline, first, &serial, &certificate, true)?;
    pki_revoked_crl(&pipeline, first, &leaf, &issuer)?;
    Ok(())
}

#[test]
fn formal_native_pki_ha_batch_lease_keeps_typed_owner_across_actual_cold_election() -> TestResult {
    let mut pipeline = PkiPipeline::start()?;
    let first = pipeline.ready_leader()?;
    let follower = (first + 1) % 3;
    pki_setup(&pipeline, follower)?;
    for (path, body) in [
        ("sys/auth/up", json!({"type":"userpass"})),
        (
            "sys/policies/acl/pki-ha",
            json!({"policy":"path \"pki/issue/web\" { capabilities=[\"update\"] }"}),
        ),
        (
            "auth/up/users/batch",
            json!({"password":"synthetic-pki-ha-batch","policies":["pki-ha"],
            "token_type":"batch","token_ttl":120,"token_max_ttl":600,"token_num_uses":0}),
        ),
    ] {
        expect(
            pipeline.call(follower, "POST", path, pipeline.admin(), body)?,
            204,
            "formal-HA-real-batch-issuer-setup",
        )?;
    }
    let mut login = expect(
        pipeline.call(
            follower,
            "POST",
            "auth/up/login/batch",
            "",
            json!({"password":"synthetic-pki-ha-batch"}),
        )?,
        200,
        "formal-HA-real-batch-login",
    )?;
    assert_eq!(login.body["auth"]["token_type"], "batch");
    let actor = secret_field(&mut login, "/auth/client_token")?;
    erase_json(&mut login.body);
    let (lease, serial, certificate, leaf, issuer) = pki_issued(&pipeline, follower, &actor)?;
    let owner = pipeline.with_service(first, |service| {
        let state = service.state.as_ref().ok_or("HA PKI state")?;
        assert_eq!(state.schema, AUTH_SECURITY_CONTRACT_STATE_SCHEMA);
        let root = service.native_root.as_ref().ok_or("actual HA PKI root")?;
        assert_eq!(root.state_schema, AUTH_SECURITY_CONTRACT_STATE_SCHEMA);
        assert_eq!(
            root.reader_floor.minimum_state_schema,
            AUTH_SECURITY_CONTRACT_STATE_SCHEMA
        );
        state
            .validate_namespace_batch_state()
            .map_err(|_| "actual paired lifecycle")?;
        state
            .engines
            .lease_owners()
            .into_iter()
            .find(|(_, owner)| owner.batch_claims().is_some())
            .map(|(_, owner)| owner)
            .ok_or_else(|| "actual typed PKI batch owner".into())
    })?;
    let claims = owner.batch_claims().ok_or("actual batch claims")?;
    let deadline = claims.precision().map_or_else(
        || crate::engines::timestamp(claims.expires_at()),
        |value| value.expires_at.rfc3339(),
    );
    let actor_end = openssl::asn1::Asn1Time::from_unix(i64::try_from(claims.expires_at())?)?;
    assert_eq!(
        leaf.not_after().compare(&actor_end)?,
        std::cmp::Ordering::Greater
    );
    pipeline.stop_process(first)?;
    let next = pipeline.ready_leader()?;
    assert_ne!(next, first);
    let lookup = expect(
        pipeline.call(
            next,
            "POST",
            "sys/leases/lookup",
            pipeline.admin(),
            json!({"lease_id":lease}),
        )?,
        200,
        "formal-HA-batch-lease-survives-leader",
    )?;
    assert_eq!(lookup.body["data"]["expire_time"], deadline);
    pipeline.start_formal_process(first)?;
    pipeline.wait_cold_native_readindex_ready(first)?;
    pipeline.unseal(first)?;
    pki_cold_public(&pipeline, first, &serial, &certificate, false)?;
    pipeline.with_service(first, |service| {
        let state = service.state.as_ref().ok_or("cold HA PKI state")?;
        assert_eq!(state.schema, AUTH_SECURITY_CONTRACT_STATE_SCHEMA);
        let root = service.native_root.as_ref().ok_or("cold HA PKI root")?;
        assert_eq!(root.state_schema, AUTH_SECURITY_CONTRACT_STATE_SCHEMA);
        assert_eq!(
            root.reader_floor.minimum_state_schema,
            AUTH_SECURITY_CONTRACT_STATE_SCHEMA
        );
        state
            .validate_namespace_batch_state()
            .map_err(|_| "cold paired lifecycle")?;
        assert!(
            state
                .engines
                .lease_owners()
                .iter()
                .any(|(_, current)| current == &owner)
        );
        Ok(())
    })?;
    expect(
        pipeline.call(
            first,
            "POST",
            "sys/leases/revoke",
            pipeline.admin(),
            json!({"lease_id":lease}),
        )?,
        204,
        "formal-HA-real-batch-owned-lease-revocation",
    )?;
    pipeline.stop_process(first)?;
    pipeline.start_formal_process(first)?;
    pipeline.wait_cold_native_readindex_ready(first)?;
    pipeline.unseal(first)?;
    pki_cold_public(&pipeline, first, &serial, &certificate, true)?;
    pki_revoked_crl(&pipeline, first, &leaf, &issuer)?;
    Ok(())
}

#[test]
fn formal_native_pki_ha_lost_actual_quorum_cannot_sign_or_disclose_public_material() -> TestResult {
    let mut pipeline = PkiPipeline::start()?;
    let leader = pipeline.ready_leader()?;
    pki_setup(&pipeline, leader)?;
    let before = pipeline.with_service(leader, |service| {
        service
            .current_state_identity()
            .map_err(|_| "PKI HA source identity".into())
    })?;
    for index in (0..3).filter(|index| *index != leader) {
        pipeline.stop_process(index)?;
    }
    for (method, path, body) in [
        (
            "POST",
            "pki/issue/web",
            json!({"common_name":"must-not-sign.example.test","ttl":"1h"}),
        ),
        ("GET", "pki/cert/ca", json!({})),
    ] {
        let response = expect(
            pipeline.call(
                leader,
                method,
                path,
                if method == "GET" {
                    ""
                } else {
                    pipeline.admin()
                },
                body,
            )?,
            503,
            "formal-HA-no-quorum-PKI-proof-veto",
        )?;
        assert!(response.body.get("data").is_none() && response.body.get("auth").is_none());
        assert!(response.consistency_index.is_none());
    }
    pipeline.with_service(leader, |service| {
        assert!(
            service
                .current_state_identity()
                .map_err(|_| "PKI HA identity")?
                == before
        );
        assert!(service.pending_native_auth_delivery.is_none());
        Ok(())
    })?;
    Ok(())
}

impl Deref for PkiPipeline {
    type Target = Pipeline;
    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl DerefMut for PkiPipeline {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.inner
    }
}

impl PkiPipeline {
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
