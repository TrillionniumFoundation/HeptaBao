use super::super::tests::{Root, bootstrap, call};
use super::*;
use sha2::{Digest, Sha256};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

struct SocketDirectory(PathBuf);
impl Drop for SocketDirectory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
struct Fixture {
    service: Service,
    admin: String,
    image: PathBuf,
    _socket: SocketDirectory,
    _root: Root,
}
impl Fixture {
    fn new() -> TestResult<Self> {
        let root = Root::new();
        let mut service = root.service()?;
        let directory = root.path.join("operator-provider");
        fs::create_dir(&directory)?;
        fs::set_permissions(&directory, fs::Permissions::from_mode(0o700))?;
        let image = directory.join("provider");
        let bridge = directory.join("bridge");
        let sandbox = directory.join("sandbox");
        // No executable is invoked in these delivery-boundary cfg controls.
        // The typed result below is not evidence of genuine provider RPC.
        for p in [&image, &bridge, &sandbox] {
            let mut f = OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o700)
                .open(p)?;
            f.write_all(b"#!/bin/sh\nexit 0\n")?;
        }
        let deployment = directory.join("deployment.json");
        let encoded = serde_json::to_vec(&json!({
            "provider":"transit",
            "image":image.to_str().ok_or("image path")?,
            "image_sha256":hex(&Sha256::digest(fs::read(&image)?)),
            "args":[],
            "libraries":[]
        }))?;
        let mut f = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&deployment)?;
        f.write_all(&encoded)?;
        drop(f);
        // A short, newly owned 0700 socket directory is the same real admission
        // prerequisite used by the operator configuration. No source clocks or
        // ambient directory permissions are altered to satisfy it.
        let mut socket_nonce = [0u8; 4];
        getrandom::fill(&mut socket_nonce)
            .map_err(|_| std::io::Error::other("fixture socket entropy failed"))?;
        let socket_path = std::env::temp_dir().join(format!("k-{}", hex(&socket_nonce)));
        fs::create_dir(&socket_path)?;
        let socket = SocketDirectory(socket_path);
        fs::set_permissions(&socket.0, fs::Permissions::from_mode(0o700))?;
        service.install_external_kms_plugins(vec![
            super::super::external_kms::PluginExternalKmsConfig {
                id: "transit".into(),
                command: bridge.to_str().ok_or("bridge path")?.into(),
                command_sha256: hex(&Sha256::digest(fs::read(&bridge)?)),
                sandbox_provider_id: "delivery-test-sandbox".into(),
                sandbox_command: sandbox.to_str().ok_or("sandbox path")?.into(),
                sandbox_command_sha256: hex(&Sha256::digest(fs::read(&sandbox)?)),
                sandbox_profile_id: "delivery-test-profile".into(),
                deployment_file: deployment.to_str().ok_or("deployment path")?.into(),
                deployment_sha256: hex(&Sha256::digest(&encoded)),
                owned_temp: socket.0.to_str().ok_or("socket path")?.into(),
                enabled: true,
                maximum_request_bytes: 256 * 1024,
                maximum_response_bytes: 1024 * 1024,
                timeout_ms: 5000,
            },
        ])?;
        let (_, admin) = bootstrap(&mut service)?;
        Ok(Self {
            service,
            admin,
            image,
            _socket: socket,
            _root: root,
        })
    }

    fn stage(&mut self, name: &str) -> TestResult<PendingExternalRequest> {
        let path = format!("sys/external-keys/configs/{name}");
        match self.service.begin_at_mode(RequestDispatch {
            method: "POST",
            path: &path,
            namespace: "",
            token: &self.admin,
            body: json!({
                "plugin":"transit","verify":true,"token":"synthetic-unused",
                "address":"https://127.0.0.1:1","mount_path":"transit"
            }),
            now: 100,
            allow_forward: false,
            enforce_namespace: true,
            wrap_ttl_seconds: None,
            origin_peer: None,
            client_certificates: None,
        }) {
            RequestExecution::External(pending) => {
                assert!(
                    matches!(&pending.effect, ExternalEffectPlan::ExternalKey(plan) if plan.is_genuine())
                );
                Ok(*pending)
            }
            RequestExecution::Complete(response) => {
                Err(format!("delivery cfg stage status {}", response.status).into())
            }
        }
    }
}
fn publication(
    fixture: &mut Fixture,
    pending: PendingExternalRequest,
    audited: bool,
) -> TestResult<(ExternalKeyPlan, Response, String)> {
    let ExternalEffectPlan::ExternalKey(mut plan) = pending.effect else {
        return Err("genuine verification cfg expected private plan".into());
    };
    // Only a cfg observation supplied at the existing typed completion boundary;
    // deployment admission, writer, original authority and audit are real.
    let response = fixture.service.finalize_external_key(&mut plan, Ok(()));
    assert_eq!(response.status, 204);
    assert!(plan.candidate.is_none());
    assert!(plan.delivery_checkpoint.is_some());
    assert!(!plan.response_audited);
    assert!(
        fixture
            .service
            .state
            .as_ref()
            .is_some_and(|s| s.engines.has_external_key_state())
    );
    let response = if audited {
        let response = fixture.service.audit_external_key_response(
            &mut plan,
            &pending.fingerprint,
            (pending.now, pending.token_clock),
            response,
        );
        assert_eq!(response.status, 204);
        assert!(plan.response_audited);
        response
    } else {
        response
    };
    Ok((plan, response, pending.fingerprint))
}

#[test]
fn genuine_kms_verification_actual_publication_audit_and_final_delivery_succeed() -> TestResult {
    let mut fixture = Fixture::new()?;
    let pending = fixture.stage("delivery-healthy")?;
    let (mut plan, response, fingerprint) = publication(&mut fixture, pending, true)?;
    assert_eq!(
        fixture
            .service
            .complete_external_key_delivery(&mut plan, response, &fingerprint)
            .status,
        204
    );
    let pending = fixture.stage("delivery-service")?;
    assert_eq!(
        fixture
            .service
            .finish_external_request(pending, ExternalEffectResult::ExternalKey(Ok(())))
            .status,
        204
    );
    Ok(())
}

#[test]
fn genuine_kms_verification_committed_result_without_response_audit_is_withheld() -> TestResult {
    let mut fixture = Fixture::new()?;
    let pending = fixture.stage("delivery-unaudited")?;
    let (mut plan, response, fingerprint) = publication(&mut fixture, pending, false)?;
    let committed = fixture
        .service
        .current_state_identity()
        .map_err(|_| "committed identity")?;
    let response =
        fixture
            .service
            .complete_external_key_delivery(&mut plan, response, &fingerprint);
    assert_eq!(response.status, 503);
    assert!(!plan.response_audited);
    assert!(
        fixture
            .service
            .current_state_identity()
            .is_ok_and(|id| id == committed)
    );
    Ok(())
}

#[test]
fn genuine_kms_verification_original_image_change_after_audit_withholds_committed_response()
-> TestResult {
    let mut fixture = Fixture::new()?;
    let pending = fixture.stage("delivery-provider-change")?;
    let (mut plan, response, fingerprint) = publication(&mut fixture, pending, true)?;
    let before = Zeroizing::new(serde_json::to_vec(&fixture.service.state)?);
    fs::write(&fixture.image, b"#!/bin/sh\nexit 1\n")?;
    let response =
        fixture
            .service
            .complete_external_key_delivery(&mut plan, response, &fingerprint);
    assert_eq!(response.status, 503);
    assert!(plan.response_audited);
    assert!(before.as_slice() == serde_json::to_vec(&fixture.service.state)?.as_slice());
    Ok(())
}

#[test]
fn genuine_kms_verification_original_actor_revoked_after_audit_cannot_deliver() -> TestResult {
    let mut fixture = Fixture::new()?;
    let pending = fixture.stage("delivery-actor-revoke")?;
    let (mut plan, response, fingerprint) = publication(&mut fixture, pending, true)?;
    assert_eq!(
        call(
            &mut fixture.service,
            "POST",
            "auth/token/revoke-self",
            &fixture.admin,
            json!({})
        )
        .status,
        204
    );
    let response =
        fixture
            .service
            .complete_external_key_delivery(&mut plan, response, &fingerprint);
    assert_eq!(response.status, 403);
    assert!(plan.response_audited);
    Ok(())
}
