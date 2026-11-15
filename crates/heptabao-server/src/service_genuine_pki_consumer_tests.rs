//! These cfg controls supply maintained-crypto observations at the existing
//! completion boundary. No Go bridge or external provider is invoked here.
use super::*;
use crate::service::tests::{Root, bootstrap, call};
use openssl::{
    ec::{EcGroup, EcKey},
    hash::MessageDigest,
    nid::Nid,
    pkey::{Id, PKey, Private},
    rsa::{Padding, Rsa},
    sign::{RsaPssSaltlen, Signer},
    x509::X509,
};
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
    first: PKey<Private>,
    second: PKey<Private>,
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
            "provider":"pkcs11","image":image.to_str().ok_or("image path")?,
            "image_sha256":hex(&Sha256::digest(fs::read(&image)?)),"args":[],"libraries":[]
        }))?;
        let mut f = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&deployment)?;
        f.write_all(&encoded)?;
        drop(f);
        let mut socket_nonce = [0u8; 4];
        getrandom::fill(&mut socket_nonce)
            .map_err(|_| std::io::Error::other("fixture socket entropy failed"))?;
        let socket_path = std::env::temp_dir().join(format!("p-{}", hex(&socket_nonce)));
        fs::create_dir(&socket_path)?;
        let socket = SocketDirectory(socket_path);
        fs::set_permissions(&socket.0, fs::Permissions::from_mode(0o700))?;
        service.install_external_kms_plugins(vec![external_kms::PluginExternalKmsConfig {
            id: "pkcs11".into(),
            command: bridge.to_str().ok_or("bridge path")?.into(),
            command_sha256: hex(&Sha256::digest(fs::read(&bridge)?)),
            sandbox_provider_id: "pki-consumer-test-sandbox".into(),
            sandbox_command: sandbox.to_str().ok_or("sandbox path")?.into(),
            sandbox_command_sha256: hex(&Sha256::digest(fs::read(&sandbox)?)),
            sandbox_profile_id: "pki-consumer-test-profile".into(),
            deployment_file: deployment.to_str().ok_or("deployment path")?.into(),
            deployment_sha256: hex(&Sha256::digest(&encoded)),
            owned_temp: socket.0.to_str().ok_or("socket path")?.into(),
            enabled: true,
            maximum_request_bytes: 256 * 1024,
            maximum_response_bytes: 1024 * 1024,
            timeout_ms: 5000,
        }])?;
        let (_, admin) = bootstrap(&mut service)?;
        for (path, body) in [
            ("sys/mounts/pki", json!({"type":"pki"})),
            (
                "sys/external-keys/configs/hsm",
                json!({"plugin":"pkcs11","verify":false,"lib":"operator-alias","pin":"unused-fixture"}),
            ),
            (
                "sys/external-keys/configs/hsm/keys/first",
                json!({"verify":false,"id":"first"}),
            ),
            (
                "sys/external-keys/configs/hsm/keys/second",
                json!({"verify":false,"id":"second"}),
            ),
            (
                "sys/external-keys/configs/hsm/keys/first/grants/pki",
                json!({}),
            ),
            (
                "sys/external-keys/configs/hsm/keys/second/grants/pki",
                json!({}),
            ),
        ] {
            assert_eq!(call(&mut service, "POST", path, &admin, body).status, 204);
        }
        let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1)?;
        let first = PKey::from_ec_key(EcKey::generate(&group)?)?;
        let second = PKey::generate_ed25519()?;
        Ok(Self {
            service,
            admin,
            image,
            first,
            second,
            _socket: socket,
            _root: root,
        })
    }

    fn stage_body(&mut self, body: Value) -> RequestExecution {
        self.service.begin_at_mode(RequestDispatch {
            method: "POST",
            path: "pki/root/generate/kms",
            namespace: "",
            token: &self.admin,
            body,
            now: 100,
            allow_forward: false,
            enforce_namespace: true,
            wrap_ttl_seconds: None,
            origin_peer: None,
            client_certificates: None,
        })
    }
    fn stage(&mut self, key: &str) -> TestResult<PendingExternalRequest> {
        match self.stage_body(json!({"external_key_ref":format!("hsm:{key}"),"common_name":"genuine-pki.example","ttl":"1h"})) {
            RequestExecution::External(pending) => {
                assert!(matches!(&pending.effect, ExternalEffectPlan::ExternalPki(plan) if plan.genuine.is_some()));
                Ok(*pending)
            },
            RequestExecution::Complete(response) => Err(format!("genuine PKI cfg stage status {}",response.status).into()),
        }
    }
    fn observe(&self, plan: &ExternalPkiPlan) -> TestResult<Observation> {
        let pair_for = |template: &crate::engines::ExternalPkiTemplate| {
            if template.reference == "hsm:first" {
                &self.first
            } else {
                &self.second
            }
        };
        let mut observed = observation(&plan.template, pair_for(&plan.template))?;
        for lane in &plan.related {
            observed
                .related
                .push(observation(&lane.template, pair_for(&lane.template))?);
        }
        Ok(observed)
    }
    fn publish(
        &mut self,
        pending: PendingExternalRequest,
        audit: bool,
    ) -> TestResult<(ExternalPkiPlan, Response, String)> {
        let ExternalEffectPlan::ExternalPki(mut plan) = pending.effect else {
            return Err("PKI plan".into());
        };
        let observation = self.observe(&plan)?;
        let response = self
            .service
            .finalize_external_pki(&mut plan, Ok(observation));
        assert_eq!(response.status, 200);
        assert!(plan.delivery_checkpoint.is_some());
        assert!(!plan.response_audited);
        let response = if audit {
            self.service.audit_external_pki_response(
                &mut plan,
                &pending.fingerprint,
                (pending.now, pending.token_clock),
                response,
                || {},
            )
        } else {
            response
        };
        Ok((plan, response, pending.fingerprint))
    }
}
fn observation(
    template: &crate::engines::ExternalPkiTemplate,
    pair: &PKey<Private>,
) -> TestResult<Observation> {
    let spki = pair.public_key_to_der()?;
    let public = crate::engines::ExternalPkiPublicKey::from_spki(&spki)?;
    let material = template.clone().materialize(public)?;
    let mut signatures = Vec::new();
    for (index, tbs) in material.tbs_parts().enumerate() {
        let signature = if pair.id() == Id::ED25519 {
            Signer::new_without_digest(pair)?.sign_oneshot_to_vec(tbs)?
        } else {
            let digest = match material.hash_algorithm() {
                Some("sha2-384") => MessageDigest::sha384(),
                Some("sha2-512") => MessageDigest::sha512(),
                Some("sha2-256") => MessageDigest::sha256(),
                _ => return Err("cfg unexpected PKI digest".into()),
            };
            let mut signer = Signer::new(digest, pair)?;
            if pair.id() == Id::RSA {
                signer.set_rsa_padding(if material.signature_algorithm() == "pss" {
                    Padding::PKCS1_PSS
                } else {
                    Padding::PKCS1
                })?;
                if material.signature_algorithm() == "pss" {
                    signer.set_rsa_pss_saltlen(RsaPssSaltlen::DIGEST_LENGTH)?;
                }
            }
            signer.update(tbs)?;
            signer.sign_to_vec()?
        };
        let signature = Zeroizing::new(signature);
        material.verify_at(index, &signature)?;
        signatures.push(signature);
    }
    Ok(Observation {
        material: Box::new(material),
        signatures,
        related: Vec::new(),
    })
}

#[test]
fn genuine_pki_public_spki_is_canonical_and_private_unknown_or_trailing_keys_fail() -> TestResult {
    let fixture = Fixture::new()?;
    for pair in [&fixture.first, &fixture.second] {
        let der = pair.public_key_to_der()?;
        let public = crate::engines::ExternalPkiPublicKey::from_spki(&der)?;
        assert!(public.spki()? == der);
        let mut trailing = der.clone();
        trailing.push(0);
        assert!(crate::engines::ExternalPkiPublicKey::from_spki(&trailing).is_err());
        assert!(
            crate::engines::ExternalPkiPublicKey::from_spki(&pair.private_key_to_der()?).is_err()
        );
    }
    let x = PKey::generate_x25519()?;
    assert!(crate::engines::ExternalPkiPublicKey::from_spki(&x.public_key_to_der()?).is_err());
    Ok(())
}

#[test]
fn genuine_pki_real_grant_and_operator_selection_preserve_private_parameters() -> TestResult {
    let mut f = Fixture::new()?;
    let pending = f.stage("first")?;
    let ExternalEffectPlan::ExternalPki(plan) = pending.effect else {
        return Err("PKI plan".into());
    };
    assert!(
        plan.sign_url.is_empty() && plan.metadata_url.is_empty() && plan.provider_binding.is_none()
    );
    let input = SensitiveJson(crate::auth::parse_strict_json(plan.request.expose())?);
    assert!(input.0["config"]["pin"] == "unused-fixture" && input.0["key"]["id"] == "first");
    assert!(input.0.get("token").is_none() && input.0.get("url").is_none());
    assert_eq!(
        call(
            &mut f.service,
            "DELETE",
            "sys/external-keys/configs/hsm/keys/first/grants/pki",
            &f.admin,
            json!({})
        )
        .status,
        204
    );
    assert!(
        matches!(f.stage_body(json!({"external_key_ref":"hsm:first","common_name":"genuine-pki.example"})),RequestExecution::Complete(response) if response.status==400)
    );
    Ok(())
}

#[test]
fn genuine_pki_explicit_key_type_or_bits_are_rejected_before_effect() -> TestResult {
    for extra in [
        json!({"key_type":"ed25519"}),
        json!({"key_type":"rsa"}),
        json!({"key_bits":2048}),
    ] {
        let mut f = Fixture::new()?;
        let mut body = json!({"external_key_ref":"hsm:first","common_name":"genuine-pki.example"});
        for (key, value) in extra.as_object().ok_or("cfg object")? {
            body[key] = value.clone();
        }
        assert!(
            matches!(f.stage_body(body),RequestExecution::Complete(response) if response.status==400)
        );
        assert!(f.service.pending_external_pki.is_none());
    }
    Ok(())
}

#[test]
fn genuine_pki_crypto_ack_wrong_operation_and_noncanonical_bytes_never_succeed() -> TestResult {
    use heptabao_plugin_host::kms_bridge::{Operation, ProviderResult};
    for result in [
        ProviderResult::ConfigOpened,
        ProviderResult::KeyResolved,
        ProviderResult::Verified(true),
    ] {
        assert!(genuine_pki_bytes(result, Operation::ExportPublic, 8192).is_err());
    }
    for (operation, text) in [(Operation::Sign, "AQ=="), (Operation::ExportPublic, "AR==")] {
        let result = ProviderResult::Bytes {
            operation,
            encoded: SecretValue::new(text.as_bytes().to_vec())?,
        };
        assert!(genuine_pki_bytes(result, Operation::ExportPublic, 8192).is_err());
    }
    Ok(())
}

#[test]
fn genuine_pki_original_tbs_signing_options_match_ed_and_ecdsa_without_transit_rehash() -> TestResult
{
    let mut f = Fixture::new()?;
    for selection in ["first", "second", "rsa"] {
        let key = if selection == "rsa" {
            f.first = PKey::from_rsa(Rsa::generate(2048)?)?;
            "first"
        } else {
            selection
        };
        let pending = f.stage(key)?;
        let ExternalEffectPlan::ExternalPki(plan) = pending.effect else {
            return Err("PKI plan".into());
        };
        let pair = if key == "first" { &f.first } else { &f.second };
        let material =
            plan.template
                .clone()
                .materialize(crate::engines::ExternalPkiPublicKey::from_spki(
                    &pair.public_key_to_der()?,
                )?)?;
        for tbs in material.tbs_parts() {
            let request = genuine_pki_sign_request(&plan.request, &material, tbs)
                .map_err(|_| "cfg genuine PKI signing request")?;
            let input = SensitiveJson(crate::auth::parse_strict_json(request.expose())?);
            let actual =
                Zeroizing::new(BASE64.decode(input.0["data"].as_str().ok_or("signing input")?)?);
            assert!(*actual == material.signing_input(tbs)?);
            assert!(input.0["prehashed"] == json!(material.hash_algorithm().is_some()));
            assert!(input.0["hash"] == json!(material.hash_algorithm().unwrap_or("none")));
            assert!(input.0["scheme"] == "hash" && input.0["marshaling"] == "asn1");
            assert!(input.0["config"]["pin"] == "unused-fixture");
        }
    }
    Ok(())
}

#[test]
fn genuine_pki_actual_root_crls_and_related_lane_use_original_hosts_and_verified_signatures()
-> TestResult {
    let mut f = Fixture::new()?;
    let first = f.stage("first")?;
    let (mut plan, response, fingerprint) = f.publish(first, true)?;
    let cert = X509::from_pem(
        response.body["data"]["certificate"]
            .as_str()
            .ok_or("public cert")?
            .as_bytes(),
    )?;
    assert!(cert.verify(&f.first)?);
    let response = f
        .service
        .complete_external_pki_delivery(&mut plan, response, &fingerprint);
    assert_eq!(response.status, 200);
    let second = f.stage("second")?;
    let ExternalEffectPlan::ExternalPki(plan) = &second.effect else {
        return Err("PKI plan".into());
    };
    assert_eq!(plan.related.len(), 1);
    assert!(plan.related.iter().all(|lane| lane.genuine.is_some()));
    assert_eq!(plan.retained_hosts().len(), 1);
    let observation = f.observe(plan)?;
    assert!(observation.signatures.len() >= 3 && observation.related[0].signatures.len() >= 2);
    let (mut plan, response, fingerprint) = f.publish(second, true)?;
    let cert = X509::from_pem(
        response.body["data"]["certificate"]
            .as_str()
            .ok_or("public cert")?
            .as_bytes(),
    )?;
    assert!(cert.verify(&f.second)?);
    assert_eq!(
        f.service
            .complete_external_pki_delivery(&mut plan, response, &fingerprint)
            .status,
        200
    );
    Ok(())
}

#[test]
fn genuine_pki_wrong_signer_is_withheld_before_any_publication() -> TestResult {
    for change in ["altered-signature", "fresh-wrong-key"] {
        let mut f = Fixture::new()?;
        let pending = f.stage("first")?;
        let ExternalEffectPlan::ExternalPki(mut plan) = pending.effect else {
            return Err("PKI plan".into());
        };
        let before = serde_json::to_vec(f.service.state.as_ref().ok_or("state")?)?;
        let mut observed = f.observe(&plan)?;
        if change == "altered-signature" {
            observed.signatures[0][0] ^= 1;
        } else {
            let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1)?;
            let wrong = PKey::from_ec_key(EcKey::generate(&group)?)?;
            assert!(wrong.public_key_to_der()? != f.first.public_key_to_der()?);
            let mut signer = Signer::new(MessageDigest::sha256(), &wrong)?;
            signer.update(&observed.material.tbs)?;
            observed.signatures[0] = Zeroizing::new(signer.sign_to_vec()?);
        }
        let response = f.service.finalize_external_pki(&mut plan, Ok(observed));
        assert_eq!(response.status, 503);
        assert!(response.body.get("data").is_none());
        assert!(serde_json::to_vec(f.service.state.as_ref().ok_or("state")?)? == before);
    }
    Ok(())
}

#[test]
fn genuine_pki_actual_response_audit_is_required_for_delivery() -> TestResult {
    let mut f = Fixture::new()?;
    let pending = f.stage("first")?;
    let (mut plan, response, fingerprint) = f.publish(pending, false)?;
    assert_eq!(
        f.service
            .complete_external_pki_delivery(&mut plan, response, &fingerprint)
            .status,
        503
    );
    Ok(())
}

#[test]
fn genuine_pki_operator_image_change_after_audit_withholds_committed_response() -> TestResult {
    let mut f = Fixture::new()?;
    let pending = f.stage("first")?;
    let (mut plan, response, fingerprint) = f.publish(pending, true)?;
    let before = serde_json::to_vec(f.service.state.as_ref().ok_or("state")?)?;
    fs::write(&f.image, b"#!/bin/sh\nexit 1\n")?;
    let response = f
        .service
        .complete_external_pki_delivery(&mut plan, response, &fingerprint);
    assert_eq!(response.status, 503);
    assert!(response.body.get("data").is_none());
    assert!(serde_json::to_vec(f.service.state.as_ref().ok_or("state")?)? == before);
    Ok(())
}

#[test]
fn genuine_pki_actual_actor_revoke_after_audit_withholds_committed_response() -> TestResult {
    let mut f = Fixture::new()?;
    let pending = f.stage("first")?;
    let (mut plan, response, fingerprint) = f.publish(pending, true)?;
    assert_eq!(
        call(
            &mut f.service,
            "POST",
            "auth/token/revoke-self",
            &f.admin,
            json!({})
        )
        .status,
        204
    );
    let response = f
        .service
        .complete_external_pki_delivery(&mut plan, response, &fingerprint);
    assert_eq!(response.status, 403);
    assert!(response.body.get("data").is_none());
    Ok(())
}

#[test]
fn genuine_pki_next_operation_keeps_original_operator_admission_and_generation() -> TestResult {
    use heptabao_plugin_host::kms_bridge::Operation;
    let mut f = Fixture::new()?;
    let pending = f.stage("first")?;
    let ExternalEffectPlan::ExternalPki(plan) = pending.effect else {
        return Err("PKI plan".into());
    };
    let original = plan.genuine.as_ref().ok_or("original KMS admission")?;
    let signing = original
        .for_operation(Operation::Sign, &plan.request)
        .map_err(|_| "cfg genuine PKI next operation")?;
    assert!(Arc::ptr_eq(original.host_ref(), signing.host_ref()));
    let host = original.host();
    let guard = host.try_lock().map_err(|_| "cfg original host lock")?;
    assert!(original.host_current(&guard) && signing.host_current(&guard));
    drop(guard);
    fs::write(&f.image, b"#!/bin/sh\nexit 1\n")?;
    let guard = host.try_lock().map_err(|_| "cfg original host lock")?;
    assert!(!original.host_current(&guard) && !signing.host_current(&guard));
    Ok(())
}

fn attach_ha(f: &mut Fixture) -> TestResult<crate::ha::snapshot_test_support::Cluster> {
    let cluster_id = f.service.state.as_ref().ok_or("state")?.cluster_id.clone();
    let cluster = crate::ha::snapshot_test_support::Cluster::new(
        &f._root.path.join("genuine-pki-raft"),
        &cluster_id,
    )?;
    f.service.ha = Some(Arc::clone(&cluster.processes[0]));
    f.service
        .sync_from_ha()
        .map_err(|_| "genuine PKI HA seed")?;
    Ok(cluster)
}
fn return_original_leader(cluster: &crate::ha::snapshot_test_support::Cluster) -> TestResult<u64> {
    let next = cluster.processes[0]
        .lock()
        .map_err(|_| "original mutex")?
        .step_down()?;
    assert_ne!(next, 1);
    let returned = cluster.processes[(next - 1) as usize]
        .lock()
        .map_err(|_| "successor mutex")?
        .step_down()?;
    assert_eq!(returned, 1);
    let role = cluster.processes[0]
        .lock()
        .map_err(|_| "returned mutex")?
        .leader_status()?;
    assert!(role.local_is_leader && role.leader == Some(1));
    Ok(role.term)
}

#[test]
fn genuine_pki_original_ha_role_allows_actual_publication_and_final_delivery() -> TestResult {
    let mut f = Fixture::new()?;
    let cluster = attach_ha(&mut f)?;
    let original = cluster.processes[0]
        .lock()
        .map_err(|_| "role mutex")?
        .leader_status()?;
    let pending = f.stage("first")?;
    let (mut plan, response, fingerprint) = f.publish(pending, true)?;
    assert_eq!(
        f.service
            .complete_external_pki_delivery(&mut plan, response, &fingerprint)
            .status,
        200
    );
    let actual = cluster.processes[0]
        .lock()
        .map_err(|_| "role mutex")?
        .leader_status()?;
    assert!(
        actual.local_is_leader
            && (actual.local_id, actual.term) == (original.local_id, original.term)
    );
    Ok(())
}

#[test]
fn genuine_pki_actual_returned_leader_new_term_vetoes_entry_publication_and_delivery() -> TestResult
{
    for phase in ["before-entry", "before-publication", "after-audit"] {
        let mut f = Fixture::new()?;
        let cluster = attach_ha(&mut f)?;
        let original = cluster.processes[0]
            .lock()
            .map_err(|_| "role mutex")?
            .leader_status()?
            .term;
        let pending = f.stage("first")?;
        if phase == "after-audit" {
            let (mut plan, response, fingerprint) = f.publish(pending, true)?;
            assert!(return_original_leader(&cluster)? > original);
            let response =
                f.service
                    .complete_external_pki_delivery(&mut plan, response, &fingerprint);
            assert_eq!(response.status, 503);
            assert!(response.body.get("data").is_none());
        } else {
            let ExternalEffectPlan::ExternalPki(mut plan) = pending.effect else {
                return Err("PKI plan".into());
            };
            let observation = if phase == "before-publication" {
                Some(f.observe(&plan)?)
            } else {
                None
            };
            let before = serde_json::to_vec(f.service.state.as_ref().ok_or("state")?)?;
            assert!(return_original_leader(&cluster)? > original);
            let response = if let Some(observation) = observation {
                f.service.finalize_external_pki(&mut plan, Ok(observation))
            } else {
                plan.execute()
                    .err()
                    .ok_or("new term must stop original entry")?
            };
            assert_eq!(response.status, 503);
            assert!(response.body.get("data").is_none());
            assert!(serde_json::to_vec(f.service.state.as_ref().ok_or("state")?)? == before);
        }
    }
    Ok(())
}

#[test]
fn genuine_pki_original_ha_owner_cannot_be_detached_after_response_audit() -> TestResult {
    let mut f = Fixture::new()?;
    let _cluster = attach_ha(&mut f)?;
    let pending = f.stage("first")?;
    let (mut plan, response, fingerprint) = f.publish(pending, true)?;
    f.service.ha = None;
    let response = f
        .service
        .complete_external_pki_delivery(&mut plan, response, &fingerprint);
    assert_eq!(response.status, 503);
    assert!(response.body.get("data").is_none());
    Ok(())
}

#[test]
fn genuine_pki_mandatory_response_audit_failure_never_delivers_committed_body() -> TestResult {
    let mut f = Fixture::new()?;
    let pending = f.stage("first")?;
    let (mut plan, response, fingerprint) = f.publish(pending, false)?;
    f.service.audit_failed = true;
    let response = f.service.audit_external_pki_response(
        &mut plan,
        &fingerprint,
        (100, None),
        response,
        || {},
    );
    assert_eq!(response.status, 503);
    assert!(!plan.response_audited);
    assert!(f.service.recovery_required);
    let response = f
        .service
        .complete_external_pki_delivery(&mut plan, response, &fingerprint);
    assert_eq!(response.status, 503);
    assert!(response.body.get("data").is_none());
    Ok(())
}
