//! Normal configured File V6, original PKI operations and actual local crypto.
//! No injected Principal, fabricated root/receipt or alternate activation API.
use super::*;
use crate::configuration::NativeStorageProfile;
use crate::service::tests::Root;
use base64::engine::general_purpose::STANDARD as BASE64;
use openssl::{
    hash::MessageDigest,
    ocsp::{OcspCertId, OcspRequest},
    pkey::PKey,
    x509::{X509, X509Crl},
};
use std::thread;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;
const ISSUE_POLICY: &str = "path \"pki/issue/web\" { capabilities=[\"update\"] }";

#[track_caller]
fn status(response: &Response, expected: u16) {
    assert_eq!(
        response.status,
        expected,
        "native PKI error shape={:?}",
        response.body.get("errors")
    );
}
fn text(response: &Response, path: &str) -> TestResult<String> {
    response
        .body
        .pointer(path)
        .and_then(Value::as_str)
        .filter(|v| !v.is_empty())
        .map(str::to_owned)
        .ok_or_else(|| "required synthetic PKI field absent".into())
}
fn secret(response: &mut Response, path: &str) -> TestResult<Zeroizing<String>> {
    let value = Zeroizing::new(text(response, path)?);
    erase_json(&mut response.body);
    Ok(value)
}
fn call(
    service: &mut Service,
    now: &mut u64,
    token: &str,
    method: &str,
    path: &str,
    body: Value,
) -> TestResult<Response> {
    *now += 1;
    let started = Instant::now();
    let clock = RequestClock::anchored(Duration::from_secs(*now), started)?;
    let _deadline =
        crate::request_deadline::RequestDeadlineScope::enter(started + Duration::from_secs(15));
    let execution = service.begin_at_mode_precise(
        RequestDispatch {
            method,
            path,
            namespace: "",
            token,
            body,
            now: *now,
            allow_forward: true,
            enforce_namespace: true,
            wrap_ttl_seconds: None,
            origin_peer: None,
            client_certificates: None,
        },
        clock,
    );
    let response = service.finish_synchronous_request(execution);
    assert!(service.pending_native_auth_delivery.is_none());
    Ok(response)
}
fn role() -> Value {
    json!({"allowed_domains":["example.test"],"allow_subdomains":true,
        "key_type":"ec","key_bits":256,"max_ttl":"2h","generate_lease":true})
}
struct Fixture {
    files: Root,
    service: Service,
    key: Zeroizing<String>,
    admin: Zeroizing<String>,
    now: u64,
}
impl Fixture {
    fn initialized() -> TestResult<Self> {
        let files = Root::new();
        let mut service = files.service()?;
        service.configure_native_v6_storage(NativeStorageProfile::File)?;
        let mut now = 100;
        let mut init = call(
            &mut service,
            &mut now,
            "",
            "POST",
            "sys/init",
            json!({"secret_shares":1,"secret_threshold":1}),
        )?;
        status(&init, 200);
        let key = Zeroizing::new(text(&init, "/keys/0")?);
        let admin = secret(&mut init, "/root_token")?;
        status(
            &call(
                &mut service,
                &mut now,
                "",
                "POST",
                "sys/unseal",
                json!({"key":key.as_str()}),
            )?,
            200,
        );
        status(
            &call(
                &mut service,
                &mut now,
                &admin,
                "POST",
                "sys/init/ack",
                json!({}),
            )?,
            204,
        );
        Ok(Self {
            files,
            service,
            key,
            admin,
            now,
        })
    }
    fn new() -> TestResult<Self> {
        let mut f = Self::initialized()?;
        status(
            &f.admin("POST", native_storage::ACTIVATE_PATH, json!({}))?,
            204,
        );
        f.assert_native()?;
        status(
            &f.admin(
                "POST",
                "sys/mounts/pki-kv",
                json!({"type":"kv","options":{"version":"2"}}),
            )?,
            204,
        );
        status(
            &f.admin(
                "POST",
                "pki-kv/data/sentinel",
                json!({"options":{"cas":0},"data":{"value":"pki-keeps-native-kv"}}),
            )?,
            200,
        );
        f.install()?;
        Ok(f)
    }
    fn install(&mut self) -> TestResult {
        status(
            &self.admin("POST", "sys/mounts/pki", json!({"type":"pki"}))?,
            204,
        );
        status(
            &self.admin(
                "POST",
                "pki/root/generate/internal",
                json!({
            "common_name":"ca.example.test","key_type":"ec","key_bits":256,"ttl":"48h"}),
            )?,
            200,
        );
        status(&self.admin("POST", "pki/roles/web", role())?, 200);
        Ok(())
    }
    fn assert_native(&self) -> TestResult {
        assert!(matches!(
            self.service.native_storage_profile,
            Some(NativeStorageProfile::File)
        ));
        assert!(self.service.native_candidate_profile.is_some());
        assert!(self.service.native_root.is_some() && self.service.record_root.is_none());
        assert!(!self.service.recovery_required);
        assert!(
            self.service
                .state
                .as_ref()
                .ok_or("state")?
                .engines
                .supports_native_v6_root_storage()
        );
        Ok(())
    }
    fn admin(&mut self, method: &str, path: &str, body: Value) -> TestResult<Response> {
        call(
            &mut self.service,
            &mut self.now,
            &self.admin,
            method,
            path,
            body,
        )
    }
    fn actor(
        &mut self,
        token: &str,
        method: &str,
        path: &str,
        body: Value,
    ) -> TestResult<Response> {
        call(&mut self.service, &mut self.now, token, method, path, body)
    }
    fn restart(mut self) -> TestResult<Self> {
        drop(self.service);
        self.service = self.files.service()?;
        self.service
            .configure_native_v6_storage(NativeStorageProfile::File)?;
        status(
            &call(
                &mut self.service,
                &mut self.now,
                "",
                "POST",
                "sys/unseal",
                json!({"key":self.key.as_str()}),
            )?,
            200,
        );
        self.assert_native()?;
        Ok(self)
    }
    fn root(&self) -> TestResult<RecordStateRootV6> {
        self.service
            .native_root
            .clone()
            .ok_or_else(|| "native root".into())
    }
    fn graphs_unchanged(&self, before: &RecordStateRootV6) -> TestResult {
        let after = self.root()?;
        assert!(before.kv1 == after.kv1 && before.kv2 == after.kv2);
        assert_eq!(before.cluster_id, after.cluster_id);
        assert_eq!(before.replay_epoch, after.replay_epoch);
        Ok(())
    }
    fn sentinel(&mut self) -> TestResult {
        let response = self.admin("GET", "pki-kv/data/sentinel", json!({}))?;
        status(&response, 200);
        assert_eq!(response.body["data"]["metadata"]["version"], 1);
        assert_eq!(
            response.body["data"]["data"]["value"],
            "pki-keeps-native-kv"
        );
        Ok(())
    }
    fn issue(&mut self, token: &str) -> TestResult<Response> {
        let response = self.actor(
            token,
            "POST",
            "pki/issue/web",
            json!({"common_name":"api.example.test","ttl":"1h"}),
        )?;
        status(&response, 200);
        Ok(response)
    }
    fn policy(&mut self, name: &str, policy: &str) -> TestResult {
        status(
            &self.admin(
                "POST",
                &format!("sys/policies/acl/{name}"),
                json!({"policy":policy}),
            )?,
            204,
        );
        Ok(())
    }
    fn token(&mut self, policy: &str, ttl: &str) -> TestResult<Zeroizing<String>> {
        let mut response = self.admin(
            "POST",
            "auth/token/create",
            json!({
            "policies":[policy],"no_default_policy":true,"ttl":ttl}),
        )?;
        status(&response, 200);
        secret(&mut response, "/auth/client_token")
    }
    fn idle(&mut self, now: u64) -> TestResult<bool> {
        self.now = now;
        let started = Instant::now();
        let clock = RequestClock::anchored(Duration::from_secs(now), started)?;
        let _deadline =
            crate::request_deadline::RequestDeadlineScope::enter(started + Duration::from_secs(15));
        Ok(self
            .service
            .maintain_native_transit_with_clock_for_test(now, clock)?)
    }
    fn audited(
        &mut self,
        token: &str,
        method: &str,
        path: &str,
        body: Value,
        budget: Duration,
    ) -> TestResult<(Response, Instant)> {
        self.now += 1;
        let started = Instant::now();
        let until = started + budget;
        let clock = RequestClock::anchored(Duration::from_secs(self.now), started)?;
        let _deadline = crate::request_deadline::RequestDeadlineScope::enter(until);
        let response = self.service.handle_inner(RequestView {
            method,
            path,
            namespace: "",
            token,
            body: &body,
            now: self.now,
            admission_started: started,
            token_clock: Some(clock),
            allow_forward: true,
            enforce_namespace: true,
            wrap_ttl_seconds: None,
            origin_peer: None,
            client_certificates: None,
        });
        status(&response, 200);
        let delivery = self
            .service
            .pending_native_auth_delivery
            .as_ref()
            .ok_or("actual PKI owner")?;
        assert!(delivery.pki_owner.is_some() && delivery.requires_local_proof());
        assert!(delivery.tracks_terminal_checkpoint() && delivery.proof.is_none());
        let response = self.service.audit_completed_response_with_receipt(
            "native-pki-actual-audit",
            self.now,
            Some(clock),
            response,
            || {},
        );
        status(&response, 200);
        let delivery = self
            .service
            .pending_native_auth_delivery
            .as_ref()
            .ok_or("audited PKI owner")?;
        assert!(matches!(
            delivery.proof.as_ref(),
            Some(native_v6_reader::NativeProof::Single(_))
        ));
        Ok((response, until))
    }
    fn complete(&mut self, response: Response, until: Instant) -> Response {
        let _deadline = crate::request_deadline::RequestDeadlineScope::enter(until);
        self.service
            .complete_native_auth_delivery(true, response, "pki-original-audited-delivery")
    }
}
fn verify_leaf(response: &Response) -> TestResult<(X509, X509)> {
    let leaf = X509::from_pem(text(response, "/data/certificate")?.as_bytes())?;
    let issuer = X509::from_pem(text(response, "/data/issuing_ca")?.as_bytes())?;
    let issuer_key = issuer.public_key()?;
    assert!(leaf.verify(&issuer_key)?);
    if let Some(pem) = response.body["data"]["private_key"].as_str() {
        let key = PKey::private_key_from_pem(pem.as_bytes())?;
        assert!(leaf.public_key()?.public_eq(&key));
    }
    Ok((leaf, issuer))
}
fn verify_crl(response: &Response, issuer: &X509, serial: Option<&X509>) -> TestResult {
    status(response, 200);
    let crl = X509Crl::from_pem(text(response, "/data/certificate")?.as_bytes())?;
    let issuer_key = issuer.public_key()?;
    assert!(crl.verify(&issuer_key)?);
    if let Some(leaf) = serial {
        let target = leaf.serial_number().to_bn()?.to_vec();
        let mut found = false;
        if let Some(revoked) = crl.get_revoked() {
            for entry in revoked {
                found |= entry.serial_number().to_bn()?.to_vec() == target;
            }
        }
        assert!(
            found,
            "actual revoked certificate serial must be in the signed CRL"
        );
    }
    Ok(())
}
fn private_bytes_absent(path: &std::path::Path, secret: &[u8]) -> TestResult {
    assert!(!secret.is_empty());
    for entry in fs::read_dir(path)? {
        let entry = entry?;
        let kind = entry.file_type()?;
        assert!(!kind.is_symlink());
        if kind.is_dir() {
            private_bytes_absent(&entry.path(), secret)?;
        } else if kind.is_file() {
            let bytes = fs::read(entry.path())?;
            assert!(!bytes.windows(secret.len()).any(|window| window == secret));
        }
    }
    Ok(())
}
fn no_secret(response: &Response) {
    assert_eq!(response.status, 503);
    assert!(response.body.get("data").is_none());
    assert!(response.body.get("auth").is_none());
    assert!(response.consistency_index.is_none());
}

#[test]
fn native_pki_formal_source_promotion_preserves_existing_signer_certificate_and_lease() -> TestResult
{
    let mut f = Fixture::initialized()?;
    f.install()?;
    let admin = Zeroizing::new(f.admin.to_string());
    let mut issued = f.issue(&admin)?;
    let serial = text(&issued, "/data/serial_number")?;
    let certificate = text(&issued, "/data/certificate")?;
    let issuer = text(&issued, "/data/issuing_ca")?;
    let lease = text(&issued, "/lease_id")?;
    verify_leaf(&issued)?;
    erase_json(&mut issued.body);
    assert!(f.service.native_root.is_none());
    assert!(matches!(
        f.service
            .current_state_identity()
            .map_err(|_| "source identity")?,
        crate::state_record_root::StateIdentity::RecordsV5(_)
    ));
    status(
        &f.admin("POST", native_storage::ACTIVATE_PATH, json!({}))?,
        204,
    );
    let mut f = f.restart()?;
    let read = f.actor("", "GET", &format!("pki/cert/{serial}"), json!({}))?;
    status(&read, 200);
    assert_eq!(read.body["data"]["certificate"], certificate);
    status(
        &f.admin("POST", "sys/leases/lookup", json!({"lease_id":lease}))?,
        200,
    );
    let mut again = f.issue(&admin)?;
    verify_leaf(&again)?;
    assert_eq!(again.body["data"]["issuing_ca"], issuer);
    erase_json(&mut again.body);
    Ok(())
}

#[test]
fn native_pki_formal_issue_revoke_crl_and_cold_storage_preserve_real_crypto() -> TestResult {
    let mut f = Fixture::new()?;
    let before = f.root()?;
    let admin = Zeroizing::new(f.admin.to_string());
    let mut issued = f.issue(&admin)?;
    let (leaf, issuer) = verify_leaf(&issued)?;
    let serial = text(&issued, "/data/serial_number")?;
    let lease = text(&issued, "/lease_id")?;
    let private = Zeroizing::new(text(&issued, "/data/private_key")?);
    assert_eq!(issued.body["renewable"], false);
    erase_json(&mut issued.body);
    private_bytes_absent(&f.service.data_dir, private.as_bytes())?;
    f.graphs_unchanged(&before)?;
    let mut f = f.restart()?;
    status(
        &f.admin("POST", "sys/leases/lookup", json!({"lease_id":lease}))?,
        200,
    );
    status(
        &f.admin(
            "POST",
            "sys/leases/renew",
            json!({"lease_id":lease,"increment":"2h"}),
        )?,
        400,
    );
    status(
        &f.admin("POST", "sys/leases/revoke", json!({"lease_id":lease}))?,
        204,
    );
    // Inspect the installed immutable cache before any subsequent Service
    // request can reconcile it. The actual 204 already owns the signed CRL.
    let mut cached = f
        .service
        .state
        .as_ref()
        .ok_or("state")?
        .engines
        .handle_public_pki_read("", "GET", "pki/cert/crl", &json!({}), f.now)?
        .ok_or("installed CRL cache")?;
    let cached = Response {
        status: cached.status,
        body: std::mem::take(&mut cached.body),
        unwrapped_json: None,
        response_headers: Default::default(),
        consistency_index: None,
    };
    verify_crl(&cached, &issuer, Some(&leaf))?;
    let observed = f.actor("", "GET", &format!("pki/cert/{serial}"), json!({}))?;
    status(&observed, 200);
    let revoked = observed.body["data"]["revocation_time"]
        .as_u64()
        .ok_or("revocation")?;
    assert!(revoked > 0);
    let before_rotation = f.actor("", "GET", "pki/cert/crl", json!({}))?;
    verify_crl(&before_rotation, &issuer, Some(&leaf))?;
    let rotated = f.admin("GET", "pki/crl/rotate", json!({}))?;
    status(&rotated, 200);
    assert_eq!(rotated.body["data"]["success"], true);
    let after_rotation = f.actor("", "GET", "pki/cert/crl", json!({}))?;
    verify_crl(&after_rotation, &issuer, Some(&leaf))?;
    let retained_crl = text(&after_rotation, "/data/certificate")?;
    assert_ne!(text(&before_rotation, "/data/certificate")?, retained_crl);
    let mut f = f.restart()?;
    let cold = f.actor("", "GET", &format!("pki/cert/{serial}"), json!({}))?;
    status(&cold, 200);
    assert_eq!(cold.body["data"]["revocation_time"], revoked);
    let cold_crl = f.actor("", "GET", "pki/cert/crl", json!({}))?;
    verify_crl(&cold_crl, &issuer, Some(&leaf))?;
    assert_eq!(text(&cold_crl, "/data/certificate")?, retained_crl);

    // The second original GET is also a write, with an actual pending serial
    // outside the retained full CRL. Its real signature/cache survives reopen.
    status(
        &f.admin(
            "POST",
            "pki/config/crl",
            json!({"auto_rebuild":true,
        "enable_delta":true,"expiry":"2h","auto_rebuild_grace_period":"5m",
        "delta_rebuild_interval":"1m"}),
        )?,
        200,
    );
    let mut second = f.issue(&admin)?;
    let (second_leaf, _) = verify_leaf(&second)?;
    let second_lease = text(&second, "/lease_id")?;
    erase_json(&mut second.body);
    status(
        &f.admin(
            "POST",
            "sys/leases/revoke",
            json!({"lease_id":second_lease}),
        )?,
        204,
    );
    let rotated = f.admin("GET", "pki/crl/rotate-delta", json!({}))?;
    status(&rotated, 200);
    assert_eq!(rotated.body["data"]["success"], true);
    let delta = f.actor("", "GET", "pki/cert/delta-crl", json!({}))?;
    verify_crl(&delta, &issuer, Some(&second_leaf))?;
    let retained_delta = text(&delta, "/data/certificate")?;
    let mut f = f.restart()?;
    let cold_delta = f.actor("", "GET", "pki/cert/delta-crl", json!({}))?;
    verify_crl(&cold_delta, &issuer, Some(&second_leaf))?;
    assert_eq!(text(&cold_delta, "/data/certificate")?, retained_delta);
    f.sentinel()
}

#[test]
fn native_pki_formal_no_store_has_no_phantom_lease_or_certificate() -> TestResult {
    let mut f = Fixture::new()?;
    let mut policy = role();
    policy["no_store"] = json!(true);
    status(&f.admin("POST", "pki/roles/ephemeral", policy)?, 200);
    let before_owners = f
        .service
        .state
        .as_ref()
        .ok_or("state")?
        .engines
        .lease_owners();
    let mut response = f.admin(
        "POST",
        "pki/issue/ephemeral",
        json!({"common_name":"api.example.test","ttl":"1h"}),
    )?;
    status(&response, 200);
    verify_leaf(&response)?;
    assert_eq!(response.body["lease_id"], "");
    assert_eq!(response.body["lease_duration"], 0);
    let serial = text(&response, "/data/serial_number")?;
    erase_json(&mut response.body);
    assert!(
        f.service
            .state
            .as_ref()
            .ok_or("state")?
            .engines
            .lease_owners()
            == before_owners
    );
    let mut f = f.restart()?;
    status(
        &f.actor("", "GET", &format!("pki/cert/{serial}"), json!({}))?,
        404,
    );
    f.sentinel()
}

#[test]
fn native_pki_formal_intermediate_signing_keeps_actual_chain_after_cold_restart() -> TestResult {
    let mut f = Fixture::new()?;
    status(
        &f.admin("POST", "sys/mounts/intermediate", json!({"type":"pki"}))?,
        204,
    );
    let generated = f.admin(
        "POST",
        "intermediate/intermediate/generate/internal",
        json!({
        "common_name":"intermediate.example.test","key_type":"ec","key_bits":256}),
    )?;
    status(&generated, 200);
    let csr = text(&generated, "/data/csr")?;
    let signed = f.admin(
        "POST",
        "pki/root/sign-intermediate",
        json!({"csr":csr,"ttl":"24h"}),
    )?;
    status(&signed, 200);
    let intermediate = text(&signed, "/data/certificate")?;
    status(
        &f.admin(
            "POST",
            "intermediate/intermediate/set-signed",
            json!({"certificate":intermediate}),
        )?,
        200,
    );
    status(&f.admin("POST", "intermediate/roles/web", role())?, 200);
    let mut f = f.restart()?;
    let mut issued = f.admin(
        "POST",
        "intermediate/issue/web",
        json!({"common_name":"api.example.test","ttl":"1h"}),
    )?;
    status(&issued, 200);
    let (_leaf, issuer) = verify_leaf(&issued)?;
    assert_eq!(
        issuer.to_der()?,
        X509::from_pem(intermediate.as_bytes())?.to_der()?
    );
    let root = f.actor("", "GET", "pki/cert/ca", json!({}))?;
    status(&root, 200);
    let ca = X509::from_pem(text(&root, "/data/certificate")?.as_bytes())?;
    let ca_key = ca.public_key()?;
    assert!(issuer.verify(&ca_key)?);
    erase_json(&mut issued.body);
    f.sentinel()
}

#[test]
fn native_pki_formal_public_ocsp_uses_original_anonymous_semantics_and_real_signature() -> TestResult
{
    let mut f = Fixture::new()?;
    let admin = Zeroizing::new(f.admin.to_string());
    let mut issued = f.issue(&admin)?;
    let (leaf, issuer) = verify_leaf(&issued)?;
    erase_json(&mut issued.body);
    let mut request = OcspRequest::new()?;
    request.add_id(OcspCertId::from_cert(
        MessageDigest::sha256(),
        &leaf,
        &issuer,
    )?)?;
    let response = f.actor(
        "deliberately-invalid-synthetic-bearer",
        "POST",
        "pki/ocsp",
        json!({"__heptabao_pki_ocsp_request":BASE64.encode(request.to_der()?)}),
    )?;
    status(&response, 200);
    let raw =
        crate::engines::raw_ocsp_response(response.status, &response.body).ok_or("raw OCSP")?;
    let parsed = openssl::ocsp::OcspResponse::from_der(&raw)?;
    assert_eq!(
        parsed.status(),
        openssl::ocsp::OcspResponseStatus::SUCCESSFUL
    );
    let mut issuers = openssl::stack::Stack::new()?;
    issuers.push(issuer.clone())?;
    let mut trust = openssl::x509::store::X509StoreBuilder::new()?;
    trust.add_cert(issuer)?;
    let mut time = openssl::x509::verify::X509VerifyParam::new()?;
    time.set_time(f.now.try_into()?);
    trust.set_param(&time)?;
    parsed
        .basic()?
        .verify(&issuers, &trust.build(), openssl::ocsp::OcspFlag::empty())?;
    let mut f = f.restart()?;
    status(
        &f.actor("also-invalid", "GET", "pki/cert/ca", json!({}))?,
        200,
    );
    f.sentinel()
}

#[test]
fn native_pki_formal_audited_public_reply_status_change_is_vetoed() -> TestResult {
    let mut f = Fixture::new()?;
    let (mut response, until) =
        f.audited("", "GET", "pki/cert/ca", json!({}), Duration::from_secs(15))?;
    assert!(response.body["data"]["certificate"].is_string());
    response.status = 503;
    no_secret(&f.complete(response, until));
    assert!(f.service.pending_native_auth_delivery.is_none());
    Ok(())
}

#[test]
fn native_pki_formal_audited_issue_rechecks_current_policy_without_resigning() -> TestResult {
    let mut f = Fixture::new()?;
    f.policy("pki-issue", ISSUE_POLICY)?;
    let actor = f.token("pki-issue", "600s")?;
    let (response, until) = f.audited(
        &actor,
        "POST",
        "pki/issue/web",
        json!({"common_name":"api.example.test","ttl":"1h"}),
        Duration::from_secs(15),
    )?;
    let serial = text(&response, "/data/serial_number")?;
    let certificate = text(&response, "/data/certificate")?;
    let capsule = f
        .service
        .pending_native_auth_delivery
        .take()
        .ok_or("original audited capsule")?;
    f.policy(
        "pki-issue",
        "path \"pki/issue/web\" { capabilities=[\"deny\"] }",
    )?;
    assert!(f.service.pending_native_auth_delivery.is_none());
    f.service.pending_native_auth_delivery = Some(capsule);
    no_secret(&f.complete(response, until));
    let mut f = f.restart()?;
    let issued = f.actor("", "GET", &format!("pki/cert/{serial}"), json!({}))?;
    status(&issued, 200);
    assert_eq!(issued.body["data"]["certificate"], certificate);
    let denied = f.actor(
        &actor,
        "POST",
        "pki/issue/web",
        json!({"common_name":"again.example.test","ttl":"1h"}),
    )?;
    status(&denied, 403);
    assert!(denied.body.get("data").is_none());
    f.sentinel()
}

#[test]
fn native_pki_formal_audited_issue_cannot_refresh_original_deadline() -> TestResult {
    let mut f = Fixture::new()?;
    let admin = Zeroizing::new(f.admin.to_string());
    let (response, until) = f.audited(
        &admin,
        "POST",
        "pki/issue/web",
        json!({"common_name":"api.example.test","ttl":"1h"}),
        Duration::from_millis(1500),
    )?;
    thread::sleep(until.saturating_duration_since(Instant::now()) + Duration::from_millis(20));
    no_secret(&f.complete(response, until));
    assert!(f.service.pending_native_auth_delivery.is_none());
    Ok(())
}

#[test]
fn native_pki_formal_audited_issue_retains_original_precise_issuer_expiry() -> TestResult {
    let mut f = Fixture::new()?;
    f.policy("pki-issue", ISSUE_POLICY)?;
    let actor = f.token("pki-issue", "2s")?;
    let (response, until) = f.audited(
        &actor,
        "POST",
        "pki/issue/web",
        json!({"common_name":"api.example.test","ttl":"1h"}),
        Duration::from_secs(15),
    )?;
    // This sleeps inside the same original 15-second admission, not a new one.
    thread::sleep(Duration::from_millis(1200));
    let denied = f.complete(response, until);
    status(&denied, 403);
    assert!(denied.body.get("data").is_none() && denied.body.get("auth").is_none());
    assert!(denied.consistency_index.is_none());
    Ok(())
}

#[test]
fn native_pki_formal_idle_reconciles_actual_batch_expiry_and_persists_crl() -> TestResult {
    let mut f = Fixture::new()?;
    f.policy("pki-issue", ISSUE_POLICY)?;
    status(
        &f.admin("POST", "sys/auth/up", json!({"type":"userpass"}))?,
        204,
    );
    status(
        &f.admin(
            "POST",
            "auth/up/users/batch",
            json!({
        "password":"synthetic-pki-batch-password","policies":["pki-issue"],
        "token_type":"batch","token_ttl":120,"token_max_ttl":600,"token_num_uses":0}),
        )?,
        204,
    );
    let mut login = f.actor(
        "",
        "POST",
        "auth/up/login/batch",
        json!({"password":"synthetic-pki-batch-password"}),
    )?;
    status(&login, 200);
    assert_eq!(login.body["auth"]["token_type"], "batch");
    let actor = secret(&mut login, "/auth/client_token")?;
    let lookup = f.actor(&actor, "GET", "auth/token/lookup-self", json!({}))?;
    status(&lookup, 200);
    let expires = lookup.body["data"]["expire_time_unix"]
        .as_u64()
        .ok_or("batch expiry")?;
    let mut issued = f.issue(&actor)?;
    let (leaf, issuer) = verify_leaf(&issued)?;
    let certificate_end = issued.body["data"]["expiration"]
        .as_u64()
        .ok_or("leaf expiry")?;
    assert!(certificate_end > expires);
    let lease_ttl = issued.body["lease_duration"]
        .as_u64()
        .ok_or("batch lease TTL")?;
    assert!(lease_ttl > 0 && lease_ttl <= expires.saturating_sub(f.now));
    let lease_id = text(&issued, "/lease_id")?;
    let actual = f.service.state.clone().ok_or("actual batch PKI state")?;
    assert_eq!(actual.schema, AUTH_SECURITY_CONTRACT_STATE_SCHEMA);
    assert_eq!(actual.writer_schema(), AUTH_SECURITY_CONTRACT_STATE_SCHEMA);
    actual
        .validate_format()
        .map_err(|_| "actual reader admission")?;
    let root = f.root()?;
    assert_eq!(root.state_schema, AUTH_SECURITY_CONTRACT_STATE_SCHEMA);
    assert_eq!(
        root.reader_floor.minimum_state_schema,
        AUTH_SECURITY_CONTRACT_STATE_SCHEMA
    );
    let mut historical136 = actual.clone();
    historical136
        .auth
        .restore_pre141_security_owners_for_format_test();
    historical136.schema = PKI_BATCH_LEASE_STATE_SCHEMA;
    assert!(historical136.engines.has_pki_batch_lease_state());
    assert!(!historical136.auth.has_security_contract_state());
    assert!(historical136.validate_format().is_ok());
    assert_eq!(historical136.writer_schema(), PKI_BATCH_LEASE_STATE_SCHEMA);
    let mut lowered = historical136.clone();
    lowered.schema = APPROLE_NO_DEFAULT_STATE_SCHEMA;
    assert_eq!(
        lowered
            .validate_format()
            .err()
            .ok_or("reader downgrade")?
            .status,
        503
    );
    assert!(lowered.validate_publication_schema(Some(&actual)).is_err());
    assert_eq!(
        Service::validate_snapshot_protected_floor(&actual, &lowered)
            .err()
            .ok_or("snapshot downgrade")?
            .status,
        400,
    );
    let serial = text(&issued, "/data/serial_number")?;
    erase_json(&mut issued.body);
    let owners = f
        .service
        .state
        .as_ref()
        .ok_or("state")?
        .engines
        .lease_owners();
    assert!(
        owners
            .iter()
            .any(|(_, owner)| owner.batch_claims().is_some())
    );
    let mut f = f.restart()?;
    let lookup = f.admin("POST", "sys/leases/lookup", json!({"lease_id":lease_id}))?;
    status(&lookup, 200);
    let retained_ttl = lookup.body["data"]["ttl"]
        .as_u64()
        .ok_or("cold batch lease TTL")?;
    assert!(retained_ttl > 0 && retained_ttl <= expires.saturating_sub(f.now));
    assert!(f.idle(expires + 1)?);
    let mut f = f.restart()?;
    let observed = f.actor("", "GET", &format!("pki/cert/{serial}"), json!({}))?;
    status(&observed, 200);
    assert!(
        observed.body["data"]["revocation_time"]
            .as_u64()
            .is_some_and(|v| v >= expires)
    );
    verify_crl(
        &f.actor("", "GET", "pki/cert/crl", json!({}))?,
        &issuer,
        Some(&leaf),
    )?;
    status(
        &f.actor(
            &actor,
            "POST",
            "pki/issue/web",
            json!({"common_name":"late.example.test","ttl":"1h"}),
        )?,
        403,
    );
    status(&f.admin("DELETE", "sys/mounts/pki", json!({}))?, 204);
    let mut f = f.restart()?;
    let retired = f.service.state.as_ref().ok_or("retired batch PKI state")?;
    assert!(!retired.engines.has_pki_batch_lease_state());
    assert_eq!(retired.schema, AUTH_SECURITY_CONTRACT_STATE_SCHEMA);
    assert_eq!(retired.writer_schema(), AUTH_SECURITY_CONTRACT_STATE_SCHEMA);
    assert!(retired.validate_format().is_ok());
    assert_eq!(
        Service::validate_snapshot_protected_floor(retired, &lowered)
            .err()
            .ok_or("retired snapshot downgrade")?
            .status,
        400,
    );
    f.sentinel()
}

#[test]
fn native_pki_formal_idle_checkpoint_preserves_original_transit_rotation() -> TestResult {
    let mut f = Fixture::new()?;
    status(
        &f.admin("POST", "sys/mounts/transit", json!({"type":"transit"}))?,
        204,
    );
    status(
        &f.admin(
            "POST",
            "transit/keys/automatic",
            json!({"auto_rotate_period":"1h"}),
        )?,
        200,
    );
    status(
        &f.admin(
            "POST",
            "pki/config/crl",
            json!({
        "auto_rebuild":true,"expiry":"2h","auto_rebuild_grace_period":"5m"}),
        )?,
        200,
    );
    // Changing expiry does not immediately re-sign a CRL in OpenBao 2.7.1.
    // Establish an actual two-hour CRL through the public rotation operation
    // before testing idle rebuild and the independent Transit continuation.
    status(&f.admin("GET", "pki/crl/rotate", json!({}))?, 200);
    let before = f.actor("", "GET", "pki/cert/crl", json!({}))?;
    status(&before, 200);
    let old_crl = text(&before, "/data/certificate")?;
    let cached = X509Crl::from_pem(old_crl.as_bytes())?;
    let lifetime = cached
        .last_update()
        .diff(cached.next_update().ok_or("CRL nextUpdate")?)?;
    assert_eq!(
        i64::from(lifetime.days) * 86_400 + i64::from(lifetime.secs),
        7200
    );
    let before_graphs = f.root()?;
    assert!(f.idle(f.now + 7201)?);
    f.graphs_unchanged(&before_graphs)?;
    let mut f = f.restart()?;
    let key = f.admin("GET", "transit/keys/automatic", json!({}))?;
    status(&key, 200);
    assert_eq!(key.body["data"]["latest_version"], 2);
    let new_crl = f.actor("", "GET", "pki/cert/crl", json!({}))?;
    status(&new_crl, 200);
    assert_ne!(text(&new_crl, "/data/certificate")?, old_crl);
    let ca = f.actor("", "GET", "pki/cert/ca", json!({}))?;
    status(&ca, 200);
    verify_crl(
        &new_crl,
        &X509::from_pem(text(&ca, "/data/certificate")?.as_bytes())?,
        None,
    )?;
    f.sentinel()
}

fn wire_role(f: &mut Fixture, token: &str, body: &str) -> TestResult<Response> {
    f.now += 1;
    let now = f.now;
    let started = Instant::now();
    let clock = RequestClock::anchored(Duration::from_secs(now), started)?;
    let _deadline =
        crate::request_deadline::RequestDeadlineScope::enter(started + Duration::from_secs(15));
    let wire = Zeroizing::new(format!(
        "POST /v1/pki/roles/wire HTTP/1.1\r\nHost: 127.0.0.1\r\nX-Vault-Token: {token}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nAccept: application/json\r\n\r\n{body}",
        body.len()
    ));
    Ok(crate::http::logical_data_wire_dispatch_fixture(
        wire.as_bytes(),
        |request| {
            assert!(
                crate::http::pki_role_fields::request(request.method, request.path, &request.body)
                    .is_ok_and(|carrier| carrier.is_some())
            );
            let execution = f.service.begin_at_mode_precise(
                RequestDispatch {
                    method: request.method,
                    path: request.path,
                    namespace: request.namespace,
                    token: request.token,
                    body: request.body,
                    now,
                    allow_forward: true,
                    enforce_namespace: true,
                    wrap_ttl_seconds: request.wrap_ttl_seconds,
                    origin_peer: request.origin_peer,
                    client_certificates: request.client_certificates,
                },
                clock,
            );
            f.service.finish_synchronous_request(execution)
        },
    )?)
}

#[test]
fn native_pki_formal_role_numeric_transport_preserves_original_parameter_acl() -> TestResult {
    let mut f = Fixture::new()?;
    let before = f.root()?;
    // Actual OpenBao 2.7.1 HTTP/HCL comparison: numeric policy values do
    // not equal HTTP numbers, and transport must not turn a JSON number
    // into a string before ACL admission. Only the backend restores spelling.
    for (allowed, spelling, expected) in [
        ("[256]", "256", 403),
        ("[256]", r#""256""#, 403),
        (r#"["256"]"#, "256", 403),
        (r#"["256"]"#, r#""256""#, 200),
        ("[]", "256", 200),
        ("[]", r#""256""#, 200),
    ] {
        f.policy(
            "pki-role",
            &format!(
                r#"path "pki/roles/wire" {{ capabilities=["create","update"] allowed_parameters={{ "signature_bits"={allowed} "*"=[] }} }}"#
            ),
        )?;
        let actor = f.token("pki-role", "600s")?;
        let response = wire_role(
            &mut f,
            &actor,
            &format!(
                r#"{{"allowed_domains":["example.test"],"allow_subdomains":true,"key_type":"ec","signature_bits":{spelling}}}"#
            ),
        )?;
        status(&response, expected);
        if expected == 200 {
            let stored = f.admin("GET", "pki/roles/wire", json!({}))?;
            status(&stored, 200);
            assert_eq!(stored.body["data"]["signature_bits"], 256);
        } else {
            assert!(response.body.get("data").is_none());
        }
        f.graphs_unchanged(&before)?;
    }
    f.sentinel()
}

#[test]
fn native_pki_formal_selectors_retain_acme_external_and_foreign_owner_fences() -> TestResult {
    let mut f = Fixture::new()?;
    let before = f.root()?;
    for path in [
        "pki/config/acme",
        "pki/acme/new-account",
        "pki/eab",
        "pki/root/generate/kms",
        "pki/keys/generate/kms",
    ] {
        let denied = f.admin("POST", path, json!({}))?;
        status(&denied, 501);
        assert!(denied.body.get("data").is_none());
    }
    // Remount has a formal operation owner now. A PKI issue capability
    // must still not authorize moving that owner or enqueue a remount task.
    f.policy("pki-no-remount", ISSUE_POLICY)?;
    let actor = f.token("pki-no-remount", "600s")?;
    let denied = f.actor(
        &actor,
        "POST",
        "sys/remount",
        json!({"from":"pki","to":"other"}),
    )?;
    status(&denied, 403);
    assert!(denied.body.get("data").is_none());
    assert!(f.service.pending_native_remount.is_none());
    assert!(f.service.native_remount_jobs.is_empty());
    assert!(f.service.native_remount_statuses.is_empty());
    // SSH has its own native owner; Kubernetes remains outside this profile.
    let denied = f.admin("POST", "sys/mounts/foreign", json!({"type":"kubernetes"}))?;
    status(&denied, 501);
    f.graphs_unchanged(&before)?;
    let mut f = f.restart()?;
    let mut issued = f.admin(
        "POST",
        "pki/issue/web",
        json!({"common_name":"still.example.test","ttl":"1h"}),
    )?;
    status(&issued, 200);
    verify_leaf(&issued)?;
    erase_json(&mut issued.body);
    f.sentinel()
}

#[test]
fn native_pki_formal_lease_prefix_requires_sudo_and_revocation_keeps_real_owner() -> TestResult {
    let mut f = Fixture::new()?;
    f.policy(
        "pki-prefix",
        "path \"sys/leases/revoke-prefix/pki/\" { capabilities=[\"update\"] }",
    )?;
    let actor = f.token("pki-prefix", "600s")?;
    let admin = Zeroizing::new(f.admin.to_string());
    let mut issued = f.issue(&admin)?;
    let (leaf, issuer) = verify_leaf(&issued)?;
    let lease = text(&issued, "/lease_id")?;
    erase_json(&mut issued.body);
    status(
        &f.actor(&actor, "POST", "sys/leases/revoke-prefix/pki/", json!({}))?,
        403,
    );
    status(
        &f.admin("POST", "sys/leases/lookup", json!({"lease_id":lease}))?,
        200,
    );
    f.policy(
        "pki-prefix",
        "path \"sys/leases/revoke-prefix/pki/\" { capabilities=[\"update\",\"sudo\"] }",
    )?;
    status(
        &f.actor(&actor, "POST", "sys/leases/revoke-prefix/pki/", json!({}))?,
        204,
    );
    verify_crl(
        &f.actor("", "GET", "pki/cert/crl", json!({}))?,
        &issuer,
        Some(&leaf),
    )?;
    let mut f = f.restart()?;
    verify_crl(
        &f.actor("", "GET", "pki/cert/crl", json!({}))?,
        &issuer,
        Some(&leaf),
    )?;
    f.sentinel()
}

#[test]
fn native_pki_formal_mount_tune_disable_keeps_other_graphs_and_cold_custody() -> TestResult {
    let mut f = Fixture::new()?;
    let before = f.root()?;
    status(
        &f.admin(
            "POST",
            "sys/mounts/pki/tune",
            json!({"default_lease_ttl":"1h","max_lease_ttl":"4h"}),
        )?,
        204,
    );
    let tune = f.admin("GET", "sys/mounts/pki/tune", json!({}))?;
    status(&tune, 200);
    assert_eq!(tune.body["data"]["max_lease_ttl"], 14400);
    let mut f = f.restart()?;
    status(&f.admin("DELETE", "sys/mounts/pki", json!({}))?, 204);
    f.graphs_unchanged(&before)?;
    let mut f = f.restart()?;
    let mounts = f.admin("GET", "sys/mounts", json!({}))?;
    status(&mounts, 200);
    assert!(mounts.body["data"].get("pki/").is_none());
    f.sentinel()
}


#[test]
fn native_pki_formal_expired_lease_lookup_matches_openbao_271_400_and_cold() -> TestResult {
    let mut f = Fixture::new()?;
    let before = f.root()?;
    let mut issued = f.admin(
        "POST",
        "pki/issue/web",
        json!({"common_name":"short.example.test","ttl":"2s"}),
    )?;
    status(&issued, 200);
    let lease = text(&issued, "/lease_id")?;
    let serial = text(&issued, "/data/serial_number")?;
    let certificate = text(&issued, "/data/certificate")?;
    assert_eq!(issued.body["lease_duration"], 2);
    erase_json(&mut issued.body);
    status(
        &f.admin("POST", "sys/leases/lookup", json!({"lease_id":lease}))?,
        200,
    );
    f.now += 3;
    for cold in [false, true] {
        if cold {
            f = f.restart()?;
        }
        let missing = f.admin("POST", "sys/leases/lookup", json!({"lease_id":lease}))?;
        status(&missing, 400);
        assert!(
            missing.body["errors"]
                .as_array()
                .is_some_and(|errors| !errors.is_empty())
        );
        assert!(missing.body.get("data").is_none());
        let retained = f.actor("", "GET", &format!("pki/cert/{serial}"), json!({}))?;
        status(&retained, 200);
        assert_eq!(retained.body["data"]["certificate"], certificate);
    }
    f.graphs_unchanged(&before)?;
    f.sentinel()
}

#[test]
fn native_pki_formal_revoked_lease_lookup_matches_openbao_271_400_and_cold() -> TestResult {
    let mut f = Fixture::new()?;
    let before = f.root()?;
    let admin = Zeroizing::new(f.admin.to_string());
    let mut issued = f.issue(&admin)?;
    let lease = text(&issued, "/lease_id")?;
    let serial = text(&issued, "/data/serial_number")?;
    let certificate = text(&issued, "/data/certificate")?;
    erase_json(&mut issued.body);
    status(
        &f.admin("POST", "sys/leases/lookup", json!({"lease_id":lease}))?,
        200,
    );
    status(
        &f.admin("POST", "sys/leases/revoke", json!({"lease_id":lease,"sync":true}))?,
        204,
    );
    for cold in [false, true] {
        if cold {
            f = f.restart()?;
        }
        let missing = f.admin("POST", "sys/leases/lookup", json!({"lease_id":lease}))?;
        status(&missing, 400);
        assert!(
            missing.body["errors"]
                .as_array()
                .is_some_and(|errors| !errors.is_empty())
        );
        assert!(missing.body.get("data").is_none());
        let retained = f.actor("", "GET", &format!("pki/cert/{serial}"), json!({}))?;
        status(&retained, 200);
        assert_eq!(retained.body["data"]["certificate"], certificate);
    }
    f.graphs_unchanged(&before)?;
    f.sentinel()
}

#[path = "service_native_pki_archive_tests.rs"]
mod archive;
