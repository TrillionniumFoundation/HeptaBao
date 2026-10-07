//! Maintained-key signatures exercise the actual PEM Service configuration.
use super::online_auth::OnlineAuthObservation;
use super::tests::{Root, bootstrap};
use super::*;
use crate::auth::RemoteJwtLoginObservation;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use openssl::{
    ec::{EcGroup, EcKey},
    ecdsa::EcdsaSig,
    hash::MessageDigest,
    nid::Nid,
    pkey::{PKey, Private},
    rsa::Rsa,
    sign::Signer,
};
use zeroize::Zeroizing;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

fn call(
    service: &mut Service,
    namespace: &str,
    method: &str,
    path: &str,
    token: &str,
    body: Value,
    now: u64,
) -> Response {
    service.handle_at(method, path, namespace, token, body, now)
}
fn public(key: &PKey<Private>) -> TestResult<String> {
    Ok(String::from_utf8(key.public_key_to_pem()?)?)
}
fn setup(service: &mut Service, admin: &str, ns: &str, mount: &str) -> TestResult {
    assert!(
        call(
            service,
            ns,
            "POST",
            &format!("sys/auth/{mount}"),
            admin,
            json!({"type":"jwt"}),
            100
        )
        .status
            == 204,
        "JWT mount"
    );
    assert!(call(service,ns,"POST",&format!("auth/{mount}/role/custom"),admin,
        json!({"role_type":"jwt","user_claim":"username","bound_subject":"original-sub","bound_audiences":["service"],"token_ttl":120,"token_max_ttl":600}),100).status==204,"custom role");
    Ok(())
}
fn config(
    service: &mut Service,
    admin: &str,
    ns: &str,
    mount: &str,
    pems: Value,
    algs: Value,
) -> Response {
    call(
        service,
        ns,
        "POST",
        &format!("auth/{mount}/config"),
        admin,
        json!({"bound_issuer":"https://issuer.example","jwt_validation_pubkeys":pems,"jwt_supported_algs":algs}),
        100,
    )
}
fn assertion(
    key: &PKey<Private>,
    alg: &str,
    kid: Option<&str>,
    ns: &str,
) -> TestResult<Zeroizing<String>> {
    let mut header = json!({"alg":alg});
    if let Some(kid) = kid {
        header["kid"] = json!(kid);
    }
    let mut claims = json!({"iss":"https://issuer.example","sub":"original-sub","username":"selected-user","aud":"service","iat":100,"exp":1000});
    if !ns.is_empty() {
        claims["heptabao_namespace"] = json!(ns);
    }
    let data = format!(
        "{}.{}",
        URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header)?),
        URL_SAFE_NO_PAD.encode(serde_json::to_vec(&claims)?)
    );
    let mut signer = if alg == "EdDSA" {
        Signer::new_without_digest(key)?
    } else {
        Signer::new(MessageDigest::sha256(), key)?
    };
    let raw = signer.sign_oneshot_to_vec(data.as_bytes())?;
    let raw = if alg == "ES256" {
        let sig = EcdsaSig::from_der(&raw)?;
        let r = sig.r().to_vec();
        let s = sig.s().to_vec();
        if r.len() > 32 || s.len() > 32 {
            return Err("P256 signature width".into());
        }
        let mut jws = vec![0; 64];
        jws[32 - r.len()..32].copy_from_slice(&r);
        jws[64 - s.len()..].copy_from_slice(&s);
        jws
    } else {
        raw
    };
    Ok(Zeroizing::new(format!(
        "{data}.{}",
        URL_SAFE_NO_PAD.encode(raw)
    )))
}
fn login(
    service: &mut Service,
    key: &PKey<Private>,
    alg: &str,
    kid: Option<&str>,
    ns: &str,
    mount: &str,
) -> TestResult<Response> {
    let jwt = assertion(key, alg, kid, ns)?;
    Ok(call(
        service,
        ns,
        "POST",
        &format!("auth/{mount}/login"),
        "",
        json!({"role":"custom","jwt":jwt.as_str()}),
        105,
    ))
}
fn jwks(key: &PKey<Private>) -> TestResult<Value> {
    let rsa = key.rsa()?;
    Ok(
        json!({"keys":[{"kid":"synthetic-rsa","kty":"RSA","alg":"RS256","n":URL_SAFE_NO_PAD.encode(rsa.n().to_vec()),"e":URL_SAFE_NO_PAD.encode(rsa.e().to_vec())}]}),
    )
}

#[test]
fn jwt_pem_rs256_accepts_unbound_kid_only_in_pem_source_and_keeps_selected_alias() -> TestResult {
    let root = Root::new();
    let mut service = root.service()?;
    let (_, admin) = bootstrap(&mut service)?;
    let key = PKey::from_rsa(Rsa::generate(2048)?)?;
    let wrong = PKey::from_rsa(Rsa::generate(2048)?)?;
    setup(&mut service, &admin, "", "pemjwt")?;
    assert!(
        config(
            &mut service,
            &admin,
            "",
            "pemjwt",
            json!([public(&key)?]),
            json!(["RS256"])
        )
        .status
            == 204,
        "PEM config uses role audience"
    );
    let mut entity = None;
    for kid in [Some("synthetic-rsa"), Some("unconfigured-kid"), None] {
        let result = login(&mut service, &key, "RS256", kid, "", "pemjwt")?;
        assert!(result.status == 200, "real signature in PEM source");
        let selected = result.body["auth"]["entity_id"].clone();
        assert!(
            entity.as_ref().is_none_or(|expected| expected == &selected),
            "same selected alias"
        );
        entity = Some(selected);
    }
    let denied = login(&mut service, &wrong, "RS256", None, "", "pemjwt")?;
    assert!(
        denied.status == 400 && denied.body.get("auth").is_none(),
        "wrong key never issues auth"
    );
    let accessor = service
        .state
        .as_ref()
        .ok_or("state")?
        .auth
        .mount_accessor("", "pemjwt")?;
    let alias = call(
        &mut service,
        "",
        "POST",
        "identity/lookup/entity",
        &admin,
        json!({"alias_name":"selected-user","alias_mount_accessor":accessor}),
        106,
    );
    assert!(
        alias.status == 200 && Some(alias.body["data"]["id"].clone()) == entity,
        "selected verified claim binds alias"
    );
    let inline = call(
        &mut service,
        "",
        "POST",
        "auth/pemjwt/config",
        &admin,
        json!({"issuer":"https://issuer.example","audiences":["service"],"jwks":jwks(&key)?}),
        110,
    );
    assert!(
        inline.status == 204,
        "existing inline source remains available"
    );
    for kid in [None, Some("unconfigured-kid")] {
        let denied = login(&mut service, &key, "RS256", kid, "", "pemjwt")?;
        assert!(
            denied.status == 400 && denied.body.get("auth").is_none(),
            "inline source still requires exact kid"
        );
    }
    assert!(
        login(
            &mut service,
            &key,
            "RS256",
            Some("synthetic-rsa"),
            "",
            "pemjwt"
        )?
        .status
            == 200,
        "inline positive control"
    );
    Ok(())
}

#[test]
fn jwt_pem_maintained_rsa_ec_ed_signatures_use_only_same_algorithm_keys() -> TestResult {
    let root = Root::new();
    let mut service = root.service()?;
    let (_, admin) = bootstrap(&mut service)?;
    let rsa = PKey::from_rsa(Rsa::generate(2048)?)?;
    let second = PKey::from_rsa(Rsa::generate(2048)?)?;
    let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1)?;
    let ec = PKey::from_ec_key(EcKey::generate(&group)?)?;
    let ed = PKey::generate_ed25519()?;
    setup(&mut service, &admin, "", "pemjwt")?;
    assert!(
        config(
            &mut service,
            &admin,
            "",
            "pemjwt",
            json!([public(&rsa)?, public(&ec)?, public(&ed)?, public(&second)?]),
            json!(["RS256", "ES256", "EdDSA"])
        )
        .status
            == 204,
        "mixed bounded public keyset"
    );
    for (key, alg) in [
        (&rsa, "RS256"),
        (&second, "RS256"),
        (&ec, "ES256"),
        (&ed, "EdDSA"),
    ] {
        assert!(
            login(&mut service, key, alg, None, "", "pemjwt")?.status == 200,
            "same algorithm signature verifier"
        );
    }
    assert!(
        config(
            &mut service,
            &admin,
            "",
            "pemjwt",
            json!([public(&rsa)?]),
            json!(["ES256"])
        )
        .status
            == 204,
        "valid but disjoint allowlist config"
    );
    let denied = login(&mut service, &rsa, "RS256", None, "", "pemjwt")?;
    assert!(
        denied.status == 400 && denied.body.get("auth").is_none(),
        "allowlist does not infer algorithm from key"
    );
    Ok(())
}

#[test]
fn jwt_pem_invalid_private_weak_wrong_curve_and_source_mix_leave_config_intact() -> TestResult {
    let root = Root::new();
    let mut service = root.service()?;
    let (_, admin) = bootstrap(&mut service)?;
    let key = PKey::from_rsa(Rsa::generate(2048)?)?;
    let pem = public(&key)?;
    setup(&mut service, &admin, "", "pemjwt")?;
    assert!(
        config(
            &mut service,
            &admin,
            "",
            "pemjwt",
            json!([pem]),
            json!(["RS256"])
        )
        .status
            == 204,
        "valid config"
    );
    let private = Zeroizing::new(String::from_utf8(key.private_key_to_pem_pkcs8()?)?);
    let pkcs1 = String::from_utf8(key.rsa()?.public_key_to_pem_pkcs1()?)?;
    let weak = PKey::from_rsa(Rsa::generate(1024)?)?;
    let group = EcGroup::from_curve_name(Nid::SECP384R1)?;
    let other_curve = PKey::from_ec_key(EcKey::generate(&group)?)?;
    let mut inputs = vec![
        json!([]),
        Value::Null,
        json!([false]),
        json!(["bad-public-envelope"]),
        json!([pkcs1]),
        json!([public(&weak)?]),
        json!([public(&other_curve)?]),
        json!([format!("{pem}{pem}")]),
        json!([" ".repeat(16 * 1024 + 1)]),
    ];
    inputs.push(json!([private.as_str()]));
    inputs.push(json!(vec![pem.clone(); 65]));
    for mut input in inputs {
        let denied = config(
            &mut service,
            &admin,
            "",
            "pemjwt",
            input.clone(),
            json!(["RS256"]),
        );
        super::erase_json(&mut input);
        assert!(
            denied.status == 400 && denied.body.get("auth").is_none(),
            "invalid public input must reject"
        );
    }
    for source in ["jwks_url", "oidc_discovery_url", "jwks", "keys"] {
        let mut body =
            json!({"bound_issuer":"https://issuer.example","jwt_validation_pubkeys":[pem]});
        body[source] = if source.ends_with("url") {
            json!("https://issuer.example/unused")
        } else {
            json!([])
        };
        assert!(
            call(
                &mut service,
                "",
                "POST",
                "auth/pemjwt/config",
                &admin,
                body,
                110
            )
            .status
                == 400,
            "sources cannot mix or fall back"
        );
    }
    assert!(
        login(&mut service, &key, "RS256", None, "", "pemjwt")?.status == 200,
        "all rejections leave old config usable"
    );
    Ok(())
}

#[test]
fn jwt_pem_namespace_reopen_renew_and_sticky_retirement_keep_existing_authority() -> TestResult {
    let root = Root::new();
    let mut service = root.service()?;
    let (unseal, admin) = bootstrap(&mut service)?;
    let unseal = Zeroizing::new(unseal);
    let admin = Zeroizing::new(admin);
    let key = PKey::from_rsa(Rsa::generate(2048)?)?;
    assert!(
        service.state.as_ref().ok_or("state")?.schema == CURRENT_STATE_SCHEMA,
        "ordinary writer starts65"
    );
    assert!(
        call(
            &mut service,
            "",
            "POST",
            "sys/namespaces/team",
            &admin,
            json!({}),
            100
        )
        .status
            == 200,
        "namespace"
    );
    setup(&mut service, &admin, "team", "pemjwt")?;
    assert!(
        config(
            &mut service,
            &admin,
            "team",
            "pemjwt",
            json!(public(&key)?),
            json!(["RS256"])
        )
        .status
            == 204,
        "tenant PEM config"
    );
    assert!(
        service.state.as_ref().ok_or("state")?.schema == JWT_PEM_KEYSET_STATE_SCHEMA,
        "all namespace schema69"
    );
    let issued = login(&mut service, &key, "RS256", None, "team", "pemjwt")?;
    assert!(issued.status == 200, "tenant real JWT");
    let token = Zeroizing::new(
        issued.body["auth"]["client_token"]
            .as_str()
            .ok_or("token")?
            .to_owned(),
    );
    let entity = issued.body["auth"]["entity_id"].clone();
    let root_jwt = assertion(&key, "RS256", None, "")?;
    let denied = call(
        &mut service,
        "team",
        "POST",
        "auth/pemjwt/login",
        "",
        json!({"role":"custom","jwt":root_jwt.as_str()}),
        106,
    );
    assert!(
        denied.status == 400 && denied.body.get("auth").is_none(),
        "namespace cannot use root signed claim"
    );
    drop(service);
    let mut service = root.service()?;
    assert!(
        call(
            &mut service,
            "",
            "POST",
            "sys/unseal",
            "",
            json!({"key":unseal.as_str()}),
            110
        )
        .status
            == 200,
        "encrypted reopen"
    );
    let renewed = call(
        &mut service,
        "team",
        "POST",
        "auth/token/renew-self",
        &token,
        json!({"increment":120}),
        111,
    );
    assert!(
        renewed.status == 200 && renewed.body["auth"]["entity_id"] == entity,
        "renewal retains issued alias ownership"
    );
    assert!(
        login(&mut service, &key, "RS256", None, "team", "pemjwt")?.body["auth"]["entity_id"]
            == entity,
        "reopened same keyset alias"
    );
    assert!(
        call(
            &mut service,
            "team",
            "POST",
            "auth/pemjwt/config",
            &admin,
            json!({"issuer":"https://issuer.example","audiences":["service"],"jwks":jwks(&key)?}),
            112
        )
        .status
            == 204,
        "retire PEM by explicit source replacement"
    );
    let current = service.state.as_ref().ok_or("state")?;
    assert!(
        !current.auth.has_jwt_pem_keyset_state() && current.schema == JWT_PEM_KEYSET_STATE_SCHEMA,
        "schema69 remains sticky"
    );
    let mut old = current.clone();
    old.schema = JWT_USER_CLAIM_STATE_SCHEMA;
    assert!(
        Service::validate_snapshot_protected_floor(current, &old).is_err(),
        "retired local and HA snapshot floor69 rejects68"
    );
    assert!(
        old.validate_publication_schema(Some(current)).is_err(),
        "retired publication cannot downgrade"
    );
    assert!(
        service.commit_state(&mut old).is_err(),
        "actual commit rejects retired downgrade"
    );
    Ok(())
}

#[test]
fn jwt_pem_state_requires69_and_revalidates_public_key_binding_without_changing_legacy_bytes()
-> TestResult {
    let root = Root::new();
    let mut service = root.service()?;
    let (_, admin) = bootstrap(&mut service)?;
    let key = PKey::from_rsa(Rsa::generate(2048)?)?;
    setup(&mut service, &admin, "", "pemjwt")?;
    assert!(
        call(
            &mut service,
            "",
            "POST",
            "auth/pemjwt/config",
            &admin,
            json!({"issuer":"https://issuer.example","audiences":["service"],"jwks":jwks(&key)?}),
            100
        )
        .status
            == 204,
        "legacy config"
    );
    let before = service.state.clone().ok_or("state")?;
    let stored = serde_json::to_value(&before.auth)?;
    assert!(
        stored["jwt_mounts"][""]["pemjwt"]["config"]
            .get("jwt_validation_pubkeys")
            .is_none(),
        "None adds no legacy persisted field"
    );
    assert!(
        before.schema == JWT_USER_CLAIM_STATE_SCHEMA,
        "custom selector retains schema68"
    );
    assert!(
        config(
            &mut service,
            &admin,
            "",
            "pemjwt",
            json!([public(&key)?]),
            json!(["RS256"])
        )
        .status
            == 204,
        "PEM config"
    );
    let current = service.state.clone().ok_or("state")?;
    assert!(
        current.schema == JWT_PEM_KEYSET_STATE_SCHEMA && current.validate_format().is_ok(),
        "valid69"
    );
    let mut downgraded = current.clone();
    downgraded.schema = JWT_USER_CLAIM_STATE_SCHEMA;
    assert!(
        downgraded.validate_format().is_err()
            && downgraded
                .validate_publication_schema(Some(&before))
                .is_err(),
        "active source cannot hide below69"
    );
    assert!(
        Service::validate_snapshot_protected_floor(&current, &before).is_err(),
        "active snapshot floor69"
    );
    let mut encoded = serde_json::to_value(&current.auth)?;
    encoded["jwt_mounts"][""]["pemjwt"]["config"]["keys"]["pem-0"]["bytes"] = json!([]);
    let mut damaged = current.clone();
    damaged.auth = serde_json::from_value(encoded)?;
    assert!(
        damaged.validate_format().is_err(),
        "cached public bytes must match source SPKI"
    );
    for (field, value) in [
        ("required_namespace", json!("another-namespace")),
        ("issuer", json!("")),
        ("clock_skew_seconds", json!(301)),
        ("maximum_token_lifetime_seconds", json!(0)),
    ] {
        let mut encoded = serde_json::to_value(&current.auth)?;
        encoded["jwt_mounts"][""]["pemjwt"]["config"][field] = value;
        let mut malformed = current.clone();
        malformed.auth = serde_json::from_value(encoded)?;
        assert!(
            malformed.validate_format().is_err(),
            "persisted PEM trust policy must remain valid"
        );
    }
    let mut future = current;
    future.schema = MAX_SUPPORTED_STATE_SCHEMA + 1;
    assert!(
        future.writer_schema() == MAX_SUPPORTED_STATE_SCHEMA + 1
            && future.validate_format().is_err(),
        "unknown70 retained and rejected"
    );
    Ok(())
}

// Public-key observations exercise the real finalization gate, without
// claiming a network fetch or repeating the separate HTTPS fixture.
fn remote_pending(
    service: &mut Service,
    path: &str,
    token: &str,
    body: Value,
) -> TestResult<Box<PendingExternalRequest>> {
    match service.begin_at_mode(RequestDispatch {
        method: "POST",
        path,
        namespace: "",
        token,
        body,
        now: 110,
        allow_forward: false,
        enforce_namespace: true,
        wrap_ttl_seconds: None,
        client_certificates: None,
        origin_peer: None,
    }) {
        RequestExecution::External(plan) => Ok(plan),
        RequestExecution::Complete(_) => Err("expected remote JWT plan".into()),
    }
}
fn remote_observed(
    service: &mut Service,
    plan: PendingExternalRequest,
    key: &PKey<Private>,
    config: bool,
) -> TestResult<Response> {
    let observed = RemoteJwtLoginObservation::from_test_jwks(&jwks(key)?)?;
    let observed = if config {
        OnlineAuthObservation::RemoteJwtConfig(observed)
    } else {
        OnlineAuthObservation::RemoteJwt(observed)
    };
    Ok(service.finish_external_request(plan, ExternalEffectResult::OnlineAuth(Ok(observed))))
}

#[test]
fn jwt_pem_source_replacement_vetoes_pending_remote_completion() -> TestResult {
    let root = Root::new();
    let mut service = root.service()?;
    let (_, admin) = bootstrap(&mut service)?;
    let key = PKey::from_rsa(Rsa::generate(2048)?)?;
    setup(&mut service, &admin, "", "pemjwt")?;
    let config_plan = remote_pending(
        &mut service,
        "auth/pemjwt/config",
        &admin,
        json!({"issuer":"https://issuer.example","audiences":["service"],"jwks_url":"https://issuer.example/keys","jwt_supported_algs":["RS256"]}),
    )?;
    assert!(
        remote_observed(&mut service, *config_plan, &key, true)?.status == 204,
        "remote config positive"
    );
    let jwt = assertion(&key, "RS256", Some("synthetic-rsa"), "")?;
    let login_plan = remote_pending(
        &mut service,
        "auth/pemjwt/login",
        "",
        json!({"role":"custom","jwt":jwt.as_str()}),
    )?;
    let replaced = call(
        &mut service,
        "",
        "POST",
        "auth/pemjwt/config",
        &admin,
        json!({"bound_issuer":"https://issuer.example","jwt_validation_pubkeys":[public(&key)?],"jwt_supported_algs":["RS256"]}),
        111,
    );
    assert!(
        replaced.status == 204,
        "replace captured remote source with same public key PEM"
    );
    let before = Zeroizing::new(serde_json::to_vec(
        &service.state.as_ref().ok_or("state")?.auth,
    )?);
    let denied = remote_observed(&mut service, *login_plan, &key, false)?;
    assert!(
        denied.status == 409 && denied.body.get("auth").is_none(),
        "captured remote completion cannot publish under PEM source"
    );
    let after = Zeroizing::new(serde_json::to_vec(
        &service.state.as_ref().ok_or("state")?.auth,
    )?);
    assert!(
        before.as_slice() == after.as_slice(),
        "veto retains authoritative config and identities"
    );
    let accessor = service
        .state
        .as_ref()
        .ok_or("state")?
        .auth
        .mount_accessor("", "pemjwt")?;
    let absent = call(
        &mut service,
        "",
        "POST",
        "identity/lookup/entity",
        &admin,
        json!({"alias_name":"selected-user","alias_mount_accessor":accessor}),
        112,
    );
    assert!(absent.status == 204, "veto creates no selected alias");
    let jwt = assertion(&key, "RS256", None, "")?;
    let accepted = call(
        &mut service,
        "",
        "POST",
        "auth/pemjwt/login",
        "",
        json!({"role":"custom","jwt":jwt.as_str()}),
        113,
    );
    assert!(
        accepted.status == 200 && accepted.body.get("auth").is_some(),
        "current PEM source remains usable"
    );
    Ok(())
}

#[test]
fn jwt_pem_authenticated_snapshot_prepare_and_final_commit_reject_active_retired_downgrade()
-> TestResult {
    let root = Root::new();
    let mut service = root.service()?;
    let (_, admin) = bootstrap(&mut service)?;
    let key = PKey::from_rsa(Rsa::generate(2048)?)?;
    setup(&mut service, &admin, "", "pemjwt")?;
    assert!(
        service.state.as_ref().ok_or("state")?.schema == JWT_USER_CLAIM_STATE_SCHEMA,
        "snapshot predecessor68"
    );
    let old68 = Zeroizing::new(service.durable.as_ref().ok_or("durable")?.export_backup()?);
    let active_prepared = service
        .prepare_snapshot_restore(&old68)
        .map_err(|_| "pre-feature active prepare")?;
    let retired_prepared = service
        .prepare_snapshot_restore(&old68)
        .map_err(|_| "pre-feature retired prepare")?;
    let mut plans = [active_prepared, retired_prepared].into_iter();
    assert!(
        config(
            &mut service,
            &admin,
            "",
            "pemjwt",
            json!([public(&key)?]),
            json!(["RS256"])
        )
        .status
            == 204,
        "PEM promotion69"
    );
    let principal = service
        .state
        .as_mut()
        .ok_or("state")?
        .auth
        .authenticate_from(&admin, 100, None)
        .map_err(|_| "snapshot actor")?;
    let body = json!({});
    let request = RequestView {
        method: "POST",
        path: "sys/storage/raft/snapshot-force",
        namespace: "",
        token: &admin,
        body: &body,
        now: 120,
        admission_started: std::time::Instant::now(),
        token_clock: None,
        allow_forward: false,
        enforce_namespace: true,
        wrap_ttl_seconds: None,
        origin_peer: None,
        client_certificates: None,
    };
    for retired in [false, true] {
        if retired {
            assert!(call(&mut service, "", "POST", "auth/pemjwt/config", &admin,
                json!({"issuer":"https://issuer.example","audiences":["service"],"jwks":jwks(&key)?}),120).status == 204,
                "explicit retirement keeps69");
            assert!(
                !service
                    .state
                    .as_ref()
                    .ok_or("state")?
                    .auth
                    .has_jwt_pem_keyset_state(),
                "final PEM state retired"
            );
        }
        let identity = service
            .current_state_identity()
            .map_err(|_| "current identity")?;
        let generation = service
            .external_effect_generation()
            .map_err(|_| "current generation")?;
        assert!(
            service
                .prepare_snapshot_restore(&old68)
                .err()
                .is_some_and(|error| error.status == 400),
            "authenticated prepare rejects old68"
        );
        let mut reader = std::io::Cursor::new(old68.as_slice());
        assert!(
            service
                .prepare_snapshot_restore_from_reader(&mut reader, old68.len() as u64)
                .err()
                .is_some_and(|error| error.status == 400),
            "streamed prepare rejects old68"
        );
        // The existing test-only constructor rebinds only the base identity to
        // isolate the mandatory final protected-floor gate. All other affine
        // activation, durable archive and principal fields remain authentic.
        let mut plan = plans.next().ok_or("affine restore plan")?;
        plan.fixture_rebind_base_for_protected_floor(identity);
        assert!(
            service
                .commit_snapshot_restore(plan, &principal, &request)
                .status
                == 400,
            "final publication rejects active/retired69 to68"
        );
        assert!(
            service
                .current_state_identity()
                .map_err(|_| "retained identity")?
                == identity
                && service
                    .external_effect_generation()
                    .map_err(|_| "retained generation")?
                    == generation
                && service.state.as_ref().ok_or("state")?.schema == JWT_PEM_KEYSET_STATE_SCHEMA,
            "restore rejection leaves encrypted publication and reader floor intact"
        );
    }
    assert!(plans.next().is_none(), "both affine plans consumed once");
    Ok(())
}
