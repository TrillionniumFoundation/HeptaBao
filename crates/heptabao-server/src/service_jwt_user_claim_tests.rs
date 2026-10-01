//! Real RS256 assertions bind a selected verified claim through Service.
use super::online_auth::OnlineAuthObservation;
use super::tests::{Root, bootstrap};
use super::*;
use crate::auth::RemoteJwtLoginObservation;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use openssl::{
    hash::MessageDigest,
    pkey::{PKey, Private},
    rsa::Rsa,
    sign::Signer,
};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

fn request(
    service: &mut Service,
    ns: &str,
    method: &str,
    path: &str,
    token: &str,
    body: Value,
    now: u64,
) -> Response {
    service.handle_at(method, path, ns, token, body, now)
}

fn keys(key: &PKey<Private>) -> TestResult<Value> {
    let rsa = key.rsa()?;
    Ok(
        json!({"keys":[{"kty":"RSA","kid":"synthetic-rsa","alg":"RS256","n":URL_SAFE_NO_PAD.encode(rsa.n().to_vec()),"e":URL_SAFE_NO_PAD.encode(rsa.e().to_vec())}]}),
    )
}

fn assertion(
    key: &PKey<Private>,
    ns: &str,
    custom: Option<Value>,
) -> TestResult<zeroize::Zeroizing<String>> {
    let mut claims = json!({"iss":"https://issuer.example","sub":"original-sub","aud":"service","iat":100,"exp":1000});
    if !ns.is_empty() {
        claims["heptabao_namespace"] = json!(ns);
    }
    if let Some(value) = custom {
        claims["username"] = value;
    }
    let payload = format!(
        "{}.{}",
        URL_SAFE_NO_PAD.encode(br#"{"alg":"RS256","kid":"synthetic-rsa"}"#),
        URL_SAFE_NO_PAD.encode(serde_json::to_vec(&claims)?)
    );
    let mut signer = Signer::new(MessageDigest::sha256(), key)?;
    Ok(zeroize::Zeroizing::new(format!(
        "{payload}.{}",
        URL_SAFE_NO_PAD.encode(signer.sign_oneshot_to_vec(payload.as_bytes())?)
    )))
}

fn configure(
    service: &mut Service,
    admin: &str,
    ns: &str,
    mount: &str,
    key: &PKey<Private>,
) -> TestResult {
    assert!(
        request(
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
        "JWT mount admission"
    );
    assert!(request(service,ns,"POST",&format!("auth/{mount}/config"),admin,json!({"issuer":"https://issuer.example","audiences":["service"],"jwt_supported_algs":["RS256"],"jwks":keys(key)?}),100).status==204,"maintained RSA public key configuration");
    Ok(())
}

fn role(
    service: &mut Service,
    admin: &str,
    ns: &str,
    mount: &str,
    name: &str,
    user_claim: &str,
) -> Response {
    request(
        service,
        ns,
        "POST",
        &format!("auth/{mount}/role/{name}"),
        admin,
        json!({"role_type":"jwt","user_claim":user_claim,"bound_subject":"original-sub","bound_audiences":["service"],"token_ttl":120,"token_max_ttl":600}),
        100,
    )
}

fn login(
    service: &mut Service,
    key: &PKey<Private>,
    ns: &str,
    mount: &str,
    name: &str,
    custom: Option<Value>,
) -> TestResult<Response> {
    let jwt = assertion(key, ns, custom)?;
    Ok(request(
        service,
        ns,
        "POST",
        &format!("auth/{mount}/login"),
        "",
        json!({"role":name,"jwt":jwt.as_str()}),
        105,
    ))
}

fn alias(
    service: &mut Service,
    admin: &str,
    ns: &str,
    mount: &str,
    name: &str,
) -> TestResult<Response> {
    let accessor = service
        .state
        .as_ref()
        .ok_or("state")?
        .auth
        .mount_accessor(ns, mount)?;
    Ok(request(
        service,
        ns,
        "POST",
        "identity/lookup/entity",
        admin,
        json!({"alias_name":name,"alias_mount_accessor":accessor}),
        106,
    ))
}

#[test]
fn jwt_user_claim_rs256_custom_alias_and_default_sub_are_distinct() -> TestResult {
    let root = Root::new();
    let mut service = root.service()?;
    let (_, admin) = bootstrap(&mut service)?;
    let key = PKey::from_rsa(Rsa::generate(2048)?)?;
    configure(&mut service, &admin, "", "jwtcustom", &key)?;
    let configured = role(&mut service, &admin, "", "jwtcustom", "custom", "username");
    assert!(
        configured.status == 204,
        "custom user_claim must be admitted, observed status {}",
        configured.status
    );
    let custom = login(
        &mut service,
        &key,
        "",
        "jwtcustom",
        "custom",
        Some(json!("selected-user")),
    )?;
    assert!(custom.status == 200, "actual RS256 custom claim login");
    let found = alias(&mut service, &admin, "", "jwtcustom", "selected-user")?;
    assert!(
        found.status == 200 && found.body["data"]["id"] == custom.body["auth"]["entity_id"],
        "selected verified claim owns alias"
    );
    assert!(
        alias(&mut service, &admin, "", "jwtcustom", "original-sub")?.status == 404,
        "registered subject does not substitute for selected alias"
    );
    assert!(
        role(&mut service, &admin, "", "jwtcustom", "default", "sub").status == 204,
        "default subject role"
    );
    let default = login(
        &mut service,
        &key,
        "",
        "jwtcustom",
        "default",
        Some(json!("selected-user")),
    )?;
    assert!(
        default.status == 200
            && default.body["auth"]["entity_id"] != custom.body["auth"]["entity_id"],
        "default sub identity remains distinct"
    );
    assert!(
        alias(&mut service, &admin, "", "jwtcustom", "original-sub")?.body["data"]["id"]
            == default.body["auth"]["entity_id"],
        "default sub alias binding"
    );
    Ok(())
}

#[test]
fn jwt_user_claim_missing_nonstring_and_wrong_signature_publish_nothing() -> TestResult {
    let root = Root::new();
    let mut service = root.service()?;
    let (_, admin) = bootstrap(&mut service)?;
    let key = PKey::from_rsa(Rsa::generate(2048)?)?;
    configure(&mut service, &admin, "", "jwtcustom", &key)?;
    assert!(
        role(&mut service, &admin, "", "jwtcustom", "custom", "username").status == 204,
        "custom role"
    );
    let before = zeroize::Zeroizing::new(serde_json::to_vec(
        &service.state.as_ref().ok_or("state")?.auth,
    )?);
    for value in [
        None,
        Some(Value::Null),
        Some(json!(false)),
        Some(json!(1)),
        Some(json!([])),
        Some(json!({})),
        Some(json!("")),
        Some(json!("bad\nclaim")),
    ] {
        let denied = login(&mut service, &key, "", "jwtcustom", "custom", value)?;
        assert!(
            denied.status == 400 && denied.body.get("auth").is_none(),
            "invalid identity claim has no token"
        );
        let after = zeroize::Zeroizing::new(serde_json::to_vec(
            &service.state.as_ref().ok_or("state")?.auth,
        )?);
        assert!(
            after.as_slice() == before.as_slice(),
            "invalid claim cannot publish token or identity evidence"
        );
    }
    let wrong = PKey::from_rsa(Rsa::generate(2048)?)?;
    let denied = login(
        &mut service,
        &wrong,
        "",
        "jwtcustom",
        "custom",
        Some(json!("selected-user")),
    )?;
    assert!(
        denied.status == 400 && denied.body.get("auth").is_none(),
        "wrong RSA signature rejects identity claim"
    );
    assert!(
        alias(&mut service, &admin, "", "jwtcustom", "selected-user")?.status == 404,
        "failed signature creates no alias"
    );
    Ok(())
}

#[test]
fn jwt_user_claim_mount_namespace_isolation_and_disabled_entity() -> TestResult {
    let root = Root::new();
    let mut service = root.service()?;
    let (_, admin) = bootstrap(&mut service)?;
    let key = PKey::from_rsa(Rsa::generate(2048)?)?;
    assert!(
        request(
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
        "namespace admission"
    );
    let mut entities = Vec::new();
    for (ns, mount) in [("", "first"), ("", "second"), ("team", "first")] {
        configure(&mut service, &admin, ns, mount, &key)?;
        assert!(
            role(&mut service, &admin, ns, mount, "custom", "username").status == 204,
            "scoped custom role"
        );
        let issued = login(
            &mut service,
            &key,
            ns,
            mount,
            "custom",
            Some(json!("same-user")),
        )?;
        assert!(issued.status == 200, "scoped signed assertion");
        entities.push(
            issued.body["auth"]["entity_id"]
                .as_str()
                .ok_or("entity")?
                .to_owned(),
        );
        assert!(
            alias(&mut service, &admin, ns, mount, "same-user")?.body["data"]["id"]
                == entities[entities.len() - 1],
            "scoped accessor binding"
        );
    }
    assert!(
        entities[0] != entities[1],
        "mount accessors keep entities distinct within one namespace"
    );
    assert!(
        request(
            &mut service,
            "",
            "POST",
            &format!("identity/entity/id/{}", entities[0]),
            &admin,
            json!({"disabled":true}),
            107
        )
        .status
            == 204,
        "entity disable"
    );
    let before = zeroize::Zeroizing::new(serde_json::to_vec(
        &service.state.as_ref().ok_or("state")?.auth,
    )?);
    let denied = login(
        &mut service,
        &key,
        "",
        "first",
        "custom",
        Some(json!("same-user")),
    )?;
    assert!(
        denied.status == 403 && denied.body.get("auth").is_none(),
        "disabled selected entity withholds token"
    );
    let after = zeroize::Zeroizing::new(serde_json::to_vec(
        &service.state.as_ref().ok_or("state")?.auth,
    )?);
    assert!(
        before.as_slice() == after.as_slice(),
        "disabled identity cannot commit a token"
    );
    // Entity IDs are namespace-local counters, so cross-namespace equality is
    // legal. Prove isolation through current scoped authorization instead.
    for (ns, mount, expected) in [
        ("", "second", &entities[1]),
        ("team", "first", &entities[2]),
    ] {
        let unaffected = login(
            &mut service,
            &key,
            ns,
            mount,
            "custom",
            Some(json!("same-user")),
        )?;
        assert!(
            unaffected.status == 200 && unaffected.body["auth"]["entity_id"] == expected.as_str(),
            "other mount and namespace remain enabled"
        );
    }
    let root_jwt = assertion(&key, "", Some(json!("same-user")))?;
    let denied = request(
        &mut service,
        "team",
        "POST",
        "auth/first/login",
        "",
        json!({"role":"custom","jwt":root_jwt.as_str()}),
        110,
    );
    assert!(
        denied.status == 400 && denied.body.get("auth").is_none(),
        "signed root namespace cannot bind a team identity"
    );
    Ok(())
}

#[test]
fn jwt_user_claim_reopen_role_edit_and_renewal_retain_issued_entity() -> TestResult {
    let root = Root::new();
    let mut service = root.service()?;
    let (unseal, admin) = bootstrap(&mut service)?;
    let key = PKey::from_rsa(Rsa::generate(2048)?)?;
    configure(&mut service, &admin, "", "jwtcustom", &key)?;
    assert!(
        role(&mut service, &admin, "", "jwtcustom", "custom", "username").status == 204,
        "custom role"
    );
    let issued = login(
        &mut service,
        &key,
        "",
        "jwtcustom",
        "custom",
        Some(json!("selected-user")),
    )?;
    assert!(issued.status == 200, "signed login");
    let token = zeroize::Zeroizing::new(
        issued.body["auth"]["client_token"]
            .as_str()
            .ok_or("token")?
            .to_owned(),
    );
    let entity = issued.body["auth"]["entity_id"].clone();
    drop(service);
    let mut service = root.service()?;
    assert!(
        request(
            &mut service,
            "",
            "POST",
            "sys/unseal",
            "",
            json!({"key":unseal}),
            110
        )
        .status
            == 200,
        "encrypted reopen"
    );
    assert!(
        request(
            &mut service,
            "",
            "GET",
            "auth/jwtcustom/role/custom",
            &admin,
            json!({}),
            111
        )
        .body["data"]["user_claim"]
            == "username",
        "persisted selected role claim"
    );
    assert!(
        request(
            &mut service,
            "",
            "POST",
            "auth/jwtcustom/role/custom",
            &admin,
            json!({"role_type":"jwt","token_ttl":180}),
            111
        )
        .status
            == 204,
        "partial update"
    );
    assert!(
        request(
            &mut service,
            "",
            "GET",
            "auth/jwtcustom/role/custom",
            &admin,
            json!({}),
            112
        )
        .body["data"]["user_claim"]
            == "username",
        "omission preserves selected claim"
    );
    assert!(
        role(
            &mut service,
            &admin,
            "",
            "jwtcustom",
            "custom",
            "other-name"
        )
        .status
            == 204,
        "later claim edit"
    );
    let renewed = request(
        &mut service,
        "",
        "POST",
        "auth/token/renew-self",
        &token,
        json!({"increment":120}),
        115,
    );
    assert!(
        renewed.status == 200 && renewed.body["auth"]["entity_id"] == entity,
        "renewal preserves original entity without revalidating JWT claim"
    );
    assert!(
        alias(&mut service, &admin, "", "jwtcustom", "selected-user")?.body["data"]["id"] == entity,
        "reopen retains selected alias"
    );
    Ok(())
}

#[test]
fn jwt_user_claim_schema68_is_conditional_sticky_and_snapshot_protected() -> TestResult {
    let root = Root::new();
    let mut service = root.service()?;
    let (_, admin) = bootstrap(&mut service)?;
    let key = PKey::from_rsa(Rsa::generate(2048)?)?;
    configure(&mut service, &admin, "", "jwtcustom", &key)?;
    assert!(
        role(&mut service, &admin, "", "jwtcustom", "default", "sub").status == 204,
        "default role"
    );
    assert!(
        service.state.as_ref().ok_or("state")?.schema == 65,
        "ordinary sub keeps schema65"
    );
    let mut ordinary = serde_json::to_value(&service.state.as_ref().ok_or("state")?.auth)?;
    assert!(
        ordinary["jwt_mounts"][""]["jwtcustom"]["roles"]["default"]
            .as_object()
            .is_some_and(|role| !role.contains_key("user_claim")),
        "default role retains the exact old field omission"
    );
    erase_json(&mut ordinary);
    assert!(
        role(&mut service, &admin, "", "jwtcustom", "custom", "username").status == 204,
        "custom role"
    );
    let active = service.state.as_ref().ok_or("state")?.clone();
    assert!(
        active.schema == 68 && active.validate_format().is_ok(),
        "selected claim activates reader fence"
    );
    let mut malformed = active.clone();
    let mut owner = serde_json::to_value(&malformed.auth)?;
    owner["jwt_mounts"][""]["jwtcustom"]["roles"]["custom"]["user_claim"] = json!("");
    malformed.auth = serde_json::from_value(owner)?;
    let before_digest = service.state_digest;
    assert!(
        malformed.validate_format().is_err() && service.commit_state(&malformed).is_err(),
        "malformed persisted selector rejected by real publication gate"
    );
    assert!(
        service.state_digest == before_digest,
        "rejected selector cannot replace durable identity"
    );
    let mut downgraded = active.clone();
    downgraded.schema = 67;
    assert!(
        downgraded.validate_format().is_err()
            && downgraded
                .validate_publication_schema(Some(&active))
                .is_err(),
        "active custom claim cannot be labelled old format"
    );
    assert!(
        Service::validate_snapshot_protected_floor(&active, &downgraded).is_err(),
        "snapshot cannot remove active reader floor"
    );
    assert!(
        request(
            &mut service,
            "",
            "DELETE",
            "auth/jwtcustom/role/custom",
            &admin,
            json!({}),
            110
        )
        .status
            == 204,
        "retire custom role"
    );
    let retired = service.state.as_ref().ok_or("state")?.clone();
    assert!(
        retired.schema == 68 && retired.writer_schema() == 68,
        "reader floor survives retirement"
    );
    let mut old = retired.clone();
    old.schema = 67;
    assert!(
        old.validate_publication_schema(Some(&retired)).is_err()
            && Service::validate_snapshot_protected_floor(&retired, &old).is_err(),
        "retired floor cannot downgrade through publication or restore"
    );
    let mut future = retired;
    future.schema = 69;
    assert!(
        future.writer_schema() == 69 && future.validate_format().is_err(),
        "unknown future schema remains rejected"
    );
    Ok(())
}

// Parsed public observations isolate the real Service publication boundary;
// network fetching itself remains covered by the existing remote JWT fixture.
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
    let observed = RemoteJwtLoginObservation::from_test_jwks(&keys(key)?)?;
    let observed = if config {
        OnlineAuthObservation::RemoteJwtConfig(observed)
    } else {
        OnlineAuthObservation::RemoteJwt(observed)
    };
    Ok(service.finish_external_request(plan, ExternalEffectResult::OnlineAuth(Ok(observed))))
}

fn remote_configure(service: &mut Service, admin: &str, key: &PKey<Private>) -> TestResult {
    assert!(
        request(
            service,
            "",
            "POST",
            "sys/auth/remote",
            admin,
            json!({"type":"jwt"}),
            100
        )
        .status
            == 204,
        "remote JWT mount"
    );
    let plan = remote_pending(
        service,
        "auth/remote/config",
        admin,
        json!({"issuer":"https://issuer.example","jwks_url":"https://issuer.example/keys","audiences":["service"],"jwt_supported_algs":["RS256"]}),
    )?;
    assert!(
        remote_observed(service, *plan, key, true)?.status == 204,
        "remote RSA public key configuration"
    );
    assert!(
        role(service, admin, "", "remote", "custom", "username").status == 204,
        "remote selected role"
    );
    Ok(())
}

#[test]
fn jwt_user_claim_remote_role_edit_vetoes_captured_completion() -> TestResult {
    let root = Root::new();
    let mut service = root.service()?;
    let (_, admin) = bootstrap(&mut service)?;
    let key = PKey::from_rsa(Rsa::generate(2048)?)?;
    remote_configure(&mut service, &admin, &key)?;
    let jwt = assertion(&key, "", Some(json!("selected-user")))?;
    let plan = remote_pending(
        &mut service,
        "auth/remote/login",
        "",
        json!({"role":"custom","jwt":jwt.as_str()}),
    )?;
    assert!(
        role(&mut service, &admin, "", "remote", "custom", "other-name").status == 204,
        "edit captured selector"
    );
    let before = zeroize::Zeroizing::new(serde_json::to_vec(
        &service.state.as_ref().ok_or("state")?.auth,
    )?);
    let denied = remote_observed(&mut service, *plan, &key, false)?;
    assert!(
        denied.status == 409 && denied.body.get("auth").is_none(),
        "edited role cannot publish captured selected identity"
    );
    let after = zeroize::Zeroizing::new(serde_json::to_vec(
        &service.state.as_ref().ok_or("state")?.auth,
    )?);
    assert!(
        before.as_slice() == after.as_slice(),
        "role fence retains current auth state"
    );
    assert!(
        alias(&mut service, &admin, "", "remote", "selected-user")?.status == 404,
        "veto creates no identity alias"
    );
    Ok(())
}

#[test]
fn jwt_user_claim_remote_entity_disable_vetoes_captured_completion() -> TestResult {
    let root = Root::new();
    let mut service = root.service()?;
    let (_, admin) = bootstrap(&mut service)?;
    let key = PKey::from_rsa(Rsa::generate(2048)?)?;
    remote_configure(&mut service, &admin, &key)?;
    let jwt = assertion(&key, "", Some(json!("selected-user")))?;
    let plan = remote_pending(
        &mut service,
        "auth/remote/login",
        "",
        json!({"role":"custom","jwt":jwt.as_str()}),
    )?;
    let issued = remote_observed(&mut service, *plan, &key, false)?;
    assert!(issued.status == 200, "actual RSA remote completion");
    let entity = issued.body["auth"]["entity_id"].as_str().ok_or("entity")?;
    let plan = remote_pending(
        &mut service,
        "auth/remote/login",
        "",
        json!({"role":"custom","jwt":jwt.as_str()}),
    )?;
    assert!(
        request(
            &mut service,
            "",
            "POST",
            &format!("identity/entity/id/{entity}"),
            &admin,
            json!({"disabled":true}),
            111
        )
        .status
            == 204,
        "disable selected identity during provider window"
    );
    let before = zeroize::Zeroizing::new(serde_json::to_vec(
        &service.state.as_ref().ok_or("state")?.auth,
    )?);
    let denied = remote_observed(&mut service, *plan, &key, false)?;
    assert!(
        denied.status == 403 && denied.body.get("auth").is_none(),
        "current entity disable vetoes token release"
    );
    let after = zeroize::Zeroizing::new(serde_json::to_vec(
        &service.state.as_ref().ok_or("state")?.auth,
    )?);
    assert!(
        before.as_slice() == after.as_slice(),
        "disabled completion publishes no token or alias mutation"
    );
    Ok(())
}

#[test]
fn jwt_user_claim_role_validation_preserves_previous_selector_and_subject_binding() -> TestResult {
    let root = Root::new();
    let mut service = root.service()?;
    let (_, admin) = bootstrap(&mut service)?;
    let key = PKey::from_rsa(Rsa::generate(2048)?)?;
    configure(&mut service, &admin, "", "jwtcustom", &key)?;
    assert!(
        role(&mut service, &admin, "", "jwtcustom", "custom", "username").status == 204,
        "selected role"
    );
    for value in [
        Value::Null,
        json!(false),
        json!(17),
        json!(""),
        json!("bad\nname"),
        json!("a".repeat(1025)),
    ] {
        assert!(
            request(
                &mut service,
                "",
                "POST",
                "auth/jwtcustom/role/custom",
                &admin,
                json!({"user_claim":value}),
                110
            )
            .status
                == 400,
            "malformed role claim rejected"
        );
        assert!(
            request(
                &mut service,
                "",
                "GET",
                "auth/jwtcustom/role/custom",
                &admin,
                json!({}),
                111
            )
            .body["data"]["user_claim"]
                == "username",
            "failed role write retains selector"
        );
    }
    assert!(
        request(
            &mut service,
            "",
            "POST",
            "auth/jwtcustom/role/custom",
            &admin,
            json!({"role_type":"jwt","user_claim":"username","user_claim_json_pointer":true}),
            112
        )
        .status
            == 400,
        "unsupported JSON pointer does not alter literal selection"
    );
    assert!(
        request(
            &mut service,
            "",
            "POST",
            "auth/jwtcustom/role/custom",
            &admin,
            json!({"role_type":"jwt","user_claim":"username","bound_subject":"selected-user"}),
            112
        )
        .status
            == 204,
        "independent subject constraint"
    );
    let denied = login(
        &mut service,
        &key,
        "",
        "jwtcustom",
        "custom",
        Some(json!("selected-user")),
    )?;
    assert!(
        denied.status == 400 && denied.body.get("auth").is_none(),
        "bound_subject remains registered sub rather than selected alias"
    );
    assert!(
        alias(&mut service, &admin, "", "jwtcustom", "selected-user")?.status == 404,
        "failed registered subject binding creates no alias"
    );
    Ok(())
}

#[test]
fn jwt_user_claim_create_requires_selector_existing_updates_preserve_selector() -> TestResult {
    let root = Root::new();
    let mut service = root.service()?;
    let (_, admin) = bootstrap(&mut service)?;
    let key = PKey::from_rsa(Rsa::generate(2048)?)?;
    configure(&mut service, &admin, "", "jwtcustom", &key)?;
    let before = zeroize::Zeroizing::new(serde_json::to_vec(
        &service.state.as_ref().ok_or("state")?.auth,
    )?);
    for method in ["POST", "PUT"] {
        let denied = request(
            &mut service,
            "",
            method,
            "auth/jwtcustom/role/new",
            &admin,
            json!({"role_type":"jwt","bound_audiences":["service"]}),
            110,
        );
        assert!(
            denied.status == 400,
            "new role must explicitly name its verified alias claim"
        );
        let after = zeroize::Zeroizing::new(serde_json::to_vec(
            &service.state.as_ref().ok_or("state")?.auth,
        )?);
        assert!(
            before.as_slice() == after.as_slice(),
            "missing selector cannot publish any role or token"
        );
    }
    for (name, selector) in [("custom", "username"), ("default", "sub")] {
        assert!(
            role(&mut service, &admin, "", "jwtcustom", name, selector).status == 204,
            "explicit selector admission"
        );
        for method in ["POST", "PUT"] {
            assert!(
                request(
                    &mut service,
                    "",
                    method,
                    &format!("auth/jwtcustom/role/{name}"),
                    &admin,
                    json!({"role_type":"jwt","token_ttl":180}),
                    111
                )
                .status
                    == 204,
                "existing JWT update may omit selector"
            );
            let read = request(
                &mut service,
                "",
                "GET",
                &format!("auth/jwtcustom/role/{name}"),
                &admin,
                json!({}),
                112,
            );
            assert!(
                read.status == 200 && read.body["data"]["user_claim"] == selector,
                "omitted field preserves selected claim including legacy sub"
            );
        }
    }
    Ok(())
}
