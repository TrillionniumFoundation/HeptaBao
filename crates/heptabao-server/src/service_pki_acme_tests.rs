use super::super::tests::{Root, bootstrap, call};
use super::*;
use openssl::{
    bn::BigNumContext,
    ec::{EcGroup, EcKey},
    ecdsa::EcdsaSig,
    hash::MessageDigest,
    nid::Nid,
    pkey::{PKey, Private},
    sign::Signer,
};
type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

fn key() -> TestResult<(PKey<Private>, Value)> {
    let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1)?;
    let ec = EcKey::generate(&group)?;
    let mut x = openssl::bn::BigNum::new()?;
    let mut y = openssl::bn::BigNum::new()?;
    let mut context = BigNumContext::new()?;
    ec.public_key()
        .affine_coordinates_gfp(&group, &mut x, &mut y, &mut context)?;
    let jwk = json!({"kty":"EC","crv":"P-256","x":URL_SAFE_NO_PAD.encode(x.to_vec_padded(32)?),"y":URL_SAFE_NO_PAD.encode(y.to_vec_padded(32)?)});
    Ok((PKey::from_ec_key(ec)?, jwk))
}
fn signed(
    key: &PKey<Private>,
    jwk: &Value,
    nonce: &str,
    url: &str,
    kid: Option<&str>,
    payload: Option<Value>,
) -> TestResult<Value> {
    let mut header = json!({"alg":"ES256","nonce":nonce,"url":url});
    match kid {
        Some(kid) => header["kid"] = json!(kid),
        None => header["jwk"] = jwk.clone(),
    }
    let protected = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header)?);
    let payload = payload
        .map(|v| serde_json::to_vec(&v))
        .transpose()?
        .unwrap_or_default();
    let payload = URL_SAFE_NO_PAD.encode(payload);
    let message = format!("{protected}.{payload}");
    let mut signer = Signer::new(MessageDigest::sha256(), key)?;
    signer.update(message.as_bytes())?;
    let signature = EcdsaSig::from_der(&signer.sign_to_vec()?)?;
    let mut raw = signature.r().to_vec_padded(32)?;
    raw.extend(signature.s().to_vec_padded(32)?);
    Ok(json!({"protected":protected,"payload":payload,"signature":URL_SAFE_NO_PAD.encode(raw)}))
}
fn header(response: &Response, name: &str) -> TestResult<String> {
    let h = serde_json::to_value(&response.response_headers)?;
    Ok(h[name][0]
        .as_str()
        .ok_or("actual filtered ACME header")?
        .to_owned())
}
fn setup(service: &mut Service, token: &str) -> TestResult {
    assert_eq!(
        call(
            service,
            "POST",
            "sys/mounts/acmeca",
            token,
            json!({"type":"pki"})
        )
        .status,
        204
    );
    assert_eq!(
        call(
            service,
            "POST",
            "acmeca/root/generate/internal",
            token,
            json!({"common_name":"Actual ACME CA","key_type":"ed25519","ttl":"4h"})
        )
        .status,
        200
    );
    assert_eq!(
        call(
            service,
            "POST",
            "acmeca/config/cluster",
            token,
            json!({"path":"https://acme.example.test/v1/acmeca"})
        )
        .status,
        200
    );
    assert_eq!(
        call(
            service,
            "POST",
            "acmeca/config/acme",
            token,
            json!({"enabled":true,"eab_policy":"not-required"})
        )
        .status,
        200
    );
    assert_eq!(
        call(
            service,
            "POST",
            "sys/mounts/acmeca/tune",
            token,
            json!({"allowed_response_headers":["Replay-Nonce","Link","Location"]})
        )
        .status,
        204
    );
    Ok(())
}
fn nonce(service: &mut Service) -> TestResult<String> {
    let response = call(service, "HEAD", "acmeca/acme/new-nonce", "", json!({}));
    assert_eq!(response.status, 200);
    header(&response, "Replay-Nonce")
}
#[test]
fn pki_acme99_nonce_single_use_exact_90s_and_process_owner() -> TestResult {
    let owner = AcmeBinding {
        cluster_id: "actual-cluster".into(),
        namespace: "".into(),
        namespace_incarnation: Some(0),
        mount: "pki/".into(),
        mount_incarnation: 1,
    };
    let at = Timestamp::checked(100, 700_000_000)?;
    let mut table = Nonces::default();
    let nonce = table
        .mint(&owner, "actual-activation", at)
        .map_err(|_| "nonce")?;
    assert_eq!(URL_SAFE_NO_PAD.decode(&nonce)?.len(), 46);
    assert!(table.redeem(&nonce, &owner, "actual-activation", Timestamp::whole(190)?));
    assert!(!table.redeem(&nonce, &owner, "actual-activation", Timestamp::whole(190)?));
    let expired = table
        .mint(&owner, "actual-activation", at)
        .map_err(|_| "nonce")?;
    assert!(!table.redeem(
        &expired,
        &owner,
        "actual-activation",
        Timestamp::checked(190, 1)?
    ));
    let process = table
        .mint(&owner, "actual-activation", at)
        .map_err(|_| "nonce")?;
    assert!(!Nonces::default().redeem(&process, &owner, "actual-activation", at));
    let mut changed = owner.clone();
    changed.mount_incarnation = 2;
    assert!(!table.redeem(&process, &changed, "actual-activation", at));
    assert!(!table.redeem(&process, &owner, "actual-activation", at));
    Ok(())
}
#[test]
fn pki_acme99_real_jws_accounts_replay_encrypted_reopen_and_deactivation_floor() -> TestResult {
    let directory = Root::new();
    let mut service = directory.service()?;
    let (unseal, admin) = bootstrap(&mut service)?;
    setup(&mut service, &admin)?;
    let (key, jwk) = key()?;
    let base = "https://acme.example.test/v1/acmeca/acme/";
    let n = nonce(&mut service)?;
    let request = signed(
        &key,
        &jwk,
        &n,
        &format!("{base}new-account"),
        None,
        Some(json!({"contact":["mailto:actual@example.test"],"termsOfServiceAgreed":true})),
    )?;
    let response = call(
        &mut service,
        "POST",
        "acmeca/acme/new-account",
        "",
        request.clone(),
    );
    assert_eq!(response.status, 201);
    assert_eq!(
        response.body["__heptabao_acme"]["contact"],
        json!(["mailto:actual@example.test"])
    );
    let kid = header(&response, "Location")?;
    assert_eq!(service.state.as_ref().ok_or("state")?.schema, 99);
    let replay = call(&mut service, "POST", "acmeca/acme/new-account", "", request);
    assert_eq!(replay.status, 400);
    assert!(
        replay.response_headers.is_empty(),
        "native problem does not issue a replacement nonce"
    );
    assert_eq!(
        replay.body["__heptabao_acme"]["type"],
        "urn:ietf:params:acme:error:badNonce"
    );
    let fresh = nonce(&mut service)?;
    let alias = format!(
        "https://unrelated-public.example.test/account/{}",
        kid.rsplit('/').next().ok_or("account")?
    );
    let alias_request = signed(&key, &jwk, &fresh, &kid, Some(&alias), None)?;
    let account_path = format!(
        "acmeca/acme/account/{}",
        kid.rsplit('/').next().ok_or("account")?
    );
    let alias_response = call(&mut service, "POST", &account_path, "", alias_request);
    assert_eq!(alias_response.status, 200);
    assert_eq!(header(&alias_response, "Location")?, kid);
    let fresh = nonce(&mut service)?;
    let other_id = "00000000-0000-4000-8000-000000000001";
    let route = format!("acmeca/acme/account/{other_id}");
    let route_url = format!("{base}account/{other_id}");
    let alias_request = signed(&key, &jwk, &fresh, &route_url, Some(&kid), None)?;
    let alias_response = call(&mut service, "POST", &route, "", alias_request);
    assert_eq!(alias_response.status, 200);
    assert_eq!(header(&alias_response, "Location")?, kid);
    let fresh = nonce(&mut service)?;
    let mut invalid = signed(&key, &jwk, &fresh, &kid, Some(&kid), None)?;
    let mut signature =
        URL_SAFE_NO_PAD.decode(invalid["signature"].as_str().ok_or("signature")?)?;
    signature[0] ^= 1;
    invalid["signature"] = json!(URL_SAFE_NO_PAD.encode(signature));
    let error = call(&mut service, "POST", &account_path, "", invalid);
    assert_eq!(error.status, 500);
    assert_eq!(
        error.body["__heptabao_acme"]["type"],
        "urn:ietf:params:acme:error:serverInternal"
    );
    let consumed = signed(&key, &jwk, &fresh, &kid, Some(&kid), None)?;
    assert_eq!(
        call(&mut service, "POST", &account_path, "", consumed).status,
        400
    );
    let stale = service.state.clone().ok_or("state")?;
    let old_nonce = nonce(&mut service)?;
    assert_eq!(
        call(&mut service, "PUT", "sys/seal", &admin, json!({})).status,
        204
    );
    drop(service);
    let mut service = directory.service()?;
    assert_eq!(
        call(&mut service, "PUT", "sys/unseal", "", json!({"key":unseal})).status,
        200
    );
    let path = format!(
        "acmeca/acme/account/{}",
        kid.rsplit('/').next().ok_or("account")?
    );
    let old = signed(&key, &jwk, &old_nonce, &kid, Some(&kid), None)?;
    assert_eq!(call(&mut service, "POST", &path, "", old).status, 400);
    let fresh = nonce(&mut service)?;
    let get = signed(&key, &jwk, &fresh, &kid, Some(&kid), None)?;
    let response = call(&mut service, "POST", &path, "", get);
    assert_eq!(response.status, 200);
    assert!(
        response.body["__heptabao_acme"].get("contact").is_none(),
        "native POST-as-GET clears contact"
    );
    let fresh = nonce(&mut service)?;
    let wrong = signed(
        &key,
        &jwk,
        &fresh,
        "https://wrong.example.test/",
        Some(&kid),
        None,
    )?;
    assert_eq!(call(&mut service, "POST", &path, "", wrong).status, 401);
    let consumed = signed(&key, &jwk, &fresh, &kid, Some(&kid), None)?;
    assert_eq!(
        call(&mut service, "POST", &path, "", consumed).status,
        400,
        "URL failure consumes the nonce before signature validation"
    );
    let fresh = nonce(&mut service)?;
    let deactivate = signed(
        &key,
        &jwk,
        &fresh,
        &kid,
        Some(&kid),
        Some(json!({"status":"deactivated"})),
    )?;
    let response = call(&mut service, "POST", &path, "", deactivate);
    assert_eq!(response.status, 200);
    assert_eq!(response.body["__heptabao_acme"]["status"], "deactivated");
    let current = service.state.as_ref().ok_or("state")?;
    assert!(Service::validate_snapshot_protected_floor(current, &stale).is_err());
    let mut lowered = current.clone();
    lowered.schema = 98;
    assert_eq!(lowered.writer_schema(), 99);
    assert!(lowered.validate_format().is_err());
    let mut mutated = serde_json::to_value(current)?;
    mutated["engines"]["namespaces"][""]["mounts"]["acmeca/"]["backend"]["Pki"]["acme_protocol"]
        ["owner"]["cluster_id"] = json!("another-real-cluster");
    let bad: State = serde_json::from_value(mutated)?;
    assert!(bad.validate_format().is_err());
    let fresh = nonce(&mut service)?;
    let get = signed(&key, &jwk, &fresh, &kid, Some(&kid), None)?;
    assert_eq!(call(&mut service, "POST", &path, "", get).status, 401);
    assert_eq!(
        call(
            &mut service,
            "DELETE",
            "sys/mounts/acmeca",
            &admin,
            json!({})
        )
        .status,
        204
    );
    assert_eq!(
        service.state.as_ref().ok_or("state")?.schema,
        99,
        "account reader floor survives mount retirement"
    );
    Ok(())
}
#[test]
fn pki_acme99_public_capsule_vetoes_nonce_after_mount_aba_and_deadline() -> TestResult {
    let directory = Root::new();
    let mut service = directory.service()?;
    let (_, admin) = bootstrap(&mut service)?;
    setup(&mut service, &admin)?;
    let state = service.state.as_ref().ok_or("state")?;
    let view = state
        .engines
        .acme_view(
            "",
            "acmeca/acme/new-nonce",
            &state.cluster_id,
            state.namespaces.incarnation(""),
        )?
        .ok_or("view")?;
    let request = RequestView {
        method: "HEAD",
        path: "acmeca/acme/new-nonce",
        namespace: "",
        token: "",
        body: &Value::Null,
        now: 100,
        admission_started: std::time::Instant::now(),
        token_clock: None,
        allow_forward: false,
        enforce_namespace: false,
        wrap_ttl_seconds: None,
        origin_peer: None,
        client_certificates: None,
    };
    let mut authority = Authority::capture(state, &view, &request, &service.unseal_nonce, None);
    assert!(authority.check(&mut service).is_ok());
    authority.deadline = Some(std::time::Instant::now());
    assert!(authority.check(&mut service).is_err());
    authority.deadline = None;
    assert_eq!(
        call(
            &mut service,
            "DELETE",
            "sys/mounts/acmeca",
            &admin,
            json!({})
        )
        .status,
        204
    );
    assert_eq!(
        call(
            &mut service,
            "POST",
            "sys/mounts/acmeca",
            &admin,
            json!({"type":"pki"})
        )
        .status,
        204
    );
    assert!(authority.check(&mut service).is_err());
    Ok(())
}

#[test]
fn pki_acme99_final_publish_rejects_original_deadline_without_committing_candidate() -> TestResult {
    let directory = Root::new();
    let mut service = directory.service()?;
    let (_, admin) = bootstrap(&mut service)?;
    setup(&mut service, &admin)?;
    let state = service.state.as_ref().ok_or("state")?;
    let view = state
        .engines
        .acme_view(
            "",
            "acmeca/acme/new-nonce",
            &state.cluster_id,
            state.namespaces.incarnation(""),
        )?
        .ok_or("view")?;
    let request = RequestView {
        method: "HEAD",
        path: "acmeca/acme/new-nonce",
        namespace: "",
        token: "",
        body: &Value::Null,
        now: 100,
        admission_started: std::time::Instant::now(),
        token_clock: None,
        allow_forward: false,
        enforce_namespace: false,
        wrap_ttl_seconds: None,
        origin_peer: None,
        client_certificates: None,
    };
    let mut authority = Authority::capture(state, &view, &request, &service.unseal_nonce, None);
    let identity = service.current_state_identity().map_err(|_| "identity")?;
    let mut candidate = state.clone();
    candidate
        .engines
        .acme_activate_nonce_owner(&view.owner, Timestamp::whole(101)?)?;
    let plan = service
        .prepare_record_plan(&mut candidate)
        .map_err(|_| "plan")?;
    authority.bind_candidate(&candidate).map_err(|_| "bind")?;
    authority.deadline = Some(std::time::Instant::now());
    let rejected = service.commit_record_plan_with_before_publish(
        &candidate,
        plan,
        |_| authority.check_state(&candidate),
        #[cfg(all(feature = "fixture-native-restore-faults", target_os = "linux"))]
        None,
    );
    assert_eq!(
        rejected
            .err()
            .ok_or("expired original deadline must reject")?
            .status,
        503
    );
    assert!(service.current_state_identity().map_err(|_| "identity")? == identity);
    assert!(authority.check(&mut service).is_err());
    Ok(())
}

#[test]
fn pki_acme99_header_append_preserves_admitted_case_variants_and_value_order() -> TestResult {
    let values: Vec<_> = (0..32).map(|i| format!("old-{i}")).collect();
    let source = json!({"X-Example":values,"x-example":["variant"]});
    let allowed = vec!["X-Example".to_owned(), "Link".to_owned()];
    let mut headers = ResponseHeaders::from_sdk(Some(&source), &allowed).map_err(|_| "headers")?;
    headers
        .append_from_sdk(
            Some(&json!({"X-Example":["new"],"Link":["actual-link"]})),
            &allowed,
        )
        .map_err(|_| "append")?;
    let actual = serde_json::to_value(headers)?;
    let values = actual["X-Example"].as_array().ok_or("values")?;
    assert_eq!(values.len(), 34);
    assert_eq!(values[0], "old-0");
    assert_eq!(values[32], "variant");
    assert_eq!(values[33], "new");
    assert_eq!(actual["Link"][0], "actual-link");
    Ok(())
}

#[test]
fn pki_acme99_namespace_retirement_uses_actual_catalog_frontier_and_retains_root_account()
-> TestResult {
    let directory = Root::new();
    let mut service = directory.service()?;
    let (_, admin) = bootstrap(&mut service)?;
    assert_eq!(
        call(
            &mut service,
            "POST",
            "sys/namespaces/empty",
            &admin,
            json!({})
        )
        .status,
        200
    );
    setup(&mut service, &admin)?;
    let original_nonce = nonce(&mut service)?;
    let before = service.state.as_ref().ok_or("state")?.clone();
    let deleted = call(
        &mut service,
        "DELETE",
        "sys/namespaces/empty",
        &admin,
        json!({}),
    );
    assert_eq!(deleted.status, 200);
    assert_eq!(deleted.body["data"]["status"], "in-progress");
    let retired = service.state.as_ref().ok_or("state")?;
    assert!(
        Service::validate_snapshot_protected_floor(retired, &before).is_err(),
        "actual namespace retirement cannot be restored even with the same99 floor"
    );
    assert_eq!(
        call(
            &mut service,
            "POST",
            "sys/namespaces/empty",
            &admin,
            json!({})
        )
        .status,
        200
    );
    let (key, jwk) = key()?;
    let created = call(
        &mut service,
        "POST",
        "acmeca/acme/new-account",
        "",
        signed(
            &key,
            &jwk,
            &original_nonce,
            "https://acme.example.test/v1/acmeca/acme/new-account",
            None,
            Some(json!({"termsOfServiceAgreed":true})),
        )?,
    );
    assert_eq!(created.status, 201);
    assert_eq!(service.state.as_ref().ok_or("state")?.schema, 99);
    Ok(())
}

#[test]
fn pki_acme99_actual_issuer_selection_role_override_and_policy_rejection() -> TestResult {
    let directory = Root::new();
    let mut service = directory.service()?;
    let (_, admin) = bootstrap(&mut service)?;
    setup(&mut service, &admin)?;
    let first = call(
        &mut service,
        "GET",
        "acmeca/config/issuers",
        &admin,
        json!({}),
    )
    .body["data"]["default"]
        .as_str()
        .ok_or("actual default issuer")?
        .to_owned();
    let second = call(
        &mut service,
        "POST",
        "acmeca/root/generate/internal",
        &admin,
        json!({"common_name":"Actual second ACME CA","issuer_name":"second","key_type":"ed25519","ttl":"4h"}),
    );
    assert_eq!(second.status, 200);
    let second_id = second.body["data"]["issuer_id"]
        .as_str()
        .ok_or("second issuer")?
        .to_owned();
    assert_ne!(first, second_id);
    assert_eq!(
        call(
            &mut service,
            "POST",
            "acmeca/config/acme",
            &admin,
            json!({"allowed_issuers":[first]})
        )
        .status,
        200
    );
    for (path, status) in [
        ("acmeca/acme/directory".to_owned(), 200),
        (format!("acmeca/issuer/{first}/acme/directory"), 200),
        ("acmeca/issuer/second/acme/directory".to_owned(), 500),
        ("acmeca/issuer/missing/acme/directory".to_owned(), 400),
    ] {
        assert_eq!(
            call(&mut service, "GET", &path, "", json!({})).status,
            status
        );
    }
    assert_eq!(
        call(
            &mut service,
            "POST",
            "acmeca/config/issuers",
            &admin,
            json!({"default":"second"})
        )
        .status,
        200
    );
    assert_eq!(
        call(&mut service, "GET", "acmeca/acme/directory", "", json!({})).status,
        500
    );
    assert_eq!(
        call(
            &mut service,
            "POST",
            "acmeca/roles/web",
            &admin,
            json!({"issuer_ref":first,"allowed_domains":["example.test"]})
        )
        .status,
        200
    );
    assert_eq!(
        call(
            &mut service,
            "GET",
            "acmeca/roles/web/acme/directory",
            "",
            json!({})
        )
        .status,
        200
    );
    assert_eq!(
        call(
            &mut service,
            "GET",
            "acmeca/issuer/second/roles/web/acme/directory",
            "",
            json!({})
        )
        .status,
        500
    );
    assert_eq!(
        call(
            &mut service,
            "POST",
            "acmeca/config/acme",
            &admin,
            json!({"allowed_issuers":["*"],"default_directory_policy":"forbid"})
        )
        .status,
        200
    );
    assert_eq!(
        call(
            &mut service,
            "GET",
            "acmeca/issuer/second/acme/directory",
            "",
            json!({})
        )
        .status,
        500
    );
    assert_eq!(
        call(
            &mut service,
            "GET",
            "acmeca/issuer/second/roles/web/acme/directory",
            "",
            json!({})
        )
        .status,
        200
    );
    Ok(())
}

#[test]
fn pki_acme99_retired_allowlist_reference_reopens_without_rebinding_another_issuer() -> TestResult {
    let directory = Root::new();
    let mut service = directory.service()?;
    let (unseal, admin) = bootstrap(&mut service)?;
    setup(&mut service, &admin)?;
    let second = call(
        &mut service,
        "POST",
        "acmeca/root/generate/internal",
        &admin,
        json!({"common_name":"Retired ACME CA","issuer_name":"retiring","key_type":"ed25519","ttl":"4h"}),
    );
    assert_eq!(second.status, 200);
    assert_eq!(
        call(
            &mut service,
            "POST",
            "acmeca/config/acme",
            &admin,
            json!({"allowed_issuers":["retiring"]})
        )
        .status,
        200
    );
    assert_eq!(
        call(
            &mut service,
            "GET",
            "acmeca/issuer/retiring/acme/directory",
            "",
            json!({})
        )
        .status,
        200
    );
    assert_eq!(
        call(
            &mut service,
            "DELETE",
            "acmeca/issuer/retiring",
            &admin,
            json!({})
        )
        .status,
        200
    );
    assert_eq!(
        call(
            &mut service,
            "GET",
            "acmeca/issuer/retiring/acme/directory",
            "",
            json!({})
        )
        .status,
        400
    );
    let refused = call(&mut service, "GET", "acmeca/acme/directory", "", json!({}));
    assert_eq!(refused.status, 500);
    assert!(
        refused.body["__heptabao_acme"]["detail"]
            .as_str()
            .is_some_and(|s| s.contains("allowed_issuer entry 0"))
    );
    let identity = service.current_state_identity().map_err(|_| "identity")?;
    assert_eq!(
        call(
            &mut service,
            "POST",
            "acmeca/config/acme",
            &admin,
            json!({"allowed_issuers":["missing"]})
        )
        .status,
        500
    );
    assert!(
        identity
            == service
                .current_state_identity()
                .map_err(|_| "unchanged identity")?
    );
    drop(service);
    let mut reopened = directory.service()?;
    assert_eq!(
        call(
            &mut reopened,
            "POST",
            "sys/unseal",
            "",
            json!({"key":unseal})
        )
        .status,
        200
    );
    assert_eq!(
        call(&mut reopened, "GET", "acmeca/acme/directory", "", json!({})).status,
        500
    );
    assert_eq!(
        call(
            &mut reopened,
            "GET",
            "acmeca/config/acme",
            &admin,
            json!({})
        )
        .body["data"]["allowed_issuers"],
        json!(["retiring"])
    );
    assert_eq!(reopened.state.as_ref().ok_or("reopened")?.schema, 99);
    Ok(())
}

fn order_post(
    service: &mut Service,
    key: &PKey<Private>,
    jwk: &Value,
    kid: &str,
    endpoint: &str,
    payload: Option<Value>,
) -> TestResult<Response> {
    let n = nonce(service)?;
    let base = "https://acme.example.test/v1/acmeca/acme/";
    let request = signed(
        key,
        jwk,
        &n,
        &format!("{base}{endpoint}"),
        Some(kid),
        payload,
    )?;
    Ok(call(
        service,
        "POST",
        &format!("acmeca/acme/{endpoint}"),
        "",
        request,
    ))
}
fn order_account(service: &mut Service, key: &PKey<Private>, jwk: &Value) -> TestResult<String> {
    let n = nonce(service)?;
    let created = call(
        service,
        "POST",
        "acmeca/acme/new-account",
        "",
        signed(
            key,
            jwk,
            &n,
            "https://acme.example.test/v1/acmeca/acme/new-account",
            None,
            Some(json!({"termsOfServiceAgreed":true})),
        )?,
    );
    assert_eq!(created.status, 201);
    header(&created, "Location")
}
#[test]
fn pki_acme99_pending_orders_real_jws_challenges_encrypted_reopen_and_deactivation() -> TestResult {
    let directory = Root::new();
    let mut service = directory.service()?;
    let (unseal, admin) = bootstrap(&mut service)?;
    setup(&mut service, &admin)?;
    let (key, jwk) = key()?;
    let kid = order_account(&mut service, &key, &jwk)?;
    let empty = order_post(
        &mut service,
        &key,
        &jwk,
        &kid,
        "new-order",
        Some(json!({"identifiers":[]})),
    )?;
    assert_eq!(empty.status, 201);
    assert_eq!(empty.body["__heptabao_acme"]["identifiers"], Value::Null);
    assert_eq!(empty.body["__heptabao_acme"]["authorizations"], Value::Null);
    let identifiers = json!([{"type":"dns","value":"example.test"},{"type":"dns","value":"example.test"},{"type":"dns","value":"*.example.test"},{"type":"ip","value":"127.0.0.1"},{"type":"ip","value":"2001:db8::1"}]);
    let created = order_post(
        &mut service,
        &key,
        &jwk,
        &kid,
        "new-order",
        Some(json!({"identifiers":identifiers})),
    )?;
    assert_eq!(created.status, 201);
    assert_eq!(created.body["__heptabao_acme"]["identifiers"], identifiers);
    let order_url = header(&created, "Location")?;
    let order_endpoint = order_url.split("/acme/").nth(1).ok_or("order route")?;
    let auth_urls: Vec<String> = created.body["__heptabao_acme"]["authorizations"]
        .as_array()
        .ok_or("authorizations")?
        .iter()
        .map(|v| v.as_str().ok_or("auth URL").map(str::to_owned))
        .collect::<Result<_, _>>()?;
    assert_ne!(
        auth_urls[0], auth_urls[1],
        "duplicate identifiers retain independently owned authorizations"
    );
    for (index, url) in auth_urls.iter().enumerate() {
        let auth = order_post(
            &mut service,
            &key,
            &jwk,
            &kid,
            url.split("/acme/").nth(1).ok_or("auth route")?,
            None,
        )?;
        assert_eq!(auth.status, 200);
        let data = &auth.body["__heptabao_acme"];
        let challenges = data["challenges"].as_array().ok_or("challenges")?;
        let expected: &[&str] = if index < 2 {
            &["http-01", "dns-01", "tls-alpn-01"]
        } else if index == 2 {
            &["dns-01"]
        } else {
            &["http-01"]
        };
        assert_eq!(
            challenges
                .iter()
                .filter_map(|c| c["type"].as_str())
                .collect::<Vec<_>>(),
            expected
        );
        for c in challenges {
            assert_eq!(
                URL_SAFE_NO_PAD
                    .decode(c["token"].as_str().ok_or("public token")?)?
                    .len(),
                21
            );
        }
        assert_eq!(data["wildcard"], index == 2);
        if index == 2 {
            assert_eq!(data["identifier"]["value"], "example.test");
        }
    }
    let actual = service.state.as_ref().ok_or("state")?;
    let value = serde_json::to_value(actual)?;
    let protocol =
        &value["engines"]["namespaces"][""]["mounts"]["acmeca/"]["backend"]["Pki"]["acme_protocol"];
    let order_id = order_endpoint.strip_prefix("order/").ok_or("order ID")?;
    let private_created: Timestamp =
        serde_json::from_value(protocol["orders"][order_id]["created"].clone())?;
    let private_expires: Timestamp =
        serde_json::from_value(protocol["orders"][order_id]["expires"].clone())?;
    assert_eq!(private_expires.seconds() - private_created.seconds(), 86400);
    assert_eq!(
        private_expires.duration_since_epoch().subsec_nanos(),
        private_created.duration_since_epoch().subsec_nanos()
    );
    assert_eq!(actual.schema, 99);
    assert_eq!(
        call(&mut service, "PUT", "sys/seal", &admin, json!({})).status,
        204
    );
    drop(service);
    let mut service = directory.service()?;
    assert_eq!(
        call(&mut service, "PUT", "sys/unseal", "", json!({"key":unseal})).status,
        200
    );
    let read = order_post(&mut service, &key, &jwk, &kid, order_endpoint, None)?;
    assert_eq!(read.status, 200);
    assert_eq!(
        read.body["__heptabao_acme"],
        created.body["__heptabao_acme"]
    );
    let stale = service.state.as_ref().ok_or("state")?.clone();
    let auth_endpoint = auth_urls[0].split("/acme/").nth(1).ok_or("auth route")?;
    let deactivated = order_post(
        &mut service,
        &key,
        &jwk,
        &kid,
        auth_endpoint,
        Some(json!({"status":"deactivated"})),
    )?;
    assert_eq!(deactivated.status, 200);
    assert!(
        deactivated.body["__heptabao_acme"]["challenges"]
            .as_array()
            .ok_or("challenges")?
            .iter()
            .all(|c| c["status"] == "invalid")
    );
    let invalid = order_post(&mut service, &key, &jwk, &kid, order_endpoint, None)?;
    assert_eq!(invalid.body["__heptabao_acme"]["status"], "invalid");
    assert_eq!(
        invalid.body["__heptabao_acme"]["authorizations"],
        Value::Null
    );
    let listed = order_post(&mut service, &key, &jwk, &kid, "orders", None)?;
    assert!(
        listed.body["__heptabao_acme"]["orders"]
            .as_array()
            .ok_or("orders")?
            .contains(&json!(order_url)),
        "native computed GET invalid is not a persisted list transition"
    );
    let current = service.state.as_ref().ok_or("state")?;
    assert!(
        Service::validate_snapshot_protected_floor(current, &stale).is_err(),
        "retained authorization deactivation cannot roll back within same99"
    );
    Ok(())
}
#[test]
fn pki_acme99_order_account_proof_and_authenticated_relation_cannot_be_forged() -> TestResult {
    let directory = Root::new();
    let mut service = directory.service()?;
    let (_, admin) = bootstrap(&mut service)?;
    setup(&mut service, &admin)?;
    let (first_key, first_jwk) = key()?;
    let kid = order_account(&mut service, &first_key, &first_jwk)?;
    let order = order_post(
        &mut service,
        &first_key,
        &first_jwk,
        &kid,
        "new-order",
        Some(json!({"identifiers":[{"type":"dns","value":"example.test"}]})),
    )?;
    assert_eq!(order.status, 201);
    let location = header(&order, "Location")?;
    let endpoint = location.split("/acme/").nth(1).ok_or("order route")?;
    let id = endpoint.strip_prefix("order/").ok_or("order ID")?;
    let (other_key, other_jwk) = key()?;
    let other_kid = order_account(&mut service, &other_key, &other_jwk)?;
    assert_eq!(
        order_post(
            &mut service,
            &other_key,
            &other_jwk,
            &other_kid,
            endpoint,
            None
        )?
        .status,
        400,
        "valid foreign account proof does not own this order"
    );
    let actual = service.state.as_ref().ok_or("state")?;
    for field in ["account", "owner", "authorizations"] {
        let mut value = serde_json::to_value(actual)?;
        let p = &mut value["engines"]["namespaces"][""]["mounts"]["acmeca/"]["backend"]["Pki"]["acme_protocol"];
        match field {
            "account" => {
                p["orders"][id]["account"] = json!(other_kid.rsplit('/').next().ok_or("account")?)
            }
            "owner" => p["orders"][id]["owner"]["mount_incarnation"] = json!(2),
            _ => p["orders"][id]["authorizations"] = json!([]),
        }
        let forged: State = serde_json::from_value(value)?;
        assert!(
            forged.validate_format().is_err(),
            "actual authenticated order relation rejects {field}"
        );
    }
    let missing = order_post(
        &mut service,
        &first_key,
        &first_jwk,
        &kid,
        "new-order",
        Some(json!({})),
    )?;
    assert_eq!(missing.status, 400);
    assert_eq!(
        missing.body["__heptabao_acme"]["detail"],
        "missing required identifiers argument: the request message was malformed"
    );
    let unsupported = order_post(
        &mut service,
        &first_key,
        &first_jwk,
        &kid,
        "new-order",
        Some(json!({"identifiers":[{"type":"uri","value":"https://example.test"}]})),
    )?;
    assert_eq!(
        unsupported.body["__heptabao_acme"]["type"],
        "urn:ietf:params:acme:error:unsupportedIdentifier"
    );
    Ok(())
}

fn pending_http01(
    service: &mut Service,
    key: &PKey<Private>,
    jwk: &Value,
    kid: &str,
) -> TestResult<(String, String, String)> {
    let order = order_post(
        service,
        key,
        jwk,
        kid,
        "new-order",
        Some(json!({"identifiers":[{"type":"ip","value":"127.0.0.1"}]})),
    )?;
    assert_eq!(order.status, 201);
    let order = header(&order, "Location")?
        .split("/acme/")
        .nth(1)
        .ok_or("order route")?
        .to_owned();
    let get = order_post(service, key, jwk, kid, &order, None)?;
    let auth = get.body["__heptabao_acme"]["authorizations"][0]
        .as_str()
        .ok_or("auth route")?
        .split("/acme/")
        .nth(1)
        .ok_or("auth route")?
        .to_owned();
    let get = order_post(service, key, jwk, kid, &auth, None)?;
    let challenge = get.body["__heptabao_acme"]["challenges"][0]["url"]
        .as_str()
        .ok_or("challenge")?
        .split("/acme/")
        .nth(1)
        .ok_or("challenge route")?
        .to_owned();
    Ok((order, auth, challenge))
}
fn maintenance_clock(at: u64) -> TestResult<RequestClock> {
    Ok(RequestClock::anchored(
        Duration::from_secs(at),
        std::time::Instant::now(),
    )?)
}
#[test]
fn pki_acme99_http01_actual_network_owned_queue_reopen_and_ready() -> TestResult {
    let directory = Root::new();
    let mut service = directory.service()?;
    let (unseal, admin) = bootstrap(&mut service)?;
    setup(&mut service, &admin)?;
    let (key, jwk) = key()?;
    let kid = order_account(&mut service, &key, &jwk)?;
    let (order, auth, challenge) = pending_http01(&mut service, &key, &jwk, &kid)?;
    let fetch = order_post(&mut service, &key, &jwk, &kid, &challenge, None)?;
    assert_eq!(fetch.status, 200);
    assert_eq!(fetch.body["__heptabao_acme"]["status"], "pending");
    assert!(
        service
            .prepare_acme_maintenance(maintenance_clock(101)?)
            .map_err(|_| "prepare")?
            .is_none()
    );
    let bad = order_post(
        &mut service,
        &key,
        &jwk,
        &kid,
        &challenge,
        Some(json!({"unexpected":true})),
    )?;
    assert_eq!(bad.status, 400);
    let accept = order_post(&mut service, &key, &jwk, &kid, &challenge, Some(json!({})))?;
    assert_eq!(accept.status, 200);
    assert_eq!(accept.body["__heptabao_acme"]["status"], "processing");
    let original = service
        .prepare_acme_maintenance(maintenance_clock(101)?)
        .map_err(|_| "prepare")?
        .ok_or("queue")?;
    drop(service);
    let mut service = directory.service()?;
    assert_eq!(
        call(
            &mut service,
            "POST",
            "sys/unseal",
            "",
            json!({"key":unseal})
        )
        .status,
        200
    );
    assert!(
        original.check(&service).is_err(),
        "process activation never resurrects an old attempt"
    );
    let plan = service
        .prepare_acme_maintenance(maintenance_clock(101)?)
        .map_err(|_| "prepare")?
        .ok_or("persisted queue")?;
    let listener = std::net::TcpListener::bind("127.0.0.1:0")?;
    let port = listener.local_addr()?.port();
    let expected = format!(
        "  {}.{} \n",
        plan.queued.challenge.token, plan.queued.thumbprint
    );
    let token = plan.queued.challenge.token.clone();
    let server = std::thread::spawn(move || -> std::io::Result<()> {
        use std::io::{Read, Write};
        let (mut socket, _) = listener.accept()?;
        socket.set_read_timeout(Some(Duration::from_secs(3)))?;
        let mut raw = Vec::new();
        let mut one = [0; 1];
        while !raw.ends_with(b"\r\n\r\n") {
            socket.read_exact(&mut one)?;
            raw.push(one[0]);
            if raw.len() > 4096 {
                return Err(std::io::Error::other("oversized request"));
            }
        }
        assert!(String::from_utf8_lossy(&raw).starts_with(&format!(
            "GET /.well-known/acme-challenge/{token} HTTP/1.1\r\n"
        )));
        socket.write_all(
            format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{expected}",
                expected.len()
            )
            .as_bytes(),
        )
    });
    let result = plan.execute_port(port);
    server.join().map_err(|_| "listener thread")??;
    assert!(result.is_ok());
    service
        .finish_acme_maintenance(plan, result)
        .map_err(|_| "actual proof publication")?;
    let valid = order_post(&mut service, &key, &jwk, &kid, &auth, None)?;
    assert_eq!(valid.body["__heptabao_acme"]["status"], "valid");
    assert!(valid.body["__heptabao_acme"]["expires"].is_string());
    let ready = order_post(&mut service, &key, &jwk, &kid, &order, None)?;
    assert_eq!(ready.body["__heptabao_acme"]["status"], "ready");
    let repeat = order_post(&mut service, &key, &jwk, &kid, &challenge, Some(json!({})))?;
    assert_eq!(repeat.status, 400);
    drop(service);
    let mut service = directory.service()?;
    assert_eq!(
        call(
            &mut service,
            "POST",
            "sys/unseal",
            "",
            json!({"key":unseal})
        )
        .status,
        200
    );
    let ready = order_post(&mut service, &key, &jwk, &kid, &order, None)?;
    assert_eq!(ready.body["__heptabao_acme"]["status"], "ready");
    Ok(())
}
#[test]
fn pki_acme99_http01_attempt_vetoes_retired_account_authorization_mount_and_timeout() -> TestResult
{
    for cut in ["account", "authorization", "mount", "timeout"] {
        let directory = Root::new();
        let mut service = directory.service()?;
        let (_, admin) = bootstrap(&mut service)?;
        setup(&mut service, &admin)?;
        let (key, jwk) = key()?;
        let kid = order_account(&mut service, &key, &jwk)?;
        let (order, auth, challenge) = pending_http01(&mut service, &key, &jwk, &kid)?;
        assert_eq!(
            order_post(&mut service, &key, &jwk, &kid, &challenge, Some(json!({})))?.status,
            200
        );
        let mut plan = service
            .prepare_acme_maintenance(maintenance_clock(101)?)
            .map_err(|_| "prepare")?
            .ok_or("queue")?;
        match cut {
            "account" => {
                let endpoint = kid.split("/acme/").nth(1).ok_or("account route")?;
                assert_eq!(
                    order_post(
                        &mut service,
                        &key,
                        &jwk,
                        &kid,
                        endpoint,
                        Some(json!({"status":"deactivated"}))
                    )?
                    .status,
                    200
                );
            }
            "authorization" => {
                assert_eq!(
                    order_post(
                        &mut service,
                        &key,
                        &jwk,
                        &kid,
                        &auth,
                        Some(json!({"status":"deactivated"}))
                    )?
                    .status,
                    200
                );
            }
            "mount" => {
                assert_eq!(
                    call(
                        &mut service,
                        "DELETE",
                        "sys/mounts/acmeca",
                        &admin,
                        json!({})
                    )
                    .status,
                    204
                );
                setup(&mut service, &admin)?;
            }
            _ => plan.deadline = std::time::Instant::now() - Duration::from_millis(1),
        }
        assert!(
            plan.check(&service).is_err(),
            "{cut} must veto before network"
        );
        assert!(
            service.finish_acme_maintenance(plan, Ok(())).is_err(),
            "{cut} must veto after network and before publication"
        );
        if cut == "authorization" {
            let invalid = order_post(&mut service, &key, &jwk, &kid, &order, None)?;
            assert_eq!(invalid.body["__heptabao_acme"]["status"], "invalid");
        }
    }
    Ok(())
}

#[test]
fn pki_acme99_http01_slow_network_cannot_refresh_attempt_deadline_or_publish_valid() -> TestResult {
    let directory = Root::new();
    let mut service = directory.service()?;
    let (_, admin) = bootstrap(&mut service)?;
    setup(&mut service, &admin)?;
    let (key, jwk) = key()?;
    let kid = order_account(&mut service, &key, &jwk)?;
    let (_, auth, challenge) = pending_http01(&mut service, &key, &jwk, &kid)?;
    assert_eq!(
        order_post(&mut service, &key, &jwk, &kid, &challenge, Some(json!({})))?.status,
        200
    );
    let mut plan = service
        .prepare_acme_maintenance(maintenance_clock(101)?)
        .map_err(|_| "prepare")?
        .ok_or("queue")?;
    plan.deadline = std::time::Instant::now() + Duration::from_millis(100);
    let listener = std::net::TcpListener::bind("127.0.0.1:0")?;
    let port = listener.local_addr()?.port();
    let proof = format!("{}.{}", plan.queued.challenge.token, plan.queued.thumbprint);
    let server = std::thread::spawn(move || -> std::io::Result<()> {
        use std::io::{Read, Write};
        let (mut socket, _) = listener.accept()?;
        socket.set_read_timeout(Some(Duration::from_secs(3)))?;
        let mut raw = Vec::new();
        let mut one = [0; 1];
        while !raw.ends_with(b"\r\n\r\n") {
            socket.read_exact(&mut one)?;
            raw.push(one[0]);
        }
        std::thread::sleep(Duration::from_millis(250));
        let _ = socket.write_all(
            format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{proof}",
                proof.len()
            )
            .as_bytes(),
        );
        Ok(())
    });
    let result = plan.execute_port(port);
    assert!(
        result.is_err(),
        "actual late network proof must fail the original deadline"
    );
    server.join().map_err(|_| "owned HTTP thread")??;
    assert!(
        service.finish_acme_maintenance(plan, result).is_err(),
        "a new finalize time cannot refresh the exhausted attempt"
    );
    let observed = order_post(&mut service, &key, &jwk, &kid, &auth, None)?;
    assert_eq!(observed.body["__heptabao_acme"]["status"], "pending");
    assert_eq!(
        observed.body["__heptabao_acme"]["challenges"][0]["status"],
        "processing"
    );
    assert!(
        observed.body["__heptabao_acme"]["challenges"][0]
            .get("validated")
            .is_none()
    );
    assert!(
        service
            .prepare_acme_maintenance(maintenance_clock(102)?)
            .map_err(|_| "prepare")?
            .is_some(),
        "durable queue can receive a fresh host attempt without resurrecting the expired one"
    );
    Ok(())
}
#[test]
fn pki_acme99_http01_namespace_delete_recreate_vetoes_original_queue_owner() -> TestResult {
    let directory = Root::new();
    let mut service = directory.service()?;
    let (_, admin) = bootstrap(&mut service)?;
    assert_eq!(
        call(
            &mut service,
            "POST",
            "sys/namespaces/challenge",
            &admin,
            json!({})
        )
        .status,
        200
    );
    let namespace = "challenge";
    let mut ns_call = |method: &str, path: &str, token: &str, body: Value| {
        service.handle_at(method, path, namespace, token, body, 100)
    };
    for (path, body, status) in [
        ("sys/mounts/acmeca", json!({"type":"pki"}), 204),
        (
            "acmeca/root/generate/internal",
            json!({"common_name":"Actual namespace CA","key_type":"ed25519","ttl":"4h"}),
            200,
        ),
        (
            "acmeca/config/cluster",
            json!({"path":"https://acme.example.test/v1/acmeca"}),
            200,
        ),
        (
            "acmeca/config/acme",
            json!({"enabled":true,"eab_policy":"not-required"}),
            200,
        ),
        (
            "sys/mounts/acmeca/tune",
            json!({"allowed_response_headers":["Replay-Nonce","Link","Location"]}),
            204,
        ),
    ] {
        assert_eq!(ns_call("POST", path, &admin, body).status, status);
    }
    let (key, jwk) = key()?;
    let base = "https://acme.example.test/v1/acmeca/acme/";
    let mut ns_post =
        |endpoint: &str, kid: Option<&str>, payload: Option<Value>| -> TestResult<Response> {
            let n = header(
                &ns_call("HEAD", "acmeca/acme/new-nonce", "", json!({})),
                "Replay-Nonce",
            )?;
            Ok(ns_call(
                "POST",
                &format!("acmeca/acme/{endpoint}"),
                "",
                signed(&key, &jwk, &n, &format!("{base}{endpoint}"), kid, payload)?,
            ))
        };
    let account = ns_post(
        "new-account",
        None,
        Some(json!({"termsOfServiceAgreed":true})),
    )?;
    assert_eq!(account.status, 201);
    let kid = header(&account, "Location")?;
    let order = ns_post(
        "new-order",
        Some(&kid),
        Some(json!({"identifiers":[{"type":"ip","value":"127.0.0.1"}]})),
    )?;
    assert_eq!(order.status, 201);
    let auth = order.body["__heptabao_acme"]["authorizations"][0]
        .as_str()
        .ok_or("auth")?
        .split("/acme/")
        .nth(1)
        .ok_or("auth route")?
        .to_owned();
    let fetched = ns_post(&auth, Some(&kid), None)?;
    let challenge = fetched.body["__heptabao_acme"]["challenges"][0]["url"]
        .as_str()
        .ok_or("challenge")?
        .split("/acme/")
        .nth(1)
        .ok_or("challenge route")?
        .to_owned();
    assert_eq!(
        ns_post(&challenge, Some(&kid), Some(json!({})))?.status,
        200
    );
    let plan = service
        .prepare_acme_maintenance(maintenance_clock(101)?)
        .map_err(|_| "prepare")?
        .ok_or("actual child queue")?;
    assert_eq!(plan.queued.owner.namespace, namespace);
    assert_eq!(
        service
            .handle_at(
                "DELETE",
                "sys/mounts/acmeca",
                namespace,
                &admin,
                json!({}),
                101
            )
            .status,
        204,
        "owned mount cleanup precedes namespace retirement"
    );
    assert_eq!(
        call(
            &mut service,
            "DELETE",
            "sys/namespaces/challenge",
            &admin,
            json!({})
        )
        .status,
        200
    );
    assert_eq!(
        call(
            &mut service,
            "POST",
            "sys/namespaces/challenge",
            &admin,
            json!({})
        )
        .status,
        200
    );
    assert!(
        plan.check(&service).is_err(),
        "same namespace string cannot renew the retired incarnation"
    );
    assert!(
        service.finish_acme_maintenance(plan, Ok(())).is_err(),
        "late network result cannot publish into the recreated namespace"
    );
    Ok(())
}

#[test]
fn pki_acme99_dns01_actual_jws_queue_encrypted_reopen_and_current_owner_proof() -> TestResult {
    let directory = Root::new();
    let mut service = directory.service()?;
    let (unseal, admin) = bootstrap(&mut service)?;
    setup(&mut service, &admin)?;
    let socket = std::net::UdpSocket::bind("127.0.0.1:0")?;
    socket.set_read_timeout(Some(Duration::from_secs(3)))?;
    let address = socket.local_addr()?;
    assert_eq!(
        call(
            &mut service,
            "POST",
            "acmeca/config/acme",
            &admin,
            json!({"dns_resolver":address.to_string()})
        )
        .status,
        200
    );
    let (key, jwk) = key()?;
    let kid = order_account(&mut service, &key, &jwk)?;
    let created = order_post(
        &mut service,
        &key,
        &jwk,
        &kid,
        "new-order",
        Some(json!({"identifiers":[{"type":"dns","value":"*.dns-proof.example"}]})),
    )?;
    assert_eq!(created.status, 201);
    let order = header(&created, "Location")?
        .split("/acme/")
        .nth(1)
        .ok_or("order route")?
        .to_owned();
    let auth = created.body["__heptabao_acme"]["authorizations"][0]
        .as_str()
        .ok_or("authorization")?
        .split("/acme/")
        .nth(1)
        .ok_or("auth route")?
        .to_owned();
    let fetched = order_post(&mut service, &key, &jwk, &kid, &auth, None)?;
    assert_eq!(fetched.body["__heptabao_acme"]["wildcard"], true);
    let challenge = fetched.body["__heptabao_acme"]["challenges"][0]["url"]
        .as_str()
        .ok_or("challenge")?
        .split("/acme/")
        .nth(1)
        .ok_or("challenge route")?
        .to_owned();
    assert!(challenge.ends_with("/dns-01"));
    assert_eq!(
        order_post(&mut service, &key, &jwk, &kid, &challenge, Some(json!({})))?.body["__heptabao_acme"]
            ["status"],
        "processing"
    );
    let original = service
        .prepare_acme_maintenance(maintenance_clock(101)?)
        .map_err(|_| "original prepare")?
        .ok_or("queued challenge")?;
    drop(service);
    let mut service = directory.service()?;
    assert_eq!(
        call(
            &mut service,
            "POST",
            "sys/unseal",
            "",
            json!({"key":unseal})
        )
        .status,
        200
    );
    assert!(original.check(&service).is_err());
    let plan = service
        .prepare_acme_maintenance(maintenance_clock(101)?)
        .map_err(|_| "reopened prepare")?
        .ok_or("reopened challenge")?;
    assert_eq!(plan.queued.challenge.kind, "dns-01");
    assert_eq!(plan.queued.host, "dns-proof.example");
    assert_eq!(plan.queued.dns_resolver, address.to_string());
    let proof = URL_SAFE_NO_PAD.encode(crate::crypto::digest(
        format!("{}.{}", plan.queued.challenge.token, plan.queued.thumbprint).as_bytes(),
    ));
    let responder = std::thread::spawn(move || -> std::io::Result<()> {
        let mut query = vec![0; 2048];
        let (n, peer) = socket.recv_from(&mut query)?;
        query.truncate(n);
        let mut response = query[..2].to_vec();
        response.extend_from_slice(&[0x81, 0x80, 0, 1, 0, 1, 0, 0, 0, 0]);
        response.extend_from_slice(&query[12..]);
        response.extend_from_slice(&[0xc0, 0x0c, 0, 16, 0, 1, 0, 0, 0, 30]);
        response.extend_from_slice(&((proof.len() + 1) as u16).to_be_bytes());
        response.push(proof.len() as u8);
        response.extend_from_slice(proof.as_bytes());
        socket.send_to(&response, peer)?;
        Ok(())
    });
    let result = plan.execute_port(80);
    responder.join().map_err(|_| "DNS responder")??;
    assert!(result.is_ok(), "{result:?}");
    service
        .finish_acme_maintenance(plan, result)
        .map_err(|_| "proof publication")?;
    assert_eq!(
        order_post(&mut service, &key, &jwk, &kid, &auth, None)?.body["__heptabao_acme"]["status"],
        "valid"
    );
    assert_eq!(
        order_post(&mut service, &key, &jwk, &kid, &order, None)?.body["__heptabao_acme"]["status"],
        "ready"
    );
    drop(service);
    let mut reopened = directory.service()?;
    assert_eq!(
        call(
            &mut reopened,
            "POST",
            "sys/unseal",
            "",
            json!({"key":unseal})
        )
        .status,
        200
    );
    assert_eq!(
        order_post(&mut reopened, &key, &jwk, &kid, &order, None)?.body["__heptabao_acme"]["status"],
        "ready"
    );
    Ok(())
}

#[path = "service_pki_acme_eab_tests.rs"]
mod eab_tests;
