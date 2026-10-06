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
