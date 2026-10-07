use super::*;

const BASE: &str = "https://acme.example.test/v1/acmeca/acme/";
fn binding(entry: &Value, jwk: &Value, alg: &str) -> TestResult<Value> {
    let protected = URL_SAFE_NO_PAD.encode(serde_json::to_vec(
        &json!({"alg":alg,"kid":entry["id"],"url":format!("{BASE}new-account")}),
    )?);
    let payload = URL_SAFE_NO_PAD.encode(serde_json::to_vec(jwk)?);
    let private =
        zeroize::Zeroizing::new(URL_SAFE_NO_PAD.decode(entry["key"].as_str().ok_or("key")?)?);
    let key = PKey::hmac(&private)?;
    let digest = match alg {
        "HS384" => MessageDigest::sha384(),
        "HS512" => MessageDigest::sha512(),
        _ => MessageDigest::sha256(),
    };
    let mut signer = Signer::new(digest, &key)?;
    signer.update(format!("{protected}.{payload}").as_bytes())?;
    Ok(
        json!({"protected":protected,"payload":payload,"signature":URL_SAFE_NO_PAD.encode(signer.sign_to_vec()?)}),
    )
}
fn create(service: &mut Service, admin: &str) -> TestResult<Value> {
    let response = call(service, "POST", "acmeca/acme/new-eab", admin, json!({}));
    assert_eq!(
        response.status,
        200,
        "only static errors: {:?}",
        response.body.get("errors")
    );
    Ok(response.body["data"].clone())
}
fn account(
    service: &mut Service,
    key: &PKey<Private>,
    jwk: &Value,
    eab: Option<Value>,
) -> TestResult<Response> {
    let n = nonce(service)?;
    let mut payload = json!({"termsOfServiceAgreed":true});
    if let Some(eab) = eab {
        payload["externalAccountBinding"] = eab;
    }
    Ok(call(
        service,
        "POST",
        "acmeca/acme/new-account",
        "",
        signed(
            key,
            jwk,
            &n,
            &format!("{BASE}new-account"),
            None,
            Some(payload),
        )?,
    ))
}
#[test]
fn pki_acme99_eab_admin_acl_one_use_encrypted_reopen_and_consumption_floor() -> TestResult {
    let directory = Root::new();
    let mut service = directory.service()?;
    let (unseal, admin) = bootstrap(&mut service)?;
    setup(&mut service, &admin)?;
    assert_eq!(
        call(&mut service, "POST", "acmeca/acme/new-eab", "", json!({})).status,
        403
    );
    assert_eq!(
        call(&mut service, "LIST", "acmeca/eab", "", json!({})).status,
        403
    );
    let entry = create(&mut service, &admin)?;
    let encoded = entry["key"].as_str().ok_or("key")?;
    assert!(encoded.starts_with("vault-eab-0-"));
    assert_eq!(URL_SAFE_NO_PAD.decode(encoded)?.len(), 41);
    let before = service.state.as_ref().ok_or("state")?.clone();
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
    let list = call(&mut service, "LIST", "acmeca/eab", &admin, json!({}));
    assert_eq!(list.status, 200);
    assert_eq!(list.body["data"]["keys"], json!([entry["id"]]));
    let (key, jwk) = super::key()?;
    let proof = binding(&entry, &jwk, "HS256")?;
    let response = account(&mut service, &key, &jwk, Some(proof.clone()))?;
    assert_eq!(response.status, 201);
    assert_eq!(
        response.body["__heptabao_acme"]["externalAccountBinding"],
        proof
    );
    assert_eq!(
        call(&mut service, "LIST", "acmeca/eab", &admin, json!({})).status,
        404
    );
    let current = service.state.as_ref().ok_or("state")?;
    assert!(Service::validate_snapshot_protected_floor(current, &before).is_err());
    assert!(
        before
            .engines
            .validate_acme_successor(Some(&current.engines), |_| false)
            .is_err()
    );
    let consumed = current.clone();
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
    let (other, other_jwk) = super::key()?;
    let replay = account(
        &mut service,
        &other,
        &other_jwk,
        Some(binding(&entry, &other_jwk, "HS256")?),
    )?;
    assert_eq!(replay.status, 401);
    assert_eq!(
        replay.body["__heptabao_acme"]["detail"],
        "the client lacks sufficient authorization: failed to verify eab"
    );
    assert!(
        service
            .state
            .as_ref()
            .ok_or("state")?
            .engines
            .validate_acme_successor(Some(&consumed.engines), |_| false)
            .is_ok()
    );
    Ok(())
}
#[test]
fn pki_acme99_eab_real_mac_exact_jwk_bytes_and_native_short_key_errors() -> TestResult {
    let directory = Root::new();
    let mut service = directory.service()?;
    let (_, admin) = bootstrap(&mut service)?;
    setup(&mut service, &admin)?;
    let entry = create(&mut service, &admin)?;
    let (key, jwk) = super::key()?;
    let mut wrong = binding(&entry, &jwk, "HS256")?;
    let mut signature = URL_SAFE_NO_PAD.decode(wrong["signature"].as_str().ok_or("sig")?)?;
    signature[0] ^= 1;
    wrong["signature"] = json!(URL_SAFE_NO_PAD.encode(signature));
    assert_eq!(account(&mut service, &key, &jwk, Some(wrong))?.status, 500);
    for alg in ["HS384", "HS512"] {
        let row = account(&mut service, &key, &jwk, Some(binding(&entry, &jwk, alg)?))?;
        assert_eq!(row.status, 500);
        assert_eq!(
            row.body["__heptabao_acme"]["detail"],
            "go-jose/go-jose: error in cryptographic primitive"
        );
    }
    let mut different = binding(&entry, &jwk, "HS256")?;
    // Correctly MAC a different raw serialization of the same public JWK.
    let raw = serde_json::to_string_pretty(&jwk)?;
    let payload = URL_SAFE_NO_PAD.encode(raw);
    different["payload"] = json!(payload);
    let private =
        zeroize::Zeroizing::new(URL_SAFE_NO_PAD.decode(entry["key"].as_str().ok_or("key")?)?);
    let hmac = PKey::hmac(&private)?;
    let mut signer = Signer::new(MessageDigest::sha256(), &hmac)?;
    signer.update(
        format!(
            "{}.{}",
            different["protected"].as_str().ok_or("protected")?,
            payload
        )
        .as_bytes(),
    )?;
    different["signature"] = json!(URL_SAFE_NO_PAD.encode(signer.sign_to_vec()?));
    assert_eq!(
        account(&mut service, &key, &jwk, Some(different))?.status,
        400
    );
    assert_eq!(
        account(
            &mut service,
            &key,
            &jwk,
            Some(binding(&entry, &jwk, "HS256")?)
        )?
        .status,
        201
    );
    Ok(())
}
#[test]
fn pki_acme99_eab_existing_new_and_always_policies_use_actual_bound_account() -> TestResult {
    let directory = Root::new();
    let mut service = directory.service()?;
    let (_, admin) = bootstrap(&mut service)?;
    setup(&mut service, &admin)?;
    let (key, jwk) = super::key()?;
    let response = account(&mut service, &key, &jwk, None)?;
    assert_eq!(response.status, 201);
    let kid = header(&response, "Location")?;
    let path = format!(
        "acmeca/acme/account/{}",
        kid.rsplit('/').next().ok_or("id")?
    );
    for (policy, expected) in [("new-account-required", 200), ("always-required", 401)] {
        assert_eq!(
            call(
                &mut service,
                "POST",
                "acmeca/config/acme",
                &admin,
                json!({"eab_policy":policy})
            )
            .status,
            200
        );
        let n = nonce(&mut service)?;
        assert_eq!(
            call(
                &mut service,
                "POST",
                &path,
                "",
                signed(&key, &jwk, &n, &kid, Some(&kid), None)?
            )
            .status,
            expected
        );
    }
    let (other, other_jwk) = super::key()?;
    let missing = account(&mut service, &other, &other_jwk, None)?;
    assert_eq!(missing.status, 401);
    assert_eq!(
        missing.body["__heptabao_acme"]["type"],
        "urn:ietf:params:acme:error:externalAccountRequired"
    );
    let entry = create(&mut service, &admin)?;
    assert_eq!(
        account(
            &mut service,
            &other,
            &other_jwk,
            Some(binding(&entry, &other_jwk, "HS256")?)
        )?
        .status,
        201
    );
    let mut wrong = binding(&entry, &other_jwk, "HS256")?;
    wrong["signature"] = json!("invalid");
    assert_eq!(
        account(&mut service, &other, &other_jwk, Some(wrong))?.status,
        200
    );
    Ok(())
}
#[test]
fn pki_acme99_eab_delete_cannot_resurrect_key_or_replace_durable_owner() -> TestResult {
    let directory = Root::new();
    let mut service = directory.service()?;
    let (_, admin) = bootstrap(&mut service)?;
    setup(&mut service, &admin)?;
    let entry = create(&mut service, &admin)?;
    let id = entry["id"].as_str().ok_or("id")?;
    let old = service.state.as_ref().ok_or("state")?.clone();
    assert_eq!(
        call(
            &mut service,
            "DELETE",
            &format!("acmeca/eab/{id}"),
            &admin,
            json!({})
        )
        .status,
        200
    );
    let repeated = call(
        &mut service,
        "DELETE",
        &format!("acmeca/eab/{id}"),
        &admin,
        json!({}),
    );
    assert_eq!(repeated.status, 200);
    assert_eq!(
        repeated.body["warnings"],
        json!([format!("No key id found with id: {id}")])
    );
    let current = service.state.as_ref().ok_or("state")?;
    assert!(
        old.engines
            .validate_acme_successor(Some(&current.engines), |_| false)
            .is_err()
    );
    let (key, jwk) = super::key()?;
    assert_eq!(
        account(
            &mut service,
            &key,
            &jwk,
            Some(binding(&entry, &jwk, "HS256")?)
        )?
        .status,
        401
    );
    Ok(())
}

fn operator_delivery_cut(expire: bool, wrapped: bool) -> TestResult {
    let directory = Root::new();
    let mut service = directory.service()?;
    let (_, admin) = bootstrap(&mut service)?;
    setup(&mut service, &admin)?;
    assert_eq!(
        call(
            &mut service,
            "PUT",
            "sys/policies/acl/eab-admin",
            &admin,
            json!({"policy":r#"path "acmeca/acme/new-eab" { capabilities=["update"] }"#})
        )
        .status,
        204
    );
    let state = service.state.as_ref().ok_or("state")?;
    let at = state
        .auth
        .terminal_token_clock_floor()
        .map_or(101, |at| at.seconds() + 1);
    let issue_clock =
        RequestClock::anchored(Duration::new(at, 250_000_000), std::time::Instant::now())?;
    fn dispatch<'a>(at: u64, path: &'a str, token: &'a str, body: Value) -> RequestDispatch<'a> {
        RequestDispatch {
            method: "POST",
            path,
            namespace: "",
            token,
            body,
            now: at,
            allow_forward: true,
            enforce_namespace: false,
            wrap_ttl_seconds: None,
            origin_peer: None,
            client_certificates: None,
        }
    }
    let execution = service.begin_at_mode_precise(
        dispatch(
            at,
            "auth/token/create",
            &admin,
            json!({"ttl":"2s","policies":["eab-admin"],"no_default_policy":true}),
        ),
        issue_clock,
    );
    let response = service.finish_synchronous_request(execution);
    assert_eq!(response.status, 200);
    let actor = response.body["auth"]["client_token"]
        .as_str()
        .ok_or("actor")?
        .to_owned();
    let original =
        RequestClock::anchored(Duration::new(at, 500_000_000), std::time::Instant::now())?;
    let body = json!({});
    let response = service.handle_inner(RequestView {
        method: "POST",
        path: "acmeca/acme/new-eab",
        namespace: "",
        token: &actor,
        body: &body,
        now: at,
        admission_started: original.started(),
        token_clock: Some(original),
        allow_forward: true,
        enforce_namespace: false,
        wrap_ttl_seconds: wrapped.then_some(120),
        origin_peer: None,
        client_certificates: None,
    });
    assert_eq!(response.status, 200);
    if wrapped {
        assert!(response.body["data"].is_null());
        assert!(response.body["wrap_info"]["token"].as_str().is_some());
    } else {
        assert!(response.body["data"]["key"].as_str().is_some());
    }
    let response = service.audit_completed_response_with_receipt(
        "actual-eab-operator-delivery-cut",
        at,
        Some(original),
        response,
        || {},
    );
    assert_eq!(
        response.status, 200,
        "actual response audit before delivery cut"
    );
    let held = service
        .pending_acme_authority
        .take()
        .ok_or("original EAB operator capsule")?;
    if expire {
        std::thread::sleep(Duration::from_millis(2100));
    } else {
        let execution = service.begin_at_mode_precise(
            dispatch(at, "auth/token/revoke", &admin, json!({"token":actor})),
            original,
        );
        let revoked = service.finish_synchronous_request(execution);
        assert_eq!(
            revoked.status,
            204,
            "only static errors: {:?}",
            revoked.body.get("errors")
        );
    }
    service.pending_acme_authority = Some(held);
    let delivered =
        service.complete_pending_acme_delivery(true, response, "actual-eab-operator-delivery-cut");
    assert_eq!(delivered.status, 403);
    assert!(delivered.body.get("data").is_none());
    assert!(delivered.body.get("wrap_info").is_none());
    assert!(delivered.response_headers.is_empty());
    assert!(delivered.consistency_index.is_none());
    Ok(())
}
#[test]
fn pki_acme99_eab_real_original_operator_revocation_withholds_new_private_key() -> TestResult {
    operator_delivery_cut(false, false)
}
#[test]
fn pki_acme99_eab_real_original_operator_precise_expiry_after_2100ms_withholds_private_key()
-> TestResult {
    operator_delivery_cut(true, false)
}

#[test]
fn pki_acme99_eab_wrapping_original_operator_revocation_withholds_wrapper() -> TestResult {
    operator_delivery_cut(false, true)
}

#[test]
fn pki_acme99_eab_wrapping_original_operator_precise_expiry_withholds_wrapper() -> TestResult {
    operator_delivery_cut(true, true)
}

#[test]
fn pki_acme99_eab_wrapping_real_original_creation_clock_reopen_and_one_use() -> TestResult {
    let directory = Root::new();
    let mut service = directory.service()?;
    let (unseal, admin) = bootstrap(&mut service)?;
    setup(&mut service, &admin)?;
    let state = service.state.as_ref().ok_or("actual EAB state")?;
    let at = state
        .auth
        .terminal_token_clock_floor()
        .map_or(101, |at| at.seconds() + 1);
    let wall = Duration::new(at, 250_000_000);
    let started = std::time::Instant::now();
    let original = RequestClock::anchored(wall, started)?;
    let before = original.observed_at()?.duration_since_epoch();
    let response = {
        // Match the trusted ingress scope. No body value selects this anchor.
        let _origin = external_pki::PublicationClockScope::enter(wall, started);
        let execution = service.begin_at_mode_precise(
            RequestDispatch {
                method: "POST",
                path: "acmeca/acme/new-eab",
                namespace: "",
                token: &admin,
                body: json!({}),
                now: at,
                allow_forward: true,
                enforce_namespace: false,
                wrap_ttl_seconds: Some(120),
                origin_peer: None,
                client_certificates: None,
            },
            original,
        );
        service.finish_synchronous_request(execution)
    };
    let after = original.observed_at()?.duration_since_epoch();
    assert_eq!(
        response.status,
        200,
        "only static EAB wrapping errors: {:?}",
        response.body.get("errors")
    );
    assert!(response.body["data"].is_null());
    assert!(response.body["auth"].is_null());
    assert_eq!(response.body["wrap_info"]["ttl"], 120);
    assert_eq!(
        response.body["wrap_info"]["creation_path"],
        "acmeca/acme/new-eab"
    );
    let creation = chrono::DateTime::parse_from_rfc3339(
        response.body["wrap_info"]["creation_time"]
            .as_str()
            .ok_or("actual wrapper creation time")?,
    )?;
    let creation = Duration::new(
        u64::try_from(creation.timestamp())?,
        creation.timestamp_subsec_nanos(),
    );
    assert!(
        before <= creation && creation <= after,
        "creation derives from original trusted ingress bounds"
    );
    let bearer = zeroize::Zeroizing::new(
        response.body["wrap_info"]["token"]
            .as_str()
            .ok_or("private EAB wrapper")?
            .to_owned(),
    );
    drop(response);
    let lookup = call(
        &mut service,
        "POST",
        "sys/wrapping/lookup",
        &admin,
        json!({"token":bearer.as_str()}),
    );
    assert_eq!(lookup.status, 200);
    assert_eq!(lookup.body["data"]["creation_ttl"], 120);
    assert_eq!(lookup.body["data"]["creation_path"], "acmeca/acme/new-eab");
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
    let mut unwrapped = call(
        &mut reopened,
        "POST",
        "sys/wrapping/unwrap",
        &admin,
        json!({"token":bearer.as_str()}),
    );
    assert_eq!(unwrapped.status, 200);
    assert!(unwrapped.body["data"]["key"].as_str().is_some());
    assert_eq!(
        call(
            &mut reopened,
            "POST",
            "sys/wrapping/unwrap",
            &admin,
            json!({"token":bearer.as_str()})
        )
        .status,
        400
    );
    let (key, jwk) = super::key()?;
    let proof = binding(&unwrapped.body["data"], &jwk, "HS256")?;
    assert_eq!(account(&mut reopened, &key, &jwk, Some(proof))?.status, 201);
    erase_json(&mut unwrapped.body);
    Ok(())
}

#[test]
fn pki_acme99_eab_wrapping_original_clock_expiry_before_delivery_withholds_bearer() -> TestResult {
    let directory = Root::new();
    let mut service = directory.service()?;
    let (_, admin) = bootstrap(&mut service)?;
    setup(&mut service, &admin)?;
    let state = service.state.as_ref().ok_or("actual EAB state")?;
    let at = state
        .auth
        .terminal_token_clock_floor()
        .map_or(101, |at| at.seconds() + 1);
    let original =
        RequestClock::anchored(Duration::new(at, 250_000_000), std::time::Instant::now())?;
    let body = json!({});
    let response = service.handle_inner(RequestView {
        method: "POST",
        path: "acmeca/acme/new-eab",
        namespace: "",
        token: &admin,
        body: &body,
        now: at,
        admission_started: original.started(),
        token_clock: Some(original),
        allow_forward: true,
        enforce_namespace: false,
        wrap_ttl_seconds: Some(1),
        origin_peer: None,
        client_certificates: None,
    });
    assert_eq!(response.status, 200);
    assert!(response.body["wrap_info"]["token"].as_str().is_some());
    let response = service.audit_completed_response_with_receipt(
        "actual-eab-wrapper-expiry",
        at,
        Some(original),
        response,
        || {},
    );
    assert_eq!(response.status, 200);
    std::thread::sleep(Duration::from_millis(1100));
    let delivered =
        service.complete_pending_acme_delivery(true, response, "actual-eab-wrapper-expiry");
    assert_eq!(delivered.status, 403);
    assert!(delivered.body.get("data").is_none());
    assert!(delivered.body.get("wrap_info").is_none());
    assert!(delivered.response_headers.is_empty());
    assert!(delivered.consistency_index.is_none());
    Ok(())
}
