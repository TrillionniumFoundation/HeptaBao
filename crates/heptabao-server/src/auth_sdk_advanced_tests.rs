use super::*;
type TestResult = std::result::Result<(), Box<dyn std::error::Error>>;

fn clock(seconds: u64, nanos: u32) -> Result<RequestClock, Box<dyn std::error::Error>> {
    Ok(RequestClock::anchored(
        std::time::Duration::new(seconds, nanos),
        std::time::Instant::now(),
    )?)
}
fn setup() -> Result<(AuthState, Binding, String), Box<dyn std::error::Error>> {
    let (mut auth, root) = AuthState::bootstrap(100)?;
    let actor = auth.authenticate(&root, 100)?;
    assert_eq!(
        auth.handle(
            Some(&actor),
            "",
            "POST",
            "sys/auth/sdk",
            &json!({"type":"plugin"}),
            100
        )?
        .ok_or("mount")?
        .status,
        204
    );
    auth.register_sdk_auth_descriptor(Descriptor {
        name: "advanced_probe".into(),
        version: "v0.0.1".into(),
        command: "probe".into(),
        args: vec!["--serve".into()],
        sha256: "a".repeat(64),
        generation: 1,
    })?;
    let descriptor = auth
        .sdk_auth_descriptor("advanced_probe", "v0.0.1")
        .ok_or("descriptor")?;
    let binding = auth.bind_sdk_auth_mount("", "sdk", &descriptor)?;
    Ok((auth, binding, root))
}
fn raw(response: &AuthResponse) -> Result<String, Box<dyn std::error::Error>> {
    Ok(response.body["auth"]["client_token"]
        .as_str()
        .ok_or("native token")?
        .to_owned())
}
fn reopen(auth: &AuthState) -> Result<AuthState, Box<dyn std::error::Error>> {
    Ok(serde_json::from_slice(
        &crate::secret_serde::to_vec(auth, 16 * 1024 * 1024)
            .map_err(|_| "synthetic Auth record encoding failed")?,
    )?)
}

#[test]
fn sdk126_periodic_renewal_keeps_fractional_anchor_and_explicit_lifetime_cap() -> TestResult {
    let (mut auth, binding, root) = setup()?;
    let first = clock(100, 125_000_000)?;
    let response = auth.finish_sdk_auth_login(
        &binding,
        "login",
        &json!({
            "alias":{"name":"alice"}, "renewable":true, "period":2_000_000_000u64,
            "explicit_max_ttl":3_500_000_000u64, "max_ttl":1_000_000_000u64,
            "metadata":{"issuer":"advanced"}
        }),
        first,
    )?;
    let bearer = raw(&response)?;
    let original = auth.tokens.get(&hash(&bearer)).ok_or("issued")?;
    let Some(TokenAuthProvenance::Sdk { origin }) = &original.auth_provenance else {
        return Err("SDK owner".into());
    };
    let issued = origin.lease.issued_at;
    assert_eq!(origin.lease.requested_period.nanoseconds(), 2_000_000_000);
    assert_eq!(
        origin.maximum,
        Some(issued.checked_add(token_precision::DurationNanos::checked(3_500_000_000)?)?)
    );
    assert_eq!(original.period, 2);
    assert!(auth.has_sdk_advanced_state());
    let renewal_clock = clock(101, 125_000_000)?;
    let actor = auth.authenticate_from_observed(
        &root,
        AuthorityTime::Precise(renewal_clock.observed_at()?),
        None,
    )?;
    let target = auth.prepare_sdk_renewal(
        &actor,
        "",
        "auth/token/renew",
        &json!({"token":bearer}),
        &root,
        renewal_clock,
    )?;
    let response = auth.finish_sdk_renewal(
        &target,
        &json!({
            "renewable":true, "period":2_000_000_000u64, "explicit_max_ttl":9_000_000_000u64,
            "lease":90_000_000_000u64, "max_ttl":1_000_000_000u64
        }),
        renewal_clock,
    )?;
    assert_eq!(raw(&response)?, bearer);
    let restored = reopen(&auth)?;
    restored.validate_sdk_auth_state()?;
    let token = restored.tokens.get(&hash(&bearer)).ok_or("renewed")?;
    let Some(TokenAuthProvenance::Sdk { origin }) = &token.auth_provenance else {
        return Err("SDK renewed owner".into());
    };
    assert_eq!(origin.lease.issued_at, issued);
    assert_eq!(
        origin.lease.requested_explicit_max.nanoseconds(),
        3_500_000_000
    );
    assert!(origin.lease.expires_at.ok_or("expiry")? <= origin.maximum.ok_or("hard cap")?);
    let expired = clock(104, 0)?;
    assert!(restored.sdk_auth_issued_live(&bearer, expired).is_err());
    Ok(())
}

#[test]
fn sdk126_period_without_explicit_max_extends_beyond_initial_backend_max_and_rejects_late_callback()
-> TestResult {
    let (mut auth, binding, root) = setup()?;
    let first = clock(100, 100_000_000)?;
    let response = auth.finish_sdk_auth_login(
        &binding,
        "login",
        &json!({
            "alias":{"name":"alice"}, "renewable":true, "period":10_000_000_000u64,
            "max_ttl":1_000_000_000u64
        }),
        first,
    )?;
    let bearer = raw(&response)?;
    assert!(
        auth.tokens
            .get(&hash(&bearer))
            .ok_or("token")?
            .max_expires_at
            .is_none()
    );
    let renewal_clock = clock(105, 100_000_000)?;
    let actor = auth.authenticate_from_observed(
        &root,
        AuthorityTime::Precise(renewal_clock.observed_at()?),
        None,
    )?;
    let target = auth.prepare_sdk_renewal(
        &actor,
        "",
        "auth/token/renew",
        &json!({"token":bearer,"increment":1000}),
        &root,
        renewal_clock,
    )?;
    let (input, _, _) = target.input(&auth, renewal_clock)?;
    assert_eq!(input["period"], json!(10_000_000_000u64));
    assert_eq!(input["explicit_max_ttl"], json!(0));
    auth.finish_sdk_renewal(
        &target,
        &json!({
            "renewable":true, "period":10_000_000_000u64, "lease":1u64, "max_ttl":1_000_000_000u64
        }),
        renewal_clock,
    )?;
    let origin = match &auth
        .tokens
        .get(&hash(&bearer))
        .ok_or("token")?
        .auth_provenance
    {
        Some(TokenAuthProvenance::Sdk { origin }) => origin,
        _ => return Err("origin".into()),
    };
    assert!(origin.maximum.is_none());
    assert!(origin.lease.expires_at.ok_or("deadline")? > Timestamp::whole(115)?);
    let before = crate::secret_serde::to_vec(&auth, 16 * 1024 * 1024)
        .map_err(|_| "synthetic Auth record encoding failed")?;
    let late = clock(111, 0)?;
    assert!(
        auth.finish_sdk_renewal(
            &target,
            &json!({"renewable":true,"period":10_000_000_000u64}),
            late
        )
        .is_err()
    );
    assert_eq!(
        crate::secret_serde::to_vec(&auth, 16 * 1024 * 1024)
            .map_err(|_| "synthetic Auth record encoding failed")?,
        before
    );
    reopen(&auth)?.validate_sdk_auth_state()?;
    Ok(())
}

#[test]
fn sdk126_batch_sealing_requires_entity_and_keeps_authenticated_cidr_namespace_and_issuer()
-> TestResult {
    let (mut auth, binding, _) = setup()?;
    let at = clock(100, 100_000_000)?;
    let payload = json!({
        "alias":{"name":"alice"}, "lease":5_000_000_000u64, "token_type":2,
        "bound_cidrs":["127.0.0.0/8"], "metadata":{"source":"SDK"}
    });
    let tokens_before = auth.tokens.len();
    let mut unbound = auth.finish_sdk_auth_login(&binding, "login", &payload, at)?;
    assert!(unbound.body["auth"].get("client_token").is_none());
    assert!(
        auth.finish_pending_batch_observed(
            &mut unbound,
            "",
            100,
            AuthorityTime::Precise(at.observed_at()?)
        )
        .is_err()
    );
    assert!(auth.batch_authority.is_none());
    assert_eq!(auth.tokens.len(), tokens_before);
    let mut response = auth.finish_sdk_auth_login(&binding, "login", &payload, at)?;
    auth.bind_issued_entity(
        &mut response,
        "",
        "sdk",
        "e-00000000000000000000000000000001",
    )?;
    auth.finish_pending_batch_observed(
        &mut response,
        "",
        100,
        AuthorityTime::Precise(at.observed_at()?),
    )?;
    let bearer = raw(&response)?;
    assert!(bearer.starts_with("hvb."));
    assert_eq!(response.body["auth"]["renewable"], json!(false));
    assert_eq!(response.body["auth"]["accessor"], json!(""));
    assert_eq!(auth.tokens.len(), tokens_before);
    let mut restored = reopen(&auth)?;
    let peer = "127.0.0.1".parse()?;
    let actor = restored.authenticate_from_observed(
        &bearer,
        AuthorityTime::Precise(at.observed_at()?),
        Some(peer),
    )?;
    let issuer = restored
        .admitted_standard_sdk_lease_issuer_observed(
            &actor,
            "",
            AuthorityTime::Precise(at.observed_at()?),
        )?
        .ok_or("actual issuer")?;
    assert!(issuer.issuer.owner.batch_claims().is_some());
    let wire = serde_json::to_value(&issuer.issuer.owner)?;
    assert!(wire.get("sdk_issuer").is_some());
    assert!(
        restored
            .resolve_lease_owner_observed(
                &issuer.issuer.owner,
                "",
                AuthorityTime::Precise(at.observed_at()?)
            )
            .is_some()
    );
    assert!(
        restored
            .authenticate_from_observed(
                &bearer,
                AuthorityTime::Precise(at.observed_at()?),
                Some("192.0.2.1".parse()?)
            )
            .is_err()
    );
    assert!(
        restored
            .resolve_lease_owner_observed(
                &issuer.issuer.owner,
                "other",
                AuthorityTime::Precise(at.observed_at()?)
            )
            .is_none()
    );
    let mut changed = bearer.into_bytes();
    let last = changed.len() - 1;
    changed[last] = if changed[last] == b'A' { b'B' } else { b'A' };
    assert!(
        restored
            .sdk_auth_issued_live(std::str::from_utf8(&changed)?, at)
            .is_err()
    );
    restored.disable_auth_mount(AuthScope {
        namespace: "",
        mount: "sdk",
    });
    assert!(
        restored
            .resolve_lease_owner_observed(
                &issuer.issuer.owner,
                "",
                AuthorityTime::Precise(at.observed_at()?)
            )
            .is_none()
    );
    assert!(restored.has_sdk_advanced_state());
    restored.validate_sdk_advanced_state(Some(&auth))?;
    Ok(())
}

#[test]
fn sdk126_group_aliases_use_actual_mount_and_sdk_service_cidr_keeps_native_admission() -> TestResult
{
    let (mut auth, binding, _) = setup()?;
    let at = clock(100, 0)?;
    let response = auth.finish_sdk_auth_login(&binding, "login", &json!({
        "alias":{"name":"alice"}, "lease":1_000_000_000u64,
        "group_aliases":[{"name":"operators","mount_accessor":"foreign","namespace_id":"foreign"}],
        "bound_cidrs":["127.0.0.1"],
        "internal_data":{"$serde_json::private::Number":"7"}
    }), at)?;
    let groups = response
        .external_groups
        .as_ref()
        .ok_or("native group projection")?;
    assert_eq!(groups.mount, "sdk");
    assert_eq!(groups.alias, "alice");
    assert_eq!(groups.names, BTreeSet::from(["operators".to_owned()]));
    let bearer = raw(&response)?;
    let restored = reopen(&auth)?;
    restored.validate_sdk_auth_state()?;
    assert!(
        restored
            .authenticate_from_observed(
                &bearer,
                AuthorityTime::Precise(at.observed_at()?),
                Some("127.0.0.1".parse()?)
            )
            .is_ok()
    );
    assert!(
        restored
            .authenticate_from_observed(
                &bearer,
                AuthorityTime::Precise(at.observed_at()?),
                Some("127.0.0.2".parse()?)
            )
            .is_err()
    );
    assert!(
        restored
            .authenticate_from_observed(&bearer, AuthorityTime::Precise(at.observed_at()?), None)
            .is_err()
    );
    let token = restored.tokens.get(&hash(&bearer)).ok_or("saved token")?;
    let Some(TokenAuthProvenance::Sdk { origin }) = &token.auth_provenance else {
        return Err("SDK".into());
    };
    assert!(origin.internal_data["$serde_json::private::Number"].is_string());
    let mut torn = serde_json::to_value(&restored)?;
    torn.as_object_mut()
        .ok_or("auth object")?
        .remove("sdk_advanced_format");
    let torn: AuthState = serde_json::from_slice(&serde_json::to_vec(&torn)?)?;
    assert!(torn.validate_sdk_advanced_state(None).is_err());
    let mut retired = restored.clone();
    retired.tokens.remove(&hash(&bearer));
    retired.validate_sdk_advanced_state(Some(&restored))?;
    assert!(retired.has_sdk_advanced_state());
    Ok(())
}

#[test]
fn sdk126_closed_invalid_advanced_fields_and_ordinary_wire_shape_preserve_native_owner()
-> TestResult {
    let (mut auth, binding, _) = setup()?;
    let at = clock(100, 100_000_000)?;
    let before = crate::secret_serde::to_vec(&auth, 16 * 1024 * 1024)
        .map_err(|_| "synthetic Auth record encoding failed")?;
    for invalid in [
        json!({"period":-1}),
        json!({"explicit_max_ttl":"2s"}),
        json!({"token_type":5}),
        json!({"token_type":2,"period":1}),
        json!({"token_type":2,"num_uses":1}),
        json!({"bound_cidrs":["not-an-IP"]}),
        json!({"bound_cidrs":{}}),
        json!({"group_aliases":[{}]}),
        json!({"group_aliases":[{"name":"bad\nname"}]}),
        json!({"external_namespace_policies":{"foreign":["root"]}}),
        json!({"mfa_requirement":{"mfa_request_id":"foreign"}}),
    ] {
        let mut payload = json!({"alias":{"name":"alice"},"lease":1_000_000_000u64});
        payload
            .as_object_mut()
            .ok_or("payload")?
            .extend(invalid.as_object().ok_or("invalid")?.clone());
        assert!(
            auth.finish_sdk_auth_login(&binding, "login", &payload, at)
                .is_err()
        );
        assert_eq!(
            crate::secret_serde::to_vec(&auth, 16 * 1024 * 1024)
                .map_err(|_| "synthetic Auth record encoding failed")?,
            before
        );
    }
    let ordinary = auth.finish_sdk_auth_login(
        &binding,
        "login",
        &json!({"alias":{"name":"alice"},"lease":1_000_000_000u64}),
        at,
    )?;
    let token = auth.tokens.get(&hash(&raw(&ordinary)?)).ok_or("ordinary")?;
    let value = serde_json::to_value(token)?;
    assert!(value["auth_provenance"]["origin"].get("advanced").is_none());
    assert!(value["auth_provenance"]["origin"]["maximum"].is_object());
    assert!(!auth.has_sdk_advanced_state());
    reopen(&auth)?.validate_sdk_auth_state()?;
    Ok(())
}

#[test]
fn sdk126_wrapped_sdk_auth_preserves_inner_native_issuer_and_one_use_durable_reply() -> TestResult {
    let (mut auth, binding, _) = setup()?;
    let at = clock(100, 100_000_000)?;
    let response = auth.finish_sdk_auth_login(
        &binding,
        "login",
        &json!({"alias":{"name":"alice"},"lease":5_000_000_000u64}),
        at,
    )?;
    let issuer = raw(&response)?;
    let _ingress = crate::auth::IngressReplyScope::listener(&[0xA6; 16]);
    let context = crate::auth::current_ingress().ok_or("original ingress")?;
    let wrapped =
        auth.wrap_sdk_response("", "auth/sdk/login", 2, &response.body, 100, Some(&context))?;
    auth.mark_sdk_advanced_state();
    let wrapper = wrapped.body["wrap_info"]["token"]
        .as_str()
        .ok_or("wrapper")?;
    assert_ne!(wrapper, issuer);
    assert!(wrapped.body["auth"].is_null());
    let mut restored = reopen(&auth)?;
    let mut torn = serde_json::to_value(&restored)?;
    torn.as_object_mut()
        .ok_or("saved Auth")?
        .remove("sdk_advanced_format");
    let torn: AuthState = serde_json::from_slice(&serde_json::to_vec(&torn)?)?;
    assert!(torn.validate_sdk_advanced_state(None).is_err());
    assert_eq!(
        restored.sdk_wrapped_auth_token(
            wrapper,
            "",
            "auth/sdk/login",
            AuthorityTime::Precise(at.observed_at()?)
        )?,
        Some(issuer.as_str())
    );
    assert!(
        restored
            .sdk_wrapped_auth_token(
                wrapper,
                "",
                "auth/foreign/login",
                AuthorityTime::Precise(at.observed_at()?)
            )
            .is_err()
    );
    let actor = restored.authenticate_from_observed(
        wrapper,
        AuthorityTime::Precise(at.observed_at()?),
        None,
    )?;
    let unwrapped = restored
        .handle(
            Some(&actor),
            "",
            "POST",
            "sys/wrapping/unwrap",
            &json!({}),
            100,
        )?
        .ok_or("unwrap")?;
    assert_eq!(unwrapped.body["auth"]["client_token"], json!(issuer));
    assert!(
        restored
            .authenticate_from_observed(wrapper, AuthorityTime::Precise(at.observed_at()?), None)
            .is_err()
    );
    assert!(restored.has_sdk_advanced_state());
    restored.validate_sdk_advanced_state(Some(&auth))?;
    Ok(())
}
