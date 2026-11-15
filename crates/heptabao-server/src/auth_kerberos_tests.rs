#![allow(clippy::unwrap_used, clippy::expect_used)]
use super::*;

const AUTHORIZATION: &str = "Negotiate YWxpY2VAYm91bmRhcnk=";

fn config() -> Value {
    json!({
        "service_account": "HTTP/heptabao.test@HBKRB.TEST",
        "realm": "HBKRB.TEST",
        "service": "HTTP",
        "keytab_path": "/tmp/heptabao-kerberos-test.keytab",
        "token_policies": ["default"],
        "token_ttl": 120,
        "token_max_ttl": 600,
        "clock_skew_seconds": 60
    })
}

fn configured() -> (AuthState, String, Principal) {
    let (mut state, raw, root) = setup();
    call(
        &mut state,
        &root,
        "",
        "POST",
        "sys/auth/kerberos",
        json!({"type":"kerberos"}),
        100,
    );
    call(
        &mut state,
        &root,
        "",
        "POST",
        "auth/kerberos/config",
        config(),
        100,
    );
    (state, raw, root)
}

fn observation(expires_at: u64) -> KerberosLoginObservation {
    KerberosLoginObservation::for_test(
        "alice@HBKRB.TEST",
        "HBKRB.TEST",
        "HTTP/heptabao.test@HBKRB.TEST",
        expires_at,
    )
}

fn login_plan(state: &AuthState, now: u64) -> KerberosLoginPlan {
    state
        .prepare_kerberos_login(
            "",
            "kerberos",
            "POST",
            &json!({"kerberos_authorization": AUTHORIZATION}),
            now,
        )
        .unwrap()
}

#[test]
fn kerberos_config_is_bounded_and_readback_redacts_keytab_location() {
    let (mut state, _raw, root) = configured();
    let readback = call(
        &mut state,
        &root,
        "",
        "GET",
        "auth/kerberos/config",
        json!({}),
        101,
    );
    assert_eq!(readback.body["data"]["realm"], "HBKRB.TEST");
    assert_eq!(
        readback.body["data"]["service_account"],
        "HTTP/heptabao.test@HBKRB.TEST"
    );
    assert_eq!(readback.body["data"]["clock_skew_seconds"], 60);
    assert!(readback.body["data"].get("keytab_path").is_none());

    assert!(
        state
            .handle(
                Some(&root),
                "",
                "POST",
                "auth/kerberos/config",
                &json!({"clock_skew_seconds":301}),
                101,
            )
            .is_err()
    );
    assert!(
        state
            .handle(
                Some(&root),
                "",
                "POST",
                "auth/kerberos/config",
                &json!({"realm":"OTHER.TEST"}),
                101,
            )
            .is_err()
    );
}

#[test]
fn kerberos_login_result_binds_provider_identity_and_revisions() {
    let (mut state, _raw, _root) = configured();
    let response = state
        .finish_kerberos_login(login_plan(&state, 100), observation(200))
        .unwrap();
    let metadata = &response.body["auth"]["metadata"];
    assert_eq!(metadata["principal"], "alice@HBKRB.TEST");
    assert_eq!(metadata["realm"], "HBKRB.TEST");
    assert_eq!(metadata["service"], "HTTP/heptabao.test@HBKRB.TEST");
    assert_eq!(metadata["provider"], "cross-krb5:gssapi-krb5");
    assert_eq!(metadata["mount_revision"], 1);
    assert_eq!(metadata["config_revision"].as_str().unwrap().len(), 43);

    let raw = response.body["auth"]["client_token"].as_str().unwrap();
    let provenance = state
        .tokens
        .get(&hash(raw))
        .unwrap()
        .auth_provenance
        .as_ref();
    assert!(matches!(
        provenance,
        Some(TokenAuthProvenance::Kerberos { .. })
    ));
    if let Some(TokenAuthProvenance::Kerberos {
        provider,
        service_account,
        realm,
        service,
        mount_revision,
        config_revision,
    }) = provenance
    {
        assert_eq!(provider, "cross-krb5:gssapi-krb5");
        assert_eq!(service_account, "HTTP/heptabao.test@HBKRB.TEST");
        assert_eq!(realm, "HBKRB.TEST");
        assert_eq!(service, "HTTP");
        assert_eq!(*mount_revision, 1);
        assert_eq!(
            config_revision,
            metadata["config_revision"].as_str().unwrap()
        );
    }
}

#[test]
fn kerberos_malformed_authorization_and_stale_config_fail_before_issue() {
    let (mut state, _raw, _root) = configured();
    for authorization in ["Bearer token", "Negotiate", "Negotiate !!!"] {
        let error = state
            .prepare_kerberos_login(
                "",
                "kerberos",
                "POST",
                &json!({"kerberos_authorization": authorization}),
                100,
            )
            .err()
            .unwrap();
        assert_eq!(error.status, 400, "{authorization}");
    }
    let plan = login_plan(&state, 100);
    state
        .handle(
            Some(&_root),
            "",
            "PUT",
            "auth/kerberos/config",
            &json!({
                "service":"HTTPS",
                "service_account":"HTTPS/heptabao.test@HBKRB.TEST"
            }),
            101,
        )
        .unwrap()
        .unwrap();
    let error = state
        .finish_kerberos_login(plan, observation(200))
        .err()
        .unwrap();
    assert_eq!(error.status, 409);
    assert_eq!(state.tokens.len(), 1, "root token only");
}

#[test]
fn kerberos_mount_disable_and_recreate_revokes_old_login_tokens() {
    let (mut state, _raw, root) = configured();
    let response = state
        .finish_kerberos_login(login_plan(&state, 100), observation(200))
        .unwrap();
    let raw = response.body["auth"]["client_token"]
        .as_str()
        .unwrap()
        .to_owned();
    assert!(state.authenticate(&raw, 101).is_ok());

    call(
        &mut state,
        &root,
        "",
        "DELETE",
        "sys/auth/kerberos",
        json!({}),
        101,
    );
    mount_auth(&mut state, &root, "", "kerberos", "kerberos");
    call(
        &mut state,
        &root,
        "",
        "POST",
        "auth/kerberos/config",
        config(),
        101,
    );
    assert!(state.authenticate(&raw, 102).is_err());
}

#[test]
fn kerberos_binds_namespace_and_mount_incarnation() {
    let (mut state, _raw, root) = configured();
    mount_auth(&mut state, &root, "team", "kerberos", "kerberos");
    call(
        &mut state,
        &root,
        "team",
        "POST",
        "auth/kerberos/config",
        config(),
        100,
    );
    assert!(
        state
            .prepare_kerberos_login(
                "other",
                "kerberos",
                "POST",
                &json!({"kerberos_authorization": AUTHORIZATION}),
                100,
            )
            .is_err()
    );
    assert!(
        state
            .prepare_kerberos_login(
                "team",
                "kerberos",
                "POST",
                &json!({"kerberos_authorization": AUTHORIZATION}),
                100,
            )
            .is_ok()
    );

    let plan = state
        .prepare_kerberos_login(
            "team",
            "kerberos",
            "POST",
            &json!({"kerberos_authorization": AUTHORIZATION}),
            100,
        )
        .unwrap();
    call(
        &mut state,
        &root,
        "team",
        "DELETE",
        "sys/auth/kerberos",
        json!({}),
        101,
    );
    mount_auth(&mut state, &root, "team", "kerberos", "kerberos");
    call(
        &mut state,
        &root,
        "team",
        "POST",
        "auth/kerberos/config",
        config(),
        101,
    );
    let error = state
        .finish_kerberos_login(plan, observation(200))
        .err()
        .unwrap();
    assert_eq!(error.status, 409);
}

#[test]
fn kerberos_replay_expiry_clock_and_restart_are_fail_closed() {
    let (mut state, _raw, _root) = configured();
    let first = login_plan(&state, 100);
    let duplicate_in_flight = login_plan(&state, 100);
    let before_clock_advance = login_plan(&state, 99);
    let response = state
        .finish_kerberos_login(first, observation(160))
        .unwrap();
    assert!(response.body["auth"]["client_token"].is_string());
    assert_eq!(
        state
            .prepare_kerberos_login(
                "",
                "kerberos",
                "POST",
                &json!({"kerberos_authorization":AUTHORIZATION}),
                101
            )
            .err()
            .unwrap()
            .status,
        403
    );
    assert_eq!(
        state
            .finish_kerberos_login(duplicate_in_flight, observation(160))
            .err()
            .unwrap()
            .status,
        403
    );
    assert_eq!(
        state
            .finish_kerberos_login(before_clock_advance, observation(200))
            .err()
            .unwrap()
            .status,
        400
    );

    let fresh = "Negotiate ZnJlc2hAYm91bmRhcnk=";
    let plan = |state: &AuthState| {
        state
            .prepare_kerberos_login(
                "",
                "kerberos",
                "POST",
                &json!({"kerberos_authorization":fresh}),
                101,
            )
            .unwrap()
    };
    assert_eq!(
        state
            .finish_kerberos_login(plan(&state), observation(101))
            .err()
            .unwrap()
            .status,
        403
    );
    for wrong in [
        KerberosLoginObservation::for_test(
            "alice@OTHER.TEST",
            "OTHER.TEST",
            "HTTP/heptabao.test@HBKRB.TEST",
            200,
        ),
        KerberosLoginObservation::for_test(
            "alice@HBKRB.TEST",
            "HBKRB.TEST",
            "HTTP/other.test@HBKRB.TEST",
            200,
        ),
    ] {
        assert_eq!(
            state
                .finish_kerberos_login(plan(&state), wrong)
                .err()
                .unwrap()
                .status,
            403
        );
    }
    // Failed observations must neither consume a ticket nor allocate a token.
    assert!(
        state
            .finish_kerberos_login(plan(&state), observation(200))
            .is_ok()
    );
    let saved = serde_json::to_vec(&state).unwrap();
    let restarted: AuthState = serde_json::from_slice(&saved).unwrap();
    restarted.validate_online_auth().unwrap();
    for authorization in [AUTHORIZATION, fresh] {
        assert_eq!(
            restarted
                .prepare_kerberos_login(
                    "",
                    "kerberos",
                    "POST",
                    &json!({"kerberos_authorization":authorization}),
                    103
                )
                .err()
                .unwrap()
                .status,
            403
        );
        assert!(!String::from_utf8_lossy(&saved).contains(authorization));
    }
}

#[test]
fn kerberos_distinct_inflight_logins_preserve_both_durable_replay_entries() {
    let (mut state, _raw, _root) = configured();
    let other = "Negotiate ZGlzdGluY3RAYm91bmRhcnk=";
    let first = login_plan(&state, 100);
    let second = state
        .prepare_kerberos_login(
            "",
            "kerberos",
            "POST",
            &json!({"kerberos_authorization":other}),
            100,
        )
        .unwrap();
    assert!(state.finish_kerberos_login(first, observation(200)).is_ok());
    assert!(
        state
            .finish_kerberos_login(second, observation(200))
            .is_ok()
    );
    state.validate_online_auth().unwrap();
    for authorization in [AUTHORIZATION, other] {
        assert_eq!(
            state
                .prepare_kerberos_login(
                    "",
                    "kerberos",
                    "POST",
                    &json!({"kerberos_authorization":authorization}),
                    102
                )
                .err()
                .unwrap()
                .status,
            403
        );
    }
}

#[test]
fn kerberos_committed_ap_req_cannot_replay_across_namespace_or_mount() {
    let (mut state, _raw, root) = configured();
    mount_auth(&mut state, &root, "team", "kerberos", "kerberos");
    call(
        &mut state,
        &root,
        "team",
        "POST",
        "auth/kerberos/config",
        config(),
        100,
    );
    let first = login_plan(&state, 100);
    let other_namespace = state
        .prepare_kerberos_login(
            "team",
            "kerberos",
            "POST",
            &json!({"kerberos_authorization":AUTHORIZATION}),
            100,
        )
        .unwrap();
    assert!(state.finish_kerberos_login(first, observation(200)).is_ok());
    assert_eq!(
        state
            .finish_kerberos_login(other_namespace, observation(200))
            .err()
            .unwrap()
            .status,
        403
    );
    let saved = serde_json::to_vec(&state).unwrap();
    let restored: AuthState = serde_json::from_slice(&saved).unwrap();
    assert_eq!(
        restored
            .prepare_kerberos_login(
                "team",
                "kerberos",
                "POST",
                &json!({"kerberos_authorization":AUTHORIZATION}),
                102
            )
            .err()
            .unwrap()
            .status,
        403
    );
}
