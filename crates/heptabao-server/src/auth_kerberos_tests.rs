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
    let (mut state, _raw, root) = configured();
    let plan = login_plan(&state, 100);
    let response = state.finish_kerberos_login(plan, observation(160)).unwrap();
    assert!(response.body["auth"]["client_token"].is_string());

    let replay = state.finish_kerberos_login(login_plan(&state, 101), observation(160));
    assert_eq!(replay.err().unwrap().status, 403);

    let expired = state.finish_kerberos_login(login_plan(&state, 101), observation(101));
    assert_eq!(expired.err().unwrap().status, 403);

    let wrong_realm = KerberosLoginObservation::for_test(
        "alice@OTHER.TEST",
        "OTHER.TEST",
        "HTTP/heptabao.test@HBKRB.TEST",
        200,
    );
    assert_eq!(
        state
            .finish_kerberos_login(login_plan(&state, 101), wrong_realm)
            .err()
            .unwrap()
            .status,
        403
    );
    let wrong_service = KerberosLoginObservation::for_test(
        "alice@HBKRB.TEST",
        "HBKRB.TEST",
        "HTTP/other.test@HBKRB.TEST",
        200,
    );
    assert_eq!(
        state
            .finish_kerberos_login(login_plan(&state, 101), wrong_service)
            .err()
            .unwrap()
            .status,
        403
    );

    let rollback = state.finish_kerberos_login(login_plan(&state, 99), observation(200));
    assert_eq!(rollback.err().unwrap().status, 400);

    let saved = serde_json::to_vec(&state).unwrap();
    let mut restarted: AuthState = serde_json::from_slice(&saved).unwrap();
    restarted.validate_online_auth().unwrap();
    let replay_after_restart = restarted.finish_kerberos_login(
        restarted
            .prepare_kerberos_login(
                "",
                "kerberos",
                "POST",
                &json!({"kerberos_authorization": AUTHORIZATION}),
                102,
            )
            .unwrap(),
        observation(200),
    );
    assert_eq!(replay_after_restart.err().unwrap().status, 403);

    let serialized = String::from_utf8(saved).unwrap();
    assert!(!serialized.contains(AUTHORIZATION));
    let _ = root;
}
