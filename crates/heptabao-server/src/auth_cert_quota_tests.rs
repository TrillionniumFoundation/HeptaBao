use super::*;
type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;
const NOW: u64 = 100;
const LEAF: &[u8] = include_bytes!("../testdata/cert-selector.der");
fn setup(leaf: &[u8]) -> TestResult<(AuthState, Principal)> {
    let (mut state, raw) = AuthState::bootstrap(NOW)?;
    let root = state.authenticate(&raw, NOW)?;
    for (path, body) in [
        ("sys/auth/cert", json!({"type":"cert"})),
        (
            "auth/cert/certs/operator",
            json!({"certificate_sha256":certificate_sha256(leaf), "token_ttl":300}),
        ),
        (
            "sys/quotas/rate-limit/role",
            json!({"path":"auth/cert","role":"operator","rate":1,"interval":"1h"}),
        ),
    ] {
        let response = state
            .handle(Some(&root), "", "POST", path, &body, NOW)?
            .ok_or("setup")?;
        assert_eq!(response.status, 204);
    }
    Ok((state, root))
}
fn scope(
    state: &AuthState,
    path: &str,
    body: &Value,
    time: AuthorityTime,
    chain: Option<&[Vec<u8>]>,
) -> TestResult<(String, String)> {
    state
        .rate_limit_native_auth_scope("", "POST", path, body, Some(time), chain)?
        .ok_or_else(|| "missing quota scope".into())
}
#[test]
fn certificate_quota_readonly_resolver_never_mints_or_accepts_requested_identity() -> TestResult {
    let (state, _) = setup(LEAF)?;
    let before = Zeroizing::new(serde_json::to_vec(&state)?);
    let chain = vec![LEAF.to_vec()];
    assert_eq!(
        scope(
            &state,
            "auth/cert/login",
            &json!({"name":"operator"}),
            AuthorityTime::Coarse(NOW),
            Some(&chain)
        )?
        .1,
        "operator"
    );
    for (body, chain) in [
        (json!({"name":"missing"}), Some(chain.as_slice())),
        (json!({"name":"operator"}), None),
        (
            json!({"name":"operator","certificate_sha256":certificate_sha256(LEAF),"peer":"127.0.0.1"}),
            None,
        ),
    ] {
        assert!(
            scope(
                &state,
                "auth/cert/login",
                &body,
                AuthorityTime::Coarse(NOW),
                chain
            )?
            .1
            .is_empty()
        );
    }
    let wrong = vec![include_bytes!("../testdata/cert-selector-other.der").to_vec()];
    assert!(
        scope(
            &state,
            "auth/cert/login",
            &json!({"name":"operator"}),
            AuthorityTime::Coarse(NOW),
            Some(&wrong)
        )?
        .1
        .is_empty()
    );
    let opaque = vec![b"opaque certificate".to_vec()];
    assert!(
        scope(
            &state,
            "auth/cert/login",
            &json!({"name":"operator"}),
            AuthorityTime::Coarse(NOW),
            Some(&opaque)
        )?
        .1
        .is_empty()
    );
    assert!(before.as_slice() == Zeroizing::new(serde_json::to_vec(&state)?).as_slice());
    Ok(())
}
#[test]
fn certificate_quota_uses_original_precise_der_validity_and_constraints() -> TestResult {
    let leaf = include_bytes!("../testdata/cert-validity-boundary.der");
    let (mut state, root) = setup(leaf)?;
    let chain = vec![leaf.to_vec()];
    let end = 1_791_849_720;
    assert_eq!(
        scope(
            &state,
            "auth/cert/login",
            &json!({"name":"operator"}),
            AuthorityTime::Precise(Timestamp::checked(end, 0)?),
            Some(&chain)
        )?
        .1,
        "operator"
    );
    for time in [
        Timestamp::checked(end, 1)?,
        Timestamp::checked(end - 121, 999_999_999)?,
    ] {
        assert!(
            scope(
                &state,
                "auth/cert/login",
                &json!({"name":"operator"}),
                AuthorityTime::Precise(time),
                Some(&chain)
            )?
            .1
            .is_empty()
        );
    }
    state
        .handle(
            Some(&root),
            "",
            "POST",
            "auth/cert/certs/operator",
            &json!({"allowed_common_names":["never-matches.invalid"]}),
            end - 60,
        )?
        .ok_or("constraint update")?;
    assert!(
        scope(
            &state,
            "auth/cert/login",
            &json!({"name":"operator"}),
            AuthorityTime::Coarse(end - 60),
            Some(&chain)
        )?
        .1
        .is_empty()
    );
    Ok(())
}
#[test]
fn certificate_quota_native_mount_selection_uses_longest_current_mount() -> TestResult {
    let (mut state, root) = setup(LEAF)?;
    let other = include_bytes!("../testdata/cert-selector-other.der");
    for (path, body) in [
        ("sys/auth/cert/child", json!({"type":"cert"})),
        (
            "auth/cert/child/certs/childrole",
            json!({"certificate_sha256":certificate_sha256(other)}),
        ),
        (
            "sys/quotas/rate-limit/child",
            json!({"path":"auth/cert/child","role":"childrole","rate":1,"interval":"1h"}),
        ),
    ] {
        assert_eq!(
            state
                .handle(Some(&root), "", "POST", path, &body, NOW)?
                .ok_or("nested setup")?
                .status,
            204
        );
    }
    let chain = vec![other.to_vec()];
    assert_eq!(
        scope(
            &state,
            "auth/cert/child/login",
            &json!({"name":"childrole"}),
            AuthorityTime::Coarse(NOW),
            Some(&chain)
        )?,
        ("auth/cert/child/".into(), "childrole".into())
    );
    assert!(
        state
            .rate_limit_native_auth_scope(
                "child",
                "POST",
                "auth/cert/login",
                &json!({}),
                Some(AuthorityTime::Coarse(NOW)),
                Some(&chain)
            )?
            .is_none()
    );
    Ok(())
}
#[test]
fn certificate_quota_erased_and_retired_reader_markers_fail_closed() -> TestResult {
    let (mut state, root) = setup(LEAF)?;
    assert!(state.has_certificate_quota_state());
    let before = state.clone();
    state
        .handle(
            Some(&root),
            "",
            "DELETE",
            "sys/quotas/rate-limit/role",
            &json!({}),
            NOW,
        )?
        .ok_or("delete")?;
    assert!(state.has_certificate_quota_state());
    state.validate_rate_limit_quota_state(Some(&before))?;
    let mut json = serde_json::to_value(&state)?;
    json["rate_limit_quotas"]
        .as_object_mut()
        .ok_or("registry")?
        .remove("certificate_reader_floor");
    let erased: AuthState = serde_json::from_value(json)?;
    assert!(
        erased
            .validate_rate_limit_quota_state(Some(&state))
            .is_err()
    );
    Ok(())
}
