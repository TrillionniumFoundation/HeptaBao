#![allow(clippy::unwrap_used)]
use super::*;

const CUSTOM: &str = r#"path "secret/data/startup143" { capabilities = ["read"] }"#;

fn at(seconds: u64) -> AuthorityTime {
    AuthorityTime::Precise(Timestamp::whole(seconds).unwrap())
}

fn timed_default(state: &mut AuthState, namespace: &str, expires: u64) {
    let policy = security_contract::prepare_policy(
        None,
        &json!({"policy": CUSTOM, "expiration": expires, "cas_required": true, "cas": -1}),
        false,
        false,
        at(100),
    )
    .unwrap();
    state
        .policies
        .entry(namespace.into())
        .or_default()
        .insert("default".into(), policy);
}

#[test]
fn startup143_only_expired_root_default_has_a_closed_reset() {
    let (mut state, _) = AuthState::bootstrap(100).unwrap();
    assert!(!state.default_policy_activation_needs_clock());
    assert!(
        state
            .capture_default_policy_reset(at(200))
            .unwrap()
            .is_none()
    );
    timed_default(&mut state, "tenant", 101);
    assert!(!state.default_policy_activation_needs_clock());
    assert!(
        state
            .capture_default_policy_reset(at(200))
            .unwrap()
            .is_none()
    );
    let child = serde_json::to_vec(&state.policies["tenant"]).unwrap();
    timed_default(&mut state, "", 101);
    assert!(state.default_policy_activation_needs_clock());
    assert!(
        state
            .capture_default_policy_reset(at(101))
            .unwrap()
            .is_none()
    );
    assert!(
        state
            .capture_default_policy_reset(AuthorityTime::Coarse(102))
            .is_err()
    );
    let reset = state
        .capture_default_policy_reset(at(102))
        .unwrap()
        .unwrap();
    let source = state.clone();
    reset.apply(&mut state).unwrap();
    reset.validate_candidate(&source, &state).unwrap();
    let policy = &state.policies[""]["default"];
    assert_eq!(policy.source, default_policy_source());
    assert!(!policy.has_expiration());
    let data = policy.read_security_data("default", false).unwrap();
    assert_eq!(data["version"], 1);
    assert_eq!(data["modified"], "1970-01-01T00:01:42Z");
    assert_eq!(data["cas_required"], false);
    assert_eq!(
        serde_json::to_vec(&state.policies["tenant"]).unwrap(),
        child
    );
    assert!(reset.apply(&mut state).is_err());
}

#[test]
fn startup143_tombstone_reset_rejects_rewrite_and_extra_auth_changes() {
    let (mut state, root) = AuthState::bootstrap(100).unwrap();
    state
        .policies
        .entry("".into())
        .or_default()
        .insert("default".into(), Policy::expired_default());
    let reset = state
        .capture_default_policy_reset(at(102))
        .unwrap()
        .unwrap();
    let source = state.clone();
    reset.apply(&mut state).unwrap();
    reset.validate_candidate(&source, &state).unwrap();
    let mut changed = state.clone();
    changed
        .tokens
        .get_mut(&hash(&root))
        .unwrap()
        .display_name
        .push_str("extra");
    assert!(reset.validate_candidate(&source, &changed).is_err());
    let mut rewritten = source;
    timed_default(&mut rewritten, "", 103);
    let before = serde_json::to_vec(&rewritten).unwrap();
    assert!(reset.apply(&mut rewritten).is_err());
    assert_eq!(serde_json::to_vec(&rewritten).unwrap(), before);
}

#[test]
fn startup143_path_expiration_does_not_recreate_the_whole_default() {
    let (mut state, _) = AuthState::bootstrap(100).unwrap();
    let policy = security_contract::prepare_policy(None,
        &json!({"policy": r#"path "secret/data/startup143" { capabilities = ["read"] expiration = "101" }"#}),
        false, false, at(100)).unwrap();
    state
        .policies
        .entry("".into())
        .or_default()
        .insert("default".into(), policy);
    assert!(!state.default_policy_activation_needs_clock());
    let before = serde_json::to_vec(&state).unwrap();
    assert!(
        state
            .capture_default_policy_reset(at(102))
            .unwrap()
            .is_none()
    );
    assert_eq!(serde_json::to_vec(&state).unwrap(), before);
}

#[test]
fn startup143_fresh_root_factory_persists_builtin_version_one() {
    let time = AuthorityTime::Precise(Timestamp::checked(100, 123_456_789).unwrap());
    let (mut auth, token) = AuthState::bootstrap_current_root_with_default_policy(time).unwrap();
    assert_eq!(auth.policies.len(), 1);
    assert_eq!(auth.policies[""].len(), 1);
    let policy = &auth.policies[""]["default"];
    assert_eq!(policy.source, default_policy_source());
    assert!(!policy.has_expiration());
    let data = policy.read_security_data("default", false).unwrap();
    assert_eq!(data["version"], 1);
    assert_eq!(data["modified"], "1970-01-01T00:01:40.123456789Z");
    assert_eq!(data["cas_required"], false);
    assert_eq!(data["allow_slashes_in_identity_templates"], false);
    assert_eq!(data["allow_wildcards_in_identity_templates"], false);
    assert!(auth.has_security_contract_state());
    assert!(!auth.default_policy_activation_needs_clock());
    assert!(auth.authenticate(&token, 100).unwrap().is_root());
    assert_eq!(auth.tokens[&hash(&token)].created_at, 100);
    let bytes = serde_json::to_vec(&auth).unwrap();
    let loaded: AuthState = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(
        loaded.policies[""]["default"]
            .read_security_data("default", false)
            .unwrap(),
        data
    );
    assert!(
        loaded
            .capture_default_policy_reset(at(200))
            .unwrap()
            .is_none()
    );
    assert_eq!(serde_json::to_vec(&loaded).unwrap(), bytes);
}

#[test]
fn startup143_fresh_root_factory_uses_supplied_coarse_clock_and_rejects_invalid_time()
-> Result<(), &'static str> {
    let (auth, _) =
        AuthState::bootstrap_current_root_with_default_policy(AuthorityTime::Coarse(100)).unwrap();
    let data = auth.policies[""]["default"]
        .read_security_data("default", false)
        .unwrap();
    assert_eq!(data["version"], 1);
    assert_eq!(data["modified"], "1970-01-01T00:01:40Z");
    let error = match AuthState::bootstrap_current_root_with_default_policy(AuthorityTime::Coarse(
        u64::MAX,
    )) {
        Ok(_) => return Err("unrepresentable factory clock accepted"),
        Err(error) => error,
    };
    assert_eq!(error.status, 503);
    Ok(())
}

#[test]
fn startup143_historical_absence_is_not_converted_by_loading_or_activation() {
    let (old, _) = AuthState::bootstrap(100).unwrap();
    assert!(old.policies.is_empty());
    assert!(!old.has_security_contract_state());
    let bytes = serde_json::to_vec(&old).unwrap();
    let loaded: AuthState = serde_json::from_slice(&bytes).unwrap();
    assert!(!loaded.default_policy_activation_needs_clock());
    assert!(
        loaded
            .capture_default_policy_reset(at(200))
            .unwrap()
            .is_none()
    );
    assert_eq!(serde_json::to_vec(&loaded).unwrap(), bytes);
    let fallback = parse_policy(&json!(default_policy_source())).unwrap();
    let data = fallback.read_security_data("default", false).unwrap();
    assert_eq!(data["version"], 0);
    assert!(data.get("modified").is_none());
}
