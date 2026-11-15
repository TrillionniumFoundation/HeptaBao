#![allow(clippy::unwrap_used)]
use super::*;
use std::time::{Duration, Instant};

const SOURCE: &str =
    r#"path "secret/data/retirement143" { capabilities = ["read", "update", "create"] }"#;

fn at(seconds: u64, nanoseconds: u32) -> AuthorityTime {
    AuthorityTime::Precise(Timestamp::checked(seconds, nanoseconds).unwrap())
}

fn admit(state: &mut AuthState, token: &str, time: AuthorityTime) -> Principal {
    let mut actor = state.authenticate_from_observed(token, time, None).unwrap();
    let clock = RequestClock::anchored(Duration::ZERO, Instant::now())
        .unwrap()
        .with_timestamp_floor(time.exact().unwrap());
    actor.bind_request_clock(Some(clock)).unwrap();
    actor
}

fn call(
    state: &mut AuthState,
    token: &str,
    time: AuthorityTime,
    method: &str,
    path: &str,
    body: Value,
) -> AuthResponse {
    let actor = admit(state, token, time);
    state
        .handle_with_connection_clock(
            Some(&actor),
            "",
            method,
            path,
            &body,
            time,
            actor.original_request_clock(),
            None,
            None,
        )
        .unwrap()
        .unwrap()
}

fn policy(state: &mut AuthState, root: &str, name: &str, expires: u64) {
    assert_eq!(
        call(
            state,
            root,
            at(100, 0),
            "POST",
            &format!("sys/policies/acl/{name}"),
            json!({"policy":SOURCE,"expiration":expires,"cas":-1,"cas_required":true})
        )
        .status,
        204
    );
}

fn token(state: &mut AuthState, root: &str, names: &[&str], uses: u64) -> String {
    // Token API removes even an explicitly requested default policy when
    // no_default_policy is true. Keep exactly the policies this case selects.
    let no_default_policy = !names.contains(&"default");
    let reply = call(
        state,
        root,
        at(100, 0),
        "POST",
        "auth/token/create",
        json!({"policies":names,"ttl":1000,"no_default_policy":no_default_policy,"num_uses":uses}),
    );
    assert_eq!(reply.status, 200);
    reply.body["auth"]["client_token"]
        .as_str()
        .unwrap()
        .to_owned()
}

#[test]
fn retirement143_fixed_batch_respects_equality_path_only_and_actual_actor_names() {
    let (mut state, root) = AuthState::bootstrap(100).unwrap();
    for name in ["selected", "other"] {
        policy(&mut state, &root, name, 101);
    }
    let path = r#"path "secret/data/retirement143" { capabilities = ["read"] expiration = "101" }"#;
    assert_eq!(
        call(
            &mut state,
            &root,
            at(100, 0),
            "POST",
            "sys/policies/acl/path-only",
            json!({"policy":path})
        )
        .status,
        204
    );
    let raw = token(&mut state, &root, &["selected", "path-only"], 0);
    let actor = admit(&mut state, &raw, at(101, 0));
    let equal = state
        .actor_policy_retirement(&actor, "", at(101, 0))
        .unwrap();
    assert!(equal.is_empty());
    let before = serde_json::to_vec(&state).unwrap();
    assert!(!equal.apply(&mut state).unwrap());
    assert_eq!(serde_json::to_vec(&state).unwrap(), before);
    let expired = state
        .actor_policy_retirement(&actor, "", at(101, 1))
        .unwrap();
    assert_eq!(expired.entries.len(), 1);
    assert!(expired.entries.contains_key("selected"));
    let source = state.clone();
    assert!(expired.apply(&mut state).unwrap());
    expired
        .validate_candidate(&source, &state, at(101, 1))
        .unwrap();
    assert!(!state.policies[""].contains_key("selected"));
    assert!(state.policies[""].contains_key("other"));
    assert!(state.policies[""].contains_key("path-only"));
    assert!(expired.apply(&mut state).is_err());
}

#[test]
fn retirement143_preimage_rewrite_and_extra_auth_delta_are_rejected_atomically() {
    let (mut state, root) = AuthState::bootstrap(100).unwrap();
    for name in ["a", "z"] {
        policy(&mut state, &root, name, 101);
    }
    let raw = token(&mut state, &root, &["a", "z"], 0);
    let actor = admit(&mut state, &raw, at(102, 0));
    let batch = state
        .actor_policy_retirement(&actor, "", at(102, 0))
        .unwrap();
    assert_eq!(
        call(
            &mut state,
            &root,
            at(102, 0),
            "POST",
            "sys/policies/acl/z",
            json!({"policy":SOURCE,"expiration":200,"cas":1})
        )
        .status,
        204
    );
    let rewritten = serde_json::to_vec(&state).unwrap();
    assert!(batch.apply(&mut state).is_err());
    assert_eq!(serde_json::to_vec(&state).unwrap(), rewritten);
    assert!(state.policies[""].contains_key("a"));

    let batch = state
        .actor_policy_retirement(&actor, "", at(102, 0))
        .unwrap();
    let source = state.clone();
    let mut candidate = source.clone();
    batch.apply(&mut candidate).unwrap();
    batch
        .validate_candidate(&source, &candidate, at(102, 0))
        .unwrap();
    candidate
        .tokens
        .get_mut(&hash(&raw))
        .unwrap()
        .display_name
        .push_str("changed");
    assert!(
        batch
            .validate_candidate(&source, &candidate, at(102, 0))
            .is_err()
    );
    assert!(
        batch
            .validate_candidate(&source, &candidate, at(101, 999_999_999))
            .is_err()
    );
}

#[test]
fn retirement143_default_tombstone_identity_selection_and_no_second_token_use() {
    let (mut state, root) = AuthState::bootstrap(100).unwrap();
    assert_eq!(
        call(
            &mut state,
            &root,
            at(100, 0),
            "POST",
            "sys/policies/acl/default",
            json!({"policy":SOURCE,"expiration":101})
        )
        .status,
        204
    );
    policy(&mut state, &root, "identity", 101);
    policy(&mut state, &root, "unrelated", 101);
    let raw = token(&mut state, &root, &["default"], 1);
    assert_eq!(
        state.tokens[&hash(&raw)].policies,
        BTreeSet::from(["default".into()])
    );
    let mut actor = admit(&mut state, &raw, at(102, 0));
    actor.bind_identity_policies(BTreeSet::from(["identity".into()]));
    assert_eq!(state.tokens[&hash(&raw)].uses_remaining, Some(0));
    let batch = state
        .actor_policy_retirement(&actor, "", at(102, 0))
        .unwrap();
    assert_eq!(batch.entries.len(), 2);
    let source = state.clone();
    batch.apply(&mut state).unwrap();
    batch
        .validate_candidate(&source, &state, at(102, 0))
        .unwrap();
    assert_eq!(state.tokens[&hash(&raw)].uses_remaining, Some(0));
    assert!(state.policies[""]["default"].expired_default);
    assert!(!state.policies[""].contains_key("identity"));
    assert!(state.policies[""].contains_key("unrelated"));
    assert!(
        !state
            .policy_allows_observed(
                "",
                "secret/data/retirement143",
                "read",
                &BTreeSet::from(["default".into()]),
                &BTreeSet::new(),
                &IdentityTemplateValues::default(),
                at(102, 0)
            )
            .unwrap()
    );
    assert!(
        state
            .actor_policy_retirement(&actor, "", at(102, 0))
            .unwrap()
            .is_empty()
    );
}

#[test]
fn retirement143_foreign_target_keeps_identity_and_never_consumes_target_uses() {
    let (mut state, root) = AuthState::bootstrap(100).unwrap();
    policy(&mut state, &root, "target", 101);
    policy(&mut state, &root, "actor-only", 101);
    let raw = token(&mut state, &root, &["target"], 3);
    let actor = admit(&mut state, &root, at(102, 0));
    let body = json!({"token":raw});
    let target = state
        .inspection_target_observed(&actor, "", "sys/capabilities", &body, at(102, 0))
        .unwrap();
    let batch = state
        .inspection_policy_retirement(&actor, "", target, &BTreeSet::new(), at(102, 0))
        .unwrap();
    assert_eq!(batch.entries.len(), 1);
    assert!(batch.entries.contains_key("target"));
    assert_eq!(state.tokens[&hash(&raw)].uses_remaining, Some(3));
    let source = state.clone();
    batch.apply(&mut state).unwrap();
    batch
        .validate_candidate(&source, &state, at(102, 0))
        .unwrap();
    assert_eq!(state.tokens[&hash(&raw)].uses_remaining, Some(3));
    let same = state
        .inspection_target_observed(&actor, "", "sys/capabilities", &body, at(102, 0))
        .unwrap();
    assert!(batch.target().is_some_and(|original| original == &same));
    assert!(state.policies[""].contains_key("actor-only"));
}
