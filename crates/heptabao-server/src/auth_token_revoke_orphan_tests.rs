//! Revocation severs only direct service-token parent edges, never authority metadata.
use super::*;

fn issuer(state: &mut AuthState, root: &Principal, namespace: &str) {
    put_policy(
        state,
        root,
        namespace,
        "orphan-issuer",
        json!(
            r#"
        path "auth/token/create" { capabilities = ["update"] }
        path "auth/token/revoke-orphan" { capabilities = ["update"] }
    "#
        ),
    );
}

#[test]
fn revoke_orphan_severs_only_direct_children_and_survives_serialization() {
    for method in ["POST", "PUT"] {
        let (mut state, root_raw, root) = setup();
        issuer(&mut state, &root, "");
        let parent_raw = token(
            &mut state,
            &root,
            "",
            json!({"policies":["default","orphan-issuer"],"ttl":30}),
            100,
        );
        let parent = state.authenticate(&parent_raw, 101).unwrap();
        let child_raw = token(
            &mut state,
            &parent,
            "",
            json!({"policies":["default","orphan-issuer"],"ttl":300}),
            101,
        );
        let sibling_raw = token(
            &mut state,
            &parent,
            "",
            json!({"policies":["default"],"ttl":300}),
            101,
        );
        let child = state.authenticate(&child_raw, 101).unwrap();
        let grand_raw = token(
            &mut state,
            &child,
            "",
            json!({"policies":["default"],"ttl":300}),
            101,
        );
        let peer_raw = token(
            &mut state,
            &root,
            "",
            json!({"policies":["default"],"ttl":300}),
            101,
        );
        let mut expected_child = state.tokens[&hash(&child_raw)].clone();
        expected_child.parent = None;
        let expected_grand = serde_json::to_value(&state.tokens[&hash(&grand_raw)]).unwrap();
        let count = state.tokens.len();
        let result = call(
            &mut state,
            &root,
            "",
            method,
            "auth/token/revoke-orphan",
            json!({"token":parent_raw}),
            102,
        );
        assert_eq!(result.status, 204);
        assert!(result.mutated);
        assert_eq!(state.tokens.len(), count - 1);
        assert!(!state.tokens.contains_key(&hash(&parent_raw)));
        assert_eq!(
            serde_json::to_value(&state.tokens[&hash(&child_raw)]).unwrap(),
            serde_json::to_value(expected_child).unwrap()
        );
        assert_eq!(
            serde_json::to_value(&state.tokens[&hash(&grand_raw)]).unwrap(),
            expected_grand
        );
        assert!(state.tokens[&hash(&sibling_raw)].parent.is_none());
        assert!(state.authenticate(&parent_raw, 103).is_err());
        assert!(
            state
                .authorize_request(&parent, "", "auth/token/create", "update", 103)
                .is_err()
        );
        let encoded = Zeroizing::new(serde_json::to_vec(&state).unwrap());
        let mut reopened: AuthState = serde_json::from_slice(&encoded).unwrap();
        reopened.validate_system_lease_defaults().unwrap();
        for raw in [&child_raw, &sibling_raw, &grand_raw, &peer_raw, &root_raw] {
            assert!(
                reopened.authenticate(raw, 135).is_ok(),
                "survivor outlives removed parent's original expiry"
            );
        }
        let root = reopened.authenticate(&root_raw, 135).unwrap();
        call(
            &mut reopened,
            &root,
            "",
            "POST",
            "auth/token/revoke",
            json!({"token":child_raw}),
            136,
        );
        assert!(reopened.authenticate(&child_raw, 137).is_err());
        assert!(reopened.authenticate(&grand_raw, 137).is_err());
        assert!(reopened.authenticate(&sibling_raw, 137).is_ok());
        assert!(reopened.authenticate(&peer_raw, 137).is_ok());
    }
}

#[test]
fn revoke_orphan_requires_sudo_before_target_resolution_without_mutating_edges() {
    let (mut state, _, root) = setup();
    issuer(&mut state, &root, "");
    let raw = token(
        &mut state,
        &root,
        "",
        json!({"policies":["default","orphan-issuer"]}),
        100,
    );
    let actor = state.authenticate(&raw, 101).unwrap();
    let child = token(&mut state, &actor, "", json!({"policies":["default"]}), 101);
    for (principal, method, body, expected) in [
        (&actor, "POST", json!({"token":raw}), 400),
        (&actor, "POST", json!({"token":"missing-token"}), 400),
        (&root, "POST", json!({"token":""}), 400),
        (&root, "GET", json!({"token":raw}), 405),
    ] {
        let before = Zeroizing::new(serde_json::to_vec(&state).unwrap());
        let error = state
            .token_route(
                Some(principal),
                "",
                method,
                "auth/token/revoke-orphan",
                &body,
                102,
                None,
            )
            .err()
            .unwrap();
        assert_eq!(error.status, expected);
        assert_eq!(
            serde_json::to_vec(&state).unwrap().as_slice(),
            before.as_slice()
        );
        assert_eq!(
            state.tokens[&hash(&child)].parent.as_deref(),
            Some(hash(&raw).as_str())
        );
    }
}

#[test]
fn revoke_orphan_missing_target_is_invalid_request_without_damaging_live_children() {
    let (mut state, _, root) = setup();
    let gone = token(&mut state, &root, "", json!({"policies":["default"]}), 100);
    call(
        &mut state,
        &root,
        "",
        "POST",
        "auth/token/revoke",
        json!({"token":gone}),
        101,
    );
    let before = Zeroizing::new(serde_json::to_vec(&state).unwrap());
    let error = state
        .token_route(
            Some(&root),
            "",
            "POST",
            "auth/token/revoke-orphan",
            &json!({"token":gone}),
            102,
            None,
        )
        .err()
        .unwrap();
    assert_eq!(error.status, 400);
    assert_eq!(
        serde_json::to_vec(&state).unwrap().as_slice(),
        before.as_slice()
    );
}
