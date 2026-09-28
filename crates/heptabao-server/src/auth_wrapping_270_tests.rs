//! OpenBao 2.7.0 wrapping-token authority: discard without disclosure.
use super::*;
type TestResult = Result<(), Box<dyn std::error::Error>>;

fn bearer(response: &AuthResponse) -> Result<String, Box<dyn std::error::Error>> {
    Ok(response
        .body
        .pointer("/wrap_info/token")
        .and_then(Value::as_str)
        .ok_or("missing synthetic wrapper")?
        .to_owned())
}

#[test]
fn wrapping_270_self_revocation_is_scoped_and_survives_serialization() -> TestResult {
    for namespace in ["", "team"] {
        for method in ["POST", "PUT"] {
            let (mut state, root) = AuthState::bootstrap(100)?;
            let admin = state.authenticate(&root, 100)?;
            let response = state.wrap_response(
                namespace,
                "sys/wrapping/wrap",
                60,
                &json!({"data":{"value":"synthetic-discard-only-payload"}}),
                100,
            )?;
            let raw = bearer(&response)?;
            let peer = bearer(&state.wrap_response(
                namespace,
                "sys/wrapping/wrap",
                60,
                &json!({"data":{"value":"synthetic-independent-peer"}}),
                100,
            )?)?;
            let target = state.inspection_target(
                &admin,
                namespace,
                "sys/capabilities",
                &json!({"token":raw}),
                100,
            )?;
            assert_eq!(
                state.inspect_capabilities(
                    namespace,
                    "auth/token/revoke-self",
                    &target,
                    &BTreeSet::new(),
                    false,
                    &IdentityTemplateValues::default()
                )?,
                vec!["update"]
            );
            let actor = state.authenticate(&raw, 100)?;
            state.authorize_request(&actor, namespace, "auth/token/revoke-self", "update", 100)?;
            assert!(
                state
                    .authorize_request(&actor, namespace, "auth/token/revoke", "update", 100)
                    .is_err()
            );
            let revoked = state.token_route(
                Some(&actor),
                namespace,
                method,
                "auth/token/revoke-self",
                &json!({}),
                100,
                None,
            )?;
            assert_eq!(revoked.status, 204);
            assert!(revoked.mutated);
            assert!(revoked.body.get("data").is_none_or(Value::is_null));
            assert!(revoked.body.get("wrap_info").is_none_or(Value::is_null));
            assert!(state.authenticate(&raw, 100).is_err());
            assert!(
                state
                    .token_route(
                        Some(&actor),
                        namespace,
                        method,
                        "auth/token/revoke-self",
                        &json!({}),
                        100,
                        None
                    )
                    .is_err()
            );
            state.validate_wrapping_state()?;
            let encoded = Zeroizing::new(serde_json::to_vec(&state)?);
            let forbidden = b"synthetic-discard-only-payload";
            assert!(
                !encoded
                    .windows(forbidden.len())
                    .any(|window| window == forbidden)
            );
            let mut reopened: AuthState = serde_json::from_slice(&encoded)?;
            reopened.validate_wrapping_state()?;
            assert!(reopened.authenticate(&raw, 100).is_err());
            reopened.authenticate(&root, 100)?;
            assert_eq!(
                reopened
                    .lookup_wrapping_request(&peer, namespace, "POST", &json!({}), 100)?
                    .status,
                200
            );
        }
    }
    Ok(())
}

#[test]
fn wrapping_270_self_revocation_does_not_expand_other_capabilities() -> TestResult {
    let (mut state, _root) = AuthState::bootstrap(100)?;
    let raw = bearer(&state.wrap_response(
        "team",
        "sys/wrapping/wrap",
        60,
        &json!({"data":{"value":"synthetic"}}),
        100,
    )?)?;
    let actor = state.authenticate(&raw, 100)?;
    state.authorize_request(&actor, "team", "auth/token/revoke-self", "update", 100)?;
    for capability in ["read", "create", "delete", "list", "scan", "sudo"] {
        assert!(
            state
                .authorize_request(&actor, "team", "auth/token/revoke-self", capability, 100)
                .is_err()
        );
    }
    for path in [
        "auth/token/revoke",
        "auth/token/revoke-accessor",
        "auth/token/renew-self",
        "auth/token/create",
        "sys/wrapping/rewrap",
        "sys/wrapping/wrap",
        "auth/token/revoke-self/peer",
    ] {
        assert!(
            state
                .authorize_request(&actor, "team", path, "update", 100)
                .is_err()
        );
    }
    assert!(
        state
            .authorize_request(&actor, "other", "auth/token/revoke-self", "update", 100)
            .is_err()
    );
    assert!(
        state
            .authorize_request(&actor, "team", "auth/token/revoke-self", "update", 160)
            .is_err()
    );
    for method in ["GET", "DELETE", "LIST", "SCAN"] {
        assert!(
            state
                .token_route(
                    Some(&actor),
                    "team",
                    method,
                    "auth/token/revoke-self",
                    &json!({}),
                    100,
                    None
                )
                .is_err_and(|error| error.status == 405)
        );
    }
    Ok(())
}
