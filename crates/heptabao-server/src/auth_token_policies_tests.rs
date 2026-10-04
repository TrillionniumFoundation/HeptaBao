use super::super::*;

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn request(
    state: &mut AuthState,
    actor: &Principal,
    namespace: &str,
    path: &str,
    body: Value,
) -> Result<AuthResponse, AuthError> {
    state
        .handle(Some(actor), namespace, "POST", path, &body, 100)?
        .ok_or_else(|| err(500, "token policy fixture route not owned"))
}

fn issue(
    state: &mut AuthState,
    actor: &Principal,
    namespace: &str,
    path: &str,
    body: Value,
) -> Result<(Principal, Value), Box<dyn std::error::Error>> {
    let response = request(state, actor, namespace, path, body)?;
    let raw = response.body["auth"]["client_token"]
        .as_str()
        .ok_or("actual issued token absent")?;
    Ok((state.authenticate(raw, 100)?, response.body["auth"].clone()))
}

fn setup() -> Result<(AuthState, Principal), Box<dyn std::error::Error>> {
    let (mut state, raw) = AuthState::bootstrap(100)?;
    let root = state.authenticate(&raw, 100)?;
    for (name, policy) in [
        (
            "creator",
            r#"path "auth/token/create*" { capabilities = ["update"] }"#,
        ),
        (
            "creator-sudo",
            r#"path "auth/token/create*" { capabilities = ["update", "sudo"] }"#,
        ),
        (
            "p-one",
            r#"path "token-policy-probe/allowed" { capabilities = ["read"] }"#,
        ),
        (
            "p-two",
            r#"path "auth/token/lookup-self" { capabilities = ["read"] }"#,
        ),
    ] {
        request(
            &mut state,
            &root,
            "",
            &format!("sys/policies/acl/{name}"),
            json!({"policy":policy}),
        )?;
    }
    Ok((state, root))
}

#[test]
fn token_empty_policies_inherit_actual_root_for_create_and_orphan() -> TestResult {
    let (mut state, root) = setup()?;
    for path in ["auth/token/create", "auth/token/create-orphan"] {
        for body in [
            json!({}),
            json!({"policies":[]}),
            json!({"policies":""}),
            json!({"no_default_policy":true}),
            json!({"policies":[],"no_default_policy":true}),
            json!({"policies":"","no_default_policy":true}),
            json!({"policies":null}),
            json!({"policies":null,"no_default_policy":true}),
        ] {
            let (child, auth) = issue(&mut state, &root, "", path, body)?;
            assert_eq!(auth["policies"], json!(["root"]));
            state.authorize_request(&child, "", "token-policy-probe/allowed", "read", 100)?;
            state.authorize_request(&child, "", "sys/seal", "sudo", 100)?;
        }
    }
    Ok(())
}

#[test]
fn token_explicit_default_removal_creates_no_policy_and_survives_reopen() -> TestResult {
    let (mut state, root) = setup()?;
    let (child, auth) = issue(
        &mut state,
        &root,
        "",
        "auth/token/create",
        json!({"policies":["default"],"no_default_policy":true}),
    )?;
    assert_eq!(auth["policies"], json!([]));
    for capability in ["read", "sudo"] {
        assert_eq!(
            state
                .authorize_request(&child, "", "token-policy-probe/allowed", capability, 100)
                .err()
                .ok_or("policy-free child admitted")?
                .status,
            403
        );
    }
    let encoded = Zeroizing::new(serde_json::to_vec(&state)?);
    let reopened: AuthState = serde_json::from_slice(&encoded)?;
    assert_eq!(reopened.tokens[&child.digest].policies, BTreeSet::new());
    assert!(!reopened.tokens[&child.digest].root);
    assert_eq!(
        reopened.tokens[&child.digest].parent.as_deref(),
        Some(root.digest.as_str())
    );
    Ok(())
}

#[test]
fn token_nonroot_empty_inherits_parent_and_default_removal_is_exact() -> TestResult {
    for parent_no_default in [false, true] {
        let (mut state, root) = setup()?;
        let (parent, _) = issue(
            &mut state,
            &root,
            "",
            "auth/token/create",
            json!({"policies":["creator","p-one"],"no_default_policy":parent_no_default}),
        )?;
        for no_default in [false, true] {
            for policies in [None, Some(json!([])), Some(json!(""))] {
                let mut body = json!({"no_default_policy":no_default});
                if let Some(policies) = policies {
                    body["policies"] = policies;
                }
                let (child, auth) = issue(&mut state, &parent, "", "auth/token/create", body)?;
                assert_eq!(
                    auth["policies"],
                    if parent_no_default || no_default {
                        json!(["creator", "p-one"])
                    } else {
                        json!(["creator", "default", "p-one"])
                    }
                );
                state.authorize_request(&child, "", "token-policy-probe/allowed", "read", 100)?;
                assert_eq!(
                    state
                        .authorize_request(&child, "", "sys/seal", "sudo", 100)
                        .err()
                        .ok_or("nonroot child escalated")?
                        .status,
                    403
                );
            }
        }
    }
    Ok(())
}

#[test]
fn token_named_subset_does_not_add_default_absent_from_parent() -> TestResult {
    let (mut state, root) = setup()?;
    let (parent, _) = issue(
        &mut state,
        &root,
        "",
        "auth/token/create",
        json!({"policies":["creator","p-one"],"no_default_policy":true}),
    )?;
    let (child, auth) = issue(
        &mut state,
        &parent,
        "",
        "auth/token/create",
        json!({"policies":["p-one"]}),
    )?;
    assert_eq!(auth["policies"], json!(["p-one"]));
    state.authorize_request(&child, "", "token-policy-probe/allowed", "read", 100)?;
    for body in [
        json!({"policies":["default"],"no_default_policy":true}),
        json!({"policies":["p-two"],"no_default_policy":true}),
        json!({"policies":["root"],"no_default_policy":true}),
    ] {
        let before = Zeroizing::new(serde_json::to_vec(&state)?);
        let error = request(&mut state, &parent, "", "auth/token/create", body)
            .err()
            .ok_or("foreign policy admitted")?;
        assert_eq!(error.status, 400);
        assert_eq!(error.message, "child policies must be subset of parent");
        assert_eq!(before.as_slice(), serde_json::to_vec(&state)?.as_slice());
    }
    Ok(())
}

#[test]
fn token_sudo_allows_named_disjoint_policies_but_never_root_escalation() -> TestResult {
    let (mut state, root) = setup()?;
    let (parent, _) = issue(
        &mut state,
        &root,
        "",
        "auth/token/create",
        json!({"policies":["creator-sudo","p-one"],"no_default_policy":true}),
    )?;
    for no_default in [false, true] {
        let (child, auth) = issue(
            &mut state,
            &parent,
            "",
            "auth/token/create",
            json!({"policies":["p-two"],"no_default_policy":no_default}),
        )?;
        assert_eq!(
            auth["policies"],
            if no_default {
                json!(["p-two"])
            } else {
                json!(["default", "p-two"])
            }
        );
        assert_eq!(
            state
                .authorize_request(&child, "", "token-policy-probe/allowed", "read", 100)
                .err()
                .ok_or("disjoint child borrowed parent policy")?
                .status,
            403
        );
    }
    let before = Zeroizing::new(serde_json::to_vec(&state)?);
    let error = request(
        &mut state,
        &parent,
        "",
        "auth/token/create",
        json!({"policies":["root","p-two"],"no_default_policy":true}),
    )
    .err()
    .ok_or("sudo parent granted root")?;
    assert_eq!(error.status, 400);
    assert_eq!(
        error.message,
        "root tokens may not be created without parent token being root"
    );
    assert_eq!(before.as_slice(), serde_json::to_vec(&state)?.as_slice());
    Ok(())
}

#[test]
fn token_policy_resolution_keeps_route_acl_authority() -> TestResult {
    let (mut state, root) = setup()?;
    let (parent, _) = issue(
        &mut state,
        &root,
        "",
        "auth/token/create",
        json!({"policies":["p-one"],"no_default_policy":true}),
    )?;
    let before = Zeroizing::new(serde_json::to_vec(&state)?);
    assert_eq!(
        request(
            &mut state,
            &parent,
            "",
            "auth/token/create",
            json!({"policies":[]}),
        )
        .err()
        .ok_or("route ACL bypassed")?
        .status,
        403
    );
    assert_eq!(before.as_slice(), serde_json::to_vec(&state)?.as_slice());
    Ok(())
}

#[test]
fn token_parent_namespace_never_inherits_root_into_child_namespace() -> TestResult {
    let (mut state, root) = setup()?;
    for (body, expected) in [
        (json!({}), json!(["default"])),
        (json!({"policies":[]}), json!(["default"])),
        (json!({"no_default_policy":true}), json!([])),
        (json!({"policies":[],"no_default_policy":true}), json!([])),
    ] {
        let (child, auth) = issue(
            &mut state,
            &root,
            "token-policy-child",
            "auth/token/create",
            body,
        )?;
        assert_eq!(auth["policies"], expected);
        assert!(!state.tokens[&child.digest].root);
        assert_eq!(state.tokens[&child.digest].namespace, "token-policy-child");
    }
    let before = Zeroizing::new(serde_json::to_vec(&state)?);
    let error = request(
        &mut state,
        &root,
        "token-policy-child",
        "auth/token/create",
        json!({"policies":["root"]}),
    )
    .err()
    .ok_or("root issued outside root namespace")?;
    assert_eq!(error.status, 400);
    assert_eq!(
        error.message,
        "root tokens may not be created from a parent namespace"
    );
    assert_eq!(before.as_slice(), serde_json::to_vec(&state)?.as_slice());
    Ok(())
}

#[test]
fn token_policy_normalization_preserves_actual_root_parent_requirement() -> TestResult {
    let (mut state, root) = setup()?;
    let (_, auth) = issue(
        &mut state,
        &root,
        "",
        "auth/token/create",
        json!({"policies":[" P-ONE ","p-one"],"no_default_policy":true}),
    )?;
    assert_eq!(auth["policies"], json!(["p-one"]));
    let (child, auth) = issue(
        &mut state,
        &root,
        "",
        "auth/token/create",
        json!({"policies":["root","default","p-one"],"no_default_policy":true}),
    )?;
    assert_eq!(auth["policies"], json!(["root"]));
    state.authorize_request(&child, "", "sys/seal", "sudo", 100)?;
    Ok(())
}

#[test]
fn token_wrapping_policy_is_not_assignable_and_root_normalizes_first() -> TestResult {
    let (mut state, root) = setup()?;
    for body in [
        json!({"policies":["response-wrapping"]}),
        json!({"policies":[" RESPONSE-WRAPPING "],"no_default_policy":true}),
    ] {
        let before = Zeroizing::new(serde_json::to_vec(&state)?);
        let error = request(&mut state, &root, "", "auth/token/create", body)
            .err()
            .ok_or("internal wrapping policy assigned")?;
        assert_eq!(error.status, 400);
        assert_eq!(error.message, "cannot assign policy \"response-wrapping\"");
        assert_eq!(before.as_slice(), serde_json::to_vec(&state)?.as_slice());
    }
    let (child, auth) = issue(
        &mut state,
        &root,
        "",
        "auth/token/create",
        json!({"policies":[" ROOT "," response-wrapping "],"no_default_policy":true}),
    )?;
    assert_eq!(auth["policies"], json!(["root"]));
    state.authorize_request(&child, "", "sys/seal", "sudo", 100)?;
    Ok(())
}

#[test]
fn token_explicit_whitespace_and_empty_elements_do_not_inherit_root() -> TestResult {
    let (mut state, root) = setup()?;
    for policies in [json!(" \t "), json!([""]), json!([" "]), json!(["", ""])] {
        for no_default in [false, true] {
            let (child, auth) = issue(
                &mut state,
                &root,
                "",
                "auth/token/create",
                json!({"policies":policies,"no_default_policy":no_default}),
            )?;
            assert_eq!(
                auth["policies"],
                if no_default {
                    json!([])
                } else {
                    json!(["default"])
                }
            );
            assert_eq!(
                state
                    .authorize_request(&child, "", "token-policy-probe/allowed", "read", 100)
                    .err()
                    .ok_or("explicit sanitized empty policy borrowed root")?
                    .status,
                403
            );
        }
    }
    Ok(())
}

#[test]
fn token_literal_string_and_unicode_names_remain_without_unknown_grants() -> TestResult {
    let (mut state, root) = setup()?;
    for (policies, expected) in [
        (json!(","), json!([","])),
        (json!(", ,"), json!([", ,"])),
        (json!(["Σ"]), json!(["σ"])),
        (json!(["İ"]), json!(["i"])),
        (json!(["КЛЮЧ"]), json!(["ключ"])),
        (json!(["control-group"]), json!(["control-group"])),
    ] {
        let (child, auth) = issue(
            &mut state,
            &root,
            "",
            "auth/token/create",
            json!({"policies":policies,"no_default_policy":true}),
        )?;
        assert_eq!(auth["policies"], expected);
        assert_eq!(
            state
                .authorize_request(&child, "", "token-policy-probe/allowed", "read", 100)
                .err()
                .ok_or("unknown normalized name granted authority")?
                .status,
            403
        );
        let encoded = Zeroizing::new(serde_json::to_vec(&state)?);
        let reopened: AuthState = serde_json::from_slice(&encoded)?;
        assert_eq!(
            reopened.tokens[&child.digest].policies,
            state.tokens[&child.digest].policies
        );
        assert!(!reopened.tokens[&child.digest].root);
    }
    Ok(())
}
