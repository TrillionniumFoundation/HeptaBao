use super::*;
type TestResult = Result<(), Box<dyn std::error::Error>>;
fn call(
    state: &mut AuthState,
    actor: &Principal,
    namespace: &str,
    path: &str,
    body: Value,
    now: u64,
) -> Result<AuthResponse, AuthError> {
    state
        .handle(Some(actor), namespace, "POST", path, &body, now)?
        .ok_or_else(|| bad("missing route"))
}
fn issue(
    state: &mut AuthState,
    root: &Principal,
    namespace: &str,
    body: Value,
) -> Result<String, Box<dyn std::error::Error>> {
    let r = call(state, root, namespace, "auth/token/create", body, 100)?;
    Ok(r.body["auth"]["client_token"]
        .as_str()
        .ok_or("missing service token")?
        .to_owned())
}
#[test]
fn expired_renew_classification_follows_acl_and_does_not_replace_ancestor_or_namespace_checks()
-> TestResult {
    let (mut state, raw_root) = AuthState::bootstrap(100)?;
    let root = state.authenticate(&raw_root, 100)?;
    call(
        &mut state,
        &root,
        "",
        "sys/policies/acl/renewer",
        json!({"policy":"path \"auth/token/renew\" { capabilities = [\"update\"] }"}),
        100,
    )?;
    let granted = issue(
        &mut state,
        &root,
        "",
        json!({"policies":["renewer"],"no_default_policy":true,"ttl":"1h"}),
    )?;
    let denied_raw = issue(
        &mut state,
        &root,
        "",
        json!({"policies":["default"],"no_default_policy":true,"ttl":"1h"}),
    )?;
    let renewer = state.authenticate(&granted, 102)?;
    let no_grant = state.authenticate(&denied_raw, 102)?;
    let expired = issue(
        &mut state,
        &root,
        "",
        json!({"policies":["default"],"ttl":"1s"}),
    )?;
    for actor in [&root, &renewer] {
        let e = call(
            &mut state,
            actor,
            "",
            "auth/token/renew",
            json!({"token":expired}),
            102,
        )
        .err()
        .ok_or("expired renewed")?;
        assert_eq!((e.status, e.message.as_str()), (400, "token not found"));
    }
    assert_eq!(
        call(
            &mut state,
            &no_grant,
            "",
            "auth/token/renew",
            json!({"token":expired}),
            102
        )
        .err()
        .ok_or("ACL bypass")?
        .status,
        403
    );
    let foreign = issue(
        &mut state,
        &root,
        "team",
        json!({"policies":["default"],"ttl":"1s"}),
    )?;
    assert_eq!(
        call(
            &mut state,
            &root,
            "",
            "auth/token/renew",
            json!({"token":foreign}),
            102
        )
        .err()
        .ok_or("namespace bypass")?
        .status,
        403
    );
    let child = issue(
        &mut state,
        &root,
        "",
        json!({"policies":["default"],"ttl":"10s"}),
    )?;
    state
        .tokens
        .get_mut(&hash(&child))
        .ok_or("child absent")?
        .parent = Some(hash(&expired));
    assert_eq!(
        call(
            &mut state,
            &root,
            "",
            "auth/token/renew",
            json!({"token":child}),
            102
        )
        .err()
        .ok_or("ancestor bypass")?
        .status,
        403
    );
    assert_eq!(
        call(
            &mut state,
            &root,
            "",
            "auth/token/lookup",
            json!({"token":expired}),
            102
        )
        .err()
        .ok_or("lookup expired")?
        .message,
        "bad token"
    );
    Ok(())
}
#[test]
fn ordinary_nonrenewable_lease_has_reference_error_and_unknown_handle_remains_closed() -> TestResult
{
    let (mut state, raw_root) = AuthState::bootstrap(100)?;
    let root = state.authenticate(&raw_root, 100)?;
    let raw = issue(
        &mut state,
        &root,
        "",
        json!({"policies":["default"],"ttl":"1h","renewable":false}),
    )?;
    let e = call(
        &mut state,
        &root,
        "",
        "auth/token/renew",
        json!({"token":raw}),
        101,
    )
    .err()
    .ok_or("nonrenewable renewed")?;
    assert_eq!(
        (e.status, e.message.as_str()),
        (400, "lease is not renewable")
    );
    state.revoke(&hash(&raw));
    assert_eq!(
        call(
            &mut state,
            &root,
            "",
            "auth/token/renew",
            json!({"token":raw}),
            101
        )
        .err()
        .ok_or("revoked renewed")?
        .status,
        403
    );
    // This finite change does not invent cryptographic handle provenance or
    // tombstones to turn every absent hvs handle into a 400 token-not-found.
    assert_eq!(
        call(
            &mut state,
            &root,
            "",
            "auth/token/renew",
            json!({"token":format!("hvs.{}","a".repeat(43))}),
            101
        )
        .err()
        .ok_or("unknown renewed")?
        .status,
        403
    );
    Ok(())
}
