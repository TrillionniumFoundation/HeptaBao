use super::super::hash;
use super::*;

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn call(
    state: &mut AuthState,
    raw: &str,
    namespace: &str,
    method: &str,
    path: &str,
    body: Value,
    now: u64,
) -> Result<AuthResponse, AuthError> {
    let actor = state.authenticate(raw, now)?;
    state
        .handle(Some(&actor), namespace, method, path, &body, now)?
        .ok_or_else(|| err(500, "test route not owned"))
}

fn issue(
    state: &mut AuthState,
    root: &str,
    body: Value,
) -> Result<String, Box<dyn std::error::Error>> {
    let result = call(state, root, "", "POST", "auth/token/create", body, 100)?;
    Ok(result.body["auth"]["client_token"]
        .as_str()
        .ok_or("missing token")?
        .to_owned())
}

#[test]
fn cubbyhole_is_private_even_from_root_and_other_tokens() -> TestResult {
    let (mut state, root) = AuthState::bootstrap(100)?;
    let a = issue(&mut state, &root, json!({"policies":["default"]}))?;
    let b = issue(&mut state, &root, json!({"policies":["default"]}))?;
    call(
        &mut state,
        &a,
        "",
        "POST",
        "cubbyhole/item",
        json!({"private":"sentinel"}),
        100,
    )?;
    for actor in [&b, &root] {
        assert_eq!(
            call(
                &mut state,
                actor,
                "",
                "GET",
                "cubbyhole/item",
                json!({}),
                100
            )
            .err()
            .ok_or("cross-token read succeeded")?
            .status,
            404
        );
    }
    assert_eq!(
        call(&mut state, &a, "", "GET", "cubbyhole/item", json!({}), 100)?.body["data"]["private"],
        "sentinel"
    );
    let lookup = call(
        &mut state,
        &a,
        "",
        "GET",
        "auth/token/lookup-self",
        json!({}),
        100,
    )?;
    assert!(!lookup.body.to_string().contains("sentinel"));
    Ok(())
}

#[test]
fn cubbyhole_root_namespace_dimensions_do_not_collide() -> TestResult {
    let (mut state, root) = AuthState::bootstrap(100)?;
    call(
        &mut state,
        &root,
        "team",
        "POST",
        "cubbyhole/a/b",
        json!({"v":1}),
        100,
    )?;
    call(
        &mut state,
        &root,
        "team/a",
        "POST",
        "cubbyhole/b",
        json!({"v":2}),
        100,
    )?;
    assert_eq!(
        call(
            &mut state,
            &root,
            "team",
            "GET",
            "cubbyhole/a/b",
            json!({}),
            100
        )?
        .body["data"]["v"],
        1
    );
    assert_eq!(
        call(
            &mut state,
            &root,
            "team/a",
            "GET",
            "cubbyhole/b",
            json!({}),
            100
        )?
        .body["data"]["v"],
        2
    );
    assert!(
        call(
            &mut state,
            &root,
            "",
            "GET",
            "cubbyhole/a/b",
            json!({}),
            100
        )
        .is_err()
    );
    Ok(())
}

#[test]
fn cubbyhole_listing_is_sorted_shallow_and_never_lists_values() -> TestResult {
    let (mut state, root) = AuthState::bootstrap(100)?;
    for path in ["foo", "foo/bar", "foo/nested/leaf", "food", "z"] {
        call(
            &mut state,
            &root,
            "",
            "POST",
            &format!("cubbyhole/{path}"),
            json!({"secret":"not-a-key"}),
            100,
        )?;
    }
    assert_eq!(
        call(&mut state, &root, "", "LIST", "cubbyhole/", json!({}), 100)?.body["data"]["keys"],
        json!(["foo", "foo/", "food", "z"])
    );
    assert_eq!(
        call(
            &mut state,
            &root,
            "",
            "GET",
            "cubbyhole/foo",
            json!({"list":"true"}),
            100
        )?
        .body["data"]["keys"],
        json!(["bar", "nested/"])
    );
    assert!(
        call(
            &mut state,
            &root,
            "",
            "LIST",
            "cubbyhole/food",
            json!({}),
            100
        )
        .is_err()
    );
    Ok(())
}

#[test]
fn cubbyhole_replaces_values_and_delete_is_exact_and_idempotent() -> TestResult {
    let (mut state, root) = AuthState::bootstrap(100)?;
    call(
        &mut state,
        &root,
        "",
        "POST",
        "cubbyhole/a",
        json!({"old":1}),
        100,
    )?;
    call(
        &mut state,
        &root,
        "",
        "PUT",
        "cubbyhole/a",
        json!({"new":2}),
        100,
    )?;
    call(
        &mut state,
        &root,
        "",
        "POST",
        "cubbyhole/a/b",
        json!({"child":3}),
        100,
    )?;
    assert_eq!(
        call(&mut state, &root, "", "GET", "cubbyhole/a", json!({}), 100)?.body["data"],
        json!({"new":2})
    );
    for _ in 0..2 {
        assert_eq!(
            call(
                &mut state,
                &root,
                "",
                "DELETE",
                "cubbyhole/a",
                json!({}),
                100
            )?
            .status,
            204
        );
    }
    assert_eq!(
        call(
            &mut state,
            &root,
            "",
            "GET",
            "cubbyhole/a/b",
            json!({}),
            100
        )?
        .body["data"],
        json!({"child":3})
    );
    Ok(())
}

#[test]
fn cubbyhole_acl_distinguishes_creation_and_update() -> TestResult {
    let (mut state, root) = AuthState::bootstrap(100)?;
    call(
        &mut state,
        &root,
        "",
        "PUT",
        "sys/policies/acl/create-only",
        json!({"policy":"path \"cubbyhole/*\" { capabilities = [\"create\", \"read\"] }"}),
        100,
    )?;
    let token = issue(
        &mut state,
        &root,
        json!({"policies":["create-only"],"no_default_policy":true}),
    )?;
    call(
        &mut state,
        &token,
        "",
        "POST",
        "cubbyhole/item",
        json!({"v":1}),
        100,
    )?;
    assert_eq!(
        call(
            &mut state,
            &token,
            "",
            "PUT",
            "cubbyhole/item",
            json!({"v":2}),
            100
        )
        .err()
        .ok_or("update admitted")?
        .status,
        403
    );
    assert_eq!(
        call(
            &mut state,
            &token,
            "",
            "GET",
            "cubbyhole/item",
            json!({}),
            100
        )?
        .body["data"]["v"],
        1
    );
    let denied_token = issue(
        &mut state,
        &root,
        json!({"policies":[],"no_default_policy":true}),
    )?;
    assert_eq!(
        call(
            &mut state,
            &denied_token,
            "",
            "POST",
            "cubbyhole/item",
            json!({"v":1}),
            100
        )
        .err()
        .ok_or("default deny failed")?
        .status,
        403
    );
    Ok(())
}

#[test]
fn cubbyhole_final_read_uses_affine_snapshot_but_clears_admitted_state() -> TestResult {
    let (mut state, root) = AuthState::bootstrap(100)?;
    let token = issue(
        &mut state,
        &root,
        json!({"policies":["default"],"num_uses":2}),
    )?;
    call(
        &mut state,
        &token,
        "",
        "POST",
        "cubbyhole/item",
        json!({"v":"one-time-value"}),
        100,
    )?;
    let principal = state.authenticate(&token, 100)?;
    assert_eq!(
        state
            .tokens
            .get(&hash(&token))
            .ok_or("token lost")?
            .cubbyhole
            .len(),
        0
    );
    let result = state
        .handle(
            Some(&principal),
            "",
            "GET",
            "cubbyhole/item",
            &json!({}),
            100,
        )?
        .ok_or("route missing")?;
    assert_eq!(result.body["data"]["v"], "one-time-value");
    drop(principal);
    let bytes = serde_json::to_vec(&state)?;
    let mut reopened: AuthState = serde_json::from_slice(&bytes)?;
    assert!(reopened.authenticate(&token, 100).is_err());
    assert!(!String::from_utf8(bytes)?.contains("one-time-value"));
    Ok(())
}

#[test]
fn cubbyhole_final_use_on_another_route_also_destroys_stored_values() -> TestResult {
    let (mut state, root) = AuthState::bootstrap(100)?;
    let token = issue(
        &mut state,
        &root,
        json!({"policies":["default"],"num_uses":2}),
    )?;
    call(
        &mut state,
        &token,
        "",
        "POST",
        "cubbyhole/item",
        json!({"v":1}),
        100,
    )?;
    call(
        &mut state,
        &token,
        "",
        "GET",
        "auth/token/lookup-self",
        json!({}),
        100,
    )?;
    assert_eq!(
        state
            .tokens
            .get(&hash(&token))
            .ok_or("token lost")?
            .cubbyhole
            .len(),
        0
    );
    let final_writer = issue(
        &mut state,
        &root,
        json!({"policies":["default"],"num_uses":1}),
    )?;
    assert_eq!(
        call(
            &mut state,
            &final_writer,
            "",
            "POST",
            "cubbyhole/item",
            json!({"v":1}),
            100
        )?
        .status,
        204
    );
    assert_eq!(
        state
            .tokens
            .get(&hash(&final_writer))
            .ok_or("token lost")?
            .cubbyhole
            .len(),
        0
    );
    Ok(())
}

#[test]
fn cubbyhole_revocation_cascades_and_expired_tokens_are_tidyable() -> TestResult {
    let (mut state, root) = AuthState::bootstrap(100)?;
    let parent = issue(&mut state, &root, json!({"ttl":5}))?;
    let child = issue(&mut state, &parent, json!({"policies":["default"]}))?;
    call(
        &mut state,
        &child,
        "",
        "POST",
        "cubbyhole/item",
        json!({"v":"expired-secret"}),
        100,
    )?;
    assert!(
        call(
            &mut state,
            &child,
            "",
            "GET",
            "cubbyhole/item",
            json!({}),
            105
        )
        .is_err()
    );
    call(
        &mut state,
        &root,
        "",
        "POST",
        "auth/token/tidy",
        json!({}),
        105,
    )?;
    assert!(!state.tokens.contains_key(&hash(&child)));
    let token = issue(&mut state, &root, json!({"policies":["default"]}))?;
    call(
        &mut state,
        &token,
        "",
        "POST",
        "cubbyhole/item",
        json!({"v":1}),
        100,
    )?;
    call(
        &mut state,
        &root,
        "",
        "POST",
        "auth/token/revoke",
        json!({"token":token}),
        100,
    )?;
    assert!(!state.tokens.contains_key(&hash(&token)));
    Ok(())
}

#[test]
fn cubbyhole_bounds_reject_without_changing_existing_values() -> TestResult {
    let (mut state, root) = AuthState::bootstrap(100)?;
    for n in 0..MAX_ENTRIES {
        call(
            &mut state,
            &root,
            "",
            "POST",
            &format!("cubbyhole/{n}"),
            json!({"v":n}),
            100,
        )?;
    }
    assert_eq!(
        call(
            &mut state,
            &root,
            "",
            "POST",
            "cubbyhole/overflow",
            json!({"v":1}),
            100
        )
        .err()
        .ok_or("entry bound bypassed")?
        .status,
        507
    );
    let before = serde_json::to_vec(&state)?;
    for body in [
        json!({}),
        json!([]),
        json!({"v":"x".repeat(MAX_VALUE_BYTES)}),
    ] {
        assert!(call(&mut state, &root, "", "POST", "cubbyhole/0", body, 100).is_err());
        assert_eq!(serde_json::to_vec(&state)?, before);
    }
    call(
        &mut state,
        &root,
        "",
        "PUT",
        "cubbyhole/0",
        json!({"replacement":true}),
        100,
    )?;
    Ok(())
}

#[test]
fn cubbyhole_old_token_schema_remains_readable_and_unknown_shape_fails() -> TestResult {
    let (state, root) = AuthState::bootstrap(100)?;
    let mut value = serde_json::to_value(&state)?;
    value["tokens"][hash(&root)]
        .as_object_mut()
        .ok_or("token missing")?
        .remove("cubbyhole");
    let mut reopened: AuthState = serde_json::from_value(value)?;
    assert!(
        call(
            &mut reopened,
            &root,
            "",
            "GET",
            "cubbyhole/item",
            json!({}),
            100
        )
        .is_err()
    );
    assert!(
        serde_json::from_value::<TokenCubbyhole>(json!({"namespaces":{},"other":true})).is_err()
    );
    for path in [
        "cubbyhole/../x",
        "cubbyhole//x",
        "cubbyhole/%2f",
        "cubbyhole/x\\y",
    ] {
        assert!(call(&mut reopened, &root, "", "GET", path, json!({}), 100).is_err());
    }
    Ok(())
}
