use super::super::*;
type TestResult = Result<(), Box<dyn std::error::Error>>;
fn call(
    state: &mut AuthState,
    actor: &Principal,
    namespace: &str,
    method: &str,
    path: &str,
    body: Value,
    now: u64,
) -> Result<AuthResponse, AuthError> {
    state
        .handle(Some(actor), namespace, method, path, &body, now)?
        .ok_or_else(|| err(500, "token role route not owned"))
}
fn setup() -> Result<(AuthState, Principal), Box<dyn std::error::Error>> {
    let (mut state, raw) = AuthState::bootstrap(100)?;
    let root = state.authenticate(&raw, 100)?;
    for (name, text) in [
        (
            "creator",
            r#"path "auth/token/create*" { capabilities = ["update"] }"#,
        ),
        (
            "p-one",
            r#"path "probe/allowed" { capabilities = ["read"] }"#,
        ),
        (
            "p-two",
            r#"path "auth/token/lookup-self" { capabilities = ["read"] }"#,
        ),
    ] {
        call(
            &mut state,
            &root,
            "",
            "POST",
            &format!("sys/policies/acl/{name}"),
            json!({"policy":text}),
            100,
        )?;
    }
    Ok((state, root))
}
fn issued(
    state: &mut AuthState,
    actor: &Principal,
    path: &str,
    body: Value,
) -> Result<(Principal, String, Value), Box<dyn std::error::Error>> {
    let response = call(state, actor, "", "POST", path, body, 100)?;
    let raw = response.body["auth"]["client_token"]
        .as_str()
        .ok_or("actual service grant absent")?
        .to_owned();
    Ok((state.authenticate(&raw, 100)?, raw, response.body))
}
#[test]
fn token_role_management_is_namespaced_partial_and_atomic() -> TestResult {
    let (mut state, root) = setup()?;
    assert_eq!(
        call(
            &mut state,
            &root,
            "",
            "LIST",
            "auth/token/roles",
            json!({}),
            100
        )?
        .status,
        404
    );
    assert_eq!(
        call(
            &mut state,
            &root,
            "",
            "POST",
            "auth/token/roles/shared",
            json!({"allowed_policies":"P-ONE,p-two,p-one","orphan":true,"path_suffix":"!abc!"}),
            100
        )?
        .status,
        204
    );
    call(
        &mut state,
        &root,
        "",
        "POST",
        "auth/token/roles/shared",
        json!({"renewable":false}),
        100,
    )?;
    call(
        &mut state,
        &root,
        "team",
        "POST",
        "auth/token/roles/shared",
        json!({"allowed_policies":["other"]}),
        100,
    )?;
    let info = call(
        &mut state,
        &root,
        "",
        "GET",
        "auth/token/roles/shared",
        json!({}),
        100,
    )?
    .body["data"]
        .clone();
    assert_eq!(info["allowed_policies"], json!(["p-one", "p-two"]));
    assert_eq!(info["orphan"], true);
    assert_eq!(info["renewable"], false);
    assert_eq!(info["path_suffix"], "!abc!");
    assert!(info["allowed_entity_aliases"].is_null());
    assert!(state.known_namespaces().contains("team"));
    assert!(!state.namespace_is_empty("team"));
    let before = serde_json::to_vec(&state)?;
    let failure = call(
        &mut state,
        &root,
        "",
        "POST",
        "auth/token/roles/shared",
        json!({"path_suffix":"a..b","allowed_policies":["changed"]}),
        100,
    )
    .err()
    .ok_or("invalid role update committed")?;
    assert_eq!(
        failure.message,
        "error registering path suffix: path cannot contain parent references"
    );
    assert_eq!(serde_json::to_vec(&state)?, before);
    let mut reopened: AuthState = serde_json::from_slice(&before)?;
    reopened.validate_token_role_state()?;
    assert_eq!(
        call(
            &mut reopened,
            &root,
            "",
            "GET",
            "auth/token/roles/shared",
            json!({}),
            100
        )?
        .body["data"],
        info
    );
    call(
        &mut reopened,
        &root,
        "",
        "DELETE",
        "auth/token/roles/shared",
        json!({}),
        100,
    )?;
    assert_eq!(
        call(
            &mut reopened,
            &root,
            "",
            "GET",
            "auth/token/roles/shared",
            json!({}),
            100
        )?
        .status,
        404
    );
    assert_eq!(
        call(
            &mut reopened,
            &root,
            "team",
            "GET",
            "auth/token/roles/shared",
            json!({}),
            100
        )?
        .body["data"]["allowed_policies"],
        json!(["other"])
    );
    Ok(())
}
#[test]
fn token_roles_delegate_policy_and_orphans_with_actual_route_acl_only() -> TestResult {
    let (mut state, root) = setup()?;
    let (parent, _, _) = issued(
        &mut state,
        &root,
        "auth/token/create",
        json!({"policies":["creator","p-one"],"no_default_policy":true}),
    )?;
    call(
        &mut state,
        &root,
        "",
        "POST",
        "auth/token/roles/delegated",
        json!({"allowed_policies":["p-two"],"orphan":true,"token_no_default_policy":true}),
        100,
    )?;
    let (child, _, body) = issued(
        &mut state,
        &parent,
        "auth/token/create/delegated",
        json!({"policies":["p-two"]}),
    )?;
    assert_eq!(body["auth"]["policies"], json!(["p-two"]));
    assert!(state.tokens[&child.digest].parent.is_none());
    assert_eq!(
        state.tokens[&child.digest]
            .token_role
            .as_ref()
            .ok_or("role marker")?
            .name,
        "delegated"
    );
    let (_, _, orphan) = issued(
        &mut state,
        &parent,
        "auth/token/create-orphan",
        json!({"policies":["p-one"],"no_default_policy":true}),
    )?;
    assert_eq!(orphan["auth"]["orphan"], true);
    let before = serde_json::to_vec(&state)?;
    assert_eq!(
        call(
            &mut state,
            &parent,
            "",
            "POST",
            "auth/token/create",
            json!({"no_parent":true}),
            100
        )
        .err()
        .ok_or("ordinary no_parent lost sudo")?
        .status,
        400
    );
    assert_eq!(serde_json::to_vec(&state)?, before);
    assert_eq!(
        call(
            &mut state,
            &parent,
            "",
            "POST",
            "auth/token/create-orphan",
            json!({"no_parent":"true"}),
            100
        )
        .err()
        .ok_or("explicit no_parent lost sudo on orphan route")?
        .status,
        400
    );
    assert_eq!(serde_json::to_vec(&state)?, before);
    let malformed = call(
        &mut state,
        &parent,
        "",
        "POST",
        "auth/token/create/delegated",
        json!({"no_parent":"yes"}),
        100,
    )
    .err()
    .ok_or("role bypassed request field conversion")?;
    assert_eq!(malformed.status, 400);
    assert!(
        malformed
            .message
            .contains("error converting input for field \"no_parent\"")
    );
    assert_eq!(serde_json::to_vec(&state)?, before);
    let (_, _, nonrenewable) = issued(
        &mut state,
        &root,
        "auth/token/create",
        json!({"policies":["p-one"],"ttl":30,"renewable":"false","no_parent":"false"}),
    )?;
    assert_eq!(nonrenewable["auth"]["renewable"], false);
    call(
        &mut state,
        &root,
        "",
        "POST",
        "auth/token/roles/root-allowed",
        json!({"allowed_policies":["root"]}),
        100,
    )?;
    let before = serde_json::to_vec(&state)?;
    let e = call(
        &mut state,
        &parent,
        "",
        "POST",
        "auth/token/create/root-allowed",
        json!({"policies":["root"]}),
        100,
    )
    .err()
    .ok_or("role granted root without root parent")?;
    assert_eq!(e.status, 400);
    assert_eq!(
        e.message,
        "root tokens may not be created without parent token being root"
    );
    assert_eq!(serde_json::to_vec(&state)?, before);
    let (no_create, _, _) = issued(
        &mut state,
        &root,
        "auth/token/create",
        json!({"policies":["p-one"],"no_default_policy":true}),
    )?;
    assert_eq!(
        call(
            &mut state,
            &no_create,
            "",
            "POST",
            "auth/token/create/delegated",
            json!({}),
            100
        )
        .err()
        .ok_or("role bypassed route ACL")?
        .status,
        403
    );
    Ok(())
}
#[test]
fn token_role_globs_disallowed_and_unrestricted_default_follow_reference() -> TestResult {
    let (mut state, root) = setup()?;
    call(
        &mut state,
        &root,
        "",
        "POST",
        "auth/token/roles/glob",
        json!({"allowed_policies_glob":["p-*"],"disallowed_policies":["p-two"]}),
        100,
    )?;
    let (_, _, empty) = issued(&mut state, &root, "auth/token/create/glob", json!({}))?;
    assert_eq!(empty["auth"]["policies"], json!(["default"]));
    let (_, _, named) = issued(
        &mut state,
        &root,
        "auth/token/create/glob",
        json!({"policies":["P-ONE"]}),
    )?;
    assert_eq!(named["auth"]["policies"], json!(["default", "p-one"]));
    let before = serde_json::to_vec(&state)?;
    let e = call(
        &mut state,
        &root,
        "",
        "POST",
        "auth/token/create/glob",
        json!({"policies":["p-two"]}),
        100,
    )
    .err()
    .ok_or("disallowed role policy")?;
    assert_eq!(
        e.message,
        "token policy \"p-two\" is disallowed by this role"
    );
    assert_eq!(serde_json::to_vec(&state)?, before);
    call(
        &mut state,
        &root,
        "",
        "POST",
        "auth/token/roles/plain",
        json!({"token_no_default_policy":true}),
        100,
    )?;
    let (_, _, named) = issued(
        &mut state,
        &root,
        "auth/token/create/plain",
        json!({"policies":["p-one"]}),
    )?;
    assert_eq!(named["auth"]["policies"], json!(["default", "p-one"]));
    Ok(())
}
#[test]
fn token_role_renewal_uses_current_role_and_deleted_role_preserves_live_token() -> TestResult {
    let (mut state, root) = setup()?;
    call(
        &mut state,
        &root,
        "",
        "POST",
        "auth/token/roles/periodic",
        json!({"allowed_policies":["p-one"],"token_period":30,"token_explicit_max_ttl":90}),
        100,
    )?;
    let (child, raw, body) = issued(
        &mut state,
        &root,
        "auth/token/create/periodic",
        json!({"policies":["p-one"],"ttl":60,"period":45,"explicit_max_ttl":75}),
    )?;
    assert_eq!(body["auth"]["lease_duration"], 30);
    assert_eq!(state.tokens[&child.digest].period, 45);
    let lookup = call(
        &mut state,
        &root,
        "",
        "POST",
        "auth/token/lookup",
        json!({"token":raw}),
        100,
    )?
    .body["data"]
        .clone();
    assert_eq!(lookup["period"], 45);
    assert_eq!(lookup["explicit_max_ttl"], 75);
    assert_eq!(lookup["creation_ttl"], 30);
    assert_eq!(lookup["role"], "periodic");
    call(
        &mut state,
        &root,
        "",
        "POST",
        "auth/token/roles/periodic",
        json!({"token_period":20,"token_explicit_max_ttl":40}),
        100,
    )?;
    assert_eq!(
        call(
            &mut state,
            &root,
            "",
            "POST",
            "auth/token/renew",
            json!({"token":raw,"increment":5}),
            101
        )?
        .body["auth"]["lease_duration"],
        20
    );
    call(
        &mut state,
        &root,
        "",
        "DELETE",
        "auth/token/roles/periodic",
        json!({}),
        101,
    )?;
    assert_eq!(
        call(
            &mut state,
            &root,
            "",
            "POST",
            "auth/token/lookup",
            json!({"token":raw}),
            102
        )?
        .status,
        200
    );
    let before = serde_json::to_vec(&state)?;
    let e = call(
        &mut state,
        &root,
        "",
        "POST",
        "auth/token/renew",
        json!({"token":raw}),
        102,
    )
    .err()
    .ok_or("deleted role renewed token")?;
    assert_eq!(e.status, 500);
    assert!(
        e.message
            .contains("original token role \"periodic\" could not be found, not renewing")
    );
    assert_eq!(serde_json::to_vec(&state)?, before);
    let reopened: AuthState = serde_json::from_slice(&before)?;
    reopened.validate_token_role_state()?;
    assert!(reopened.has_token_role_state());
    assert_eq!(
        reopened
            .active_token(&child.digest, 121, false)
            .err()
            .ok_or("expired role token admitted")?
            .status,
        403
    );
    Ok(())
}
#[test]
fn token_role_fixed_type_and_batch_role_uses_follow_issuance_and_lookup_contract() -> TestResult {
    let (mut state, root) = setup()?;
    call(
        &mut state,
        &root,
        "",
        "POST",
        "auth/token/roles/service",
        json!({"token_type":"service"}),
        100,
    )?;
    let (_, _, body) = issued(
        &mut state,
        &root,
        "auth/token/create/service",
        json!({"type":"batch","policies":["p-one"]}),
    )?;
    assert_eq!(body["auth"]["token_type"], "service");
    call(
        &mut state,
        &root,
        "",
        "POST",
        "auth/token/roles/batch",
        json!({"token_type":"batch","orphan":true,"renewable":false,"token_num_uses":2}),
        100,
    )?;
    let records = state.tokens.len();
    let mut grant = call(
        &mut state,
        &root,
        "",
        "POST",
        "auth/token/create/batch",
        json!({"policies":["p-one"]}),
        100,
    )?;
    assert_eq!(grant.status, 200);
    assert_eq!(grant.body["auth"]["num_uses"], 2);
    state.finish_pending_batch(&mut grant, "", 100)?;
    let raw = grant.body["auth"]["client_token"]
        .as_str()
        .ok_or("sealed role batch grant")?;
    let info = call(
        &mut state,
        &root,
        "",
        "POST",
        "auth/token/lookup",
        json!({"token":raw}),
        100,
    )?
    .body["data"]
        .clone();
    assert_eq!(info["num_uses"], 0);
    assert_eq!(info["role"], "batch");
    assert_eq!(info["path"], "auth/token/create/batch");
    assert_eq!(state.tokens.len(), records);
    let before = serde_json::to_vec(&state)?;
    let failure = call(
        &mut state,
        &root,
        "",
        "POST",
        "auth/token/create/batch",
        json!({"policies":["p-one"],"num_uses":1}),
        100,
    )
    .err()
    .ok_or("batch request num_uses bypassed")?;
    assert_eq!(failure.status, 400);
    assert_eq!(failure.message, "batch tokens cannot have \"num_uses\" set");
    assert_eq!(serde_json::to_vec(&state)?, before);
    call(
        &mut state,
        &root,
        "",
        "POST",
        "auth/token/roles/limited",
        json!({"token_num_uses":2}),
        100,
    )?;
    let (child, _, _) = issued(
        &mut state,
        &root,
        "auth/token/create/limited",
        json!({"policies":["p-one"],"num_uses":4}),
    )?;
    assert_eq!(state.tokens[&child.digest].uses_remaining, Some(1));
    Ok(())
}

#[test]
fn token_role_cidr_authority_uses_trusted_peer_and_role_child_owns_its_bounds() -> TestResult {
    let (mut state, root) = setup()?;
    call(
        &mut state,
        &root,
        "",
        "POST",
        "auth/token/roles/bound",
        json!({"allowed_policies":["creator","p-one"],"token_bound_cidrs":["192.0.2.0/24"]}),
        100,
    )?;
    let response = call(
        &mut state,
        &root,
        "",
        "POST",
        "auth/token/create/bound",
        json!({"no_default_policy":true}),
        100,
    )?;
    let raw = response.body["auth"]["client_token"]
        .as_str()
        .ok_or("bounded grant")?
        .to_owned();
    assert_eq!(
        state
            .authenticate_from(&raw, 100, Some("198.51.100.1".parse()?))
            .err()
            .ok_or("wrong peer admitted")?
            .status,
        403
    );
    let parent = state.authenticate_from(&raw, 100, Some("192.0.2.10".parse()?))?;
    call(
        &mut state,
        &root,
        "",
        "POST",
        "auth/token/roles/unbound",
        json!({"allowed_policies":["p-one"]}),
        100,
    )?;
    let response = call(
        &mut state,
        &parent,
        "",
        "POST",
        "auth/token/create/unbound",
        json!({"no_default_policy":true}),
        100,
    )?;
    let raw = response.body["auth"]["client_token"]
        .as_str()
        .ok_or("role-owned child grant")?;
    let child = state.authenticate_from(raw, 100, Some("198.51.100.1".parse()?))?;
    assert!(state.tokens[&child.digest].bound_cidrs.is_empty());
    state.authorize_request(&child, "", "probe/allowed", "read", 100)?;
    Ok(())
}
#[test]
fn token_role_forged_client_provenance_and_persisted_issuer_path_are_refused() -> TestResult {
    let (mut state, root) = setup()?;
    let before = serde_json::to_vec(&state)?;
    assert_eq!(call(&mut state,&root,"","POST","auth/token/create",json!({"policies":["p-one"],"token_role":{"name":"unowned","path":"auth/token/create/unowned"}}),100).err().ok_or("client manufactured provenance")?.status,400);
    assert_eq!(serde_json::to_vec(&state)?, before);
    call(
        &mut state,
        &root,
        "",
        "POST",
        "auth/token/roles/owned",
        json!({"allowed_policies":["p-one"]}),
        100,
    )?;
    let (child, _, _) = issued(
        &mut state,
        &root,
        "auth/token/create/owned",
        json!({"no_default_policy":true}),
    )?;
    let mut invalid = state.clone();
    invalid
        .tokens
        .get_mut(&child.digest)
        .ok_or("issued token")?
        .token_role
        .as_mut()
        .ok_or("issued role")?
        .path = "auth/token/create/owned-forged".into();
    assert!(invalid.validate_token_role_state().is_err());
    let mut invalid = state.clone();
    invalid
        .tokens
        .get_mut(&child.digest)
        .ok_or("issued token")?
        .auth_provenance = None;
    assert!(invalid.validate_token_role_state().is_err());
    state.validate_token_role_state()?;
    Ok(())
}

#[test]
fn token_api_unicode_batch_uses_resolved_names_and_never_accepts_client_provenance() -> TestResult {
    let (mut state, root) = setup()?;
    assert!(!state.has_token_api_schema80_state());
    let mut ordinary = call(
        &mut state,
        &root,
        "",
        "POST",
        "auth/token/create",
        json!({"type":"batch","policies":["Σ","x,y"],"no_default_policy":true,"ttl":"60s"}),
        100,
    )?;
    assert!(state.has_token_api_schema80_state());
    assert!(!state.has_token_role_state());
    assert_eq!(ordinary.body["auth"]["token_policies"], json!(["x,y", "σ"]));
    assert_eq!(
        ordinary.body["warnings"],
        json!([
            "Policy \"x,y\" does not exist",
            "Policy \"σ\" does not exist"
        ])
    );
    state.finish_pending_batch(&mut ordinary, "", 100)?;
    let raw = ordinary.body["auth"]["client_token"]
        .as_str()
        .ok_or("ordinary batch")?;
    let reopened: AuthState = serde_json::from_slice(&serde_json::to_vec(&state)?)?;
    assert!(reopened.has_token_api_schema80_state());
    let verified = reopened
        .authenticate_read_only(raw, 100)?
        .ok_or("read-only batch admission")?;
    assert_eq!(
        verified.policies(),
        &BTreeSet::from(["x,y".into(), "σ".into()])
    );
    let before = serde_json::to_vec(&state)?;
    let forged = call(
        &mut state,
        &root,
        "",
        "POST",
        "auth/token/create",
        json!({"type":"batch","policies":["p-one"],"token_api_policy_names":true}),
        100,
    )
    .err()
    .ok_or("client marker accepted")?;
    assert_eq!(forged.status, 400);
    assert_eq!(serde_json::to_vec(&state)?, before);
    call(
        &mut state,
        &root,
        "",
        "POST",
        "auth/token/roles/unicode",
        json!({"token_type":"batch","orphan":true,"renewable":false,"allowed_policies":["Σ","x,y"]}),
        100,
    )?;
    let mut role = call(
        &mut state,
        &root,
        "",
        "POST",
        "auth/token/create/unicode",
        json!({"policies":["Σ","x,y"],"no_default_policy":true}),
        100,
    )?;
    state.finish_pending_batch(&mut role, "", 100)?;
    let raw = role.body["auth"]["client_token"]
        .as_str()
        .ok_or("role batch")?;
    let info = call(
        &mut state,
        &root,
        "",
        "POST",
        "auth/token/lookup",
        json!({"token":raw}),
        100,
    )?;
    assert_eq!(info.body["data"]["role"], "unicode");
    assert_eq!(info.body["data"]["policies"], json!(["x,y", "σ"]));
    Ok(())
}

#[test]
fn token_role_framework_weak_fields_preserve_duration_units_integer_bases_and_atomic_errors()
-> TestResult {
    let (mut state, root) = setup()?;
    call(
        &mut state,
        &root,
        "",
        "POST",
        "auth/token/roles/weak",
        json!({"token_period":"1h2m3.5s","token_num_uses":"0x10","orphan":"true"}),
        100,
    )?;
    let read = call(
        &mut state,
        &root,
        "",
        "GET",
        "auth/token/roles/weak",
        json!({}),
        100,
    )?;
    assert_eq!(read.body["data"]["token_period"], 3723);
    assert_eq!(read.body["data"]["token_num_uses"], 16);
    assert_eq!(read.body["data"]["orphan"], true);
    for (value, seconds) in [
        (json!("1.5s"), 1),
        (json!("2500ms"), 2),
        (json!("-0.5s"), 0),
        (json!("2d"), 172800),
    ] {
        call(
            &mut state,
            &root,
            "",
            "POST",
            "auth/token/roles/weak",
            json!({"token_period":value}),
            100,
        )?;
        assert_eq!(
            call(
                &mut state,
                &root,
                "",
                "GET",
                "auth/token/roles/weak",
                json!({}),
                100
            )?
            .body["data"]["token_period"],
            seconds
        );
    }
    for (value, uses) in [
        (json!("010"), 8),
        (json!("0b11"), 3),
        (json!("0o11"), 9),
        (json!("1_000"), 1000),
        (json!(""), 0),
    ] {
        call(
            &mut state,
            &root,
            "",
            "POST",
            "auth/token/roles/weak",
            json!({"token_num_uses":value}),
            100,
        )?;
        let actual = call(
            &mut state,
            &root,
            "",
            "GET",
            "auth/token/roles/weak",
            json!({}),
            100,
        )?;
        if uses == 0 {
            assert!(actual.body["data"].get("token_num_uses").is_none());
        } else {
            assert_eq!(actual.body["data"]["token_num_uses"], uses);
        }
    }
    let before = serde_json::to_vec(&state)?;
    for (body, message) in [
        (
            json!({"orphan":[]}),
            "error converting input for field \"orphan\": '' expected type 'bool', got unconvertible type '[]interface {}'",
        ),
        (
            json!({"renewable":-1}),
            "error converting input for field \"renewable\": '' cannot parse value as 'bool': strconv.ParseBool: invalid syntax",
        ),
        (
            json!({"token_num_uses":1.5}),
            "error converting input for field \"token_num_uses\": '' cannot parse value as 'int': strconv.ParseInt: invalid syntax",
        ),
        (
            json!({"token_num_uses":"9223372036854775808"}),
            "error converting input for field \"token_num_uses\": '' cannot parse value as 'int': strconv.ParseInt: value out of range",
        ),
        (
            json!({"token_num_uses":-1}),
            "error parsing role fields: 'token_num_uses' cannot be negative",
        ),
        (
            json!({"token_period":true}),
            "error converting input for field \"token_period\": could not parse duration from input",
        ),
        (
            json!({"token_period":1.5}),
            "error converting input for field \"token_period\": time: missing unit in duration \"1.5\"",
        ),
        (
            json!({"token_period":"1.5d"}),
            "error converting input for field \"token_period\": strconv.ParseInt: parsing \"1.5\": invalid syntax",
        ),
        (
            json!({"token_period":"9223372037s"}),
            "error converting input for field \"token_period\": time: invalid duration \"9223372037s\"",
        ),
        (
            json!({"token_period":"-1.5s"}),
            "error converting input for field \"token_period\": cannot provide negative value '-1'",
        ),
    ] {
        let failure = call(
            &mut state,
            &root,
            "",
            "POST",
            "auth/token/roles/weak",
            body,
            100,
        )
        .err()
        .ok_or("invalid field updated role")?;
        assert_eq!(failure.status, 400);
        assert_eq!(failure.message, message);
        assert_eq!(serde_json::to_vec(&state)?, before);
    }
    let ordinary = call(
        &mut state,
        &root,
        "",
        "POST",
        "auth/token/create",
        json!({"policies":["p-one"],"renewable":[]}),
        100,
    )
    .err()
    .ok_or("ordinary type error accepted")?;
    assert!(ordinary.message.starts_with("Field validation failed: "));
    assert_eq!(serde_json::to_vec(&state)?, before);
    let mut reopened: AuthState = serde_json::from_slice(&before)?;
    reopened.validate_token_role_state()?;
    assert_eq!(
        call(
            &mut reopened,
            &root,
            "",
            "GET",
            "auth/token/roles/weak",
            json!({}),
            100
        )?
        .body["data"]["token_period"],
        172800
    );
    Ok(())
}

#[test]
fn token_role_list_weak_fields_and_cidr_errors_are_atomic_and_durable() -> TestResult {
    let (mut state, root) = setup()?;
    call(
        &mut state,
        &root,
        "",
        "POST",
        "auth/token/roles/weak-lists",
        json!({"allowed_policies":[" P-ONE ",2,true,null,"Σ","X,Y"],"allowed_entity_aliases":{},"path_suffix":123,"token_bound_cidrs":" 127.0.0.2/24 , ::1/128 "}),
        100,
    )?;
    let info = call(
        &mut state,
        &root,
        "",
        "GET",
        "auth/token/roles/weak-lists",
        json!({}),
        100,
    )?
    .body["data"]
        .clone();
    assert_eq!(
        info["allowed_policies"],
        json!(["1", "2", "p-one", "x,y", "σ"])
    );
    assert_eq!(info["allowed_entity_aliases"], json!([]));
    assert_eq!(info["path_suffix"], "123");
    assert_eq!(info["token_bound_cidrs"], json!(["127.0.0.2/24", "::1"]));
    let before = serde_json::to_vec(&state)?;
    for (body, expected) in [
        (
            json!({"renewable":false,"allowed_policies":[{"a":1}]}),
            "error converting input for field \"allowed_policies\": 1 error(s) decoding:\n\n* '[0]' expected type 'string', got unconvertible type 'map[string]interface {}', value: 'map[a:1]'",
        ),
        (
            json!({"token_bound_cidrs":["127.0.0.1/32",123]}),
            "error parsing role fields: error parsing address \"123\": Unable to convert \"123\" to an IPv4 or IPv6 address, or a UNIX Socket",
        ),
        (
            json!({"bound_cidrs":true}),
            "error parsing bound_cidrs: error parsing address \"1\": Unable to convert \"1\" to an IPv4 or IPv6 address, or a UNIX Socket",
        ),
        (
            json!({"path_suffix":[]}),
            "error converting input for field \"path_suffix\": '' expected type 'string', got unconvertible type '[]interface {}'",
        ),
        (
            json!({"token_type":{}}),
            "error converting input for field \"token_type\": '' expected type 'string', got unconvertible type 'map[string]interface {}'",
        ),
    ] {
        let e = call(
            &mut state,
            &root,
            "",
            "POST",
            "auth/token/roles/weak-lists",
            body,
            100,
        )
        .err()
        .ok_or("invalid role field was admitted")?;
        assert_eq!(e.status, 400);
        assert_eq!(e.message, expected);
        assert_eq!(serde_json::to_vec(&state)?, before);
    }
    call(
        &mut state,
        &root,
        "",
        "POST",
        "auth/token/roles/weak-lists",
        json!({"token_bound_cidrs":null,"allowed_policies":true,"path_suffix":null}),
        100,
    )?;
    let reopened: AuthState = serde_json::from_slice(&serde_json::to_vec(&state)?)?;
    reopened.validate_token_role_state()?;
    assert!(reopened.has_token_api_schema80_state());
    let read = reopened.token_roles[""]["weak-lists"].info("weak-lists");
    assert_eq!(read["allowed_policies"], json!(["1"]));
    assert_eq!(read["path_suffix"], "");
    assert!(read.get("token_bound_cidrs").is_none());
    Ok(())
}
