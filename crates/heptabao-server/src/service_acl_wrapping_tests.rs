//! Real Service-boundary checks. All tokens, data and storage are synthetic.
use super::*;

fn wrapped(
    s: &mut Service,
    token: &str,
    method: &str,
    path: &str,
    body: Value,
    ttl: Option<u64>,
) -> Response {
    let mut request = ServiceRequest::new(method, path, "", token, body);
    request.wrap_ttl_seconds = ttl;
    s.handle_request_at(request, 100)
}

fn install(s: &mut Service, admin: &str, name: &str, source: &str) {
    assert_eq!(
        call(
            s,
            "PUT",
            &format!("sys/policies/acl/{name}"),
            admin,
            json!({"policy":source})
        )
        .status,
        204
    );
}

fn issue(
    s: &mut Service,
    admin: &str,
    policies: &[&str],
    batch: bool,
    uses: u64,
) -> TestResult<String> {
    let response = call(
        s,
        "POST",
        "auth/token/create",
        admin,
        json!({
            "policies":policies,"no_default_policy":!policies.contains(&"default"),"ttl":"10m",
            "type":if batch {"batch"} else {"service"},"num_uses":uses
        }),
    );
    assert_eq!(response.status, 200);
    Ok(response.body["auth"]["client_token"]
        .as_str()
        .ok_or("token")?
        .into())
}

fn fresh() -> TestResult<(Root, Service, String, String)> {
    let root = Root::new();
    let mut service = root.service()?;
    let (key, admin) = bootstrap(&mut service)?;
    assert_eq!(
        call(
            &mut service,
            "POST",
            "secret/data/item",
            &admin,
            json!({"data":{"synthetic":"original"}})
        )
        .status,
        200
    );
    Ok((root, service, key, admin))
}

fn read_original(s: &mut Service, admin: &str) {
    let response = call(s, "GET", "secret/data/item", admin, json!({}));
    assert_eq!(response.status, 200);
    assert_eq!(
        response.body["data"]["data"],
        json!({"synthetic":"original"})
    );
    assert_eq!(response.body["data"]["metadata"]["version"], 1);
}

#[test]
fn acl_wrapping_bounds_distinguish_absent_zero_and_positive_for_service_and_batch() -> TestResult {
    for batch in [false, true] {
        let (_root, mut service, _, admin) = fresh()?;
        for (name, min, max) in [
            ("min", 10, 0),
            ("max", 0, 30),
            ("range", 10, 30),
            ("zero", 0, 0),
        ] {
            install(
                &mut service,
                &admin,
                name,
                &format!(
                    "path \"secret/data/item\" {{ capabilities=[\"read\"] min_wrapping_ttl={min} max_wrapping_ttl={max} }}"
                ),
            );
            let token = issue(&mut service, &admin, &[name], batch, 0)?;
            for ttl in [
                None,
                Some(0),
                Some(9),
                Some(10),
                Some(20),
                Some(30),
                Some(31),
            ] {
                let allowed = min == 0 && max == 0
                    || ttl.is_some_and(|ttl| ttl >= min && (max == 0 || ttl <= max));
                let response = wrapped(
                    &mut service,
                    &token,
                    "GET",
                    "secret/data/item",
                    json!({}),
                    ttl,
                );
                assert_eq!(
                    response.status,
                    if allowed { 200 } else { 403 },
                    "{name} {ttl:?} batch={batch}"
                );
                if !allowed {
                    assert!(response.body.get("wrap_info").is_none_or(Value::is_null));
                    assert!(response.body.get("data").is_none_or(Value::is_null));
                } else if ttl.is_some_and(|ttl| ttl > 0) {
                    assert_eq!(response.body["wrap_info"]["ttl"], ttl.ok_or("ttl")?);
                    assert!(response.body.get("data").is_none_or(Value::is_null));
                    let bearer = response.body["wrap_info"]["token"]
                        .as_str()
                        .ok_or("wrapper")?;
                    let value = call(
                        &mut service,
                        "POST",
                        "sys/wrapping/unwrap",
                        bearer,
                        json!({}),
                    );
                    assert_eq!(value.status, 200);
                    assert_eq!(value.body["data"]["data"], json!({"synthetic":"original"}));
                    assert_eq!(
                        call(
                            &mut service,
                            "POST",
                            "sys/wrapping/unwrap",
                            bearer,
                            json!({})
                        )
                        .status,
                        400
                    );
                } else {
                    assert!(response.body.get("wrap_info").is_none_or(Value::is_null));
                    assert_eq!(
                        response.body["data"]["data"],
                        json!({"synthetic":"original"})
                    );
                }
            }
        }
    }
    Ok(())
}

#[test]
fn acl_wrapping_constraints_precede_write_delete_list_and_scan_effects() -> TestResult {
    let (_root, mut service, _, admin) = fresh()?;
    install(
        &mut service,
        &admin,
        "bounds",
        r#"
path "secret/data/item" { capabilities=["read","create","update","delete"] min_wrapping_ttl=10 max_wrapping_ttl=30 }
path "secret/metadata/*" { capabilities=["list","scan"] min_wrapping_ttl=10 }
"#,
    );
    let token = issue(&mut service, &admin, &["bounds"], false, 0)?;
    for method in ["POST", "PUT", "DELETE"] {
        for ttl in [None, Some(0), Some(9), Some(31)] {
            let before = service.current_state_digest().map_err(|_| "state digest")?;
            let response = wrapped(
                &mut service,
                &token,
                method,
                "secret/data/item",
                json!({"data":{"synthetic":"forbidden"}}),
                ttl,
            );
            assert_eq!(
                response.status, 403,
                "failed wrapping bounds must reject before any mutation"
            );
            assert_eq!(
                service.current_state_digest().map_err(|_| "after digest")?,
                before
            );
            read_original(&mut service, &admin);
        }
    }
    for method in ["LIST", "SCAN"] {
        for ttl in [None, Some(0), Some(9)] {
            assert_eq!(
                wrapped(
                    &mut service,
                    &token,
                    method,
                    "secret/metadata/",
                    json!({}),
                    ttl
                )
                .status,
                403
            );
        }
        let response = wrapped(
            &mut service,
            &token,
            method,
            "secret/metadata/",
            json!({}),
            Some(10),
        );
        assert_eq!(response.status, 200);
        let bearer = response.body["wrap_info"]["token"]
            .as_str()
            .ok_or("list wrapper")?;
        let response = call(
            &mut service,
            "POST",
            "sys/wrapping/unwrap",
            bearer,
            json!({}),
        );
        assert_eq!(response.status, 200);
        assert_eq!(response.body["data"]["keys"], json!(["item"]));
    }
    let deleted = wrapped(
        &mut service,
        &token,
        "DELETE",
        "secret/data/item",
        json!({}),
        Some(20),
    );
    assert_eq!(deleted.status, 204);
    assert!(deleted.body.get("wrap_info").is_none_or(Value::is_null));
    assert_eq!(
        call(&mut service, "GET", "secret/data/item", &admin, json!({})).status,
        404
    );
    Ok(())
}

#[test]
fn acl_wrapping_same_path_union_uses_native_nonzero_minima_but_not_broad_rules() -> TestResult {
    let (_root, mut service, _, admin) = fresh()?;
    for (name, source) in [
        (
            "narrow",
            r#"path "secret/data/item" { capabilities=["read"] min_wrapping_ttl=10 max_wrapping_ttl=30 }"#,
        ),
        (
            "wide",
            r#"path "secret/data/item" { capabilities=["read"] min_wrapping_ttl=40 max_wrapping_ttl=50 }"#,
        ),
        (
            "broad",
            r#"path "*" { capabilities=["read"] min_wrapping_ttl=90 }"#,
        ),
        (
            "conflict-min",
            r#"path "secret/data/item" { capabilities=["read"] min_wrapping_ttl=40 }"#,
        ),
        (
            "conflict-max",
            r#"path "secret/data/item" { capabilities=["read"] max_wrapping_ttl=30 }"#,
        ),
    ] {
        install(&mut service, &admin, name, source);
    }
    for policies in [
        &["narrow", "wide", "broad"][..],
        &["wide", "broad", "narrow"][..],
    ] {
        let token = issue(&mut service, &admin, policies, false, 0)?;
        assert_eq!(
            wrapped(
                &mut service,
                &token,
                "GET",
                "secret/data/item",
                json!({}),
                Some(20)
            )
            .status,
            200
        );
        assert_eq!(
            wrapped(
                &mut service,
                &token,
                "GET",
                "secret/data/item",
                json!({}),
                Some(31)
            )
            .status,
            403
        );
    }
    let conflict = issue(
        &mut service,
        &admin,
        &["conflict-min", "conflict-max"],
        false,
        0,
    )?;
    assert_eq!(
        wrapped(
            &mut service,
            &conflict,
            "GET",
            "secret/data/item",
            json!({}),
            Some(40)
        )
        .status,
        403
    );
    Ok(())
}

#[test]
fn acl_wrapping_default_specificity_and_parameter_constraints_remain_independent() -> TestResult {
    let (_root, mut service, _, admin) = fresh()?;
    install(
        &mut service,
        &admin,
        "broad",
        r#"path "*" { capabilities=["read","update"] min_wrapping_ttl=60 required_parameters=["never"] }"#,
    );
    let token = issue(&mut service, &admin, &["default", "broad"], false, 0)?;
    assert_eq!(
        call(
            &mut service,
            "GET",
            "auth/token/lookup-self",
            &token,
            json!({})
        )
        .status,
        200,
        "the default exact path must beat broad body and wrapping constraints"
    );
    install(
        &mut service,
        &admin,
        "parameters",
        r#"path "secret/data/item" { capabilities=["read"] min_wrapping_ttl=10 required_parameters=["version"] }"#,
    );
    let token = issue(&mut service, &admin, &["parameters"], false, 0)?;
    assert_eq!(
        wrapped(
            &mut service,
            &token,
            "GET",
            "secret/data/item",
            json!({}),
            Some(10)
        )
        .status,
        403
    );
    assert_eq!(
        wrapped(
            &mut service,
            &token,
            "GET",
            "secret/data/item",
            json!({"version":1}),
            None
        )
        .status,
        403
    );
    assert_eq!(
        wrapped(
            &mut service,
            &token,
            "GET",
            "secret/data/item",
            json!({"version":1}),
            Some(10)
        )
        .status,
        200
    );
    // Capability reporting describes grants, not satisfaction of a request's
    // wrapping conditions; the actual request above still enforces both.
    let caps = call(
        &mut service,
        "POST",
        "sys/capabilities",
        &admin,
        json!({"token":token,"path":"secret/data/item"}),
    );
    assert_eq!(caps.status, 200);
    assert_eq!(caps.body["data"]["capabilities"], json!(["read"]));
    Ok(())
}

#[test]
fn acl_wrapping_retained_actor_rechecks_current_bounds_before_late_delivery() -> TestResult {
    let (_root, mut service, _, admin) = fresh()?;
    install(
        &mut service,
        &admin,
        "late",
        r#"path "secret/data/item" { capabilities=["read"] min_wrapping_ttl=10 max_wrapping_ttl=30 }"#,
    );
    let token = issue(&mut service, &admin, &["late"], false, 0)?;
    let before = service.state.as_mut().ok_or("state")?;
    let mut actor = before.auth.authenticate(&token, 100)?;
    actor.bind_request_wrapping_ttl(Some(20));
    before
        .auth
        .authorize_request(&actor, "", "secret/data/item", "read", 100)?;
    install(
        &mut service,
        &admin,
        "late",
        r#"path "secret/data/item" { capabilities=["read"] min_wrapping_ttl=25 max_wrapping_ttl=30 }"#,
    );
    let state = service.state.as_ref().ok_or("state")?;
    assert!(
        state
            .auth
            .authorize_request(&actor, "", "secret/data/item", "read", 100)
            .is_err()
    );
    assert!(
        state
            .auth
            .authorize_request_parameters(&actor, "", "GET", "secret/data/item", &json!({}), 100)
            .is_err()
    );
    read_original(&mut service, &admin);
    Ok(())
}

#[test]
fn acl_wrapping_schema61_is_independent_and_schema60_promotes_only_on_mutation() -> TestResult {
    let (root, mut service, key, admin) = fresh()?;
    let mut legacy = service.state.clone().ok_or("state")?;
    legacy.schema = 60;
    assert!(!legacy.auth.has_acl_wrapping_ttl_state());
    legacy.validate_format().map_err(|_| "legacy validation")?;
    crate::service::tests::commit_legacy_state_fixture(&mut service, &legacy)
        .map_err(|_| "publish schema60")?;
    service.state = Some(legacy);
    drop(service);
    let mut service = root.service()?;
    assert_eq!(
        call(&mut service, "POST", "sys/unseal", "", json!({"key":key})).status,
        200
    );
    read_original(&mut service, &admin);
    assert_eq!(service.state.as_ref().ok_or("state")?.schema, 60);
    install(
        &mut service,
        &admin,
        "persisted",
        r#"path "secret/data/item" { capabilities=["read"] max_wrapping_ttl="30s" }"#,
    );
    let token = issue(&mut service, &admin, &["persisted"], false, 0)?;
    let state = service.state.as_ref().ok_or("state")?;
    assert_eq!(state.schema, CURRENT_STATE_SCHEMA);
    assert!(state.auth.has_acl_wrapping_ttl_state());
    assert!(!state.auth.has_acl_template_state());
    let mut disguised = state.clone();
    disguised.schema = 60;
    let rejected = disguised.validate_format().err().ok_or("missing fence")?;
    assert_eq!(
        rejected.body["errors"][0],
        "ACL wrapping TTL constraints require schema 61"
    );
    drop(service);
    let mut service = root.service()?;
    assert_eq!(
        call(&mut service, "POST", "sys/unseal", "", json!({"key":key})).status,
        200
    );
    assert_eq!(
        wrapped(
            &mut service,
            &token,
            "GET",
            "secret/data/item",
            json!({}),
            None
        )
        .status,
        403
    );
    assert_eq!(
        wrapped(
            &mut service,
            &token,
            "GET",
            "secret/data/item",
            json!({}),
            Some(0)
        )
        .status,
        200
    );
    assert_eq!(
        wrapped(
            &mut service,
            &token,
            "GET",
            "secret/data/item",
            json!({}),
            Some(31)
        )
        .status,
        403
    );
    Ok(())
}
