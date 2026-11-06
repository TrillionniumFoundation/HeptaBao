//! Real native File operations in a cataloged child; no direct state grants.
use super::*;

fn scoped_call(
    fixture: &mut NativeFixture,
    namespace: &str,
    token: &str,
    method: &str,
    path: &str,
    body: Value,
) -> TestResult<Response> {
    fixture.now += 1;
    let started = Instant::now();
    let _deadline =
        crate::request_deadline::RequestDeadlineScope::enter(started + Duration::from_secs(15));
    let clock = RequestClock::anchored(Duration::from_secs(fixture.now), started)?;
    let execution = fixture.service.begin_at_mode_precise(
        RequestDispatch {
            method,
            path,
            namespace,
            token,
            body,
            now: fixture.now,
            allow_forward: true,
            enforce_namespace: true,
            wrap_ttl_seconds: None,
            origin_peer: None,
            client_certificates: None,
        },
        clock,
    );
    Ok(fixture.service.finish_synchronous_request(execution))
}

fn child_admin(
    fixture: &mut NativeFixture,
    namespace: &str,
    method: &str,
    path: &str,
    body: Value,
) -> TestResult<Response> {
    let admin = Zeroizing::new(fixture.admin.to_string());
    scoped_call(fixture, namespace, &admin, method, path, body)
}

fn child_login(
    f: &mut NativeFixture,
    namespace: &str,
    name: &str,
    policy: &str,
) -> TestResult<Login> {
    let path = format!("auth/cg-child/role/{name}");
    assert_eq!(
        child_admin(
            f,
            namespace,
            "POST",
            &path,
            json!({"token_policies":[policy],"secret_id_num_uses":1,
            "token_no_default_policy":true,"token_ttl":"1h"})
        )?
        .status,
        204
    );
    let role_id = child_admin(f, namespace, "GET", &format!("{path}/role-id"), json!({}))?;
    assert_eq!(role_id.status, 200);
    let role_id = Zeroizing::new(text(&role_id.body, "/data/role_id")?);
    let secret_id = child_admin(
        f,
        namespace,
        "POST",
        &format!("{path}/secret-id"),
        json!({}),
    )?;
    assert_eq!(secret_id.status, 200);
    let secret_id = Zeroizing::new(text(&secret_id.body, "/data/secret_id")?);
    let reply = scoped_call(
        f,
        namespace,
        "",
        "POST",
        "auth/cg-child/login",
        json!({"role_id":role_id.as_str(),"secret_id":secret_id.as_str()}),
    )?;
    assert_eq!(reply.status, 200, "real child AppRole login");
    let result = Login {
        token: Zeroizing::new(text(&reply.body, "/auth/client_token")?),
        entity: text(&reply.body, "/auth/entity_id")?,
    };
    // A second use is a deliberate known-result negative check, never a retry.
    assert_eq!(
        scoped_call(
            f,
            namespace,
            "",
            "POST",
            "auth/cg-child/login",
            json!({"role_id":role_id.as_str(),"secret_id":secret_id.as_str()})
        )?
        .status,
        400
    );
    Ok(result)
}

fn child_value(f: &mut NativeFixture, ns: &str) -> TestResult {
    let result = child_admin(f, ns, "GET", "secret/data/child-controlled", json!({}))?;
    assert_eq!(result.status, 200);
    assert_eq!(result.body["data"]["metadata"]["version"], 1);
    assert_eq!(result.body["data"]["data"]["value"], "namespace-owned");
    Ok(())
}

fn pending_snapshot(
    f: &mut NativeFixture,
    method: &str,
) -> TestResult<Box<PendingExternalRequest>> {
    match f.service.begin_native_snapshot_before(
        ServiceRequest::new(method, "sys/storage/raft/snapshot", "", &f.admin, json!({})),
        Instant::now() + Duration::from_secs(15),
    ) {
        NativeSnapshotAdmission::Execute(RequestExecution::External(plan)) => Ok(plan),
        NativeSnapshotAdmission::Execute(RequestExecution::Complete(response)) => {
            Err(format!("actual child snapshot admission status={}", response.status).into())
        }
        NativeSnapshotAdmission::Redirect(_) => Err("File snapshot unexpectedly redirected".into()),
        #[cfg(feature = "native-v6-ha")]
        NativeSnapshotAdmission::Forward(_) => Err("File snapshot unexpectedly forwarded".into()),
    }
}

// Restore an authentic pending approval before execution. The test does not
// claim that historical administrative restore preserves post-archive spends.
fn roundtrip_pending_snapshot(f: &mut NativeFixture) -> TestResult {
    let mut export = pending_snapshot(f, "GET")?;
    let (result, archive) = export.execute_snapshot_transfer(&mut std::io::empty());
    assert_eq!(
        f.service.finish_external_request(*export, result).status,
        200
    );
    let mut bytes = Zeroizing::new(Vec::new());
    archive
        .ok_or("actual child snapshot archive")?
        .read_to_end(&mut bytes)?;
    assert!(bytes.starts_with(&[0x1f, 0x8b]));
    assert_eq!(
        child_admin(
            f,
            "",
            "POST",
            "secret/data/after-child-snapshot",
            json!({"options":{"cas":0},"data":{"after_archive":true}})
        )?
        .status,
        200
    );
    let mut restore = pending_snapshot(f, "POST")?;
    let (result, output) = restore.execute_snapshot_transfer(&mut &bytes[..]);
    assert!(output.is_none());
    // This observer fires only after the real File restore outcome and live
    // state installation succeed. It cannot grant or change any operation.
    let commit_observed = std::rc::Rc::new(std::cell::Cell::new(false));
    let commit_observed_for_callback = std::rc::Rc::clone(&commit_observed);
    let commit_observer = Service::observe_next_native_snapshot_commit_for_test(move |_| {
        commit_observed_for_callback.set(true);
    })?;
    // Finalize exactly once. Keep the actual response and disclose no body.
    let response = f.service.finish_external_request(*restore, result);
    drop(commit_observer);
    let errors = response.body.get("errors").and_then(Value::as_array);
    let first_error = errors
        .and_then(|values| values.first())
        .and_then(Value::as_str);
    let first_error_bytes = first_error.unwrap_or("").as_bytes();
    eprintln!(
        "HBNS138-FILE-RESTORE-OBS status={} errors_array={} errors_count={} first_error_string={} first_error_utf8_bytes={} first_error_sha256={} commit_observed={}",
        response.status,
        errors.is_some(),
        errors.map_or(0, |values| values.len()),
        first_error.is_some(),
        first_error_bytes.len(),
        hex(&crate::crypto::digest(first_error_bytes)),
        commit_observed.get(),
    );
    assert_eq!(response.status, 200);
    assert_eq!(
        child_admin(
            f,
            "",
            "GET",
            "secret/metadata/after-child-snapshot",
            json!({})
        )?
        .status,
        404
    );
    assert!(
        f.service
            .native_root
            .as_ref()
            .ok_or("restored native root")?
            .reader_floor
            .minimum_state_schema
            >= NATIVE_PLAIN_NAMESPACE_STATE_SCHEMA
    );
    Ok(())
}

#[test]
fn native_cg271_child_scope_pending_cold_execute_and_spent_cold_are_atomic() -> TestResult {
    let mut f = setup_native(true)?;
    // Snapshot admission retains real wall time. Issue every child credential
    // from that same era instead of extending the older synthetic root actors.
    f.now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_secs();
    let ns = "cg-child";
    let sibling = "cg-sibling";
    for namespace in [ns, sibling] {
        assert_eq!(
            f.request(
                Actor::Admin,
                "POST",
                &format!("sys/namespaces/{namespace}"),
                json!({})
            )?
            .status,
            200
        );
        assert_eq!(
            child_admin(
                &mut f,
                namespace,
                "POST",
                "sys/mounts/secret",
                json!({"type":"kv","options":{"version":"2"}})
            )?
            .status,
            204
        );
        assert_eq!(
            child_admin(
                &mut f,
                namespace,
                "POST",
                "sys/auth/cg-child",
                json!({"type":"approle"})
            )?
            .status,
            204
        );
    }
    let requester_policy = r#"path "secret/data/child-controlled" {
        capabilities=["create","update","read"]
        control_group={ttl="600s" self_auth_allowed=false
            factor "review" {controlled_capabilities=["create","update","read"]
                identity {group_names=["child-reviewers"] approvals=1 self_authorization=true}
            }
        }
    }
    path "sys/control-group/request" {capabilities=["update"]}
    path "sys/control-group/authorize" {capabilities=["update"]}"#;
    let reviewer_policy = r#"path "sys/control-group/request" {capabilities=["update"]}
        path "sys/control-group/authorize" {capabilities=["update"]}
        path "sys/wrapping/unwrap" {capabilities=["update"]}"#;
    for (namespace, name, policy) in [
        (ns, "requester", requester_policy),
        (ns, "reviewer", reviewer_policy),
        (sibling, "reviewer", reviewer_policy),
    ] {
        assert_eq!(
            child_admin(
                &mut f,
                namespace,
                "PUT",
                &format!("sys/policies/acl/{name}"),
                json!({"policy":policy})
            )?
            .status,
            204
        );
    }
    let requester = child_login(&mut f, ns, "requester", "requester")?;
    let reviewer = child_login(&mut f, ns, "reviewer", "reviewer")?;
    let foreign = child_login(&mut f, sibling, "reviewer", "reviewer")?;
    assert_eq!(
        child_admin(
            &mut f,
            ns,
            "POST",
            "identity/group",
            json!({"name":"child-reviewers","type":"internal",
            "member_entity_ids":[requester.entity,reviewer.entity]})
        )?
        .status,
        200
    );
    let deferred = scoped_call(
        &mut f,
        ns,
        &requester.token,
        "POST",
        "secret/data/child-controlled",
        json!({"data":{"value":"namespace-owned"}}),
    )?;
    assert_eq!(deferred.status, 200);
    let raw = Zeroizing::new(text(&deferred.body, "/wrap_info/token")?);
    let accessor = text(&deferred.body, "/wrap_info/accessor")?;
    for wrong in ["", sibling] {
        for route in ["sys/control-group/request", "sys/control-group/authorize"] {
            let reply = child_admin(&mut f, wrong, "POST", route, json!({"accessor":accessor}))?;
            assert!(reply.status >= 400);
            assert!(reply.body["data"].is_null());
        }
        let reply = scoped_call(
            &mut f,
            wrong,
            &raw,
            "POST",
            "sys/wrapping/unwrap",
            json!({}),
        )?;
        assert!(matches!(reply.status, 400 | 403));
        for namespace in ["", ns, sibling] {
            assert_eq!(
                child_admin(
                    &mut f,
                    namespace,
                    "GET",
                    "secret/metadata/child-controlled",
                    json!({})
                )?
                .status,
                404
            );
        }
    }
    let foreign_reply = scoped_call(
        &mut f,
        ns,
        &foreign.token,
        "POST",
        "sys/control-group/authorize",
        json!({"accessor":accessor}),
    )?;
    assert_eq!(
        foreign_reply.status, 403,
        "sibling actor cannot acquire child approval authority"
    );
    let review = scoped_call(
        &mut f,
        ns,
        &reviewer.token,
        "POST",
        "sys/control-group/request",
        json!({"accessor":accessor}),
    )?;
    assert_eq!(review.status, 200);
    assert_eq!(review.body["data"]["authorizations"], json!([]));
    assert_eq!(review.body["data"]["approved"], false);
    assert_eq!(
        scoped_call(
            &mut f,
            ns,
            &requester.token,
            "POST",
            "sys/control-group/authorize",
            json!({"accessor":accessor})
        )?
        .status,
        500
    );
    let approved = scoped_call(
        &mut f,
        ns,
        &reviewer.token,
        "POST",
        "sys/control-group/authorize",
        json!({"accessor":accessor}),
    )?;
    assert_eq!(approved.status, 200);
    assert_eq!(approved.body["data"]["approved"], true);
    assert_eq!(
        child_admin(
            &mut f,
            ns,
            "GET",
            "secret/metadata/child-controlled",
            json!({})
        )?
        .status,
        404
    );
    assert!(
        f.service
            .native_root
            .as_ref()
            .ok_or("native root")?
            .reader_floor
            .minimum_state_schema
            >= NATIVE_PLAIN_NAMESPACE_STATE_SCHEMA
    );
    assert!(
        f.service
            .native_root
            .as_ref()
            .ok_or("native root")?
            .kv2
            .iter()
            .any(|g| g.scope.namespace == ns)
    );
    roundtrip_pending_snapshot(&mut f)?;
    let mut f = f.restart()?;
    let review = scoped_call(
        &mut f,
        ns,
        &reviewer.token,
        "POST",
        "sys/control-group/request",
        json!({"accessor":accessor}),
    )?;
    assert_eq!(review.status, 200);
    assert_eq!(review.body["data"]["approved"], true);
    assert_eq!(
        review.body["data"]["authorizations"]
            .as_array()
            .map(Vec::len),
        Some(1)
    );
    assert_eq!(
        child_admin(
            &mut f,
            ns,
            "GET",
            "secret/metadata/child-controlled",
            json!({})
        )?
        .status,
        404
    );
    let executed = scoped_call(&mut f, ns, &raw, "POST", "sys/wrapping/unwrap", json!({}))?;
    assert_eq!(executed.status, 200);
    assert_eq!(executed.body["data"]["version"], 1);
    child_value(&mut f, ns)?;
    assert_eq!(
        scoped_call(&mut f, ns, &raw, "POST", "sys/wrapping/unwrap", json!({}))?.status,
        400
    );
    child_value(&mut f, ns)?;
    let mut f = f.restart()?;
    assert_eq!(
        scoped_call(&mut f, ns, &raw, "POST", "sys/wrapping/unwrap", json!({}))?.status,
        400
    );
    child_value(&mut f, ns)?;
    // Controlled GET retains the child immutable graph and spends Auth only.
    let deferred = scoped_call(
        &mut f,
        ns,
        &requester.token,
        "GET",
        "secret/data/child-controlled",
        json!({}),
    )?;
    assert_eq!(deferred.status, 200);
    let read_raw = Zeroizing::new(text(&deferred.body, "/wrap_info/token")?);
    let read_accessor = text(&deferred.body, "/wrap_info/accessor")?;
    assert_eq!(
        scoped_call(
            &mut f,
            ns,
            &reviewer.token,
            "POST",
            "sys/control-group/authorize",
            json!({"accessor":read_accessor})
        )?
        .status,
        200
    );
    let read = scoped_call(
        &mut f,
        ns,
        &read_raw,
        "POST",
        "sys/wrapping/unwrap",
        json!({}),
    )?;
    assert_eq!(read.status, 200);
    assert_eq!(read.body["data"]["data"]["value"], "namespace-owned");
    assert_eq!(read.body["data"]["metadata"]["version"], 1);
    assert_eq!(
        scoped_call(
            &mut f,
            ns,
            &read_raw,
            "POST",
            "sys/wrapping/unwrap",
            json!({})
        )?
        .status,
        400
    );
    child_value(&mut f, ns)?;
    for namespace in ["", sibling] {
        assert_eq!(
            child_admin(
                &mut f,
                namespace,
                "GET",
                "secret/metadata/child-controlled",
                json!({})
            )?
            .status,
            404
        );
    }
    Ok(())
}
