//! Actual File V6 child scope, absent/retired mount observations, ACL and
//! durable catalog changes after the real mandatory response audit.
use super::*;

fn scoped(
    service: &mut Service,
    namespace: &str,
    method: &str,
    path: &str,
    token: &str,
    body: Value,
) -> Response {
    let started = Instant::now();
    let _scope = crate::request_deadline::RequestDeadlineScope::enter(
        started + Duration::from_secs(SECONDS),
    );
    let response = service.handle(method, path, namespace, token, body);
    assert!(started.elapsed() < Duration::from_secs(SECONDS));
    assert!(service.pending_native_auth_delivery.is_none());
    assert!(service.native_request_binding.is_none());
    response
}

fn admin(f: &mut Fixture, namespace: &str, method: &str, path: &str, body: Value) -> Response {
    scoped(&mut f.service, namespace, method, path, &f.admin, body)
}

fn create(f: &mut Fixture, namespace: &str, name: &str) -> TestResult {
    expect(
        admin(
            f,
            namespace,
            "POST",
            &format!("sys/namespaces/{name}"),
            json!({}),
        ),
        200,
        "actual child namespace creation",
    )?;
    Ok(())
}

fn token(f: &mut Fixture, namespace: &str, uses: u64) -> TestResult<Zeroizing<String>> {
    expect(
        admin(
            f,
            namespace,
            "PUT",
            "sys/policies/acl/child-absence",
            json!({"policy":r#"path "unmounted/allowed" { capabilities=["read"] }"#}),
        ),
        204,
        "actual child absence policy",
    )?;
    let mut issued = expect(
        admin(
            f,
            namespace,
            "POST",
            "auth/token/create",
            json!({"policies":["child-absence"],"no_default_policy":true,"num_uses":uses,"ttl":"1h"}),
        ),
        200,
        "actual child absence token",
    )?;
    let actor = take_secret(&mut issued, "/auth/client_token")?;
    erase_json(&mut issued.body);
    Ok(actor)
}

#[test]
fn native_missing_route_formal_child_retirement_and_initial_namespace_absence_cold() -> TestResult {
    let mut f = Fixture::start(true, false)?;
    create(&mut f, "", "team")?;
    create(&mut f, "", "sibling")?;
    create(&mut f, "team", "child")?;
    for namespace in ["", "team", "team/child", "sibling"] {
        for method in ["GET", "HEAD", "LIST"] {
            negative(admin(
                &mut f,
                namespace,
                method,
                "never-mounted/value",
                json!({}),
            ))?;
        }
    }
    // The root mount is real; absence must be selected from the child catalog.
    negative(admin(
        &mut f,
        "team/child",
        "GET",
        "secret/data/kept",
        json!({}),
    ))?;
    for namespace in ["", "team/child"] {
        expect(
            admin(
                &mut f,
                namespace,
                "POST",
                "sys/mounts/retired",
                json!({"type":"kv","options":{"version":"1"},"config":{"default_lease_ttl":"-1s","max_lease_ttl":"60s"}}),
            ),
            204,
            "actual scoped KV1 mount",
        )?;
        expect(
            admin(
                &mut f,
                namespace,
                "POST",
                "retired/value",
                json!({"scope":namespace}),
            ),
            204,
            "actual scoped KV1 value",
        )?;
    }
    let child = expect(
        admin(&mut f, "team/child", "GET", "retired/value", json!({})),
        200,
        "child signed value before retirement",
    )?;
    assert_eq!(child.body["data"], json!({"scope":"team/child"}));
    assert_eq!(child.body["lease_duration"], -1);
    expect(
        admin(
            &mut f,
            "team/child",
            "DELETE",
            "sys/mounts/retired",
            json!({}),
        ),
        204,
        "actual child KV1 retirement",
    )?;
    negative(admin(
        &mut f,
        "team/child",
        "GET",
        "retired/value",
        json!({}),
    ))?;
    negative(admin(&mut f, "sibling", "GET", "retired/value", json!({})))?;
    let root = expect(
        f.admin("GET", "retired/value", json!({})),
        200,
        "child retirement preserves root mount",
    )?;
    assert_eq!(root.body["data"], json!({"scope":""}));
    expect(
        f.admin("DELETE", "sys/mounts/retired", json!({})),
        204,
        "actual root retirement",
    )?;
    negative(f.admin("GET", "retired/value", json!({})))?;
    for (method, path, body) in [
        ("GET", "sys/unimplemented-owner", json!({})),
        ("GET", "auth/unmounted/users/a", json!({})),
        ("POST", "never-mounted/value", json!({})),
        ("SCAN", "never-mounted/value", json!({})),
        ("GET", "never-mounted/value", json!({"scan":true})),
    ] {
        expect(
            admin(&mut f, "team/child", method, path, body),
            501,
            "unsupported child owner remains unsupported",
        )?;
    }
    expect(
        admin(&mut f, "team", "DELETE", "sys/namespaces/child", json!({})),
        200,
        "actual empty child namespace retirement",
    )?;
    let response = expect(
        admin(&mut f, "team/child", "GET", "retired/value", json!({})),
        404,
        "new request selects absent namespace",
    )?;
    assert!(response.body.get("data").is_none() && response.unwrapped_json.is_none());
    let mut f = f.restart()?;
    for namespace in ["", "team", "sibling"] {
        negative(admin(&mut f, namespace, "GET", "retired/value", json!({})))?;
    }
    expect(
        admin(&mut f, "team/child", "GET", "retired/value", json!({})),
        404,
        "cold new request retains namespace absence",
    )?;
    f.sentinel()
}

#[test]
fn native_missing_route_formal_child_acl_finite_use_and_http_namespace_cold() -> TestResult {
    let mut f = Fixture::start(true, false)?;
    create(&mut f, "", "team")?;
    create(&mut f, "", "sibling")?;
    create(&mut f, "team", "child")?;
    let once = token(&mut f, "team/child", 1)?;
    negative(scoped(
        &mut f.service,
        "team/child",
        "GET",
        "unmounted/allowed",
        &once,
        json!({}),
    ))?;
    expect(
        scoped(
            &mut f.service,
            "team/child",
            "GET",
            "unmounted/allowed",
            &once,
            json!({}),
        ),
        403,
        "child finite use consumed once",
    )?;
    let actor = token(&mut f, "team/child", 0)?;
    for namespace in ["", "team", "sibling"] {
        expect(
            scoped(
                &mut f.service,
                namespace,
                "GET",
                "unmounted/allowed",
                &actor,
                json!({}),
            ),
            403,
            "child actor cannot ascend or cross sibling scope",
        )?;
    }
    for (method, path, body) in [
        ("LIST", "unmounted/allowed", json!({})),
        ("GET", "unmounted/denied", json!({})),
        ("GET", "unmounted/allowed", json!({"list":true})),
    ] {
        expect(
            scoped(&mut f.service, "team/child", method, path, &actor, body),
            403,
            "actual child operation ACL",
        )?;
    }
    expect(
        scoped(
            &mut f.service,
            "team/child",
            "GET",
            "unmounted/allowed",
            "",
            json!({}),
        ),
        403,
        "child absence requires an actor",
    )?;
    let mut f = f.restart()?;
    expect(
        scoped(
            &mut f.service,
            "team/child",
            "GET",
            "unmounted/allowed",
            &once,
            json!({}),
        ),
        403,
        "cold child finite-use actor remains spent",
    )?;
    let wire = Zeroizing::new(format!(
        "GET /v1/unmounted/allowed HTTP/1.1\r\nHost: localhost\r\nX-Vault-Namespace: team/child/\r\nX-Vault-Token: {}\r\nConnection: close\r\n\r\n",
        actor.as_str(),
    ));
    let deadline = Instant::now() + Duration::from_secs(SECONDS);
    let _scope = crate::request_deadline::RequestDeadlineScope::enter(deadline);
    let response = crate::http::logical_data_wire_dispatch_fixture(wire.as_bytes(), |request| {
        let execution = f.service.begin_request_before(request, deadline, true);
        f.service.finish_synchronous_request(execution)
    })?;
    negative(response)?;
    assert!(Instant::now() < deadline);
    f.sentinel()
}

#[test]
fn native_missing_route_after_actual_audit_child_and_ancestor_reincarnation_veto() -> TestResult {
    for retire_ancestor in [false, true] {
        let mut f = Fixture::start(true, false)?;
        create(&mut f, "", "team")?;
        create(&mut f, "team", "child")?;
        let writer = f.admin.clone();
        let observed = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let hook_observed = Arc::clone(&observed);
        let _hook = after_audit(move |service, response| {
            assert_eq!(response.status, 404);
            hook_observed.store(true, std::sync::atomic::Ordering::SeqCst);
            assert_eq!(
                scoped(
                    service,
                    "team",
                    "DELETE",
                    "sys/namespaces/child",
                    &writer,
                    json!({})
                )
                .status,
                200
            );
            if retire_ancestor {
                assert_eq!(
                    scoped(
                        service,
                        "",
                        "DELETE",
                        "sys/namespaces/team",
                        &writer,
                        json!({})
                    )
                    .status,
                    200
                );
                assert_eq!(
                    scoped(
                        service,
                        "",
                        "POST",
                        "sys/namespaces/team",
                        &writer,
                        json!({})
                    )
                    .status,
                    200
                );
            }
            assert_eq!(
                scoped(
                    service,
                    "team",
                    "POST",
                    "sys/namespaces/child",
                    &writer,
                    json!({})
                )
                .status,
                200
            );
        })?;
        let response = expect(
            admin(&mut f, "team/child", "GET", "absent/value", json!({})),
            503,
            "retained scope cannot follow a new incarnation",
        )?;
        assert!(observed.load(std::sync::atomic::Ordering::SeqCst));
        assert!(response.body.get("data").is_none());
        assert!(response.unwrapped_json.is_none() && response.response_headers.is_empty());
        negative(admin(
            &mut f,
            "team/child",
            "GET",
            "absent/value",
            json!({}),
        ))?;
        let mut f = f.restart()?;
        negative(admin(
            &mut f,
            "team/child",
            "GET",
            "absent/value",
            json!({}),
        ))?;
        f.sentinel()?;
    }
    Ok(())
}

#[test]
fn native_missing_route_after_actual_audit_child_mount_and_actor_changes_veto() -> TestResult {
    let mut f = Fixture::start(true, false)?;
    create(&mut f, "", "team")?;
    create(&mut f, "team", "child")?;
    let writer = f.admin.clone();
    let _hook = after_audit(move |service, response| {
        assert_eq!(response.status, 404);
        assert_eq!(
            scoped(
                service,
                "team/child",
                "POST",
                "sys/mounts/late",
                &writer,
                json!({"type":"kv","options":{"version":"1"}})
            )
            .status,
            204
        );
    })?;
    expect(
        admin(&mut f, "team/child", "GET", "late/value", json!({})),
        503,
        "child catalog changes after audit",
    )?;
    expect(
        admin(
            &mut f,
            "team/child",
            "POST",
            "late/value",
            json!({"owner":"child"}),
        ),
        204,
        "new child owner writes",
    )?;
    let read = expect(
        admin(&mut f, "team/child", "GET", "late/value", json!({})),
        200,
        "new child owner reads",
    )?;
    assert_eq!(read.body["data"], json!({"owner":"child"}));
    negative(f.admin("GET", "late/value", json!({})))?;
    let actor = token(&mut f, "team/child", 0)?;
    let writer = f.admin.clone();
    let revoked = actor.clone();
    let _hook = after_audit(move |service, response| {
        assert_eq!(response.status, 404);
        assert_eq!(
            scoped(
                service,
                "team/child",
                "POST",
                "auth/token/revoke",
                &writer,
                json!({"token":revoked.as_str()})
            )
            .status,
            204
        );
    })?;
    expect(
        scoped(
            &mut f.service,
            "team/child",
            "GET",
            "unmounted/allowed",
            &actor,
            json!({}),
        ),
        503,
        "child actor revoked after mandatory audit",
    )?;
    expect(
        scoped(
            &mut f.service,
            "team/child",
            "GET",
            "unmounted/allowed",
            &actor,
            json!({}),
        ),
        403,
        "revoked child actor remains denied",
    )?;
    f.sentinel()
}
