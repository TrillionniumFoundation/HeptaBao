use super::super::tests::{Root, bootstrap, call};
use super::*;
use serde_json::json;

#[test]
fn namespace_tree_metadata_restart_and_incarnation_are_durable()
-> Result<(), Box<dyn std::error::Error>> {
    let root = Root::new();
    let mut service = root.service()?;
    let (key, token) = bootstrap(&mut service)?;

    assert_eq!(
        call(
            &mut service,
            "POST",
            "sys/namespaces/team",
            &token,
            json!({"custom_metadata":{"owner":"platform","tier":"dev"}})
        )
        .status,
        200
    );
    let team = call(
        &mut service,
        "GET",
        "sys/namespaces/team",
        &token,
        json!({}),
    );
    assert_eq!(team.status, 200);
    assert_eq!(team.body["data"]["path"], "team/");
    assert_eq!(team.body["data"]["custom_metadata"]["owner"], "platform");
    let first_id = team.body["data"]["id"]
        .as_str()
        .ok_or("missing namespace id")?
        .to_owned();

    let list = call(&mut service, "LIST", "sys/namespaces", &token, json!({}));
    assert_eq!(list.status, 200);
    assert_eq!(list.body["data"]["keys"], json!(["team/"]));
    assert_eq!(list.body["data"]["key_info"]["team/"]["id"], first_id);

    assert_eq!(
        service
            .handle_at(
                "POST",
                "sys/namespaces/child",
                "team",
                &token,
                json!({"custom_metadata":{"owner":"application"}}),
                100
            )
            .status,
        200
    );
    let child = service.handle_at(
        "GET",
        "sys/namespaces/child",
        "team",
        &token,
        json!({}),
        100,
    );
    assert_eq!(child.status, 200);
    assert_eq!(child.body["data"]["path"], "team/child/");
    assert_eq!(
        service
            .handle_at(
                "PATCH",
                "sys/namespaces/child",
                "team",
                &token,
                json!({"custom_metadata":{"owner":"payments","obsolete":"remove-me"}}),
                100
            )
            .status,
        200
    );
    assert_eq!(
        service
            .handle_at(
                "PATCH",
                "sys/namespaces/child",
                "team",
                &token,
                json!({"custom_metadata":{"obsolete":null}}),
                100
            )
            .status,
        200
    );
    let scan = call(&mut service, "SCAN", "sys/namespaces", &token, json!({}));
    assert_eq!(scan.status, 200);
    assert_eq!(scan.body["data"]["keys"], json!(["team/", "team/child/"]));
    assert_eq!(
        call(
            &mut service,
            "DELETE",
            "sys/namespaces/team",
            &token,
            json!({})
        )
        .status,
        409
    );

    drop(service);
    let mut service = root.service()?;
    assert_eq!(
        call(&mut service, "PUT", "sys/unseal", "", json!({"key":key})).status,
        200
    );
    let reopened = call(
        &mut service,
        "GET",
        "sys/namespaces/team",
        &token,
        json!({}),
    );
    assert_eq!(reopened.status, 200);
    assert_eq!(reopened.body["data"]["id"], first_id);
    let child = service.handle_at(
        "GET",
        "sys/namespaces/child",
        "team",
        &token,
        json!({}),
        100,
    );
    assert_eq!(child.body["data"]["custom_metadata"]["owner"], "payments");
    assert!(
        child.body["data"]["custom_metadata"]
            .get("obsolete")
            .is_none()
    );

    assert_eq!(
        service
            .handle_at(
                "DELETE",
                "sys/namespaces/child",
                "team",
                &token,
                json!({}),
                100
            )
            .status,
        200
    );
    assert_eq!(
        call(
            &mut service,
            "DELETE",
            "sys/namespaces/team",
            &token,
            json!({})
        )
        .status,
        200
    );
    assert_eq!(
        call(
            &mut service,
            "POST",
            "sys/namespaces/team",
            &token,
            json!({})
        )
        .status,
        200
    );
    let recreated = call(
        &mut service,
        "GET",
        "sys/namespaces/team",
        &token,
        json!({}),
    );
    assert_ne!(recreated.body["data"]["id"], first_id);
    Ok(())
}

#[test]
fn namespace_catalog_seal_state_and_nonempty_delete() -> Result<(), Box<dyn std::error::Error>> {
    let root = Root::new();
    let mut service = root.service()?;
    let (_, token) = bootstrap(&mut service)?;
    assert_eq!(
        call(
            &mut service,
            "POST",
            "sys/namespaces/sealed",
            &token,
            json!({"seal":"invalid"})
        )
        .status,
        400
    );
    assert_eq!(
        call(
            &mut service,
            "POST",
            "sys/namespaces/sealed",
            &token,
            json!({"seal":true})
        )
        .status,
        200
    );
    let sealed = call(
        &mut service,
        "GET",
        "sys/namespaces/sealed/seal-status",
        &token,
        json!({}),
    );
    assert_eq!(sealed.status, 200);
    assert_eq!(sealed.body["sealed"], true);
    assert_eq!(
        call(
            &mut service,
            "POST",
            "sys/namespaces/team",
            &token,
            json!({})
        )
        .status,
        200
    );
    assert_eq!(
        service
            .handle_at(
                "POST",
                "secret/data/item",
                "team",
                &token,
                json!({"data":{"value":"secret"}}),
                100
            )
            .status,
        200
    );
    assert_eq!(
        call(
            &mut service,
            "DELETE",
            "sys/namespaces/team",
            &token,
            json!({})
        )
        .status,
        409
    );
    let state = service.state.as_ref().ok_or("missing state")?;
    assert_eq!(state.schema, CURRENT_STATE_SCHEMA);
    let mut downgraded = state.clone();
    downgraded.auth.remove_name_modes_for_legacy_format_test();
    downgraded.schema = 8;
    downgraded.auth.omit_lease_metadata_for_legacy_fixture();
    assert!(downgraded.validate_format().is_err());
    Ok(())
}

#[test]
fn namespace_seal_routes_fail_closed_and_unseal_from_parent()
-> Result<(), Box<dyn std::error::Error>> {
    let root = Root::new();
    let mut service = root.service()?;
    let (_, token) = bootstrap(&mut service)?;
    let network_call = |service: &mut Service,
                        method: &str,
                        path: &str,
                        namespace: &str,
                        body: Value|
     -> Response {
        match service.begin_request(ServiceRequest {
            method,
            path,
            namespace,
            token: &token,
            body,
            wrap_ttl_seconds: None,
            origin_peer: None,
            client_certificates: None,
        }) {
            RequestExecution::Complete(response) => response,
            RequestExecution::External(_) => Response::error(500, "unexpected external effect"),
        }
    };
    assert_eq!(
        call(
            &mut service,
            "POST",
            "sys/namespaces/team",
            &token,
            json!({}),
        )
        .status,
        200
    );
    assert_eq!(
        network_call(
            &mut service,
            "POST",
            "sys/namespaces/team/seal",
            "",
            json!({}),
        )
        .status,
        204
    );
    assert_eq!(
        network_call(&mut service, "GET", "secret/data/item", "team", json!({}),).status,
        503
    );
    let status = network_call(
        &mut service,
        "GET",
        "sys/namespaces/team/seal-status",
        "",
        json!({}),
    );
    assert_eq!(status.status, 200);
    assert_eq!(status.body["sealed"], true);
    assert_eq!(
        network_call(
            &mut service,
            "POST",
            "sys/namespaces/team/unseal",
            "",
            json!({}),
        )
        .status,
        204
    );
    assert_eq!(
        network_call(&mut service, "GET", "secret/data/item", "team", json!({}),).status,
        404
    );
    Ok(())
}

#[test]
fn unknown_namespace_is_not_an_implicit_scope_or_write_target()
-> Result<(), Box<dyn std::error::Error>> {
    let root = Root::new();
    let mut service = root.service()?;
    let (_, token) = bootstrap(&mut service)?;
    let generation = service
        .durable
        .as_ref()
        .ok_or("missing durable store")?
        .generation();
    let network_call = |service: &mut Service,
                        method: &str,
                        path: &str,
                        namespace: &str,
                        token: &str,
                        body: Value|
     -> Response {
        match service.begin_request(ServiceRequest {
            method,
            path,
            namespace,
            token,
            body,
            wrap_ttl_seconds: None,
            origin_peer: None,
            client_certificates: None,
        }) {
            RequestExecution::Complete(response) => response,
            RequestExecution::External(_) => Response::error(
                500,
                "namespace fixture unexpectedly staged an external effect",
            ),
        }
    };

    for (method, path) in [
        ("GET", "sys/health"),
        ("GET", "sys/seal-status"),
        ("GET", "secret/data/ghost-item"),
        ("POST", "secret/data/ghost-item"),
        ("POST", "auth/token/create"),
    ] {
        assert_eq!(
            network_call(&mut service, method, path, "ghost", &token, json!({})).status,
            404,
            "unknown namespace must fail before {method} {path}"
        );
    }
    assert_eq!(
        service
            .durable
            .as_ref()
            .ok_or("missing durable store")?
            .generation(),
        generation,
        "unknown namespace requests must not publish owner state"
    );

    assert_eq!(
        call(
            &mut service,
            "POST",
            "sys/namespaces/ghost",
            &token,
            json!({}),
        )
        .status,
        200
    );
    assert_eq!(
        call(
            &mut service,
            "DELETE",
            "sys/namespaces/ghost",
            &token,
            json!({}),
        )
        .status,
        200
    );
    assert_eq!(
        network_call(
            &mut service,
            "POST",
            "secret/data/ghost-item",
            "ghost",
            &token,
            json!({"data":{"v":"must-not-resurrect"}}),
        )
        .status,
        404,
        "deleted namespace must not reappear through an owner map"
    );
    assert!(
        !service
            .state
            .as_ref()
            .ok_or("missing state")?
            .namespace_exists("ghost")
    );
    Ok(())
}

#[test]
fn health_get_and_head_preserve_namespace_and_recovery_fences()
-> Result<(), Box<dyn std::error::Error>> {
    let health = |service: &mut Service, method: &str, namespace: &str| {
        service.handle_at_mode(RequestDispatch {
            method,
            path: "sys/health",
            namespace,
            token: "",
            body: json!({}),
            now: 100,
            allow_forward: false,
            enforce_namespace: true,
            wrap_ttl_seconds: None,
            origin_peer: None,
            client_certificates: None,
        })
    };
    let root = Root::new();
    let mut service = root.service()?;
    let (_, token) = bootstrap(&mut service)?;
    assert_eq!(
        call(
            &mut service,
            "POST",
            "sys/namespaces/team",
            &token,
            json!({})
        )
        .status,
        200
    );
    for method in ["GET", "HEAD"] {
        let before = service.state_digest;
        let generation = service.durable.as_ref().ok_or("durable")?.generation();
        let unknown = health(&mut service, method, "absent");
        assert_eq!(unknown.status, 404);
        let valid = health(&mut service, method, "team");
        assert_eq!(valid.status, 200);
        assert_eq!(service.state_digest, before);
        assert_eq!(
            service.durable.as_ref().ok_or("durable")?.generation(),
            generation
        );
        service.recovery_required = true;
        let fenced = health(&mut service, method, "team");
        assert_eq!(fenced.status, 503);
        assert!(service.recovery_required);
        assert_eq!(service.state_digest, before);
        assert_eq!(
            service.durable.as_ref().ok_or("durable")?.generation(),
            generation
        );
        // Restore only the test-injected flag before the next independent case.
        service.recovery_required = false;
    }
    Ok(())
}

#[test]
fn malformed_health_queries_never_change_application_state()
-> Result<(), Box<dyn std::error::Error>> {
    let root = Root::new();
    let mut service = root.service()?;
    bootstrap(&mut service)?;
    let before = service.state_digest;
    let generation = service.durable.as_ref().ok_or("durable")?.generation();
    for method in ["GET", "HEAD"] {
        for body in [
            json!({"standbyok":"true"}),
            json!({"perfstandbyok":1}),
            json!({"activecode":99}),
        ] {
            assert_eq!(
                service
                    .handle_request_at(ServiceRequest::new(method, "sys/health", "", "", body), 100)
                    .status,
                400
            );
        }
    }
    assert_eq!(service.state_digest, before);
    assert_eq!(
        service.durable.as_ref().ok_or("durable")?.generation(),
        generation
    );
    Ok(())
}

#[test]
fn native_namespace_wire_projection_preserves_durable_identity()
-> Result<(), Box<dyn std::error::Error>> {
    let root = Root::new();
    let mut service = root.service()?;
    let (key, token) = bootstrap(&mut service)?;
    let created = call(
        &mut service,
        "POST",
        "sys/namespaces/native",
        &token,
        json!({"custom_metadata":{"owner":"first"}}),
    );
    assert_eq!(created.status, 200);
    let data = created.body["data"].clone();
    assert_eq!(data["path"], "native/");
    assert_eq!(data["locked"], false);
    assert_eq!(data["tainted"], false);
    assert_eq!(data["uuid"].as_str().ok_or("uuid")?.len(), 36);
    // The pre-existing v1 persisted ID remains unchanged, not rewritten to
    // imitate the variable-length opaque identifier of another implementation.
    assert_eq!(data["id"].as_str().ok_or("id")?.len(), 5);
    let before = serde_json::to_vec(&service.state.as_ref().ok_or("state")?.namespaces)?;
    let generation = service.durable.as_ref().ok_or("durable")?.generation();
    let read = call(
        &mut service,
        "GET",
        "sys/namespaces/native",
        &token,
        json!({}),
    );
    assert_eq!(read.body["data"], data);
    assert_eq!(
        service.durable.as_ref().ok_or("durable")?.generation(),
        generation
    );
    assert_eq!(
        serde_json::to_vec(&service.state.as_ref().ok_or("state")?.namespaces)?,
        before
    );
    let saved: Value = serde_json::from_slice(&before)?;
    assert!(saved["entries"]["native"].get("uuid").is_none());
    drop(service);
    let mut service = root.service()?;
    assert_eq!(
        call(&mut service, "POST", "sys/unseal", "", json!({"key":key})).status,
        200
    );
    let reopened = call(
        &mut service,
        "GET",
        "sys/namespaces/native",
        &token,
        json!({}),
    );
    assert_eq!(reopened.body["data"], data);
    let patched = call(
        &mut service,
        "PATCH",
        "sys/namespaces/native",
        &token,
        json!({"custom_metadata":{"owner":"second"}}),
    );
    assert_eq!(patched.status, 200);
    assert_eq!(patched.body["data"]["id"], data["id"]);
    assert_eq!(patched.body["data"]["uuid"], data["uuid"]);
    assert_eq!(patched.body["data"]["custom_metadata"]["owner"], "second");
    let removed = call(
        &mut service,
        "DELETE",
        "sys/namespaces/native",
        &token,
        json!({}),
    );
    assert_eq!(removed.status, 200);
    assert_eq!(removed.body, json!({"data":{"status":"in-progress"}}));
    // Lose the deletion acknowledgement, then recover the same committed absence.
    drop(service);
    let mut service = root.service()?;
    assert_eq!(
        call(&mut service, "POST", "sys/unseal", "", json!({"key":key})).status,
        200
    );
    assert_eq!(
        call(
            &mut service,
            "GET",
            "sys/namespaces/native",
            &token,
            json!({})
        )
        .status,
        404
    );
    let generation = service.durable.as_ref().ok_or("durable")?.generation();
    let repeated = call(
        &mut service,
        "DELETE",
        "sys/namespaces/native",
        &token,
        json!({}),
    );
    assert_eq!(repeated.status, 200);
    assert_eq!(repeated.body, json!({"data":null}));
    assert_eq!(
        service.durable.as_ref().ok_or("durable")?.generation(),
        generation
    );
    let recreated = call(
        &mut service,
        "POST",
        "sys/namespaces/native",
        &token,
        json!({}),
    );
    assert_eq!(recreated.status, 200);
    assert_ne!(recreated.body["data"]["id"], data["id"]);
    assert_ne!(recreated.body["data"]["uuid"], data["uuid"]);
    Ok(())
}

#[test]
fn native_namespace_rejections_do_not_publish_or_rebind_owner_state()
-> Result<(), Box<dyn std::error::Error>> {
    let root = Root::new();
    let mut service = root.service()?;
    let (_, token) = bootstrap(&mut service)?;
    assert_eq!(
        call(
            &mut service,
            "POST",
            "sys/namespaces/team",
            &token,
            json!({})
        )
        .status,
        200
    );
    let before = service.state_digest;
    let generation = service.durable.as_ref().ok_or("durable")?.generation();
    for method in ["GET", "POST", "PATCH", "DELETE"] {
        assert_eq!(
            call(
                &mut service,
                method,
                "sys/namespaces/team/child",
                &token,
                json!({})
            )
            .status,
            400
        );
    }
    for reserved in ["root", "sys", "audit", "auth", "cubbyhole", "identity"] {
        assert_eq!(
            call(
                &mut service,
                "POST",
                &format!("sys/namespaces/{reserved}"),
                &token,
                json!({})
            )
            .status,
            400
        );
    }
    assert_eq!(
        call(
            &mut service,
            "DELETE",
            "sys/namespaces/team",
            "invalid",
            json!({})
        )
        .status,
        403
    );
    assert_eq!(
        call(
            &mut service,
            "PATCH",
            "sys/namespaces/team",
            &token,
            json!({"custom_metadata":{"good":"must-not-commit","invalid":1}})
        )
        .status,
        400
    );
    assert_eq!(service.state_digest, before);
    assert_eq!(
        service.durable.as_ref().ok_or("durable")?.generation(),
        generation
    );
    Ok(())
}
