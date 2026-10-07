use super::*;
use crate::service::tests::{Root, bootstrap_unmounted};
type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

fn native(
    service: &mut Service,
    method: &str,
    path: &str,
    namespace: &str,
    token: &str,
    body: Value,
) -> Response {
    let execution = service.begin_request_before(
        ServiceRequest {
            method,
            path,
            namespace,
            token,
            body,
            wrap_ttl_seconds: None,
            origin_peer: None,
            client_certificates: None,
        },
        Instant::now() + Duration::from_secs(15),
        false,
    );
    service.finish_synchronous_request(execution)
}
fn clock() -> TestResult<RequestClock> {
    Ok(RequestClock::anchored(
        SystemTime::now().duration_since(UNIX_EPOCH)?,
        Instant::now(),
    )?)
}
fn populate(service: &mut Service, root: &str, path: &str) -> TestResult<String> {
    assert_eq!(
        native(
            service,
            "POST",
            &format!("sys/namespaces/{path}"),
            "",
            root,
            json!({})
        )
        .status,
        200
    );
    assert_eq!(
        native(
            service,
            "POST",
            "sys/auth/userpass",
            path,
            root,
            json!({"type":"userpass"})
        )
        .status,
        204
    );
    assert_eq!(
        native(
            service,
            "POST",
            "auth/userpass/users/alice",
            path,
            root,
            json!({"password":"finite-synthetic-delete-password","token_ttl":"10m"})
        )
        .status,
        204
    );
    assert_eq!(
        native(
            service,
            "POST",
            "sys/mounts/local",
            path,
            root,
            json!({"type":"kv","options":{"version":"1"}})
        )
        .status,
        204
    );
    assert_eq!(
        native(
            service,
            "POST",
            "local/item",
            path,
            root,
            json!({"payload":"owned-leaf"})
        )
        .status,
        204
    );
    let login = native(
        service,
        "POST",
        "auth/userpass/login/ALICE",
        path,
        "",
        json!({"password":"finite-synthetic-delete-password"}),
    );
    assert_eq!(login.status, 200);
    Ok(login.body["auth"]["client_token"]
        .as_str()
        .ok_or("issued token")?
        .to_owned())
}
fn cleanup(service: &mut Service) -> TestResult {
    let _scope = crate::request_deadline::RequestDeadlineScope::enter(
        Instant::now() + Duration::from_secs(15),
    );
    assert!(
        service
            .maintain_namespace_deletions(clock()?)
            .map_err(|_| "native cleanup")?
    );
    Ok(())
}
fn begin(service: &mut Service, root: &str, leaf: &str) {
    let response = native(
        service,
        "DELETE",
        &format!("sys/namespaces/{leaf}"),
        "",
        root,
        json!({}),
    );
    assert_eq!(response.status, 200);
    assert_eq!(response.body["data"]["status"], "in-progress");
}

#[test]
fn native_leaf_delete_taints_issued_login_and_retires_actual_kv_owner() -> TestResult {
    let root = Root::new();
    let mut service = root.service()?;
    let (_, actor) = bootstrap_unmounted(&mut service)?;
    let issued = populate(&mut service, &actor, "retire")?;
    let old_binding = service
        .state
        .as_ref()
        .ok_or("state")?
        .namespaces
        .custody_binding(&service.state.as_ref().ok_or("state")?.cluster_id, "retire")
        .map_err(|_| "binding")?;
    begin(&mut service, &actor, "retire");
    let state = service.state.as_ref().ok_or("state")?;
    assert_eq!(state.schema, NAMESPACE_DELETION_STATE_SCHEMA);
    assert!(state.namespace_is_tainted("retire"));
    state.validate_format().map_err(|_| "pending format")?;
    let mut downgrade = state.clone();
    downgrade.schema = AUTH_MOUNT_OPTIONS_STATE_SCHEMA;
    assert!(
        downgrade.validate_format().is_err(),
        "real pending owner cannot be labeled 103"
    );
    let mut mismatch = state.clone();
    mismatch.namespaces.deletions = None;
    assert!(
        mismatch.validate_format().is_err(),
        "Auth and catalog mirrors cannot disagree"
    );

    let metadata = native(
        &mut service,
        "GET",
        "sys/namespaces/retire",
        "",
        &actor,
        json!({}),
    );
    assert_eq!(metadata.status, 200);
    assert_eq!(metadata.body["data"]["tainted"], true);
    assert_eq!(metadata.body["data"]["locked"], false);
    assert_eq!(
        native(&mut service, "GET", "sys/auth", "retire", &actor, json!({})).status,
        404
    );
    assert_eq!(
        native(
            &mut service,
            "POST",
            "auth/userpass/login/ALICE",
            "retire",
            "",
            json!({"password":"finite-synthetic-delete-password"})
        )
        .status,
        403
    );
    assert_eq!(
        native(
            &mut service,
            "GET",
            "auth/token/lookup-self",
            "retire",
            &issued,
            json!({})
        )
        .status,
        403
    );
    assert_eq!(
        native(
            &mut service,
            "GET",
            "local/item",
            "retire",
            &actor,
            json!({})
        )
        .status,
        403
    );
    cleanup(&mut service)?;
    let state = service.state.as_ref().ok_or("state")?;
    assert!(!state.namespace_exists("retire"));
    assert_eq!(
        state
            .namespaces
            .deletions
            .as_ref()
            .ok_or("ledger")?
            .retired()
            .get("retire"),
        Some(&old_binding.incarnation())
    );
    state.validate_format().map_err(|_| "retired format")?;
    assert_eq!(
        native(
            &mut service,
            "GET",
            "sys/namespaces/retire",
            "",
            &actor,
            json!({})
        )
        .status,
        404
    );
    assert_eq!(
        native(
            &mut service,
            "GET",
            "local/item",
            "retire",
            &actor,
            json!({})
        )
        .status,
        404
    );
    let fresh = populate(&mut service, &actor, "retire")?;
    assert_eq!(
        native(
            &mut service,
            "GET",
            "auth/token/lookup-self",
            "retire",
            &issued,
            json!({})
        )
        .status,
        403
    );
    assert_eq!(
        native(
            &mut service,
            "GET",
            "auth/token/lookup-self",
            "retire",
            &fresh,
            json!({})
        )
        .status,
        200
    );
    assert!(
        service
            .state
            .as_ref()
            .ok_or("state")?
            .namespaces
            .incarnation("retire")
            .is_some_and(|inc| inc > old_binding.incarnation())
    );
    Ok(())
}

#[test]
fn pending_native_leaf_deletion_reopens_and_old_backup_cannot_remove_taint() -> TestResult {
    let root = Root::new();
    let mut service = root.service()?;
    let (key, actor) = bootstrap_unmounted(&mut service)?;
    let issued = populate(&mut service, &actor, "retire")?;
    let archive = Zeroizing::new(service.durable.as_ref().ok_or("durable")?.export_backup()?);
    begin(&mut service, &actor, "retire");
    assert!(service.prepare_snapshot_restore(&archive).is_err());
    drop(service);
    let mut service = root.service()?;
    assert_eq!(
        native(
            &mut service,
            "POST",
            "sys/unseal",
            "",
            "",
            json!({"key":key})
        )
        .status,
        200
    );
    assert!(
        service
            .state
            .as_ref()
            .ok_or("reopened")?
            .namespace_is_tainted("retire")
    );
    assert_eq!(
        native(
            &mut service,
            "GET",
            "auth/token/lookup-self",
            "retire",
            &issued,
            json!({})
        )
        .status,
        403
    );
    assert!(service.prepare_snapshot_restore(&archive).is_err());
    cleanup(&mut service)?;
    assert!(service.prepare_snapshot_restore(&archive).is_err());
    assert_eq!(
        service.state.as_ref().ok_or("state")?.schema,
        NAMESPACE_DELETION_STATE_SCHEMA
    );
    Ok(())
}

#[test]
fn actual_child_namespace_rejection_is_400_and_keeps_account_and_catalog() -> TestResult {
    let root = Root::new();
    let mut service = root.service()?;
    let (_, actor) = bootstrap_unmounted(&mut service)?;
    let issued = populate(&mut service, &actor, "parent")?;
    assert_eq!(
        native(
            &mut service,
            "POST",
            "sys/namespaces/child",
            "parent",
            &actor,
            json!({})
        )
        .status,
        200
    );
    let response = native(
        &mut service,
        "DELETE",
        "sys/namespaces/parent",
        "",
        &actor,
        json!({}),
    );
    assert_eq!(response.status, 400);
    let state = service.state.as_ref().ok_or("state")?;
    assert!(state.namespaces.deletions.is_none());
    assert!(state.namespace_exists("parent") && state.namespace_exists("parent/child"));
    assert_eq!(
        native(
            &mut service,
            "GET",
            "auth/token/lookup-self",
            "parent",
            &issued,
            json!({})
        )
        .status,
        200
    );
    assert_eq!(
        native(
            &mut service,
            "GET",
            "local/item",
            "parent",
            &actor,
            json!({})
        )
        .body["data"]["payload"],
        "owned-leaf"
    );
    Ok(())
}

#[test]
fn unsupported_non_kv_owner_is_rejected_before_taint_or_resource_drop() -> TestResult {
    let root = Root::new();
    let mut service = root.service()?;
    let (_, actor) = bootstrap_unmounted(&mut service)?;
    let issued = populate(&mut service, &actor, "retire")?;
    assert_eq!(
        native(
            &mut service,
            "POST",
            "sys/mounts/transit",
            "retire",
            &actor,
            json!({"type":"transit"})
        )
        .status,
        204
    );
    assert_eq!(
        native(
            &mut service,
            "POST",
            "transit/keys/preserve",
            "retire",
            &actor,
            json!({})
        )
        .status,
        200
    );
    assert_eq!(
        native(
            &mut service,
            "DELETE",
            "sys/namespaces/retire",
            "",
            &actor,
            json!({})
        )
        .status,
        409
    );
    assert!(
        service
            .state
            .as_ref()
            .ok_or("state")?
            .namespaces
            .deletions
            .is_none()
    );
    assert_eq!(
        native(
            &mut service,
            "GET",
            "transit/keys/preserve",
            "retire",
            &actor,
            json!({})
        )
        .status,
        200
    );
    assert_eq!(
        native(
            &mut service,
            "GET",
            "auth/token/lookup-self",
            "retire",
            &issued,
            json!({})
        )
        .status,
        200
    );
    Ok(())
}

#[test]
fn cleanup_original_deadline_and_nonce_cannot_publish_but_new_task_can_finish() -> TestResult {
    let root = Root::new();
    let mut service = root.service()?;
    let (_, actor) = bootstrap_unmounted(&mut service)?;
    populate(&mut service, &actor, "retire")?;
    begin(&mut service, &actor, "retire");
    let state = service.state.as_ref().ok_or("state")?;
    let binding = state
        .namespaces
        .deletions
        .as_ref()
        .ok_or("ledger")?
        .pending()
        .get("retire")
        .ok_or("intent")?
        .clone();
    let generation = service.durable.as_ref().ok_or("durable")?.generation();
    {
        let _scope = crate::request_deadline::RequestDeadlineScope::enter(
            Instant::now() + Duration::from_millis(250),
        );
        let owner = LocalCleanup::capture(&service, state, binding.clone(), clock()?)
            .map_err(|_| "capture")?;
        std::thread::sleep(Duration::from_millis(260));
        assert!(owner.check_base(&service).is_err());
        assert!(service.maintain_namespace_deletions(clock()?).is_err());
    }
    assert_eq!(
        service.durable.as_ref().ok_or("durable")?.generation(),
        generation
    );
    {
        let _scope = crate::request_deadline::RequestDeadlineScope::enter(
            Instant::now() + Duration::from_secs(15),
        );
        let owner = LocalCleanup::capture(
            &service,
            service.state.as_ref().ok_or("state")?,
            binding,
            clock()?,
        )
        .map_err(|_| "capture original activation")?;
        service.rotate_unseal_nonce()?;
        assert!(owner.check_base(&service).is_err());
    }
    assert!(
        service
            .state
            .as_ref()
            .ok_or("state")?
            .namespace_is_tainted("retire")
    );
    cleanup(&mut service)?;
    assert!(
        !service
            .state
            .as_ref()
            .ok_or("state")?
            .namespace_exists("retire")
    );
    Ok(())
}

#[test]
fn deletion_ack_after_real_actor_revocation_is_withheld_and_intent_survives() -> TestResult {
    let root = Root::new();
    let mut service = root.service()?;
    let (_, root_actor) = bootstrap_unmounted(&mut service)?;
    populate(&mut service, &root_actor, "retire")?;
    assert_eq!(
        native(
            &mut service,
            "POST",
            "sys/policies/acl/retire-admin",
            "",
            &root_actor,
            json!({"policy":r#"path "sys/namespaces/retire" { capabilities = ["delete","sudo"] }"#})
        )
        .status,
        204
    );
    let issued = native(
        &mut service,
        "POST",
        "auth/token/create",
        "",
        &root_actor,
        json!({"policies":["retire-admin"],"ttl":"10m","num_uses":2}),
    );
    assert_eq!(issued.status, 200);
    let actor = issued.body["auth"]["client_token"]
        .as_str()
        .ok_or("delete actor")?
        .to_owned();
    let clock = clock()?;
    let body = json!({});
    let _scope = crate::request_deadline::RequestDeadlineScope::enter(
        Instant::now() + Duration::from_secs(15),
    );
    let response = service.handle_inner(RequestView {
        method: "DELETE",
        path: "sys/namespaces/retire",
        namespace: "",
        token: &actor,
        body: &body,
        now: clock.admitted_at().seconds(),
        admission_started: clock.started(),
        token_clock: Some(clock),
        allow_forward: false,
        enforce_namespace: true,
        wrap_ttl_seconds: None,
        origin_peer: None,
        client_certificates: None,
    });
    assert_eq!(response.status, 200);
    let owner = service
        .pending_namespace_deletion
        .take()
        .ok_or("affine original actor")?;
    assert_eq!(
        native(
            &mut service,
            "POST",
            "auth/token/revoke",
            "",
            &root_actor,
            json!({"token":actor})
        )
        .status,
        204
    );
    service.pending_namespace_deletion = Some(owner);
    let response = service.audit_completed_response(
        "delete-test",
        clock.admitted_at().seconds(),
        Some(clock),
        response,
    );
    let response = service.complete_namespace_deletion_delivery(true, response, "delete-test");
    assert_eq!(response.status, 403);
    assert!(response.body.get("data").is_none());
    assert!(service.pending_namespace_deletion.is_none());
    assert!(
        service
            .state
            .as_ref()
            .ok_or("state")?
            .namespace_is_tainted("retire")
    );
    cleanup(&mut service)?;
    Ok(())
}

#[test]
fn failed_actual_cleanup_writer_is_audited_and_keeps_pending_owner() -> TestResult {
    let root = Root::new();
    let mut service = root.service()?;
    let (_, token) = bootstrap_unmounted(&mut service)?;
    let issued = populate(&mut service, &token, "retire")?;
    assert_eq!(
        native(
            &mut service,
            "DELETE",
            "sys/namespaces/retire",
            "",
            &token,
            json!({})
        )
        .status,
        200
    );
    let actual_writer = service.durable.take().ok_or("actual durable writer")?;
    let generation = actual_writer.generation();
    assert!(cleanup(&mut service).is_err());
    assert_eq!(actual_writer.generation(), generation);
    assert!(
        service
            .state
            .as_ref()
            .ok_or("retained")?
            .namespace_is_tainted("retire")
    );
    assert!(service.pending_namespace_deletion.is_none());
    let audit = fs::read_to_string(root.path.join("audit.jsonl"))?;
    let last: Value = serde_json::from_str(audit.lines().last().ok_or("response audit")?)?;
    assert_eq!(last["event"]["kind"], "namespace-cleanup-response");
    assert_eq!(last["event"]["status"], 503);
    service.durable = Some(actual_writer);
    cleanup(&mut service)?;
    assert_eq!(
        native(
            &mut service,
            "GET",
            "sys/namespaces/retire",
            "",
            &token,
            json!({})
        )
        .status,
        404
    );
    assert!(
        native(
            &mut service,
            "GET",
            "auth/token/lookup-self",
            "retire",
            &issued,
            json!({})
        )
        .status
            >= 400
    );
    Ok(())
}

#[test]
fn actual_workflow_owner_rejects_before_taint_and_keeps_definition_and_data() -> TestResult {
    let root = Root::new();
    let mut service = root.service()?;
    let (_, token) = bootstrap_unmounted(&mut service)?;
    let issued = populate(&mut service, &token, "retire")?;
    let definition = json!({
        "cas": 0,
        "steps": [{"name":"read","method":"GET","path":"local/item"}],
        "outputs": {"value":{"step":"read","field":["data","payload"]}}
    });
    assert_eq!(
        native(
            &mut service,
            "POST",
            "sys/workflows/manage/operations/retained",
            "retire",
            &token,
            definition
        )
        .status,
        200
    );
    assert_eq!(
        native(
            &mut service,
            "DELETE",
            "sys/namespaces/retire",
            "",
            &token,
            json!({})
        )
        .status,
        409
    );
    let state = service.state.as_ref().ok_or("retained workflow owner")?;
    assert!(!state.namespaces.workflows.namespace_is_empty("retire"));
    assert!(!state.has_namespace_deletion_state());
    let stored = native(
        &mut service,
        "GET",
        "sys/workflows/manage/operations/retained",
        "retire",
        &token,
        json!({}),
    );
    assert_eq!(stored.status, 200);
    assert_eq!(
        stored.body["data"]["workflow"]["steps"],
        json!([{"name":"read","method":"GET","path":"local/item","body":{}}])
    );
    assert_eq!(
        native(
            &mut service,
            "GET",
            "local/item",
            "retire",
            &token,
            json!({})
        )
        .body["data"]["payload"],
        "owned-leaf"
    );
    assert_eq!(
        native(
            &mut service,
            "GET",
            "auth/token/lookup-self",
            "retire",
            &issued,
            json!({})
        )
        .status,
        200
    );
    let executed = native(
        &mut service,
        "POST",
        "sys/workflows/execute/operations/retained",
        "retire",
        &token,
        json!({}),
    );
    assert_eq!(executed.status, 200);
    assert_eq!(executed.body["data"]["value"], "owned-leaf");
    Ok(())
}
