//! Actual Service admission and audit regressions for immutable KV dispatch.
use super::tests::{Root, bootstrap, call, limited_token};
use super::*;
type TestResult = Result<(), Box<dyn std::error::Error>>;

fn seed(service: &mut Service, token: &str) {
    assert_eq!(
        call(
            service,
            "PUT",
            "secret/data/small",
            token,
            json!({"data":{"value":"synthetic-read-value"}})
        )
        .status,
        200
    );
}

#[test]
fn immutable_kv_reads_keep_generation_replay_and_state_unchanged_across_restart() -> TestResult {
    let root = Root::new();
    let mut service = root.service()?;
    let (key, token) = bootstrap(&mut service)?;
    seed(&mut service, &token);
    for index in 0..8 {
        let response = call(
            &mut service,
            "PUT",
            &format!("secret/data/large/{index}"),
            &token,
            json!({"data":{"payload":"x".repeat(192 * 1024)}}),
        );
        assert_eq!(response.status, 200);
    }
    let before = serde_json::to_vec(service.state.as_ref().ok_or("state missing")?)?;
    assert!(before.len() > 768 * 1024);
    let generation = service
        .durable
        .as_ref()
        .ok_or("durable missing")?
        .generation();
    let retained = service
        .durable
        .as_ref()
        .ok_or("durable missing")?
        .retained_request_count();
    let audit = service.audit_sequence;
    let reads = service.kv_read_only_dispatches;
    let response = call(&mut service, "GET", "secret/data/small", &token, json!({}));
    assert_eq!(response.status, 200);
    assert_eq!(
        response.body["data"]["data"]["value"],
        "synthetic-read-value"
    );
    let listed = call(
        &mut service,
        "LIST",
        "secret/metadata",
        &token,
        json!({"limit":1}),
    );
    assert_eq!(listed.status, 200);
    assert_eq!(listed.body["data"]["keys"], json!(["large/"]));
    let scanned = call(
        &mut service,
        "SCAN",
        "secret/metadata",
        &token,
        json!({"after":"large/5","limit":2}),
    );
    assert_eq!(scanned.status, 200);
    assert_eq!(scanned.body["data"]["keys"], json!(["large/6", "large/7"]));
    assert_eq!(service.kv_read_only_dispatches, reads + 3);
    assert_eq!(service.audit_sequence, audit + 6);
    assert_eq!(
        service
            .durable
            .as_ref()
            .ok_or("durable missing")?
            .generation(),
        generation
    );
    assert_eq!(
        service
            .durable
            .as_ref()
            .ok_or("durable missing")?
            .retained_request_count(),
        retained
    );
    assert_eq!(
        serde_json::to_vec(service.state.as_ref().ok_or("state missing")?)?,
        before
    );
    drop(service);
    let mut service = root.service()?;
    assert_eq!(
        call(&mut service, "PUT", "sys/unseal", "", json!({"key":key})).status,
        200
    );
    assert_eq!(service.kv_read_only_dispatches, 0);
    assert_eq!(
        call(&mut service, "GET", "secret/data/small", &token, json!({})).status,
        200
    );
    assert_eq!(service.kv_read_only_dispatches, 1);
    Ok(())
}

#[test]
fn immutable_read_keeps_live_acl_parent_expiry_and_namespace_checks() -> TestResult {
    let root = Root::new();
    let mut service = root.service()?;
    let (_, root_token) = bootstrap(&mut service)?;
    seed(&mut service, &root_token);
    assert_eq!(
        call(
            &mut service,
            "PUT",
            "sys/policies/acl/readonly",
            &root_token,
            json!({"policy":"path \"secret/*\" { capabilities = [\"read\"] }"})
        )
        .status,
        204
    );
    let created = call(
        &mut service,
        "POST",
        "auth/token/create",
        &root_token,
        json!({"policies":["readonly"], "ttl":"20s", "explicit_max_ttl":"20s"}),
    );
    let token = created.body["auth"]["client_token"]
        .as_str()
        .ok_or("token missing")?;
    assert_eq!(
        call(&mut service, "GET", "secret/data/small", token, json!({})).status,
        200
    );
    // A direct embedding must not turn read authority into LIST authority.
    for alias in [json!(true), json!("true")] {
        assert_eq!(
            call(
                &mut service,
                "GET",
                "secret/metadata",
                token,
                json!({"list":alias})
            )
            .status,
            403
        );
    }
    assert_eq!(
        call(
            &mut service,
            "GET",
            "secret/data/small",
            "invalid",
            json!({})
        )
        .status,
        403
    );
    assert_eq!(
        service
            .handle_at("GET", "secret/data/small", "other", token, json!({}), 100)
            .status,
        403
    );
    assert_eq!(
        service
            .handle_at("GET", "secret/data/small", "", token, json!({}), 120)
            .status,
        403
    );
    assert_eq!(
        call(
            &mut service,
            "PUT",
            "sys/policies/acl/readonly",
            &root_token,
            json!({"policy":"path \"secret/*\" { capabilities = [\"deny\"] }"})
        )
        .status,
        204
    );
    assert_eq!(
        call(&mut service, "GET", "secret/data/small", token, json!({})).status,
        403
    );
    assert!(service.kv_read_only_dispatches >= 5);
    Ok(())
}

#[test]
fn finite_use_reads_retain_durable_admission_and_are_never_fast_path() -> TestResult {
    let root = Root::new();
    let mut service = root.service()?;
    let (key, root_token) = bootstrap(&mut service)?;
    seed(&mut service, &root_token);
    let token = limited_token(
        &mut service,
        &root_token,
        "path \"secret/data/small\" { capabilities = [\"read\"] }",
    )?;
    let reads = service.kv_read_only_dispatches;
    let generation = service
        .durable
        .as_ref()
        .ok_or("durable missing")?
        .generation();
    assert_eq!(
        call(&mut service, "GET", "secret/data/small", &token, json!({})).status,
        200
    );
    assert_eq!(service.kv_read_only_dispatches, reads);
    assert!(
        service
            .durable
            .as_ref()
            .ok_or("durable missing")?
            .generation()
            > generation
    );
    drop(service);
    let mut service = root.service()?;
    assert_eq!(
        call(&mut service, "PUT", "sys/unseal", "", json!({"key":key})).status,
        200
    );
    assert_eq!(
        call(&mut service, "GET", "secret/data/small", &token, json!({})).status,
        403
    );
    Ok(())
}

#[test]
fn immutable_read_result_audit_failure_withholds_secret_and_fences_service() -> TestResult {
    let root = Root::new();
    let mut service = root.service()?;
    let (_, token) = bootstrap(&mut service)?;
    seed(&mut service, &token);
    let event = AuditUnsigned {
        schema: 2,
        sequence: service.audit_sequence + 1,
        previous: STANDARD.encode(service.audit_previous),
        time: 100,
        kind: "request".into(),
        status: None,
        path_digest: service.request_fingerprint("GET", "secret/data/small", "", &token),
    };
    let payload = serde_json::to_vec(&event)?;
    let mac = STANDARD.encode(hmac::sign(&service.audit_key, &payload).as_ref());
    let request_bytes = serde_json::to_vec(&AuditRecord { event, mac })?.len() + 1;
    service.audit_capacity = service.audit.metadata()?.len() + request_bytes as u64;
    let reads = service.kv_read_only_dispatches;
    let response = call(&mut service, "GET", "secret/data/small", &token, json!({}));
    assert_eq!(service.kv_read_only_dispatches, reads + 1);
    assert_eq!(response.status, 503);
    assert!(!response.body.to_string().contains("synthetic-read-value"));
    assert!(service.recovery_required);
    Ok(())
}

#[test]
fn wrapping_read_uses_transactional_capture_not_immutable_dispatch() -> TestResult {
    let root = Root::new();
    let mut service = root.service()?;
    let (_, token) = bootstrap(&mut service)?;
    seed(&mut service, &token);
    let before = service.kv_read_only_dispatches;
    let response = service.handle_at_mode(RequestDispatch {
        method: "GET",
        path: "secret/data/small",
        namespace: "",
        token: &token,
        body: json!({}),
        now: 100,
        allow_forward: true,
        wrap_ttl_seconds: Some(30),
    });
    assert_eq!(response.status, 200);
    let wrapping = response.body["wrap_info"]["token"]
        .as_str()
        .ok_or("wrapping missing")?;
    assert!(!response.body.to_string().contains("synthetic-read-value"));
    assert_eq!(service.kv_read_only_dispatches, before);
    assert_eq!(
        call(
            &mut service,
            "GET",
            "secret/data/small",
            wrapping,
            json!({})
        )
        .status,
        403
    );
    assert_eq!(service.kv_read_only_dispatches, before);
    Ok(())
}

#[test]
fn immutable_read_rechecks_parent_revocation_after_restart() -> TestResult {
    let root = Root::new();
    let mut service = root.service()?;
    let (key, root_token) = bootstrap(&mut service)?;
    seed(&mut service, &root_token);
    assert_eq!(
        call(
            &mut service,
            "PUT",
            "sys/policies/acl/readonly",
            &root_token,
            json!({"policy":"path \"secret/*\" { capabilities = [\"read\"] }"})
        )
        .status,
        204
    );
    let parent_reply = call(
        &mut service,
        "POST",
        "auth/token/create",
        &root_token,
        json!({"policies":["root"],"ttl":"1h"}),
    );
    assert_eq!(parent_reply.status, 200);
    let parent = parent_reply.body["auth"]["client_token"]
        .as_str()
        .ok_or("parent missing")?;
    let child_reply = call(
        &mut service,
        "POST",
        "auth/token/create",
        parent,
        json!({"policies":["readonly"],"ttl":"1h"}),
    );
    assert_eq!(child_reply.status, 200);
    let child = child_reply.body["auth"]["client_token"]
        .as_str()
        .ok_or("child missing")?;
    assert_eq!(
        call(&mut service, "GET", "secret/data/small", child, json!({})).status,
        200
    );
    let reads = service.kv_read_only_dispatches;
    assert_eq!(
        call(
            &mut service,
            "POST",
            "auth/token/revoke",
            &root_token,
            json!({"token":parent})
        )
        .status,
        204
    );
    assert_eq!(
        call(&mut service, "GET", "secret/data/small", child, json!({})).status,
        403
    );
    assert_eq!(service.kv_read_only_dispatches, reads + 1);
    drop(service);
    let mut service = root.service()?;
    assert_eq!(
        call(&mut service, "POST", "sys/unseal", "", json!({"key":key})).status,
        200
    );
    assert_eq!(
        call(&mut service, "GET", "secret/data/small", child, json!({})).status,
        403
    );
    assert_eq!(service.kv_read_only_dispatches, 1);
    Ok(())
}
