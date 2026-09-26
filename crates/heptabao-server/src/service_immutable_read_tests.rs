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
    let mut expected_scan = vec!["small".to_owned()];
    expected_scan.extend((0..8).map(|index| format!("large/{index}")));
    assert_eq!(scanned.body["data"]["keys"], json!(expected_scan));
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
        enforce_namespace: true,
        wrap_ttl_seconds: Some(30),
        origin_peer: None,
        client_certificates: None,
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

#[test]
fn kv_root_enumeration_canonicalizes_before_authorization_and_forwarded_dispatch() -> TestResult {
    let root = Root::new();
    let mut service = root.service()?;
    let (_, root_token) = bootstrap(&mut service)?;
    for (mount, key) in [
        ("legacy", "short-key"),
        ("legacy-long", "long-key"),
        ("team/legacy", "nested-key"),
    ] {
        assert_eq!(
            call(
                &mut service,
                "POST",
                &format!("sys/mounts/{mount}"),
                &root_token,
                json!({"type":"kv","options":{"version":"1"}})
            )
            .status,
            204
        );
        assert_eq!(
            call(
                &mut service,
                "POST",
                &format!("{mount}/{key}"),
                &root_token,
                json!({"v":"synthetic"})
            )
            .status,
            204
        );
    }
    let engines = &service.state.as_ref().ok_or("missing state")?.engines;
    for path in [
        "leg",
        "legacy-lon",
        "legacy/key",
        "transit",
        "auth/token/accessors",
        "sys/auth",
    ] {
        assert!(
            engines
                .canonical_kv_enumeration_root("", "LIST", path)
                .is_none()
        );
    }
    assert!(
        engines
            .canonical_kv_enumeration_root("other", "LIST", "legacy")
            .is_none()
    );
    assert!(
        engines
            .canonical_kv_enumeration_root("", "GET", "legacy")
            .is_none()
    );
    assert_eq!(
        engines
            .canonical_kv_enumeration_root("", "SCAN", "team/legacy")
            .as_deref(),
        Some("team/legacy/")
    );

    // The bare spelling must receive the canonical root's list permission.
    // Explicitly denying the bare spelling detects authorization before fixup.
    for (policy, rules) in [
        (
            "root-list",
            "path \"legacy/\" { capabilities = [\"list\"] }\npath \"legacy\" { capabilities = [\"deny\"] }",
        ),
        (
            "root-read",
            "path \"legacy/*\" { capabilities = [\"read\"] }",
        ),
    ] {
        assert_eq!(
            call(
                &mut service,
                "POST",
                &format!("sys/policies/acl/{policy}"),
                &root_token,
                json!({"policy":rules})
            )
            .status,
            204
        );
    }
    let mut tokens = Vec::new();
    for policy in ["root-list", "root-read"] {
        let response = call(
            &mut service,
            "POST",
            "auth/token/create",
            &root_token,
            json!({"policies":[policy],"no_default_policy":true}),
        );
        assert_eq!(response.status, 200);
        tokens.push(
            response.body["auth"]["client_token"]
                .as_str()
                .ok_or("missing token")?
                .to_owned(),
        );
    }
    let before = serde_json::to_vec(service.state.as_ref().ok_or("missing state")?)?;
    for method in ["LIST", "SCAN"] {
        let audit_before = service.audit_sequence;
        let bare = call(&mut service, method, "legacy", &tokens[0], json!({}));
        let canonical = call(&mut service, method, "legacy/", &tokens[0], json!({}));
        assert_eq!(bare.status, 200);
        assert_eq!(bare.body, canonical.body);
        assert_eq!(bare.body["data"]["keys"], json!(["short-key"]));
        let audit_bytes = fs::read(root.path.join("audit.jsonl"))?;
        let events = audit_bytes
            .split(|byte| *byte == b'\n')
            .filter(|line| !line.is_empty())
            .map(serde_json::from_slice::<AuditRecord>)
            .collect::<Result<Vec<_>, _>>()?
            .into_iter()
            .filter(|record| record.event.sequence > audit_before)
            .map(|record| record.event)
            .collect::<Vec<_>>();
        assert_eq!(events.len(), 4);
        for (pair, client_path) in events.as_chunks::<2>().0.iter().zip(["legacy", "legacy/"]) {
            assert_eq!(pair[0].kind, "request");
            assert_eq!(pair[1].kind, "response");
            let fingerprint = service.request_fingerprint(method, client_path, "", &tokens[0]);
            assert_eq!(pair[0].path_digest, fingerprint);
            assert_eq!(pair[1].path_digest, fingerprint);
        }

        for path in ["legacy", "legacy/"] {
            assert_eq!(
                call(&mut service, method, path, &tokens[1], json!({})).status,
                403
            );
        }
        assert_eq!(
            call(&mut service, method, "legacy-long", &tokens[0], json!({})).status,
            403
        );
        assert_eq!(
            call(&mut service, method, "legacy-long", &root_token, json!({})).body["data"]["keys"],
            json!(["long-key"])
        );
        assert_eq!(
            call(&mut service, method, "team/legacy", &root_token, json!({})).body["data"]["keys"],
            json!(["nested-key"])
        );
        // Exercise the shared authenticated-forwarding entry with the same
        // deterministic clock as bootstrap and the preceding direct requests.
        let forwarded = match service.begin_at_mode(RequestDispatch {
            method,
            path: "legacy",
            namespace: "",
            token: &root_token,
            body: json!({}),
            now: 100,
            allow_forward: false,
            enforce_namespace: true,
            wrap_ttl_seconds: None,
            origin_peer: None,
            client_certificates: None,
        }) {
            RequestExecution::Complete(response) => response,
            RequestExecution::External(_) => return Err("unexpected external request".into()),
        };
        assert_eq!(forwarded.status, 200);
        assert_eq!(forwarded.body["data"]["keys"], json!(["short-key"]));
    }
    assert_eq!(
        serde_json::to_vec(service.state.as_ref().ok_or("missing state")?)?,
        before
    );
    drop(service);
    let mut sealed = root.service()?;
    assert!(sealed.state.is_none());
    for path in ["legacy", "legacy/"] {
        assert_eq!(
            call(&mut sealed, "LIST", path, &root_token, json!({})).status,
            503
        );
    }
    Ok(())
}
