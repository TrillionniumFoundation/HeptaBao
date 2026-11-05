//! Actual normal NativeV6Raft and pinned peer TLS, with the real HTTP parser,
//! Service dispatch, response audit and wire projection. The HTTP client here
//! is in-process; this is not a public HTTPS or physical LAN qualification.
use super::*;
use crate::http::no_forward_tests::{Wire, request, wire};

struct Unchanged {
    identity: crate::state_record_root::StateIdentity,
    generation: u64,
    state: Zeroizing<Vec<u8>>,
    native_root: Zeroizing<Vec<u8>>,
    uses: u64,
}

fn unchanged(service: &Service) -> TestResult<Unchanged> {
    let deadline = crate::v6_native_custody::OriginalDeadline::capture()?;
    let state = service.state.as_ref().ok_or("normal HA state")?;
    assert!(service.native_root.is_some() && service.record_root.is_none());
    assert!(state.has_token_api_precision_state());
    let mut auth = serde_json::to_value(&*state.auth)?;
    let tokens = auth["tokens"].as_object().ok_or("actual token registry")?;
    let selected = tokens
        .values()
        .filter(|token| token["display_name"] == "no-forward-fixture")
        .collect::<Vec<_>>();
    assert_eq!(selected.len(), 1);
    assert!(selected[0]["token_api_precision"].is_object());
    let uses = selected[0]["uses_remaining"]
        .as_u64()
        .ok_or("actual finite uses")?;
    erase_json(&mut auth);
    // Native KV2 is encoded as authenticated records, never a flat State.
    // This root-only fixture has no loaded namespace view. Preserve every
    // original metadata field and witness the actual live record owners.
    assert!(state.namespace_protected.is_none() && state.namespace_leases.is_empty());
    let root = service.native_root.as_ref().ok_or("actual native root")?;
    let key = root.kv1_key().map_err(|_| "actual native KV1 key")?;
    assert!(state.engines.record_root().as_ref() == Some(&root.kv1));
    assert!(
        state
            .engines
            .record_address_key()
            .is_some_and(|actual| actual.expose() == key.expose())
    );
    let parent = root.kv2_parent_key().map_err(|_| "actual native KV2 key")?;
    // Borrow the existing Pipeline inspection scope, including every checked
    // projection visit; do not create or extend a business request deadline.
    let check = || {
        deadline
            .check()
            .map_err(|_| crate::state_records::RecordError::Invalid)
    };
    let (engines, graphs) = state
        .engines
        .project_checked_native_roots(
            &parent,
            &root.kv2,
            root.reader_floor.native_kv2_format,
            &check,
        )
        .map_err(|_| "actual native KV2 roots")?;
    assert!(graphs == root.kv2);
    let mut metadata = state.clone();
    metadata.engines = engines.into();
    let observed = Unchanged {
        identity: service
            .current_state_identity()
            .map_err(|_| "actual root identity")?,
        generation: service
            .durable
            .as_ref()
            .ok_or("actual durable owner")?
            .generation(),
        state: Zeroizing::new(serde_json::to_vec(&metadata)?),
        native_root: root.encode().map_err(|_| "actual native root encoding")?,
        uses,
    };
    deadline.check()?;
    Ok(observed)
}

fn assert_unchanged(service: &Service, before: &Unchanged) -> TestResult {
    let after = unchanged(service)?;
    assert!(after.identity == before.identity);
    assert_eq!(after.generation, before.generation);
    assert!(after.state.as_slice() == before.state.as_slice());
    assert!(after.native_root.as_slice() == before.native_root.as_slice());
    assert_eq!(after.uses, before.uses);
    assert_eq!(after.uses, 2);
    assert!(service.pending_forward_delivery.is_none());
    assert!(service.pending_ordinary_kv_authority.is_none());
    assert!(service.pending_native_auth_delivery.is_none());
    Ok(())
}

fn finite_actor(
    pipeline: &PkiPipeline,
    leader: usize,
    follower: usize,
) -> TestResult<Zeroizing<String>> {
    let mut issued = expect(pipeline.call(leader, "POST", "auth/token/create", pipeline.admin(),
        json!({"policies":["root"],"ttl":"5m","num_uses":2,"no_default_policy":true,"no_parent":true,
               "display_name":"no-forward-fixture"}))?, 200, "no-forward-actual-finite-token")?;
    let actor = secret_field(&mut issued, "/auth/client_token")?;
    erase_json(&mut issued.body);
    pipeline.with_service_mut_for_delivery_test(follower, |service| {
        service
            .sync_from_ha_before_request_admission(false, true)
            .map_err(|_| "actual follower catch-up before no-forward observation")?;
        assert_eq!(unchanged(service)?.uses, 2);
        Ok(())
    })?;
    Ok(actor)
}

fn http(
    pipeline: &PkiPipeline,
    node: usize,
    method: &str,
    target: &str,
    actor: &str,
    fields: &str,
    body: Value,
    attempt: u8,
) -> TestResult<Wire> {
    let until = Instant::now() + REQUEST_BUDGET;
    let raw = request(method, target, actor, fields, &body);
    let service = pipeline.services[node]
        .as_ref()
        .ok_or("actual HTTP Service")?;
    let response = wire(service, &raw, &[attempt; 16], until)?;
    assert!(
        Instant::now() < until,
        "the original 15-second request budget is unchanged"
    );
    Ok(response)
}

fn configured_origin(pipeline: &PkiPipeline, node: usize, leader: usize) -> TestResult<String> {
    let process = pipeline.processes[node]
        .as_ref()
        .ok_or("actual HA process")?;
    let process = process.lock().map_err(|_| "actual HA process lock")?;
    assert_eq!(process.leader()?, Some(u64::try_from(leader + 1)?));
    process
        .api_address(u64::try_from(leader + 1)?)
        .map(str::to_owned)
        .ok_or_else(|| "configured leader API origin".into())
}

#[test]
fn no_forward271_normal_ha_keeps_local_routes_and_does_not_consume_actor() -> TestResult {
    let pipeline = PkiPipeline::start()?;
    let leader = pipeline.ready_leader()?;
    let follower = (leader + 1) % 3;
    let actor = finite_actor(&pipeline, leader, follower)?;
    let origin = configured_origin(&pipeline, follower, leader)?;
    let target = "/v1/secret/data/pipeline/history?version=1&ordinary=a%2Fb+z&encoded=x%26y";
    let before_leader = pipeline.with_service(leader, unchanged)?;
    let before_follower = pipeline.with_service(follower, unchanged)?;
    let before_audit = pipeline.with_service(follower, |service| Ok(service.audit_sequence))?;
    for (index, fields) in [
        "X-Vault-No-Request-Forwarding: 1\r\n",
        "X-Vault-No-Request-Forwarding: false\r\n",
        "X-Vault-No-Request-Forwarding: 0\r\n",
        "x-VaUlT-nO-rEqUeSt-FoRwArDiNg:\t false \t\r\n",
        "X-Vault-No-Request-Forwarding: 1\r\nx-vault-no-request-forwarding: \r\n",
    ]
    .into_iter()
    .enumerate()
    {
        let response = http(
            &pipeline,
            follower,
            "GET",
            target,
            &actor,
            fields,
            json!({}),
            u8::try_from(10 + index)?,
        )?;
        assert_eq!(response.status, 307);
        assert_eq!(response.header("Location"), &[format!("{origin}{target}")]);
        assert!(response.body.is_empty());
        pipeline.with_service(follower, |service| {
            assert_unchanged(service, &before_follower)
        })?;
        pipeline.with_service(leader, |service| assert_unchanged(service, &before_leader))?;
    }
    // The original incomplete-wire counterexample was a write with a body.
    // This complete original POST is routed before actor admission; the two
    // actual state graphs prove no write without a later leader API request.
    let write_target = "/v1/secret/data/no-forward-write";
    let response = http(
        &pipeline,
        follower,
        "POST",
        write_target,
        &actor,
        "X-Vault-No-Request-Forwarding: 1\r\n",
        json!({"options":{"cas":0},"data":{"value":"must-not-be-written"}}),
        25,
    )?;
    assert_eq!(response.status, 307);
    assert_eq!(
        response.header("Location"),
        &[format!("{origin}{write_target}")]
    );
    assert!(response.body.is_empty());
    pipeline.with_service(follower, |service| {
        assert_unchanged(service, &before_follower)
    })?;
    pipeline.with_service(leader, |service| assert_unchanged(service, &before_leader))?;
    pipeline.with_service(follower, |service| {
        assert_eq!(
            service.audit_sequence,
            before_audit + 12,
            "all six local routing hints have both actual audit events"
        );
        Ok(())
    })?;
    let health = http(
        &pipeline,
        follower,
        "GET",
        "/v1/sys/health?standbyok=true",
        "",
        "X-Vault-No-Request-Forwarding: 1\r\n",
        json!({}),
        30,
    )?;
    assert_eq!(health.status, 200);
    assert!(health.header("Location").is_empty());
    pipeline.with_service(follower, |service| {
        assert_unchanged(service, &before_follower)
    })?;

    // The original receiver loop guard still rejects a forwarded hop. A local
    // HTTP preference cannot mint a second redirect from this receiver path.
    pipeline.with_service_mut_for_delivery_test(follower, |service| {
        let attempt = [31; 16];
        let _ingress = crate::auth::IngressReplyScope::listener(&attempt);
        let body = json!({});
        let mut frame = crate::request_metadata::DataFrame::default();
        frame.headers.insert(
            crate::request_metadata::NO_FORWARD_HEADER.to_owned(),
            vec!["1".to_owned()],
        );
        frame.bind_local_redirect(
            crate::request_metadata::CheckedLocalRedirectTarget::checked(
                "/v1/secret/data/pipeline/history",
            )?,
            ("GET", "secret/data/pipeline/history", "", &body),
            &attempt,
        )?;
        let _metadata = crate::request_metadata::Scope::enter(
            Some(frame),
            "GET",
            "secret/data/pipeline/history",
            "",
            &body,
        )?;
        let until = crate::request_deadline::current().ok_or("original loop guard deadline")?;
        let execution = service.begin_request_before(
            ServiceRequest::new("GET", "secret/data/pipeline/history", "", &actor, body),
            until,
            true,
        );
        let response = service.finish_synchronous_request(execution);
        assert_eq!(response.status, 503);
        assert!(!response.response_headers.has_local_redirect());
        assert!(response.body.get("data").is_none());
        Ok(())
    })?;

    // Empty first values preserve the normal peer-forwarding route. CAS=0
    // and the actual metadata/version check prove one original execution.
    for (index, fields) in [
        "X-Vault-No-Request-Forwarding: \r\n",
        "X-Vault-No-Request-Forwarding: \r\nx-vault-no-request-forwarding: 1\r\n",
    ]
    .into_iter()
    .enumerate()
    {
        let path = format!("secret/data/no-forward-empty-{index}");
        let response = http(
            &pipeline,
            follower,
            "POST",
            &format!("/v1/{path}"),
            pipeline.admin(),
            fields,
            json!({"options":{"cas":0},"data":{"value":"exact-once"}}),
            u8::try_from(40 + index)?,
        )?;
        assert_eq!(response.status, 200);
        assert!(response.header("Location").is_empty());
        assert_eq!(response.json()?["data"]["version"], 1);
        let read = expect(
            pipeline.call(leader, "GET", &path, pipeline.admin(), json!({}))?,
            200,
            "no-forward-empty-actual-leader-read",
        )?;
        assert_eq!(read.body["data"]["metadata"]["version"], 1);
        assert_eq!(read.body["data"]["data"]["value"], "exact-once");
        let metadata = expect(
            pipeline.call(
                leader,
                "GET",
                &path.replacen("/data/", "/metadata/", 1),
                pipeline.admin(),
                json!({}),
            )?,
            200,
            "no-forward-empty-actual-versions",
        )?;
        assert_eq!(metadata.body["data"]["current_version"], 1);
        assert_eq!(
            metadata.body["data"]["versions"]
                .as_object()
                .ok_or("actual versions")?
                .len(),
            1
        );
    }
    let response = http(
        &pipeline,
        leader,
        "POST",
        "/v1/secret/data/no-forward-leader",
        pipeline.admin(),
        "X-Vault-No-Request-Forwarding: false\r\n",
        json!({"options":{"cas":0},"data":{"value":"leader-once"}}),
        50,
    )?;
    assert_eq!(response.status, 200);
    assert_eq!(response.json()?["data"]["version"], 1);
    assert!(response.header("Location").is_empty());
    let metadata = expect(
        pipeline.call(
            leader,
            "GET",
            "secret/metadata/no-forward-leader",
            pipeline.admin(),
            json!({}),
        )?,
        200,
        "no-forward-leader-actual-versions",
    )?;
    assert_eq!(metadata.body["data"]["current_version"], 1);
    assert_eq!(
        metadata.body["data"]["versions"]
            .as_object()
            .ok_or("actual leader versions")?
            .len(),
        1
    );
    Ok(())
}

#[test]
fn no_forward271_normal_ha_original_deadline_and_real_response_audit_withhold_location()
-> TestResult {
    let pipeline = PkiPipeline::start()?;
    let leader = pipeline.ready_leader()?;
    let follower = (leader + 1) % 3;
    let actor = finite_actor(&pipeline, leader, follower)?;
    let path = "secret/data/pipeline/history";
    let target = "/v1/secret/data/pipeline/history";
    let fields = "X-Vault-No-Request-Forwarding: 1\r\n";
    let before = pipeline.with_service(follower, unchanged)?;
    let positive = http(
        &pipeline,
        follower,
        "GET",
        target,
        &actor,
        fields,
        json!({}),
        60,
    )?;
    assert_eq!(positive.status, 307);
    assert!(positive.body.is_empty());
    pipeline.with_service(follower, |service| assert_unchanged(service, &before))?;

    let raw = request("GET", target, &actor, fields, &json!({}));
    let service = pipeline.services[follower]
        .as_ref()
        .ok_or("actual follower Service")?;
    let expired = wire(
        service,
        &raw,
        &[61; 16],
        Instant::now() - Duration::from_millis(1),
    )?;
    assert_eq!(expired.status, 503);
    assert!(expired.header("Location").is_empty());
    pipeline.with_service(follower, |service| assert_unchanged(service, &before))?;

    // Permit precisely the real next request append, then fail the response
    // append. MAC contents and wall seconds do not change their encoded width.
    let before_audit = pipeline.with_service_mut_for_delivery_test(follower, |service| {
        let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
        let event = AuditUnsigned {
            schema: 2,
            sequence: service.audit_sequence + 1,
            previous: STANDARD.encode(service.audit_previous),
            time: now,
            kind: "request".into(),
            path_digest: service.request_fingerprint("GET", path, "", &actor),
            status: None,
        };
        let payload = serde_json::to_vec(&event)?;
        let mac = STANDARD.encode(hmac::sign(&service.audit_key, &payload).as_ref());
        let length = serde_json::to_vec(&AuditRecord { event, mac })?.len() + 1;
        service.audit_capacity = service.audit.metadata()?.len() + u64::try_from(length)?;
        Ok(service.audit_sequence)
    })?;
    let refused = http(
        &pipeline,
        follower,
        "GET",
        target,
        &actor,
        fields,
        json!({}),
        62,
    )?;
    assert_eq!(refused.status, 503);
    assert!(refused.header("Location").is_empty());
    assert!(
        refused
            .json()?
            .get("errors")
            .and_then(Value::as_array)
            .is_some_and(|errors| errors
                .iter()
                .any(|value| value.as_str().is_some_and(|value| value.contains("audit"))))
    );
    pipeline.with_service(follower, |service| {
        assert_eq!(
            service.audit_sequence,
            before_audit + 1,
            "request audit succeeded and response audit did not"
        );
        assert!(service.recovery_required);
        assert_unchanged(service, &before)
    })?;
    Ok(())
}
