use super::super::tests::{Root, bootstrap_unmounted, call};
use super::*;
type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

fn wire(
    service: &mut Service,
    method: &str,
    path: &str,
    namespace: &str,
    token: &str,
    body: Value,
) -> Response {
    service.handle_at_mode(RequestDispatch {
        method,
        path,
        namespace,
        token,
        body,
        now: 100,
        allow_forward: true,
        enforce_namespace: true,
        wrap_ttl_seconds: None,
        origin_peer: None,
        client_certificates: None,
    })
}

fn create(
    service: &mut Service,
    namespace: &str,
    child: &str,
    token: &str,
) -> TestResult<Vec<zeroize::Zeroizing<String>>> {
    let response = wire(
        service,
        "POST",
        &format!("sys/namespaces/{child}"),
        namespace,
        token,
        json!({"seal":"seal \"shamir\" { shares = 3\n threshold = 2 }"}),
    );
    assert_eq!(
        response.status, 200,
        "strong namespace created through real dispatch"
    );
    let shares = response.body["data"]["key_shares"]
        .as_array()
        .ok_or("shares omitted")?
        .iter()
        .map(|part| {
            part.as_str()
                .map(|part| zeroize::Zeroizing::new(part.to_owned()))
                .ok_or("share shape")
        })
        .collect::<Result<Vec<_>, _>>()?;
    assert_eq!(
        shares.len(),
        3,
        "only committed namespace returns its three shares"
    );
    Ok(shares)
}

fn unseal(
    service: &mut Service,
    namespace: &str,
    child: &str,
    token: &str,
    shares: &[zeroize::Zeroizing<String>],
) {
    for (index, share) in shares.iter().take(2).enumerate() {
        let response = wire(
            service,
            "POST",
            &format!("sys/namespaces/{child}/unseal"),
            namespace,
            token,
            json!({"key":share.as_str()}),
        );
        assert_eq!(response.status, 200, "actual share request accepted");
        assert_eq!(
            response.body["data"]["sealed"],
            index == 0,
            "threshold gates actual runtime installation"
        );
    }
}

fn write_marker(service: &mut Service, namespace: &str, token: &str) {
    assert_eq!(
        wire(
            service,
            "POST",
            "sys/mounts/kv",
            namespace,
            token,
            json!({"type":"kv"})
        )
        .status,
        204
    );
    assert_eq!(
        wire(
            service,
            "POST",
            "kv/public",
            namespace,
            token,
            json!({"marker":"durable-public"})
        )
        .status,
        204
    );
}

fn marker(service: &mut Service, namespace: &str, token: &str) {
    let response = wire(service, "GET", "kv/public", namespace, token, json!({}));
    assert_eq!(
        response.status, 200,
        "real previously written KV survives its barrier lifecycle"
    );
    assert_eq!(response.body["data"]["marker"], "durable-public");
}

fn short_actor(
    service: &mut Service,
    root: &str,
    explicit: bool,
) -> TestResult<zeroize::Zeroizing<String>> {
    let request = ServiceRequest::new(
        "PUT",
        "sys/policies/acl/namespace-custody",
        "",
        root,
        json!({"policy":"path \"sys/namespaces/*\" { capabilities = [\"read\", \"update\"] }"}),
    );
    let response = if explicit {
        service.handle_request_at(request, 100)
    } else {
        service.handle_request(request)
    };
    assert_eq!(response.status, 204);
    let request = ServiceRequest::new(
        "POST",
        "auth/token/create",
        "",
        root,
        json!({"policies":["namespace-custody"],"no_default_policy":true,"ttl":"2s"}),
    );
    let response = if explicit {
        service.handle_request_at(request, 100)
    } else {
        service.handle_request(request)
    };
    assert_eq!(response.status, 200, "real scoped short-lived actor issued");
    Ok(zeroize::Zeroizing::new(
        response.body["auth"]["client_token"]
            .as_str()
            .ok_or("actor token")?
            .to_owned(),
    ))
}

#[test]
fn strong_http_actor_expires_after_real_commit_without_share_delivery() -> TestResult {
    let root = Root::new();
    let mut service = root.service()?;
    let (_, token) = bootstrap_unmounted(&mut service)?;
    let actor = short_actor(&mut service, &token, false)?;
    let before = service.durable.as_ref().ok_or("durable")?.generation();
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
    let _original = crate::request_deadline::RequestDeadlineScope::enter(deadline);
    let _delay = external_pki::PublicationDelayScope::enter(std::time::Duration::from_millis(2100));
    let response = service.handle_request(ServiceRequest::new(
        "POST",
        "sys/namespaces/late-actor",
        "",
        &actor,
        json!({"seal":"seal \"shamir\" { shares = 3 threshold = 2 }"}),
    ));
    assert!(
        response.status == 403 && response.body.get("data").is_none(),
        "expired actor cannot receive committed namespace shares"
    );
    assert!(
        service.durable.as_ref().ok_or("durable")?.generation() != before
            && service
                .state
                .as_ref()
                .ok_or("state")?
                .namespaces
                .contains("late-actor"),
        "the real commit completed before the delayed actor check"
    );
    assert!(
        !service.namespace_runtime.has_loaded_within("late-actor")
            && crate::request_deadline::current() == Some(deadline),
        "no key is installed and the original deadline is retained"
    );
    Ok(())
}

#[test]
fn strong_http_explicit_clock_retains_its_time_under_real_clock_scope() -> TestResult {
    let root = Root::new();
    let mut service = root.service()?;
    let (_, token) = bootstrap_unmounted(&mut service)?;
    let actor = short_actor(&mut service, &token, true)?;
    let observed = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)?;
    let _listener = external_pki::PublicationClockScope::enter(observed, std::time::Instant::now());
    let _delay = external_pki::PublicationDelayScope::enter(std::time::Duration::from_millis(2100));
    let response = service.handle_request_at(
        ServiceRequest::new(
            "POST",
            "sys/namespaces/explicit-clock",
            "",
            &actor,
            json!({"seal":"seal \"shamir\" { shares = 3 threshold = 2 }"}),
        ),
        100,
    );
    assert!(
        response.status == 200
            && response.body["data"]["key_shares"]
                .as_array()
                .is_some_and(|shares| shares.len() == 3),
        "explicit time remains valid despite actual delay and an outer listener clock"
    );
    Ok(())
}

#[test]
fn strong_http_completed_unseal_late_actor_rejects_before_slot_registration() -> TestResult {
    let root = Root::new();
    let mut service = root.service()?;
    let (_, token) = bootstrap_unmounted(&mut service)?;
    let shares = create(&mut service, "", "late-unseal", &token)?;
    let actor = short_actor(&mut service, &token, false)?;
    let first = service.handle_request(ServiceRequest::new(
        "POST",
        "sys/namespaces/late-unseal/unseal",
        "",
        &actor,
        json!({"key":shares[0].as_str()}),
    ));
    assert_eq!(first.status, 200);
    let observed = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)?;
    let now = observed.as_secs();
    let started = std::time::Instant::now();
    let _clock = external_pki::PublicationClockScope::enter(observed, started);
    let deadline = started + std::time::Duration::from_secs(30);
    let _original = crate::request_deadline::RequestDeadlineScope::enter(deadline);
    let mut state = service.state.clone().ok_or("state")?;
    let principal = state.auth.authenticate(&actor, now)?;
    let binding = state
        .namespaces
        .custody_binding(&state.cluster_id, "late-unseal")
        .map_err(|_| "binding")?;
    let caller = state.namespaces.incarnation("").ok_or("caller")?;
    let before = owner_store::serialize_owner(service.state.as_ref().ok_or("state")?)?;
    let body = json!({"key":shares[1].as_str()});
    let request = RequestView {
        method: "POST",
        path: "sys/namespaces/late-unseal/unseal",
        namespace: "",
        token: &actor,
        body: &body,
        now,
        admission_started: started,
        allow_forward: true,
        enforce_namespace: true,
        wrap_ttl_seconds: None,
        origin_peer: None,
        client_certificates: None,
    };
    let fragment = zeroize::Zeroizing::new(decode_hex(&shares[1]).ok_or("fragment")?);
    let result = service
        .namespace_runtime
        .submit(&state, "late-unseal", &fragment, |candidate| {
            // The real threshold/MAC/typed restoration has already completed.
            // This callback is still before the sole runtime key is registered.
            std::thread::sleep(std::time::Duration::from_millis(2100));
            Service::namespace_custody_gate(
                candidate,
                &principal,
                &request,
                caller,
                "late-unseal",
                &binding,
            )
        });
    assert!(
        result.is_err_and(|error| error.status == 403)
            && !service.namespace_runtime.has_loaded_within("late-unseal")
            && owner_store::serialize_owner(service.state.as_ref().ok_or("state")?)?.as_slice()
                == before.as_slice()
            && crate::request_deadline::current() == Some(deadline),
        "expired actor receives no restored key slot or candidate state"
    );
    assert_eq!(
        service
            .namespace_runtime
            .status(service.state.as_ref().ok_or("state")?, "late-unseal")
            .map_err(|_| "status")?
            .body["data"]["progress"],
        0,
        "completed but denied unseal clears its private progress"
    );
    unseal(&mut service, "", "late-unseal", &token, &shares);
    Ok(())
}

#[test]
fn strong_http_progress_manual_seal_restart_and_stale_candidate_frontier() -> TestResult {
    let root = Root::new();
    let mut service = root.service()?;
    let (root_key, token) = bootstrap_unmounted(&mut service)?;
    let shares = create(&mut service, "", "custody", &token)?;
    let status = wire(
        &mut service,
        "GET",
        "sys/namespaces/custody/seal-status",
        "",
        &token,
        json!({}),
    );
    assert_eq!(status.status, 200);
    assert_eq!(status.body["data"]["sealed"], true);
    assert_eq!(status.body["data"]["progress"], 0);
    assert_eq!(
        wire(
            &mut service,
            "GET",
            "sys/mounts",
            "custody",
            &token,
            json!({})
        )
        .status,
        503
    );
    assert_eq!(
        wire(
            &mut service,
            "POST",
            "sys/namespaces/custody/unseal",
            "",
            &token,
            json!({})
        )
        .status,
        500
    );
    assert_eq!(
        wire(
            &mut service,
            "POST",
            "sys/namespaces/custody/unseal",
            "",
            &token,
            json!({"key":"!"})
        )
        .status,
        400
    );
    let first = wire(
        &mut service,
        "POST",
        "sys/namespaces/custody/unseal",
        "",
        &token,
        json!({"key":shares[0].as_str()}),
    );
    let duplicate = wire(
        &mut service,
        "POST",
        "sys/namespaces/custody/unseal",
        "",
        &token,
        json!({"key":shares[0].as_str()}),
    );
    assert_eq!(first.body["data"]["progress"], 1);
    assert_eq!(duplicate.body["data"]["progress"], 1);
    assert!(
        first.body["data"]["nonce"] == duplicate.body["data"]["nonce"],
        "duplicate does not advance or replace private progress"
    );
    let reset = wire(
        &mut service,
        "POST",
        "sys/namespaces/custody/unseal",
        "",
        &token,
        json!({"reset":true}),
    );
    assert_eq!(reset.body["data"]["progress"], 0);
    assert_eq!(reset.body["data"]["nonce"], "");
    unseal(&mut service, "", "custody", &token, &shares);
    write_marker(&mut service, "custody", &token);
    let mut stale = service.state.clone().ok_or("state")?;
    let before = stale
        .namespaces
        .custody_owner("custody")
        .ok_or("descriptor")?
        .seal_frontier();
    assert_eq!(
        wire(
            &mut service,
            "POST",
            "sys/namespaces/custody/seal",
            "",
            &token,
            json!({})
        )
        .status,
        204
    );
    let closed = service.state.as_ref().ok_or("state")?;
    assert!(
        closed
            .namespaces
            .custody_owner("custody")
            .ok_or("descriptor")?
            .seal_frontier()
            > before,
        "manual closure durably advances the actual frontier"
    );
    assert!(
        stale.namespace_leases.validate().is_err() && service.commit_state(&mut stale).is_err(),
        "old slot references cannot authorize a post-seal publication"
    );
    assert_eq!(
        wire(
            &mut service,
            "GET",
            "kv/public",
            "custody",
            &token,
            json!({})
        )
        .status,
        503
    );
    unseal(&mut service, "", "custody", &token, &shares);
    marker(&mut service, "custody", &token);
    drop(service);
    let mut service = root.service()?;
    assert_eq!(
        call(
            &mut service,
            "POST",
            "sys/unseal",
            "",
            json!({"key":root_key})
        )
        .status,
        200
    );
    assert_eq!(
        wire(
            &mut service,
            "GET",
            "kv/public",
            "custody",
            &token,
            json!({})
        )
        .status,
        503,
        "root restart never reloads an independent namespace key"
    );
    unseal(&mut service, "", "custody", &token, &shares);
    marker(&mut service, "custody", &token);
    Ok(())
}

#[test]
fn strong_http_nested_actual_parent_control_requires_each_independent_key() -> TestResult {
    let root = Root::new();
    let mut service = root.service()?;
    let (_, token) = bootstrap_unmounted(&mut service)?;
    let outer = create(&mut service, "", "outer", &token)?;
    unseal(&mut service, "", "outer", &token, &outer);
    let inner = create(&mut service, "outer", "inner", &token)?;
    let closed_bytes = owner_store::serialize_owner(service.state.as_ref().ok_or("state")?)?;
    let closed_identity = service.current_state_identity().map_err(|_| "identity")?;
    unseal(&mut service, "outer", "inner", &token, &inner);
    let opened = service.state.as_ref().ok_or("state")?;
    assert!(
        owner_store::serialize_owner(opened)?.as_slice() == closed_bytes.as_slice()
            && owner_store::serialize_owner(opened.protected_state().map_err(|_| "protected")?)?
                .as_slice()
                == closed_bytes.as_slice()
            && service.current_state_identity().map_err(|_| "identity")? == closed_identity,
        "child restore immediately preserves the exact protected bytes and durable HA identity"
    );
    write_marker(&mut service, "outer/inner", &token);
    assert_eq!(
        wire(
            &mut service,
            "GET",
            "sys/namespaces/outer/inner/seal-status",
            "",
            &token,
            json!({})
        )
        .status,
        400
    );
    assert_eq!(
        wire(
            &mut service,
            "POST",
            "sys/namespaces/outer/seal",
            "",
            &token,
            json!({})
        )
        .status,
        204
    );
    assert_eq!(
        wire(
            &mut service,
            "POST",
            "sys/namespaces/inner/unseal",
            "outer",
            &token,
            json!({"key":inner[0].as_str()})
        )
        .status,
        503,
        "a sealed request header cannot bypass its barrier via a control route"
    );
    assert_eq!(
        wire(
            &mut service,
            "GET",
            "kv/public",
            "outer/inner",
            &token,
            json!({})
        )
        .status,
        404,
        "closed parent hides the child catalog"
    );
    unseal(&mut service, "", "outer", &token, &outer);
    assert_eq!(
        wire(
            &mut service,
            "GET",
            "kv/public",
            "outer/inner",
            &token,
            json!({})
        )
        .status,
        503,
        "parent shares do not grant the independent child key"
    );
    unseal(&mut service, "outer", "inner", &token, &inner);
    marker(&mut service, "outer/inner", &token);
    Ok(())
}

#[test]
fn strong_http_failed_durable_creation_returns_no_shares_or_runtime_slot() -> TestResult {
    let root = Root::new();
    let mut service = root.service()?;
    let (_, token) = bootstrap_unmounted(&mut service)?;
    let mut state = service.state.clone().ok_or("state")?;
    let principal = state.auth.authenticate(&token, 100)?;
    let body = json!({"seal":"seal \"shamir\" { shares = 3 threshold = 2 }"});
    // Remove the actual durable writer after normal admission. The production
    // commit path must reject the ciphertext candidate and discard its shares.
    service.durable = None;
    let response = service.namespace_route(
        state,
        Some(&principal),
        &RequestView {
            method: "POST",
            path: "sys/namespaces/uncommitted",
            namespace: "",
            token: &token,
            body: &body,
            now: 100,
            admission_started: std::time::Instant::now(),
            allow_forward: true,
            enforce_namespace: true,
            wrap_ttl_seconds: None,
            origin_peer: None,
            client_certificates: None,
        },
    );
    assert!(
        response.status >= 400 && response.body.get("data").is_none(),
        "failed commit cannot deliver shares"
    );
    assert!(
        !service
            .state
            .as_ref()
            .ok_or("state")?
            .namespaces
            .contains("uncommitted"),
        "failed commit cannot publish a catalog owner"
    );
    Ok(())
}

#[test]
fn strong_http_delete_recreate_retires_slots_cells_and_actual_incarnation() -> TestResult {
    let root = Root::new();
    let mut service = root.service()?;
    let (_, token) = bootstrap_unmounted(&mut service)?;
    let old = create(&mut service, "", "empty-owner", &token)?;
    unseal(&mut service, "", "empty-owner", &token, &old);
    let stale = service.state.clone().ok_or("state")?;
    let incarnation = stale
        .namespaces
        .incarnation("empty-owner")
        .ok_or("incarnation")?;
    assert_eq!(
        wire(
            &mut service,
            "DELETE",
            "sys/namespaces/empty-owner",
            "",
            &token,
            json!({})
        )
        .status,
        200
    );
    assert!(
        stale.namespace_leases.validate().is_err(),
        "successful deletion drops the old sole key despite retained state references"
    );
    assert!(
        !service
            .state
            .as_ref()
            .ok_or("state")?
            .engines
            .has_namespace_record_custody(),
        "deleted owner's opaque cells and binding are removed in the same durable candidate"
    );
    let fresh = create(&mut service, "", "empty-owner", &token)?;
    assert!(
        service
            .state
            .as_ref()
            .ok_or("state")?
            .namespaces
            .incarnation("empty-owner")
            .ok_or("incarnation")?
            > incarnation,
        "recreation cannot reuse the deleted actual incarnation"
    );
    assert_eq!(
        wire(
            &mut service,
            "POST",
            "sys/namespaces/empty-owner/unseal",
            "",
            &token,
            json!({"key":old[0].as_str()})
        )
        .status,
        200
    );
    assert_eq!(
        wire(
            &mut service,
            "POST",
            "sys/namespaces/empty-owner/unseal",
            "",
            &token,
            json!({"key":old[1].as_str()})
        )
        .status,
        400,
        "old shares cannot load a recreated owner's key"
    );
    unseal(&mut service, "", "empty-owner", &token, &fresh);
    Ok(())
}

#[test]
fn strong_http_original_expired_deadline_returns_no_grant_and_clears_progress() -> TestResult {
    let root = Root::new();
    let mut service = root.service()?;
    let (_, token) = bootstrap_unmounted(&mut service)?;
    {
        let _deadline =
            crate::request_deadline::RequestDeadlineScope::enter(std::time::Instant::now());
        let response = wire(
            &mut service,
            "POST",
            "sys/namespaces/expired-create",
            "",
            &token,
            json!({"seal":"seal \"shamir\" { shares = 3 threshold = 2 }"}),
        );
        assert_eq!(response.status, 503);
        assert!(
            response.body.get("data").is_none()
                && !service
                    .state
                    .as_ref()
                    .ok_or("state")?
                    .namespaces
                    .contains("expired-create"),
            "expired original request cannot deliver shares or install a new owner"
        );
    }
    let shares = create(&mut service, "", "partial-owner", &token)?;
    assert_eq!(
        wire(
            &mut service,
            "POST",
            "sys/namespaces/partial-owner/unseal",
            "",
            &token,
            json!({"key":shares[0].as_str()})
        )
        .status,
        200
    );
    {
        let _deadline =
            crate::request_deadline::RequestDeadlineScope::enter(std::time::Instant::now());
        assert_eq!(
            wire(
                &mut service,
                "POST",
                "sys/namespaces/partial-owner/unseal",
                "",
                &token,
                json!({"key":shares[1].as_str()})
            )
            .status,
            503
        );
    }
    let status = wire(
        &mut service,
        "GET",
        "sys/namespaces/partial-owner/seal-status",
        "",
        &token,
        json!({}),
    );
    assert_eq!(status.body["data"]["sealed"], true);
    assert_eq!(status.body["data"]["progress"], 0);
    unseal(&mut service, "", "partial-owner", &token, &shares);
    Ok(())
}
