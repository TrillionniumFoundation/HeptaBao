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
    // RequestDispatch is the trusted internal HTTP bridge. A direct HELP still
    // needs exactly the carrier built by http::help::carrier on the wire path.
    let body = if method == "HELP" {
        json!({"__heptabao_http_help_request":{
            "path":path,"query":"","wire_method":"HELP"
        }})
    } else {
        body
    };
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

#[test]
fn ordinary_control_input_priority_matches_pinned_official_before_and_after_seal() -> TestResult {
    let root = Root::new();
    let mut service = root.service()?;
    let (root_key, token) = bootstrap_unmounted(&mut service)?;
    let root_key = zeroize::Zeroizing::new(root_key);
    let root_bytes = zeroize::Zeroizing::new(STANDARD.decode(root_key.as_bytes())?);
    assert_eq!(
        wire(
            &mut service,
            "POST",
            "sys/namespaces/plain",
            "",
            &token,
            json!({})
        )
        .status,
        200
    );
    // Pinned genuine R34: 30 observations. Input parsing precedes the
    // not-sealable rejection; root-key input grants no independent slot.
    for closed in [false, true] {
        if closed {
            assert_eq!(
                wire(
                    &mut service,
                    "POST",
                    "sys/namespaces/plain/seal",
                    "",
                    &token,
                    json!({})
                )
                .status,
                204
            );
        }
        assert_eq!(
            wire(
                &mut service,
                "GET",
                "sys/namespaces/plain/seal-status",
                "",
                &token,
                json!({})
            )
            .status,
            400
        );
        for (label, body, expected) in [
            ("missing", json!({}), 500),
            ("empty-key", json!({"key":""}), 500),
            ("null-key", json!({"key":null}), 500),
            ("wrong-type", json!({"key":{}}), 400),
            ("malformed", json!({"key":"!"}), 400),
            ("hex-short", json!({"key":"00"}), 400),
            ("hex-root", json!({"key":hex(&root_bytes)}), 400),
            ("base64-root", json!({"key":root_key.as_str()}), 400),
            ("reset-true", json!({"reset":true}), 400),
            ("reset-false", json!({"reset":false}), 500),
            ("reset-invalid", json!({"reset":"invalid"}), 400),
            ("reset-with-malformed", json!({"reset":true,"key":"!"}), 400),
        ] {
            assert_eq!(
                wire(
                    &mut service,
                    "POST",
                    "sys/namespaces/plain/unseal",
                    "",
                    &token,
                    body
                )
                .status,
                expected,
                "official ordinary input priority: {label}, closed={closed}"
            );
            assert!(
                !service.namespace_runtime.has_loaded_within("plain"),
                "ordinary controls cannot manufacture an independent key grant"
            );
        }
    }
    Ok(())
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
        json!({"policy":"path \"sys/namespaces/*\" { capabilities = [\"read\", \"update\", \"delete\"] }"}),
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

#[test]
fn ordinary_http_late_actor_after_real_commit_closes_assets_without_acknowledgement() -> TestResult
{
    let root = Root::new();
    let mut service = root.service()?;
    let (_, token) = bootstrap_unmounted(&mut service)?;
    assert!(
        wire(
            &mut service,
            "POST",
            "sys/namespaces/ordinary-late",
            "",
            &token,
            json!({})
        )
        .status
            == 200,
        "actual ordinary owner"
    );
    write_marker(&mut service, "ordinary-late", &token);
    let actor = short_actor(&mut service, &token, false)?;
    let before = service.durable.as_ref().ok_or("durable")?.generation();
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
    let _original = crate::request_deadline::RequestDeadlineScope::enter(deadline);
    let _delay = external_pki::PublicationDelayScope::enter(std::time::Duration::from_millis(2100));
    let response = service.handle_request(ServiceRequest::new(
        "POST",
        "sys/namespaces/ordinary-late/seal",
        "",
        &actor,
        json!({}),
    ));
    assert!(
        response.status == 403,
        "actor expiration after real ordinary closure cannot receive an acknowledgement"
    );
    let closed = service.state.as_ref().ok_or("closed candidate")?;
    assert!(
        service.durable.as_ref().ok_or("durable")?.generation() != before
            && closed.namespaces.inherited_owner("ordinary-late").is_some()
            && closed.engines.namespace_is_empty("ordinary-late")
            && !service.namespace_runtime.has_loaded_within("ordinary-late"),
        "successful durable closure still removes assets and key slots after actor expiry"
    );
    assert!(
        crate::request_deadline::current() == Some(deadline),
        "original actor request budget is retained"
    );
    Ok(())
}

fn reopened_empty_inherited(root: &Root) -> TestResult<(Service, String)> {
    let mut service = root.service()?;
    let (root_share, token) = bootstrap_unmounted(&mut service)?;
    assert!(
        wire(
            &mut service,
            "POST",
            "sys/namespaces/empty",
            "",
            &token,
            json!({})
        )
        .status
            == 200,
        "actual empty namespace created"
    );
    assert!(
        wire(
            &mut service,
            "POST",
            "sys/namespaces/empty/seal",
            "",
            &token,
            json!({})
        )
        .status
            == 204,
        "genuine inherited owner closed before restart"
    );
    drop(service);
    let mut service = root.service()?;
    assert!(
        call(
            &mut service,
            "POST",
            "sys/unseal",
            "",
            json!({"key":root_share})
        )
        .status
            == 200
            && service.namespace_runtime.is_loaded("empty"),
        "genuine root key restores the actual inherited slot"
    );
    Ok((service, token))
}

#[test]
fn ordinary_delete_late_actor_after_commit_retires_and_destroys_old_key() -> TestResult {
    let root = Root::new();
    let (mut service, token) = reopened_empty_inherited(&root)?;
    let actor = short_actor(&mut service, &token, false)?;
    let stale = service.state.clone().ok_or("loaded owner")?;
    let before = service.durable.as_ref().ok_or("durable")?.generation();
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
    let _original = crate::request_deadline::RequestDeadlineScope::enter(deadline);
    let _delay = external_pki::PublicationDelayScope::enter(std::time::Duration::from_millis(2100));
    let response = service.handle_request(ServiceRequest::new(
        "DELETE",
        "sys/namespaces/empty",
        "",
        &actor,
        json!({}),
    ));
    let retired = service.state.as_ref().ok_or("retired owner")?;
    assert!(
        response.status == 403
            && service.durable.as_ref().ok_or("durable")?.generation() != before
            && !retired.namespace_exists("empty")
            && retired.namespaces.custody_frontiers["empty"].is_retired()
            && !service.namespace_runtime.has_loaded_within("empty")
            && stale.namespace_leases.validate().is_err(),
        "expired actual actor receives no ACK while durable retirement revokes the sole old key"
    );
    assert!(
        crate::request_deadline::current() == Some(deadline),
        "original actor budget retained"
    );
    Ok(())
}

#[test]
fn ordinary_delete_late_original_deadline_retires_without_acknowledgement() -> TestResult {
    let root = Root::new();
    let (mut service, token) = reopened_empty_inherited(&root)?;
    let stale = service.state.clone().ok_or("loaded owner")?;
    let before = service.durable.as_ref().ok_or("durable")?.generation();
    let deadline = std::time::Instant::now() + std::time::Duration::from_millis(250);
    let _original = crate::request_deadline::RequestDeadlineScope::enter(deadline);
    let _delay = external_pki::PublicationDelayScope::enter(std::time::Duration::from_millis(350));
    let response = service.handle_request(ServiceRequest::new(
        "DELETE",
        "sys/namespaces/empty",
        "",
        &token,
        json!({}),
    ));
    let retired = service.state.as_ref().ok_or("retired owner")?;
    assert!(
        response.status == 503
            && service.durable.as_ref().ok_or("durable")?.generation() != before
            && !retired.namespace_exists("empty")
            && retired.namespaces.custody_frontiers["empty"].is_retired()
            && !service.namespace_runtime.has_loaded_within("empty")
            && stale.namespace_leases.validate().is_err(),
        "original deadline blocks ACK after the real retirement has destroyed the sole key"
    );
    assert!(
        crate::request_deadline::current() == Some(deadline),
        "deletion does not renew request budget"
    );
    Ok(())
}

#[test]
fn ordinary_router_keeps_authenticated_self_context_and_cross_namespace_acl_order() -> TestResult {
    let root = Root::new();
    let mut service = root.service()?;
    let (_, token) = bootstrap_unmounted(&mut service)?;
    assert!(
        wire(
            &mut service,
            "POST",
            "sys/namespaces/plain",
            "",
            &token,
            json!({})
        )
        .status
            == 200,
        "ordinary namespace created through actual dispatch"
    );
    let shares = create(&mut service, "", "barrier", &token)?;
    unseal(&mut service, "", "barrier", &token, &shares);
    assert!(
        wire(
            &mut service,
            "PUT",
            "sys/policies/acl/reader",
            "barrier",
            &token,
            json!({"policy":"path \"*\" { capabilities = [\"read\", \"update\", \"list\"] }"})
        )
        .status
            == 204,
        "actual barrier policy created"
    );
    let issued = wire(
        &mut service,
        "POST",
        "auth/token/create",
        "barrier",
        &token,
        json!({"policies":["reader"], "no_default_policy":true}),
    );
    assert!(
        issued.status == 200,
        "actual nonroot namespace token issued"
    );
    let actor = zeroize::Zeroizing::new(
        issued.body["auth"]["client_token"]
            .as_str()
            .ok_or("actor")?
            .to_owned(),
    );
    assert!(
        wire(
            &mut service,
            "POST",
            "sys/namespaces/plain/seal",
            "",
            &token,
            json!({})
        )
        .status
            == 204,
        "ordinary resource owner closes with its actual inherited key"
    );
    for (label, caller, header, method, path, expected) in [
        (
            "root self context",
            token.as_str(),
            "plain",
            "GET",
            "auth/token/lookup-self",
            200,
        ),
        (
            "root self Help context",
            token.as_str(),
            "plain",
            "HELP",
            "auth/token/lookup-self",
            200,
        ),
        (
            "root auth owner unloaded",
            token.as_str(),
            "plain",
            "HELP",
            "auth/token/create",
            404,
        ),
        (
            "root mount owner unloaded",
            token.as_str(),
            "plain",
            "GET",
            "sys/mounts",
            404,
        ),
        (
            "root namespace router unloaded",
            token.as_str(),
            "plain",
            "GET",
            "sys/namespaces/missing/seal-status",
            404,
        ),
        (
            "loaded missing child control",
            token.as_str(),
            "barrier",
            "GET",
            "sys/namespaces/missing/seal-status",
            500,
        ),
        (
            "actual barrier token self context",
            actor.as_str(),
            "plain",
            "GET",
            "auth/token/lookup-self",
            200,
        ),
        (
            "omitted header actual token context",
            actor.as_str(),
            "",
            "GET",
            "auth/token/lookup-self",
            200,
        ),
        (
            "actual barrier token self Help",
            actor.as_str(),
            "plain",
            "HELP",
            "auth/token/lookup-self",
            200,
        ),
        (
            "cross namespace mount ACL first",
            actor.as_str(),
            "plain",
            "GET",
            "sys/mounts",
            403,
        ),
        (
            "cross namespace namespace ACL first",
            actor.as_str(),
            "plain",
            "GET",
            "sys/namespaces/missing/seal-status",
            403,
        ),
        (
            "authenticated Help sees actual unloaded owner",
            actor.as_str(),
            "plain",
            "HELP",
            "auth/token/create",
            404,
        ),
        (
            "invalid actor before resource lookup",
            "hvs.invalid",
            "plain",
            "GET",
            "sys/mounts",
            403,
        ),
        (
            "invalid Help actor before lookup",
            "hvs.invalid",
            "plain",
            "HELP",
            "auth/token/create",
            403,
        ),
        (
            "unknown header before self context",
            token.as_str(),
            "unknown",
            "GET",
            "auth/token/lookup-self",
            404,
        ),
    ] {
        let response = wire(&mut service, method, path, header, caller, json!({}));
        assert!(
            response.status == expected,
            "fixed official owner/context priority: {label}; status={} expected={expected}",
            response.status
        );
        if method == "HELP" && expected == 200 {
            assert!(
                response.body["id"].as_str() == Some(caller),
                "actual caller id remains dynamic"
            );
        }
    }
    assert!(
        wire(
            &mut service,
            "POST",
            "sys/namespaces/barrier/seal",
            "",
            &token,
            json!({})
        )
        .status
            == 204,
        "actual independent barrier closes"
    );
    for caller in [token.as_str(), actor.as_str()] {
        assert!(
            wire(
                &mut service,
                "GET",
                "auth/token/lookup-self",
                "barrier",
                caller,
                json!({})
            )
            .status
                == 503,
            "original strong header guard precedes any authenticated self rewrite"
        );
    }
    Ok(())
}

fn closed_auth_fixture(
    service: &mut Service,
    root: &str,
    namespace: &str,
    parent: &str,
    uses: u32,
    ttl: &str,
) -> TestResult<zeroize::Zeroizing<String>> {
    let relative = namespace.rsplit('/').next().ok_or("actual name")?;
    assert!(
        wire(
            service,
            "POST",
            &format!("sys/namespaces/{relative}"),
            parent,
            root,
            json!({})
        )
        .status
            == 200,
        "actual ordinary namespace creation"
    );
    assert!(
        wire(
            service,
            "PUT",
            "sys/policies/acl/closed-reader",
            namespace,
            root,
            json!({"policy":"path \"*\" { capabilities = [\"read\", \"update\", \"list\"] }"})
        )
        .status
            == 204,
        "actual namespace policy"
    );
    let response = wire(
        service,
        "POST",
        "auth/token/create",
        namespace,
        root,
        json!({"policies":["closed-reader"],"no_default_policy":true,"num_uses":uses,"ttl":ttl}),
    );
    assert!(response.status == 200, "actual namespace credential");
    Ok(zeroize::Zeroizing::new(
        response.body["auth"]["client_token"]
            .as_str()
            .ok_or("credential shape")?
            .to_owned(),
    ))
}

#[test]
fn closed_auth_affine_help_consumes_only_after_real_owner_commit_and_survives_restart() -> TestResult
{
    let root = Root::new();
    let mut service = root.service()?;
    let (key, token) = bootstrap_unmounted(&mut service)?;
    let actor = closed_auth_fixture(&mut service, &token, "plain", "", 1, "1h")?;
    assert!(
        wire(
            &mut service,
            "POST",
            "sys/namespaces/plain/seal",
            "",
            &token,
            json!({})
        )
        .status
            == 204,
        "genuine inherited resource closure"
    );
    let before = service.durable.as_ref().ok_or("durable")?.generation();
    assert!(
        wire(
            &mut service,
            "HELP",
            "auth/token/lookup-self",
            "unknown",
            &actor,
            json!({})
        )
        .status
            == 404
            && service.durable.as_ref().ok_or("durable")?.generation() == before,
        "unknown original header neither authenticates nor consumes"
    );
    assert!(
        wire(
            &mut service,
            "HELP",
            "auth/token/lookup-self",
            "",
            &actor,
            json!({})
        )
        .status
            == 404,
        "verified actual self owner is unloaded after atomic finite use"
    );
    assert!(
        service.durable.as_ref().ok_or("durable")?.generation() > before,
        "404 admission genuinely commits finite use"
    );
    let current = service.state.as_ref().ok_or("state")?;
    assert!(
        current.auth.namespace_is_empty("plain")
            && !service.namespace_runtime.is_loaded("plain")
            && current
                .engines
                .help_projection("plain", "secret/plain")?
                .is_none(),
        "credential admission never loads a logical auth, engine or shared key"
    );
    assert!(
        wire(
            &mut service,
            "HELP",
            "auth/token/lookup-self",
            "",
            &actor,
            json!({})
        )
        .status
            == 403,
        "same one-use capability cannot replay its authenticated404"
    );
    drop(service);
    let mut recovered = root.service()?;
    assert!(
        call(&mut recovered, "POST", "sys/unseal", "", json!({"key":key})).status == 200,
        "genuine root recovery restores the typed parcel"
    );
    assert!(
        wire(
            &mut recovered,
            "GET",
            "auth/token/lookup-self",
            "plain",
            &actor,
            json!({})
        )
        .status
            == 403,
        "durable consumed state survives recovery"
    );
    Ok(())
}

#[test]
fn closed_auth_nearest_independent_parent_requires_real_key_and_current_caller_acl() -> TestResult {
    let root = Root::new();
    let mut service = root.service()?;
    let (_, token) = bootstrap_unmounted(&mut service)?;
    let shares = create(&mut service, "", "parent", &token)?;
    unseal(&mut service, "", "parent", &token, &shares);
    let actor = closed_auth_fixture(&mut service, &token, "parent/plain", "parent", 2, "1h")?;
    assert!(
        wire(
            &mut service,
            "POST",
            "sys/namespaces/plain/seal",
            "parent",
            &token,
            json!({})
        )
        .status
            == 204,
        "ordinary owner closes under genuine nearest independent parent key"
    );
    assert!(
        wire(&mut service, "GET", "sys/mounts", "", &actor, json!({})).status == 403,
        "actual token namespace scope runs before other owner dispatch"
    );
    assert!(
        wire(
            &mut service,
            "HELP",
            "auth/token/lookup-self",
            "",
            &actor,
            json!({})
        )
        .status
            == 404,
        "second finite use resolves verified closed self context"
    );
    assert!(
        wire(
            &mut service,
            "HELP",
            "auth/token/create",
            "parent/plain",
            &actor,
            json!({})
        )
        .status
            == 403,
        "two committed uses exhaust the stored closed token"
    );
    assert!(
        !service.namespace_runtime.is_loaded("parent/plain")
            && service.namespace_runtime.is_loaded("parent"),
        "transient admission retains only the already genuine parent slot"
    );
    assert!(
        wire(
            &mut service,
            "POST",
            "sys/namespaces/parent/seal",
            "",
            &token,
            json!({})
        )
        .status
            == 204,
        "parent genuine key revocation"
    );
    let state = service.state.as_ref().ok_or("state")?;
    let root_key = service.barrier_key.as_ref().ok_or("root key")?;
    assert!(
        service
            .namespace_runtime
            .closed_auth_attempt(state, "parent/plain", root_key, &actor, 100, None)
            .is_err(),
        "root key cannot substitute for unavailable actual independent parent"
    );
    Ok(())
}

#[test]
fn closed_auth_failed_commit_never_grants_or_registers_a_transient_key() -> TestResult {
    let root = Root::new();
    let mut service = root.service()?;
    let (_, token) = bootstrap_unmounted(&mut service)?;
    let actor = closed_auth_fixture(&mut service, &token, "plain", "", 1, "1h")?;
    assert!(
        wire(
            &mut service,
            "POST",
            "sys/namespaces/plain/seal",
            "",
            &token,
            json!({})
        )
        .status
            == 204,
        "actual closed owner"
    );
    let prior = owner_store::serialize_owner(service.state.as_ref().ok_or("state")?)?;
    service.durable = None;
    let response = wire(
        &mut service,
        "HELP",
        "auth/token/lookup-self",
        "",
        &actor,
        json!({}),
    );
    let after = owner_store::serialize_owner(service.state.as_ref().ok_or("state")?)?;
    assert!(
        response.status == 503
            && response.body.get("data").is_none()
            && prior == after
            && !service.namespace_runtime.is_loaded("plain"),
        "failed durable admission releases neither a response grant nor a key slot"
    );
    Ok(())
}

#[test]
fn closed_auth_route_verifier_never_authenticates_wrong_token_or_wrong_key() -> TestResult {
    let root = Root::new();
    let mut service = root.service()?;
    let (_, token) = bootstrap_unmounted(&mut service)?;
    let actor = closed_auth_fixture(&mut service, &token, "plain", "", 0, "1h")?;
    assert!(
        wire(
            &mut service,
            "POST",
            "sys/namespaces/plain/seal",
            "",
            &token,
            json!({})
        )
        .status
            == 204,
        "real closed parcel"
    );
    let mut candidate = service.state.clone().ok_or("state")?;
    let binding = candidate
        .namespaces
        .custody_binding(&candidate.cluster_id, "plain")
        .map_err(|_| "binding")?;
    candidate
        .namespaces
        .capture_closed_auth_routes(
            &binding,
            vec![AuthState::namespace_token_route_verifier("hvs.invalid").ok_or("verifier")?],
        )
        .map_err(|_| "route candidate")?;
    candidate
        .validate_format()
        .map_err(|_| "valid route-only candidate")?;
    let root_key = service.barrier_key.as_ref().ok_or("root key")?;
    let wrong_actor = service
        .namespace_runtime
        .closed_auth_attempt(&candidate, "plain", root_key, "hvs.invalid", 100, None)
        .map_err(|_| "private complete parcel")?;
    assert!(
        wrong_actor.actor().is_err(),
        "structurally valid locator cannot manufacture an authenticated actor"
    );
    assert!(
        service
            .namespace_runtime
            .closed_auth_attempt(&candidate, "plain", &[0u8; 32], &actor, 100, None)
            .is_err(),
        "matching candidate binding cannot replace the genuine root key"
    );
    assert!(
        !service.namespace_runtime.is_loaded("plain"),
        "no test path installs transient key custody"
    );
    Ok(())
}

#[test]
fn closed_auth_wrapping_help_commits_one_use_and_monotonic_clock_without_payload_release()
-> TestResult {
    let root = Root::new();
    let mut service = root.service()?;
    let (_, token) = bootstrap_unmounted(&mut service)?;
    assert!(
        wire(
            &mut service,
            "POST",
            "sys/namespaces/plain",
            "",
            &token,
            json!({})
        )
        .status
            == 200,
        "actual wrapper owner"
    );
    let mut request = ServiceRequest::new(
        "POST",
        "sys/wrapping/wrap",
        "plain",
        &token,
        json!({"secret":"private-cfg-wrapper-payload"}),
    );
    request.wrap_ttl_seconds = Some(60);
    let response = service.handle_request_at(request, 100);
    assert!(
        response.status == 200 && response.body.get("data").is_none(),
        "real wrapped payload publication"
    );
    let wrapper = zeroize::Zeroizing::new(
        response.body["wrap_info"]["token"]
            .as_str()
            .ok_or("wrapper shape")?
            .to_owned(),
    );
    assert!(
        wire(
            &mut service,
            "POST",
            "sys/namespaces/plain/seal",
            "",
            &token,
            json!({})
        )
        .status
            == 204,
        "wrapper complete typed owner closes"
    );
    let response = service.handle_request_at(ServiceRequest::new("HELP", "auth/token/create", "plain", &wrapper,
        json!({"__heptabao_http_help_request":{"path":"auth/token/create","query":"","wire_method":"HELP"}})), 110);
    assert!(
        response.status == 404 && response.body.get("data").is_none(),
        "closed Help consumes wrapper without releasing payload"
    );
    let current = service.state.as_ref().ok_or("state")?;
    let private = service
        .namespace_runtime
        .closed_auth_attempt(
            current,
            "plain",
            service.barrier_key.as_ref().ok_or("root key")?,
            &wrapper,
            100,
            None,
        )
        .map_err(|_| "complete private parcel")?;
    assert!(
        private.actor().is_err()
            && current.auth.namespace_is_empty("plain")
            && !service.namespace_runtime.is_loaded("plain"),
        "clock rollback cannot recover the consumed private wrapper"
    );
    Ok(())
}

#[test]
fn closed_auth_post_commit_actor_expiry_and_original_deadline_withhold_help() -> TestResult {
    let root = Root::new();
    let mut service = root.service()?;
    let (_, token) = bootstrap_unmounted(&mut service)?;
    let _ = closed_auth_fixture(&mut service, &token, "plain", "", 0, "1h")?;
    let response = service.handle_request(ServiceRequest::new(
        "POST",
        "auth/token/create",
        "plain",
        &token,
        json!({"policies":["closed-reader"],"no_default_policy":true,"num_uses":1,"ttl":"2s"}),
    ));
    assert!(response.status == 200, "actual short-lived affine actor");
    let actor = zeroize::Zeroizing::new(
        response.body["auth"]["client_token"]
            .as_str()
            .ok_or("actor shape")?
            .to_owned(),
    );
    let response = service.handle_request(ServiceRequest::new(
        "POST",
        "sys/namespaces/plain/seal",
        "",
        &token,
        json!({}),
    ));
    assert!(response.status == 204, "real-clock actual closure");
    let before = service.durable.as_ref().ok_or("durable")?.generation();
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
    let _budget = crate::request_deadline::RequestDeadlineScope::enter(deadline);
    let _delay = external_pki::PublicationDelayScope::enter(std::time::Duration::from_millis(2100));
    let response = service.handle_request(ServiceRequest::new("HELP", "auth/token/create", "plain", &actor,
        json!({"__heptabao_http_help_request":{"path":"auth/token/create","query":"","wire_method":"HELP"}})));
    assert!(
        response.status == 403 && service.durable.as_ref().ok_or("durable")?.generation() > before,
        "actor expires during genuine committed use before any Help response"
    );
    assert!(
        crate::request_deadline::current() == Some(deadline)
            && !service.namespace_runtime.is_loaded("plain"),
        "actual late actor check keeps original deadline and closed slot"
    );
    Ok(())
}
