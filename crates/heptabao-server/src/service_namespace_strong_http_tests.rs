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
    unseal(&mut service, "outer", "inner", &token, &inner);
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
