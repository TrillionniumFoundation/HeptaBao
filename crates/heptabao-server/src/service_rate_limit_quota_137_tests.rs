use super::super::tests::{Root, bootstrap, call};
use super::*;

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn from_peer(
    service: &mut Service,
    namespace: &str,
    path: &str,
    method: &str,
    token: &str,
    body: Value,
    last_octet: u8,
) -> Response {
    service.handle_request_at(
        ServiceRequest::new(method, path, namespace, token, body)
            .with_origin_peer(IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, last_octet))),
        100,
    )
}

fn headers(response: &Response) -> Result<Value, serde_json::Error> {
    serde_json::to_value(&response.response_headers)
}

#[test]
fn quota_headers_are_opt_in_and_distinguish_first_from_blocked_denial() -> TestResult {
    let root = Root::new();
    let mut service = root.service()?;
    let (_, admin) = bootstrap(&mut service)?;
    assert_eq!(
        call(
            &mut service,
            "POST",
            "sys/auth/forms",
            &admin,
            json!({"type":"approle"})
        )
        .status,
        204
    );
    let definition = json!({"path":"auth/forms/", "rate":1,
        "interval":"1h", "block_interval":"1h"});
    for enabled in [false, true] {
        assert_eq!(
            call(
                &mut service,
                "POST",
                "sys/quotas/config",
                &admin,
                json!({"enable_rate_limit_response_headers":enabled})
            )
            .status,
            204
        );
        assert_eq!(
            call(
                &mut service,
                "POST",
                "sys/quotas/rate-limit/headers",
                &admin,
                definition.clone()
            )
            .status,
            204
        );
        // A logical authentication error still consumed one real request.
        let first = from_peer(
            &mut service,
            "",
            "auth/forms/login",
            "POST",
            "",
            json!({"role_id":"unknown", "secret_id":"invalid"}),
            1,
        );
        assert_eq!(first.status, 400);
        let first_headers = headers(&first)?;
        if enabled {
            assert_eq!(first_headers.as_object().ok_or("header object")?.len(), 3);
            assert_eq!(first_headers["X-Ratelimit-Limit"], json!(["1"]));
            assert_eq!(first_headers["X-Ratelimit-Remaining"], json!(["0"]));
            let reset = first_headers["X-Ratelimit-Reset"][0]
                .as_str()
                .ok_or("reset header")?
                .parse::<u64>()?;
            assert!((3500..=3600).contains(&reset));
        } else {
            assert_eq!(first_headers, json!({}));
        }
        for first_denial in [true, false] {
            let denied = from_peer(
                &mut service,
                "",
                "auth/forms/login",
                "POST",
                "",
                json!({"role_id":"unknown", "secret_id":"invalid"}),
                1,
            );
            assert_eq!(denied.status, 429);
            assert!(denied.body.get("auth").is_none());
            let denied_headers = headers(&denied)?;
            if enabled {
                assert_eq!(
                    denied_headers.as_object().ok_or("denial headers")?.len(),
                    if first_denial { 4 } else { 1 }
                );
                let retry = denied_headers["Retry-After"]
                    .as_array()
                    .ok_or("retry array")?;
                assert_eq!(retry.len(), 1);
                assert!(
                    (3500..=3600)
                        .contains(&retry[0].as_str().ok_or("retry string")?.parse::<u64>()?)
                );
            } else {
                assert_eq!(denied_headers, json!({}));
            }
        }
    }
    Ok(())
}

#[test]
fn global_quota_really_covers_non_approle_namespace_and_unexempt_health() -> TestResult {
    for inheritable in [false, true] {
        let root = Root::new();
        let mut service = root.service()?;
        let (_, admin) = bootstrap(&mut service)?;
        assert_eq!(
            call(
                &mut service,
                "POST",
                "sys/namespaces/child",
                &admin,
                json!({})
            )
            .status,
            200
        );
        assert_eq!(
            call(
                &mut service,
                "POST",
                "sys/quotas/config",
                &admin,
                json!({"enable_rate_limit_response_headers":true, "rate_limit_exempt_paths":[]})
            )
            .status,
            204
        );
        assert_eq!(
            call(
                &mut service,
                "POST",
                "sys/quotas/rate-limit/global",
                &admin,
                json!({"rate":1,"interval":"1h","inheritable":inheritable})
            )
            .status,
            204
        );
        let child = from_peer(&mut service, "child", "sys/health", "GET", "", json!({}), 1);
        assert_eq!(child.status, 200);
        assert_eq!(
            headers(&child)?.get("X-Ratelimit-Limit").is_some(),
            inheritable
        );
        let root_health = from_peer(&mut service, "", "sys/health", "GET", "", json!({}), 1);
        assert_eq!(root_health.status, if inheritable { 429 } else { 200 });
        let non_auth = from_peer(
            &mut service,
            "",
            "sys/quotas/config",
            "GET",
            &admin,
            json!({}),
            1,
        );
        assert_eq!(non_auth.status, 429);
        // A separate observed transport peer retains an independent bucket.
        let independent = from_peer(
            &mut service,
            "",
            "sys/quotas/config",
            "GET",
            &admin,
            json!({}),
            2,
        );
        assert_eq!(independent.status, 200);
        assert_eq!(
            headers(&independent)?["X-Ratelimit-Remaining"],
            json!(["0"])
        );
    }
    Ok(())
}

#[test]
fn default_health_exemption_does_not_consume_global_budget() -> TestResult {
    let root = Root::new();
    let mut service = root.service()?;
    let (_, admin) = bootstrap(&mut service)?;
    assert_eq!(
        call(
            &mut service,
            "POST",
            "sys/quotas/rate-limit/global",
            &admin,
            json!({"path":"", "rate":1, "interval":"1h"})
        )
        .status,
        204
    );
    for _ in 0..2 {
        assert_eq!(
            from_peer(&mut service, "", "sys/health", "GET", "", json!({}), 1).status,
            200
        );
    }
    assert_eq!(
        from_peer(
            &mut service,
            "",
            "sys/quotas/config",
            "GET",
            &admin,
            json!({}),
            1
        )
        .status,
        200
    );
    assert_eq!(
        from_peer(
            &mut service,
            "",
            "sys/quotas/config",
            "GET",
            &admin,
            json!({}),
            1
        )
        .status,
        429
    );
    Ok(())
}

#[test]
fn old_134_reader_state_remains_readable_and_extended_floor_survives_restart_and_retirement()
-> TestResult {
    let root = Root::new();
    let mut service = root.service()?;
    let (key, admin) = crate::service::tests::bootstrap_pre141(&mut service)?;
    assert_eq!(
        call(
            &mut service,
            "POST",
            "sys/auth/forms",
            &admin,
            json!({"type":"approle"})
        )
        .status,
        204
    );
    assert_eq!(
        call(
            &mut service,
            "POST",
            "sys/quotas/rate-limit/old",
            &admin,
            json!({"path":"auth/forms/", "rate":10})
        )
        .status,
        204
    );
    let old = service.state.clone().ok_or("old state")?;
    assert_eq!(old.schema, RATE_LIMIT_QUOTA_STATE_SCHEMA);
    assert!(!old.auth.has_extended_rate_limit_quota_state());
    drop(service);
    let mut service = root.service()?;
    assert_eq!(
        call(&mut service, "POST", "sys/unseal", "", json!({"key":key})).status,
        200
    );
    assert_eq!(
        service.state.as_ref().ok_or("reopened old state")?.schema,
        RATE_LIMIT_QUOTA_STATE_SCHEMA
    );
    assert_eq!(
        call(
            &mut service,
            "POST",
            "sys/quotas/rate-limit/global",
            &admin,
            json!({"rate":1000000})
        )
        .status,
        204
    );
    let read = from_peer(
        &mut service,
        "",
        "sys/quotas/rate-limit/global",
        "GET",
        &admin,
        json!({}),
        1,
    );
    assert_eq!(read.status, 200);
    assert_eq!(read.body["data"]["path"], "");
    assert_eq!(read.body["data"]["inheritable"], true);
    let current = service.state.as_ref().ok_or("extended state")?;
    assert_eq!(current.schema, EXTENDED_RATE_LIMIT_QUOTA_STATE_SCHEMA);
    assert!(current.auth.has_extended_rate_limit_quota_state());
    assert!(Service::validate_snapshot_protected_floor(current, &old).is_err());
    assert!(old.validate_publication_schema(Some(current)).is_err());
    drop(service);
    let mut service = root.service()?;
    assert_eq!(
        call(&mut service, "POST", "sys/unseal", "", json!({"key":key})).status,
        200
    );
    let persisted = from_peer(
        &mut service,
        "",
        "sys/quotas/rate-limit/global",
        "GET",
        &admin,
        json!({}),
        1,
    );
    assert_eq!(persisted.status, 200);
    assert_eq!(persisted.body["data"]["inheritable"], true);
    assert_eq!(
        from_peer(
            &mut service,
            "",
            "sys/quotas/rate-limit/global",
            "DELETE",
            &admin,
            json!({}),
            1
        )
        .status,
        204
    );
    assert_eq!(
        call(
            &mut service,
            "POST",
            "sys/quotas/config",
            &admin,
            json!({"enable_rate_limit_response_headers":false})
        )
        .status,
        204
    );
    let retained = service.state.as_ref().ok_or("retained floor")?;
    assert_eq!(retained.schema, EXTENDED_RATE_LIMIT_QUOTA_STATE_SCHEMA);
    assert!(retained.auth.has_extended_rate_limit_quota_state());
    assert!(Service::validate_snapshot_protected_floor(retained, &old).is_err());
    Ok(())
}

#[test]
fn ingress_rate_limit_is_the_only_implicit_one_second_retry_source() -> TestResult {
    let root = Root::new();
    let mut service = root.service()?;
    let (_, _admin) = bootstrap(&mut service)?;
    let ingress = service.handle_wire_rejection(
        &[1; 16],
        WireRejection::RateLimited,
        429,
        "request rate limit exceeded",
    );
    assert_eq!(ingress.status, 429);
    assert_eq!(headers(&ingress)?, json!({"Retry-After":["1"]}));
    let other = service.handle_wire_rejection(
        &[2; 16],
        WireRejection::ParseRejected,
        429,
        "synthetic status-only rejection",
    );
    assert_eq!(other.status, 429);
    assert_eq!(headers(&other)?, json!({}));
    Ok(())
}
