use super::tests::{Root, bootstrap, call};
use super::*;
type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;
const LEAF: &[u8] = include_bytes!("../testdata/cert-selector.der");
fn setup(service: &mut Service, admin: &str) -> TestResult {
    let digest: String = ring::digest::digest(&ring::digest::SHA256, LEAF)
        .as_ref()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    for (path, body) in [
        ("sys/auth/cert", json!({"type":"cert"})),
        (
            "auth/cert/certs/operator",
            json!({"certificate_sha256":digest,"token_ttl":300}),
        ),
    ] {
        assert_eq!(call(service, "POST", path, admin, body).status, 204);
    }
    Ok(())
}
fn quota(service: &mut Service, admin: &str, name: &str, path: &str, role: &str) -> TestResult {
    assert_eq!(
        call(
            service,
            "POST",
            &format!("sys/quotas/rate-limit/{name}"),
            admin,
            json!({"path":path,"role":role,"rate":1,"interval":"1h"})
        )
        .status,
        204
    );
    Ok(())
}
fn login(service: &mut Service, body: Value, chain: Option<Vec<Vec<u8>>>) -> Response {
    login_path(service, "auth/cert/login", body, chain)
}
fn login_path(
    service: &mut Service,
    path: &str,
    body: Value,
    chain: Option<Vec<Vec<u8>>>,
) -> Response {
    service.handle_at_mode(RequestDispatch {
        method: "POST",
        path,
        namespace: "",
        token: "",
        body,
        now: 100,
        allow_forward: false,
        enforce_namespace: true,
        wrap_ttl_seconds: None,
        origin_peer: Some(std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)),
        client_certificates: chain,
    })
}
#[test]
fn certificate_quota_service_role_binds_leaf_without_requested_name_or_body_identity() -> TestResult
{
    let root = Root::new();
    let mut service = root.service()?;
    let (_, admin) = bootstrap(&mut service)?;
    setup(&mut service, &admin)?;
    quota(&mut service, &admin, "role", "auth/cert", "operator")?;
    for body in [
        json!({"name":"operator"}),
        json!({"name":"operator","certificate_sha256":"forged","peer":"192.0.2.1"}),
    ] {
        let response = login(&mut service, body, None);
        assert!(matches!(response.status, 400 | 403));
    }
    let other = include_bytes!("../testdata/cert-selector-other.der").to_vec();
    assert_eq!(
        login(&mut service, json!({"name":"operator"}), Some(vec![other])).status,
        403
    );
    assert_eq!(
        login(
            &mut service,
            json!({"name":"missing"}),
            Some(vec![LEAF.to_vec()])
        )
        .status,
        403
    );
    assert_eq!(
        login(
            &mut service,
            json!({"name":"operator"}),
            Some(vec![LEAF.to_vec()])
        )
        .status,
        200
    );
    assert_eq!(
        login(
            &mut service,
            json!({"name":"operator"}),
            Some(vec![LEAF.to_vec()])
        )
        .status,
        429
    );
    Ok(())
}
#[test]
fn certificate_quota_service_invalid_role_still_consumes_exact_path_and_mount_fallback()
-> TestResult {
    for fallback in ["auth/cert/login", "auth/cert"] {
        let root = Root::new();
        let mut service = root.service()?;
        let (_, admin) = bootstrap(&mut service)?;
        setup(&mut service, &admin)?;
        quota(&mut service, &admin, "role", "auth/cert", "operator")?;
        quota(&mut service, &admin, "fallback", fallback, "")?;
        assert_eq!(
            login(&mut service, json!({"name":"operator"}), None).status,
            403
        );
        assert_eq!(
            login(&mut service, json!({"name":"operator"}), None).status,
            429
        );
        // The role bucket was never consumed by an absent observed certificate.
        assert_eq!(
            login(
                &mut service,
                json!({"name":"operator"}),
                Some(vec![LEAF.to_vec()])
            )
            .status,
            200
        );
    }
    Ok(())
}
#[test]
fn certificate_quota_service_origin_bucket_ignores_forged_body_ip() -> TestResult {
    let root = Root::new();
    let mut service = root.service()?;
    let (_, admin) = bootstrap(&mut service)?;
    setup(&mut service, &admin)?;
    quota(&mut service, &admin, "role", "auth/cert", "operator")?;
    assert_eq!(
        login(
            &mut service,
            json!({"name":"operator","origin_peer":"192.0.2.1"}),
            Some(vec![LEAF.to_vec()])
        )
        .status,
        400
    );
    assert_eq!(
        login(
            &mut service,
            json!({"name":"operator","origin_peer":"192.0.2.2"}),
            Some(vec![LEAF.to_vec()])
        )
        .status,
        429
    );
    Ok(())
}
#[test]
fn certificate_quota_service_durable_cold_reopen_and_rule_retirement_keep_schema136() -> TestResult
{
    let root = Root::new();
    let mut service = root.service()?;
    let (key, admin) = bootstrap(&mut service)?;
    setup(&mut service, &admin)?;
    quota(&mut service, &admin, "role", "auth/cert", "operator")?;
    let state = service.state.clone().ok_or("state")?;
    assert_eq!(state.schema, CERTIFICATE_QUOTA_STATE_SCHEMA);
    for schema in [RATE_LIMIT_QUOTA_STATE_SCHEMA, 135] {
        let mut downgraded = state.clone();
        downgraded.schema = schema;
        assert!(downgraded.validate_format().is_err());
    }
    assert_eq!(
        login(
            &mut service,
            json!({"name":"operator"}),
            Some(vec![LEAF.to_vec()])
        )
        .status,
        200
    );
    drop(service);
    let mut reopened = root.service()?;
    assert_eq!(
        call(&mut reopened, "POST", "sys/unseal", "", json!({"key":key})).status,
        200
    );
    assert_eq!(
        reopened.state.as_ref().ok_or("reopened")?.schema,
        CERTIFICATE_QUOTA_STATE_SCHEMA
    );
    assert_eq!(
        login(
            &mut reopened,
            json!({"name":"operator"}),
            Some(vec![LEAF.to_vec()])
        )
        .status,
        200
    );
    assert_eq!(
        call(
            &mut reopened,
            "DELETE",
            "sys/quotas/rate-limit/role",
            &admin,
            json!({})
        )
        .status,
        204
    );
    assert_eq!(
        reopened.state.as_ref().ok_or("retired")?.schema,
        CERTIFICATE_QUOTA_STATE_SCHEMA
    );
    assert!(
        reopened
            .state
            .as_ref()
            .ok_or("retired")?
            .auth
            .has_certificate_quota_state()
    );
    Ok(())
}

#[test]
fn certificate_quota_service_parent_child_grants_and_child_fallback_are_independent() -> TestResult
{
    let root = Root::new();
    let mut service = root.service()?;
    let (_, admin) = bootstrap(&mut service)?;
    setup(&mut service, &admin)?;
    let other = include_bytes!("../testdata/cert-selector-other.der").to_vec();
    let digest: String = ring::digest::digest(&ring::digest::SHA256, &other)
        .as_ref()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    for (path, body) in [
        ("sys/auth/cert/child", json!({"type":"cert"})),
        (
            "auth/cert/child/certs/childrole",
            json!({"certificate_sha256":digest,"token_ttl":300}),
        ),
    ] {
        assert_eq!(call(&mut service, "POST", path, &admin, body).status, 204);
    }
    quota(&mut service, &admin, "parent", "auth/cert", "operator")?;
    quota(
        &mut service,
        &admin,
        "child",
        "auth/cert/child",
        "childrole",
    )?;
    quota(
        &mut service,
        &admin,
        "child-fallback",
        "auth/cert/child/login",
        "",
    )?;
    assert_eq!(
        login(
            &mut service,
            json!({"name":"operator"}),
            Some(vec![LEAF.to_vec()])
        )
        .status,
        200
    );
    assert_eq!(
        login_path(
            &mut service,
            "auth/cert/child/login",
            json!({"name":"childrole"}),
            Some(vec![other.clone()])
        )
        .status,
        200
    );
    assert_eq!(
        login_path(
            &mut service,
            "auth/cert/child/login",
            json!({"name":"childrole"}),
            Some(vec![other])
        )
        .status,
        429
    );
    // A parent leaf cannot grant the child role; only the child's fallback is consumed.
    assert_eq!(
        login_path(
            &mut service,
            "auth/cert/child/login",
            json!({"name":"childrole"}),
            Some(vec![LEAF.to_vec()])
        )
        .status,
        403
    );
    assert_eq!(
        login_path(
            &mut service,
            "auth/cert/child/login",
            json!({"name":"childrole"}),
            Some(vec![LEAF.to_vec()])
        )
        .status,
        429
    );
    Ok(())
}
