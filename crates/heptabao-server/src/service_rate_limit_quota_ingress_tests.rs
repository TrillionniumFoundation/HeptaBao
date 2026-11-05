//! Public requests each own one quota charge, including workflow execution.
use super::super::tests::{Root, bootstrap, call};
use super::*;

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn request(service: &mut Service, method: &str, path: &str, token: &str, body: Value) -> Response {
    service.handle_request_at(
        ServiceRequest::new(method, path, "", token, body)
            .with_origin_peer(IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)),
        100,
    )
}

#[test]
fn global_quota_charges_each_public_workflow_once_and_restores_outer_ingress() -> TestResult {
    let root = Root::new();
    let mut service = root.service()?;
    let (_, admin) = bootstrap(&mut service)?;
    assert_eq!(
        call(
            &mut service,
            "POST",
            "secret/data/quota-workflow",
            &admin,
            json!({"data":{"value":"preserved"}})
        )
        .status,
        200
    );
    let document = r#"input { field "string" "credential" { required = true } }
flow "read" { request "kv" {
 operation = "read" path = "secret/data/quota-workflow"
 token = { eval_source = "input" eval_type = "string" field_name = "credential" }
} }
output { data = { value = { eval_source = "response" eval_type = "string"
 flow_name = "read" response_name = "kv" field_selector = ["data", "data", "value"] } } }"#;
    assert_eq!(
        call(
            &mut service,
            "POST",
            "sys/workflows/manage/quota-once",
            &admin,
            json!({"workflow":document})
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
            json!({"enable_rate_limit_response_headers":true})
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
            json!({"rate":2,"interval":"1h"})
        )
        .status,
        204
    );
    for remaining in ["1", "0"] {
        let response = request(
            &mut service,
            "POST",
            "sys/workflows/execute/quota-once",
            &admin,
            json!({"credential":admin}),
        );
        assert_eq!(response.status, 200);
        assert_eq!(response.body["data"]["value"], "preserved");
        let headers = serde_json::to_value(&response.response_headers)?;
        assert_eq!(headers["X-Ratelimit-Remaining"], json!([remaining]));
    }
    let denied = request(
        &mut service,
        "GET",
        "secret/data/quota-workflow",
        &admin,
        json!({}),
    );
    assert_eq!(denied.status, 429);
    assert!(denied.body.get("data").is_none());
    Ok(())
}
