//! Persisted workflow inputs, outputs, and actual Service execution after reopen.
#[cfg(target_os = "linux")]
use super::*;
#[cfg(target_os = "linux")]
use crate::service::tests::{Root, bootstrap, call};
#[cfg(target_os = "linux")]
type TestResult = Result<(), Box<dyn std::error::Error>>;

#[test]
#[cfg(target_os = "linux")]
fn workflow_lossless_body_survives_durable_restart_and_actual_output_mapping() -> TestResult {
    let root = Root::new();
    let mut service = root.service()?;
    let (key, token) = bootstrap(&mut service)?;
    let value = heptabao_domain::json::decode(br#"{"big":184467440737095516160001,"decimal":0.12345678901234567890123456789,"fake":{"$serde_json::private::Number":"7"}}"#)?;
    assert_eq!(
        call(
            &mut service,
            "POST",
            "sys/mounts/lossless-workflow",
            &token,
            json!({"type":"kv","options":{"version":"2"}})
        )
        .status,
        204
    );
    let definition = json!({"cas":0,"steps":[
        {"name":"write","method":"POST","path":"lossless-workflow/data/item","body":{"data":value}},
        {"name":"read","method":"GET","path":"lossless-workflow/data/item"}
    ],"outputs":{"payload":{"step":"read","field":["data","data"]}}});
    assert_eq!(
        call(
            &mut service,
            "POST",
            "sys/workflows/manage/operations/lossless",
            &token,
            definition
        )
        .status,
        200
    );
    let before = serde_json::to_vec(&service.state.as_ref().ok_or("state")?.namespaces.workflows)?;
    drop(service);
    let mut service = root.service()?;
    assert_eq!(
        call(&mut service, "POST", "sys/unseal", "", json!({"key":key})).status,
        200
    );
    assert_eq!(
        serde_json::to_vec(&service.state.as_ref().ok_or("state")?.namespaces.workflows)?,
        before
    );
    let executed = call(
        &mut service,
        "POST",
        "sys/workflows/execute/operations/lossless",
        &token,
        json!({}),
    );
    assert_eq!(executed.status, 200);
    assert_eq!(executed.body["data"]["payload"], value);
    assert_eq!(
        call(
            &mut service,
            "GET",
            "lossless-workflow/data/item",
            &token,
            json!({})
        )
        .body["data"]["data"],
        value
    );
    let stored = service
        .state
        .as_ref()
        .ok_or("state")?
        .namespaces
        .workflows
        .get("", "operations/lossless")
        .ok_or("workflow")?;
    assert_eq!(stored.definition.steps[0].body["data"], value);
    Ok(())
}
