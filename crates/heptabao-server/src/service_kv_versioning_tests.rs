//! Real encrypted publication and restart; no provider or wire fixture is mocked.
use super::tests::{Root, bootstrap, call, limited_token};
use super::*;
type TestResult = Result<(), Box<dyn std::error::Error>>;
fn populate(service: &mut Service, token: &str) {
    assert_eq!(
        call(
            service,
            "POST",
            "sys/mounts/raw",
            token,
            json!({"type":"kv","options":{"version":"1"}})
        )
        .status,
        204
    );
    for path in ["leaf", "nested/item"] {
        assert_eq!(
            call(
                service,
                "POST",
                &format!("raw/{path}"),
                token,
                json!({"value":path,"typed":[true,null,1]})
            )
            .status,
            204
        );
    }
}
#[test]
fn kv_versioning_publishes_one_mapping_and_reopens_encrypted_history() -> TestResult {
    let root = Root::new();
    let mut service = root.service()?;
    let (key, token) = bootstrap(&mut service)?;
    populate(&mut service, &token);
    let before = service.durable.as_ref().ok_or("durable")?.generation();
    let result = call(
        &mut service,
        "POST",
        "sys/mounts/raw/tune",
        &token,
        json!({"options":{"version":"2"}}),
    );
    assert_eq!(result.status, 200);
    assert_eq!(
        service.durable.as_ref().ok_or("durable")?.generation(),
        before + 1
    );
    assert_eq!(
        call(&mut service, "GET", "raw/data/leaf", &token, json!({})).body["data"]["metadata"]["version"],
        1
    );
    let stable = service.state_digest;
    assert_eq!(
        call(
            &mut service,
            "POST",
            "sys/mounts/raw/tune",
            &token,
            json!({"options":{"version":"2"}})
        )
        .status,
        204
    );
    assert_eq!(service.state_digest, stable);
    assert_eq!(
        service.durable.as_ref().ok_or("durable")?.generation(),
        before + 1
    );
    drop(service);
    let mut service = root.service()?;
    assert_eq!(
        call(&mut service, "PUT", "sys/unseal", "", json!({"key":key})).status,
        200
    );
    for path in ["leaf", "nested/item"] {
        assert_eq!(
            call(
                &mut service,
                "GET",
                &format!("raw/data/{path}"),
                &token,
                json!({})
            )
            .body["data"]["data"],
            json!({"value":path,"typed":[true,null,1]})
        );
    }
    assert_eq!(
        call(
            &mut service,
            "POST",
            "raw/data/leaf",
            &token,
            json!({"options":{"cas":0},"data":{"value":"stale"}})
        )
        .status,
        400
    );
    assert_eq!(
        call(
            &mut service,
            "POST",
            "raw/data/leaf",
            &token,
            json!({"options":{"cas":1},"data":{"value":"new"}})
        )
        .body["data"]["version"],
        2
    );
    // The HTTP parser places query fields into body before Service admission.
    let historical = call(
        &mut service,
        "GET",
        "raw/data/leaf",
        &token,
        json!({"version":1}),
    );
    assert_eq!(historical.status, 200);
    assert_eq!(historical.body["data"]["data"]["value"], "leaf");
    Ok(())
}
#[test]
fn kv_versioning_capacity_veto_and_acl_denial_preserve_original_mapping_on_restart() -> TestResult {
    let root = Root::new();
    let mut service = root.service()?;
    let (key, token) = bootstrap(&mut service)?;
    populate(&mut service, &token);
    let reader = limited_token(
        &mut service,
        &token,
        "path \"raw/*\" { capabilities = [\"read\"] }",
    )?;
    let before_engine =
        owner_store::serialize_owner(&service.state.as_ref().ok_or("state")?.engines)
            .map_err(|_| "engine")?;
    assert_eq!(
        call(
            &mut service,
            "POST",
            "sys/mounts/raw/tune",
            &reader,
            json!({"options":{"version":"2"}})
        )
        .status,
        403
    );
    assert_eq!(
        owner_store::serialize_owner(&service.state.as_ref().ok_or("state")?.engines)
            .map_err(|_| "engine")?,
        before_engine
    );
    let generation = service.durable.as_ref().ok_or("durable")?.generation();
    let digest = service.state_digest;
    let root_record = service.current_state_identity().map_err(|_| "identity")?;
    service.state_capacity = 1;
    assert_eq!(
        call(
            &mut service,
            "POST",
            "sys/mounts/raw/tune",
            &token,
            json!({"options":{"version":"2"}})
        )
        .status,
        507
    );
    assert_eq!(
        service.durable.as_ref().ok_or("durable")?.generation(),
        generation
    );
    assert_eq!(service.state_digest, digest);
    assert_eq!(
        service.current_state_identity().map_err(|_| "identity")?,
        root_record
    );
    assert_eq!(
        owner_store::serialize_owner(&service.state.as_ref().ok_or("state")?.engines)
            .map_err(|_| "engine")?,
        before_engine
    );
    drop(service);
    let mut service = root.service()?;
    assert_eq!(
        call(&mut service, "PUT", "sys/unseal", "", json!({"key":key})).status,
        200
    );
    for path in ["leaf", "nested/item"] {
        assert_eq!(
            call(
                &mut service,
                "GET",
                &format!("raw/{path}"),
                &token,
                json!({})
            )
            .body["data"],
            json!({"value":path,"typed":[true,null,1]})
        );
    }
    assert_eq!(
        call(
            &mut service,
            "GET",
            "sys/mounts/raw/tune",
            &token,
            json!({})
        )
        .body["data"]["options"]["version"],
        "1"
    );
    assert_eq!(
        call(
            &mut service,
            "POST",
            "sys/mounts/raw/tune",
            &token,
            json!({"options":{"version":"2"}})
        )
        .status,
        200
    );
    Ok(())
}
