//! Actual State publication, encrypted record reopen, and pre-writer floor controls.
use super::*;
use crate::service::tests::{Root, bootstrap, call};
type TestResult<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;

fn data() -> TestResult<Value> {
    Ok(heptabao_domain::json::decode(br#"{"big":184467440737095516160001,"decimal":0.12345678901234567890123456789,"fake":{"$serde_json::private::Number":"7"},"raw":{"$serde_json::private::RawValue":"[1]"}}"#)?)
}
fn mount(service: &mut Service, token: &str) {
    assert_eq!(
        call(
            service,
            "POST",
            "sys/mounts/records-lossless",
            token,
            json!({"type":"kv","options":{"version":"1"}})
        )
        .status,
        204
    );
}
fn global(service: &Service) -> TestResult<Option<u32>> {
    Ok(service
        .state
        .as_ref()
        .ok_or("sealed")?
        .global_lossless_json_format)
}
fn legacy_empty_bundle() -> Value {
    json!({"schema":"openbao270-kv2-lossless-v1",
        "config":{"max_versions":0,"cas_required":false,"metadata_cas_required":false,"delete_version_after":"0s"},
        "entries":{}})
}

#[test]
fn global_lossless_kv1_record_commit_and_encrypted_reopen_preserve_scope_and_exact_data()
-> TestResult {
    let root = Root::new();
    let mut service = root.service()?;
    let (key, token) = bootstrap(&mut service)?;
    mount(&mut service, &token);
    assert_eq!(global(&service)?, None);
    let ordinary = serde_json::to_vec(service.state.as_ref().ok_or("state")?)?;
    assert!(!std::str::from_utf8(&ordinary)?.contains("global_lossless_json_format"));
    let historical_snapshot = call(
        &mut service,
        "GET",
        "sys/storage/raft/snapshot",
        &token,
        json!({}),
    );
    assert_eq!(historical_snapshot.status, 200);
    let snapshot = historical_snapshot.body["data"]["snapshot"]
        .as_str()
        .ok_or("snapshot")?
        .to_owned();
    assert_eq!(
        call(
            &mut service,
            "PUT",
            "sys/policies/acl/read-lossless",
            &token,
            json!({"policy":r#"path "records-lossless/*" { capabilities=["read"] }"#})
        )
        .status,
        204
    );
    let actor = call(
        &mut service,
        "POST",
        "auth/token/create",
        &token,
        json!({"policies":["read-lossless"],"no_default_policy":true,"num_uses":0}),
    );
    assert_eq!(actor.status, 200);
    let actor = actor.body["auth"]["client_token"]
        .as_str()
        .ok_or("actor")?
        .to_owned();
    let before = service.current_state_identity().map_err(|_| "identity")?;
    let denied = call(
        &mut service,
        "POST",
        "records-lossless/item",
        &actor,
        data()?,
    );
    assert_eq!(denied.status, 403);
    assert_eq!(
        service.current_state_identity().map_err(|_| "identity")?,
        before
    );
    assert_eq!(global(&service)?, None);
    let value = data()?;
    assert_eq!(
        call(
            &mut service,
            "POST",
            "records-lossless/item",
            &token,
            value.clone()
        )
        .status,
        204
    );
    assert_eq!(global(&service)?, Some(1));
    let state = service.state.as_ref().ok_or("state")?;
    assert!(state.schema >= GLOBAL_LOSSLESS_JSON_STATE_SCHEMA);
    state.validate_format().map_err(|_| "format")?;
    assert_eq!(
        service
            .record_root
            .as_ref()
            .ok_or("real record root")?
            .global_lossless_json_format,
        Some(1)
    );
    assert_eq!(
        call(
            &mut service,
            "GET",
            "records-lossless/item",
            &token,
            json!({})
        )
        .body["data"],
        value
    );
    let before_restore = service.current_state_identity().map_err(|_| "identity")?;
    assert_eq!(
        call(
            &mut service,
            "POST",
            "sys/storage/raft/snapshot-force",
            &token,
            json!({"snapshot":snapshot})
        )
        .status,
        400
    );
    assert_eq!(
        service.current_state_identity().map_err(|_| "identity")?,
        before_restore
    );
    drop(service);
    let mut service = root.service()?;
    assert_eq!(
        call(&mut service, "PUT", "sys/unseal", "", json!({"key":key})).status,
        200
    );
    assert_eq!(global(&service)?, Some(1));
    assert_eq!(
        service
            .record_root
            .as_ref()
            .ok_or("reopened record root")?
            .global_lossless_json_format,
        Some(1)
    );
    service
        .state
        .as_ref()
        .ok_or("state")?
        .validate_format()
        .map_err(|_| "format")?;
    assert_eq!(
        call(
            &mut service,
            "GET",
            "records-lossless/item",
            &token,
            json!({})
        )
        .body["data"],
        value
    );
    Ok(())
}

#[test]
fn global_lossless_record_retirement_keeps_marker_and_rejects_torn_or_lower_same_owner()
-> TestResult {
    let root = Root::new();
    let mut service = root.service()?;
    let (key, token) = bootstrap(&mut service)?;
    mount(&mut service, &token);
    assert_eq!(
        call(
            &mut service,
            "POST",
            "records-lossless/item",
            &token,
            data()?
        )
        .status,
        204
    );
    let active = service.state.as_ref().ok_or("state")?.clone();
    assert_eq!(
        call(
            &mut service,
            "DELETE",
            "sys/mounts/records-lossless",
            &token,
            json!({})
        )
        .status,
        204
    );
    assert_eq!(global(&service)?, Some(1));
    drop(service);
    let mut service = root.service()?;
    assert_eq!(
        call(&mut service, "PUT", "sys/unseal", "", json!({"key":key})).status,
        200
    );
    let retired = service.state.as_ref().ok_or("retired")?.clone();
    assert_eq!(retired.global_lossless_json_format, Some(1));
    assert!(
        !retired.has_global_lossless_json_state(),
        "Retired opaque records are not claimed to be scanned"
    );
    retired.validate_format().map_err(|_| "format")?;
    retired
        .validate_publication_schema(Some(&active))
        .map_err(|_| "publication")?;
    let mut lower = retired.clone();
    lower.schema = GLOBAL_LOSSLESS_JSON_STATE_SCHEMA - 1;
    assert!(lower.validate_format().is_err());
    assert!(lower.validate_publication_schema(Some(&retired)).is_err());
    assert!(Service::validate_snapshot_protected_floor(&retired, &lower).is_err());
    let mut torn = retired.clone();
    torn.global_lossless_json_format = None;
    assert!(torn.validate_publication_schema(Some(&retired)).is_err());
    assert!(Service::validate_snapshot_protected_floor(&retired, &torn).is_err());
    let identity = service.current_state_identity().map_err(|_| "identity")?;
    assert!(service.commit_state(&mut torn).is_err());
    assert_eq!(
        service.current_state_identity().map_err(|_| "identity")?,
        identity
    );
    assert_eq!(global(&service)?, Some(1));
    let mut invalid = retired.clone();
    invalid.global_lossless_json_format = Some(2);
    assert!(invalid.validate_format().is_err());
    assert!(invalid.validate_publication_schema(Some(&retired)).is_err());
    let encoded = serde_json::to_vec(&retired)?;
    let loaded: State = serde_json::from_slice(&encoded)?;
    assert_eq!(loaded.global_lossless_json_format, Some(1));
    assert_eq!(serde_json::to_vec(&loaded)?, encoded);
    Ok(())
}

#[test]
fn global_lossless_auth_cubbyhole_and_workflow_durable_inputs_latch_same_state_owner() -> TestResult
{
    let root = Root::new();
    let mut service = root.service()?;
    let (key, token) = bootstrap(&mut service)?;
    let value = data()?;
    assert_eq!(
        call(
            &mut service,
            "POST",
            "cubbyhole/item",
            &token,
            value.clone()
        )
        .status,
        204
    );
    assert_eq!(global(&service)?, Some(1));
    assert!(
        service
            .state
            .as_ref()
            .ok_or("state")?
            .auth
            .has_lossless_json_state()
    );
    let definition = json!({"cas":0,"steps":[
        {"name":"write","method":"POST","path":"secret/data/workflow-lossless","body":{"data":value}},
        {"name":"read","method":"GET","path":"secret/data/workflow-lossless"}
    ],"outputs":{"payload":{"step":"read","field":["data","data"]}}});
    assert_eq!(
        call(
            &mut service,
            "POST",
            "sys/workflows/manage/operations/global-lossless",
            &token,
            definition
        )
        .status,
        200
    );
    assert_eq!(global(&service)?, Some(1));
    assert!(
        service
            .state
            .as_ref()
            .ok_or("state")?
            .namespaces
            .workflows
            .has_lossless_json_state()
    );
    drop(service);
    let mut service = root.service()?;
    assert_eq!(
        call(&mut service, "PUT", "sys/unseal", "", json!({"key":key})).status,
        200
    );
    assert_eq!(global(&service)?, Some(1));
    assert_eq!(
        call(&mut service, "GET", "cubbyhole/item", &token, json!({})).body["data"],
        value
    );
    let executed = call(
        &mut service,
        "POST",
        "sys/workflows/execute/operations/global-lossless",
        &token,
        json!({}),
    );
    assert_eq!(executed.status, 200);
    assert_eq!(executed.body["data"]["payload"], value);
    assert_eq!(global(&service)?, Some(1));
    Ok(())
}

#[test]
fn global_lossless_kv2_only_uses_its_independent_sticky_engine_custody() -> TestResult {
    let root = Root::new();
    let mut service = root.service()?;
    let (_, token) = bootstrap(&mut service)?;
    assert_eq!(
        call(
            &mut service,
            "POST",
            "sys/migration/openbao/kv2",
            &token,
            json!({"mount":"secret","bundle":legacy_empty_bundle()})
        )
        .status,
        204
    );
    assert_eq!(global(&service)?, None);
    let imported = service.state.as_ref().ok_or("imported")?.clone();
    assert!(imported.engines.has_kv2_lossless_state());
    assert_eq!(imported.schema, KV2_LOSSLESS_STATE_SCHEMA);
    imported.validate_format().map_err(|_| "format")?;
    assert_eq!(
        call(
            &mut service,
            "DELETE",
            "sys/mounts/secret",
            &token,
            json!({})
        )
        .status,
        204
    );
    let retired = service.state.as_ref().ok_or("retired")?.clone();
    assert_eq!(retired.global_lossless_json_format, None);
    assert!(retired.engines.has_kv2_lossless_state());
    let mut wire = serde_json::to_value(&*retired.engines)?;
    wire.as_object_mut()
        .ok_or("engines")?
        .remove("kv2_lossless_format");
    let mut torn = retired.clone();
    torn.engines = serde_json::from_value::<EngineState>(wire)?.into();
    assert!(torn.validate_format().is_err());
    assert!(torn.validate_publication_schema(Some(&retired)).is_err());
    assert!(Service::validate_snapshot_protected_floor(&retired, &torn).is_err());
    assert_eq!(torn.global_lossless_json_format, None);
    Ok(())
}

#[test]
fn global_lossless_v4_owner_manifest_binds_format_and_preserves_all_legacy_logical_bytes()
-> TestResult {
    let logical =
        br#"{"schema":120,"global_lossless_json_format":1,"cluster_id":"lossless-owner-fixture"}"#;
    let owners = ["namespaces", "auth", "engines", "database", "raft_admin"]
        .into_iter()
        .map(|name| (name, Some(Zeroizing::new(b"{}".to_vec()))))
        .collect();
    let plan = owner_store::OwnerWritePlan::new_with_reuse(
        logical,
        "lossless-owner",
        120,
        "lossless-owner-fixture",
        0,
        owners,
        None,
        Vec::new(),
    )?
    .with_global_lossless_json_format(Some(1))?;
    let manifest = owner_store::decode_manifest(&plan.manifest_bytes)?.ok_or("manifest")?;
    assert_eq!(manifest.global_lossless_json_format(), Some(1));
    manifest.verify_logical(logical)?;
    assert!(
        manifest
            .verify_logical(br#"{"schema":120,"cluster_id":"lossless-owner-fixture"}"#)
            .is_err()
    );
    let owners = ["namespaces", "auth", "engines", "database", "raft_admin"]
        .into_iter()
        .map(|name| (name, Some(Zeroizing::new(b"{}".to_vec()))))
        .collect();
    let legacy = br#"{"schema":9,"cluster_id":"legacy"}"#;
    let old = owner_store::OwnerWritePlan::new_with_reuse(
        legacy,
        "ordinary-owner",
        9,
        "legacy",
        0,
        owners,
        None,
        Vec::new(),
    )?;
    let original = old.manifest_bytes.clone();
    let old = old.with_global_lossless_json_format(None)?;
    assert_eq!(old.manifest_bytes, original);
    let manifest = owner_store::decode_manifest(&old.manifest_bytes)?.ok_or("legacy manifest")?;
    assert_eq!(manifest.global_lossless_json_format(), None);
    manifest.verify_logical(legacy)?;
    assert!(old.with_global_lossless_json_format(Some(1)).is_err());
    let invalid = owner_store::decode_manifest(&plan.manifest_bytes)?.ok_or("manifest")?;
    invalid.verify_logical(logical)?;
    assert!(plan.with_global_lossless_json_format(Some(2)).is_err());
    Ok(())
}
