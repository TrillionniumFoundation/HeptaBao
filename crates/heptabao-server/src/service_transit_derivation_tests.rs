//! Durable reader, publication, original encrypted restart and retirement fences.
use super::tests::{Root, bootstrap};
use super::*;
use zeroize::Zeroizing;
type TestResult = Result<(), &'static str>;
fn call(service: &mut Service, method: &str, path: &str, token: &str, body: Value) -> Response {
    service.handle_at(method,path,"",token,body,100)
}
fn erase_marker(value: &mut Value) -> usize {
    match value {
        Value::Object(fields) => usize::from(fields.remove("derived_ed_format").is_some())
            + fields.values_mut().map(erase_marker).sum::<usize>(),
        Value::Array(values) => values.iter_mut().map(erase_marker).sum(),
        _ => 0,
    }
}
#[test]
fn derivation127_service_old_reader_marker_rollback_snapshot_restart_and_retirement_are_closed() -> TestResult {
    let root = Root::new();
    let mut service = root.service().map_err(|_| "service bootstrap")?;
    let (unseal, admin) = bootstrap(&mut service).map_err(|_| "bootstrap credentials")?;
    let unseal = Zeroizing::new(unseal);
    let admin = Zeroizing::new(admin);
    let before = Zeroizing::new(service.durable.as_ref().ok_or("durable missing")?
        .export_backup().map_err(|_| "original snapshot")?);
    assert!(call(&mut service,"POST","sys/mounts/derive",&admin,json!({"type":"transit"})).status == 204);
    assert!(call(&mut service,"POST","derive/keys/context",&admin,json!({"type":"ed25519","derived":true,"deletion_allowed":true})).status == 200);
    let request = json!({"input":"bmV3IGVuY3J5cHRlZCByZXN0YXJ0IHZlY3Rvcg==","context":"dGVuYW50"});
    let signed = call(&mut service,"POST","derive/sign/context",&admin,request.clone());
    assert!(signed.status == 200 && signed.body["data"]["public_key"].as_str().is_some_and(|value| !value.is_empty()));
    let current = service.state.as_ref().ok_or("state missing")?.clone();
    assert!(current.schema == TRANSIT_DERIVED_ED_STATE_SCHEMA
        && current.writer_schema() == TRANSIT_DERIVED_ED_STATE_SCHEMA
        && current.engines.has_transit_derived_ed_state()
        && current.validate_format().is_ok());
    assert!(supported_reader_schema(127) && !supported_reader_schema(MAX_SUPPORTED_STATE_SCHEMA + 1));
    for schema in [SYMMETRIC_BACKUP_STATE_SCHEMA, TRANSIT_ROTATION_PRECISION_STATE_SCHEMA] {
        let mut lower = current.clone();lower.schema = schema;
        assert!(lower.validate_format().is_err());
        assert!(lower.validate_publication_schema(Some(&current)).is_err());
        assert!(Service::validate_snapshot_protected_floor(&current,&lower).is_err());
    }
    let raw = Zeroizing::new(serde_json::to_vec(&current).map_err(|_| "private state encoding")?);
    let mut erased: Value = serde_json::from_slice(&raw).map_err(|_| "private state decoding")?;
    assert!(erase_marker(&mut erased) == 1);
    let raw = Zeroizing::new(serde_json::to_vec(&erased).map_err(|_| "synthetic marker encoding")?);
    let mut erased: State = serde_json::from_slice(&raw).map_err(|_| "synthetic marker decoding")?;
    assert!(erased.validate_format().is_err());
    assert!(erased.validate_publication_schema(Some(&current)).is_err());
    assert!(Service::validate_snapshot_protected_floor(&current,&erased).is_err());
    // Erasing both the explicit marker and public derived flag cannot turn a 64-byte master into a legacy Ed key.
    let mut double_erased: Value = serde_json::from_slice(&raw).map_err(|_| "double-erased decoding")?;
    fn erase_derived(value: &mut Value) {
        match value {
            Value::Object(fields) => {
                if fields.get("kind").is_some_and(|kind| kind=="ed25519") { fields.remove("derived"); }
                for value in fields.values_mut() { erase_derived(value); }
            }
            Value::Array(values) => for value in values { erase_derived(value); },
            _ => {}
        }
    }
    erase_derived(&mut double_erased);
    let mut double_erased: State = serde_json::from_value(double_erased).map_err(|_| "double-erased state")?;
    double_erased.schema = TRANSIT_ROTATION_PRECISION_STATE_SCHEMA;
    assert!(double_erased.engines.has_transit_derived_ed_state());
    assert!(double_erased.validate_format().is_err());
    assert!(double_erased.validate_publication_schema(Some(&current)).is_err());
    assert!(Service::validate_snapshot_protected_floor(&current,&double_erased).is_err());
    let identity = service.current_state_identity().map_err(|_| "current identity")?;
    assert!(service.commit_state(&mut erased).is_err());
    assert!(service.current_state_identity().map_err(|_| "identity after reject")? == identity);
    assert!(service.prepare_snapshot_restore(&before).err().is_some_and(|error| error.status == 400));
    drop(service);
    let mut service = root.service().map_err(|_| "encrypted restart")?;
    assert!(call(&mut service,"POST","sys/unseal","",json!({"key":unseal.as_str()})).status == 200);
    let restarted = call(&mut service,"POST","derive/sign/context",&admin,request);
    assert!(restarted.status == 200 && restarted.body["data"] == signed.body["data"]);
    assert!(call(&mut service,"DELETE","derive/keys/context",&admin,json!({})).status == 204);
    let retired_key = service.state.as_ref().ok_or("retired state missing")?.clone();
    assert!(retired_key.schema == 127 && retired_key.engines.has_transit_derived_ed_state());
    let raw = Zeroizing::new(serde_json::to_vec(&retired_key).map_err(|_| "retired state encoding")?);
    let mut erased: Value = serde_json::from_slice(&raw).map_err(|_| "retired state decoding")?;
    assert!(erase_marker(&mut erased) == 1);
    let erased: State = serde_json::from_value(erased).map_err(|_| "retired marker decoding")?;
    assert!(erased.validate_publication_schema(Some(&retired_key)).is_err());
    assert!(Service::validate_snapshot_protected_floor(&retired_key,&erased).is_err());
    assert!(call(&mut service,"DELETE","sys/mounts/derive",&admin,json!({})).status == 204);
    let retired = service.state.as_ref().ok_or("retired mount missing")?.clone();
    assert!(retired.schema == 127 && retired.writer_schema() == 127 && !retired.engines.has_transit_derived_ed_state());
    let mut lower = retired.clone();lower.schema = 124;
    assert!(lower.validate_publication_schema(Some(&retired)).is_err());
    assert!(Service::validate_snapshot_protected_floor(&retired,&lower).is_err());
    let identity = service.current_state_identity().map_err(|_| "retired identity")?;
    assert!(service.commit_state(&mut lower).is_err());
    assert!(service.current_state_identity().map_err(|_| "retired reject identity")? == identity);
    drop(service);
    let mut service = root.service().map_err(|_| "retired encrypted restart")?;
    assert!(call(&mut service,"POST","sys/unseal","",json!({"key":unseal.as_str()})).status == 200);
    assert!(service.state.as_ref().ok_or("retired restart state")?.schema == 127);
    Ok(())
}
