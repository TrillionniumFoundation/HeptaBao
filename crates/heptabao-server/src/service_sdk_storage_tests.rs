use super::tests::{Root, bootstrap, call};
use super::*;
use crate::engines::sdk::{Descriptor, MountOwner, StorageEntry};

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn descriptor(name: &str) -> Descriptor {
    Descriptor {
        name: name.into(),
        version: "v1.0.0".into(),
        command: "probe".into(),
        args: Vec::new(),
        sha256: "a".repeat(64),
        generation: 1,
    }
}
fn mount(state: &mut State, name: &str) -> Result<MountOwner, Box<dyn std::error::Error>> {
    let d = state.engines.register_sdk_descriptor(descriptor(name))?;
    state.engines.handle(
        "",
        "POST",
        &format!("sys/mounts/{name}"),
        &json!({"type":"plugin","config":{"plugin_id":name}}),
        100,
    )?;
    Ok(state.engines.bind_sdk_mount("", &format!("{name}/"), &d)?)
}
fn publish(service: &mut Service, mut candidate: State) -> Result<(), Box<dyn std::error::Error>> {
    candidate.schema = candidate.writer_schema();
    service
        .commit_state(&mut candidate)
        .map_err(|e| format!("record publication: {} {}", e.status, e.body))?;
    service.state = Some(candidate);
    Ok(())
}
fn entry(key: &str, value: &[u8]) -> StorageEntry {
    StorageEntry {
        key: key.into(),
        value: Zeroizing::new(value.to_vec()),
        seal_wrap: true,
    }
}

#[test]
fn sdk_storage92_real_record_publication_backup_and_reopen() -> TestResult {
    let directory = Root::new();
    let mut service = directory.service()?;
    let (key, token) = bootstrap(&mut service)?;
    let mut candidate = service.state.clone().ok_or("state")?;
    let owner = mount(&mut candidate, "sdk_probe")?;
    for (k, v) in [
        ("item", b"durable SDK secret".as_slice()),
        ("nested/child", b"nested".as_slice()),
        ("z", b"last".as_slice()),
    ] {
        candidate
            .engines
            .sdk_storage_put("", "sdk_probe/", &owner, entry(k, v))?;
    }
    publish(&mut service, candidate)?;
    assert_eq!(service.state.as_ref().ok_or("state")?.schema, 92);
    let identity = service.current_state_identity().map_err(|_| "identity")?;
    let backup = service.durable.as_ref().ok_or("durable")?.export_backup()?;
    let restored = service
        .prepare_snapshot_restore(&backup)
        .map_err(|_| "backup validation")?;
    drop(restored);
    assert_eq!(
        call(&mut service, "PUT", "sys/seal", &token, json!({})).status,
        204
    );
    drop(service);
    let mut service = directory.service()?;
    assert_eq!(
        call(&mut service, "PUT", "sys/unseal", "", json!({"key":key})).status,
        200
    );
    assert_eq!(
        service
            .current_state_identity()
            .map_err(|_| "reopen identity")?,
        identity
    );
    let state = service.state.as_ref().ok_or("reopened state")?;
    let item = state
        .engines
        .sdk_storage_get("", "sdk_probe/", &owner, "item")?
        .ok_or("item")?;
    assert_eq!(item.value.as_slice(), b"durable SDK secret");
    assert!(item.seal_wrap);
    assert_eq!(
        state
            .engines
            .sdk_storage_list("", "sdk_probe/", &owner, "", "", 0)?,
        vec!["item", "nested/", "z"]
    );
    assert_eq!(
        state
            .engines
            .sdk_storage_list("", "sdk_probe/", &owner, "", "item", 1)?,
        vec!["nested/"]
    );
    let mut candidate = state.clone();
    candidate
        .engines
        .sdk_storage_delete("", "sdk_probe/", &owner, "item")?;
    publish(&mut service, candidate)?;
    drop(service);
    let mut service = directory.service()?;
    assert_eq!(
        call(&mut service, "PUT", "sys/unseal", "", json!({"key":key})).status,
        200
    );
    assert!(
        service
            .state
            .as_ref()
            .ok_or("state")?
            .engines
            .sdk_storage_get("", "sdk_probe/", &owner, "item")?
            .is_none()
    );
    Ok(())
}

#[test]
fn sdk_storage92_unmount_recreate_retires_exact_incarnation() -> TestResult {
    let directory = Root::new();
    let mut service = directory.service()?;
    let (key, _) = bootstrap(&mut service)?;
    let mut candidate = service.state.clone().ok_or("state")?;
    let old = mount(&mut candidate, "sdk_probe")?;
    let sibling = mount(&mut candidate, "sdk_sibling")?;
    candidate
        .engines
        .sdk_storage_put("", "sdk_probe/", &old, entry("same", b"old"))?;
    candidate
        .engines
        .sdk_storage_put("", "sdk_sibling/", &sibling, entry("same", b"sibling"))?;
    publish(&mut service, candidate)?;
    let mut candidate = service.state.clone().ok_or("state")?;
    assert!(
        candidate
            .engines
            .deregister_sdk_descriptor("sdk_probe", "v1.0.0")
            .is_err()
    );
    candidate
        .engines
        .handle("", "DELETE", "sys/mounts/sdk_probe", &json!({}), 100)?;
    candidate.engines.handle(
        "",
        "POST",
        "sys/mounts/sdk_probe",
        &json!({"type":"plugin","config":{"plugin_id":"sdk_probe"}}),
        100,
    )?;
    let d = candidate
        .engines
        .sdk_descriptor("sdk_probe", "v1.0.0")
        .ok_or("descriptor")?;
    let new = candidate.engines.bind_sdk_mount("", "sdk_probe/", &d)?;
    assert_ne!(old.mount_incarnation, new.mount_incarnation);
    assert!(
        candidate
            .engines
            .sdk_storage_get("", "sdk_probe/", &old, "same")
            .is_err()
    );
    assert!(
        candidate
            .engines
            .sdk_storage_get("", "sdk_probe/", &new, "same")?
            .is_none()
    );
    assert_eq!(
        candidate
            .engines
            .sdk_storage_get("", "sdk_sibling/", &sibling, "same")?
            .ok_or("sibling")?
            .value
            .as_slice(),
        b"sibling"
    );
    publish(&mut service, candidate)?;
    drop(service);
    let mut service = directory.service()?;
    assert_eq!(
        call(&mut service, "PUT", "sys/unseal", "", json!({"key":key})).status,
        200
    );
    assert!(
        service
            .state
            .as_ref()
            .ok_or("state")?
            .engines
            .sdk_storage_get("", "sdk_probe/", &new, "same")?
            .is_none()
    );
    Ok(())
}

#[test]
fn sdk_storage92_old_plan_cannot_publish_new_catalog_metadata_or_downgrade() -> TestResult {
    let directory = Root::new();
    let mut service = directory.service()?;
    bootstrap(&mut service)?;
    let mut candidate = service.state.clone().ok_or("state")?;
    let owner = mount(&mut candidate, "sdk_probe")?;
    candidate
        .engines
        .sdk_storage_put("", "sdk_probe/", &owner, entry("item", b"value"))?;
    publish(&mut service, candidate)?;
    let mut old = service.state.clone().ok_or("state")?;
    let plan = service
        .prepare_record_plan(&mut old)
        .map_err(|_| "old plan")?;
    let identity = service.current_state_identity().map_err(|_| "identity")?;
    let generation = service.durable.as_ref().ok_or("durable")?.generation();
    let mut changed = old.clone();
    changed
        .engines
        .register_sdk_descriptor(descriptor("other_probe"))?;
    assert!(service.commit_record_plan(&changed, plan).is_err());
    assert_eq!(
        service
            .current_state_identity()
            .map_err(|_| "identity after reject")?,
        identity
    );
    assert_eq!(
        service.durable.as_ref().ok_or("durable")?.generation(),
        generation
    );
    changed.schema = 90;
    assert!(changed.validate_format().is_err());
    assert!(service.commit_state(&mut changed).is_err());
    let mut candidate = old;
    candidate
        .engines
        .handle("", "DELETE", "sys/mounts/sdk_probe", &json!({}), 100)?;
    candidate
        .engines
        .deregister_sdk_descriptor("sdk_probe", "v1.0.0")?;
    publish(&mut service, candidate)?;
    assert_eq!(service.state.as_ref().ok_or("state")?.schema, 92);
    Ok(())
}

#[test]
fn sdk_storage92_first_empty_mount_publishes_authenticated_root_and_reopens() -> TestResult {
    let directory = Root::new();
    let mut service = directory.service()?;
    let (key, token) = super::tests::bootstrap_unmounted(&mut service)?;
    assert!(service.record_root.is_none());
    let mut candidate = service.state.clone().ok_or("initial state")?;
    assert!(candidate.engines.record_root().is_none());
    let owner = mount(&mut candidate, "sdk_probe")?;
    service
        .prepare_sdk_mount_record_root(&mut candidate)
        .map_err(|e| format!("first SDK root: {} {}", e.status, e.body))?;
    publish(&mut service, candidate)?;
    assert!(service.record_root.is_some());
    assert_eq!(service.state.as_ref().ok_or("SDK state")?.schema, 92);
    assert!(
        service
            .state
            .as_ref()
            .ok_or("SDK state")?
            .engines
            .sdk_storage_get("", "sdk_probe/", &owner, "missing")?
            .is_none()
    );
    assert_eq!(
        call(&mut service, "PUT", "sys/seal", &token, json!({})).status,
        204
    );
    drop(service);
    let mut service = directory.service()?;
    assert_eq!(
        call(&mut service, "PUT", "sys/unseal", "", json!({"key":key})).status,
        200
    );
    assert!(service.record_root.is_some());
    assert!(
        service
            .state
            .as_ref()
            .ok_or("SDK reopened")?
            .engines
            .sdk_storage_get("", "sdk_probe/", &owner, "missing")?
            .is_none()
    );
    Ok(())
}
