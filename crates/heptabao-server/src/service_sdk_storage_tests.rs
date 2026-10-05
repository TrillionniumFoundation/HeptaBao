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

#[test]
fn sdk_remount92_real_records_owner_tombstone_and_durable_reopen() -> TestResult {
    let directory = Root::new();
    let mut service = directory.service()?;
    let (key, token) = bootstrap(&mut service)?;
    let mut candidate = service.state.clone().ok_or("state")?;
    let owner = mount(&mut candidate, "sdk_probe")?;
    let sibling = mount(&mut candidate, "sdk_sibling")?;
    mount(&mut candidate, "sdk_moved")?;
    candidate
        .engines
        .handle("", "DELETE", "sys/mounts/sdk_moved", &json!({}), 100)?;
    candidate.engines.sdk_storage_put(
        "",
        "sdk_probe/",
        &owner,
        entry("item", b"move-preserved"),
    )?;
    candidate.engines.sdk_storage_put(
        "",
        "sdk_probe/",
        &owner,
        entry("nested/child", b"nested-preserved"),
    )?;
    candidate.engines.sdk_storage_put(
        "",
        "sdk_sibling/",
        &sibling,
        entry("item", b"sibling-preserved"),
    )?;
    publish(&mut service, candidate)?;
    let original = service.state.clone().ok_or("original")?;
    let mut candidate = original.clone();
    candidate
        .engines
        .remount("", "sdk_probe/", "sdk_moved/", None)?;
    candidate.engines.validate_sdk_state()?;
    let (_, moved) = candidate
        .engines
        .sdk_mount_binding("", "sdk_moved/item")
        .ok_or("moved owner")?;
    assert_eq!(moved.catalog_generation, owner.catalog_generation);
    assert!(moved.mount_incarnation > owner.mount_incarnation);
    assert!(
        candidate
            .engines
            .sdk_storage_get("", "sdk_probe/", &owner, "item")
            .is_err()
    );
    assert_eq!(
        candidate
            .engines
            .sdk_storage_get("", "sdk_moved/", &moved, "item")?
            .ok_or("moved item")?
            .value
            .as_slice(),
        b"move-preserved"
    );
    assert_eq!(
        candidate
            .engines
            .sdk_storage_list("", "sdk_moved/", &moved, "", "", 0)?,
        vec!["item", "nested/"]
    );
    assert_eq!(
        original
            .engines
            .sdk_storage_get("", "sdk_probe/", &owner, "item")?
            .ok_or("original COW item")?
            .value
            .as_slice(),
        b"move-preserved"
    );
    candidate.engines.handle(
        "",
        "POST",
        "sys/mounts/sdk_probe",
        &json!({"type":"plugin","config":{"plugin_id":"sdk_probe"}}),
        100,
    )?;
    let descriptor = candidate
        .engines
        .sdk_descriptor("sdk_probe", "v1.0.0")
        .ok_or("original descriptor")?;
    let fresh = candidate
        .engines
        .bind_sdk_mount("", "sdk_probe/", &descriptor)?;
    assert!(fresh.mount_incarnation > owner.mount_incarnation);
    assert!(
        candidate
            .engines
            .sdk_storage_get("", "sdk_probe/", &fresh, "item")?
            .is_none()
    );
    publish(&mut service, candidate)?;
    let backup = service.durable.as_ref().ok_or("durable")?.export_backup()?;
    service
        .prepare_snapshot_restore(&backup)
        .map_err(|_| "remount backup validation")?;
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
    let state = service.state.as_ref().ok_or("reopened")?;
    let value = state
        .engines
        .sdk_storage_get("", "sdk_moved/", &moved, "nested/child")?
        .ok_or("reopened moved child")?;
    assert_eq!(value.value.as_slice(), b"nested-preserved");
    assert!(value.seal_wrap);
    assert!(
        state
            .engines
            .sdk_storage_get("", "sdk_probe/", &fresh, "item")?
            .is_none()
    );
    assert_eq!(
        state
            .engines
            .sdk_storage_get("", "sdk_sibling/", &sibling, "item")?
            .ok_or("reopened sibling")?
            .value
            .as_slice(),
        b"sibling-preserved"
    );
    Ok(())
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
fn sdk_remount92_actual_control_capsule_and_status_read_without_sudo() -> TestResult {
    fn precise(
        service: &mut Service,
        token: &str,
        method: &str,
        path: &str,
        body: Value,
    ) -> Result<Response, Box<dyn std::error::Error>> {
        let clock =
            RequestClock::anchored(Duration::new(100, 200_000_000), std::time::Instant::now())?;
        let execution = service.begin_at_mode_precise(
            RequestDispatch {
                method,
                path,
                namespace: "",
                token,
                body,
                now: 100,
                allow_forward: true,
                enforce_namespace: true,
                wrap_ttl_seconds: None,
                origin_peer: None,
                client_certificates: None,
            },
            clock,
        );
        Ok(service.finish_synchronous_request(execution))
    }
    let directory = Root::new();
    let mut service = directory.service()?;
    let (_, root) = bootstrap(&mut service)?;
    let mut candidate = service.state.clone().ok_or("state")?;
    let owner = mount(&mut candidate, "sdk_probe")?;
    candidate.engines.sdk_storage_put(
        "",
        "sdk_probe/",
        &owner,
        entry("item", b"original-body-owner"),
    )?;
    publish(&mut service, candidate)?;
    for (name, policy) in [
        (
            "sdk-remount-denied",
            r#"path "sys/remount" { capabilities=["update"] }"#,
        ),
        (
            "sdk-remount-status",
            r#"path "sys/remount/status/*" { capabilities=["read"] }"#,
        ),
    ] {
        assert_eq!(
            call(
                &mut service,
                "PUT",
                &format!("sys/policies/acl/{name}"),
                &root,
                json!({"policy":policy})
            )
            .status,
            204
        );
    }
    let denied = precise(
        &mut service,
        &root,
        "POST",
        "auth/token/create",
        json!({"policies":["sdk-remount-denied"],"ttl":"30s","no_default_policy":true}),
    )?;
    assert_eq!(denied.status, 200, "{}", denied.body);
    let denied_token = denied.body["auth"]["client_token"]
        .as_str()
        .ok_or("denied actor")?;
    let response = precise(
        &mut service,
        denied_token,
        "POST",
        "sys/remount",
        json!({"from":"sdk_probe/","to":"sdk_moved/"}),
    )?;
    assert_eq!(response.status, 403);
    assert!(service.sdk_migrations.is_empty());
    // Authentication may durably advance its floor, but the original SDK owner remains.
    let current = service.state.as_ref().ok_or("post-denial")?;
    assert_eq!(
        current.engines.sdk_mount_binding("", "sdk_probe/item"),
        Some(("sdk_probe/".into(), owner.clone()))
    );
    let response = precise(
        &mut service,
        &root,
        "POST",
        "sys/remount",
        json!({"from":"sdk_probe/","to":"sdk_moved/"}),
    )?;
    assert_eq!(response.status, 200, "{}", response.body);
    let id = response.body["data"]["migration_id"]
        .as_str()
        .ok_or("migration id")?
        .to_owned();
    assert!(service.pending_sdk_control_authority.is_none());
    assert!(service.sdk_hosts.is_empty());
    let reader = precise(
        &mut service,
        &root,
        "POST",
        "auth/token/create",
        json!({"policies":["sdk-remount-status"],"ttl":"30s","no_default_policy":true}),
    )?;
    assert_eq!(reader.status, 200, "{}", reader.body);
    let reader_token = reader.body["auth"]["client_token"]
        .as_str()
        .ok_or("status actor")?;
    let status = precise(
        &mut service,
        reader_token,
        "GET",
        &format!("sys/remount/status/{id}"),
        json!({}),
    )?;
    assert_eq!(status.status, 200, "{}", status.body);
    assert_eq!(status.body["data"]["migration_id"], id);
    assert_eq!(status.body["data"]["migration_info"]["status"], "success");
    assert!(service.pending_sdk_control_authority.is_none());
    let (_, moved) = service
        .state
        .as_ref()
        .ok_or("state")?
        .engines
        .sdk_mount_binding("", "sdk_moved/item")
        .ok_or("moved")?;
    assert_eq!(
        service
            .state
            .as_ref()
            .ok_or("state")?
            .engines
            .sdk_storage_get("", "sdk_moved/", &moved, "item")?
            .ok_or("moved value")?
            .value
            .as_slice(),
        b"original-body-owner"
    );
    Ok(())
}
