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

#[test]
fn sdk_headers95_durable_configuration_stale_owner_and_sticky_floor() -> TestResult {
    let directory = Root::new();
    let mut service = directory.service()?;
    let (key, token) = bootstrap(&mut service)?;
    let mut candidate = service.state.clone().ok_or("state")?;
    let old = mount(&mut candidate, "sdk_probe")?;
    candidate.engines.sdk_storage_put(
        "",
        "sdk_probe/",
        &old,
        entry("item", b"configuration-independent-value"),
    )?;
    publish(&mut service, candidate)?;
    let old_backup = service.durable.as_ref().ok_or("durable")?.export_backup()?;
    let original = service.state.clone().ok_or("published state")?;
    let mut candidate = original.clone();
    let configured = candidate.engines.set_sdk_response_headers(
        "",
        "sdk_probe/",
        &old,
        vec![
            "X-SDK-One".into(),
            "x-sdk-Multi".into(),
            "X-SDK-Prefix-*".into(),
        ],
    )?;
    assert_ne!(
        configured.response_config_revision,
        old.response_config_revision
    );
    assert!(
        candidate
            .engines
            .sdk_storage_get("", "sdk_probe/", &old, "item")
            .is_err()
    );
    assert_eq!(
        candidate
            .engines
            .sdk_storage_get("", "sdk_probe/", &configured, "item")?
            .ok_or("item")?
            .value
            .as_slice(),
        b"configuration-independent-value"
    );
    assert_eq!(
        original
            .engines
            .sdk_mount_binding("", "sdk_probe/item")
            .ok_or("COW original owner")?
            .1,
        old
    );
    candidate.schema = candidate.writer_schema();
    assert_eq!(candidate.schema, 95);
    for lower in [92, 93, 94] {
        let mut downgraded = candidate.clone();
        downgraded.schema = lower;
        assert!(downgraded.validate_format().is_err());
        assert!(
            downgraded
                .validate_publication_schema(Some(&original))
                .is_err()
        );
    }
    publish(&mut service, candidate)?;
    let rejected = match service.prepare_snapshot_restore(&old_backup) {
        Err(error) => error,
        Ok(_) => return Err("old snapshot downgraded SDK header ownership".into()),
    };
    assert_eq!(rejected.status, 400);
    assert!(
        rejected
            .body
            .to_string()
            .contains("snapshot would downgrade SDK response header ownership"),
        "{}",
        rejected.body
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
    let reopened = service.state.as_ref().ok_or("reopened")?;
    assert_eq!(reopened.schema, 95);
    assert_eq!(
        reopened
            .engines
            .sdk_mount_binding("", "sdk_probe/item")
            .ok_or("reopened owner")?
            .1,
        configured
    );
    assert_eq!(
        reopened
            .engines
            .sdk_storage_get("", "sdk_probe/", &configured, "item")?
            .ok_or("reopened item")?
            .value
            .as_slice(),
        b"configuration-independent-value"
    );
    let mut retired = reopened.clone();
    retired
        .engines
        .handle("", "DELETE", "sys/mounts/sdk_probe", &json!({}), 100)?;
    retired
        .engines
        .deregister_sdk_descriptor("sdk_probe", "v1.0.0")?;
    assert!(!retired.engines.has_sdk_response_header_state());
    assert_eq!(retired.writer_schema(), 95);
    let mut downgraded = retired.clone();
    downgraded.schema = 93;
    assert!(
        downgraded
            .validate_publication_schema(Some(reopened))
            .is_err()
    );
    publish(&mut service, retired)?;
    let rejected = match service.prepare_snapshot_restore(&old_backup) {
        Err(error) => error,
        Ok(_) => return Err("old snapshot downgraded SDK header ownership".into()),
    };
    assert_eq!(rejected.status, 400);
    assert!(
        rejected
            .body
            .to_string()
            .contains("snapshot would downgrade SDK response header ownership"),
        "{}",
        rejected.body
    );
    assert_eq!(service.state.as_ref().ok_or("retired")?.schema, 95);
    Ok(())
}

fn sdk96_fixture(
    candidate: &mut State,
    token: &str,
) -> Result<(crate::engines::sdk_lease::Lease, MountOwner), Box<dyn std::error::Error>> {
    use crate::engines::sdk_lease::{Binding, Grant, Lease};
    let owner = mount(candidate, "sdk_probe")?;
    let principal = candidate.auth.authenticate(token, 100)?;
    let issuer =
        candidate
            .auth
            .typed_lease_issuer_observed(&principal, "", AuthorityTime::Coarse(100))?;
    let at = crate::auth::Timestamp::checked(100, 123_456_789)?;
    let lease = Lease::new(
        Binding {
            id: "sdk_probe/leased/abcdef".into(),
            namespace: String::new(),
            cluster: candidate.cluster_id.clone(),
            mount: "sdk_probe/".into(),
            path: "sdk_probe/leased".into(),
            backend: owner.clone(),
            issuer: issuer.owner,
        },
        Grant {
            issued: at,
            ttl_ns: 20_000_000_000,
            max_ttl_ns: 90_000_000_000,
            renewable: true,
            secret: json!({"LeaseID":"","lease":20_000_000_000_u64,"max_ttl":90_000_000_000_u64,"renewable":true,"internal_data":{"secret_type":"sdk_credential","storage_key":"credential-record"}}),
            data: json!({"credential":"registered-secret96"}),
        },
    )?;
    candidate.engines.observe_sdk_lease_clock(at);
    candidate.engines.store_sdk_lease(lease.clone())?;
    candidate.engines.sdk_storage_put(
        "",
        "sdk_probe/",
        &owner,
        entry("credential-record", b"registered-secret96"),
    )?;
    Ok((lease, owner))
}

#[test]
fn sdk96_encrypted_registry_storage_backup_reopen_and_sticky_retirement() -> TestResult {
    let directory = Root::new();
    let mut service = directory.service()?;
    let (key, token) = bootstrap(&mut service)?;
    let mut candidate = service.state.clone().ok_or("state")?;
    let (mut lease, owner) = sdk96_fixture(&mut candidate, &token)?;
    publish(&mut service, candidate)?;
    assert_eq!(service.state.as_ref().ok_or("state")?.schema, 96);
    let backup = service.durable.as_ref().ok_or("durable")?.export_backup()?;
    assert!(
        !backup
            .windows(b"registered-secret96".len())
            .any(|w| w == b"registered-secret96")
    );
    service
        .prepare_snapshot_restore(&backup)
        .map_err(|_| "real backup admission")?;
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
    let state = service.state.as_ref().ok_or("reopened state")?;
    let restored = state
        .engines
        .sdk_lease("", &lease.id)
        .ok_or("registered lease")?;
    assert!(restored.issuer == lease.issuer);
    assert_eq!(restored.issued, lease.issued);
    assert_eq!(
        restored.response_data(),
        json!({"credential":"registered-secret96"})
    );
    assert_eq!(
        state
            .engines
            .sdk_storage_get("", "sdk_probe/", &owner, "credential-record")?
            .ok_or("Storage")?
            .value
            .as_slice(),
        b"registered-secret96"
    );
    let at = crate::auth::Timestamp::checked(105, 777_000_000)?;
    let mut candidate = state.clone();
    lease.renew(crate::engines::sdk_lease::Grant {
        issued: at,
        ttl_ns: 30_000_000_000,
        max_ttl_ns: 90_000_000_000,
        renewable: true,
        secret: lease.callback(),
        data: lease.response_data(),
    })?;
    candidate.engines.observe_sdk_lease_clock(at);
    candidate.engines.store_sdk_lease(lease.clone())?;
    candidate.engines.sdk_storage_put(
        "",
        "sdk_probe/",
        &owner,
        entry("credential-record", b"renewed-secret96"),
    )?;
    publish(&mut service, candidate)?;
    let mut candidate = service.state.clone().ok_or("state")?;
    lease.revoke();
    candidate.engines.store_sdk_lease(lease.clone())?;
    candidate
        .engines
        .sdk_storage_delete("", "sdk_probe/", &owner, "credential-record")?;
    publish(&mut service, candidate)?;
    drop(service);
    let mut service = directory.service()?;
    assert_eq!(
        call(&mut service, "PUT", "sys/unseal", "", json!({"key":key})).status,
        200
    );
    let state = service.state.as_ref().ok_or("state")?;
    assert_eq!(state.schema, 96);
    assert!(
        state
            .engines
            .sdk_lease("", &lease.id)
            .ok_or("retired lease")?
            .lookup(at)
            .is_err()
    );
    assert!(
        state
            .engines
            .sdk_storage_get("", "sdk_probe/", &owner, "credential-record")?
            .is_none()
    );
    Ok(())
}

#[test]
fn sdk96_floor_rollback_or_old_reader_cannot_publish_or_restore() -> TestResult {
    let directory = Root::new();
    let mut service = directory.service()?;
    let (_, token) = bootstrap(&mut service)?;
    let old_backup = service.durable.as_ref().ok_or("durable")?.export_backup()?;
    let mut candidate = service.state.clone().ok_or("state")?;
    sdk96_fixture(&mut candidate, &token)?;
    publish(&mut service, candidate)?;
    assert!(service.prepare_snapshot_restore(&old_backup).is_err());
    let actual = service.state.clone().ok_or("state")?;
    let identity = service.current_state_identity().map_err(|_| "identity")?;
    for floor in [Value::Null, json!({"seconds":99,"nanoseconds":0})] {
        let mut wire = serde_json::to_value(&actual)?;
        wire["engines"]["sdk_lease_clock"] = floor;
        let mut downgraded: State = serde_json::from_value(wire)?;
        assert!(
            downgraded
                .validate_publication_schema(Some(&actual))
                .is_err()
        );
        assert!(service.commit_state(&mut downgraded).is_err());
        assert_eq!(
            service.current_state_identity().map_err(|_| "identity")?,
            identity
        );
    }
    let mut old_reader = actual.clone();
    old_reader.schema = 95;
    assert!(old_reader.validate_format().is_err());
    assert!(service.commit_state(&mut old_reader).is_err());
    Ok(())
}

#[test]
fn sdk96_exact_cluster_mount_and_go_secret_wire_tampering_rejected() -> TestResult {
    let directory = Root::new();
    let mut service = directory.service()?;
    let (_, token) = bootstrap(&mut service)?;
    let mut candidate = service.state.clone().ok_or("state")?;
    let (lease, _) = sdk96_fixture(&mut candidate, &token)?;
    for field in ["cluster", "mount_incarnation", "LeaseID", "lease"] {
        let mut wire = serde_json::to_value(&lease)?;
        match field {
            "cluster" => wire["cluster"] = json!("foreign-cluster"),
            "mount_incarnation" => wire["backend"]["mount_incarnation"] = json!(999),
            "LeaseID" => wire["secret"]["LeaseID"] = json!("plugin-chosen-identity"),
            _ => wire["secret"]["lease"] = json!(-1),
        }
        let altered: crate::engines::sdk_lease::Lease = serde_json::from_value(wire)?;
        let mut rejected = candidate.clone();
        if rejected.engines.store_sdk_lease(altered).is_ok() {
            assert!(rejected.validate_format().is_err());
        }
    }
    assert!(
        lease
            .lookup(crate::auth::Timestamp::checked(121, 0)?)
            .is_err()
    );
    Ok(())
}

#[test]
fn sdk96_clock_only_commit_changes_exact_engine_owner_and_reopens() -> TestResult {
    let directory = Root::new();
    let mut service = directory.service()?;
    let (key, token) = bootstrap(&mut service)?;
    let mut candidate = service.state.clone().ok_or("state")?;
    mount(&mut candidate, "sdk_probe")?;
    let initial = crate::auth::Timestamp::checked(100, 1)?;
    candidate.engines.observe_sdk_lease_clock(initial);
    publish(&mut service, candidate)?;
    let original = service.state.clone().ok_or("state")?;
    let original_owner = service.record_root.as_ref().ok_or("record root")?.owners[2].digest;
    let old_backup = service.durable.as_ref().ok_or("durable")?.export_backup()?;
    let later = crate::auth::Timestamp::checked(101, 999)?;
    let mut candidate = original.clone();
    assert!(candidate.engines.observe_sdk_lease_clock(later));
    assert!(
        !candidate
            .engines
            .owner_metadata_shared_with(&original.engines)
    );
    assert_eq!(original.engines.sdk_lease_clock_floor(), Some(initial));
    publish(&mut service, candidate)?;
    assert!(service.record_root.as_ref().ok_or("record root")?.owners[2].digest != original_owner);
    let backup = service.durable.as_ref().ok_or("durable")?.export_backup()?;
    service
        .prepare_snapshot_restore(&backup)
        .map_err(|_| "fresh clock-only backup")?;
    assert!(service.prepare_snapshot_restore(&old_backup).is_err());
    assert!(
        Service::validate_snapshot_protected_floor(
            service.state.as_ref().ok_or("state")?,
            &original
        )
        .is_err()
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
    assert_eq!(
        service
            .state
            .as_ref()
            .ok_or("state")?
            .engines
            .sdk_lease_clock_floor(),
        Some(later)
    );
    Ok(())
}

#[test]
fn sdk96_pki97_joint_encrypted_owners_floor_backup_and_reopen() -> TestResult {
    let directory = Root::new();
    let mut service = directory.service()?;
    let (key, token) = bootstrap(&mut service)?;
    let old_backup = service.durable.as_ref().ok_or("durable")?.export_backup()?;
    let mut candidate = service.state.clone().ok_or("state")?;
    let (lease, owner) = sdk96_fixture(&mut candidate, &token)?;
    candidate
        .engines
        .handle("", "POST", "sys/mounts/ca", &json!({"type":"pki"}), 100)?;
    candidate.engines.handle(
        "",
        "POST",
        "ca/config/urls",
        &json!({"issuing_certificates":["https://ca.example.test/issuer"]}),
        100,
    )?;
    assert_eq!(candidate.writer_schema(), PKI_URLS_STATE_SCHEMA);
    publish(&mut service, candidate)?;
    let joint = service.state.as_ref().ok_or("joint state")?;
    assert_eq!(joint.schema, PKI_URLS_STATE_SCHEMA);
    assert!(joint.engines.has_sdk_lease_state());
    assert!(joint.engines.has_pki_url_state());
    joint.validate_format().map_err(|_| "joint format")?;
    for lower in [
        SDK_RESPONSE_HEADERS_STATE_SCHEMA,
        SDK_SECRET_LEASE_STATE_SCHEMA,
    ] {
        let mut lowered = joint.clone();
        lowered.schema = lower;
        assert!(lowered.validate_format().is_err());
        assert!(lowered.validate_publication_schema(Some(joint)).is_err());
    }
    let joint_backup = service.durable.as_ref().ok_or("durable")?.export_backup()?;
    assert!(
        !joint_backup
            .windows(b"registered-secret96".len())
            .any(|bytes| bytes == b"registered-secret96")
    );
    service
        .prepare_snapshot_restore(&joint_backup)
        .map_err(|_| "joint backup")?;
    assert!(service.prepare_snapshot_restore(&old_backup).is_err());
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
    let reopened = service.state.as_ref().ok_or("reopened joint")?;
    assert_eq!(reopened.schema, PKI_URLS_STATE_SCHEMA);
    assert!(reopened.engines.has_pki_url_state());
    let restored = reopened
        .engines
        .sdk_lease("", &lease.id)
        .ok_or("restored lease")?;
    assert!(restored.issuer == lease.issuer);
    assert_eq!(restored.issued, lease.issued);
    assert_eq!(restored.response_data(), lease.response_data());
    assert_eq!(
        reopened
            .engines
            .sdk_storage_get("", "sdk_probe/", &owner, "credential-record")?
            .ok_or("restored storage")?
            .value
            .as_slice(),
        b"registered-secret96"
    );
    let mut candidate = reopened.clone();
    candidate
        .engines
        .handle("", "DELETE", "sys/mounts/ca", &json!({}), 101)?;
    let later = crate::auth::Timestamp::checked(105, 777_000_000)?;
    assert!(candidate.engines.observe_sdk_lease_clock(later));
    assert!(!candidate.engines.has_pki_url_state());
    assert_eq!(candidate.writer_schema(), PKI_URLS_STATE_SCHEMA);
    publish(&mut service, candidate)?;
    // Both backups have schema 97: the clock value itself prevents rollback.
    assert!(service.prepare_snapshot_restore(&joint_backup).is_err());
    let current_backup = service.durable.as_ref().ok_or("durable")?.export_backup()?;
    service
        .prepare_snapshot_restore(&current_backup)
        .map_err(|_| "current joint backup")?;
    let retired = service.state.as_ref().ok_or("retired URL owner")?;
    let mut lowered = retired.clone();
    lowered.schema = SDK_SECRET_LEASE_STATE_SCHEMA;
    assert!(lowered.validate_publication_schema(Some(retired)).is_err());
    Ok(())
}

#[test]
fn sdk96_pending_revoke_intent_reopens_exact_owner_and_storage_before_retry() -> TestResult {
    let directory = Root::new();
    let mut service = directory.service()?;
    let (key, token) = bootstrap(&mut service)?;
    let mut candidate = service.state.clone().ok_or("state")?;
    let (mut lease, owner) = sdk96_fixture(&mut candidate, &token)?;
    let original_secret = lease.callback();
    let original_data = lease.response_data();
    let original_issuer = lease.issuer.clone();
    assert!(candidate.engines.has_live_sdk_leases());
    lease.phase = crate::engines::sdk_lease::Phase::PendingRevoke;
    candidate.engines.store_sdk_lease(lease.clone())?;
    assert!(candidate.engines.has_live_sdk_leases());
    publish(&mut service, candidate)?;
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
    let state = service.state.as_ref().ok_or("reopened state")?;
    let recovered = state
        .engines
        .sdk_cleanup_candidate(&state.auth, crate::auth::Timestamp::checked(101, 0)?, None)?
        .ok_or("pending cleanup")?;
    assert_eq!(recovered.id, lease.id);
    assert!(recovered.issuer == original_issuer);
    assert_eq!(recovered.callback(), original_secret);
    assert_eq!(recovered.response_data(), original_data);
    assert!(recovered.same_backend(&owner));
    assert!(
        state
            .engines
            .sdk_storage_get("", "sdk_probe/", &owner, "credential-record")?
            .is_some()
    );
    let mut terminal = state.clone();
    let mut retired = recovered;
    retired.revoke();
    terminal.engines.store_sdk_lease(retired)?;
    terminal
        .engines
        .sdk_storage_delete("", "sdk_probe/", &owner, "credential-record")?;
    publish(&mut service, terminal)?;
    let state = service.state.as_ref().ok_or("terminal state")?;
    assert!(
        state
            .engines
            .sdk_cleanup_candidate(&state.auth, crate::auth::Timestamp::checked(500, 0)?, None)?
            .is_none()
    );
    assert!(!state.engines.has_live_sdk_leases());
    Ok(())
}

#[test]
fn sdk96_cleanup_cursor_passes_pending_unavailable_owner_without_changing_records() -> TestResult {
    let directory = Root::new();
    let mut service = directory.service()?;
    let (_, token) = bootstrap(&mut service)?;
    let mut candidate = service.state.clone().ok_or("state")?;
    let (mut first, _) = sdk96_fixture(&mut candidate, &token)?;
    first.phase = crate::engines::sdk_lease::Phase::PendingRevoke;
    candidate.engines.store_sdk_lease(first.clone())?;
    let mut later = first.clone();
    later.id = "sdk_probe/leased/ffffffff".into();
    candidate.engines.store_sdk_lease(later.clone())?;
    publish(&mut service, candidate)?;
    let state = service.state.as_ref().ok_or("state")?;
    let identity = service.current_state_identity().map_err(|_| "identity")?;
    let at = crate::auth::Timestamp::checked(101, 0)?;
    let skipped = state
        .engines
        .sdk_cleanup_candidate(&state.auth, at, None)?
        .ok_or("first")?;
    assert_eq!(skipped.id, first.id);
    // The first owner's hidden/busy rejection must not make the set empty.
    let next = state
        .engines
        .sdk_cleanup_candidate(&state.auth, at, Some((&skipped.namespace, &skipped.id)))?
        .ok_or("later")?;
    assert_eq!(next.id, later.id);
    let wrapped = state
        .engines
        .sdk_cleanup_candidate(&state.auth, at, Some((&next.namespace, &next.id)))?
        .ok_or("wrapped")?;
    assert_eq!(wrapped.id, first.id);
    assert_eq!(
        state
            .engines
            .sdk_lease("", &first.id)
            .ok_or("first retained")?
            .callback(),
        first.callback()
    );
    assert_eq!(
        state
            .engines
            .sdk_lease("", &later.id)
            .ok_or("later retained")?
            .callback(),
        later.callback()
    );
    assert_eq!(
        service.current_state_identity().map_err(|_| "identity")?,
        identity
    );
    Ok(())
}

#[test]
fn sdk96_readonly_observation_preserves_other_mount_cleanup_and_reopens() -> TestResult {
    let directory = Root::new();
    let mut service = directory.service()?;
    let (key, token) = bootstrap(&mut service)?;
    let mut candidate = service.state.clone().ok_or("state")?;
    let (lease, owner) = sdk96_fixture(&mut candidate, &token)?;
    let other = mount(&mut candidate, "sdk_other")?;
    candidate.engines.sdk_storage_put(
        "",
        "sdk_other/",
        &other,
        entry("credential-record", b"other-live"),
    )?;
    publish(&mut service, candidate)?;
    let original = service.state.clone().ok_or("original")?;
    let mut current = original.clone();
    current
        .engines
        .sdk_storage_delete("", "sdk_other/", &other, "credential-record")?;
    current
        .engines
        .observe_sdk_lease_clock(crate::auth::Timestamp::checked(103, 17)?);
    publish(&mut service, current)?;
    let current = service.state.as_ref().ok_or("current")?;
    assert!(current.engines.sdk_storage_observations_match(
        &original.engines,
        "",
        "sdk_probe/",
        &owner
    )?);
    assert!(
        current
            .engines
            .sdk_storage_get("", "sdk_other/", &other, "credential-record")?
            .is_none()
    );
    assert_eq!(
        current
            .engines
            .sdk_lease("", &lease.id)
            .ok_or("captured lease")?
            .callback(),
        lease.callback()
    );
    assert_eq!(
        call(&mut service, "PUT", "sys/seal", &token, json!({})).status,
        204
    );
    drop(service);
    let mut reopened = directory.service()?;
    assert_eq!(
        call(&mut reopened, "PUT", "sys/unseal", "", json!({"key":key})).status,
        200
    );
    let current = reopened.state.as_ref().ok_or("reopened")?;
    assert!(current.engines.sdk_storage_observations_match(
        &original.engines,
        "",
        "sdk_probe/",
        &owner
    )?);
    assert!(
        current
            .engines
            .sdk_storage_get("", "sdk_other/", &other, "credential-record")?
            .is_none()
    );
    Ok(())
}

#[test]
fn sdk96_readonly_observation_rejects_same_mount_storage_and_retired_incarnation() -> TestResult {
    let directory = Root::new();
    let mut service = directory.service()?;
    let (_, token) = bootstrap(&mut service)?;
    let mut candidate = service.state.clone().ok_or("state")?;
    let (lease, owner) = sdk96_fixture(&mut candidate, &token)?;
    publish(&mut service, candidate)?;
    let original = service.state.clone().ok_or("original")?;
    for key in ["credential-record", "new-list-member"] {
        let mut changed = original.clone();
        changed
            .engines
            .sdk_storage_put("", "sdk_probe/", &owner, entry(key, b"changed"))?;
        publish(&mut service, changed)?;
        assert!(
            !service
                .state
                .as_ref()
                .ok_or("current")?
                .engines
                .sdk_storage_observations_match(&original.engines, "", "sdk_probe/", &owner)?
        );
    }
    let mut retired = original.clone();
    let mut lease = lease;
    lease.revoke();
    retired.engines.store_sdk_lease(lease)?;
    retired
        .engines
        .handle("", "DELETE", "sys/mounts/sdk_probe", &json!({}), 100)?;
    let replacement = mount(&mut retired, "sdk_probe")?;
    assert_ne!(owner.mount_incarnation, replacement.mount_incarnation);
    publish(&mut service, retired)?;
    assert!(
        service
            .state
            .as_ref()
            .ok_or("current")?
            .engines
            .sdk_storage_observations_match(&original.engines, "", "sdk_probe/", &owner)
            .is_err()
    );
    Ok(())
}

#[test]
fn sdk_admitted_merge_preserves_current_auth_other_mount_and_encrypted_reopen() -> TestResult {
    let directory = Root::new();
    let mut service = directory.service()?;
    let (key, root) = bootstrap(&mut service)?;
    let actor = call(
        &mut service,
        "POST",
        "auth/token/create",
        &root,
        json!({"policies":["default"]}),
    );
    assert_eq!(actor.status, 200);
    let actor = actor.body["auth"]["client_token"]
        .as_str()
        .ok_or("actor")?
        .to_owned();
    let mut original = service.state.clone().ok_or("state")?;
    let owner = mount(&mut original, "sdk_probe")?;
    let other = mount(&mut original, "sdk_other")?;
    original
        .engines
        .sdk_storage_put("", "sdk_probe/", &owner, entry("delete", b"old"))?;
    original
        .engines
        .sdk_storage_put("", "sdk_other/", &other, entry("other", b"old-other"))?;
    publish(&mut service, original)?;
    let original = service.state.clone().ok_or("original")?;
    let mut working = original.clone();
    working
        .engines
        .sdk_storage_delete("", "sdk_probe/", &owner, "delete")?;
    working.engines.sdk_storage_put(
        "",
        "sdk_probe/",
        &owner,
        entry("new", b"original-callback"),
    )?;
    assert_eq!(
        call(
            &mut service,
            "POST",
            "auth/token/revoke",
            &root,
            json!({"token":actor})
        )
        .status,
        204
    );
    assert_eq!(
        call(
            &mut service,
            "PUT",
            "sys/policies/acl/concurrent-deny",
            &root,
            json!({"policy":r#"path "sdk_probe/*" { capabilities=["deny"] }"#})
        )
        .status,
        204
    );
    let mut current = service.state.clone().ok_or("current")?;
    current
        .engines
        .sdk_storage_delete("", "sdk_other/", &other, "other")?;
    current
        .engines
        .observe_sdk_lease_clock(crate::auth::Timestamp::checked(103, 17)?);
    publish(&mut service, current)?;
    let mut current = service.state.clone().ok_or("current")?;
    let auth = crate::secret_serde::to_vec(&*current.auth, 4 * 1024 * 1024)
        .map_err(|_| "canonical owner serialization")?;
    assert!(current.engines.sdk_merge_admitted_storage(
        &original.engines,
        &working.engines,
        "",
        "sdk_probe/",
        &owner
    )?);
    assert_eq!(
        *auth,
        *crate::secret_serde::to_vec(&*current.auth, 4 * 1024 * 1024)
            .map_err(|_| "canonical owner serialization")?
    );
    assert_eq!(
        current.engines.sdk_lease_clock_floor(),
        Some(crate::auth::Timestamp::checked(103, 17)?)
    );
    assert!(
        current
            .engines
            .sdk_storage_get("", "sdk_other/", &other, "other")?
            .is_none()
    );
    publish(&mut service, current)?;
    assert_eq!(
        call(
            &mut service,
            "GET",
            "auth/token/lookup-self",
            &actor,
            json!({})
        )
        .status,
        403
    );
    assert_eq!(
        call(&mut service, "PUT", "sys/seal", &root, json!({})).status,
        204
    );
    drop(service);
    let mut reopened = directory.service()?;
    assert_eq!(
        call(&mut reopened, "PUT", "sys/unseal", "", json!({"key":key})).status,
        200
    );
    assert_eq!(
        call(
            &mut reopened,
            "GET",
            "auth/token/lookup-self",
            &actor,
            json!({})
        )
        .status,
        403
    );
    let state = reopened.state.as_ref().ok_or("reopened")?;
    assert!(
        state
            .engines
            .sdk_storage_get("", "sdk_probe/", &owner, "delete")?
            .is_none()
    );
    assert_eq!(
        state
            .engines
            .sdk_storage_get("", "sdk_probe/", &owner, "new")?
            .ok_or("new")?
            .value
            .as_slice(),
        b"original-callback"
    );
    assert!(
        state
            .engines
            .sdk_storage_get("", "sdk_other/", &other, "other")?
            .is_none()
    );
    Ok(())
}
#[test]
fn sdk_admitted_merge_rejects_changed_value_list_member_and_retired_mount() -> TestResult {
    let directory = Root::new();
    let mut service = directory.service()?;
    let (_, root) = bootstrap(&mut service)?;
    let mut original = service.state.clone().ok_or("state")?;
    let owner = mount(&mut original, "sdk_probe")?;
    original
        .engines
        .sdk_storage_put("", "sdk_probe/", &owner, entry("existing", b"before"))?;
    publish(&mut service, original)?;
    let original = service.state.clone().ok_or("original")?;
    let mut working = original.clone();
    working
        .engines
        .sdk_storage_put("", "sdk_probe/", &owner, entry("callback", b"candidate"))?;
    for key in ["existing", "new-member"] {
        let mut current = original.clone();
        current
            .engines
            .sdk_storage_put("", "sdk_probe/", &owner, entry(key, b"other-writer"))?;
        let before = crate::secret_serde::to_vec(&*current.engines, 4 * 1024 * 1024)
            .map_err(|_| "canonical owner serialization")?;
        assert!(
            current
                .engines
                .sdk_merge_admitted_storage(
                    &original.engines,
                    &working.engines,
                    "",
                    "sdk_probe/",
                    &owner
                )
                .is_err()
        );
        assert_eq!(
            *before,
            *crate::secret_serde::to_vec(&*current.engines, 4 * 1024 * 1024)
                .map_err(|_| "canonical owner serialization")?
        );
    }
    let mut retired = original.clone();
    retired
        .engines
        .handle("", "DELETE", "sys/mounts/sdk_probe", &json!({}), 100)?;
    let replacement = mount(&mut retired, "sdk_probe")?;
    assert_ne!(owner.mount_incarnation, replacement.mount_incarnation);
    assert!(
        retired
            .engines
            .sdk_merge_admitted_storage(
                &original.engines,
                &working.engines,
                "",
                "sdk_probe/",
                &owner
            )
            .is_err()
    );
    assert_eq!(
        call(
            &mut service,
            "GET",
            "auth/token/lookup-self",
            &root,
            json!({})
        )
        .status,
        200
    );
    Ok(())
}

fn sdk101_entry(
    auth: &mut crate::auth::AuthState,
    raw: &str,
    at: crate::auth::Timestamp,
) -> Result<crate::auth::AcceptedSdkLeaseIssuer, Box<dyn std::error::Error>> {
    let actor = auth.authenticate_from_observed(raw, AuthorityTime::Precise(at), None)?;
    Ok(auth
        .admitted_standard_sdk_lease_issuer_observed(&actor, "", AuthorityTime::Precise(at))?
        .ok_or("service entrance issuer")?)
}
fn sdk101_register(
    candidate: &mut State,
    lease: &mut crate::engines::sdk_lease::Lease,
    accepted: &crate::auth::AcceptedSdkLeaseIssuer,
    at: crate::auth::Timestamp,
    final_use: bool,
) -> TestResult {
    let registration = crate::engines::sdk_registration::Registration::from_entry(
        accepted,
        at,
        lease.issued,
        final_use,
        &candidate.auth,
        "",
        candidate.namespaces.incarnation(""),
    )?;
    lease.register(registration)?;
    candidate.engines.store_sdk_lease(lease.clone())?;
    Ok(())
}
#[test]
fn sdk101_registration_encrypted_reopen_sticky_floor_and_backup_rollback_rejected() -> TestResult {
    let directory = Root::new();
    let mut service = directory.service()?;
    let (key, token) = bootstrap(&mut service)?;
    let mut candidate = service.state.clone().ok_or("state")?;
    let (mut lease, owner) = sdk96_fixture(&mut candidate, &token)?;
    assert!(lease.registration.is_none());
    assert!(serde_json::to_value(&lease)?.get("registration").is_none());
    publish(&mut service, candidate)?;
    assert_eq!(service.state.as_ref().ok_or("state")?.schema, 96);
    let old_backup = service.durable.as_ref().ok_or("durable")?.export_backup()?;
    let mut candidate = service.state.clone().ok_or("state")?;
    let legacy = candidate.clone();
    let at = crate::auth::Timestamp::checked(100, 0)?;
    let accepted = sdk101_entry(&mut candidate.auth, &token, at)?;
    let mut retroactive = candidate.clone();
    sdk101_register(&mut retroactive, &mut lease, &accepted, at, false)?;
    assert!(
        retroactive
            .validate_publication_schema(Some(&legacy))
            .is_err()
    );
    // Only a genuinely new registration receives the accepted-entry model;
    // a saved96 lease cannot silently acquire a fresh entrance after issuance.
    lease.id = "sdk_probe/leased/accepted".into();
    lease.registration = None;
    sdk101_register(&mut candidate, &mut lease, &accepted, at, false)?;
    publish(&mut service, candidate)?;
    assert_eq!(service.state.as_ref().ok_or("state")?.schema, 101);
    assert!(service.prepare_snapshot_restore(&old_backup).is_err());
    let backup = service.durable.as_ref().ok_or("durable")?.export_backup()?;
    assert!(
        !backup
            .windows(b"registered-secret96".len())
            .any(|bytes| bytes == b"registered-secret96")
    );
    service
        .prepare_snapshot_restore(&backup)
        .map_err(|_| "current101 backup")?;
    let saved = serde_json::to_value(&lease.registration)?;
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
    let actual = service.state.as_ref().ok_or("reopened")?.clone();
    assert_eq!(actual.schema, 101);
    assert_eq!(
        serde_json::to_value(
            &actual
                .engines
                .sdk_lease("", &lease.id)
                .ok_or("lease")?
                .registration
        )?,
        saved
    );
    assert_eq!(
        actual
            .engines
            .sdk_storage_get("", "sdk_probe/", &owner, "credential-record")?
            .ok_or("Storage")?
            .value
            .as_slice(),
        b"registered-secret96"
    );
    let mut old_reader = actual.clone();
    old_reader.schema = 100;
    assert!(old_reader.validate_format().is_err());
    assert!(
        old_reader
            .validate_publication_schema(Some(&actual))
            .is_err()
    );
    let mut retired = actual;
    lease.revoke();
    retired.engines.store_sdk_lease(lease)?;
    publish(&mut service, retired)?;
    assert_eq!(service.state.as_ref().ok_or("retired")?.schema, 101);
    Ok(())
}
#[test]
fn sdk101_registration_successor_rejects_removal_issuer_mode_and_clock_changes() -> TestResult {
    let directory = Root::new();
    let mut service = directory.service()?;
    let (_, token) = bootstrap(&mut service)?;
    let mut candidate = service.state.clone().ok_or("state")?;
    let (mut lease, _) = sdk96_fixture(&mut candidate, &token)?;
    let at = crate::auth::Timestamp::checked(100, 0)?;
    let accepted = sdk101_entry(&mut candidate.auth, &token, at)?;
    sdk101_register(&mut candidate, &mut lease, &accepted, at, false)?;
    publish(&mut service, candidate)?;
    let original = service.state.clone().ok_or("state")?;
    let identity = service.current_state_identity().map_err(|_| "identity")?;
    for change in [
        "remove",
        "issuer",
        "mode",
        "accepted",
        "registered",
        "instance",
        "namespace",
    ] {
        let mut wire = serde_json::to_value(&lease)?;
        match change {
            "remove" => wire
                .as_object_mut()
                .ok_or("lease object")?
                .remove("registration"),
            "issuer" => {
                wire["issuer"] = json!("A".repeat(43));
                None
            }
            "mode" => {
                wire["registration"]["parent"] =
                    json!({"kind":"Ended","reason":"CurrentOwnerMissing"});
                None
            }
            "accepted" => {
                wire["registration"]["accepted"] = json!({"seconds":99,"nanoseconds":1});
                None
            }
            "registered" => {
                wire["registration"]["registered"] =
                    json!({"seconds":100,"nanoseconds":100_000_000});
                None
            }
            "instance" => {
                wire["registration"]["instance"] = json!("b".repeat(64));
                None
            }
            _ => {
                wire["registration"]["namespace_incarnation"] = json!(999);
                None
            }
        };
        let mut rejected = original.clone();
        match serde_json::from_value::<crate::engines::sdk_lease::Lease>(wire) {
            Err(_) => (),
            Ok(changed) => {
                if rejected.engines.store_sdk_lease(changed).is_ok() {
                    assert!(
                        rejected
                            .validate_publication_schema(Some(&original))
                            .is_err(),
                        "{change}"
                    );
                    assert!(service.commit_state(&mut rejected).is_err(), "{change}");
                }
            }
        }
        assert_eq!(
            service.current_state_identity().map_err(|_| "identity")?,
            identity,
            "{change}"
        );
    }
    Ok(())
}
#[test]
fn sdk101_registration_actual_parent_renewal_preserves_instance_and_future_dependency() -> TestResult
{
    let directory = Root::new();
    let mut service = directory.service()?;
    let (_, root) = bootstrap(&mut service)?;
    let mut candidate = service.state.clone().ok_or("state")?;
    let principal = candidate.auth.authenticate(&root, 100)?;
    let response = candidate
        .auth
        .handle(
            Some(&principal),
            "",
            "POST",
            "auth/token/create",
            &json!({"ttl":"5s","policies":["default"],"renewable":true}),
            100,
        )?
        .ok_or("create")?;
    let raw = response.body["auth"]["client_token"]
        .as_str()
        .ok_or("token")?
        .to_owned();
    let at = crate::auth::Timestamp::checked(100, 0)?;
    let accepted = sdk101_entry(&mut candidate.auth, &raw, at)?;
    let before = candidate
        .auth
        .sdk_service_parent_instance(&accepted.issuer.owner, "")?
        .ok_or("instance")?;
    let response = candidate
        .auth
        .handle(
            Some(&principal),
            "",
            "POST",
            "auth/token/renew",
            &json!({"token":raw,"increment":"20s"}),
            102,
        )?
        .ok_or("renew")?;
    assert_eq!(response.status, 200);
    assert_eq!(
        candidate
            .auth
            .sdk_service_parent_instance(&accepted.issuer.owner, "")?,
        Some(before)
    );
    let registered = crate::auth::Timestamp::checked(103, 0)?;
    let registration = crate::engines::sdk_registration::Registration::from_entry(
        &accepted,
        at,
        registered,
        false,
        &candidate.auth,
        "",
        None,
    )?;
    let value = serde_json::to_value(&registration)?;
    assert_eq!(value["parent"]["kind"], "Linked");
    assert_eq!(value["original_expiry"]["seconds"], 105);
    assert!(
        value["parent"]["expiry"]["seconds"]
            .as_u64()
            .ok_or("current expiry")?
            > 105
    );
    assert!(!registration.parent_cleanup_required(
        &accepted.issuer.owner,
        "",
        &candidate.auth,
        crate::auth::Timestamp::checked(107, 0)?
    )?);
    assert!(registration.parent_cleanup_required(
        &accepted.issuer.owner,
        "",
        &candidate.auth,
        crate::auth::Timestamp::checked(125, 0)?
    )?);
    let digest = accepted.issuer.owner.service_digest().ok_or("digest")?;
    let mut wire = serde_json::to_value(&candidate.auth)?;
    wire["tokens"][digest]["accessor"] = json!("replacement-token-instance");
    let replaced: crate::auth::AuthState = serde_json::from_value(wire)?;
    assert!(
        crate::engines::sdk_registration::Registration::from_entry(
            &accepted, at, registered, false, &replaced, "", None
        )
        .is_err()
    );
    assert!(registration.parent_cleanup_required(
        &accepted.issuer.owner,
        "",
        &replaced,
        registered
    )?);
    Ok(())
}
#[test]
fn sdk101_registration_ended_parent_retains_own_lifetime_and_last_use_is_pending() -> TestResult {
    use crate::engines::sdk_lease::Phase;
    let directory = Root::new();
    let mut service = directory.service()?;
    let (_, root) = bootstrap(&mut service)?;
    let mut candidate = service.state.clone().ok_or("state")?;
    let (mut lease, _) = sdk96_fixture(&mut candidate, &root)?;
    let principal = candidate.auth.authenticate(&root, 100)?;
    let response = candidate
        .auth
        .handle(
            Some(&principal),
            "",
            "POST",
            "auth/token/create",
            &json!({"ttl":"1s","policies":["default"]}),
            100,
        )?
        .ok_or("create")?;
    let raw = response.body["auth"]["client_token"]
        .as_str()
        .ok_or("token")?
        .to_owned();
    let at = crate::auth::Timestamp::checked(100, 0)?;
    let accepted = sdk101_entry(&mut candidate.auth, &raw, at)?;
    lease.issuer = accepted.issuer.owner.clone();
    lease.issued = crate::auth::Timestamp::checked(102, 0)?;
    lease.expires = crate::auth::Timestamp::checked(122, 0)?;
    sdk101_register(&mut candidate, &mut lease, &accepted, at, false)?;
    assert!(
        candidate
            .auth
            .resolve_lease_owner_observed(&lease.issuer, "", AuthorityTime::Precise(lease.issued))
            .is_none()
    );
    assert!(
        !lease
            .parent_cleanup_required(&candidate.auth, crate::auth::Timestamp::checked(110, 0)?)?
    );
    candidate.engines.observe_sdk_lease_clock(lease.issued);
    assert!(
        candidate
            .engines
            .sdk_cleanup_candidate(
                &candidate.auth,
                crate::auth::Timestamp::checked(110, 0)?,
                None
            )?
            .is_none()
    );
    assert_eq!(
        candidate
            .engines
            .sdk_cleanup_candidate(&candidate.auth, lease.expires, None)?
            .ok_or("own expiry")?
            .id,
        lease.id
    );
    let response = candidate
        .auth
        .handle(
            Some(&principal),
            "",
            "POST",
            "auth/token/create",
            &json!({"ttl":"20s","policies":["default"],"num_uses":1}),
            100,
        )?
        .ok_or("create last-use")?;
    let raw = response.body["auth"]["client_token"]
        .as_str()
        .ok_or("last token")?
        .to_owned();
    let actor =
        candidate
            .auth
            .authenticate_from_observed(&raw, AuthorityTime::Precise(at), None)?;
    assert!(actor.consumed_last_use());
    let accepted = candidate
        .auth
        .admitted_standard_sdk_lease_issuer_observed(&actor, "", AuthorityTime::Precise(at))?
        .ok_or("last issuer")?;
    let mut pending = lease;
    pending.id = "sdk_probe/leased/last-use".into();
    pending.registration = None;
    pending.issuer = accepted.issuer.owner.clone();
    sdk101_register(&mut candidate, &mut pending, &accepted, at, true)?;
    assert!(pending.phase == Phase::PendingRevoke);
    assert!(!pending.renewable);
    assert!(!pending.callback().is_null());
    assert_eq!(
        candidate
            .engines
            .sdk_cleanup_candidate(&candidate.auth, pending.issued, None)?
            .ok_or("pending callback")?
            .id,
        pending.id
    );
    Ok(())
}
