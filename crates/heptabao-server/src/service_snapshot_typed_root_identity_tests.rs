//! Data equivalence never replaces the original live export/physical owners.
use super::*;
use crate::state_record_root_v6::{NativeRootContentIdentity, OwnerDomain, RecordStateRootV6};
use crate::state_records::{ObjectId, ObjectKind};
use std::fs;

fn staged(service: &mut Service, token: &str) -> TestResult<Box<PendingExternalRequest>> {
    let request = ServiceRequest::new("GET", PATH, "", token, json!({"mount":"secret"}));
    match service.begin_native_snapshot_before(request, Instant::now() + Duration::from_secs(15)) {
        NativeSnapshotAdmission::Execute(RequestExecution::External(pending)) => Ok(pending),
        _ => Err("typed root test must reach actual lossless staging".into()),
    }
}
fn plan(pending: &PendingExternalRequest) -> TestResult<&SnapshotTransferPlan> {
    match &pending.effect {
        ExternalEffectPlan::SnapshotTransfer(plan) => Ok(plan),
        _ => Err("actual snapshot plan required".into()),
    }
}

#[test]
fn typed_root_contents_reject_every_root_and_nested_reference_field_change() -> TestResult {
    let (_files, mut service, _key, token) = initialized()?;
    let pending = staged(&mut service, &token)?;
    let plan = plan(&pending)?;
    assert!(plan.native_root_contents.is_some());
    let root = service.native_root.clone().ok_or("actual native root")?;
    let identity = root.identity().map_err(|_| "actual root identity")?;
    let contents =
        NativeRootContentIdentity::capture(&root, identity).map_err(|_| "root capture")?;
    assert!(
        contents
            .matches_current(&root, identity, identity.digest())
            .is_ok_and(|same| same)
    );
    let encoded = root.encode().map_err(|_| "root encode")?;
    let decoded = RecordStateRootV6::decode(&encoded).map_err(|_| "root decode")?;
    assert!(
        contents
            .matches_current(&decoded, identity, identity.digest())
            .is_ok_and(|same| same)
    );
    assert!(
        NativeRootContentIdentity::capture(&root, StateIdentity::Legacy(identity.digest()))
            .is_err()
    );
    type Change = (&'static str, fn(&mut RecordStateRootV6));
    let changes: Vec<Change> = vec![
        ("storage_format", |r| r.storage_format.push('x')),
        ("state_schema", |r| r.state_schema += 1),
        ("floor.record_format", |r| r.reader_floor.record_format += 1),
        ("floor.minimum_schema", |r| {
            r.reader_floor.minimum_state_schema -= 1
        }),
        ("floor.native_format", |r| {
            r.reader_floor.native_kv2_format = 1
        }),
        ("global_format", |r| {
            r.global_lossless_json_format = if r.global_lossless_json_format.is_some() {
                None
            } else {
                Some(1)
            }
        }),
        ("cluster", |r| r.cluster_id.push('x')),
        ("replay_epoch", |r| r.replay_epoch += 1),
        ("owner.domain", |r| r.owners[0].domain = OwnerDomain::Auth),
        ("owner.name", |r| r.owners[0].owner.name.push('x')),
        ("owner.total", |r| r.owners[0].owner.total_bytes += 1),
        ("owner.digest", |r| r.owners[0].owner.digest[0] ^= 1),
        ("owner.chunks", |r| r.owners[0].owner.chunks.clear()),
        ("owner.chunk.id", |r| {
            r.owners[0].owner.chunks[0].id = ObjectId::from_bytes([17; 32])
        }),
        ("owner.chunk.kind", |r| {
            r.owners[0].owner.chunks[0].kind = ObjectKind::Block
        }),
        ("owner.chunk.encoded", |r| {
            r.owners[0].owner.chunks[0].encoded_bytes += 1
        }),
        ("owner.chunk.records", |r| {
            r.owners[0].owner.chunks[0].record_count += 1
        }),
        ("owner.chunk.payload", |r| {
            r.owners[0].owner.chunks[0].payload_bytes += 1
        }),
        ("kv1.height", |r| r.kv1.height += 1),
        ("kv1.reference", |r| r.kv1 = r.kv2[0].root.clone()),
        ("kv2.count", |r| r.kv2.clear()),
        ("kv2.namespace", |r| {
            r.kv2[0].scope.namespace.push_str("child")
        }),
        ("kv2.mount", |r| r.kv2[0].scope.mount.push('x')),
        ("kv2.incarnation", |r| r.kv2[0].scope.incarnation += 1),
        ("kv2.graph_format", |r| r.kv2[0].graph_format.push('x')),
        ("kv2.logical_bytes", |r| r.kv2[0].logical_payload_bytes += 1),
        ("kv2.root.height", |r| r.kv2[0].root.height += 1),
        ("kv2.root.reference", |r| r.kv2[0].root.reference = None),
        ("kv2.ref.id", |r| {
            if let Some(v) = r.kv2[0].root.reference.as_mut() {
                v.id = ObjectId::from_bytes([19; 32]);
            }
        }),
        ("kv2.ref.kind", |r| {
            if let Some(v) = r.kv2[0].root.reference.as_mut() {
                v.kind = ObjectKind::Block;
            }
        }),
        ("kv2.ref.encoded", |r| {
            if let Some(v) = r.kv2[0].root.reference.as_mut() {
                v.encoded_bytes += 1;
            }
        }),
        ("kv2.ref.records", |r| {
            if let Some(v) = r.kv2[0].root.reference.as_mut() {
                v.record_count += 1;
            }
        }),
        ("kv2.ref.payload", |r| {
            if let Some(v) = r.kv2[0].root.reference.as_mut() {
                v.payload_bytes += 1;
            }
        }),
    ];
    assert!(root.kv2[0].root.reference.is_some());
    for (label, change) in changes {
        let mut changed = root.clone();
        change(&mut changed);
        assert!(
            !contents
                .matches_current(&changed, identity, identity.digest())
                .is_ok_and(|same| same),
            "{label}"
        );
        service.native_root = Some(changed);
        assert_eq!(
            service.current_identity_matches_snapshot_plan(plan, identity),
            service.current_state_identity().ok() == Some(identity),
            "{label}"
        );
        assert!(
            !service.current_identity_matches_snapshot_plan(plan, identity),
            "{label}"
        );
    }
    for byte in 0..32 {
        let mut changed = root.clone();
        changed.object_address_key.0[byte] ^= 1;
        assert!(
            !contents
                .matches_current(&changed, identity, identity.digest())
                .is_ok_and(|same| same),
            "key byte {byte}"
        );
    }
    service.native_root = Some(root);
    assert!(service.current_identity_matches_snapshot_plan(plan, identity));
    Ok(())
}

#[test]
fn typed_root_contents_require_current_digest_native_selection_and_target_identity() -> TestResult {
    let (_files, mut service, _key, token) = initialized()?;
    let pending = staged(&mut service, &token)?;
    let plan = plan(&pending)?;
    let identity = plan.base;
    assert!(service.current_identity_matches_snapshot_plan(plan, identity));
    let digest = service.state_digest.take().ok_or("state digest")?;
    assert!(!service.current_identity_matches_snapshot_plan(plan, identity));
    let mut changed_digest = digest;
    changed_digest[0] ^= 1;
    service.state_digest = Some(changed_digest);
    assert!(!service.current_identity_matches_snapshot_plan(plan, identity));
    service.state_digest = Some(digest);
    assert!(!service.current_identity_matches_snapshot_plan(plan, StateIdentity::Legacy(digest)));
    assert!(
        !service
            .current_identity_matches_snapshot_plan(plan, StateIdentity::RecordsV6(changed_digest))
    );
    let state = service.state.take().ok_or("state")?;
    assert!(!service.current_identity_matches_snapshot_plan(plan, identity));
    service.state = Some(state);
    let root = service.native_root.take().ok_or("native root")?;
    assert!(!service.current_identity_matches_snapshot_plan(plan, identity));
    service.native_root = Some(root);
    let source = service
        .durable
        .as_ref()
        .ok_or("durable")?
        .get(
            "system",
            crate::service::native_v6_reader::ACTIVE_SOURCE_ROOT_RESOURCE,
        )
        .map_err(|_| "source root read")?
        .ok_or("source root bytes")?;
    service.record_root = Some(
        crate::state_record_root::RecordStateRoot::decode(source.expose())
            .map_err(|_| "source root decode")?,
    );
    assert!(!service.current_identity_matches_snapshot_plan(plan, identity));
    service.record_root = None;
    assert!(service.current_identity_matches_snapshot_plan(plan, identity));
    Ok(())
}

#[test]
fn typed_root_export_after_audit_root_key_epoch_and_digest_changes_withhold_file() -> TestResult {
    for change in ["key", "epoch", "digest", "floor"] {
        let (_files, mut service, _key, token) = initialized()?;
        let fired = Arc::new(AtomicBool::new(false));
        let seen = Arc::clone(&fired);
        let _hook = audit_hook(move |service| {
            seen.store(true, Ordering::SeqCst);
            if change == "digest" {
                if let Some(digest) = service.state_digest.as_mut() {
                    digest[0] ^= 1;
                }
            } else if let Some(root) = service.native_root.as_mut() {
                match change {
                    "key" => root.object_address_key.0[0] ^= 1,
                    "epoch" => root.replay_epoch += 1,
                    _ => root.reader_floor.minimum_state_schema -= 1,
                }
            }
        })?;
        let (response, file) = transfer(&mut service, &token, "", json!({"mount":"secret"}))?;
        assert!(fired.load(Ordering::SeqCst));
        assert_eq!(response.status, 503);
        assert!(file.is_none());
        assert!(service.pending_snapshot_transfer.is_none());
        assert!(service.native_request_binding.is_none());
    }
    Ok(())
}

#[test]
fn typed_root_export_consumed_rejected_scope_does_not_authorize_fresh_cold_scope() -> TestResult {
    let (files, mut service, key, token) = initialized()?;
    let fired = Arc::new(AtomicBool::new(false));
    let seen = Arc::clone(&fired);
    {
        let _hook = audit_hook(move |service| {
            seen.store(true, Ordering::SeqCst);
            service.unseal_nonce.push_str("-old-scope-lost");
        })?;
        let (response, bytes) = transfer(&mut service, &token, "", json!({"mount":"secret"}))?;
        assert!(fired.load(Ordering::SeqCst));
        assert_eq!(response.status, 503);
        assert!(bytes.is_none());
    }
    assert!(service.pending_snapshot_transfer.is_none());
    assert!(service.native_request_binding.is_none());
    drop(service);
    let mut service = files.service()?;
    service.configure_native_v6_storage(NativeStorageProfile::File)?;
    assert_eq!(
        call(
            &mut service,
            "POST",
            "sys/unseal",
            "",
            json!({"key":key.as_str()})
        )
        .status,
        200
    );
    let bytes = downloaded(&mut service, &token, "secret")?;
    let mut value = crate::engines::decode_lossless_json(&bytes)?;
    assert_eq!(value, bundle()?);
    erase_json(&mut value);
    Ok(())
}

#[test]
fn typed_root_contents_changed_checkpoint_uses_original_identity_without_reviving_old_request()
-> TestResult {
    let (_files, mut service, _key, token) = initialized()?;
    let mut pending = staged(&mut service, &token)?;
    let old_identity = plan(&pending)?.base;
    assert_eq!(
        call(
            &mut service,
            "POST",
            "secret/data/history",
            &token,
            json!({"data":{"after":"typed-root-checkpoint"},"options":{"cas":3}})
        )
        .status,
        200
    );
    let advanced = service
        .current_state_identity()
        .map_err(|_| "advanced identity")?;
    assert_ne!(advanced, old_identity);
    assert!(service.current_identity_matches_snapshot_plan(plan(&pending)?, advanced));
    assert!(!service.current_identity_matches_snapshot_plan(plan(&pending)?, old_identity));
    let (observation, file) = pending.execute_snapshot_transfer(&mut io::empty());
    let response = service.finish_external_request(*pending, observation);
    assert!(response.status >= 400);
    drop(file);
    assert!(service.pending_snapshot_transfer.is_none());
    assert!(service.native_request_binding.is_none());
    Ok(())
}

#[test]
fn typed_root_equal_data_does_not_replace_physical_seal_check_or_revive_consumed_scope()
-> TestResult {
    let (files, mut service, key, token) = initialized()?;
    let mut pending = staged(&mut service, &token)?;
    let selected = plan(&pending)?;
    assert!(service.current_identity_matches_snapshot_plan(selected, selected.base));
    let seal = service.data_dir.join("seal.json");
    let held = service.data_dir.join("typed-root-owned-seal.private");
    fs::rename(&seal, &held)?;
    assert!(service.current_identity_matches_snapshot_plan(selected, selected.base));
    assert!(service.check_v6_snapshot_owner(selected).is_err());
    let (observation, file) = pending.execute_snapshot_transfer(&mut io::empty());
    let response = service.finish_external_request(*pending, observation);
    assert!(response.status >= 400);
    drop(file);
    assert!(service.pending_snapshot_transfer.is_none());
    assert!(service.native_request_binding.is_none());
    fs::rename(&held, &seal)?;
    drop(service);
    let mut service = files.service()?;
    service.configure_native_v6_storage(NativeStorageProfile::File)?;
    assert_eq!(
        call(
            &mut service,
            "POST",
            "sys/unseal",
            "",
            json!({"key":key.as_str()})
        )
        .status,
        200
    );
    let bytes = downloaded(&mut service, &token, "secret")?;
    let mut value = crate::engines::decode_lossless_json(&bytes)?;
    assert_eq!(value, bundle()?);
    erase_json(&mut value);
    Ok(())
}
