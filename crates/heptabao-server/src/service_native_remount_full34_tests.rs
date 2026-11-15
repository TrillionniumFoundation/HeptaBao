//! Real V5 prefix -> formal File -> 17 retained 2 MiB versions -> remount.
//! Every request uses the original fifteen seconds. The accepted asynchronous
//! move inherits its ACK deadline and is consumed exactly once.
use super::*;

const VERSIONS: u64 = 17;
const V5_PREFIX: u64 = 2;
const PAYLOAD_BYTES: usize = 2 * 1024 * 1024;

fn full34_value(version: u64) -> Value {
    let mut payload = String::with_capacity(PAYLOAD_BYTES);
    let fill = char::from(b'a' + version as u8).to_string();
    for block in 0..PAYLOAD_BYTES / 1024 {
        let prefix = format!("version-{version:02}/piece-{block:04}:");
        payload.push_str(&prefix);
        payload.push_str(&fill.repeat(1024 - prefix.len()));
    }
    assert_eq!(payload.len(), PAYLOAD_BYTES);
    // Distinct version/piece prefixes keep physical block deduplication from
    // hiding loss of an old version or the retained graph's actual byte size.
    json!({"ordinal":version,"payload":payload})
}

fn full34_history(service: &mut Service, mount: &str, token: &str) -> TestResult<Value> {
    let metadata = call(
        service,
        "",
        "GET",
        &format!("{mount}/metadata/history"),
        token,
        json!({}),
    );
    assert_eq!(metadata.status, 200);
    assert_eq!(metadata.body["data"]["current_version"], VERSIONS);
    assert_eq!(
        metadata.body["data"]["versions"]
            .as_object()
            .ok_or("actual version metadata absent")?
            .len(),
        VERSIONS as usize
    );
    for version in 1..=VERSIONS {
        let response = call(
            service,
            "",
            "GET",
            &format!("{mount}/data/history"),
            token,
            json!({"version":version}),
        );
        assert_eq!(response.status, 200);
        assert_eq!(response.body["data"]["data"], full34_value(version));
        let witness = call(
            service,
            "",
            "POST",
            "sys/internal/storage/kv2-version-witness",
            token,
            json!({"mount":mount,"path":"history","version":version}),
        );
        assert_eq!(witness.status, 200);
        assert_eq!(witness.body["data"]["payload_present"], true);
        let expected = crate::secret_serde::to_vec(
            &full34_value(version),
            crate::state_records::MAX_VALUE_BYTES,
        )
        .map_err(|_| "independent synthetic payload encoding failed")?;
        assert_eq!(
            witness.body["data"]["payload_canonical_sha256"],
            hex(&crypto::digest(&expected))
        );
        assert_eq!(
            witness.body["data"]["payload_canonical_bytes"],
            expected.len()
        );
    }
    let kept = call(service, "", "GET", "keep/data/sentinel", token, json!({}));
    assert_eq!(kept.status, 200);
    assert_eq!(
        kept.body["data"]["data"],
        json!({"kept":"full34-unrelated-owner"})
    );
    let root_kv1 = call(
        service,
        "",
        "GET",
        "migration-prefix/sentinel",
        token,
        json!({}),
    );
    assert_eq!(root_kv1.status, 200);
    assert_eq!(root_kv1.body["data"]["kept"], "full34-root-kv1");
    Ok(metadata.body["data"].clone())
}

type CipherFiles = BTreeMap<PathBuf, (u64, u64, [u8; 32])>;

fn full34_files(service: &Service) -> TestResult<CipherFiles> {
    // Test-only observation. Production selection still walks authenticated
    // locators and typed roots; neither remount nor GC trusts these filenames.
    cipher_observation(service)?
        .into_iter()
        .map(|(path, (inode, digest))| {
            let bytes = fs::metadata(&path)?.len();
            Ok((path, (inode, bytes, digest)))
        })
        .collect()
}

fn require_original_files(before: &CipherFiles, service: &Service) -> TestResult {
    let after = full34_files(service)?;
    assert!(
        before
            .iter()
            .all(|(path, identity)| after.get(path) == Some(identity))
    );
    Ok(())
}

fn missing_original_files(before: &CipherFiles) -> TestResult<(usize, u64)> {
    let mut count = 0;
    let mut bytes = 0_u64;
    for (path, (_, size, _)) in before {
        match fs::metadata(path) {
            Ok(_) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                count += 1;
                bytes = bytes
                    .checked_add(*size)
                    .ok_or("observed physical size overflow")?;
            }
            Err(error) => return Err(error.into()),
        }
    }
    Ok((count, bytes))
}

fn full34_sweep(service: &mut Service, token: &str, stage: &'static str) -> TestResult<(u64, u64)> {
    let mut removed = 0_u64;
    let mut bytes = 0_u64;
    // Each call is a fresh workset after a known completion. An error or an
    // unknown result aborts immediately; there is no mutation retry or resume.
    // Sixteen worksets is the same bounded observer used by the GC full34
    // fixture. It is not a relaxed request or accepted-remount deadline.
    for batch in 0..16_u64 {
        let response = call(
            service,
            "",
            "POST",
            native_storage::file_gc::PATH,
            token,
            json!({}),
        );
        assert_eq!(response.status, 200);
        let count = response.body["data"]["removed_objects"]
            .as_u64()
            .ok_or("actual retirement count absent")?;
        let reclaimed = response.body["data"]["removed_ciphertext_bytes"]
            .as_u64()
            .ok_or("actual retirement bytes absent")?;
        assert!(count <= 32);
        assert_eq!(response.body["data"]["confirmed_absent_objects"], 0);
        assert_eq!(
            response.body["data"]["historical_request_outcome_reclassified"],
            false
        );
        assert!(!service.recovery_required && !service.audit_failed);
        assert!(service.pending_native_file_gc.is_none());
        removed = removed
            .checked_add(count)
            .ok_or("retirement count overflow")?;
        bytes = bytes
            .checked_add(reclaimed)
            .ok_or("retirement size overflow")?;
        eprintln!(
            "HBREMOUNT34 stage={stage} batch={batch} removed={count} ciphertext_bytes={reclaimed}"
        );
        if count < 32 {
            return Ok((removed, bytes));
        }
    }
    Err("fresh GC worksets exceeded the explicit sixteen-operation fixture bound".into())
}

#[test]
fn native_remount_full34_formal_file_history_pins_gc_cold_and_archive_restore() -> TestResult {
    let root = Root::new();
    let mut service = root.service()?;
    service.configure_native_v6_storage(NativeStorageProfile::File)?;
    let (key, token) = initialize(&mut service)?;
    assert_eq!(
        call(
            &mut service,
            "",
            "POST",
            "sys/mounts/migration-prefix",
            &token,
            json!({"type":"kv","options":{"version":"1"}})
        )
        .status,
        204
    );
    assert_eq!(
        call(
            &mut service,
            "",
            "PUT",
            "migration-prefix/sentinel",
            &token,
            json!({"kept":"full34-root-kv1"})
        )
        .status,
        204
    );
    for mount in ["before", "keep"] {
        assert_eq!(
            call(
                &mut service,
                "",
                "POST",
                &format!("sys/mounts/{mount}"),
                &token,
                json!({"type":"kv","options":{"version":"2"}})
            )
            .status,
            204
        );
    }
    assert_eq!(
        call(
            &mut service,
            "",
            "POST",
            "before/config",
            &token,
            json!({"max_versions":32,"cas_required":true})
        )
        .status,
        204
    );
    assert_eq!(
        call(
            &mut service,
            "",
            "POST",
            "keep/data/sentinel",
            &token,
            json!({"data":{"kept":"full34-unrelated-owner"},"options":{"cas":0}})
        )
        .status,
        200
    );
    for version in 1..=V5_PREFIX {
        let response = call(
            &mut service,
            "",
            "POST",
            "before/data/history",
            &token,
            json!({"data":full34_value(version),"options":{"cas":version-1}}),
        );
        assert_eq!(response.status, 200);
        assert_eq!(response.body["data"]["version"], version);
    }
    assert!(service.record_root.is_some() && service.native_root.is_none());
    assert_eq!(
        call(
            &mut service,
            "",
            "POST",
            native_storage::ACTIVATE_PATH,
            &token,
            json!({})
        )
        .status,
        204
    );
    assert!(service.record_root.is_none());
    assert_eq!(
        service
            .native_root
            .as_ref()
            .ok_or("actual activated root absent")?
            .reader_floor
            .native_kv2_format,
        2
    );
    for version in 1..=V5_PREFIX {
        let response = call(
            &mut service,
            "",
            "GET",
            "before/data/history",
            &token,
            json!({"version":version}),
        );
        assert_eq!(response.status, 200);
        assert_eq!(response.body["data"]["data"], full34_value(version));
    }
    for version in V5_PREFIX + 1..=VERSIONS {
        let response = call(
            &mut service,
            "",
            "POST",
            "before/data/history",
            &token,
            json!({"data":full34_value(version),"options":{"cas":version-1}}),
        );
        assert_eq!(response.status, 200);
        assert_eq!(response.body["data"]["version"], version);
    }
    assert_eq!(
        call(
            &mut service,
            "",
            "POST",
            "before/metadata/history",
            &token,
            json!({"custom_metadata":{"owner":"full34-remount","history":"all-retained"}})
        )
        .status,
        204
    );
    let original = full34_history(&mut service, "before", &token)?;
    full34_sweep(&mut service, &token, "before-move-all-retained")?;
    assert_eq!(full34_history(&mut service, "before", &token)?, original);
    let graphs = service
        .native_root
        .as_ref()
        .ok_or("actual pre-move root absent")?
        .kv2
        .clone();
    let old = graphs
        .iter()
        .find(|graph| graph.scope.namespace.is_empty() && graph.scope.mount == "before/")
        .ok_or("actual old graph absent")?;
    let keep = graphs
        .iter()
        .find(|graph| graph.scope.namespace.is_empty() && graph.scope.mount == "keep/")
        .ok_or("actual unrelated graph absent")?;
    assert_eq!(old.graph_format, "heptabao-kv2-native-paged-v2");
    assert!(old.logical_payload_bytes >= VERSIONS * PAYLOAD_BYTES as u64);

    // The completed archive has its own verified bytes. The separate live
    // backup source below is a real original-owner lease, never a fake pin.
    let (snapshot_response, archive_file) =
        transfer(&mut service, "GET", &token, &mut io::empty())?;
    assert_eq!(snapshot_response.status, 200);
    let mut archive_file = archive_file.ok_or("actual pre-move snapshot absent")?;
    archive_file.rewind_checked()?;
    let mut archive = Zeroizing::new(Vec::new());
    archive_file.read_to_end(&mut archive)?;
    assert!(!archive.is_empty());
    drop(archive_file);
    let backup = service
        .durable
        .as_mut()
        .ok_or("actual durable owner absent")?
        .prepare_v6_backup(&mut || Ok(()))?;
    let before = full34_files(&service)?;
    assert!(!before.is_empty());
    let id = queued(
        &mut service,
        "",
        &token,
        json!({"from":"before/","to":"after/"}),
    )?;
    // The parent finishes precisely this original accepted Task once. It does
    // not mint another request clock or extend its captured ACK deadline.
    finish(&mut service, "", &token, &id)?;
    assert_eq!(full34_history(&mut service, "after", &token)?, original);
    assert_eq!(
        call(
            &mut service,
            "",
            "GET",
            "before/data/history",
            &token,
            json!({})
        )
        .status,
        404
    );
    let current = service
        .native_root
        .as_ref()
        .ok_or("actual moved root absent")?;
    let moved = current
        .kv2
        .iter()
        .find(|graph| graph.scope.namespace.is_empty() && graph.scope.mount == "after/")
        .ok_or("actual destination graph absent")?;
    assert_ne!(moved.root, old.root);
    assert!(moved.scope != old.scope);
    assert_eq!(moved.scope.namespace, old.scope.namespace);
    assert_eq!(moved.logical_payload_bytes, old.logical_payload_bytes);
    assert_eq!(moved.graph_format, old.graph_format);
    assert!(
        current
            .kv2
            .iter()
            .find(|graph| graph.scope.namespace.is_empty() && graph.scope.mount == "keep/")
            == Some(keep)
    );
    require_original_files(&before, &service)?;

    assert_eq!(
        call(
            &mut service,
            "",
            "POST",
            native_storage::file_gc::PATH,
            &token,
            json!({})
        )
        .status,
        503
    );
    assert!(
        !service.recovery_required
            && !service.audit_failed
            && service.pending_native_file_gc.is_none()
    );
    require_original_files(&before, &service)?;
    drop(backup);
    let spool_lease = service
        .snapshot_spool
        .as_ref()
        .ok_or("actual snapshot spool absent")?
        .lease()?;
    assert_eq!(
        call(
            &mut service,
            "",
            "POST",
            native_storage::file_gc::PATH,
            &token,
            json!({})
        )
        .status,
        409
    );
    assert!(
        !service.recovery_required
            && !service.audit_failed
            && service.pending_native_file_gc.is_none()
    );
    require_original_files(&before, &service)?;
    drop(spool_lease);
    let (removed, reported_bytes) =
        full34_sweep(&mut service, &token, "after-move-leases-released")?;
    let (missing, missing_bytes) = missing_original_files(&before)?;
    assert!(removed > 0 && missing > 0);
    assert!(missing_bytes >= VERSIONS * PAYLOAD_BYTES as u64);
    assert!(reported_bytes >= missing_bytes);
    assert_eq!(full34_history(&mut service, "after", &token)?, original);
    drop(service);

    let mut service = cold(&root, &key)?;
    assert_eq!(full34_history(&mut service, "after", &token)?, original);
    assert_eq!(
        call(
            &mut service,
            "",
            "GET",
            "before/data/history",
            &token,
            json!({})
        )
        .status,
        404
    );
    assert_eq!(
        call(
            &mut service,
            "",
            "GET",
            &format!("sys/remount/status/{id}"),
            &token,
            json!({})
        )
        .status,
        404
    );
    let (restored, output) = transfer(
        &mut service,
        "POST",
        &token,
        &mut io::Cursor::new(archive.as_slice()),
    )?;
    assert_eq!(restored.status, 200);
    assert!(output.is_none());
    assert_eq!(full34_history(&mut service, "before", &token)?, original);
    assert_eq!(
        call(
            &mut service,
            "",
            "GET",
            "after/data/history",
            &token,
            json!({})
        )
        .status,
        404
    );
    drop(service);
    let mut service = cold(&root, &key)?;
    assert_eq!(full34_history(&mut service, "before", &token)?, original);
    full34_sweep(&mut service, &token, "restored-original-scope")?;
    assert_eq!(full34_history(&mut service, "before", &token)?, original);
    let response = call(
        &mut service,
        "",
        "POST",
        "before/data/history",
        &token,
        json!({"data":full34_value(VERSIONS + 1),"options":{"cas":VERSIONS}}),
    );
    assert_eq!(response.status, 200);
    assert_eq!(response.body["data"]["version"], VERSIONS + 1);
    let read = call(
        &mut service,
        "",
        "GET",
        "before/data/history",
        &token,
        json!({}),
    );
    assert_eq!(read.status, 200);
    assert_eq!(read.body["data"]["data"], full34_value(VERSIONS + 1));
    eprintln!(
        "HBREMOUNT34 completed=true retained_versions=17 payload_bytes={} original_http_seconds=15 backup_hold=true spool_hold=true physical_missing={missing} physical_bytes={missing_bytes} cold_reopens=2 archive_restore_once=true next_cas=true",
        VERSIONS * PAYLOAD_BYTES as u64
    );
    Ok(())
}
