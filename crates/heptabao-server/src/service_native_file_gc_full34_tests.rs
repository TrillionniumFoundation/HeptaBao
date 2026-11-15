//! Real V5 prefix -> formal File activation -> ordinary native CAS history.
//! Every request retains the parent's original 15-second deadline. This unit
//! fixture does not substitute for the official/candidate process comparison.
use super::*;

const VERSION_COUNT: u64 = 17;
const PREFIX_COUNT: u64 = 2;
const PAYLOAD_BYTES: usize = 2 * 1024 * 1024;
const DESTROYED: [u64; 3] = [2, 8, 16];

fn full34_value(version: u64) -> Value {
    let mut payload = String::with_capacity(PAYLOAD_BYTES);
    let fill = char::from(b'a' + version as u8).to_string();
    for block in 0..PAYLOAD_BYTES / 1024 {
        let prefix = format!("version-{version:02}/piece-{block:04}:");
        payload.push_str(&prefix);
        payload.push_str(&fill.repeat(1024 - prefix.len()));
    }
    assert_eq!(payload.len(), PAYLOAD_BYTES);
    // Every 1 KiB piece has a distinct version/piece prefix. Repeated whole
    // chunks cannot hide physical retirement behind identical payload blocks.
    json!({"ordinal":version,"payload":payload})
}

fn full34_history(service: &mut Service, token: &str, destroyed: &[u64]) -> TestResult<Value> {
    let metadata = call(service, "GET", "secret/metadata/history", token, json!({}));
    assert_eq!(metadata.status, 200);
    assert_eq!(metadata.body["data"]["current_version"], VERSION_COUNT);
    assert_eq!(
        metadata.body["data"]["versions"]
            .as_object()
            .ok_or("actual version metadata absent")?
            .len(),
        VERSION_COUNT as usize
    );
    for version in 1..=VERSION_COUNT {
        let response = call(
            service,
            "GET",
            "secret/data/history",
            token,
            json!({"version":version}),
        );
        if destroyed.contains(&version) {
            assert_eq!(response.status, 404);
            assert_eq!(response.body["data"]["metadata"]["destroyed"], true);
            assert!(response.body["data"]["data"].is_null());
        } else {
            assert_eq!(response.status, 200);
            assert_eq!(response.body["data"]["data"], full34_value(version));
        }
        let witness = call(
            service,
            "POST",
            "sys/internal/storage/kv2-version-witness",
            token,
            json!({"mount":"secret","path":"history","version":version}),
        );
        assert_eq!(witness.status, 200);
        assert_eq!(
            witness.body["data"]["payload_present"],
            !destroyed.contains(&version)
        );
        if destroyed.contains(&version) {
            assert!(witness.body["data"]["payload_canonical_sha256"].is_null());
            assert_eq!(witness.body["data"]["payload_canonical_bytes"], 0);
        } else {
            let expected = crate::secret_serde::to_vec(
                &full34_value(version),
                crate::state_records::MAX_VALUE_BYTES,
            )
            .map_err(|_| "independent fixture payload encoding failed")?;
            assert_eq!(
                witness.body["data"]["payload_canonical_sha256"],
                hex(&crypto::digest(&expected))
            );
            assert_eq!(
                witness.body["data"]["payload_canonical_bytes"],
                expected.len()
            );
        }
    }
    let sentinel = call(service, "GET", "keep/data/sentinel", token, json!({}));
    assert_eq!(sentinel.status, 200);
    assert_eq!(
        sentinel.body["data"]["data"],
        json!({"kept":"large-history-unrelated-root"})
    );
    Ok(metadata.body["data"].clone())
}

fn observed_cipher_files(service: &Service) -> TestResult<BTreeMap<PathBuf, u64>> {
    selected_files(service)?
        .into_iter()
        .map(|path| {
            let metadata = fs::metadata(&path)?;
            assert!(metadata.is_file());
            Ok((path, metadata.len()))
        })
        .collect()
}

fn missing_original_files(before: &BTreeMap<PathBuf, u64>) -> TestResult<(usize, u64)> {
    let mut count = 0;
    let mut bytes = 0;
    for (path, size) in before {
        match fs::metadata(path) {
            Ok(_) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                count += 1;
                bytes += size;
            }
            Err(error) => return Err(error.into()),
        }
    }
    Ok((count, bytes))
}

// These are distinct bounded GC worksets after known completions, not retries
// of a failed/unknown mutation. Any non-200 aborts immediately. A short batch
// completes the catalog seen by that mark; a terminal clock may create later
// metadata, so an indefinite zero-garbage convergence loop is not used.
fn full34_sweep(service: &mut Service, token: &str, stage: &'static str) -> TestResult<(u64, u64)> {
    let mut removed = 0_u64;
    let mut bytes = 0_u64;
    for batch in 0..16_u64 {
        let started = Instant::now();
        let response = call(service, "POST", PATH, token, json!({}));
        let elapsed = started.elapsed();
        assert_eq!(response.status, 200);
        assert!(elapsed < Duration::from_secs(15));
        let count = response.body["data"]["removed_objects"]
            .as_u64()
            .ok_or("retirement count absent")?;
        let reclaimed = response.body["data"]["removed_ciphertext_bytes"]
            .as_u64()
            .ok_or("retirement bytes absent")?;
        assert!(count <= 32);
        assert_eq!(response.body["data"]["confirmed_absent_objects"], 0);
        assert_eq!(
            response.body["data"]["historical_request_outcome_reclassified"],
            false
        );
        assert!(!service.recovery_required);
        assert!(service.pending_native_file_gc.is_none());
        removed = removed
            .checked_add(count)
            .ok_or("retirement count overflow")?;
        bytes = bytes
            .checked_add(reclaimed)
            .ok_or("retirement size overflow")?;
        eprintln!(
            "HBGC34 stage={stage} batch={batch} removed={count} ciphertext_bytes={reclaimed} elapsed_ms={}",
            elapsed.as_millis()
        );
        if count < 32 {
            return Ok((removed, bytes));
        }
    }
    Err("fresh GC worksets exceeded the explicit sixteen-operation fixture bound".into())
}

fn cold_formal(root: &Root, key: &str) -> TestResult<Service> {
    let mut service = root.service()?;
    service.configure_native_v6_storage(NativeStorageProfile::File)?;
    assert_eq!(
        call(&mut service, "POST", "sys/unseal", "", json!({"key":key})).status,
        200
    );
    assert!(service.record_root.is_none());
    assert_eq!(
        service
            .native_root
            .as_ref()
            .ok_or("cold native root absent")?
            .reader_floor
            .native_kv2_format,
        2
    );
    assert!(!service.recovery_required);
    Ok(service)
}

#[test]
fn native_file_gc_full34_v5_prefix_native_history_destroy_cold_and_archive_restore() -> TestResult {
    let root = Root::new();
    let mut service = root.service()?;
    service.configure_native_v6_storage(NativeStorageProfile::File)?;
    let (key, token) = initialize(&mut service)?;
    for mount in ["secret", "keep"] {
        assert_eq!(
            call(
                &mut service,
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
            "POST",
            "secret/config",
            &token,
            json!({"max_versions":32,"cas_required":true})
        )
        .status,
        204
    );
    assert_eq!(
        call(
            &mut service,
            "POST",
            "keep/data/sentinel",
            &token,
            json!({"data":{"kept":"large-history-unrelated-root"},"options":{"cas":0}})
        )
        .status,
        200
    );
    for version in 1..=PREFIX_COUNT {
        let response = call(
            &mut service,
            "POST",
            "secret/data/history",
            &token,
            json!({"data":full34_value(version),"options":{"cas":version-1}}),
        );
        assert_eq!(response.status, 200);
        assert_eq!(response.body["data"]["version"], version);
    }
    assert!(service.native_root.is_none());
    assert!(service.record_root.is_some());
    assert_eq!(
        call(
            &mut service,
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
            .ok_or("activated native root absent")?
            .reader_floor
            .native_kv2_format,
        2
    );
    for version in 1..=PREFIX_COUNT {
        let response = call(
            &mut service,
            "GET",
            "secret/data/history",
            &token,
            json!({"version":version}),
        );
        assert_eq!(response.status, 200);
        assert_eq!(response.body["data"]["data"], full34_value(version));
    }
    for version in PREFIX_COUNT + 1..=VERSION_COUNT {
        let response = call(
            &mut service,
            "POST",
            "secret/data/history",
            &token,
            json!({"data":full34_value(version),"options":{"cas":version-1}}),
        );
        assert_eq!(response.status, 200);
        assert_eq!(response.body["data"]["version"], version);
    }
    let graph = service
        .native_root
        .as_ref()
        .ok_or("native root absent")?
        .kv2
        .iter()
        .find(|graph| graph.scope.namespace.is_empty() && graph.scope.mount == "secret/")
        .ok_or("actual secret graph absent")?;
    assert_eq!(graph.graph_format, "heptabao-kv2-native-paged-v2");
    assert!(graph.logical_payload_bytes >= VERSION_COUNT * PAYLOAD_BYTES as u64);
    let original = full34_history(&mut service, &token, &[])?;
    full34_sweep(&mut service, &token, "all-17-retained")?;
    assert_eq!(full34_history(&mut service, &token, &[])?, original);
    let archive = download(&mut service, &token)?;
    assert!(!archive.is_empty());
    let before_destroy = observed_cipher_files(&service)?;
    assert_eq!(
        call(
            &mut service,
            "POST",
            "secret/destroy/history",
            &token,
            json!({"versions":DESTROYED})
        )
        .status,
        204
    );
    let destroyed = full34_history(&mut service, &token, &DESTROYED)?;
    let (removed, reported_bytes) = full34_sweep(&mut service, &token, "three-destroyed")?;
    assert!(removed > 0);
    let (missing, missing_bytes) = missing_original_files(&before_destroy)?;
    assert!(missing > 0);
    assert!(missing_bytes >= DESTROYED.len() as u64 * PAYLOAD_BYTES as u64);
    assert!(reported_bytes >= missing_bytes);
    let after_destroy = observed_cipher_files(&service)?;
    assert!(after_destroy.values().sum::<u64>() < before_destroy.values().sum::<u64>());
    assert_eq!(full34_history(&mut service, &token, &DESTROYED)?, destroyed);
    drop(service);

    let mut cold = cold_formal(&root, &key)?;
    assert_eq!(full34_history(&mut cold, &token, &DESTROYED)?, destroyed);
    let (response, file) = transfer(&mut cold, "POST", &token, &mut archive.as_slice())?;
    assert_eq!(response.status, 200);
    assert!(file.is_none());
    assert_eq!(full34_history(&mut cold, &token, &[])?, original);
    drop(cold);
    let mut again = cold_formal(&root, &key)?;
    assert_eq!(full34_history(&mut again, &token, &[])?, original);
    full34_sweep(&mut again, &token, "restored-17-retained")?;
    assert_eq!(full34_history(&mut again, &token, &[])?, original);
    eprintln!(
        "HBGC34 completed=true versions=17 payload_bytes={} destroyed=3 physical_missing={missing} physical_bytes={missing_bytes} cold_reopens=2 original_http_seconds=15",
        VERSION_COUNT * PAYLOAD_BYTES as u64
    );
    Ok(())
}
