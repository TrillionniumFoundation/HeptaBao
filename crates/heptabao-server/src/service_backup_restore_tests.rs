use super::super::tests::{Root, bootstrap, call};
use super::*;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

fn actor(service: &mut Service, token: &str) -> TestResult<Principal> {
    service
        .state
        .as_mut()
        .ok_or("state")?
        .auth
        .authenticate_from(token, 100, None)
        .map_err(|_| "actor".into())
}
fn request<'a>(token: &'a str, body: &'a Value) -> RequestView<'a> {
    RequestView {
        method: "POST",
        path: "sys/storage/raft/snapshot-force",
        namespace: "",
        token,
        body,
        now: 100,
        admission_started: std::time::Instant::now(),
        allow_forward: false,
        enforce_namespace: true,
        wrap_ttl_seconds: None,
        origin_peer: None,
        client_certificates: None,
    }
}
fn archive(service: &Service) -> TestResult<Zeroizing<Vec<u8>>> {
    Ok(Zeroizing::new(
        service.durable.as_ref().ok_or("durable")?.export_backup()?,
    ))
}
fn state_record(service: &Service) -> TestResult<Secret> {
    Ok(service
        .durable
        .as_ref()
        .ok_or("durable")?
        .get("system", "state")?
        .ok_or("state record")?)
}
fn write(service: &mut Service, token: &str, value: &str) {
    assert_eq!(
        call(
            service,
            "PUT",
            "secret/data/prepared",
            token,
            json!({"data":{"value":value}})
        )
        .status,
        200
    );
}

#[test]
fn prepared_v5_candidate_installs_and_reopens_with_exact_snapshot_root() -> TestResult {
    let root = Root::new();
    let mut service = root.service()?;
    let (key, token) = bootstrap(&mut service)?;
    write(&mut service, &token, "before");
    assert!(service.record_root.is_some());
    let backup = archive(&service)?;
    let snapshot_root = state_record(&service)?;
    write(&mut service, &token, "after");
    let principal = actor(&mut service, &token)?;
    let prepared = service
        .prepare_snapshot_restore(&backup)
        .map_err(|_| "prepare")?;
    assert_eq!(
        prepared
            .durable
            .get("system", "state")?
            .ok_or("prepared root")?,
        snapshot_root.expose()
    );
    let body = json!({});
    let response = service.commit_snapshot_restore(prepared, &principal, &request(&token, &body));
    assert_eq!(response.status, 200);
    assert_eq!(state_record(&service)?, snapshot_root);
    assert_eq!(
        call(
            &mut service,
            "GET",
            "secret/data/prepared",
            &token,
            json!({})
        )
        .body["data"]["data"]["value"],
        "before"
    );
    assert_eq!(
        call(&mut service, "PUT", "sys/seal", &token, json!({})).status,
        204
    );
    drop(service);
    let mut service = root.service()?;
    assert_eq!(
        call(&mut service, "PUT", "sys/unseal", "", json!({"key":key})).status,
        200
    );
    assert_eq!(state_record(&service)?, snapshot_root);
    assert_eq!(
        call(
            &mut service,
            "GET",
            "secret/data/prepared",
            &token,
            json!({})
        )
        .body["data"]["data"]["value"],
        "before"
    );
    Ok(())
}

#[test]
fn activation_or_durable_frontier_change_rejects_prepared_restore_without_publication() -> TestResult
{
    let root = Root::new();
    let mut service = root.service()?;
    let (_, token) = bootstrap(&mut service)?;
    write(&mut service, &token, "before");
    let backup = archive(&service)?;
    write(&mut service, &token, "after");
    let principal = actor(&mut service, &token)?;
    let prepared = service
        .prepare_snapshot_restore(&backup)
        .map_err(|_| "prepare")?;
    service.rotate_unseal_nonce()?;
    let activation = service.unseal_nonce.clone();
    let before = state_record(&service)?;
    let generation = service.durable.as_ref().ok_or("durable")?.generation();
    let body = json!({});
    assert_eq!(
        service
            .commit_snapshot_restore(prepared, &principal, &request(&token, &body))
            .status,
        503
    );
    assert_eq!(state_record(&service)?, before);
    assert_eq!(
        service.durable.as_ref().ok_or("durable")?.generation(),
        generation
    );
    assert_eq!(service.unseal_nonce, activation);
    assert!(!service.recovery_required);
    let prepared = service
        .prepare_snapshot_restore(&backup)
        .map_err(|_| "prepare")?;
    // Change durable authority without changing Service's application digest.
    service
        .durable
        .as_mut()
        .ok_or("durable")?
        .put(PutRequest::new(
            "test",
            "system",
            "prepared-intervening",
            "test-marker",
            [1; 32],
            Secret::new(b"marker".to_vec())?,
        )?)?;
    let generation = service.durable.as_ref().ok_or("durable")?.generation();
    assert_eq!(
        service
            .commit_snapshot_restore(prepared, &principal, &request(&token, &body))
            .status,
        409
    );
    assert_eq!(state_record(&service)?, before);
    assert_eq!(
        service.durable.as_ref().ok_or("durable")?.generation(),
        generation
    );
    assert_eq!(service.unseal_nonce, activation);
    assert!(!service.recovery_required);
    Ok(())
}

fn authenticated_invalid_archive(
    service: &Service,
    state_bytes: &[u8],
) -> TestResult<Zeroizing<Vec<u8>>> {
    let root = Root::new();
    private_directory(&root.path)?;
    let key = **service.barrier_key.as_ref().ok_or("barrier key")?;
    let barrier = AeadBarrier::new(key).map_err(|_| "barrier")?;
    let mut durable = DurableService::create_new(root.path.join("archive"), barrier, 16)?;
    durable.put(PutRequest::new(
        "test",
        "system",
        "invalid-archive",
        "state",
        [1; 32],
        Secret::new(state_bytes.to_vec())?,
    )?)?;
    Ok(Zeroizing::new(durable.export_backup()?))
}

#[test]
fn authenticated_missing_graph_and_invalid_legacy_schema_fail_before_any_restore() -> TestResult {
    let root = Root::new();
    let mut service = root.service()?;
    let (_, token) = bootstrap(&mut service)?;
    // A barrier-authenticated but semantically invalid legacy State must not
    // reach publish_checkpoint, unlike a post-commit refresh failure.
    let mut invalid = service.state.clone().ok_or("state")?;
    invalid.schema = u32::MAX;
    let bytes = owner_store::serialize_owner(&invalid).map_err(|_| "encode")?;
    let backup = authenticated_invalid_archive(&service, &bytes)?;
    let before = state_record(&service)?;
    let generation = service.durable.as_ref().ok_or("durable")?.generation();
    assert_eq!(
        call(
            &mut service,
            "POST",
            "sys/storage/raft/snapshot-force",
            &token,
            json!({"snapshot":STANDARD.encode(backup.as_slice())})
        )
        .status,
        400
    );
    assert_eq!(state_record(&service)?, before);
    assert_eq!(
        service.durable.as_ref().ok_or("durable")?.generation(),
        generation
    );
    write(&mut service, &token, "record-backed");
    let before = state_record(&service)?;
    // Valid encrypted root, but every referenced object is absent.
    let backup = authenticated_invalid_archive(&service, before.expose())?;
    let generation = service.durable.as_ref().ok_or("durable")?.generation();
    assert_eq!(
        call(
            &mut service,
            "POST",
            "sys/storage/raft/snapshot-force",
            &token,
            json!({"snapshot":STANDARD.encode(backup.as_slice())})
        )
        .status,
        400
    );
    assert_eq!(state_record(&service)?, before);
    assert_eq!(
        service.durable.as_ref().ok_or("durable")?.generation(),
        generation
    );
    assert!(!service.recovery_required);
    Ok(())
}

#[test]
fn snapshot_authorization_precedes_decode_and_is_rechecked_before_commit() -> TestResult {
    let root = Root::new();
    let mut service = root.service()?;
    let (_, token) = bootstrap(&mut service)?;
    let issued = call(
        &mut service,
        "POST",
        "auth/token/create",
        &token,
        json!({"policies":["default"],"ttl":300}),
    );
    assert_eq!(issued.status, 200);
    let child = issued.body["auth"]["client_token"]
        .as_str()
        .ok_or("child")?
        .to_owned();
    // Same-floor snapshot isolates permission and late recheck behavior. The
    // dedicated public-origin tests retain rejection of pre-86 snapshots.
    let backup = archive(&service)?;
    assert_eq!(
        call(
            &mut service,
            "POST",
            "sys/storage/raft/snapshot-force",
            &child,
            json!({"snapshot":"invalid"})
        )
        .status,
        403
    );
    let principal = actor(&mut service, &child)?;
    let prepared = service
        .prepare_snapshot_restore(&backup)
        .map_err(|_| "prepare")?;
    let generation = service.durable.as_ref().ok_or("durable")?.generation();
    let before = state_record(&service)?;
    let body = json!({});
    assert_eq!(
        service
            .commit_snapshot_restore(prepared, &principal, &request(&child, &body))
            .status,
        403
    );
    assert_eq!(state_record(&service)?, before);
    assert_eq!(
        service.durable.as_ref().ok_or("durable")?.generation(),
        generation
    );
    Ok(())
}

#[test]
fn owner_format_backup_restore_preserves_legacy_format_without_forcing_record_migration()
-> TestResult {
    let root = Root::new();
    let mut service = root.service()?;
    let (_, token) = super::super::tests::bootstrap_unmounted(&mut service)?;
    assert!(service.record_root.is_none());
    let backup = archive(&service)?;
    let before = state_record(&service)?;
    let principal = actor(&mut service, &token)?;
    let prepared = service
        .prepare_snapshot_restore(&backup)
        .map_err(|_| "prepare")?;
    assert!(prepared.root.is_none());
    let body = json!({});
    assert_eq!(
        service
            .commit_snapshot_restore(prepared, &principal, &request(&token, &body))
            .status,
        200
    );
    assert!(service.record_root.is_none());
    assert_eq!(state_record(&service)?, before);
    assert_eq!(
        call(
            &mut service,
            "GET",
            "auth/token/lookup-self",
            &token,
            json!({})
        )
        .status,
        200
    );
    Ok(())
}

#[test]
fn capacity_guard_restore_checks_v4_and_v5_before_prepare_and_commit() -> TestResult {
    for records in [false, true] {
        let root = Root::new();
        let mut service = root.service()?;
        let (_, token) = bootstrap(&mut service)?;
        if records {
            write(&mut service, &token, "capacity-guard");
        }
        let backup = archive(&service)?;
        let before = state_record(&service)?;
        let generation = service.durable.as_ref().ok_or("durable")?.generation();
        let limit = service.opaque_owner_capacity;
        service.opaque_owner_capacity = 1;
        let error = service
            .prepare_snapshot_restore(&backup)
            .err()
            .ok_or("over-capacity restore preparation was accepted")?;
        assert_eq!(error.status, 507);
        assert_eq!(state_record(&service)?, before);
        assert_eq!(
            service.durable.as_ref().ok_or("durable")?.generation(),
            generation
        );
        service.opaque_owner_capacity = limit;
        let prepared = service
            .prepare_snapshot_restore(&backup)
            .map_err(|_| "prepare")?;
        let principal = actor(&mut service, &token)?;
        // Test the final publication choke point independently of preparation.
        service.opaque_owner_capacity = 1;
        let body = json!({});
        let response =
            service.commit_snapshot_restore(prepared, &principal, &request(&token, &body));
        assert_eq!(response.status, 507);
        assert!(!service.recovery_required);
        assert_eq!(state_record(&service)?, before);
        assert_eq!(
            service.durable.as_ref().ok_or("durable")?.generation(),
            generation
        );
        service.opaque_owner_capacity = limit;
        let prepared = service
            .prepare_snapshot_restore(&backup)
            .map_err(|_| "retry prepare")?;
        assert_eq!(
            service
                .commit_snapshot_restore(prepared, &principal, &request(&token, &body))
                .status,
            200
        );
    }
    Ok(())
}

#[test]
fn aad_bound_convergent_backups_preserve_versions_floor_and_invocation_counters() -> TestResult {
    let root = Root::new();
    let mut service = root.service()?;
    let (_, token) = bootstrap(&mut service)?;
    assert!(
        call(
            &mut service,
            "POST",
            "sys/mounts/safe",
            &token,
            json!({"type":"transit"})
        )
        .status
            == 204
    );
    assert!(
        call(
            &mut service,
            "POST",
            "safe/keys/key",
            &token,
            json!({"derived":true,"convergent_encryption":true})
        )
        .status
            == 200
    );
    let legacy = archive(&service)?;
    let mut legacy_stream = Zeroizing::new(Vec::new());
    let legacy_length = service
        .durable
        .as_ref()
        .ok_or("durable")?
        .export_backup_to(&mut *legacy_stream)?;
    assert!(
        call(
            &mut service,
            "POST",
            "safe/keys/key/rotate",
            &token,
            json!({"heptabao_convergent_version":1})
        )
        .status
            == 200
    );
    let input = json!({"plaintext":STANDARD.encode(b"synthetic message"),"context":STANDARD.encode(b"synthetic context"),"associated_data":STANDARD.encode(b"synthetic AAD")});
    let cipher = call(
        &mut service,
        "POST",
        "safe/encrypt/key",
        &token,
        input.clone(),
    );
    assert!(cipher.status == 200);
    let backup = archive(&service)?;
    let before = state_record(&service)?;
    for streaming in [false, true] {
        let rejected = if streaming {
            service.prepare_snapshot_restore_from_reader(
                &mut io::Cursor::new(&*legacy_stream),
                legacy_length,
            )
        } else {
            service.prepare_snapshot_restore(&legacy)
        };
        assert!(rejected.err().is_some_and(|error| error.status == 400
            && error.body["errors"][0]
                == "snapshot would downgrade AAD-bound convergent encryption"));
        assert!(state_record(&service)? == before);
    }
    let principal = actor(&mut service, &token)?;
    let prepared = service
        .prepare_snapshot_restore(&backup)
        .map_err(|_| "safe prepare")?;
    let body = json!({});
    assert!(
        service
            .commit_snapshot_restore(prepared, &principal, &request(&token, &body))
            .status
            == 200
    );
    let descriptor = call(&mut service, "GET", "safe/keys/key", &token, json!({}));
    assert!(
        descriptor.status == 200
            && descriptor.body["data"]["heptabao_convergent_versions"] == json!({"1":0,"2":1})
            && descriptor.body["data"]["heptabao_convergent_min_encryption_version"] == 2
    );
    let decrypted = call(
        &mut service,
        "POST",
        "safe/decrypt/key",
        &token,
        json!({"ciphertext":cipher.body["data"]["ciphertext"],"context":input["context"],"associated_data":input["associated_data"]}),
    );
    assert!(decrypted.status == 200 && decrypted.body["data"]["plaintext"] == input["plaintext"]);
    assert!(call(&mut service, "POST", "safe/encrypt/key", &token, input).status == 200);
    let before = state_record(&service)?;
    let rejected = service
        .prepare_snapshot_restore(&backup)
        .err()
        .ok_or("counter downgrade accepted")?;
    assert!(
        rejected.status == 400
            && rejected.body["errors"][0]
                == "snapshot would downgrade AAD-bound convergent encryption"
    );
    assert!(state_record(&service)? == before);
    Ok(())
}

#[test]
fn aad_bound_schema66_backup_cannot_restore65_after_last_safe_mount_is_deleted() -> TestResult {
    let root = Root::new();
    let mut service = root.service()?;
    let (_, token) = bootstrap(&mut service)?;
    let legacy = archive(&service)?;
    assert!(service.state.as_ref().ok_or("state")?.schema == CURRENT_STATE_SCHEMA);
    assert!(
        call(
            &mut service,
            "POST",
            "sys/mounts/safe",
            &token,
            json!({"type":"transit"})
        )
        .status
            == 204
    );
    assert!(
        call(
            &mut service,
            "POST",
            "safe/keys/key",
            &token,
            json!({"derived":true,"convergent_encryption":true,"heptabao_convergent_version":1})
        )
        .status
            == 200
    );
    assert!(call(&mut service, "DELETE", "sys/mounts/safe", &token, json!({})).status == 204);
    let state = service.state.as_ref().ok_or("state")?;
    assert!(
        !state.engines.has_aad_bound_convergent_state() && state.schema == AAD_BOUND_STATE_SCHEMA
    );
    let before = state_record(&service)?;
    assert!(
        service
            .prepare_snapshot_restore(&legacy)
            .err()
            .is_some_and(|response| response.status == 400)
    );
    assert!(state_record(&service)? == before);
    Ok(())
}
