//! Real public snapshot transfer, ordinary restore and encrypted cold loading.
//! No restore plan, principal, archive metadata or batch claim is fabricated.
use super::*;
use crate::auth::Timestamp;
use crate::service::snapshot_transfer::NativeSnapshotAdmission;
use crate::v6_read_validation::{ReadContext, ReadError, ReadIdentity};
use std::io::{self, Cursor, Read};
use std::time::{SystemTime, UNIX_EPOCH};

fn archive_fixture() -> TestResult<Fixture> {
    let mut f = Fixture::initialized()?;
    // Public snapshot admission owns an actual wall-clock anchor. Start the
    // existing fixture's PKI installation in that epoch, before any CA or
    // finite actor is created; do not replace a clock on an admitted request.
    f.now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    status(
        &f.admin("POST", native_storage::ACTIVATE_PATH, json!({}))?,
        204,
    );
    f.assert_native()?;
    status(
        &f.admin(
            "POST",
            "sys/mounts/pki-kv",
            json!({"type":"kv","options":{"version":"2"}}),
        )?,
        204,
    );
    status(
        &f.admin(
            "POST",
            "pki-kv/data/sentinel",
            json!({"options":{"cas":0},"data":{"value":"pki-keeps-native-kv"}}),
        )?,
        200,
    );
    f.install()?;
    Ok(f)
}

fn pending_archive(
    f: &mut Fixture,
    method: &str,
    deadline: Instant,
) -> TestResult<PendingExternalRequest> {
    match f.service.begin_native_snapshot_before(
        ServiceRequest::new(method, "sys/storage/raft/snapshot", "", &f.admin, json!({})),
        deadline,
    ) {
        NativeSnapshotAdmission::Execute(RequestExecution::External(pending)) => Ok(*pending),
        NativeSnapshotAdmission::Execute(RequestExecution::Complete(response)) => Err(format!(
            "actual public snapshot admission status {}",
            response.status
        )
        .into()),
        NativeSnapshotAdmission::Redirect(_) => Err("File snapshot unexpectedly redirected".into()),
    }
}

fn download_archive(f: &mut Fixture) -> TestResult<Zeroizing<Vec<u8>>> {
    let deadline = Instant::now() + Duration::from_secs(15);
    let _scope = crate::request_deadline::RequestDeadlineScope::enter(deadline);
    let mut pending = pending_archive(f, "GET", deadline)?;
    let (result, file) = pending.execute_snapshot_transfer(&mut io::empty());
    status(&f.service.finish_external_request(pending, result), 200);
    let mut file = file.ok_or("actual downloaded archive descriptor")?;
    file.rewind_checked()?;
    let mut bytes = Zeroizing::new(Vec::new());
    Read::by_ref(&mut file)
        .take(crate::snapshot_file::MAX_NATIVE_ARCHIVE + 1)
        .read_to_end(&mut bytes)?;
    assert!(!bytes.is_empty() && bytes.len() as u64 <= crate::snapshot_file::MAX_NATIVE_ARCHIVE);
    assert!(
        bytes.starts_with(&[0x1f, 0x8b]),
        "actual compressed native archive"
    );
    f.now = f
        .now
        .max(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs());
    Ok(bytes)
}

fn restore_archive(f: &mut Fixture, bytes: &[u8]) -> TestResult {
    let deadline = Instant::now() + Duration::from_secs(15);
    let _scope = crate::request_deadline::RequestDeadlineScope::enter(deadline);
    let mut pending = pending_archive(f, "POST", deadline)?;
    let (result, file) = pending.execute_snapshot_transfer(&mut Cursor::new(bytes));
    assert!(file.is_none());
    status(&f.service.finish_external_request(pending, result), 200);
    assert!(
        fs::read_dir(f.service.data_dir.join(".snapshot-transfer"))?
            .next()
            .is_none()
    );
    f.now = f
        .now
        .max(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs());
    f.assert_native()
}

fn assert_current_archive_floor(f: &Fixture) -> TestResult {
    let state = f.service.state.as_ref().ok_or("actual restored state")?;
    assert_eq!(state.schema, AUTH_SECURITY_CONTRACT_STATE_SCHEMA);
    assert_eq!(state.writer_schema(), AUTH_SECURITY_CONTRACT_STATE_SCHEMA);
    state
        .validate_format()
        .map_err(|_| "actual restored reader admission")?;
    let root = f.root()?;
    assert_eq!(root.state_schema, AUTH_SECURITY_CONTRACT_STATE_SCHEMA);
    assert_eq!(
        root.reader_floor.minimum_state_schema,
        AUTH_SECURITY_CONTRACT_STATE_SCHEMA
    );
    let context = ReadContext {
        expected_identity: ReadIdentity::RecordsV6(
            root.identity()
                .map_err(|_| "actual root identity")?
                .digest(),
        ),
        cluster_id: &root.cluster_id,
        replay_epoch: root.replay_epoch,
        minimum_state_schema: CURRENT_STATE_SCHEMA,
        maximum_state_schema: MAX_SUPPORTED_STATE_SCHEMA,
        reader_format: crate::state_record_root_v6::READER_FORMAT,
    };
    crate::service::v6_records::validate_frontier(&root, context)?;
    // This is an explicitly configured 135 reader capability, not execution
    // of an old binary. The actual archive and cold load use the current reader.
    assert!(matches!(
        crate::service::v6_records::validate_frontier(
            &root,
            ReadContext {
                maximum_state_schema: APPROLE_NO_DEFAULT_STATE_SCHEMA,
                ..context
            }
        ),
        Err(ReadError::ReaderFloor),
    ));
    Ok(())
}

fn assert_original_leaf_and_lease(
    f: &mut Fixture,
    serial: &str,
    lease: &str,
    leaf: &X509,
    deadline: Timestamp,
) -> TestResult {
    let certificate = f.actor("", "GET", &format!("pki/cert/{serial}"), json!({}))?;
    status(&certificate, 200);
    assert_eq!(certificate.body["data"]["revocation_time"], 0);
    let restored = X509::from_pem(text(&certificate, "/data/certificate")?.as_bytes())?;
    assert_eq!(
        restored.to_der()?,
        leaf.to_der()?,
        "same actually signed DER after archive restore"
    );
    let lookup = f.admin("POST", "sys/leases/lookup", json!({"lease_id":lease}))?;
    status(&lookup, 200);
    assert_eq!(lookup.body["data"]["expire_time"], deadline.rfc3339());
    assert_eq!(lookup.body["data"]["renewable"], false);
    let ttl = lookup.body["data"]["ttl"]
        .as_u64()
        .ok_or("actual restored lease TTL")?;
    assert!(ttl > 0 && ttl <= deadline.ceil_seconds()?.saturating_sub(f.now));
    // Dropping lease_expires would expose the later DER deadline here. This
    // public observation therefore checks the restored field's real behavior.
    let actor_end = openssl::asn1::Asn1Time::from_unix(i64::try_from(deadline.ceil_seconds()?)?)?;
    assert_eq!(
        restored.not_after().compare(&actor_end)?,
        std::cmp::Ordering::Greater
    );
    assert_current_archive_floor(f)
}

#[test]
fn native_pki_schema136_actual_archive_restore_and_cold_reopen_preserve_batch_lease() -> TestResult
{
    let mut f = archive_fixture()?;
    f.policy("pki-archive", ISSUE_POLICY)?;
    status(
        &f.admin("POST", "sys/auth/up", json!({"type":"userpass"}))?,
        204,
    );
    status(
        &f.admin(
            "POST",
            "auth/up/users/batch",
            json!({
                "password":"synthetic-pki-archive-batch","policies":["pki-archive"],
                "token_type":"batch","token_ttl":120,"token_max_ttl":600,"token_num_uses":0
            }),
        )?,
        204,
    );
    let mut login = f.actor(
        "",
        "POST",
        "auth/up/login/batch",
        json!({"password":"synthetic-pki-archive-batch"}),
    )?;
    status(&login, 200);
    assert_eq!(login.body["auth"]["token_type"], "batch");
    let actor = secret(&mut login, "/auth/client_token")?;
    let mut issued = f.issue(&actor)?;
    let (leaf, issuer) = verify_leaf(&issued)?;
    let serial = text(&issued, "/data/serial_number")?;
    let lease = text(&issued, "/lease_id")?;
    erase_json(&mut issued.body);
    let owner = f
        .service
        .state
        .as_ref()
        .ok_or("actual batch PKI state")?
        .engines
        .lease_owners()
        .into_iter()
        .find_map(|(namespace, owner)| {
            (namespace.is_empty() && owner.batch_claims().is_some()).then_some(owner)
        })
        .ok_or("actual retained batch owner")?;
    // This unpublished historical clone isolates the 136 owner from the
    // actual current-policy 141 root. The live archive and cold reader stay 141.
    let mut historical136 = f
        .service
        .state
        .clone()
        .ok_or("historical PKI owner input")?;
    historical136
        .auth
        .restore_pre141_security_owners_for_format_test();
    historical136.schema = PKI_BATCH_LEASE_STATE_SCHEMA;
    assert!(historical136.engines.has_pki_batch_lease_state());
    assert!(historical136.validate_format().is_ok());
    assert_eq!(historical136.writer_schema(), PKI_BATCH_LEASE_STATE_SCHEMA);
    let mut lower135 = historical136;
    lower135.schema = APPROLE_NO_DEFAULT_STATE_SCHEMA;
    assert!(lower135.validate_format().is_err());
    let claims = owner
        .batch_claims()
        .ok_or("actual immutable batch claims")?;
    let deadline = match claims.precision() {
        Some(precision) => precision.expires_at,
        None => Timestamp::whole(claims.expires_at())?,
    };
    assert_original_leaf_and_lease(&mut f, &serial, &lease, &leaf, deadline)?;
    let archived_root = f.root()?;
    let archive = download_archive(&mut f)?;

    // Change both actual domains through public Service requests. A no-op
    // upload or a restore that accidentally preserves current Engine metadata
    // cannot satisfy the following observations.
    let mut changed_role = role();
    changed_role["max_ttl"] = json!("1h");
    status(&f.admin("POST", "pki/roles/web", changed_role)?, 200);
    let changed_role = f.admin("GET", "pki/roles/web", json!({}))?;
    status(&changed_role, 200);
    assert_eq!(changed_role.body["data"]["max_ttl"], 3600);
    status(
        &f.admin(
            "POST",
            "pki-kv/data/sentinel",
            json!({"options":{"cas":1},"data":{"value":"after-archive"}}),
        )?,
        200,
    );
    let changed_kv = f.admin("GET", "pki-kv/data/sentinel", json!({}))?;
    status(&changed_kv, 200);
    assert_eq!(changed_kv.body["data"]["metadata"]["version"], 2);
    let before_restore = f.root()?;
    restore_archive(&mut f, &archive)?;
    let restored_root = f.root()?;
    assert_eq!(restored_root.cluster_id, archived_root.cluster_id);
    assert!(restored_root.replay_epoch > before_restore.replay_epoch);
    assert!(restored_root.replay_epoch > archived_root.replay_epoch);
    f.sentinel()?;
    let restored_role = f.admin("GET", "pki/roles/web", json!({}))?;
    status(&restored_role, 200);
    assert_eq!(restored_role.body["data"]["max_ttl"], 7200);
    assert_original_leaf_and_lease(&mut f, &serial, &lease, &leaf, deadline)?;
    let mut f = f.restart()?;
    f.sentinel()?;
    assert_original_leaf_and_lease(&mut f, &serial, &lease, &leaf, deadline)?;
    status(
        &f.actor(&actor, "GET", "auth/token/lookup-self", json!({}))?,
        200,
    );
    assert!(
        f.service
            .state
            .as_ref()
            .ok_or("cold actual owner")?
            .engines
            .lease_owners()
            .contains(&(String::new(), owner))
    );

    // Observe one nanosecond after this real captured deadline through the
    // original maintenance entry and its retained clock. Whole-second native
    // Userpass claims remain whole-second; no fractional claim is invented.
    let started = Instant::now();
    let clock = RequestClock::anchored(
        deadline.duration_since_epoch() + Duration::from_nanos(1),
        started,
    )?;
    let observed = {
        let _scope =
            crate::request_deadline::RequestDeadlineScope::enter(started + Duration::from_secs(15));
        assert!(
            f.service
                .maintain_native_transit_with_clock_for_test(deadline.seconds(), clock)?
        );
        clock.observed_at()?
    };
    assert!(observed > deadline);
    f.now = observed.ceil_seconds()?;
    let revoked = f.actor("", "GET", &format!("pki/cert/{serial}"), json!({}))?;
    status(&revoked, 200);
    let revoked_at = revoked.body["data"]["revocation_time"]
        .as_u64()
        .ok_or("actual post-restore revocation")?;
    assert!(revoked_at >= deadline.seconds() && revoked_at <= observed.seconds());
    let crl = f.actor("", "GET", "pki/cert/crl", json!({}))?;
    verify_crl(&crl, &issuer, Some(&leaf))?;
    let retained_crl = text(&crl, "/data/certificate")?;
    status(
        &f.actor(
            &actor,
            "POST",
            "pki/issue/web",
            json!({"common_name":"late.example.test","ttl":"1h"}),
        )?,
        403,
    );
    let mut f = f.restart()?;
    let cold = f.actor("", "GET", &format!("pki/cert/{serial}"), json!({}))?;
    status(&cold, 200);
    assert_eq!(cold.body["data"]["revocation_time"], revoked_at);
    let cold_crl = f.actor("", "GET", "pki/cert/crl", json!({}))?;
    verify_crl(&cold_crl, &issuer, Some(&leaf))?;
    assert_eq!(text(&cold_crl, "/data/certificate")?, retained_crl);
    assert_current_archive_floor(&f)?;
    f.sentinel()
}
