//! Actual public archive download and ordinary restore; no fabricated metadata,
//! plan, lease, identity, or clock receipt. The retained snapshot already holds
//! the consumed OTP marker; consumption before the snapshot is the tested scope.
use super::*;
use crate::service::snapshot_transfer::NativeSnapshotAdmission;
use std::io::{self, Cursor, Read};
use std::time::{SystemTime, UNIX_EPOCH};

fn pending(f: &mut Fixture, method: &str, deadline: Instant) -> TestResult<PendingExternalRequest> {
    match f.service.begin_native_snapshot_before(
        ServiceRequest::new(method, "sys/storage/raft/snapshot", "", &f.admin, json!({})),
        deadline,
    ) {
        NativeSnapshotAdmission::Execute(RequestExecution::External(pending)) => Ok(*pending),
        NativeSnapshotAdmission::Execute(RequestExecution::Complete(response)) => {
            Err(format!("actual SSH archive admission status {}", response.status).into())
        }
        NativeSnapshotAdmission::Redirect(_) => Err("File snapshot unexpectedly redirected".into()),
    }
}
fn download(f: &mut Fixture) -> TestResult<Zeroizing<Vec<u8>>> {
    let until = Instant::now() + Duration::from_secs(15);
    let _scope = crate::request_deadline::RequestDeadlineScope::enter(until);
    let mut request = pending(f, "GET", until)?;
    let (result, file) = request.execute_snapshot_transfer(&mut io::empty());
    status(&f.service.finish_external_request(request, result), 200);
    let mut file = file.ok_or("actual SSH archive descriptor")?;
    file.rewind_checked()?;
    let mut bytes = Zeroizing::new(Vec::new());
    Read::by_ref(&mut file)
        .take(crate::snapshot_file::MAX_NATIVE_ARCHIVE + 1)
        .read_to_end(&mut bytes)?;
    assert!(
        bytes.starts_with(&[0x1f, 0x8b])
            && bytes.len() as u64 <= crate::snapshot_file::MAX_NATIVE_ARCHIVE
    );
    Ok(bytes)
}
fn restore(f: &mut Fixture, archive: &[u8]) -> TestResult {
    let until = Instant::now() + Duration::from_secs(15);
    let _scope = crate::request_deadline::RequestDeadlineScope::enter(until);
    let mut request = pending(f, "POST", until)?;
    let (result, file) = request.execute_snapshot_transfer(&mut Cursor::new(archive));
    assert!(file.is_none());
    status(&f.service.finish_external_request(request, result), 200);
    assert!(
        fs::read_dir(f.service.data_dir.join(".snapshot-transfer"))?
            .next()
            .is_none()
    );
    assert!(f.service.native_root.is_some() && f.service.record_root.is_none());
    assert!(f.service.pending_native_auth_delivery.is_none());
    Ok(())
}
fn batch(f: &mut Fixture) -> TestResult<Zeroizing<String>> {
    for (path, body) in [
        ("sys/auth/up", json!({"type":"userpass"})),
        (
            "sys/policies/acl/archive-ssh",
            json!({"policy":"path \"ssh/creds/test\" { capabilities=[\"update\"] }"}),
        ),
        (
            "auth/up/users/batch",
            json!({"password":"synthetic-ssh-archive-batch","policies":["archive-ssh"],
            "token_type":"batch","token_ttl":120,"token_max_ttl":600,"token_num_uses":0}),
        ),
    ] {
        status(&f.admin("POST", path, body)?, 204);
    }
    let mut response = f.actor(
        "",
        "POST",
        "auth/up/login/batch",
        json!({"password":"synthetic-ssh-archive-batch"}),
    )?;
    status(&response, 200);
    assert_eq!(response.body["auth"]["token_type"], "batch");
    secret(&mut response, "/auth/client_token")
}
fn sentinel(f: &mut Fixture, version: u64, value: &str) -> TestResult {
    let response = f.admin("GET", "kept/data/sentinel", json!({}))?;
    status(&response, 200);
    assert_eq!(response.body["data"]["metadata"]["version"], version);
    assert_eq!(response.body["data"]["data"], json!({"value":value}));
    Ok(())
}

#[test]
fn native_ssh_actual_archive_restore_preserves_otp_consumption_ca_and_observed_issuer_floor()
-> TestResult {
    let mut f = Fixture::initialized()?;
    // Select the wall-clock epoch before creating any finite actual credential.
    // Each public request still owns its original RequestClock and deadline.
    f.now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    f.activate()?;
    f.install()?;
    let ca = install_ca(&mut f)?;
    status(
        &f.admin(
            "POST",
            "sys/mounts/kept",
            json!({"type":"kv","options":{"version":"2"}}),
        )?,
        204,
    );
    status(
        &f.admin(
            "POST",
            "kept/data/sentinel",
            json!({"options":{"cas":0},"data":{"value":"before-archive"}}),
        )?,
        200,
    );
    let admin = f.admin.clone();
    let (consumed, _) = f.issue(&admin)?;
    status(
        &f.actor("", "POST", "ssh/verify", json!({"otp":consumed.as_str()}))?,
        200,
    );
    let (live, _) = f.issue(&admin)?;
    let actor = batch(&mut f)?;
    let (expires, lease) = f.issue(&actor)?;
    let lookup = f.admin("POST", "sys/leases/lookup", json!({"lease_id":lease}))?;
    status(&lookup, 200);
    let until = chrono::DateTime::parse_from_rfc3339(
        lookup.body["data"]["expire_time"]
            .as_str()
            .ok_or("real issuer expiry")?,
    )?
    .timestamp();
    let until = u64::try_from(until)?;
    let archived = f.service.native_root.clone().ok_or("actual archive root")?;
    let archive = download(&mut f)?;

    status(&f.admin("POST", "ssh/roles/test", json!({"key_type":"otp","default_user":"backup","allowed_users":"backup","cidr_list":"127.0.0.0/8"}))?, 204);
    status(
        &f.admin(
            "POST",
            "kept/data/sentinel",
            json!({"options":{"cas":1},"data":{"value":"after-archive"}}),
        )?,
        200,
    );
    sentinel(&mut f, 2, "after-archive")?;
    assert!(f.idle(until + 1)?);
    status(
        &f.actor("", "POST", "ssh/verify", json!({"otp":expires.as_str()}))?,
        400,
    );
    let before_restore = f
        .service
        .native_root
        .clone()
        .ok_or("actual before-restore root")?;
    restore(&mut f, &archive)?;
    let restored = f
        .service
        .native_root
        .as_ref()
        .ok_or("actual restored root")?;
    assert_eq!(restored.cluster_id, archived.cluster_id);
    assert!(
        restored.replay_epoch > before_restore.replay_epoch
            && restored.replay_epoch > archived.replay_epoch
    );
    f.service
        .state
        .as_ref()
        .ok_or("restored state")?
        .validate_format()
        .map_err(|_| "restored SSH format")?;
    sentinel(&mut f, 1, "before-archive")?;
    let role = f.admin("GET", "ssh/roles/test", json!({}))?;
    status(&role, 200);
    assert_eq!(role.body["data"]["default_user"], "deploy");
    status(
        &f.actor("", "POST", "ssh/verify", json!({"otp":consumed.as_str()}))?,
        400,
    );
    status(
        &f.actor("", "POST", "ssh/verify", json!({"otp":expires.as_str()}))?,
        400,
    );
    let mut f = f.restart()?;
    sentinel(&mut f, 1, "before-archive")?;
    let _ingress = crate::auth::IngressReplyScope::listener(&[0xd4; 16]);
    let public = f.actor("", "GET", "ssh/public_key", json!({}))?;
    status(&public, 200);
    let raw = public
        .unwrapped_json
        .as_ref()
        .ok_or("actual restored raw key")?;
    assert_eq!(
        raw.raw_http_transport(&public.body)?,
        Some((200, "text/plain"))
    );
    assert_eq!(
        raw.raw_bytes(&public.body)?
            .ok_or("actual restored public bytes")?,
        ca.as_bytes()
    );
    status(
        &f.actor("", "POST", "ssh/verify", json!({"otp":consumed.as_str()}))?,
        400,
    );
    status(
        &f.actor("", "POST", "ssh/verify", json!({"otp":expires.as_str()}))?,
        400,
    );
    status(
        &f.actor(&actor, "POST", "ssh/creds/test", json!({"ip":"127.0.0.1"}))?,
        403,
    );
    status(
        &f.actor("", "POST", "ssh/verify", json!({"otp":live.as_str()}))?,
        200,
    );
    let mut f = f.restart()?;
    status(
        &f.actor("", "POST", "ssh/verify", json!({"otp":live.as_str()}))?,
        400,
    );
    Ok(())
}
