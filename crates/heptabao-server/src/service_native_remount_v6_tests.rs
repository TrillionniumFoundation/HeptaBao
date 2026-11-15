//! Real V5 prefix, formal File storage, native root publication and cold reopen.
//! Tests retain the existing request deadlines and accepted-task once semantics.
use super::*;
use crate::configuration::NativeStorageProfile;
use crate::service::tests::Root;
use std::io::{self, Read};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;
type Fixture = (Root, Service, Zeroizing<String>, Zeroizing<String>);

fn call(
    service: &mut Service,
    namespace: &str,
    method: &str,
    path: &str,
    token: &str,
    body: Value,
) -> Response {
    let _deadline = crate::request_deadline::RequestDeadlineScope::enter(
        Instant::now() + Duration::from_secs(15),
    );
    service.handle(method, path, namespace, token, body)
}
fn call_from_observed_peer(
    service: &mut Service,
    namespace: &str,
    method: &str,
    path: &str,
    token: &str,
    body: Value,
    peer: std::net::IpAddr,
) -> Response {
    let _deadline = crate::request_deadline::RequestDeadlineScope::enter(
        Instant::now() + Duration::from_secs(15),
    );
    service.handle_request(
        ServiceRequest::new(method, path, namespace, token, body).with_origin_peer(peer),
    )
}
fn initialize(service: &mut Service) -> TestResult<(Zeroizing<String>, Zeroizing<String>)> {
    let mut response = call(
        service,
        "",
        "POST",
        "sys/init",
        "",
        json!({"secret_shares":1,"secret_threshold":1}),
    );
    assert_eq!(response.status, 200);
    let key = Zeroizing::new(
        response.body["keys"][0]
            .as_str()
            .ok_or("actual Shamir key absent")?
            .to_owned(),
    );
    let token = Zeroizing::new(
        response.body["root_token"]
            .as_str()
            .ok_or("actual root token absent")?
            .to_owned(),
    );
    erase_json(&mut response.body);
    assert_eq!(
        call(
            service,
            "",
            "POST",
            "sys/unseal",
            "",
            json!({"key":key.as_str()})
        )
        .status,
        200
    );
    assert_eq!(
        call(service, "", "POST", "sys/init/ack", &token, json!({})).status,
        204
    );
    Ok((key, token))
}
fn value(version: u64) -> Value {
    json!({"ordinal":version,"payload":format!("version-{version}-凭证").repeat(4096)})
}
fn fixture(child: bool) -> TestResult<Fixture> {
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
            json!({"kept":"root-kv1"})
        )
        .status,
        204
    );
    if child {
        assert_eq!(
            call(
                &mut service,
                "",
                "POST",
                "sys/namespaces/team",
                &token,
                json!({})
            )
            .status,
            200
        );
        // The existing V5 migration accepts real pristine child owners. Child
        // resources are created by actual native requests only after migration;
        // this fixture does not relax the nonempty-child migration boundary.
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
    }
    let namespace = if child { "team" } else { "" };
    for mount in ["before", "keep"] {
        assert_eq!(
            call(
                &mut service,
                namespace,
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
            namespace,
            "POST",
            "before/config",
            &token,
            json!({"max_versions":8,"cas_required":true})
        )
        .status,
        204
    );
    assert_eq!(
        call(
            &mut service,
            namespace,
            "POST",
            "before/data/history",
            &token,
            json!({"data":value(1),"options":{"cas":0}})
        )
        .status,
        200
    );
    assert_eq!(
        call(
            &mut service,
            namespace,
            "POST",
            "keep/data/sentinel",
            &token,
            json!({"data":{"kept":"unrelated-owner"},"options":{"cas":0}})
        )
        .status,
        200
    );
    if !child {
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
    }
    assert!(service.record_root.is_none());
    assert_eq!(
        service
            .native_root
            .as_ref()
            .ok_or("native root absent")?
            .reader_floor
            .native_kv2_format,
        2
    );
    for version in 2..=3 {
        assert_eq!(
            call(
                &mut service,
                namespace,
                "POST",
                "before/data/history",
                &token,
                json!({"data":value(version),"options":{"cas":version-1}})
            )
            .status,
            200
        );
    }
    assert_eq!(
        call(
            &mut service,
            namespace,
            "POST",
            "before/metadata/history",
            &token,
            json!({"custom_metadata":{"owner":"preserved","purpose":"mount-move"}})
        )
        .status,
        204
    );
    assert_eq!(
        call(
            &mut service,
            namespace,
            "POST",
            "before/destroy/history",
            &token,
            json!({"versions":[2]})
        )
        .status,
        204
    );
    Ok((root, service, key, token))
}
fn history(
    service: &mut Service,
    namespace: &str,
    mount: &str,
    token: &str,
    latest: u64,
) -> TestResult<Value> {
    history_from_peer(service, namespace, mount, token, latest, None)
}
fn history_from_peer(
    service: &mut Service,
    namespace: &str,
    mount: &str,
    token: &str,
    latest: u64,
    peer: Option<std::net::IpAddr>,
) -> TestResult<Value> {
    let read = |service: &mut Service,
                namespace: &str,
                method: &str,
                path: &str,
                token: &str,
                body: Value| {
        match peer {
            Some(peer) => {
                call_from_observed_peer(service, namespace, method, path, token, body, peer)
            }
            None => call(service, namespace, method, path, token, body),
        }
    };
    for version in 1..=latest {
        let response = read(
            service,
            namespace,
            "GET",
            &format!("{mount}/data/history"),
            token,
            json!({"version":version}),
        );
        if version == 2 {
            assert_eq!(response.status, 404);
            assert_eq!(response.body["data"]["metadata"]["destroyed"], true);
        } else {
            assert_eq!(response.status, 200);
            assert_eq!(response.body["data"]["data"], value(version));
        }
    }
    let metadata = read(
        service,
        namespace,
        "GET",
        &format!("{mount}/metadata/history"),
        token,
        json!({}),
    );
    assert_eq!(metadata.status, 200);
    let kept = read(
        service,
        namespace,
        "GET",
        "keep/data/sentinel",
        token,
        json!({}),
    );
    assert_eq!(kept.status, 200);
    assert_eq!(kept.body["data"]["data"], json!({"kept":"unrelated-owner"}));
    let root_kv1 = read(
        service,
        "",
        "GET",
        "migration-prefix/sentinel",
        token,
        json!({}),
    );
    assert_eq!(root_kv1.status, 200);
    assert_eq!(root_kv1.body["data"]["kept"], "root-kv1");
    Ok(metadata.body["data"].clone())
}
fn queued(service: &mut Service, namespace: &str, token: &str, body: Value) -> TestResult<String> {
    let response = call(service, namespace, "POST", "sys/remount", token, body);
    assert_eq!(response.status, 200);
    assert_eq!(response.body["warnings"], json!([QUEUED_WARNING]));
    assert_eq!(service.native_remount_jobs.len(), 1);
    Ok(response.body["data"]["migration_id"]
        .as_str()
        .ok_or("actual migration id absent")?
        .to_owned())
}
fn finish(service: &mut Service, namespace: &str, token: &str, id: &str) -> TestResult {
    assert!(service.maintain_native_remounts());
    assert!(
        !service.maintain_native_remounts(),
        "the accepted task is consumed once"
    );
    let status = call(
        service,
        namespace,
        "GET",
        &format!("sys/remount/status/{id}"),
        token,
        json!({}),
    );
    assert_eq!(status.status, 200);
    assert_eq!(status.body["data"]["migration_info"]["status"], "success");
    assert!(!service.recovery_required && !service.audit_failed);
    Ok(())
}
fn cold(root: &Root, key: &str) -> TestResult<Service> {
    let mut service = root.service()?;
    service.configure_native_v6_storage(NativeStorageProfile::File)?;
    assert_eq!(
        call(
            &mut service,
            "",
            "POST",
            "sys/unseal",
            "",
            json!({"key":key})
        )
        .status,
        200
    );
    assert!(service.record_root.is_none() && service.native_root.is_some());
    Ok(service)
}
fn transfer(
    service: &mut Service,
    method: &str,
    token: &str,
    input: &mut impl Read,
) -> TestResult<(Response, Option<crate::snapshot_file::SnapshotFile>)> {
    let request = ServiceRequest::new(method, "sys/storage/raft/snapshot", "", token, json!({}));
    match service.begin_native_snapshot_before(request, Instant::now() + Duration::from_secs(15)) {
        NativeSnapshotAdmission::Execute(RequestExecution::External(mut pending)) => {
            let (observation, file) = pending.execute_snapshot_transfer(input);
            Ok((service.finish_external_request(*pending, observation), file))
        }
        NativeSnapshotAdmission::Execute(RequestExecution::Complete(response)) => {
            Ok((response, None))
        }
        NativeSnapshotAdmission::Redirect(_) => Err("standalone snapshot redirected".into()),
        #[cfg(feature = "native-v6-ha")]
        NativeSnapshotAdmission::Forward(_) => Err("standalone snapshot forwarded".into()),
    }
}
fn cipher_observation(service: &Service) -> TestResult<BTreeMap<PathBuf, (u64, [u8; 32])>> {
    use std::os::unix::fs::MetadataExt;
    // Observation only. Production remount never enumerates filenames and
    // never renames, unlinks or overwrites an old immutable object.
    fs::read_dir(&service.data_dir)?
        .filter_map(|entry| match entry {
            Ok(entry)
                if entry
                    .file_name()
                    .to_str()
                    .is_some_and(|name| name.starts_with("nv6.") && name.ends_with(".hbo")) =>
            {
                Some(Ok(entry))
            }
            Ok(_) => None,
            Err(error) => Some(Err(error)),
        })
        .map(|entry| {
            let path = entry?.path();
            let inode = fs::metadata(&path)?.ino();
            let digest = crypto::digest(&fs::read(&path)?);
            Ok((path, (inode, digest)))
        })
        .collect()
}

#[test]
fn native_remount_formal_file_history_old_cipher_backup_and_cold_restore() -> TestResult {
    let (root, mut service, key, token) = fixture(false)?;
    let original = history(&mut service, "", "before", &token, 3)?;
    let (response, file) = transfer(&mut service, "GET", &token, &mut io::empty())?;
    assert_eq!(response.status, 200);
    let mut archive_file = file.ok_or("actual pre-move snapshot absent")?;
    let backup = service
        .durable
        .as_mut()
        .ok_or("durable owner absent")?
        .prepare_v6_backup(&mut || Ok(()))?;
    let before = cipher_observation(&service)?;
    let graphs = service.native_root.as_ref().ok_or("root")?.kv2.clone();
    let old = graphs
        .iter()
        .find(|graph| graph.scope.mount == "before/")
        .ok_or("old graph")?;
    let keep = graphs
        .iter()
        .find(|graph| graph.scope.mount == "keep/")
        .ok_or("keep graph")?;
    let id = queued(
        &mut service,
        "",
        &token,
        json!({"from":"before/","to":"after/"}),
    )?;
    finish(&mut service, "", &token, &id)?;
    assert_eq!(history(&mut service, "", "after", &token, 3)?, original);
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
        .ok_or("installed native root")?;
    assert!(
        current
            .kv2
            .iter()
            .find(|graph| graph.scope.mount == "keep/")
            == Some(keep)
    );
    assert_ne!(
        current
            .kv2
            .iter()
            .find(|graph| graph.scope.mount == "after/")
            .ok_or("moved graph")?
            .root,
        old.root
    );
    let after = cipher_observation(&service)?;
    assert!(!before.is_empty());
    assert!(
        before
            .iter()
            .all(|(path, identity)| after.get(path) == Some(identity))
    );
    assert!(after.len() > before.len());
    drop(backup);
    archive_file.rewind_checked()?;
    let mut archive = Zeroizing::new(Vec::new());
    archive_file.read_to_end(&mut archive)?;
    drop(archive_file);
    drop(service);
    let mut service = cold(&root, &key)?;
    assert_eq!(history(&mut service, "", "after", &token, 3)?, original);
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
    assert_eq!(history(&mut service, "", "before", &token, 3)?, original);
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
    assert_eq!(history(&mut service, "", "before", &token, 3)?, original);
    assert_eq!(
        call(
            &mut service,
            "",
            "POST",
            "before/data/history",
            &token,
            json!({"data":value(4),"options":{"cas":3}})
        )
        .status,
        200
    );
    Ok(())
}

#[test]
fn native_remount_formal_file_uses_latest_committed_history_after_ack() -> TestResult {
    let (_root, mut service, _key, token) = fixture(false)?;
    let id = queued(
        &mut service,
        "",
        &token,
        json!({"from":"before","to":"after"}),
    )?;
    assert_eq!(
        call(
            &mut service,
            "",
            "POST",
            "before/data/history",
            &token,
            json!({"data":value(4),"options":{"cas":3}})
        )
        .status,
        200
    );
    finish(&mut service, "", &token, &id)?;
    history(&mut service, "", "after", &token, 4)?;
    assert_eq!(
        call(
            &mut service,
            "",
            "POST",
            "after/data/history",
            &token,
            json!({"data":value(5),"options":{"cas":4}})
        )
        .status,
        200
    );
    assert_eq!(
        call(
            &mut service,
            "",
            "POST",
            "after/data/history",
            &token,
            json!({"data":value(6),"options":{"cas":4}})
        )
        .status,
        400
    );
    Ok(())
}

#[test]
fn native_remount_formal_file_plain_child_scope_and_foreign_actor() -> TestResult {
    let (root, mut service, key, token) = fixture(true)?;
    assert_eq!(
        call(
            &mut service,
            "",
            "POST",
            "sys/policies/acl/root-scoped-remounter",
            &token,
            json!({"policy":"path \"sys/remount\" { capabilities = [\"update\", \"sudo\"] }"})
        )
        .status,
        204
    );
    let mut issued = call(
        &mut service,
        "",
        "POST",
        "auth/token/create",
        &token,
        json!({"policies":["root-scoped-remounter"],"no_default_policy":true,"ttl":"60s"}),
    );
    assert_eq!(issued.status, 200);
    let foreign = Zeroizing::new(
        issued.body["auth"]["client_token"]
            .as_str()
            .ok_or("real root-scoped token absent")?
            .to_owned(),
    );
    erase_json(&mut issued.body);
    assert_eq!(
        call(
            &mut service,
            "team",
            "POST",
            "sys/remount",
            &foreign,
            json!({"from":"before","to":"foreign"})
        )
        .status,
        403
    );
    assert!(service.native_remount_jobs.is_empty());
    let original = history(&mut service, "team", "before", &token, 3)?;
    let id = queued(
        &mut service,
        "team",
        &token,
        json!({"from":"before","to":"after"}),
    )?;
    finish(&mut service, "team", &token, &id)?;
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
    assert_eq!(history(&mut service, "team", "after", &token, 3)?, original);
    drop(service);
    let mut service = cold(&root, &key)?;
    assert_eq!(history(&mut service, "team", "after", &token, 3)?, original);
    Ok(())
}

#[test]
fn native_remount_formal_file_acl_cas_collision_and_original_task_expiry() -> TestResult {
    let (_root, mut service, _key, token) = fixture(false)?;
    assert_eq!(
        call(
            &mut service,
            "",
            "POST",
            "sys/policies/acl/move-without-sudo",
            &token,
            json!({"policy":"path \"sys/remount\" { capabilities = [\"update\"] }"})
        )
        .status,
        204
    );
    let mut issued = call(
        &mut service,
        "",
        "POST",
        "auth/token/create",
        &token,
        json!({"policies":["move-without-sudo"],"no_default_policy":true,"ttl":"60s"}),
    );
    assert_eq!(issued.status, 200);
    let limited = Zeroizing::new(
        issued.body["auth"]["client_token"]
            .as_str()
            .ok_or("real limited token absent")?
            .to_owned(),
    );
    erase_json(&mut issued.body);
    assert_eq!(
        call(
            &mut service,
            "",
            "POST",
            "sys/remount",
            &limited,
            json!({"from":"before","to":"after"})
        )
        .status,
        403
    );
    assert!(service.native_remount_jobs.is_empty());
    assert_eq!(
        call(
            &mut service,
            "",
            "POST",
            "sys/remount",
            &token,
            json!({"from":"before","to":"keep"})
        )
        .status,
        400
    );
    assert_eq!(
        call(
            &mut service,
            "",
            "POST",
            "sys/remount",
            &token,
            json!({"from":"before","to":"after","cas_revision":0})
        )
        .status,
        409
    );
    assert!(service.native_remount_jobs.is_empty());
    let id = queued(
        &mut service,
        "",
        &token,
        json!({"from":"before","to":"after"}),
    )?;
    // Shorten only this real accepted task's original budget to an already
    // expired value. Never extend it or substitute a successful completion.
    service
        .native_remount_jobs
        .front_mut()
        .ok_or("original task absent")?
        .deadline = Instant::now()
        .checked_sub(Duration::from_millis(1))
        .ok_or("expired budget")?;
    assert!(service.maintain_native_remounts());
    assert!(!service.maintain_native_remounts());
    let status = call(
        &mut service,
        "",
        "GET",
        &format!("sys/remount/status/{id}"),
        &token,
        json!({}),
    );
    assert_eq!(status.body["data"]["migration_info"]["status"], "failure");
    history(&mut service, "", "before", &token, 3)?;
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
    assert_eq!(
        call(
            &mut service,
            "",
            "POST",
            "sys/policies/acl/move-with-sudo",
            &token,
            json!({"policy":"path \"sys/remount\" { capabilities = [\"update\", \"sudo\"] }"})
        )
        .status,
        204
    );
    let mut issued = call(
        &mut service,
        "",
        "POST",
        "auth/token/create",
        &token,
        json!({"policies":["move-with-sudo"],"no_default_policy":true,"ttl":"60s"}),
    );
    assert_eq!(issued.status, 200);
    let allowed = Zeroizing::new(
        issued.body["auth"]["client_token"]
            .as_str()
            .ok_or("real admitted token absent")?
            .to_owned(),
    );
    erase_json(&mut issued.body);
    let id = queued(
        &mut service,
        "",
        &allowed,
        json!({"from":"before","to":"after"}),
    )?;
    finish(&mut service, "", &token, &id)?;
    history(&mut service, "", "after", &token, 3)?;
    Ok(())
}

#[test]
fn native_remount_formal_file_quota_definitions_persist_destination_after_cold() -> TestResult {
    let (root, mut service, key, token) = fixture(false)?;
    for (name, path) in [
        ("moved-mount", "before/"),
        ("moved-exact", "before/data/history"),
        ("moved-glob", "before/data/app*"),
        ("kept", "keep/"),
    ] {
        assert_eq!(
            call(
                &mut service,
                "",
                "POST",
                &format!("sys/quotas/rate-limit/{name}"),
                &token,
                json!({"path":path,"rate":1000,"interval":"60s"})
            )
            .status,
            204
        );
    }
    let kept = call(
        &mut service,
        "",
        "GET",
        "sys/quotas/rate-limit/kept",
        &token,
        json!({}),
    )
    .body
    .clone();
    let id = queued(
        &mut service,
        "",
        &token,
        json!({"from":"before","to":"after"}),
    )?;
    finish(&mut service, "", &token, &id)?;
    // The moved rule now matches this history. Keep the production refusal
    // for a missing transport peer, then supply the actual peer of a real
    // loopback accept to the in-process Service boundary below. This does
    // not claim an external HTTP/TLS request.
    let missing_peer = call(
        &mut service,
        "",
        "GET",
        "after/data/history",
        &token,
        json!({}),
    );
    assert_eq!(missing_peer.status, 503);
    assert_eq!(
        missing_peer.body["errors"],
        json!(["rate limit quota requires an observed transport peer"])
    );
    let listener = std::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))?;
    let client =
        std::net::TcpStream::connect_timeout(&listener.local_addr()?, Duration::from_secs(15))?;
    let (accepted, observed_peer) = listener.accept()?;
    assert_eq!(observed_peer, client.local_addr()?);
    assert_eq!(accepted.peer_addr()?, observed_peer);
    for stage in 0..2 {
        for (name, path) in [
            ("moved-mount", "after/"),
            ("moved-exact", "after/data/history"),
            ("moved-glob", "after/data/app*"),
        ] {
            let response = call(
                &mut service,
                "",
                "GET",
                &format!("sys/quotas/rate-limit/{name}"),
                &token,
                json!({}),
            );
            assert_eq!(response.status, 200);
            assert_eq!(response.body["data"]["path"], path);
        }
        assert_eq!(
            call(
                &mut service,
                "",
                "GET",
                "sys/quotas/rate-limit/kept",
                &token,
                json!({})
            )
            .body,
            kept
        );
        history_from_peer(
            &mut service,
            "",
            "after",
            &token,
            3,
            Some(observed_peer.ip()),
        )?;
        if stage == 0 {
            drop(service);
            service = cold(&root, &key)?;
        }
    }
    Ok(())
}

#[path = "service_native_remount_full34_tests.rs"]
mod full34;
