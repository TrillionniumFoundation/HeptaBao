use super::*;

#[path = "service_native_empty_snapshot_floor_tests.rs"]
mod empty_snapshot_floor_tests;

#[path = "service_native_kv1_registry_tests.rs"]
mod kv1_registry_tests;

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn request(service: &mut Service, method: &str, path: &str, token: &str, body: Value) -> Response {
    let _deadline = crate::request_deadline::RequestDeadlineScope::enter(
        std::time::Instant::now() + Duration::from_secs(15),
    );
    service.handle(method, path, "", token, body)
}

fn initialize(
    service: &mut Service,
) -> Result<(Zeroizing<String>, Zeroizing<String>), Box<dyn std::error::Error>> {
    let mut initialized = request(
        service,
        "POST",
        "sys/init",
        "",
        json!({
            "secret_shares": 1, "secret_threshold": 1
        }),
    );
    assert_eq!(initialized.status, 200);
    let key = Zeroizing::new(
        initialized.body["keys"][0]
            .as_str()
            .ok_or("missing real Shamir share")?
            .to_owned(),
    );
    let token = Zeroizing::new(
        initialized.body["root_token"]
            .as_str()
            .ok_or("missing real root token")?
            .to_owned(),
    );
    erase_json(&mut initialized.body);
    assert_eq!(
        request(
            service,
            "POST",
            "sys/unseal",
            "",
            json!({"key":key.as_str()})
        )
        .status,
        200
    );
    assert!(!service.seal.as_ref().ok_or("seal")?.is_wrapper());
    assert_eq!(
        request(service, "POST", "sys/init/ack", &token, json!({})).status,
        204
    );
    Ok((key, token))
}

fn mount_kv2(service: &mut Service, token: &str) {
    assert_eq!(
        request(
            service,
            "POST",
            "sys/mounts/secret",
            token,
            json!({"type":"kv", "options":{"version":"2"}})
        )
        .status,
        204
    );
}

fn snapshot_transfer(
    service: &mut Service,
    method: &str,
    token: &str,
    input: &mut impl Read,
) -> Result<(Response, Option<crate::snapshot_file::SnapshotFile>), Box<dyn std::error::Error>> {
    let deadline = std::time::Instant::now() + Duration::from_secs(15);
    let request = ServiceRequest::new(method, "sys/storage/raft/snapshot", "", token, json!({}));
    match service.begin_native_snapshot_before(request, deadline) {
        NativeSnapshotAdmission::Execute(RequestExecution::External(mut pending)) => {
            let (observation, file) = pending.execute_snapshot_transfer(input);
            Ok((service.finish_external_request(*pending, observation), file))
        }
        NativeSnapshotAdmission::Execute(RequestExecution::Complete(response)) => {
            Ok((response, None))
        }
        NativeSnapshotAdmission::Redirect(_) => {
            Err("standalone storage unexpectedly redirected".into())
        }
    }
}

fn download(
    service: &mut Service,
    token: &str,
) -> Result<Zeroizing<Vec<u8>>, Box<dyn std::error::Error>> {
    let (response, file) = snapshot_transfer(service, "GET", token, &mut io::empty())?;
    assert_eq!(response.status, 200);
    let mut file = file.ok_or("missing authenticated binary snapshot")?;
    file.rewind_checked()?;
    let mut bytes = Zeroizing::new(Vec::new());
    file.read_to_end(&mut bytes)?;
    Ok(bytes)
}

#[test]
fn configured_native_file_uses_real_shamir_activation_and_cold_reopen() -> TestResult {
    let root = super::super::tests::Root::new();
    let mut service = root.service()?;
    service.configure_native_v6_storage(NativeStorageProfile::File)?;
    let (key, token) = initialize(&mut service)?;
    assert!(
        service.native_root.is_none(),
        "configuration must not silently migrate V5"
    );
    mount_kv2(&mut service, &token);
    assert_eq!(
        request(
            &mut service,
            "POST",
            "secret/data/lifecycle",
            &token,
            json!({"data":{"value":"before-native-activation"}})
        )
        .status,
        200
    );
    assert_eq!(
        request(&mut service, "POST", ACTIVATE_PATH, &token, json!({})).status,
        204
    );
    assert_eq!(
        service
            .native_root
            .as_ref()
            .ok_or("native root")?
            .reader_floor
            .native_kv2_format,
        2
    );
    assert_eq!(
        request(
            &mut service,
            "POST",
            "secret/data/lifecycle",
            &token,
            json!({"data":{"value":"after-native-activation"}, "options":{"cas":1}})
        )
        .status,
        200
    );
    assert_eq!(
        request(
            &mut service,
            "GET",
            "secret/data/lifecycle",
            &token,
            json!({})
        )
        .body["data"]["data"]["value"],
        "after-native-activation"
    );
    assert_eq!(
        service.capacity_response("GET", &json!({})).body["data"]["profile"],
        "bounded-native-record-state-v6-paged"
    );
    drop(service);

    // The same authenticated V6 bytes cannot enter an unconfigured V5 server.
    let mut unconfigured = root.service()?;
    let response = request(
        &mut unconfigured,
        "POST",
        "sys/unseal",
        "",
        json!({"key":key.as_str()}),
    );
    assert_eq!(response.status, 503);
    assert!(unconfigured.state.is_none());
    assert!(unconfigured.native_root.is_none());
    drop(unconfigured);

    let mut reopened = root.service()?;
    reopened.configure_native_v6_storage(NativeStorageProfile::File)?;
    assert_eq!(
        request(
            &mut reopened,
            "POST",
            "sys/unseal",
            "",
            json!({"key":key.as_str()})
        )
        .status,
        200
    );
    assert_eq!(
        request(
            &mut reopened,
            "GET",
            "secret/data/lifecycle",
            &token,
            json!({})
        )
        .body["data"]["data"]["value"],
        "after-native-activation"
    );
    let historical = request(
        &mut reopened,
        "GET",
        "secret/data/lifecycle",
        &token,
        json!({"version":1}),
    );
    assert_eq!(historical.status, 200);
    assert_eq!(
        historical.body["data"]["data"]["value"],
        "before-native-activation"
    );
    Ok(())
}

#[test]
fn configured_native_activation_requires_a_bound_profile_and_original_root_actor() -> TestResult {
    let root = super::super::tests::Root::new();
    let mut unconfigured = root.service()?;
    let (_, token) = initialize(&mut unconfigured)?;
    assert_eq!(
        request(&mut unconfigured, "POST", ACTIVATE_PATH, &token, json!({})).status,
        409
    );
    assert!(unconfigured.native_root.is_none());
    assert!(
        unconfigured
            .configure_native_v6_storage(NativeStorageProfile::File)
            .is_err(),
        "an unsealed instance cannot acquire startup eligibility"
    );
    drop(unconfigured);

    let other = super::super::tests::Root::new();
    let mut configured = other.service()?;
    configured.configure_native_v6_storage(NativeStorageProfile::File)?;
    let (_, token) = initialize(&mut configured)?;
    let mut child = request(
        &mut configured,
        "POST",
        "auth/token/create",
        &token,
        json!({"policies":["default"], "ttl":"60s"}),
    );
    assert_eq!(child.status, 200);
    let non_root = Zeroizing::new(
        child.body["auth"]["client_token"]
            .as_str()
            .ok_or("child token")?
            .to_owned(),
    );
    erase_json(&mut child.body);
    assert_eq!(
        request(&mut configured, "POST", ACTIVATE_PATH, &non_root, json!({})).status,
        403
    );
    assert!(configured.native_root.is_none());
    Ok(())
}

#[test]
fn configured_native_activation_rejects_unsupported_live_engine_without_retiring_v5() -> TestResult
{
    let root = super::super::tests::Root::new();
    // An actual bound loopback endpoint is enrolled while sealed. Config GET
    // and POST are local owner operations; no provider request is authorized.
    let provider_listener = std::net::TcpListener::bind("127.0.0.1:0")?;
    provider_listener.set_nonblocking(true)?;
    let provider_address = provider_listener.local_addr()?;
    let provider_origin = format!("https://localhost:{}", provider_address.port());
    let provider_bearer = Zeroizing::new(hex(&crypto::random::<32>()?));
    let mut service = root.service()?;
    service.install_outbound_endpoints(vec![crate::outbound::EndpointConfig {
        origin: provider_origin.clone(),
        address: provider_address,
        server_name: "localhost".to_owned(),
        ca_pem: include_str!("testdata/kubernetes-api-ca.pem").to_owned(),
        path_prefix: "/api/".to_owned(),
        shared_secret: String::new(),
    }])?;
    service.configure_native_v6_storage(NativeStorageProfile::File)?;
    let (_, token) = initialize(&mut service)?;
    // Root Kubernetes still lacks a formal native owner. Keep its genuine
    // secret-bearing config in root, so catalog validation reaches the
    // configured-storage refusal instead of an earlier child-profile refusal.
    assert_eq!(
        request(
            &mut service,
            "POST",
            "sys/mounts/kubernetes",
            &token,
            json!({"type":"kubernetes"})
        )
        .status,
        204
    );
    assert_eq!(
        request(
            &mut service,
            "POST",
            "kubernetes/config",
            &token,
            json!({"kubernetes_host":provider_origin,"service_account_token":provider_bearer.as_str()})
        )
        .status,
        204
    );
    let before = request(&mut service, "GET", "kubernetes/config", &token, json!({}));
    assert_eq!(before.status, 200);
    assert_eq!(before.body["data"]["service_account_token_set"], true);
    let source = service.state.as_ref().ok_or("unsupported Kubernetes state")?;
    assert!(!source.engines.supports_native_v6_root_storage());
    let owner_before = crate::service::owner_store::serialize_owner(source)
        .map_err(|_| "unsupported Kubernetes complete owner before")?;
    assert!(owner_before.windows(provider_bearer.len()).any(|part| part == provider_bearer.as_bytes()));
    let identity_before = service
        .current_state_identity()
        .map_err(|_| "unsupported Kubernetes v5 identity before")?;
    assert_eq!(
        request(&mut service, "POST", ACTIVATE_PATH, &token, json!({})).status,
        409
    );
    assert!(service.native_root.is_none());
    let retained = request(&mut service, "GET", "kubernetes/config", &token, json!({}));
    assert_eq!(retained.status, 200);
    assert_eq!(retained.body["data"], before.body["data"]);
    let owner_after = crate::service::owner_store::serialize_owner(
        service.state.as_ref().ok_or("unsupported Kubernetes retained state")?,
    )
    .map_err(|_| "unsupported Kubernetes complete retained owner")?;
    // Compare every secret-bearing owner byte without formatting it.
    assert!(owner_after.as_slice() == owner_before.as_slice());
    assert_eq!(
        service
            .current_state_identity()
            .map_err(|_| "unsupported Kubernetes retained v5 identity")?,
        identity_before
    );
    assert!(matches!(provider_listener.accept(), Err(error) if error.kind() == std::io::ErrorKind::WouldBlock));
    Ok(())
}

#[test]
fn configured_native_activation_rejects_unsupported_auth_mount_without_losing_it() -> TestResult {
    let root = super::super::tests::Root::new();
    let mut service = root.service()?;
    service.configure_native_v6_storage(NativeStorageProfile::File)?;
    let (_, token) = initialize(&mut service)?;
    assert_eq!(
        request(
            &mut service,
            "POST",
            "sys/auth/ldap",
            &token,
            json!({"type":"ldap"})
        )
        .status,
        204
    );
    assert_eq!(
        request(&mut service, "POST", ACTIVATE_PATH, &token, json!({})).status,
        409
    );
    assert!(service.native_root.is_none());
    let mounts = request(&mut service, "GET", "sys/auth", &token, json!({}));
    assert_eq!(mounts.status, 200);
    assert_eq!(mounts.body["data"]["ldap/"]["type"], "ldap");
    Ok(())
}

#[test]
fn configured_native_profile_cannot_replace_or_invent_a_runtime_owner() -> TestResult {
    let root = super::super::tests::Root::new();
    let mut service = root.service()?;
    assert!(
        service
            .configure_native_v6_storage(NativeStorageProfile::Raft)
            .is_err()
    );
    assert!(service.native_storage_profile.is_none());
    service.configure_native_v6_storage(NativeStorageProfile::File)?;
    assert!(
        service
            .configure_native_v6_storage(NativeStorageProfile::File)
            .is_err()
    );
    assert_eq!(
        service.native_storage_profile,
        Some(NativeStorageProfile::File)
    );
    Ok(())
}

#[test]
fn configured_native_file_restores_object_complete_history_and_reopens() -> TestResult {
    let root = super::super::tests::Root::new();
    let mut service = root.service()?;
    service.configure_native_v6_storage(NativeStorageProfile::File)?;
    let (key, token) = initialize(&mut service)?;
    mount_kv2(&mut service, &token);
    assert_eq!(
        request(
            &mut service,
            "POST",
            "secret/data/backup",
            &token,
            json!({"data":{"value":"retained-history"}})
        )
        .status,
        200
    );
    let legacy = download(&mut service, &token)?;
    assert_eq!(
        request(&mut service, "POST", ACTIVATE_PATH, &token, json!({})).status,
        204
    );
    let archive = download(&mut service, &token)?;
    assert_eq!(
        request(
            &mut service,
            "POST",
            "secret/data/backup",
            &token,
            json!({"data":{"value":"after-backup"}, "options":{"cas":1}})
        )
        .status,
        200
    );
    let before_restore = service.state.as_ref().ok_or("state")?.replay_epoch;

    let (legacy_denied, _) =
        snapshot_transfer(&mut service, "POST", &token, &mut legacy.as_slice())?;
    assert_eq!(
        legacy_denied.status, 409,
        "V5 restore must not replace active V6 custody"
    );
    assert_eq!(
        request(&mut service, "GET", "secret/data/backup", &token, json!({})).body["data"]["data"]
            ["value"],
        "after-backup"
    );

    let other = super::super::tests::Root::new();
    let mut foreign = other.service()?;
    foreign.configure_native_v6_storage(NativeStorageProfile::File)?;
    let (_, foreign_token) = initialize(&mut foreign)?;
    let (cross_seal_denied, _) = snapshot_transfer(
        &mut foreign,
        "POST",
        &foreign_token,
        &mut archive.as_slice(),
    )?;
    assert_eq!(cross_seal_denied.status, 400);
    assert!(
        foreign.native_root.is_none(),
        "foreign seal must not install native objects"
    );
    drop(foreign);

    let (restored, _) = snapshot_transfer(&mut service, "POST", &token, &mut archive.as_slice())?;
    assert_eq!(restored.status, 200);
    assert!(service.state.as_ref().ok_or("restored state")?.replay_epoch > before_restore);
    assert_eq!(
        request(&mut service, "GET", "secret/data/backup", &token, json!({})).body["data"]["data"]
            ["value"],
        "retained-history"
    );
    drop(service);
    let mut reopened = root.service()?;
    reopened.configure_native_v6_storage(NativeStorageProfile::File)?;
    assert_eq!(
        request(
            &mut reopened,
            "POST",
            "sys/unseal",
            "",
            json!({"key":key.as_str()})
        )
        .status,
        200
    );
    assert_eq!(
        request(
            &mut reopened,
            "GET",
            "secret/data/backup",
            &token,
            json!({})
        )
        .body["data"]["data"]["value"],
        "retained-history"
    );
    Ok(())
}

#[test]
fn configured_native_activation_migrates_token_private_storage_and_cold_reopens() -> TestResult {
    let root = super::super::tests::Root::new();
    let mut service = root.service()?;
    service.configure_native_v6_storage(NativeStorageProfile::File)?;
    let (key, token) = initialize(&mut service)?;
    let payload = json!({
        "value":"private-before-migration",
        "nested":{"retained":[null,false,17,"original-private-data"]}
    });
    assert_eq!(
        request(
            &mut service,
            "POST",
            "cubbyhole/retained",
            &token,
            payload.clone()
        )
        .status,
        204
    );
    assert!(service.native_root.is_none());
    let activated = request(&mut service, "POST", ACTIVATE_PATH, &token, json!({}));
    assert_eq!(activated.status, 204, "{:?}", activated.body.get("errors"));

    // Cubbyhole is now a supported Auth owner. Both warm and cold reads must
    // come from the formal V6 root, preserving the entire private JSON value.
    for after_cold in [false, true] {
        if after_cold {
            drop(service);
            service = root.service()?;
            service.configure_native_v6_storage(NativeStorageProfile::File)?;
            assert_eq!(
                request(
                    &mut service,
                    "POST",
                    "sys/unseal",
                    "",
                    json!({"key":key.as_str()})
                )
                .status,
                200
            );
        }
        assert_eq!(
            service
                .native_root
                .as_ref()
                .ok_or("migrated native root")?
                .reader_floor
                .native_kv2_format,
            2
        );
        assert!(service.record_root.is_none());
        let capacity = request(
            &mut service,
            "GET",
            "sys/internal/capacity",
            &token,
            json!({}),
        );
        assert_eq!(capacity.status, 200);
        assert_eq!(
            capacity.body["data"]["state_storage_format"],
            "heptabao-state-records-v6"
        );
        assert_eq!(capacity.body["data"]["native_kv2_reader_format"], 2);
        assert_eq!(
            capacity.body["data"]["profile"],
            "bounded-native-record-state-v6-paged"
        );
        let mut retained = request(&mut service, "GET", "cubbyhole/retained", &token, json!({}));
        assert_eq!(retained.status, 200);
        assert_eq!(retained.body["data"], payload);
        erase_json(&mut retained.body);
    }
    Ok(())
}

#[cfg(unix)]
#[test]
fn native_raft_seed_requires_real_shamir_checkpoint_and_acknowledged_initialization() -> TestResult
{
    let root = super::super::tests::Root::new();
    let mut service = root.service()?;
    assert!(Service::validate_native_v6_raft_seed(&service.data_dir).is_err());
    let recovery_nonce = Zeroizing::new(STANDARD.encode(crypto::random::<32>()?));
    let mut initialized = request(
        &mut service,
        "POST",
        "sys/init",
        "",
        json!({
            "secret_shares":1, "secret_threshold":1, "recovery_nonce":recovery_nonce.as_str()
        }),
    );
    assert_eq!(initialized.status, 200);
    assert_eq!(initialized.body["init_ack_required"], true);
    let key = Zeroizing::new(
        initialized.body["keys"][0]
            .as_str()
            .ok_or("real Shamir share")?
            .to_owned(),
    );
    let token = Zeroizing::new(
        initialized.body["root_token"]
            .as_str()
            .ok_or("real root token")?
            .to_owned(),
    );
    erase_json(&mut initialized.body);
    assert!(Service::validate_native_v6_raft_seed(&service.data_dir).is_err());
    assert_eq!(
        request(
            &mut service,
            "POST",
            "sys/unseal",
            "",
            json!({"key":key.as_str()})
        )
        .status,
        200
    );
    assert_eq!(
        request(&mut service, "POST", "sys/init/ack", &token, json!({})).status,
        204
    );
    let data_dir = service.data_dir.clone();
    drop(service);
    Service::validate_native_v6_raft_seed(&data_dir)?;
    let checkpoint = data_dir.join("state.hbs");
    let retained_checkpoint = data_dir.join("retained-test-checkpoint");
    fs::rename(&checkpoint, &retained_checkpoint)?;
    assert!(Service::validate_native_v6_raft_seed(&data_dir).is_err());
    std::os::unix::fs::symlink(&retained_checkpoint, &checkpoint)?;
    assert!(Service::validate_native_v6_raft_seed(&data_dir).is_err());
    fs::remove_file(&checkpoint)?;
    fs::rename(retained_checkpoint, checkpoint)?;
    Service::validate_native_v6_raft_seed(&data_dir)?;
    Ok(())
}

#[test]
fn configured_native_activation_keeps_pending_initialization_recoverable_until_ack() -> TestResult {
    let root = super::super::tests::Root::new();
    let mut service = root.service()?;
    service.configure_native_v6_storage(NativeStorageProfile::File)?;
    let recovery_nonce = Zeroizing::new(STANDARD.encode(crypto::random::<32>()?));
    let mut initialized = request(
        &mut service,
        "POST",
        "sys/init",
        "",
        json!({
            "secret_shares":1, "secret_threshold":1, "recovery_nonce":recovery_nonce.as_str()
        }),
    );
    assert_eq!(initialized.status, 200);
    assert_eq!(initialized.body["init_ack_required"], true);
    let key = Zeroizing::new(
        initialized.body["keys"][0]
            .as_str()
            .ok_or("real Shamir share")?
            .to_owned(),
    );
    let token = Zeroizing::new(
        initialized.body["root_token"]
            .as_str()
            .ok_or("real root token")?
            .to_owned(),
    );
    erase_json(&mut initialized.body);
    assert_eq!(
        request(
            &mut service,
            "POST",
            "sys/unseal",
            "",
            json!({"key":key.as_str()})
        )
        .status,
        200
    );
    mount_kv2(&mut service, &token);
    assert_eq!(
        request(&mut service, "POST", ACTIVATE_PATH, &token, json!({})).status,
        409
    );
    assert!(service.native_root.is_none());
    assert!(initialization_recovery_pending(&service.data_dir)?);
    assert_eq!(
        request(&mut service, "POST", "sys/init/ack", &token, json!({})).status,
        204
    );
    assert!(!initialization_recovery_pending(&service.data_dir)?);
    assert_eq!(
        request(&mut service, "POST", ACTIVATE_PATH, &token, json!({})).status,
        204
    );
    Ok(())
}

#[test]
fn configured_native_activation_keeps_pending_rekey_cancellable_in_v5() -> TestResult {
    let root = super::super::tests::Root::new();
    let mut service = root.service()?;
    service.configure_native_v6_storage(NativeStorageProfile::File)?;
    let (_, token) = initialize(&mut service)?;
    mount_kv2(&mut service, &token);
    let started = request(
        &mut service,
        "POST",
        "sys/rekey/init",
        &token,
        json!({"secret_shares":1,"secret_threshold":1,"require_verification":true}),
    );
    assert_eq!(started.status, 200);
    assert_eq!(started.body["started"], true);
    assert!(service.rekey.is_some());
    assert_eq!(
        request(&mut service, "POST", ACTIVATE_PATH, &token, json!({})).status,
        409
    );
    assert!(service.native_root.is_none());
    assert!(
        service.rekey.is_some(),
        "rejected migration must retain the original rekey"
    );
    assert_eq!(
        request(&mut service, "DELETE", "sys/rekey/init", &token, json!({})).status,
        204
    );
    assert!(service.rekey.is_none());
    assert_eq!(
        request(&mut service, "POST", ACTIVATE_PATH, &token, json!({})).status,
        204
    );
    Ok(())
}

#[test]
fn configured_native_activation_preserves_durable_nondefault_raft_policy_in_v5() -> TestResult {
    let root = super::super::tests::Root::new();
    let mut service = root.service()?;
    service.configure_native_v6_storage(NativeStorageProfile::File)?;
    let (key, token) = initialize(&mut service)?;
    mount_kv2(&mut service, &token);
    // This is the exact persisted owner shape written by the existing HA
    // administration route. The bounded native profile cannot manage it yet.
    let policy = json!({
        "config": {
            "cleanup_dead_servers": true,
            "last_contact_threshold": 10,
            "dead_server_last_contact_threshold": 86400,
            "max_trailing_logs": 1000,
            "min_quorum": 3,
            "server_stabilization_time": 10
        },
        "promote": [4]
    });
    let mut state = service
        .state
        .as_ref()
        .ok_or("actual initialized state")?
        .clone();
    state.raft_admin = serde_json::from_value::<raft_admin::RaftAdminState>(policy.clone())?.into();
    state
        .raft_admin
        .validate()
        .map_err(|_| "valid nondefault Raft policy")?;
    {
        let _deadline = crate::request_deadline::RequestDeadlineScope::enter(
            std::time::Instant::now() + Duration::from_secs(15),
        );
        service
            .commit_state(&mut state)
            .map_err(|_| "persist actual V5 owner")?;
    }
    service.state = Some(state);
    assert_eq!(
        request(&mut service, "POST", ACTIVATE_PATH, &token, json!({})).status,
        409
    );
    assert!(service.native_root.is_none());
    assert_eq!(
        serde_json::to_value(&service.state.as_ref().ok_or("retained state")?.raft_admin)?,
        policy
    );
    drop(service);
    let mut reopened = root.service()?;
    reopened.configure_native_v6_storage(NativeStorageProfile::File)?;
    assert_eq!(
        request(
            &mut reopened,
            "POST",
            "sys/unseal",
            "",
            json!({"key":key.as_str()})
        )
        .status,
        200
    );
    assert_eq!(
        serde_json::to_value(&reopened.state.as_ref().ok_or("cold V5 state")?.raft_admin)?,
        policy
    );
    assert!(reopened.native_root.is_none());
    Ok(())
}
