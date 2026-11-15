//! Formal file V6 uses its existing ordinary KV owner after registry changes.
use super::*;

fn mount_v1(service: &mut Service, token: &str, name: &str) {
    let response = request(
        service,
        "POST",
        &format!("sys/mounts/{name}"),
        token,
        json!({"type":"kv","options":{"version":"1"}}),
    );
    assert_eq!(response.status, 204, "{:?}", response.body.get("errors"));
}

fn value(service: &mut Service, token: &str, path: &str, expected: &Value) {
    let mut response = request(service, "GET", path, token, json!({}));
    assert_eq!(response.status, 200, "{:?}", response.body.get("errors"));
    assert_eq!(&response.body["data"], expected);
    erase_json(&mut response.body);
}

fn configuration(
    service: &mut Service,
    token: &str,
    name: &str,
    default: i64,
    maximum: i64,
    cache: bool,
) -> Value {
    let reply = request(
        service,
        "GET",
        &format!("sys/mounts/{name}/tune"),
        token,
        json!({}),
    );
    assert_eq!(reply.status, 200, "{:?}", reply.body.get("errors"));
    let data = reply.body["data"].clone();
    assert_eq!(data["default_lease_ttl"], json!(default));
    assert_eq!(data["max_lease_ttl"], json!(maximum));
    assert_eq!(data["force_no_cache"], json!(cache));
    data
}

fn tune_configuration(service: &mut Service, token: &str, name: &str, body: Value, expected: u16) {
    let reply = request(
        service,
        "POST",
        &format!("sys/mounts/{name}/tune"),
        token,
        body,
    );
    assert_eq!(reply.status, expected, "{:?}", reply.body.get("errors"));
}

#[test]
fn formal_v6_kv1_mount_configuration_matches_pinned_271_and_cold_state() -> TestResult {
    let root = crate::service::tests::Root::new();
    let mut service = root.service()?;
    service.configure_native_v6_storage(NativeStorageProfile::File)?;
    let (key, token) = initialize(&mut service)?;
    assert_eq!(
        request(&mut service, "POST", ACTIVATE_PATH, &token, json!({})).status,
        204
    );
    assert_eq!(
        request(
            &mut service,
            "POST",
            "sys/mounts/configured",
            &token,
            json!({"type":"kv","options":{"version":"1"},"config":{
            "default_lease_ttl":"30s","max_lease_ttl":"60s","force_no_cache":true}})
        )
        .status,
        204
    );
    write_v1(
        &mut service,
        &token,
        "configured/value",
        json!({"stable":"payload"}),
    );
    let original = configuration(&mut service, &token, "configured", 30, 60, true);
    assert_eq!(
        request(&mut service, "GET", "configured/value", &token, json!({})).body["lease_duration"],
        30
    );
    for body in [
        json!({"default_lease_ttl":30,"max_lease_ttl":60,"force_no_cache":false}),
        json!({"default_lease_ttl":"","max_lease_ttl":null,"force_no_cache":true}),
    ] {
        tune_configuration(&mut service, &token, "configured", body, 204);
        assert_eq!(
            configuration(&mut service, &token, "configured", 30, 60, true),
            original
        );
    }
    tune_configuration(
        &mut service,
        &token,
        "configured",
        json!({"default_lease_ttl":"61s"}),
        400,
    );
    assert_eq!(
        configuration(&mut service, &token, "configured", 30, 60, true),
        original
    );
    tune_configuration(
        &mut service,
        &token,
        "configured",
        json!({"default_lease_ttl":-1}),
        204,
    );
    assert_eq!(
        request(&mut service, "GET", "configured/value", &token, json!({})).body["lease_duration"],
        -1
    );
    drop(service);
    let mut service = reopen(&root, &key)?;
    configuration(&mut service, &token, "configured", -1, 60, true);
    assert_eq!(
        request(&mut service, "GET", "configured/value", &token, json!({})).body["lease_duration"],
        -1
    );
    tune_configuration(
        &mut service,
        &token,
        "configured",
        json!({"default_lease_ttl":"1.5s"}),
        204,
    );
    let fractional = configuration(&mut service, &token, "configured", 1, 60, true);
    for body in [
        json!({"default_lease_ttl":1.5}),
        json!({"max_lease_ttl":"1.4s"}),
    ] {
        tune_configuration(&mut service, &token, "configured", body, 400);
        assert_eq!(
            configuration(&mut service, &token, "configured", 1, 60, true),
            fractional
        );
    }
    tune_configuration(
        &mut service,
        &token,
        "configured",
        json!({"default_lease_ttl":0,"max_lease_ttl":60}),
        204,
    );
    configuration(&mut service, &token, "configured", 2_764_800, 60, true);
    assert_eq!(
        request(&mut service, "GET", "configured/value", &token, json!({})).body["lease_duration"],
        2_764_800
    );
    let mounts = request(&mut service, "GET", "sys/mounts", &token, json!({}));
    assert_eq!(
        mounts.body["data"]["configured/"]["config"]["default_lease_ttl"],
        0
    );
    assert_eq!(
        mounts.body["data"]["configured/"]["config"]["max_lease_ttl"],
        60
    );
    drop(service);
    let mut service = reopen(&root, &key)?;
    configuration(&mut service, &token, "configured", 2_764_800, 60, true);
    value(
        &mut service,
        &token,
        "configured/value",
        &json!({"stable":"payload"}),
    );
    assert_eq!(
        service
            .state
            .as_ref()
            .ok_or("cold configured state")?
            .schema,
        KV_MOUNT_CONFIGURATION_STATE_SCHEMA
    );
    Ok(())
}

#[test]
fn formal_v6_kv1_configuration_reader_floor_survives_last_mount_retirement() -> TestResult {
    let root = crate::service::tests::Root::new();
    let mut service = root.service()?;
    service.configure_native_v6_storage(NativeStorageProfile::File)?;
    let (key, token) = initialize(&mut service)?;
    assert_eq!(
        request(&mut service, "POST", ACTIVATE_PATH, &token, json!({})).status,
        204
    );
    let earlier = download(&mut service, &token)?;
    assert_eq!(
        request(
            &mut service,
            "POST",
            "sys/mounts/retire-config",
            &token,
            json!({"type":"kv","options":{"version":"1"},"config":{"default_lease_ttl":"30s"}})
        )
        .status,
        204
    );
    assert_eq!(
        request(
            &mut service,
            "DELETE",
            "sys/mounts/retire-config",
            &token,
            json!({})
        )
        .status,
        204
    );
    assert!(
        !service
            .state
            .as_ref()
            .ok_or("retired state")?
            .engines
            .has_kv_mount_configuration()
    );
    drop(service);
    let mut service = reopen(&root, &key)?;
    assert_eq!(
        service.state.as_ref().ok_or("cold retired state")?.schema,
        KV_MOUNT_CONFIGURATION_STATE_SCHEMA
    );
    let epoch = service.state.as_ref().ok_or("state")?.replay_epoch;
    let (rejected, _) = snapshot_transfer(&mut service, "POST", &token, &mut earlier.as_slice())?;
    assert_eq!(rejected.status, 400);
    assert!(
        rejected.body["errors"]
            .as_array()
            .ok_or("errors")?
            .iter()
            .any(|v| {
                v.as_str()
                    .is_some_and(|s| s.contains("downgrade KV mount configuration"))
            })
    );
    assert_eq!(
        service
            .state
            .as_ref()
            .ok_or("unmodified state")?
            .replay_epoch,
        epoch
    );
    Ok(())
}

#[test]
fn formal_v6_kv1_kv2_configuration_snapshot_preserves_native_payload_owner() -> TestResult {
    let root = crate::service::tests::Root::new();
    let mut service = root.service()?;
    service.configure_native_v6_storage(NativeStorageProfile::File)?;
    let (key, token) = initialize(&mut service)?;
    assert_eq!(
        request(&mut service, "POST", ACTIVATE_PATH, &token, json!({})).status,
        204
    );
    assert_eq!(
        request(
            &mut service,
            "POST",
            "sys/mounts/configured-v2",
            &token,
            json!({"type":"kv","options":{"version":"2"},"config":{
            "default_lease_ttl":"30s","max_lease_ttl":"60s","force_no_cache":true}})
        )
        .status,
        204
    );
    let data = json!({"value":"native-v2-retained"});
    assert_eq!(
        request(
            &mut service,
            "POST",
            "configured-v2/data/key",
            &token,
            json!({"options":{"cas":0},"data":data.clone()})
        )
        .status,
        200
    );
    configuration(&mut service, &token, "configured-v2", 30, 60, true);
    let snapshot = download(&mut service, &token)?;
    tune_configuration(
        &mut service,
        &token,
        "configured-v2",
        json!({"default_lease_ttl":"50s","force_no_cache":false}),
        204,
    );
    drop(service);
    let mut service = reopen(&root, &key)?;
    configuration(&mut service, &token, "configured-v2", 50, 60, true);
    let (restored, _) = snapshot_transfer(&mut service, "POST", &token, &mut snapshot.as_slice())?;
    assert_eq!(restored.status, 200, "{:?}", restored.body.get("errors"));
    drop(service);
    let mut service = reopen(&root, &key)?;
    configuration(&mut service, &token, "configured-v2", 30, 60, true);
    let read = request(
        &mut service,
        "GET",
        "configured-v2/data/key",
        &token,
        json!({}),
    );
    assert_eq!(read.status, 200);
    assert_eq!(read.body["data"]["data"], data);
    assert_eq!(read.body["data"]["metadata"]["version"], 1);
    assert!(
        read.body
            .get("lease_duration")
            .is_none_or(|value| value == &json!(0))
    );
    assert!(
        !read
            .body
            .get("lease_id")
            .and_then(Value::as_str)
            .is_some_and(|id| !id.is_empty())
    );
    assert_eq!(
        service
            .native_root
            .as_ref()
            .ok_or("root")?
            .reader_floor
            .native_kv2_format,
        2
    );
    Ok(())
}

fn write_v1(service: &mut Service, token: &str, path: &str, body: Value) {
    let response = request(service, "POST", path, token, body);
    assert_eq!(response.status, 204, "{:?}", response.body.get("errors"));
}

fn reopen(
    root: &crate::service::tests::Root,
    key: &str,
) -> Result<Service, Box<dyn std::error::Error>> {
    let mut service = root.service()?;
    service.configure_native_v6_storage(NativeStorageProfile::File)?;
    assert_eq!(
        request(&mut service, "POST", "sys/unseal", "", json!({"key":key})).status,
        200
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
    Ok(service)
}

#[test]
fn formal_v6_kv1_registry_migration_cold_restart_and_snapshot_restore() -> TestResult {
    let root = crate::service::tests::Root::new();
    let mut service = root.service()?;
    service.configure_native_v6_storage(NativeStorageProfile::File)?;
    let (key, token) = initialize(&mut service)?;
    mount_v1(&mut service, &token, "old");
    let old = json!({"before":"activation","nested":[null,false,17,{"s":"retained"}]});
    write_v1(&mut service, &token, "old/value", old.clone());
    mount_kv2(&mut service, &token);
    assert_eq!(
        request(
            &mut service,
            "POST",
            "secret/data/sentinel",
            &token,
            json!({"data":{"value":"unrelated-kv2"}})
        )
        .status,
        200
    );
    assert_eq!(
        request(&mut service, "POST", ACTIVATE_PATH, &token, json!({})).status,
        204
    );
    value(&mut service, &token, "old/value", &old);
    mount_v1(&mut service, &token, "new");
    let captured = json!({"value":"after-activation","object":{"array":[true,23,"text"]}});
    write_v1(&mut service, &token, "new/nested/value", captured.clone());
    value(&mut service, &token, "new/nested/value", &captured);
    assert_eq!(
        request(&mut service, "LIST", "new/", &token, json!({})).body["data"]["keys"],
        json!(["nested/"])
    );
    assert_eq!(
        request(&mut service, "SCAN", "new/", &token, json!({})).body["data"]["keys"],
        json!(["nested/value"])
    );
    assert_eq!(
        request(
            &mut service,
            "POST",
            "sys/mounts/new/tune",
            &token,
            json!({"description":"persisted-kv1-description","default_lease_ttl":"30s"})
        )
        .status,
        204
    );
    let tune = request(
        &mut service,
        "GET",
        "sys/mounts/new/tune",
        &token,
        json!({}),
    );
    assert_eq!(tune.status, 200);
    assert_eq!(
        tune.body["data"]["description"],
        "persisted-kv1-description"
    );
    assert_eq!(tune.body["data"]["default_lease_ttl"], 30);
    assert_eq!(
        request(&mut service, "GET", "new/nested/value", &token, json!({})).body["lease_duration"],
        30
    );
    assert_eq!(
        service.state.as_ref().ok_or("configured state")?.schema,
        KV_MOUNT_CONFIGURATION_STATE_SCHEMA
    );
    let archive = download(&mut service, &token)?;
    let changed = json!({"value":"after-snapshot"});
    write_v1(&mut service, &token, "new/nested/value", changed.clone());
    drop(service);
    let mut service = reopen(&root, &key)?;
    value(&mut service, &token, "new/nested/value", &changed);
    value(&mut service, &token, "old/value", &old);
    let prior_epoch = service.state.as_ref().ok_or("state")?.replay_epoch;
    let (restored, _) = snapshot_transfer(&mut service, "POST", &token, &mut archive.as_slice())?;
    assert_eq!(restored.status, 200, "{:?}", restored.body.get("errors"));
    assert!(service.state.as_ref().ok_or("state")?.replay_epoch > prior_epoch);
    value(&mut service, &token, "new/nested/value", &captured);
    drop(service);
    let mut service = reopen(&root, &key)?;
    value(&mut service, &token, "new/nested/value", &captured);
    value(&mut service, &token, "old/value", &old);
    assert_eq!(
        request(
            &mut service,
            "GET",
            "sys/mounts/new/tune",
            &token,
            json!({})
        )
        .body["data"]["default_lease_ttl"],
        30
    );
    assert_eq!(
        request(&mut service, "GET", "new/nested/value", &token, json!({})).body["lease_duration"],
        30
    );
    assert_eq!(
        service.state.as_ref().ok_or("restored state")?.schema,
        KV_MOUNT_CONFIGURATION_STATE_SCHEMA
    );
    assert_eq!(
        request(
            &mut service,
            "GET",
            "secret/data/sentinel",
            &token,
            json!({})
        )
        .body["data"]["data"]["value"],
        "unrelated-kv2"
    );
    assert_eq!(
        request(
            &mut service,
            "GET",
            "sys/mounts/new/tune",
            &token,
            json!({})
        )
        .body["data"]["description"],
        "persisted-kv1-description"
    );
    Ok(())
}

#[test]
fn formal_v6_kv1_disable_recreate_retires_only_exact_scope() -> TestResult {
    let root = crate::service::tests::Root::new();
    let mut service = root.service()?;
    service.configure_native_v6_storage(NativeStorageProfile::File)?;
    let (key, token) = initialize(&mut service)?;
    for name in ["alpha", "alphabet"] {
        mount_v1(&mut service, &token, name);
    }
    write_v1(&mut service, &token, "alpha/old", json!({"v":"retire"}));
    let retained = json!({"v":"retain-exact-prefix-neighbor"});
    write_v1(&mut service, &token, "alphabet/old", retained.clone());
    assert_eq!(
        request(&mut service, "POST", ACTIVATE_PATH, &token, json!({})).status,
        204
    );
    let prior_incarnation = service
        .state
        .as_ref()
        .ok_or("state")?
        .engines
        .ordinary_kv_mount_binding("", "alpha/old")
        .ok_or("mount")?
        .1;
    assert_eq!(
        request(
            &mut service,
            "DELETE",
            "sys/mounts/alpha",
            &token,
            json!({})
        )
        .status,
        204
    );
    value(&mut service, &token, "alphabet/old", &retained);
    mount_v1(&mut service, &token, "alpha");
    let incarnation = service
        .state
        .as_ref()
        .ok_or("state")?
        .engines
        .ordinary_kv_mount_binding("", "alpha/old")
        .ok_or("mount")?
        .1;
    assert!(incarnation > prior_incarnation);
    assert_eq!(
        request(&mut service, "GET", "alpha/old", &token, json!({})).status,
        404
    );
    let new = json!({"v":"new-incarnation"});
    write_v1(&mut service, &token, "alpha/new", new.clone());
    drop(service);
    let mut service = reopen(&root, &key)?;
    assert_eq!(
        request(&mut service, "GET", "alpha/old", &token, json!({})).status,
        404
    );
    value(&mut service, &token, "alpha/new", &new);
    value(&mut service, &token, "alphabet/old", &retained);
    Ok(())
}

fn token_for(
    service: &mut Service,
    root: &str,
    policy: &str,
    rules: &str,
) -> Result<Zeroizing<String>, Box<dyn std::error::Error>> {
    assert_eq!(
        request(
            service,
            "PUT",
            &format!("sys/policies/acl/{policy}"),
            root,
            json!({"policy":rules})
        )
        .status,
        204
    );
    let mut response = request(
        service,
        "POST",
        "auth/token/create",
        root,
        json!({"policies":[policy],"ttl":"60s","no_default_policy":true}),
    );
    assert_eq!(response.status, 200);
    let token = Zeroizing::new(
        response.body["auth"]["client_token"]
            .as_str()
            .ok_or("client token")?
            .to_owned(),
    );
    erase_json(&mut response.body);
    Ok(token)
}

#[test]
fn formal_v6_kv1_registry_requires_actual_sudo_and_retains_revocation() -> TestResult {
    let root = crate::service::tests::Root::new();
    let mut service = root.service()?;
    service.configure_native_v6_storage(NativeStorageProfile::File)?;
    let (_, token) = initialize(&mut service)?;
    assert_eq!(
        request(&mut service, "POST", ACTIVATE_PATH, &token, json!({})).status,
        204
    );
    let denied = token_for(
        &mut service,
        &token,
        "without-sudo",
        r#"path "sys/mounts/controlled" { capabilities = ["update"] }"#,
    )?;
    let allowed = token_for(
        &mut service,
        &token,
        "with-sudo",
        r#"path "sys/mounts/controlled" { capabilities = ["update", "delete", "sudo"] }"#,
    )?;
    let source_graph = service.state.as_ref().ok_or("state")?.engines.record_root();
    assert_eq!(
        request(
            &mut service,
            "POST",
            "sys/mounts/controlled",
            &denied,
            json!({"type":"kv","options":{"version":"1"}})
        )
        .status,
        403
    );
    assert!(
        service
            .state
            .as_ref()
            .ok_or("state")?
            .engines
            .ordinary_kv_mount_binding("", "controlled/value")
            .is_none()
    );
    assert!(service.state.as_ref().ok_or("state")?.engines.record_root() == source_graph);
    mount_v1(&mut service, &allowed, "controlled");
    write_v1(
        &mut service,
        &token,
        "controlled/value",
        json!({"v":"retained-after-revoke"}),
    );
    assert_eq!(
        request(
            &mut service,
            "POST",
            "auth/token/revoke",
            &token,
            json!({"token":allowed.as_str()})
        )
        .status,
        204
    );
    assert_eq!(
        request(
            &mut service,
            "DELETE",
            "sys/mounts/controlled",
            &allowed,
            json!({})
        )
        .status,
        403
    );
    value(
        &mut service,
        &token,
        "controlled/value",
        &json!({"v":"retained-after-revoke"}),
    );
    Ok(())
}

#[test]
fn formal_v6_kv1_registry_owner_rejects_an_unrelated_record_change() -> TestResult {
    let root = crate::service::tests::Root::new();
    let mut service = root.service()?;
    service.configure_native_v6_storage(NativeStorageProfile::File)?;
    let (_, token) = initialize(&mut service)?;
    for name in ["alpha", "beta"] {
        mount_v1(&mut service, &token, name);
    }
    write_v1(&mut service, &token, "alpha/old", json!({"v":"alpha"}));
    write_v1(&mut service, &token, "beta/old", json!({"v":"beta"}));
    assert_eq!(
        request(&mut service, "POST", ACTIVATE_PATH, &token, json!({})).status,
        204
    );
    let source = (*service.state.as_ref().ok_or("state")?.engines).clone();
    let mut owner = source
        .capture_native_kv1_owner("", "DELETE", "sys/mounts/alpha", &json!({}), "delete")
        .map_err(|_| "capture actual KV1 registry owner")?;
    let mut valid = source.clone();
    let response = valid
        .handle("", "DELETE", "sys/mounts/alpha", &json!({}), 100)
        .map_err(|_| "prepare expected disable")?
        .ok_or("disable route")?;
    assert_eq!(response.status, 204);
    let mut tampered = valid.clone();
    assert_eq!(
        tampered
            .handle(
                "",
                "POST",
                "beta/old",
                &json!({"v":"unrelated-tamper"}),
                100
            )
            .map_err(|_| "prepare synthetic unrelated change")?
            .ok_or("write route")?
            .status,
        204
    );
    assert!(owner.admit_candidate(&tampered, 204, &|| true).is_err());
    let mut owner = source
        .capture_native_kv1_owner("", "DELETE", "sys/mounts/alpha", &json!({}), "delete")
        .map_err(|_| "capture second independent owner")?;
    owner
        .admit_candidate(&valid, 204, &|| true)
        .map_err(|_| "valid exact-scope disable rejected")?;
    value(&mut service, &token, "alpha/old", &json!({"v":"alpha"}));
    value(&mut service, &token, "beta/old", &json!({"v":"beta"}));
    Ok(())
}

#[path = "service_native_kv1_signed_lease_tests.rs"]
mod signed_lease_tests;
