use super::tests::{Root, bootstrap_unmounted, call};
use super::*;

fn assert_mount_types(response: &Response, expected: &[(&str, &str)]) {
    assert_eq!(response.status, 200);
    assert!(
        response.body["data"].is_object(),
        "mount registry is an object"
    );
    let types: BTreeMap<&str, Option<&str>> = response.body["data"]
        .as_object()
        .into_iter()
        .flat_map(|data| data.iter())
        .map(|(path, value)| (path.as_str(), value["type"].as_str()))
        .collect();
    assert_eq!(
        types,
        expected
            .iter()
            .map(|(path, kind)| (*path, Some(*kind)))
            .collect()
    );
}

#[test]
fn new_init_explicit_empty_mounts_enable_once_and_reopen_true_crypto()
-> Result<(), Box<dyn std::error::Error>> {
    let root = Root::new();
    let mut service = root.service()?;
    let (key, token) = bootstrap_unmounted(&mut service)?;
    let virtuals = [
        ("cubbyhole/", "cubbyhole"),
        ("identity/", "identity"),
        ("sys/", "system"),
    ];
    let mounts = call(&mut service, "GET", "sys/mounts", &token, json!({}));
    assert_mount_types(&mounts, &virtuals);
    for path in ["secret/data/test", "transit/keys/test"] {
        assert_eq!(
            call(&mut service, "GET", path, &token, json!({})).status,
            404
        );
    }
    assert_eq!(
        call(&mut service, "GET", "sys/mounts", "", json!({})).status,
        403
    );
    for path in ["sys/", "identity/"] {
        assert!(
            mounts.body["data"][path]
                == service
                    .state
                    .as_ref()
                    .ok_or("state")?
                    .engines
                    .ui_secret_mounts("")[path],
            "raw and UI control mount descriptors agree"
        );
    }
    assert_eq!(
        call(
            &mut service,
            "POST",
            "sys/mounts/transit",
            &token,
            json!({"type":"transit"})
        )
        .status,
        204
    );
    assert_eq!(
        call(
            &mut service,
            "POST",
            "sys/mounts/transit",
            &token,
            json!({"type":"transit"})
        )
        .status,
        400
    );
    assert_eq!(
        call(&mut service, "POST", "transit/keys/test", &token, json!({})).status,
        200
    );
    let plaintext = STANDARD.encode(b"synthetic default-mount restart");
    let encrypted = call(
        &mut service,
        "POST",
        "transit/encrypt/test",
        &token,
        json!({"plaintext":plaintext}),
    );
    assert_eq!(encrypted.status, 200);
    let ciphertext = encrypted.body["data"]["ciphertext"]
        .as_str()
        .ok_or("ciphertext")?
        .to_owned();
    drop(service);
    let mut service = root.service()?;
    assert_eq!(
        call(&mut service, "PUT", "sys/unseal", "", json!({"key":key})).status,
        200
    );
    let mounts = call(&mut service, "GET", "sys/mounts", &token, json!({}));
    assert_mount_types(
        &mounts,
        &[
            ("cubbyhole/", "cubbyhole"),
            ("identity/", "identity"),
            ("sys/", "system"),
            ("transit/", "transit"),
        ],
    );
    let decrypted = call(
        &mut service,
        "POST",
        "transit/decrypt/test",
        &token,
        json!({"ciphertext":ciphertext}),
    );
    assert!(
        decrypted.status == 200 && decrypted.body["data"]["plaintext"] == plaintext,
        "encrypted restart retains the explicitly enabled key"
    );
    Ok(())
}

#[test]
fn new_namespaces_store_empty_entries_and_pristine_deletion_is_durable()
-> Result<(), Box<dyn std::error::Error>> {
    let root = Root::new();
    let mut service = root.service()?;
    let (key, token) = bootstrap_unmounted(&mut service)?;
    assert_eq!(
        call(
            &mut service,
            "POST",
            "sys/namespaces/team",
            &token,
            json!({})
        )
        .status,
        200
    );
    let mounts = service.handle_at("GET", "sys/mounts", "team", &token, json!({}), 100);
    assert_mount_types(
        &mounts,
        &[
            ("cubbyhole/", "cubbyhole"),
            ("identity/", "identity"),
            ("sys/", "system"),
        ],
    );
    let encoded = serde_json::to_value(&service.state.as_ref().ok_or("state")?.engines)?;
    assert!(
        encoded["namespaces"]["team"]["mounts"]
            .as_object()
            .is_some_and(|mounts| mounts.is_empty()),
        "namespace has an explicit empty engine entry"
    );
    drop(service);
    let mut service = root.service()?;
    assert_eq!(
        call(&mut service, "PUT", "sys/unseal", "", json!({"key":key})).status,
        200
    );
    assert_mount_types(
        &service.handle_at("GET", "sys/mounts", "team", &token, json!({}), 100),
        &[
            ("cubbyhole/", "cubbyhole"),
            ("identity/", "identity"),
            ("sys/", "system"),
        ],
    );
    assert_eq!(
        call(&mut service, "DELETE", "sys/namespaces/team", "", json!({})).status,
        403
    );
    assert_eq!(
        call(
            &mut service,
            "DELETE",
            "sys/namespaces/team",
            &token,
            json!({})
        )
        .status,
        200
    );
    assert_eq!(
        call(
            &mut service,
            "GET",
            "sys/namespaces/team",
            &token,
            json!({})
        )
        .status,
        404
    );
    assert!(
        !service
            .state
            .as_ref()
            .ok_or("state")?
            .engines
            .known_namespaces()
            .contains("team")
    );
    drop(service);
    let mut service = root.service()?;
    assert_eq!(
        call(&mut service, "PUT", "sys/unseal", "", json!({"key":key})).status,
        200
    );
    assert_eq!(
        call(
            &mut service,
            "GET",
            "sys/namespaces/team",
            &token,
            json!({})
        )
        .status,
        404
    );
    Ok(())
}

#[test]
fn pristine_namespace_fence_retains_mount_identity_and_registry_ownership()
-> Result<(), Box<dyn std::error::Error>> {
    let root = Root::new();
    let mut service = root.service()?;
    let (_, token) = bootstrap_unmounted(&mut service)?;
    for namespace in ["mounted", "ident", "registry"] {
        assert_eq!(
            call(
                &mut service,
                "POST",
                &format!("sys/namespaces/{namespace}"),
                &token,
                json!({})
            )
            .status,
            200
        );
    }
    assert_eq!(
        service
            .handle_at(
                "POST",
                "sys/mounts/kv",
                "mounted",
                &token,
                json!({"type":"kv"}),
                100
            )
            .status,
        204
    );
    let old_incarnation = service
        .state
        .as_ref()
        .ok_or("mounted state")?
        .namespaces
        .incarnation("mounted")
        .ok_or("actual mounted incarnation")?;
    assert_eq!(
        call(
            &mut service,
            "DELETE",
            "sys/namespaces/mounted",
            &token,
            json!({})
        )
        .status,
        200,
        "the actual local KV owner can retire through owned namespace cleanup"
    );
    assert!(
        service
            .state
            .as_ref()
            .ok_or("retired mounted state")?
            .namespaces
            .incarnation("mounted")
            .is_none()
    );
    assert_eq!(
        call(
            &mut service,
            "GET",
            "sys/namespaces/mounted",
            &token,
            json!({})
        )
        .status,
        404
    );
    assert_eq!(
        call(
            &mut service,
            "POST",
            "sys/namespaces/mounted",
            &token,
            json!({})
        )
        .status,
        200
    );
    assert!(
        service
            .state
            .as_ref()
            .ok_or("recreated mounted state")?
            .namespaces
            .incarnation("mounted")
            .ok_or("recreated incarnation")?
            > old_incarnation,
        "recreation never adopts the retired mount incarnation"
    );
    let entity = service.handle_at(
        "POST",
        "identity/entity",
        "ident",
        &token,
        json!({"name":"synthetic-ownership"}),
        100,
    );
    assert_eq!(entity.status, 200);
    let entity_id = entity.body["data"]["id"].as_str().ok_or("entity id")?;
    assert_eq!(
        service
            .handle_at(
                "DELETE",
                &format!("identity/entity/id/{entity_id}"),
                "ident",
                &token,
                json!({}),
                100
            )
            .status,
        204
    );
    assert_eq!(
        call(
            &mut service,
            "DELETE",
            "sys/namespaces/ident",
            &token,
            json!({})
        )
        .status,
        409
    );
    assert_eq!(service.handle_at("POST", "sys/external-keys/configs/remote", "registry", &token,
        json!({"plugin":"transit","address":"https://127.0.0.1:8200","token":"synthetic fixture","mount_path":"transit","verify":false}), 100).status, 204);
    assert_eq!(
        call(
            &mut service,
            "DELETE",
            "sys/namespaces/registry",
            &token,
            json!({})
        )
        .status,
        409
    );
    Ok(())
}

#[test]
fn explicit_entries_survive_legacy_codec_and_missing_entries_keep_legacy_defaults()
-> Result<(), Box<dyn std::error::Error>> {
    let mut engines = EngineState::initialized_empty();
    engines.ensure_empty_namespace("team");
    let encoded = serde_json::to_vec(&engines)?;
    let mut decoded: EngineState = serde_json::from_slice(&encoded)?;
    assert!(decoded.namespace_is_empty("team"));
    decoded.ensure_empty_namespace("team");
    assert!(
        serde_json::to_vec(&decoded)? == encoded,
        "ensure never replaces an existing entry"
    );
    assert!(
        decoded.remove_empty_namespace("").is_err(),
        "root engine entry is protected"
    );
    decoded
        .remove_empty_namespace("team")
        .map_err(|_| "pristine engine cleanup")?;
    assert!(!decoded.known_namespaces().contains("team"));
    let root = Root::new();
    let mut service = root.service()?;
    let (key, token) = bootstrap_unmounted(&mut service)?;
    assert_eq!(
        call(
            &mut service,
            "POST",
            "sys/namespaces/team",
            &token,
            json!({})
        )
        .status,
        200
    );
    // A test constructs the supported historical implicit representation. This
    // is an authenticated codec compatibility test, not an old-program run.
    let mut legacy = service.state.as_ref().ok_or("state")?.clone();
    legacy.engines = EngineState::default().into();
    legacy
        .validate_format()
        .map_err(|_| "legacy representation")?;
    service
        .commit_state(&mut legacy)
        .map_err(|_| "historical representation commit")?;
    service.state = Some(legacy);
    drop(service);
    let mut service = root.service()?;
    assert_eq!(
        call(&mut service, "PUT", "sys/unseal", "", json!({"key":key})).status,
        200
    );
    for namespace in ["", "team"] {
        assert_mount_types(
            &service.handle_at("GET", "sys/mounts", namespace, &token, json!({}), 100),
            &[
                ("cubbyhole/", "cubbyhole"),
                ("identity/", "identity"),
                ("secret/", "kv"),
                ("sys/", "system"),
                ("transit/", "transit"),
            ],
        );
        assert_eq!(
            service
                .handle_at(
                    "PUT",
                    "secret/data/synthetic",
                    namespace,
                    &token,
                    json!({"data":{"value":"synthetic"}}),
                    100
                )
                .status,
            200
        );
    }
    Ok(())
}
