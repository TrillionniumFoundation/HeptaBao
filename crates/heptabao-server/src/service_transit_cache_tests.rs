//! Persisted cache configuration through the genuine Service commit and reopen paths.
use super::tests::{Root, bootstrap};
use super::*;
use zeroize::Zeroizing;

type TestResult = Result<(), &'static str>;
fn call(
    service: &mut Service,
    namespace: &str,
    method: &str,
    path: &str,
    token: &str,
    body: Value,
) -> Response {
    // This test-only direct caller owns one original monotonic deadline before
    // entering Service. Nested calls retain the existing deadline, even expired.
    let deadline = crate::request_deadline::current()
        .unwrap_or_else(|| std::time::Instant::now() + Duration::from_secs(60));
    let _deadline = crate::request_deadline::RequestDeadlineScope::enter(deadline);
    service.handle_at(method, path, namespace, token, body, 100)
}

#[test]
fn cache130_service_wire_current_authority_acl_namespace_and_restart_activate_persisted_capacity()
-> TestResult {
    let root = Root::new();
    let mut service = root.service().map_err(|_| "cache service")?;
    let (unseal, admin) = bootstrap(&mut service).map_err(|_| "cache bootstrap")?;
    let unseal = Zeroizing::new(unseal);
    let admin = Zeroizing::new(admin);
    assert!(
        call(
            &mut service,
            "",
            "POST",
            "sys/mounts/cached",
            &admin,
            json!({"type":"transit"})
        )
        .status
            == 204
    );
    assert!(
        call(
            &mut service,
            "",
            "POST",
            "cached/keys/key",
            &admin,
            json!({"exportable":true})
        )
        .status
            == 200
    );
    assert!(
        call(
            &mut service,
            "",
            "GET",
            "cached/config/cache",
            &admin,
            json!({})
        )
        .body["data"]["size"]
            == 0
    );
    assert!(
        call(
            &mut service,
            "",
            "POST",
            "cached/config/cache",
            &admin,
            json!({"size":10})
        )
        .body["data"]["size"]
            == 10
    );
    let configured = service.state.as_ref().ok_or("configured state")?;
    assert!(
        configured.schema == TRANSIT_CACHE_STATE_SCHEMA
            && configured.writer_schema() == TRANSIT_CACHE_STATE_SCHEMA
    );
    assert!(
        configured
            .engines
            .transit_cache_observation("", "cached/")
            .map_err(|_| "runtime observation")?
            == Some((0, 0))
    );
    for value in [json!(9), json!(-1), json!(10.5), json!(true)] {
        let before = service
            .current_state_identity()
            .map_err(|_| "current identity")?;
        assert!(
            call(
                &mut service,
                "",
                "POST",
                "cached/config/cache",
                &admin,
                json!({"size":value})
            )
            .status
                == 400
        );
        assert!(
            service
                .current_state_identity()
                .map_err(|_| "unchanged identity")?
                == before
        );
        assert!(
            call(
                &mut service,
                "",
                "GET",
                "cached/config/cache",
                &admin,
                json!({})
            )
            .body["data"]["size"]
                == 10
        );
    }
    assert!(
        call(
            &mut service,
            "",
            "POST",
            "sys/namespaces/team",
            &admin,
            json!({})
        )
        .status
            == 200
    );
    assert!(
        call(
            &mut service,
            "team",
            "POST",
            "sys/mounts/cached",
            &admin,
            json!({"type":"transit"})
        )
        .status
            == 204
    );
    assert!(
        call(
            &mut service,
            "team",
            "GET",
            "cached/config/cache",
            &admin,
            json!({})
        )
        .body["data"]["size"]
            == 0
    );
    let limited = call(
        &mut service,
        "",
        "POST",
        "auth/token/create",
        &admin,
        json!({"policies":["default"]}),
    );
    assert!(limited.status == 200);
    let token = Zeroizing::new(
        limited.body["auth"]["client_token"]
            .as_str()
            .ok_or("limited token")?
            .to_owned(),
    );
    let before = service
        .current_state_identity()
        .map_err(|_| "before denied config")?;
    assert!(
        call(
            &mut service,
            "",
            "POST",
            "cached/config/cache",
            &token,
            json!({"size":20})
        )
        .status
            == 403
    );
    assert!(
        service
            .current_state_identity()
            .map_err(|_| "after denied config")?
            == before
    );
    drop(service);
    let mut service = root.service().map_err(|_| "encrypted reopen")?;
    assert!(
        call(
            &mut service,
            "",
            "POST",
            "sys/unseal",
            "",
            json!({"key":unseal.as_str()})
        )
        .status
            == 200
    );
    assert!(
        call(
            &mut service,
            "",
            "GET",
            "cached/keys/key",
            &admin,
            json!({})
        )
        .status
            == 200
    );
    assert!(
        service
            .state
            .as_ref()
            .ok_or("reopened state")?
            .engines
            .transit_cache_observation("", "cached/")
            .map_err(|_| "active runtime")?
            == Some((10, 1))
    );
    assert!(
        call(
            &mut service,
            "",
            "GET",
            "cached/config/cache",
            &admin,
            json!({})
        )
        .body["data"]["size"]
            == 10
    );
    let old_policy = service
        .state
        .as_ref()
        .ok_or("current cache before rotation")?
        .engines
        .transit_cache_entry_observation("", "cached/", "key")
        .map_err(|_| "old real cache owner")?
        .ok_or("old cache entry")?;
    assert!(old_policy.0 == 1 && old_policy.1.upgrade().is_some());
    assert!(
        call(
            &mut service,
            "",
            "GET",
            "cached/keys/key",
            &admin,
            json!({})
        )
        .status
            == 200
    );
    let repeated = service
        .state
        .as_ref()
        .ok_or("repeated old state")?
        .engines
        .transit_cache_entry_observation("", "cached/", "key")
        .map_err(|_| "repeated old cache")?
        .ok_or("same old cache entry")?;
    assert!(std::sync::Weak::ptr_eq(&old_policy.1, &repeated.1));
    let generation_before_rotation = service
        .durable
        .as_ref()
        .ok_or("durable before rotation")?
        .generation();
    assert!(
        call(
            &mut service,
            "",
            "POST",
            "cached/keys/key/rotate",
            &admin,
            json!({})
        )
        .body["data"]["latest_version"]
            == 2
    );
    assert!(
        call(
            &mut service,
            "",
            "GET",
            "cached/keys/key",
            &admin,
            json!({})
        )
        .body["data"]["latest_version"]
            == 2
    );
    assert!(
        service
            .state
            .as_ref()
            .ok_or("rotated state")?
            .engines
            .transit_cache_observation("", "cached/")
            .map_err(|_| "rotated runtime")?
            == Some((10, 1))
    );
    assert!(
        call(
            &mut service,
            "team",
            "GET",
            "cached/config/cache",
            &admin,
            json!({})
        )
        .body["data"]["size"]
            == 0
    );
    assert!(
        service
            .durable
            .as_ref()
            .ok_or("durable after rotation")?
            .generation()
            > generation_before_rotation
    );
    assert!(old_policy.1.upgrade().is_none() && repeated.1.upgrade().is_none());
    let current_policy = service
        .state
        .as_ref()
        .ok_or("accepted rotated state")?
        .engines
        .transit_cache_entry_observation("", "cached/", "key")
        .map_err(|_| "accepted rotated cache")?
        .ok_or("rotated cache entry")?;
    assert!(current_policy.0 == 2 && current_policy.1.upgrade().is_some());
    assert!(
        call(
            &mut service,
            "",
            "GET",
            "cached/keys/key",
            &admin,
            json!({})
        )
        .status
            == 200
    );
    let current_repeat = service
        .state
        .as_ref()
        .ok_or("same rotated state")?
        .engines
        .transit_cache_entry_observation("", "cached/", "key")
        .map_err(|_| "same accepted cache")?
        .ok_or("repeated rotated cache entry")?;
    assert!(std::sync::Weak::ptr_eq(
        &current_policy.1,
        &current_repeat.1
    ));
    let generation_before_create = service
        .durable
        .as_ref()
        .ok_or("durable before creation")?
        .generation();
    assert!(
        call(
            &mut service,
            "",
            "POST",
            "cached/keys/after-cache",
            &admin,
            json!({})
        )
        .status
            == 200
    );
    assert!(
        service
            .durable
            .as_ref()
            .ok_or("durable after creation")?
            .generation()
            > generation_before_create
    );
    assert!(
        call(
            &mut service,
            "",
            "GET",
            "cached/keys/after-cache",
            &admin,
            json!({})
        )
        .status
            == 200
    );
    let created = service
        .state
        .as_ref()
        .ok_or("accepted newly created state")?
        .engines
        .transit_cache_entry_observation("", "cached/", "after-cache")
        .map_err(|_| "newly committed cache entry")?
        .ok_or("new key entered real cache")?;
    assert!(created.0 == 1 && created.1.upgrade().is_some());
    assert!(
        call(
            &mut service,
            "",
            "GET",
            "cached/keys/after-cache",
            &admin,
            json!({})
        )
        .status
            == 200
    );
    let created_repeat = service
        .state
        .as_ref()
        .ok_or("same newly created state")?
        .engines
        .transit_cache_entry_observation("", "cached/", "after-cache")
        .map_err(|_| "repeated newly committed cache entry")?
        .ok_or("new cache reused")?;
    assert!(std::sync::Weak::ptr_eq(&created.1, &created_repeat.1));
    assert!(
        service
            .state
            .as_ref()
            .ok_or("actual two cache entries")?
            .engines
            .transit_cache_observation("", "cached/")
            .map_err(|_| "actual entry count")?
            == Some((10, 2))
    );
    Ok(())
}

#[test]
fn cache130_service_reader_previous_publication_snapshot_decoder_and_retired_floor_are_sticky()
-> TestResult {
    let root = Root::new();
    let mut service = root.service().map_err(|_| "cache service")?;
    let (unseal, admin) = bootstrap(&mut service).map_err(|_| "cache bootstrap")?;
    let unseal = Zeroizing::new(unseal);
    let admin = Zeroizing::new(admin);
    assert!(
        call(
            &mut service,
            "",
            "POST",
            "sys/mounts/cached",
            &admin,
            json!({"type":"transit"})
        )
        .status
            == 204
    );
    let ordinary = service.state.as_ref().ok_or("ordinary state")?.clone();
    assert!(!ordinary.engines.has_transit_cache_state());
    assert!(
        call(
            &mut service,
            "",
            "POST",
            "cached/config/cache",
            &admin,
            json!({"size":"10"})
        )
        .status
            == 200
    );
    let active = service.state.as_ref().ok_or("active state")?.clone();
    assert!(active.schema == TRANSIT_CACHE_STATE_SCHEMA && active.validate_format().is_ok());
    assert!(
        supported_reader_schema(130) && !supported_reader_schema(MAX_SUPPORTED_STATE_SCHEMA + 1)
    );
    let mut old_reader = active.clone();
    old_reader.schema = WORKFLOW_CREDENTIAL_STATE_SCHEMA;
    assert!(old_reader.validate_format().is_err());
    assert!(
        old_reader
            .validate_publication_schema(Some(&active))
            .is_err()
    );
    assert!(Service::validate_snapshot_protected_floor(&active, &old_reader).is_err());
    let raw = Zeroizing::new(serde_json::to_vec(&active).map_err(|_| "private active encoding")?);
    let mut missing: Value = serde_json::from_slice(&raw).map_err(|_| "private active decoding")?;
    assert!(
        missing["engines"]
            .as_object_mut()
            .ok_or("engines object")?
            .remove("transit_cache_format")
            .is_some()
    );
    fn erase_configs(value: &mut Value) -> usize {
        match value {
            Value::Object(fields) => {
                let own = usize::from(fields.remove("cache_config").is_some());
                own + fields.values_mut().map(erase_configs).sum::<usize>()
            }
            Value::Array(values) => values.iter_mut().map(erase_configs).sum(),
            _ => 0,
        }
    }
    let mut double_missing = missing.clone();
    assert!(erase_configs(&mut double_missing) == 1);
    let double_erased: State =
        serde_json::from_value(double_missing).map_err(|_| "private double erased decoder")?;
    assert!(
        double_erased.validate_format().is_err()
            && double_erased
                .validate_publication_schema(Some(&active))
                .is_err()
            && Service::validate_snapshot_protected_floor(&active, &double_erased).is_err()
    );
    let mut erased: State =
        serde_json::from_value(missing).map_err(|_| "private erased decoder")?;
    assert!(erased.validate_format().is_err());
    assert!(erased.validate_publication_schema(Some(&active)).is_err());
    assert!(Service::validate_snapshot_protected_floor(&active, &erased).is_err());
    let identity = service
        .current_state_identity()
        .map_err(|_| "before forged commit")?;
    assert!(service.commit_state(&mut erased).is_err());
    assert!(
        service
            .current_state_identity()
            .map_err(|_| "after forged commit")?
            == identity
    );
    assert!(
        call(
            &mut service,
            "",
            "POST",
            "cached/config/cache",
            &admin,
            json!({"size":0})
        )
        .status
            == 200
    );
    assert!(service.state.as_ref().ok_or("zero state")?.schema == 130);
    assert!(
        call(
            &mut service,
            "",
            "DELETE",
            "sys/mounts/cached",
            &admin,
            json!({})
        )
        .status
            == 204
    );
    let retired = service.state.as_ref().ok_or("retired state")?.clone();
    assert!(
        retired.schema == 130
            && retired.engines.has_transit_cache_state()
            && retired.writer_schema() == 130
    );
    assert!(Service::validate_snapshot_protected_floor(&retired, &ordinary).is_err());
    let mut lower = retired.clone();
    lower.schema = 128;
    assert!(
        lower.validate_format().is_err()
            && lower.validate_publication_schema(Some(&retired)).is_err()
    );
    assert!(Service::validate_snapshot_protected_floor(&retired, &lower).is_err());
    drop(service);
    let mut service = root.service().map_err(|_| "retired encrypted reopen")?;
    assert!(
        call(
            &mut service,
            "",
            "POST",
            "sys/unseal",
            "",
            json!({"key":unseal.as_str()})
        )
        .status
            == 200
    );
    assert!(service.state.as_ref().ok_or("retired restart")?.schema == 130);
    assert!(
        call(
            &mut service,
            "",
            "POST",
            "sys/mounts/cached",
            &admin,
            json!({"type":"transit"})
        )
        .status
            == 204
    );
    assert!(
        call(
            &mut service,
            "",
            "GET",
            "cached/config/cache",
            &admin,
            json!({})
        )
        .body["data"]["size"]
            == 0
    );
    assert!(service.state.as_ref().ok_or("new mount state")?.schema == 130);
    Ok(())
}

#[test]
fn cache130_reload_real_runtime_activation_lru_crypto_namespace_and_encrypted_restart() -> TestResult
{
    let root = Root::new();
    let mut service = root.service().map_err(|_| "reload service")?;
    let (unseal, admin) = bootstrap(&mut service).map_err(|_| "reload bootstrap")?;
    let unseal = Zeroizing::new(unseal);
    let admin = Zeroizing::new(admin);
    assert!(
        call(
            &mut service,
            "",
            "POST",
            "sys/mounts/cached",
            &admin,
            json!({"type":"transit"})
        )
        .status
            == 204
    );
    assert!(
        call(
            &mut service,
            "",
            "POST",
            "cached/keys/key",
            &admin,
            json!({})
        )
        .status
            == 200
    );
    let encrypted = call(
        &mut service,
        "",
        "POST",
        "cached/encrypt/key",
        &admin,
        json!({"plaintext":STANDARD.encode(b"actual reload plaintext")}),
    );
    assert!(encrypted.status == 200);
    let ciphertext = encrypted.body["data"]["ciphertext"]
        .as_str()
        .ok_or("actual reload ciphertext")?
        .to_owned();
    assert!(
        call(
            &mut service,
            "",
            "GET",
            "cached/keys/key",
            &admin,
            json!({})
        )
        .status
            == 200
    );
    let old = service
        .state
        .as_ref()
        .ok_or("old reload state")?
        .engines
        .transit_cache_entry_observation("", "cached/", "key")
        .map_err(|_| "old actual cache")?
        .ok_or("old cache entry")?;
    assert!(old.1.upgrade().is_some());
    assert!(
        call(
            &mut service,
            "",
            "POST",
            "cached/config/cache",
            &admin,
            json!({"size":10})
        )
        .status
            == 200
    );
    assert!(
        service
            .state
            .as_ref()
            .ok_or("configured pending state")?
            .engines
            .transit_cache_observation("", "cached/")
            .map_err(|_| "pending active capacity")?
            == Some((0, 1))
    );
    let reply = call(
        &mut service,
        "",
        "POST",
        "sys/plugins/reload/backend",
        &admin,
        json!({"mounts":["cached/"]}),
    );
    assert!(reply.status == 200);
    let id = reply.body["data"]["reload_id"]
        .as_str()
        .ok_or("real reload id")?;
    assert!(
        id.len() == 36
            && id.as_bytes()[14] == b'4'
            && matches!(id.as_bytes()[19], b'8' | b'9' | b'a' | b'b')
    );
    assert!(old.1.upgrade().is_none());
    assert!(
        service
            .state
            .as_ref()
            .ok_or("reloaded state")?
            .engines
            .transit_cache_observation("", "cached/")
            .map_err(|_| "activated persisted capacity")?
            == Some((10, 0))
    );
    let decrypted = call(
        &mut service,
        "",
        "POST",
        "cached/decrypt/key",
        &admin,
        json!({"ciphertext":ciphertext}),
    );
    assert!(
        decrypted.status == 200
            && decrypted.body["data"]["plaintext"] == STANDARD.encode(b"actual reload plaintext")
    );
    for index in 0..11 {
        assert!(
            call(
                &mut service,
                "",
                "POST",
                &format!("cached/keys/key{index}"),
                &admin,
                json!({})
            )
            .status
                == 200
        );
        assert!(
            call(
                &mut service,
                "",
                "GET",
                &format!("cached/keys/key{index}"),
                &admin,
                json!({})
            )
            .status
                == 200
        );
    }
    assert!(
        service
            .state
            .as_ref()
            .ok_or("bounded entries")?
            .engines
            .transit_cache_observation("", "cached/")
            .map_err(|_| "actual bounded LRU")?
            == Some((10, 10))
    );
    assert!(
        call(
            &mut service,
            "",
            "POST",
            "cached/config/cache",
            &admin,
            json!({"size":0})
        )
        .status
            == 200
    );
    let second = call(
        &mut service,
        "",
        "POST",
        "sys/plugins/reload/backend",
        &admin,
        json!({"plugin":"transit","scope":"unknown-scope"}),
    );
    assert!(second.status == 200 && second.body["data"]["reload_id"] != id);
    assert!(
        service
            .state
            .as_ref()
            .ok_or("unlimited accepted state")?
            .engines
            .transit_cache_observation("", "cached/")
            .map_err(|_| "unlimited runtime activation")?
            == Some((0, 0))
    );
    for index in 0..11 {
        assert!(
            call(
                &mut service,
                "",
                "GET",
                &format!("cached/keys/key{index}"),
                &admin,
                json!({})
            )
            .status
                == 200
        );
    }
    assert!(
        service
            .state
            .as_ref()
            .ok_or("unlimited admitted entries")?
            .engines
            .transit_cache_observation("", "cached/")
            .map_err(|_| "actual unlimited LRU")?
            == Some((0, 11))
    );
    assert!(
        call(
            &mut service,
            "",
            "POST",
            "sys/namespaces/team",
            &admin,
            json!({})
        )
        .status
            == 200
    );
    assert!(
        call(
            &mut service,
            "team",
            "POST",
            "sys/mounts/cached",
            &admin,
            json!({"type":"transit"})
        )
        .status
            == 204
    );
    assert!(
        call(
            &mut service,
            "team",
            "POST",
            "cached/keys/key",
            &admin,
            json!({})
        )
        .status
            == 200
    );
    assert!(
        call(
            &mut service,
            "team",
            "GET",
            "cached/keys/key",
            &admin,
            json!({})
        )
        .status
            == 200
    );
    let team = service
        .state
        .as_ref()
        .ok_or("team actual state")?
        .engines
        .transit_cache_entry_observation("team", "cached/", "key")
        .map_err(|_| "team real cache")?
        .ok_or("team cache entry")?;
    assert!(
        call(
            &mut service,
            "",
            "POST",
            "sys/plugins/reload/backend",
            &admin,
            json!({"mounts":"cached","scope":"global"})
        )
        .status
            == 200
    );
    assert!(team.1.upgrade().is_some());
    drop(service);
    let mut service = root.service().map_err(|_| "reload encrypted reopen")?;
    assert!(
        call(
            &mut service,
            "",
            "POST",
            "sys/unseal",
            "",
            json!({"key":unseal.as_str()})
        )
        .status
            == 200
    );
    assert!(
        call(
            &mut service,
            "",
            "GET",
            "cached/config/cache",
            &admin,
            json!({})
        )
        .body["data"]["size"]
            == 0
    );
    assert!(
        call(
            &mut service,
            "",
            "POST",
            "cached/decrypt/key",
            &admin,
            json!({"ciphertext":ciphertext})
        )
        .body["data"]["plaintext"]
            == STANDARD.encode(b"actual reload plaintext")
    );
    Ok(())
}

#[test]
fn cache130_reload_denied_selectors_original_terminal_authority_and_configuration_cannot_clear()
-> TestResult {
    let root = Root::new();
    let mut service = root.service().map_err(|_| "reload guards service")?;
    let (_, admin) = bootstrap(&mut service).map_err(|_| "reload guards bootstrap")?;
    let admin = Zeroizing::new(admin);
    assert!(
        call(
            &mut service,
            "",
            "POST",
            "sys/mounts/cached",
            &admin,
            json!({"type":"transit"})
        )
        .status
            == 204
    );
    assert!(
        call(
            &mut service,
            "",
            "POST",
            "cached/keys/key",
            &admin,
            json!({})
        )
        .status
            == 200
    );
    assert!(
        call(
            &mut service,
            "",
            "GET",
            "cached/keys/key",
            &admin,
            json!({})
        )
        .status
            == 200
    );
    let entry = service
        .state
        .as_ref()
        .ok_or("retained cache state")?
        .engines
        .transit_cache_entry_observation("", "cached/", "key")
        .map_err(|_| "retained cache owner")?
        .ok_or("retained real entry")?;
    for body in [
        json!({}),
        json!({"plugin":"transit","mounts":["cached"]}),
        json!({"mounts":[]}),
        json!({"mounts":["../cached"]}),
        json!({"mounts":["cached","cached/"]}),
    ] {
        let before = service
            .current_state_identity()
            .map_err(|_| "before malformed reload")?;
        assert!(
            call(
                &mut service,
                "",
                "POST",
                "sys/plugins/reload/backend",
                &admin,
                body
            )
            .status
                == 400
        );
        assert!(
            service
                .current_state_identity()
                .map_err(|_| "after malformed reload")?
                == before
        );
        assert!(entry.1.upgrade().is_some());
    }
    assert!(
        call(
            &mut service,
            "",
            "POST",
            "sys/plugins/reload/backend",
            &admin,
            json!({"plugin":"unsupported"})
        )
        .status
            == 501
    );
    assert!(entry.1.upgrade().is_some());
    let limited = call(
        &mut service,
        "",
        "POST",
        "auth/token/create",
        &admin,
        json!({"policies":["default"]}),
    );
    assert!(limited.status == 200);
    let token = Zeroizing::new(
        limited.body["auth"]["client_token"]
            .as_str()
            .ok_or("limited reload token")?
            .to_owned(),
    );
    assert!(
        call(
            &mut service,
            "",
            "POST",
            "sys/plugins/reload/backend",
            &token,
            json!({"plugin":"transit"})
        )
        .status
            == 403
    );
    assert!(entry.1.upgrade().is_some());

    // Use the real handle_inner admission path to obtain the affine capsule,
    // then feed a failed terminal response. Neither helper repairs cache state.
    let body = json!({"mounts":["cached"]});
    let started = std::time::Instant::now();
    let _deadline =
        crate::request_deadline::RequestDeadlineScope::enter(started + Duration::from_secs(60));
    let request = RequestView {
        method: "POST",
        path: "sys/plugins/reload/backend",
        namespace: "",
        token: &admin,
        body: &body,
        now: 100,
        admission_started: started,
        token_clock: None,
        allow_forward: false,
        enforce_namespace: true,
        wrap_ttl_seconds: None,
        origin_peer: None,
        client_certificates: None,
    };
    let staged = service.handle_inner(request);
    assert!(staged.status == 200 && service.pending_transit_cache_reload.is_some());
    assert!(entry.1.upgrade().is_some());
    let before = service
        .current_state_identity()
        .map_err(|_| "before failed terminal")?;
    assert!(
        service
            .complete_transit_cache_reload_delivery(
                true,
                Response::error(503, "synthetic mandatory terminal veto"),
                "synthetic-reload"
            )
            .status
            == 503
    );
    assert!(service.pending_transit_cache_reload.is_none() && entry.1.upgrade().is_some());
    assert!(
        service
            .current_state_identity()
            .map_err(|_| "after failed terminal")?
            == before
    );

    let request = RequestView {
        method: "POST",
        path: "sys/plugins/reload/backend",
        namespace: "",
        token: &admin,
        body: &body,
        now: 100,
        admission_started: started,
        token_clock: None,
        allow_forward: false,
        enforce_namespace: true,
        wrap_ttl_seconds: None,
        origin_peer: None,
        client_certificates: None,
    };
    let staged = service.handle_inner(request);
    assert!(staged.status == 200);
    let capsule = service
        .pending_transit_cache_reload
        .take()
        .ok_or("actual reload capsule")?;
    // A genuine accepted configuration commit after capture changes the exact
    // basis. The old capsule must not activate that replacement.
    assert!(
        call(
            &mut service,
            "",
            "POST",
            "cached/config/cache",
            &admin,
            json!({"size":10})
        )
        .status
            == 200
    );
    service.pending_transit_cache_reload = Some(capsule);
    assert!(
        service
            .complete_transit_cache_reload_delivery(true, staged, "synthetic-configuration-change")
            .status
            == 503
    );
    assert!(entry.1.upgrade().is_some());
    assert!(
        service
            .state
            .as_ref()
            .ok_or("unchanged active runtime")?
            .engines
            .transit_cache_observation("", "cached/")
            .map_err(|_| "no replacement activation")?
            == Some((0, 1))
    );
    Ok(())
}
