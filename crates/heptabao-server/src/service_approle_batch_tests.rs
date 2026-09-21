use super::tests::{Root, bootstrap, call};
use super::*;
type TestResult = Result<(), Box<dyn std::error::Error>>;

fn credentials(
    service: &mut Service,
    admin: &str,
    kind: &str,
    uses: u64,
) -> Result<Value, Box<dyn std::error::Error>> {
    assert_eq!(
        call(
            service,
            "POST",
            "auth/approle/role/example",
            admin,
            json!({"token_type":kind,"token_ttl":60,"secret_id_num_uses":uses})
        )
        .status,
        204
    );
    let rid = call(
        service,
        "GET",
        "auth/approle/role/example/role-id",
        admin,
        json!({}),
    );
    let sid = call(
        service,
        "POST",
        "auth/approle/role/example/secret-id",
        admin,
        json!({}),
    );
    Ok(
        json!({"role_id":rid.body["data"]["role_id"].as_str().ok_or("role_id")?,
        "secret_id":sid.body["data"]["secret_id"].as_str().ok_or("secret_id")?}),
    )
}
fn login(service: &mut Service, credentials: &Value, wrap: Option<u64>) -> Response {
    service.handle_at_mode(RequestDispatch {
        method: "POST",
        path: "auth/approle/login",
        namespace: "",
        token: "",
        body: credentials.clone(),
        now: 100,
        allow_forward: false,
        enforce_namespace: true,
        wrap_ttl_seconds: wrap,
        origin_peer: None,
        client_certificates: None,
    })
}
fn secret_info(service: &mut Service, admin: &str, credentials: &Value) -> Response {
    call(
        service,
        "POST",
        "auth/approle/role/example/secret-id/lookup",
        admin,
        json!({"secret_id":credentials["secret_id"]}),
    )
}
fn without_secret_ids(
    auth: &AuthState,
) -> Result<zeroize::Zeroizing<Vec<u8>>, Box<dyn std::error::Error>> {
    fn remove(value: &mut Value) {
        match value {
            Value::Object(map) => {
                if let Some(mut removed) = map.remove("secret_ids") {
                    erase_json(&mut removed);
                }
                for child in map.values_mut() {
                    remove(child);
                }
            }
            Value::Array(values) => {
                for child in values {
                    remove(child);
                }
            }
            _ => {}
        }
    }
    let bytes = owner_store::serialize_owner(auth).map_err(|_| "serialize auth")?;
    let mut value: Value = serde_json::from_slice(&bytes)?;
    remove(&mut value);
    let result = zeroize::Zeroizing::new(serde_json::to_vec(&value)?);
    erase_json(&mut value);
    Ok(result)
}
fn no_credentials(response: &Response) {
    assert!(response.body.get("auth").is_none_or(Value::is_null));
    assert!(response.body.get("wrap_info").is_none_or(Value::is_null));
}
#[test]
fn approle_identity_rejection_commits_only_one_verified_secret_consumption_for_both_kinds()
-> TestResult {
    for kind in ["service", "batch"] {
        let root = Root::new();
        let mut service = root.service()?;
        let (key, admin) = bootstrap(&mut service)?;
        let credentials = credentials(&mut service, &admin, kind, 2)?;
        let first = login(&mut service, &credentials, None);
        assert_eq!(first.status, 200);
        let entity = first.body["auth"]["entity_id"].as_str().ok_or("entity")?;
        assert_eq!(
            call(
                &mut service,
                "POST",
                &format!("identity/entity/id/{entity}"),
                &admin,
                json!({"disabled":true})
            )
            .status,
            204
        );
        let before = without_secret_ids(&service.state.as_ref().ok_or("state")?.auth)?;
        let engines = owner_store::serialize_owner(&service.state.as_ref().ok_or("state")?.engines)
            .map_err(|_| "engines")?;
        let failed = login(&mut service, &credentials, Some(60));
        assert_eq!(failed.status, 403);
        no_credentials(&failed);
        assert!(
            before.as_slice()
                == without_secret_ids(&service.state.as_ref().ok_or("state")?.auth)?.as_slice()
        );
        assert!(
            engines.as_slice()
                == owner_store::serialize_owner(&service.state.as_ref().ok_or("state")?.engines)
                    .map_err(|_| "engines")?
                    .as_slice()
        );
        assert_eq!(secret_info(&mut service, &admin, &credentials).status, 204);
        drop(service);
        let mut service = root.service()?;
        assert_eq!(
            call(&mut service, "POST", "sys/unseal", "", json!({"key":key})).status,
            200
        );
        assert_eq!(
            call(
                &mut service,
                "POST",
                &format!("identity/entity/id/{entity}"),
                &admin,
                json!({"disabled":false})
            )
            .status,
            204
        );
        let retry = login(&mut service, &credentials, None);
        assert_eq!(retry.status, 400);
        no_credentials(&retry);
    }
    Ok(())
}
#[test]
fn approle_wrapping_failure_consumes_once_but_discards_identity_token_and_batch_key_changes()
-> TestResult {
    for kind in ["service", "batch"] {
        let root = Root::new();
        let mut service = root.service()?;
        let (_, admin) = bootstrap(&mut service)?;
        let credentials = credentials(&mut service, &admin, kind, 2)?;
        let mut fixture = service.state.clone().ok_or("state")?;
        for _ in 0..256 {
            fixture
                .auth
                .wrap_response("", "fixture", 60, &json!({"data":{"ok":true}}), 100)?;
        }
        service
            .commit_state(&fixture)
            .map_err(|_| "fixture commit")?;
        service.state = Some(fixture);
        let before = without_secret_ids(&service.state.as_ref().ok_or("state")?.auth)?;
        let engines = owner_store::serialize_owner(&service.state.as_ref().ok_or("state")?.engines)
            .map_err(|_| "engines")?;
        let failed = login(&mut service, &credentials, Some(60));
        assert_eq!(failed.status, 503);
        no_credentials(&failed);
        assert_eq!(
            secret_info(&mut service, &admin, &credentials).body["data"]["secret_id_num_uses"],
            1
        );
        assert!(
            before.as_slice()
                == without_secret_ids(&service.state.as_ref().ok_or("state")?.auth)?.as_slice()
        );
        assert!(
            engines.as_slice()
                == owner_store::serialize_owner(&service.state.as_ref().ok_or("state")?.engines)
                    .map_err(|_| "engines")?
                    .as_slice()
        );
        assert_eq!(login(&mut service, &credentials, Some(60)).status, 503);
        assert_eq!(secret_info(&mut service, &admin, &credentials).status, 204);
        assert_eq!(login(&mut service, &credentials, Some(60)).status, 400);
    }
    Ok(())
}
#[test]
fn approle_invalid_secret_and_storage_rejection_never_publish_credentials_or_consumption()
-> TestResult {
    for kind in ["service", "batch"] {
        let root = Root::new();
        let mut service = root.service()?;
        let (_, admin) = bootstrap(&mut service)?;
        let credentials = credentials(&mut service, &admin, kind, 2)?;
        let before = service.current_state_digest().map_err(|_| "digest")?;
        let mut invalid = credentials.clone();
        invalid["secret_id"] = json!("wrong-secret");
        let denied = login(&mut service, &invalid, Some(60));
        assert_eq!(denied.status, 400);
        no_credentials(&denied);
        assert_eq!(
            service.current_state_digest().map_err(|_| "digest")?,
            before
        );
        let capacity = service.state_capacity;
        service.state_capacity = 1;
        let rejected = login(&mut service, &credentials, Some(60));
        assert_eq!(rejected.status, 507);
        no_credentials(&rejected);
        assert_eq!(
            service.current_state_digest().map_err(|_| "digest")?,
            before
        );
        service.state_capacity = capacity;
        assert_eq!(
            secret_info(&mut service, &admin, &credentials).body["data"]["secret_id_num_uses"],
            2
        );
        assert_eq!(login(&mut service, &credentials, None).status, 200);
        assert_eq!(
            secret_info(&mut service, &admin, &credentials).body["data"]["secret_id_num_uses"],
            1
        );
    }
    Ok(())
}
#[test]
fn approle_batch_success_wraps_and_consumes_in_one_application_publication() -> TestResult {
    let root = Root::new();
    let mut service = root.service()?;
    let (_, admin) = bootstrap(&mut service)?;
    let credentials = credentials(&mut service, &admin, "batch", 2)?;
    // Separate periodic physical GC from the number of application publications.
    service.record_writes_since_gc = 0;
    let response = login(&mut service, &credentials, Some(60));
    assert_eq!(response.status, 200);
    assert_eq!(service.record_writes_since_gc, 1);
    let wrapper = response.body["wrap_info"]["token"]
        .as_str()
        .ok_or("wrapper")?;
    let inner = call(
        &mut service,
        "POST",
        "sys/wrapping/unwrap",
        wrapper,
        json!({}),
    );
    assert_eq!(inner.status, 200);
    assert_eq!(inner.body["auth"]["token_type"], "batch");
    assert_eq!(
        inner.body["auth"]["metadata"],
        json!({"role_name":"example"})
    );
    assert!(
        inner.body["auth"]["entity_id"]
            .as_str()
            .is_some_and(|id| !id.is_empty())
    );
    assert_ne!(
        call(
            &mut service,
            "POST",
            "sys/wrapping/unwrap",
            wrapper,
            json!({})
        )
        .status,
        200
    );
    assert_eq!(
        secret_info(&mut service, &admin, &credentials).body["data"]["secret_id_num_uses"],
        1
    );
    Ok(())
}
#[test]
fn approle_batch_role_and_mount_each_require_schema42_but_old_none_admits41() -> TestResult {
    let root = Root::new();
    let mut service = root.service()?;
    let (_, admin) = bootstrap(&mut service)?;
    assert_eq!(
        call(
            &mut service,
            "POST",
            "auth/approle/role/legacy",
            &admin,
            json!({"token_ttl":60})
        )
        .status,
        204
    );
    let mut legacy = service.state.clone().ok_or("state")?;
    legacy.schema = 41;
    assert!(legacy.validate_format().is_ok());
    let before = owner_store::serialize_owner(&legacy.auth).map_err(|_| "auth")?;
    let reopened: AuthState = serde_json::from_slice(&before)?;
    assert!(
        before.as_slice()
            == owner_store::serialize_owner(&reopened)
                .map_err(|_| "auth")?
                .as_slice()
    );
    for (path, body) in [
        ("auth/approle/role/legacy", json!({"token_type":"default"})),
        (
            "sys/auth/approle/tune",
            json!({"token_type":"default-service"}),
        ),
    ] {
        service
            .commit_state(&legacy)
            .map_err(|_| "legacy fixture commit")?;
        service.state = Some(legacy.clone());
        assert_eq!(call(&mut service, "POST", path, &admin, body).status, 204);
        let mut changed = service.state.clone().ok_or("state")?;
        assert!(changed.auth.has_approle_batch_state());
        assert!(changed.validate_format().is_ok());
        changed.schema = 41;
        assert!(changed.validate_format().is_err());
    }
    Ok(())
}

#[test]
fn approle_batch_unknown_journal_outcome_fences_success_and_denied_consumption_without_credentials()
-> TestResult {
    for kind in ["service", "batch"] {
        for identity_denied in [false, true] {
            let root = Root::new();
            let mut service = root.service()?;
            let (key, admin) = bootstrap(&mut service)?;
            let credentials = credentials(&mut service, &admin, kind, 2)?;
            if identity_denied {
                let first = login(&mut service, &credentials, None);
                assert_eq!(first.status, 200);
                let entity = first.body["auth"]["entity_id"].as_str().ok_or("entity")?;
                assert_eq!(
                    call(
                        &mut service,
                        "POST",
                        &format!("identity/entity/id/{entity}"),
                        &admin,
                        json!({"disabled":true})
                    )
                    .status,
                    204
                );
            }
            let before = service.current_state_digest().map_err(|_| "digest")?;
            service.record_writes_since_gc = 0;
            fs::rename(
                root.path.join("data/journal.hbj"),
                root.path.join("data/journal.saved"),
            )?;
            fs::create_dir(root.path.join("data/journal.hbj"))?;
            let failed = login(&mut service, &credentials, Some(60));
            assert_eq!(failed.status, 503);
            no_credentials(&failed);
            assert!(service.recovery_required);
            assert_eq!(
                service.current_state_digest().map_err(|_| "digest")?,
                before
            );
            assert_eq!(login(&mut service, &credentials, None).status, 503);
            drop(service);
            fs::remove_dir(root.path.join("data/journal.hbj"))?;
            fs::rename(
                root.path.join("data/journal.saved"),
                root.path.join("data/journal.hbj"),
            )?;
            let mut reopened = root.service()?;
            assert_eq!(
                call(&mut reopened, "POST", "sys/unseal", "", json!({"key":key})).status,
                200
            );
            assert_eq!(
                secret_info(&mut reopened, &admin, &credentials).body["data"]["secret_id_num_uses"],
                if identity_denied { 1 } else { 2 }
            );
        }
    }
    Ok(())
}

fn source_login(
    service: &mut Service,
    credentials: &Value,
    peer: Option<&str>,
    wrap: Option<u64>,
) -> Response {
    service.handle_at_mode(RequestDispatch {
        method: "POST",
        path: "auth/approle/login",
        namespace: "",
        token: "",
        body: credentials.clone(),
        now: 100,
        allow_forward: false,
        enforce_namespace: true,
        wrap_ttl_seconds: wrap,
        origin_peer: peer.and_then(|value| value.parse().ok()),
        client_certificates: None,
    })
}
fn configure_source(service: &mut Service, admin: &str) {
    assert_eq!(
        call(
            service,
            "POST",
            "auth/approle/role/example",
            admin,
            json!({"secret_id_bound_cidrs":["127.0.0.1/32"]})
        )
        .status,
        204
    );
}
#[test]
fn approle_role_source_denial_commits_only_finite_sid_consumption_and_survives_reopen() -> TestResult
{
    for kind in ["service", "batch"] {
        for uses in [0, 1, 2] {
            let root = Root::new();
            let mut service = root.service()?;
            let (key, admin) = bootstrap(&mut service)?;
            let credentials = credentials(&mut service, &admin, kind, uses)?;
            configure_source(&mut service, &admin);
            let auth = without_secret_ids(&service.state.as_ref().ok_or("state")?.auth)?;
            let engines =
                owner_store::serialize_owner(&service.state.as_ref().ok_or("state")?.engines)
                    .map_err(|_| "engines")?;
            service.record_writes_since_gc = 0;
            let denied = source_login(&mut service, &credentials, Some("127.0.0.2"), Some(60));
            assert_eq!(denied.status, 400);
            no_credentials(&denied);
            assert_eq!(
                service.record_writes_since_gc,
                if uses == 0 { 0 } else { 1 }
            );
            assert!(
                auth.as_slice()
                    == without_secret_ids(&service.state.as_ref().ok_or("state")?.auth)?.as_slice()
            );
            assert!(
                engines.as_slice()
                    == owner_store::serialize_owner(
                        &service.state.as_ref().ok_or("state")?.engines
                    )
                    .map_err(|_| "engines")?
                    .as_slice()
            );
            drop(service);
            let mut service = root.service()?;
            assert_eq!(
                call(&mut service, "POST", "sys/unseal", "", json!({"key":key})).status,
                200
            );
            let info = secret_info(&mut service, &admin, &credentials);
            if uses == 1 {
                assert_eq!(info.status, 204);
            } else {
                assert_eq!(info.status, 200);
                assert_eq!(
                    info.body["data"]["secret_id_num_uses"],
                    if uses == 0 { 0 } else { 1 }
                );
            }
            let allowed = source_login(&mut service, &credentials, Some("127.0.0.1"), None);
            if uses == 1 {
                assert_eq!(allowed.status, 400);
                no_credentials(&allowed);
            } else {
                assert_eq!(allowed.status, 200);
                assert_eq!(allowed.body["auth"]["token_type"], kind);
                // Role login restrictions never become issued-token constraints.
                let token = allowed.body["auth"]["client_token"]
                    .as_str()
                    .ok_or("token")?;
                assert!(
                    service
                        .state
                        .as_ref()
                        .ok_or("state")?
                        .auth
                        .authenticate_read_only_from(token, 100, Some("127.0.0.2".parse()?))?
                        .is_some()
                );
            }
        }
    }
    Ok(())
}
#[test]
fn approle_source_rejection_storage_failure_rolls_back_and_invalid_sid_does_not_consume()
-> TestResult {
    for kind in ["service", "batch"] {
        let root = Root::new();
        let mut service = root.service()?;
        let (_, admin) = bootstrap(&mut service)?;
        let credentials = credentials(&mut service, &admin, kind, 2)?;
        configure_source(&mut service, &admin);
        let before = service.current_state_digest().map_err(|_| "digest")?;
        let mut invalid = credentials.clone();
        invalid["secret_id"] = json!("not-the-secret");
        let denied = source_login(&mut service, &invalid, Some("127.0.0.2"), Some(60));
        assert_eq!(denied.status, 400);
        no_credentials(&denied);
        assert_eq!(
            service.current_state_digest().map_err(|_| "digest")?,
            before
        );
        let capacity = service.state_capacity;
        service.state_capacity = 1;
        let failed = source_login(&mut service, &credentials, Some("127.0.0.2"), Some(60));
        assert_eq!(failed.status, 507);
        no_credentials(&failed);
        assert_eq!(
            service.current_state_digest().map_err(|_| "digest")?,
            before
        );
        service.state_capacity = capacity;
        assert_eq!(
            secret_info(&mut service, &admin, &credentials).body["data"]["secret_id_num_uses"],
            2
        );
        let missing_peer = source_login(&mut service, &credentials, None, Some(60));
        assert_eq!(missing_peer.status, 500);
        no_credentials(&missing_peer);
        assert_eq!(
            secret_info(&mut service, &admin, &credentials).body["data"]["secret_id_num_uses"],
            1
        );
        assert_eq!(
            source_login(&mut service, &credentials, Some("127.0.0.1"), None).status,
            200
        );
        assert_eq!(secret_info(&mut service, &admin, &credentials).status, 204);
    }
    Ok(())
}
