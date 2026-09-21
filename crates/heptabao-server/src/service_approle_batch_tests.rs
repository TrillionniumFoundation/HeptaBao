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

fn restricted_secret_credentials(
    service: &mut Service,
    admin: &str,
    kind: &str,
    uses: u64,
) -> Result<Value, Box<dyn std::error::Error>> {
    let mut credentials = credentials(service, admin, kind, uses)?;
    let sid = call(
        service,
        "POST",
        "auth/approle/role/example/secret-id",
        admin,
        json!({"cidr_list":["127.0.0.1/32"],"token_bound_cidrs":["127.0.0.2/32"]}),
    );
    assert_eq!(sid.status, 200);
    credentials["secret_id"] = sid.body["data"]["secret_id"].clone();
    Ok(credentials)
}

fn metadata_gate_rejects46(state: &State) -> Result<(), Box<dyn std::error::Error>> {
    let mut state = state.clone();
    assert_eq!(state.schema, CURRENT_STATE_SCHEMA);
    state.schema = 47;
    state
        .validate_format()
        .map_err(|_| "minimum metadata format")?;
    state.schema = 46;
    let response = state
        .validate_format()
        .err()
        .ok_or("missing metadata gate")?;
    assert_eq!(response.status, 503);
    assert_eq!(
        response.body["errors"][0],
        "AppRole credential or alias metadata requires schema 47"
    );
    Ok(())
}

#[test]
fn approle_sid_metadata_presence_requires47_while_absent46_reopen_and_reads_preserve_bytes()
-> TestResult {
    for metadata in [Value::Null, json!("{}"), json!(r#"{"env":"one"}"#)] {
        let root = Root::new();
        let mut service = root.service()?;
        let (key, admin) = bootstrap(&mut service)?;
        let credentials = credentials(&mut service, &admin, "service", 0)?;
        let mut old = service.state.clone().ok_or("state")?;
        assert!(!old.auth.has_approle_metadata());
        old.schema = 46;
        old.validate_format().map_err(|_| "old format")?;
        let before = owner_store::serialize_owner(&old.auth).map_err(|_| "encode")?;
        service.commit_state(&old).map_err(|_| "old fixture")?;
        drop(service);
        let mut service = root.service()?;
        assert_eq!(
            call(&mut service, "POST", "sys/unseal", "", json!({"key":key})).status,
            200
        );
        let info = secret_info(&mut service, &admin, &credentials);
        assert_eq!(info.status, 200);
        assert_eq!(info.body["data"]["metadata"], json!({}));
        let unchanged = service.state.as_ref().ok_or("state")?;
        assert_eq!(unchanged.schema, 46);
        assert!(
            before.as_slice()
                == owner_store::serialize_owner(&unchanged.auth)
                    .map_err(|_| "encode")?
                    .as_slice(),
            "read changed the auth owner"
        );
        assert_eq!(
            call(
                &mut service,
                "POST",
                "auth/approle/role/example/secret-id",
                &admin,
                json!({"metadata":metadata})
            )
            .status,
            200
        );
        let state = service.state.as_ref().ok_or("state")?;
        assert!(state.auth.has_approle_metadata());
        assert!(!state.engines.has_extended_login_alias_metadata_state());
        metadata_gate_rejects46(state)?;
    }
    Ok(())
}

#[test]
fn approle_issued_metadata_and_retained_extended_alias_require47() -> TestResult {
    for kind in ["service", "batch"] {
        let root = Root::new();
        let mut service = root.service()?;
        let (_, admin) = bootstrap(&mut service)?;
        let mut creds = credentials(&mut service, &admin, kind, 1)?;
        if kind == "batch" {
            // Native creation validates a fresh alias more narrowly than a
            // later backend metadata update. First establish that alias using
            // the legacy None SID, consuming its sole use.
            assert_eq!(source_login(&mut service, &creds, None, None).status, 200);
            assert_eq!(secret_info(&mut service, &admin, &creds).status, 204);
            let wide: BTreeMap<String, String> = (0..65)
                .map(|index| (format!("key-{index}"), "value".into()))
                .collect();
            let issued = call(
                &mut service,
                "POST",
                "auth/approle/role/example/secret-id",
                &admin,
                json!({"metadata":serde_json::to_string(&wide)?}),
            );
            assert_eq!(issued.status, 200);
            creds["secret_id"] = issued.body["data"]["secret_id"].clone();
        }
        let accepted = source_login(&mut service, &creds, None, None);
        assert_eq!(accepted.status, 200);
        assert_eq!(secret_info(&mut service, &admin, &creds).status, 204);
        let state = service.state.as_ref().ok_or("state")?;
        assert_eq!(state.auth.has_approle_metadata(), kind == "service");
        assert_eq!(
            state.engines.has_extended_login_alias_metadata_state(),
            kind == "batch"
        );
        metadata_gate_rejects46(state)?;
        if kind == "batch" {
            assert_eq!(
                call(
                    &mut service,
                    "DELETE",
                    "sys/auth/approle",
                    &admin,
                    json!({})
                )
                .status,
                204
            );
            let retained = service.state.as_ref().ok_or("state")?;
            assert!(!retained.auth.has_approle_metadata());
            assert!(retained.engines.has_extended_login_alias_metadata_state());
            metadata_gate_rejects46(retained)?;
        }
    }
    Ok(())
}

#[test]
fn approle_issued_metadata_without_identity_state_independently_requires47() -> TestResult {
    let root = Root::new();
    let mut service = root.service()?;
    let (_, admin) = bootstrap(&mut service)?;
    let creds = credentials(&mut service, &admin, "service", 1)?;
    let mut fixture = service.state.clone().ok_or("state")?;
    // Isolate the Auth producer: normal Service completion also creates an
    // AppRole alias, which would otherwise mask this independent token gate.
    let accepted = fixture
        .auth
        .handle(None, "", "POST", "auth/approle/login", &creds, 100)?
        .ok_or("auth route")?;
    assert_eq!(accepted.status, 200);
    assert!(fixture.auth.has_approle_metadata());
    assert!(!fixture.engines.has_login_alias_metadata_state());
    metadata_gate_rejects46(&fixture)?;
    Ok(())
}

#[test]
fn approle_small_retained_alias_metadata_requires47_after_credential_cleanup_and_reopen()
-> TestResult {
    for kind in ["service", "batch"] {
        let root = Root::new();
        let mut service = root.service()?;
        let (key, admin) = bootstrap(&mut service)?;
        let creds = credentials(&mut service, &admin, kind, 1)?;
        assert_eq!(login(&mut service, &creds, None).status, 200);
        assert_eq!(secret_info(&mut service, &admin, &creds).status, 204);
        assert_eq!(
            call(
                &mut service,
                "DELETE",
                "sys/auth/approle",
                &admin,
                json!({})
            )
            .status,
            204
        );
        let retained = service.state.as_ref().ok_or("state")?;
        assert!(!retained.auth.has_approle_metadata());
        assert!(!retained.engines.has_extended_login_alias_metadata_state());
        assert!(retained.engines.has_approle_login_alias_metadata_state());
        metadata_gate_rejects46(retained)?;
        let before = owner_store::serialize_owner(&retained.engines).map_err(|_| "encode")?;
        drop(service);
        let mut reopened = root.service()?;
        assert_eq!(
            call(&mut reopened, "POST", "sys/unseal", "", json!({"key":key})).status,
            200
        );
        let retained = reopened.state.as_ref().ok_or("state")?;
        metadata_gate_rejects46(retained)?;
        assert!(
            before.as_slice()
                == owner_store::serialize_owner(&retained.engines)
                    .map_err(|_| "encode")?
                    .as_slice()
        );
    }
    Ok(())
}

#[test]
fn legacy_jwt_backend_and_admin_role_name_custom_metadata_remain_schema46_readable() -> TestResult {
    let root = Root::new();
    let mut service = root.service()?;
    bootstrap(&mut service)?;
    let mut fixture = service.state.clone().ok_or("state")?;
    fixture
        .engines
        .bind_login_identity("", "auth_jwt", "subject", 100)?;
    fixture.engines.update_login_alias_metadata(
        "",
        "auth_jwt",
        "subject",
        &BTreeMap::from([("role".into(), "role_name".into())]),
        100,
    )?;
    // This unit fixture deliberately adds only administrative metadata. It is
    // not an old-binary migration fixture or externally observed evidence.
    let mut wire = serde_json::to_value(&fixture.engines)?;
    let aliases = wire["namespaces"][""]["identity"]["aliases"]
        .as_object_mut()
        .ok_or("aliases")?;
    for alias in aliases.values_mut() {
        alias["custom_metadata"] = json!({"role_name":"administrator"});
    }
    fixture.engines = serde_json::from_value(wire)?;
    fixture.engines.restore_pre47_identity_metadata_for_test();
    assert!(fixture.engines.has_login_alias_metadata_state());
    assert!(!fixture.engines.has_approle_login_alias_metadata_state());
    assert!(!fixture.engines.has_extended_login_alias_metadata_state());
    fixture.schema = 46;
    fixture.validate_format().map_err(|_| "legacy format")?;
    Ok(())
}

#[test]
fn approle_sid_source_and_subset_denials_persist_only_consumption_and_reopen() -> TestResult {
    for kind in ["service", "batch"] {
        for uses in [0, 1, 2] {
            for subset_denied in [false, true] {
                let root = Root::new();
                let mut service = root.service()?;
                let (key, admin) = bootstrap(&mut service)?;
                let credentials = restricted_secret_credentials(&mut service, &admin, kind, uses)?;
                if subset_denied {
                    assert_eq!(
                        call(
                            &mut service,
                            "POST",
                            "auth/approle/role/example",
                            &admin,
                            json!({"secret_id_bound_cidrs":["127.0.0.2/32"]})
                        )
                        .status,
                        204
                    );
                }
                let auth_before = without_secret_ids(&service.state.as_ref().ok_or("state")?.auth)?;
                let engine_before =
                    owner_store::serialize_owner(&service.state.as_ref().ok_or("state")?.engines)
                        .map_err(|_| "engine")?;
                service.record_writes_since_gc = 0;
                let rejected =
                    source_login(&mut service, &credentials, Some("127.0.0.2"), Some(60));
                assert_eq!(rejected.status, if subset_denied { 500 } else { 400 });
                no_credentials(&rejected);
                assert_eq!(
                    service.record_writes_since_gc,
                    if uses == 0 { 0 } else { 1 }
                );
                assert!(
                    auth_before.as_slice()
                        == without_secret_ids(&service.state.as_ref().ok_or("state")?.auth)?
                            .as_slice()
                );
                assert!(
                    engine_before.as_slice()
                        == owner_store::serialize_owner(
                            &service.state.as_ref().ok_or("state")?.engines
                        )
                        .map_err(|_| "engine")?
                        .as_slice()
                );
                drop(service);
                let mut reopened = root.service()?;
                assert_eq!(
                    call(&mut reopened, "POST", "sys/unseal", "", json!({"key":key})).status,
                    200
                );
                let info = secret_info(&mut reopened, &admin, &credentials);
                if uses == 1 {
                    assert_eq!(info.status, 204);
                } else {
                    assert_eq!(
                        info.body["data"]["secret_id_num_uses"],
                        if uses == 0 { 0 } else { 1 }
                    );
                    assert_eq!(info.body["data"]["cidr_list"], json!(["127.0.0.1/32"]));
                    assert_eq!(
                        info.body["data"]["token_bound_cidrs"],
                        json!(["127.0.0.2/32"])
                    );
                    assert_eq!(
                        call(
                            &mut reopened,
                            "POST",
                            "auth/approle/role/example",
                            &admin,
                            json!({"secret_id_bound_cidrs":[]})
                        )
                        .status,
                        204
                    );
                    let accepted =
                        source_login(&mut reopened, &credentials, Some("127.0.0.1"), None);
                    assert_eq!(accepted.status, 200);
                    assert_eq!(accepted.body["auth"]["token_type"], kind);
                    let raw = accepted.body["auth"]["client_token"]
                        .as_str()
                        .ok_or("token")?;
                    let auth = &reopened.state.as_ref().ok_or("state")?.auth;
                    assert!(
                        auth.authenticate_read_only_from(raw, 100, Some("127.0.0.1".parse()?))
                            .is_err()
                    );
                    assert!(
                        auth.authenticate_read_only_from(raw, 100, Some("127.0.0.2".parse()?))?
                            .is_some()
                    );
                }
            }
        }
    }
    Ok(())
}

#[test]
fn approle_sid_rejection_capacity_and_unknown_storage_outcomes_never_publish_credentials()
-> TestResult {
    for kind in ["service", "batch"] {
        let root = Root::new();
        let mut service = root.service()?;
        let (key, admin) = bootstrap(&mut service)?;
        let credentials = restricted_secret_credentials(&mut service, &admin, kind, 2)?;
        let before = service.current_state_digest().map_err(|_| "digest")?;
        let mut invalid = credentials.clone();
        invalid["secret_id"] = json!("wrong-secret");
        assert_eq!(
            source_login(&mut service, &invalid, Some("127.0.0.2"), None).status,
            400
        );
        assert_eq!(
            service.current_state_digest().map_err(|_| "digest")?,
            before
        );
        let capacity = service.state_capacity;
        service.state_capacity = 1;
        let rejected = source_login(&mut service, &credentials, Some("127.0.0.2"), Some(60));
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
        service.record_writes_since_gc = 0;
        fs::rename(
            root.path.join("data/journal.hbj"),
            root.path.join("data/journal.saved"),
        )?;
        fs::create_dir(root.path.join("data/journal.hbj"))?;
        let failed = source_login(&mut service, &credentials, Some("127.0.0.2"), Some(60));
        assert_eq!(failed.status, 503);
        no_credentials(&failed);
        assert!(service.recovery_required);
        assert_eq!(
            service.current_state_digest().map_err(|_| "digest")?,
            before
        );
        assert_eq!(
            source_login(&mut service, &credentials, Some("127.0.0.1"), None).status,
            503
        );
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
            2
        );
    }
    Ok(())
}

fn metadata_credentials(
    service: &mut Service,
    admin: &str,
    kind: &str,
    metadata: &str,
) -> Result<Value, Box<dyn std::error::Error>> {
    let mut credential = credentials(service, admin, kind, 3)?;
    let sid = call(
        service,
        "POST",
        "auth/approle/role/example/secret-id",
        admin,
        json!({"metadata":metadata}),
    );
    assert_eq!(sid.status, 200);
    credential["secret_id"] = sid.body["data"]["secret_id"].clone();
    Ok(credential)
}

#[test]
fn approle_metadata_identity_is_live_but_issued_snapshots_survive_sid_destroy_and_reopen()
-> TestResult {
    for kind in ["service", "batch"] {
        let root = Root::new();
        let mut service = root.service()?;
        let (key, admin) = bootstrap(&mut service)?;
        let first_credentials = metadata_credentials(
            &mut service,
            &admin,
            kind,
            r#"{"env":"one","role_name":"spoofed"}"#,
        )?;
        let first = login(&mut service, &first_credentials, None);
        assert_eq!(first.status, 200);
        let expected = json!({"env":"one","role_name":"example"});
        assert_eq!(first.body["auth"]["metadata"], expected);
        let raw = zeroize::Zeroizing::new(
            first.body["auth"]["client_token"]
                .as_str()
                .ok_or("token")?
                .to_owned(),
        );
        let accessor = first.body["auth"]["accessor"].clone();
        let entity = first.body["auth"]["entity_id"]
            .as_str()
            .ok_or("entity")?
            .to_owned();
        let description = call(
            &mut service,
            "GET",
            &format!("identity/entity/id/{entity}"),
            &admin,
            json!({}),
        );
        let alias = &description.body["data"]["aliases"][0];
        assert_eq!(alias["metadata"], expected);
        assert_eq!(call(&mut service, "POST", &format!("identity/entity-alias/id/{}", alias["id"].as_str().ok_or("alias")?), &admin,
            json!({"name":alias["name"],"canonical_id":entity,"mount_accessor":alias["mount_accessor"],"custom_metadata":{"owner":"control"}})).status, 200);
        let second_credentials =
            metadata_credentials(&mut service, &admin, kind, r#"{"env":"two"}"#)?;
        let second = login(&mut service, &second_credentials, None);
        assert_eq!(second.status, 200);
        assert_eq!(second.body["auth"]["entity_id"], entity);
        assert_eq!(
            secret_info(&mut service, &admin, &first_credentials).body["data"]["metadata"]["role_name"],
            "spoofed"
        );
        assert_eq!(
            call(
                &mut service,
                "POST",
                "auth/approle/role/example/secret-id/destroy",
                &admin,
                json!({"secret_id":first_credentials["secret_id"]})
            )
            .status,
            204
        );
        assert_eq!(
            call(
                &mut service,
                "POST",
                "auth/approle/role/example",
                &admin,
                json!({"token_ttl":90})
            )
            .status,
            204
        );
        drop(service);
        let mut service = root.service()?;
        assert_eq!(
            call(&mut service, "POST", "sys/unseal", "", json!({"key":key})).status,
            200
        );
        let lookup = call(
            &mut service,
            "POST",
            "auth/token/lookup",
            &admin,
            json!({"token":raw.as_str()}),
        );
        assert_eq!(lookup.status, 200);
        assert_eq!(lookup.body["data"]["meta"], expected);
        let description = call(
            &mut service,
            "GET",
            &format!("identity/entity/id/{entity}"),
            &admin,
            json!({}),
        );
        assert_eq!(
            description.body["data"]["aliases"][0]["metadata"],
            json!({"env":"two","role_name":"example"})
        );
        assert_eq!(
            description.body["data"]["aliases"][0]["custom_metadata"],
            json!({"owner":"control"})
        );
        if kind == "service" {
            for (path, actor, body) in [
                ("auth/token/renew-self", raw.as_str(), json!({})),
                (
                    "auth/token/renew",
                    admin.as_str(),
                    json!({"token":raw.as_str()}),
                ),
                (
                    "auth/token/renew-accessor",
                    admin.as_str(),
                    json!({"accessor":accessor}),
                ),
            ] {
                let renewed = call(&mut service, "POST", path, actor, body);
                assert_eq!(renewed.status, 200);
                assert_eq!(renewed.body["auth"]["metadata"], expected);
            }
        }
    }
    Ok(())
}

#[test]
fn approle_metadata_source_denial_preserves_alias_but_disabled_identity_refreshes_only_metadata()
-> TestResult {
    for kind in ["service", "batch"] {
        for identity_denied in [false, true] {
            for uses in [0, 3] {
                let root = Root::new();
                let mut service = root.service()?;
                let (key, admin) = bootstrap(&mut service)?;
                let credentials =
                    metadata_credentials(&mut service, &admin, kind, r#"{"env":"original"}"#)?;
                let first = login(&mut service, &credentials, None);
                assert_eq!(first.status, 200);
                assert_eq!(
                    call(
                        &mut service,
                        "POST",
                        "auth/approle/role/example",
                        &admin,
                        json!({"secret_id_num_uses":uses})
                    )
                    .status,
                    204
                );
                let issued = call(
                    &mut service,
                    "POST",
                    "auth/approle/role/example/secret-id",
                    &admin,
                    json!({"metadata":r#"{"env":"next"}"#}),
                );
                assert_eq!(issued.status, 200);
                let next = json!({"role_id":credentials["role_id"], "secret_id":issued.body["data"]["secret_id"]});
                let entity = first.body["auth"]["entity_id"].as_str().ok_or("entity")?;
                let description = call(
                    &mut service,
                    "GET",
                    &format!("identity/entity/id/{entity}"),
                    &admin,
                    json!({}),
                );
                let alias = &description.body["data"]["aliases"][0];
                let aid = alias["id"].as_str().ok_or("alias")?;
                assert_eq!(call(&mut service, "POST", &format!("identity/entity-alias/id/{aid}"), &admin,
                json!({"name":alias["name"],"canonical_id":entity,"mount_accessor":alias["mount_accessor"],
                    "custom_metadata":{"owner":"control"}})).status, 200);
                if identity_denied {
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
                } else {
                    assert_eq!(
                        call(
                            &mut service,
                            "POST",
                            "auth/approle/role/example",
                            &admin,
                            json!({"secret_id_bound_cidrs":["127.0.0.1/32"]})
                        )
                        .status,
                        204
                    );
                }
                let before = without_secret_ids(&service.state.as_ref().ok_or("state")?.auth)?;
                let mut expected_engines =
                    serde_json::to_value(&service.state.as_ref().ok_or("state")?.engines)?;
                if identity_denied {
                    // Only this persisted alias field may change. All requests in
                    // this fixture use time100, so its existing timestamp is100.
                    expected_engines["namespaces"][""]["identity"]["aliases"][aid]["login_metadata"] =
                        json!({"env":"next","role_name":"example"});
                }
                let failed = source_login(&mut service, &next, Some("127.0.0.2"), Some(60));
                assert_eq!(failed.status, if identity_denied { 403 } else { 400 });
                no_credentials(&failed);
                assert_eq!(
                    secret_info(&mut service, &admin, &next).body["data"]["secret_id_num_uses"],
                    if uses == 0 { 0 } else { 2 }
                );
                assert!(
                    before.as_slice()
                        == without_secret_ids(&service.state.as_ref().ok_or("state")?.auth)?
                            .as_slice()
                );
                assert!(
                    serde_json::to_value(&service.state.as_ref().ok_or("state")?.engines)?
                        == expected_engines
                );
                drop(service);
                let mut reopened = root.service()?;
                assert_eq!(
                    call(&mut reopened, "POST", "sys/unseal", "", json!({"key":key})).status,
                    200
                );
                assert!(
                    serde_json::to_value(&reopened.state.as_ref().ok_or("state")?.engines)?
                        == expected_engines
                );
                assert!(
                    before.as_slice()
                        == without_secret_ids(&reopened.state.as_ref().ok_or("state")?.auth)?
                            .as_slice()
                );
            }
        }
    }
    Ok(())
}

#[test]
fn approle_metadata_token_api_children_do_not_inherit_issuer_metadata() -> TestResult {
    let root = Root::new();
    let mut service = root.service()?;
    let (_, admin) = bootstrap(&mut service)?;
    assert_eq!(call(&mut service, "PUT", "sys/policies/acl/metadata-child", &admin,
        json!({"policy":"path \"auth/token/create\" { capabilities = [\"update\"] } path \"auth/token/create-orphan\" { capabilities = [\"update\",\"sudo\"] }"})).status, 204);
    let credential = metadata_credentials(&mut service, &admin, "service", r#"{"env":"parent"}"#)?;
    assert_eq!(
        call(
            &mut service,
            "POST",
            "auth/approle/role/example",
            &admin,
            json!({"token_policies":["metadata-child"]})
        )
        .status,
        204
    );
    let parent = login(&mut service, &credential, None);
    assert_eq!(parent.status, 200);
    let raw = parent.body["auth"]["client_token"]
        .as_str()
        .ok_or("token")?;
    for path in ["auth/token/create", "auth/token/create-orphan"] {
        let child = call(&mut service, "POST", path, raw, json!({"ttl":30}));
        assert_eq!(child.status, 200);
        assert!(
            child.body["auth"]["metadata"]
                .as_object()
                .is_none_or(|map| map.is_empty())
        );
        let lookup = call(
            &mut service,
            "POST",
            "auth/token/lookup",
            &admin,
            json!({"token":child.body["auth"]["client_token"]}),
        );
        assert_eq!(lookup.status, 200);
        assert!(
            lookup.body["data"]["meta"]
                .as_object()
                .is_none_or(|map| map.is_empty())
        );
    }
    Ok(())
}

#[test]
fn approle_large_batch_metadata_fails_atomically_and_consumes_only_the_verified_sid() -> TestResult
{
    let root = Root::new();
    let mut service = root.service()?;
    let (_, admin) = bootstrap(&mut service)?;
    // Upstream fresh-alias metadata limits are narrower than updates.
    let initial = credentials(&mut service, &admin, "batch", 1)?;
    assert_eq!(login(&mut service, &initial, None).status, 200);
    let metadata = format!("env={}", "x".repeat(9000));
    let credentials = metadata_credentials(&mut service, &admin, "batch", &metadata)?;
    let before = without_secret_ids(&service.state.as_ref().ok_or("state")?.auth)?;
    let engines = owner_store::serialize_owner(&service.state.as_ref().ok_or("state")?.engines)
        .map_err(|_| "engines")?;
    let failed = login(&mut service, &credentials, Some(60));
    assert_eq!(failed.status, 503);
    no_credentials(&failed);
    assert_eq!(
        secret_info(&mut service, &admin, &credentials).body["data"]["secret_id_num_uses"],
        2
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
    Ok(())
}

#[test]
fn approle_extended_metadata_reaches_service_batch_and_alias_without_truncation() -> TestResult {
    for kind in ["service", "batch"] {
        let root = Root::new();
        let mut service = root.service()?;
        let (_, admin) = bootstrap(&mut service)?;
        // Upstream fresh-alias metadata limits are narrower than updates.
        let initial = credentials(&mut service, &admin, kind, 1)?;
        assert_eq!(login(&mut service, &initial, None).status, 200);
        let mut fields: std::collections::BTreeMap<String, String> =
            (0..65).map(|i| (format!("key-{i}"), "v".into())).collect();
        fields.insert("".into(), "".into());
        fields.insert("k".repeat(129), "v".repeat(1025));
        fields.insert("unicode".into(), "名字\n\t".into());
        let input = serde_json::to_string(&fields)?;
        let credential = metadata_credentials(&mut service, &admin, kind, &input)?;
        let response = login(&mut service, &credential, Some(60));
        assert_eq!(response.status, 200);
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
        fields.insert("role_name".into(), "example".into());
        assert_eq!(inner.body["auth"]["metadata"], json!(fields));
        let entity = inner.body["auth"]["entity_id"].as_str().ok_or("entity")?;
        let description = call(
            &mut service,
            "GET",
            &format!("identity/entity/id/{entity}"),
            &admin,
            json!({}),
        );
        assert_eq!(
            description.body["data"]["aliases"][0]["metadata"],
            json!(fields)
        );
        assert!(
            service
                .state
                .as_ref()
                .ok_or("state")?
                .engines
                .has_extended_login_alias_metadata_state()
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
    }
    Ok(())
}

#[test]
fn fresh_alias_metadata_failure_consumes_sid_only_and_reopen_preserves_rejection() -> TestResult {
    let invalid = [
        json!({"":"v"}),
        json!({"vault-private":"v"}),
        json!({"not.allowed":"v"}),
        json!({"k".repeat(129):"v"}),
        json!({"key":"v".repeat(513)}),
        // The backend adds role_name, taking this map from 64 to 65 entries.
        serde_json::to_value(
            (0..64)
                .map(|i| (format!("k{i}"), "v".to_owned()))
                .collect::<std::collections::BTreeMap<_, _>>(),
        )?,
    ];
    for kind in ["service", "batch"] {
        for metadata in &invalid {
            let root = Root::new();
            let mut service = root.service()?;
            let (key, admin) = bootstrap(&mut service)?;
            let credentials = metadata_credentials(
                &mut service,
                &admin,
                kind,
                &serde_json::to_string(metadata)?,
            )?;
            let before = without_secret_ids(&service.state.as_ref().ok_or("state")?.auth)?;
            let engines =
                owner_store::serialize_owner(&service.state.as_ref().ok_or("state")?.engines)
                    .map_err(|_| "engines")?;
            let rejected = login(&mut service, &credentials, Some(60));
            assert_eq!(rejected.status, 500);
            no_credentials(&rejected);
            assert_eq!(
                secret_info(&mut service, &admin, &credentials).body["data"]["secret_id_num_uses"],
                2
            );
            let state = service.state.as_ref().ok_or("state")?;
            assert!(
                before.as_slice() == without_secret_ids(&state.auth)?.as_slice(),
                "fresh alias rejection published Auth changes beyond SID consumption"
            );
            assert!(
                engines.as_slice()
                    == owner_store::serialize_owner(&state.engines)
                        .map_err(|_| "engines")?
                        .as_slice(),
                "fresh alias rejection published Identity"
            );
            drop(service);
            let mut service = root.service()?;
            assert_eq!(
                call(&mut service, "POST", "sys/unseal", "", json!({"key":key})).status,
                200
            );
            assert_eq!(
                secret_info(&mut service, &admin, &credentials).body["data"]["secret_id_num_uses"],
                2
            );
            let state = service.state.as_ref().ok_or("state")?;
            assert!(
                before.as_slice() == without_secret_ids(&state.auth)?.as_slice(),
                "reopen revealed Auth changes beyond SID consumption"
            );
            assert!(
                engines.as_slice()
                    == owner_store::serialize_owner(&state.engines)
                        .map_err(|_| "engines")?
                        .as_slice(),
                "reopen revealed rejected Identity"
            );
        }
    }
    Ok(())
}

#[test]
fn fresh_alias_allows_control_values_and_existing_alias_accepts_reserved_key_update() -> TestResult
{
    for kind in ["service", "batch"] {
        let root = Root::new();
        let mut service = root.service()?;
        let (_, admin) = bootstrap(&mut service)?;
        let first = metadata_credentials(
            &mut service,
            &admin,
            kind,
            &serde_json::to_string(&json!({"safe":"\0\n\t\r"}))?,
        )?;
        let issued = login(&mut service, &first, None);
        assert_eq!(issued.status, 200);
        assert_eq!(issued.body["auth"]["metadata"]["safe"], "\0\n\t\r");
        let entity = issued.body["auth"]["entity_id"]
            .as_str()
            .ok_or("entity")?
            .to_owned();
        let next = metadata_credentials(
            &mut service,
            &admin,
            kind,
            r#"{"vault-private":"existing"}"#,
        )?;
        let issued = login(&mut service, &next, None);
        assert_eq!(issued.status, 200);
        assert_eq!(issued.body["auth"]["entity_id"], entity);
        let read = call(
            &mut service,
            "GET",
            &format!("identity/entity/id/{entity}"),
            &admin,
            json!({}),
        );
        assert_eq!(
            read.body["data"]["aliases"][0]["metadata"]["vault-private"],
            "existing"
        );
    }
    Ok(())
}
