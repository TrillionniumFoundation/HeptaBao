use super::records::{DurableReader, existing_plan};
use super::tests::{Root, bootstrap, call};
use super::*;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

fn artifacts(service: &Service) -> TestResult<Vec<[u8; 32]>> {
    ["state.hbs", "journal.hbj", "ledger.hbl"]
        .into_iter()
        .map(|name| {
            fs::read(service.data_dir.join(name))
                .map(|bytes| crypto::digest(&bytes))
                .map_err(Into::into)
        })
        .collect()
}
fn create(service: &mut Service, admin: &str) {
    assert_eq!(
        call(
            service,
            "POST",
            "auth/userpass/users/compare",
            admin,
            json!({"password":"a".repeat(72)})
        )
        .status,
        204
    );
}

#[test]
fn schema37_credentials_keep_absent_marker_on_read_reopen_and_successful_login() -> TestResult {
    let directory = Root::new();
    let mut service = directory.service()?;
    let (key, admin) = bootstrap(&mut service)?;
    create(&mut service, &admin);
    let mut old = service.state.clone().ok_or("state")?;
    let mut auth = serde_json::to_value(&old.auth)?;
    // Format fixture: old PBKDF2 over a valid72-byte credential has the same
    // verifier bytes but no comparison marker. Real old-binary upgrade is QA.
    auth["users"][""]["compare"]
        .as_object_mut()
        .ok_or("user")?
        .remove("password_semantics");
    auth["users"][""]["compare"]
        .as_object_mut()
        .ok_or("user")?
        .remove("token_policies_configured");
    auth["users"][""]["compare"]
        .as_object_mut()
        .ok_or("user")?
        .remove("token_no_default_policy");
    old.auth = serde_json::from_value::<AuthState>(auth)?.into();
    old.schema = 37;
    assert!(!old.auth.has_userpass_password_semantics());
    assert!(old.validate_format().is_ok());
    service
        .commit_state(&old)
        .map_err(|_| "legacy publication")?;
    service.state = Some(old);
    drop(service);
    let mut service = directory.service()?;
    assert_eq!(
        call(&mut service, "PUT", "sys/unseal", "", json!({"key":key})).status,
        200
    );
    assert_eq!(service.state.as_ref().ok_or("state")?.schema, 37);
    let before = artifacts(&service)?;
    assert_eq!(
        call(
            &mut service,
            "GET",
            "auth/userpass/users/compare",
            &admin,
            json!({})
        )
        .status,
        200
    );
    assert_eq!(artifacts(&service)?, before);
    assert_eq!(service.state.as_ref().ok_or("state")?.schema, 37);
    assert_eq!(
        call(
            &mut service,
            "POST",
            "auth/userpass/login/compare",
            "",
            json!({"password":"a".repeat(73)})
        )
        .status,
        400
    );
    assert_eq!(service.state.as_ref().ok_or("state")?.schema, 37);
    assert_eq!(
        call(
            &mut service,
            "POST",
            "auth/userpass/login/compare",
            "",
            json!({"password":"a".repeat(72)})
        )
        .status,
        200
    );
    // Issuing a token is a normal mutation and advances the state schema;
    // it must never reinterpret the account's historical credential.
    assert_eq!(
        service.state.as_ref().ok_or("state")?.schema,
        CURRENT_STATE_SCHEMA
    );
    assert!(
        !service
            .state
            .as_ref()
            .ok_or("state")?
            .auth
            .has_userpass_password_semantics()
    );
    assert_eq!(
        call(
            &mut service,
            "POST",
            "auth/userpass/users/compare/password",
            &admin,
            json!({"password":"a".repeat(72)})
        )
        .status,
        204
    );
    assert!(
        service
            .state
            .as_ref()
            .ok_or("state")?
            .auth
            .has_userpass_password_semantics()
    );
    assert_eq!(
        call(
            &mut service,
            "POST",
            "auth/userpass/login/compare",
            "",
            json!({"password":"a".repeat(1025)})
        )
        .status,
        200
    );
    Ok(())
}

#[test]
fn marked_credentials_cannot_hide_under_schema37_at_commit_restore_or_reopen() -> TestResult {
    let directory = Root::new();
    let mut service = directory.service()?;
    let (key, admin) = bootstrap(&mut service)?;
    create(&mut service, &admin);
    let mut downgraded = service.state.clone().ok_or("state")?;
    assert!(downgraded.auth.has_userpass_password_semantics());
    downgraded.schema = 37;
    assert_eq!(
        downgraded
            .validate_format()
            .err()
            .ok_or("format gate")?
            .status,
        503
    );
    let generation = service.durable.as_ref().ok_or("durable")?.generation();
    assert_eq!(
        service
            .commit_state(&downgraded)
            .err()
            .ok_or("commit gate")?
            .status,
        503
    );
    assert_eq!(
        service.durable.as_ref().ok_or("durable")?.generation(),
        generation
    );
    let bad = service
        .prepare_record_plan(&downgraded)
        .map_err(|_| "fixture root")?;
    assert!(
        Service::materialize_record_state(
            &bad.root,
            &DurableReader(service.durable.as_ref().ok_or("durable")?)
        )
        .is_err()
    );
    // Test-only authenticated root corruption. Existing owner objects are
    // valid and present, so failure must be the schema/payload admission gate.
    let bad = existing_plan(bad.root).map_err(|_| "fixture plan")?;
    Service::persist_record_batch(
        service.durable.as_mut().ok_or("durable")?,
        &bad,
        "password-schema-spoof",
    )?;
    let before = artifacts(&service)?;
    let durable = service.durable.as_ref().ok_or("durable")?;
    let backup = durable.export_backup()?;
    let generation = durable.generation();
    assert_eq!(
        service
            .prepare_snapshot_restore(&backup)
            .err()
            .ok_or("restore gate")?
            .status,
        400
    );
    assert_eq!(
        service.durable.as_ref().ok_or("durable")?.generation(),
        generation
    );
    assert_eq!(artifacts(&service)?, before);
    drop(service);
    let mut service = directory.service()?;
    assert_eq!(
        call(&mut service, "PUT", "sys/unseal", "", json!({"key":key})).status,
        503
    );
    assert!(service.state.is_none());
    // The replay ledger may be reauthenticated on open; authority files may not change.
    assert_eq!(artifacts(&service)?[..2], before[..2]);
    Ok(())
}
