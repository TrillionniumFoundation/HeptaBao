use super::records::{DurableReader, existing_plan};
use super::tests::{Root, bootstrap, call};
use super::*;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

#[test]
fn bcrypt_import_alone_requires38_and_survives_authenticated_reopen_and_backup() -> TestResult {
    let directory = Root::new();
    let mut service = directory.service()?;
    let (key, admin) = bootstrap(&mut service)?;
    let hashed = Zeroizing::new(
        bcrypt::hash_with_salt("imported credential", 5, [7; 16])?
            .format_for_version(bcrypt::Version::TwoB),
    );
    assert_eq!(
        call(
            &mut service,
            "POST",
            "auth/userpass/users/imported",
            &admin,
            json!({"password_hash":hashed.as_str()})
        )
        .status,
        204
    );
    let state = service.state.as_ref().ok_or("state")?;
    let encoded = serde_json::to_value(&state.auth)?;
    assert!(
        encoded["users"][""]["imported"]
            .get("password_semantics")
            .is_none()
    );
    assert_eq!(encoded["users"][""]["imported"]["rounds"], 0);
    assert!(state.auth.has_userpass_password_semantics());
    let read = call(
        &mut service,
        "GET",
        "auth/userpass/users/imported",
        &admin,
        json!({}),
    );
    assert!(!serde_json::to_string(&read.body)?.contains(hashed.as_str()));
    let issued = call(
        &mut service,
        "POST",
        "auth/userpass/login/imported",
        "",
        json!({"password":"imported credential"}),
    );
    assert_eq!(issued.status, 200);
    let token = issued.body["auth"]["client_token"]
        .as_str()
        .ok_or("token")?
        .to_owned();
    let backup = service.durable.as_ref().ok_or("durable")?.export_backup()?;
    assert!(service.prepare_snapshot_restore(&backup).is_ok());
    drop(service);
    let mut service = directory.service()?;
    assert_eq!(
        call(&mut service, "PUT", "sys/unseal", "", json!({"key":key})).status,
        200
    );
    assert_eq!(
        call(
            &mut service,
            "GET",
            "auth/token/lookup-self",
            &token,
            json!({})
        )
        .status,
        200
    );
    assert_eq!(
        call(
            &mut service,
            "POST",
            "auth/userpass/login/imported",
            "",
            json!({"password":"imported credential"})
        )
        .status,
        200
    );
    let mut downgraded = service.state.clone().ok_or("state")?;
    downgraded.auth.remove_name_modes_for_legacy_format_test();
    downgraded.schema = 37;
    assert_eq!(
        downgraded.validate_format().err().ok_or("gate")?.status,
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
    let bad = existing_plan(bad.root).map_err(|_| "fixture plan")?;
    Service::persist_record_batch(
        service.durable.as_mut().ok_or("durable")?,
        &bad,
        "bcrypt-schema-spoof",
    )?;
    let before = [
        fs::read(service.data_dir.join("state.hbs"))?,
        fs::read(service.data_dir.join("journal.hbj"))?,
    ];
    let backup = service.durable.as_ref().ok_or("durable")?.export_backup()?;
    assert_eq!(
        service
            .prepare_snapshot_restore(&backup)
            .err()
            .ok_or("restore gate")?
            .status,
        400
    );
    drop(service);
    let mut service = directory.service()?;
    assert_eq!(
        call(&mut service, "PUT", "sys/unseal", "", json!({"key":key})).status,
        503
    );
    assert!(service.state.is_none());
    assert_eq!(fs::read(service.data_dir.join("state.hbs"))?, before[0]);
    assert_eq!(fs::read(service.data_dir.join("journal.hbj"))?, before[1]);
    Ok(())
}
