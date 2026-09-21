use super::tests::{Root, bootstrap, call};
use super::*;
type TestResult = Result<(), Box<dyn std::error::Error>>;

#[test]
fn approle_secret_source_presence_requires45_but_absent44_reads_preserve_bytes() -> TestResult {
    let root = Root::new();
    let mut service = root.service()?;
    let (_, admin) = bootstrap(&mut service)?;
    assert_eq!(
        call(
            &mut service,
            "POST",
            "auth/approle/role/source",
            &admin,
            json!({"token_ttl":60})
        )
        .status,
        204
    );
    let mut old = service.state.clone().ok_or("state")?;
    old.schema = 44;
    old.validate_format().map_err(|_| "old format")?;
    let before = owner_store::serialize_owner(&old.auth).map_err(|_| "encode")?;
    service.commit_state(&old).map_err(|_| "old fixture")?;
    service.state = Some(old);
    for path in [
        "auth/approle/role/source",
        "auth/approle/role/source/secret-id-bound-cidrs",
    ] {
        let read = call(&mut service, "GET", path, &admin, json!({}));
        assert_eq!(read.status, 200);
        assert_eq!(read.body["data"]["secret_id_bound_cidrs"], Value::Null);
    }
    assert_eq!(service.state.as_ref().ok_or("state")?.schema, 44);
    assert!(
        before.as_slice()
            == owner_store::serialize_owner(&service.state.as_ref().ok_or("state")?.auth)
                .map_err(|_| "encode")?
                .as_slice(),
        "read changed the auth owner"
    );
    for cidrs in [json!([]), json!(["127.0.0.1/32"])] {
        assert_eq!(
            call(
                &mut service,
                "POST",
                "auth/approle/role/source",
                &admin,
                json!({"secret_id_bound_cidrs":cidrs})
            )
            .status,
            204
        );
        let mut changed = service.state.clone().ok_or("state")?;
        assert_eq!(changed.schema, CURRENT_STATE_SCHEMA);
        changed.schema = 45;
        changed
            .validate_format()
            .map_err(|_| "minimum source format")?;
        changed.schema = 44;
        assert_eq!(
            changed
                .validate_format()
                .err()
                .ok_or("missing source gate")?
                .status,
            503
        );
    }
    Ok(())
}

#[test]
fn approle_cidr_presence_requires43_but_absent42_role_reads_do_not_migrate() -> TestResult {
    let root = Root::new();
    let mut service = root.service()?;
    let (_, admin) = bootstrap(&mut service)?;
    assert_eq!(
        call(
            &mut service,
            "POST",
            "auth/approle/role/old",
            &admin,
            json!({"token_ttl":60})
        )
        .status,
        204
    );
    let mut old = service.state.clone().ok_or("state")?;
    old.schema = 42;
    old.validate_format().map_err(|_| "old format")?;
    let before = owner_store::serialize_owner(&old.auth).map_err(|_| "encode")?;
    service.commit_state(&old).map_err(|_| "old fixture")?;
    service.state = Some(old);
    let read = call(
        &mut service,
        "GET",
        "auth/approle/role/old/token-bound-cidrs",
        &admin,
        json!({}),
    );
    assert_eq!(read.status, 200);
    assert_eq!(read.body["data"]["token_bound_cidrs"], Value::Null);
    assert_eq!(service.state.as_ref().ok_or("state")?.schema, 42);
    assert_eq!(
        before.as_slice(),
        owner_store::serialize_owner(&service.state.as_ref().ok_or("state")?.auth)
            .map_err(|_| "encode")?
            .as_slice()
    );
    for cidrs in [json!([]), json!(["127.0.0.1/32"])] {
        assert_eq!(
            call(
                &mut service,
                "POST",
                "auth/approle/role/old/token-bound-cidrs",
                &admin,
                json!({"token_bound_cidrs":cidrs})
            )
            .status,
            204
        );
        let mut changed = service.state.clone().ok_or("state")?;
        assert_eq!(changed.schema, CURRENT_STATE_SCHEMA);
        changed.validate_format().map_err(|_| "new format")?;
        changed.schema = 43;
        changed
            .validate_format()
            .map_err(|_| "minimum CIDR format")?;
        changed.schema = 42;
        assert_eq!(
            changed
                .validate_format()
                .err()
                .ok_or("missing gate")?
                .status,
            503
        );
    }
    Ok(())
}
