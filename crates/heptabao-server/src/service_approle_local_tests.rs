use super::tests::{Root, bootstrap_approle as bootstrap, call};
use super::*;
type TestResult = Result<(), Box<dyn std::error::Error>>;

#[test]
fn approle142_real_local_credentials_read_write_restart_and_revoke() -> TestResult {
    let root = Root::new();
    let mut service = root.service()?;
    let (key, admin) = bootstrap(&mut service)?;
    assert_eq!(call(&mut service, "POST", "sys/policies/acl/local142", &admin,
        json!({"policy":"path \"secret/data/local142\" { capabilities = [\"create\", \"update\", \"read\"] }"})).status, 204);
    assert_eq!(call(&mut service, "POST", "auth/approle/role/local142", &admin,
        json!({"local_secret_ids":true,"token_policies":["local142"],"secret_id_num_uses":2,"token_ttl":120})).status, 204);
    let rid = call(
        &mut service,
        "GET",
        "auth/approle/role/local142/role-id",
        &admin,
        json!({}),
    );
    assert_eq!(rid.status, 200);
    let sid = call(
        &mut service,
        "POST",
        "auth/approle/role/local142/secret-id",
        &admin,
        json!({"metadata":r#"{"origin":"local142"}"#}),
    );
    assert_eq!(sid.status, 200);
    let credentials =
        json!({"role_id":rid.body["data"]["role_id"],"secret_id":sid.body["data"]["secret_id"]});
    let first = call(
        &mut service,
        "POST",
        "auth/approle/login",
        "",
        credentials.clone(),
    );
    assert_eq!(first.status, 200);
    let first_token = first.body["auth"]["client_token"]
        .as_str()
        .ok_or("first local token")?;
    assert_eq!(
        call(
            &mut service,
            "POST",
            "secret/data/local142",
            first_token,
            json!({"data":{"round":"before-restart"}})
        )
        .status,
        200
    );
    assert_eq!(
        service.state.as_ref().ok_or("state")?.schema,
        APPROLE_LOCAL_STATE_SCHEMA
    );
    drop(service);
    let mut service = root.service()?;
    assert_eq!(
        call(&mut service, "POST", "sys/unseal", "", json!({"key":key})).status,
        200
    );
    assert_eq!(
        call(
            &mut service,
            "GET",
            "auth/approle/role/local142",
            &admin,
            json!({})
        )
        .body["data"]["local_secret_ids"],
        true
    );
    let second = call(
        &mut service,
        "POST",
        "auth/approle/login",
        "",
        credentials.clone(),
    );
    assert_eq!(second.status, 200);
    let second_token = second.body["auth"]["client_token"]
        .as_str()
        .ok_or("second local token")?;
    assert_eq!(
        call(
            &mut service,
            "POST",
            "auth/token/renew-self",
            second_token,
            json!({"increment":60})
        )
        .status,
        200
    );
    assert_eq!(
        call(
            &mut service,
            "GET",
            "secret/data/local142",
            second_token,
            json!({})
        )
        .body["data"]["data"]["round"],
        "before-restart"
    );
    assert_eq!(
        call(
            &mut service,
            "POST",
            "secret/data/local142",
            second_token,
            json!({"data":{"round":"after-restart"},"options":{"cas":1}})
        )
        .status,
        200
    );
    assert_eq!(
        call(&mut service, "POST", "auth/approle/login", "", credentials).status,
        400
    );
    assert_eq!(
        call(
            &mut service,
            "POST",
            "auth/token/revoke-self",
            second_token,
            json!({})
        )
        .status,
        204
    );
    assert_eq!(
        call(
            &mut service,
            "GET",
            "secret/data/local142",
            second_token,
            json!({})
        )
        .status,
        403
    );
    assert_eq!(
        call(
            &mut service,
            "GET",
            "secret/data/local142",
            &admin,
            json!({})
        )
        .body["data"]["data"]["round"],
        "after-restart"
    );
    Ok(())
}

#[test]
fn approle142_state_load_publication_and_restore_reject_cross_cluster_or_old_floor() -> TestResult {
    let root = Root::new();
    let mut service = root.service()?;
    let (_, admin) = bootstrap(&mut service)?;
    let previous = service.state.clone().ok_or("previous")?;
    assert_eq!(
        call(
            &mut service,
            "POST",
            "auth/approle/role/local142",
            &admin,
            json!({"local_secret_ids":true})
        )
        .status,
        204
    );
    assert_eq!(
        call(
            &mut service,
            "POST",
            "auth/approle/role/local142/secret-id",
            &admin,
            json!({})
        )
        .status,
        200
    );
    let current = service.state.clone().ok_or("current")?;
    assert_eq!(current.schema, APPROLE_LOCAL_STATE_SCHEMA);
    assert!(current.auth.has_cluster_local_approle_state());
    current.validate_format().map_err(|_| "valid local state")?;
    current
        .validate_publication_schema(Some(&previous))
        .map_err(|_| "valid local publication")?;
    let encoded = crate::secret_serde::to_vec(&current, 16 * 1024 * 1024)
        .map_err(|_| "encode local state")?;
    let restored: State = serde_json::from_slice(&encoded)?;
    restored
        .validate_format()
        .map_err(|_| "same cluster restore")?;
    assert!(Service::validate_snapshot_protected_floor(&current, &restored).is_ok());
    assert_eq!(
        owner_store::serialize_owner(&restored.auth).map_err(|_| "restored auth")?,
        owner_store::serialize_owner(&current.auth).map_err(|_| "current auth")?
    );
    let mut lower = current.clone();
    lower.schema = AUTH_SECURITY_CONTRACT_STATE_SCHEMA;
    assert!(lower.validate_format().is_err());
    assert!(lower.validate_publication_schema(Some(&current)).is_err());
    assert!(Service::validate_snapshot_protected_floor(&current, &lower).is_err());
    let mut foreign = current.clone();
    foreign.cluster_id = "another-cluster".into();
    assert!(foreign.validate_format().is_err());
    assert!(foreign.validate_publication_schema(Some(&current)).is_err());
    assert!(Service::validate_snapshot_protected_floor(&current, &foreign).is_err());
    assert_eq!(
        call(
            &mut service,
            "DELETE",
            "auth/approle/role/local142",
            &admin,
            json!({})
        )
        .status,
        204
    );
    let retired = service.state.as_ref().ok_or("retired")?;
    assert!(!retired.auth.has_cluster_local_approle_state());
    assert_eq!(retired.writer_schema(), APPROLE_LOCAL_STATE_SCHEMA);
    assert!(Service::validate_snapshot_protected_floor(retired, &previous).is_err());
    let mut relabeled = retired.clone();
    relabeled.schema = AUTH_SECURITY_CONTRACT_STATE_SCHEMA;
    assert!(
        relabeled
            .validate_publication_schema(Some(retired))
            .is_err()
    );
    Ok(())
}
