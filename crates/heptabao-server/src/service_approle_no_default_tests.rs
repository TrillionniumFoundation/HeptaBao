use super::tests::{Root, bootstrap_approle as bootstrap, call};
use super::*;
type TestResult = Result<(), Box<dyn std::error::Error>>;

fn credentials(service: &mut Service, admin: &str, mount: &str) -> Result<Value, Box<dyn std::error::Error>> {
    let role_id = call(service, "GET", &format!("auth/{mount}/role/app/role-id"), admin, json!({}));
    assert_eq!(role_id.status, 200);
    let secret = call(service, "POST", &format!("auth/{mount}/role/app/secret-id"), admin, json!({}));
    assert_eq!(secret.status, 200);
    Ok(json!({
        "role_id":role_id.body["data"]["role_id"].as_str().ok_or("role-id")?,
        "secret_id":secret.body["data"]["secret_id"].as_str().ok_or("secret-id")?
    }))
}

#[test]
fn approle135_service_and_batch_read_write_grants_survive_durable_restart() -> TestResult {
    for kind in ["service", "batch"] {
        let root = Root::new();
        let mut service = root.service()?;
        let (key, admin) = bootstrap(&mut service)?;
        assert_eq!(call(&mut service, "POST", "sys/auth/build", &admin,
            json!({"type":"approle"})).status, 204);
        assert_eq!(call(&mut service, "PUT", "sys/policies/acl/canary", &admin,
            json!({"policy":"path \"secret/data/allowed\" { capabilities = [\"create\", \"update\", \"read\"] } path \"auth/token/renew-self\" { capabilities = [\"update\"] }"})).status, 204);
        assert_eq!(call(&mut service, "POST", "auth/build/role/app", &admin,
            json!({"token_type":kind,"token_no_default_policy":true,
                "token_policies":["canary"],"token_ttl":120,"token_max_ttl":600})).status, 204);
        let credentials = credentials(&mut service, &admin, "build")?;
        let issued = call(&mut service, "POST", "auth/build/login", "", credentials.clone());
        assert_eq!(issued.status, 200);
        assert_eq!(issued.body["auth"]["policies"], json!(["canary"]));
        assert_eq!(issued.body["auth"]["token_policies"], json!(["canary"]));
        let token = issued.body["auth"]["client_token"].as_str().ok_or("token")?.to_owned();
        assert_eq!(call(&mut service, "POST", "secret/data/allowed", &token,
            json!({"data":{"source":"fixture-value"}})).status, 200);
        assert_eq!(call(&mut service, "GET", "secret/data/forbidden", &token, json!({})).status, 403);
        assert_eq!(service.state.as_ref().ok_or("state")?.schema, APPROLE_NO_DEFAULT_STATE_SCHEMA);
        drop(service);
        let mut service = root.service()?;
        assert_eq!(call(&mut service, "POST", "sys/unseal", "", json!({"key":key})).status, 200);
        let read = call(&mut service, "GET", "auth/build/role/app", &admin, json!({}));
        assert_eq!(read.status, 200);
        assert_eq!(read.body["data"]["token_no_default_policy"], true);
        assert_eq!(read.body["data"]["token_policies"], json!(["canary"]));
        let secret = call(&mut service, "GET", "secret/data/allowed", &token, json!({}));
        assert_eq!(secret.status, 200);
        assert_eq!(secret.body["data"]["data"]["source"], "fixture-value");
        let again = call(&mut service, "POST", "auth/build/login", "", credentials);
        assert_eq!(again.status, 200);
        assert_eq!(again.body["auth"]["policies"], json!(["canary"]));
        assert_eq!(call(&mut service, "POST", "auth/build/role/app", &admin,
            json!({"token_no_default_policy":false})).status, 204);
        if kind == "service" {
            let renewed = call(&mut service, "POST", "auth/token/renew-self", &token,
                json!({"increment":180}));
            assert_eq!(renewed.status, 200);
            assert_eq!(renewed.body["auth"]["policies"], json!(["canary"]));
            assert_eq!(call(&mut service, "POST", "auth/token/revoke", &admin,
                json!({"token":token})).status, 204);
            assert_eq!(call(&mut service, "GET", "secret/data/allowed", &token, json!({})).status, 403);
        } else {
            assert_eq!(call(&mut service, "POST", "auth/token/renew-self", &token,
                json!({"increment":180})).status, 400);
        }
    }
    Ok(())
}

#[test]
fn approle135_reader_and_publication_floors_reject_lowering_and_survive_last_role_delete() -> TestResult {
    let root = Root::new();
    let mut service = root.service()?;
    let (key, admin) = bootstrap(&mut service)?;
    assert_eq!(call(&mut service, "POST", "auth/approle/role/app", &admin,
        json!({"token_ttl":60,"token_max_ttl":600})).status, 204);
    let previous = service.state.clone().ok_or("state")?;
    assert_eq!(previous.schema, APPROLE_NO_DEFAULT_STATE_SCHEMA);
    assert!(previous.validate_format().is_ok());
    assert_eq!(previous.writer_schema(), APPROLE_NO_DEFAULT_STATE_SCHEMA);
    let mut lowered = previous.clone();
    lowered.schema = CURRENT_STATE_SCHEMA;
    let denied = lowered.validate_format().err().ok_or("reader floor")?;
    assert_eq!(denied.status, 503);
    assert_eq!(denied.body["errors"][0], "AppRole default-policy semantics require schema 135");
    assert!(lowered.validate_publication_schema(Some(&previous)).is_err());
    assert_eq!(call(&mut service, "DELETE", "auth/approle/role/app", &admin, json!({})).status, 204);
    let retired = service.state.clone().ok_or("retired")?;
    assert!(!retired.auth.has_approle_no_default_policy());
    assert_eq!(retired.schema, APPROLE_NO_DEFAULT_STATE_SCHEMA);
    assert_eq!(retired.writer_schema(), APPROLE_NO_DEFAULT_STATE_SCHEMA);
    assert!(retired.validate_format().is_ok());
    assert!(retired.validate_publication_schema(Some(&previous)).is_ok());
    let mut lowered_retired = retired.clone();
    lowered_retired.schema = CURRENT_STATE_SCHEMA;
    assert!(lowered_retired.validate_publication_schema(Some(&retired)).is_err());
    drop(service);
    let mut service = root.service()?;
    assert_eq!(call(&mut service, "POST", "sys/unseal", "", json!({"key":key})).status, 200);
    assert_eq!(service.state.as_ref().ok_or("reopened")?.schema, APPROLE_NO_DEFAULT_STATE_SCHEMA);
    assert_eq!(call(&mut service, "GET", "auth/approle/role/app", &admin, json!({})).status, 404);
    Ok(())
}

#[test]
fn approle135_legacy_owner_is_readable_and_explicit_replacement_activates_reader_floor() -> TestResult {
    let root = Root::new();
    let mut service = root.service()?;
    let (_, admin) = bootstrap(&mut service)?;
    let old_schema = service.state.as_ref().ok_or("state")?.schema;
    create_legacy_approle_role_fixture(
        &mut service, "", "approle", "app", &admin,
        json!({"token_ttl":60,"token_max_ttl":600,"token_policies":["default","named"]}),
    )?;
    let legacy = service.state.clone().ok_or("state")?;
    assert_eq!(legacy.schema, old_schema);
    assert!(!legacy.auth.has_approle_no_default_policy());
    assert!(legacy.validate_format().is_ok());
    // A bounded historical-owner fixture; previous-binary upgrade is separate QA.
    super::tests::commit_legacy_state_fixture(&mut service, &legacy)
        .map_err(|_| "legacy owner publication")?;
    service.state = Some(legacy);
    let before = service.current_state_digest().map_err(|_| "digest")?;
    let read = call(&mut service, "GET", "auth/approle/role/app", &admin, json!({}));
    assert_eq!(read.status, 200);
    assert_eq!(read.body["data"]["token_no_default_policy"], false);
    assert_eq!(read.body["data"]["token_policies"], json!(["default", "named"]));
    assert_eq!(service.current_state_digest().map_err(|_| "digest")?, before);
    assert_eq!(call(&mut service, "POST", "auth/approle/role/app", &admin,
        json!({"token_no_default_policy":true})).status, 204);
    let read = call(&mut service, "GET", "auth/approle/role/app", &admin, json!({}));
    assert_eq!(read.body["data"]["token_policies"], json!(["default", "named"]));
    assert_eq!(service.state.as_ref().ok_or("state")?.schema, APPROLE_NO_DEFAULT_STATE_SCHEMA);
    assert_eq!(call(&mut service, "POST", "auth/approle/role/app", &admin,
        json!({"token_policies":["named"]})).status, 204);
    let credentials = credentials(&mut service, &admin, "approle")?;
    let issued = call(&mut service, "POST", "auth/approle/login", "", credentials);
    assert_eq!(issued.status, 200);
    assert_eq!(issued.body["auth"]["policies"], json!(["named"]));
    Ok(())
}

pub(super) fn create_legacy_approle_role_fixture(
    service: &mut Service,
    namespace: &str,
    mount: &str,
    role: &str,
    admin: &str,
    body: Value,
) -> TestResult {
    // Construct one historical owner before any modern AppRole publication.
    // The actual AuthState route validates the role; only its unpublished,
    // cfg(test) clone is converted to the predecessor's normalized policy list.
    assert!(service.ha.is_none(), "historical role fixture is single-node only");
    assert!(!mount.is_empty() && !mount.contains('/'));
    assert!(!role.is_empty() && !role.contains('/'));
    assert!(body.is_object() && body.get("token_no_default_policy").is_none());
    let current = service.state.as_ref().ok_or("historical role state")?;
    assert!(current.schema > 0 && current.schema <= CURRENT_STATE_SCHEMA);
    assert!(current.writer_schema() <= CURRENT_STATE_SCHEMA);
    assert!(!current.auth.has_approle_no_default_policy());
    current.validate_format().map_err(|_| "historical predecessor format")?;
    let mut candidate = current.clone();
    let actor = candidate.auth.authenticate(admin, 100)
        .map_err(|_| "historical root authentication")?;
    assert!(actor.is_root());
    let path = format!("auth/{mount}/role/{role}");
    let absent = candidate.auth.handle(
        Some(&actor), namespace, "GET", &path, &json!({}), 100,
    ).map_err(|_| "historical role lookup")?.ok_or("historical route absent")?;
    assert_eq!(absent.status, 404, "historical fixture creates one absent role");
    let created = candidate.auth.handle(
        Some(&actor), namespace, "POST", &path, &body, 100,
    ).map_err(|_| "historical role construction")?.ok_or("historical route absent")?;
    assert_eq!(created.status, 204);
    candidate.auth.restore_legacy_approle_policy_owners_for_format_test();
    assert!(!candidate.auth.has_approle_no_default_policy());
    candidate.validate_format().map_err(|_| "historical candidate format")?;
    assert!(candidate.writer_schema() <= CURRENT_STATE_SCHEMA);
    service.commit_state(&mut candidate).map_err(|_| "historical role publication")?;
    assert!(candidate.schema <= CURRENT_STATE_SCHEMA);
    service.state = Some(candidate);
    Ok(())
}
