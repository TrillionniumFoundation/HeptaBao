//! OpenBao 2.7 External Keys registry on the existing durable owner.
use super::tests::{Root, bootstrap, call, limited_token};
use super::*;
type TestResult = Result<(), Box<dyn std::error::Error>>;

#[test]
fn external_keys270_registry_is_durable_and_schema_fenced() -> TestResult {
    let root = Root::new();
    let mut service = root.service()?;
    let (unseal, admin) = bootstrap(&mut service)?;
    let empty = call(
        &mut service,
        "LIST",
        "sys/external-keys/configs",
        &admin,
        json!({}),
    );
    assert_eq!(empty.status, 404);
    assert_eq!(empty.body, json!({"errors":[]}));

    let created = call(
        &mut service,
        "POST",
        "sys/external-keys/configs/demo",
        &admin,
        json!({"plugin":"transit","verify":false,"address":"https://127.0.0.1:1",
            "token":"synthetic-never-used","mount_path":"transit","namespace":""}),
    );
    assert_eq!(created.status, 204);
    let state = service.state.as_ref().ok_or("state")?;
    assert_eq!(state.schema, 63);
    assert!(state.engines.has_external_key_state());

    let config = call(
        &mut service,
        "GET",
        "sys/external-keys/configs/demo",
        &admin,
        json!({}),
    );
    assert_eq!(config.status, 200);
    assert_eq!(config.body["data"]["plugin"], "transit");
    assert_eq!(config.body["data"]["token"], "(redacted)");
    assert_eq!(
        call(
            &mut service,
            "PATCH",
            "sys/external-keys/configs/demo",
            &admin,
            json!({"verify":false,"mount_path":"remote-transit","namespace":"team/"})
        )
        .status,
        204
    );
    let config = call(
        &mut service,
        "GET",
        "sys/external-keys/configs/demo",
        &admin,
        json!({}),
    );
    assert_eq!(config.body["data"]["mount_path"], "remote-transit");
    assert_eq!(config.body["data"]["namespace"], "team/");

    assert_eq!(
        call(
            &mut service,
            "POST",
            "sys/external-keys/configs/demo/keys/key1",
            &admin,
            json!({"verify":false,"name":"external","version":3})
        )
        .status,
        204
    );
    let key = call(
        &mut service,
        "GET",
        "sys/external-keys/configs/demo/keys/key1",
        &admin,
        json!({}),
    );
    assert_eq!(key.body["data"]["name"], "external");
    assert_eq!(key.body["data"]["version"], 3);
    for _ in 0..2 {
        assert_eq!(
            call(
                &mut service,
                "POST",
                "sys/external-keys/configs/demo/keys/key1/grants/pki",
                &admin,
                json!({})
            )
            .status,
            204
        );
    }
    let grants = call(
        &mut service,
        "LIST",
        "sys/external-keys/configs/demo/keys/key1/grants",
        &admin,
        json!({}),
    );
    assert_eq!(grants.body["data"]["keys"], json!(["pki/"]));

    let mut disguised = service.state.clone().ok_or("state")?;
    disguised.schema = 62;
    let denied = disguised
        .validate_format()
        .err()
        .ok_or("missing schema fence")?;
    assert_eq!(
        denied.body["errors"][0],
        "External Keys registry requires schema 63"
    );
    drop(service);

    let mut service = root.service()?;
    assert_eq!(
        call(
            &mut service,
            "POST",
            "sys/unseal",
            "",
            json!({"key":unseal})
        )
        .status,
        200
    );
    assert_eq!(
        call(
            &mut service,
            "GET",
            "sys/external-keys/configs/demo/keys/key1",
            &admin,
            json!({})
        )
        .body["data"]["version"],
        3
    );
    assert_eq!(
        call(
            &mut service,
            "DELETE",
            "sys/external-keys/configs/demo",
            &admin,
            json!({})
        )
        .status,
        204
    );
    let missing = call(
        &mut service,
        "GET",
        "sys/external-keys/configs/demo/keys/key1",
        &admin,
        json!({}),
    );
    assert_eq!(missing.status, 400);
    assert_eq!(missing.body["errors"][0], "key \"key1\" not found");
    let empty = call(
        &mut service,
        "LIST",
        "sys/external-keys/configs",
        &admin,
        json!({}),
    );
    assert_eq!(empty.status, 404);
    assert_eq!(empty.body, json!({"errors":[]}));
    Ok(())
}

#[test]
fn external_keys270_rejections_are_atomic_acl_bound_and_namespace_isolated() -> TestResult {
    let root = Root::new();
    let mut service = root.service()?;
    let (unseal, admin) = bootstrap(&mut service)?;

    let before = serde_json::to_vec(service.state.as_ref().ok_or("state")?)?;
    let verification = call(
        &mut service,
        "POST",
        "sys/external-keys/configs/rejected",
        &admin,
        json!({"plugin":"transit","token":"synthetic"}),
    );
    assert_eq!(verification.status, 501);
    assert!(
        serde_json::to_vec(service.state.as_ref().ok_or("state")?)? == before,
        "rejected registry write changed durable state"
    );
    let unknown = call(
        &mut service,
        "POST",
        "sys/external-keys/configs/rejected",
        &admin,
        json!({"plugin":"unknown","verify":false,"password":"must-not-persist"}),
    );
    assert_eq!(unknown.status, 400);
    assert!(
        serde_json::to_vec(service.state.as_ref().ok_or("state")?)? == before,
        "rejected registry write changed durable state"
    );

    let reader = limited_token(
        &mut service,
        &admin,
        r#"path "sys/external-keys/configs/*" { capabilities = ["read", "list"] }"#,
    )?;
    // Authentication precedes ACL evaluation. A rejected write must retain
    // exactly the accepted finite-use debit, not refund the credential.
    let mut expected = service.state.clone().ok_or("state")?;
    expected
        .auth
        .authenticate(&reader, 100)
        .map_err(|_| "expected authentication")?;
    let denied = call(
        &mut service,
        "POST",
        "sys/external-keys/configs/denied",
        &reader,
        json!({"plugin":"transit","verify":false,"token":"synthetic"}),
    );
    assert_eq!(denied.status, 403);
    assert!(
        serde_json::to_vec(service.state.as_ref().ok_or("state")?)?
            == serde_json::to_vec(&expected)?,
        "ACL denial changed state beyond the authenticated finite-use debit"
    );
    assert_eq!(
        call(
            &mut service,
            "GET",
            "sys/external-keys/configs/denied",
            &admin,
            json!({})
        )
        .status,
        400
    );
    assert_eq!(
        call(
            &mut service,
            "LIST",
            "sys/external-keys/configs",
            &reader,
            json!({})
        )
        .status,
        403
    );
    drop(service);
    let mut service = root.service()?;
    assert_eq!(
        call(
            &mut service,
            "POST",
            "sys/unseal",
            "",
            json!({"key":unseal})
        )
        .status,
        200
    );
    assert_eq!(
        call(
            &mut service,
            "LIST",
            "sys/external-keys/configs",
            &reader,
            json!({})
        )
        .status,
        403
    );
    assert_eq!(
        call(
            &mut service,
            "GET",
            "sys/external-keys/configs/denied",
            &admin,
            json!({})
        )
        .status,
        400
    );

    assert_eq!(
        call(
            &mut service,
            "POST",
            "sys/external-keys/configs/root-key",
            &admin,
            json!({"plugin":"pkcs11","verify":false,"pin":"synthetic-pin"}),
        )
        .status,
        204
    );
    let root_config = call(
        &mut service,
        "GET",
        "sys/external-keys/configs/root-key",
        &admin,
        json!({}),
    );
    assert_eq!(root_config.body["data"]["pin"], "(redacted)");

    assert_eq!(
        call(
            &mut service,
            "POST",
            "sys/namespaces/team",
            &admin,
            json!({"custom_metadata":{"owner":"external-keys-test"}}),
        )
        .status,
        200
    );
    assert_eq!(
        service
            .handle_at(
                "POST",
                "sys/external-keys/configs/team-key",
                "team",
                &admin,
                json!({"plugin":"transit","verify":false,"token":"team-secret"}),
                100,
            )
            .status,
        204
    );
    let root_list = call(
        &mut service,
        "LIST",
        "sys/external-keys/configs",
        &admin,
        json!({}),
    );
    assert_eq!(root_list.body["data"]["keys"], json!(["root-key"]));
    let team_list = service.handle_at(
        "LIST",
        "sys/external-keys/configs",
        "team",
        &admin,
        json!({}),
        100,
    );
    assert_eq!(team_list.body["data"]["keys"], json!(["team-key"]));
    assert_eq!(
        service
            .handle_at(
                "GET",
                "sys/external-keys/configs/root-key",
                "team",
                &admin,
                json!({}),
                100,
            )
            .status,
        400
    );
    Ok(())
}

#[test]
fn external_keys270_alias_only_acl_cannot_modify_the_canonical_config() -> TestResult {
    let root = Root::new();
    let mut service = root.service()?;
    let (_, admin) = bootstrap(&mut service)?;
    assert_eq!(
        call(
            &mut service,
            "POST",
            "sys/external-keys/configs/victim",
            &admin,
            json!({"plugin":"transit", "verify":false, "mount_path":"original"})
        )
        .status,
        204
    );
    let alias_actor = limited_token(
        &mut service,
        &admin,
        r#"path "sys/external-keys/configsvictim" { capabilities = ["update"] }"#,
    )?;
    let mut expected = service.state.clone().ok_or("state")?;
    expected
        .auth
        .authenticate(&alias_actor, 100)
        .map_err(|_| "expected authentication")?;
    let rejected = call(
        &mut service,
        "POST",
        "sys/external-keys/configsvictim",
        &alias_actor,
        json!({"plugin":"transit", "verify":false, "mount_path":"forbidden"}),
    );
    assert_eq!(rejected.status, 404);
    assert!(
        serde_json::to_vec(service.state.as_ref().ok_or("state")?)?
            == serde_json::to_vec(&expected)?,
        "alias request changed canonical state"
    );
    let readback = call(
        &mut service,
        "GET",
        "sys/external-keys/configs/victim",
        &admin,
        json!({}),
    );
    assert_eq!(readback.status, 200);
    assert_eq!(readback.body["data"]["mount_path"], "original");
    Ok(())
}

#[test]
fn external_keys270_client_private_key_redaction_survives_real_service_reopen() -> TestResult {
    let root = Root::new();
    let mut service = root.service()?;
    let (unseal, admin) = bootstrap(&mut service)?;
    let path = "sys/external-keys/configs/client-key";
    let canary = "synthetic-private-client-key-persistent-canary";
    assert_eq!(
        call(
            &mut service,
            "POST",
            path,
            &admin,
            json!({
                "plugin":"transit", "verify":false, "tls_client_key_bytes":canary,
                "tls_client_cert_bytes":"public-client-certificate"
            })
        )
        .status,
        204
    );
    for phase in 0..2 {
        if phase == 1 {
            drop(service);
            service = root.service()?;
            assert_eq!(
                call(
                    &mut service,
                    "POST",
                    "sys/unseal",
                    "",
                    json!({"key":unseal})
                )
                .status,
                200
            );
        }
        let before = Zeroizing::new(serde_json::to_vec(service.state.as_ref().ok_or("state")?)?);
        let response = call(&mut service, "GET", path, &admin, json!({}));
        assert_eq!(response.status, 200);
        assert!(
            response.body["data"]["tls_client_key_bytes"] == "(redacted)",
            "private client key was not redacted"
        );
        assert!(
            !serde_json::to_string(&response.body)?.contains(canary),
            "response exposed synthetic private key"
        );
        assert_eq!(
            response.body["data"]["tls_client_cert_bytes"],
            "public-client-certificate"
        );
        assert!(
            before.as_slice() == serde_json::to_vec(service.state.as_ref().ok_or("state")?)?,
            "read changed stored state"
        );
    }
    let reader = limited_token(
        &mut service,
        &admin,
        r#"path "sys/external-keys/configs/client-key" { capabilities = ["read"] }"#,
    )?;
    let response = call(&mut service, "GET", path, &reader, json!({}));
    assert_eq!(response.status, 200);
    assert!(response.body["data"]["tls_client_key_bytes"] == "(redacted)");
    assert!(!serde_json::to_string(&response.body)?.contains(canary));
    Ok(())
}

#[test]
fn external_keys270_oversized_patch_preserves_durable_config_key_and_grant() -> TestResult {
    let root = Root::new();
    let mut service = root.service()?;
    let (unseal, admin) = bootstrap(&mut service)?;
    let config = "sys/external-keys/configs/limit";
    let key = "sys/external-keys/configs/limit/keys/key1";
    let grant = "sys/external-keys/configs/limit/keys/key1/grants/pki";
    assert_eq!(call(&mut service, "POST", config, &admin,
        json!({"plugin":"transit","verify":false,"token":"original synthetic","namespace":"before/"})).status, 204);
    assert_eq!(
        call(
            &mut service,
            "POST",
            key,
            &admin,
            json!({"verify":false,"name":"before","version":1})
        )
        .status,
        204
    );
    assert_eq!(
        call(&mut service, "POST", grant, &admin, json!({})).status,
        204
    );
    let before = service.state_digest;
    for path in [config, key] {
        let rejected = call(
            &mut service,
            "PATCH",
            path,
            &admin,
            json!({"verify":false,"token":"x".repeat(64 * 1024),"namespace":"uncommitted/"}),
        );
        assert_eq!(rejected.status, 400);
        assert_eq!(service.state_digest, before);
    }
    drop(service);
    let mut service = root.service()?;
    assert_eq!(
        call(
            &mut service,
            "POST",
            "sys/unseal",
            "",
            json!({"key":unseal})
        )
        .status,
        200
    );
    let configuration = call(&mut service, "GET", config, &admin, json!({}));
    assert_eq!(configuration.status, 200);
    assert_eq!(configuration.body["data"]["namespace"], "before/");
    assert_eq!(configuration.body["data"]["token"], "(redacted)");
    let mapping = call(&mut service, "GET", key, &admin, json!({}));
    assert_eq!(mapping.status, 200);
    assert_eq!(mapping.body["data"]["name"], "before");
    assert_eq!(mapping.body["data"]["version"], 1);
    let grants = call(
        &mut service,
        "LIST",
        "sys/external-keys/configs/limit/keys/key1/grants",
        &admin,
        json!({}),
    );
    assert_eq!(grants.status, 200);
    assert_eq!(grants.body["data"]["keys"], json!(["pki/"]));
    Ok(())
}
