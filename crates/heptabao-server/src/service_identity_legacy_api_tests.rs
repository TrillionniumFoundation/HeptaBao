//! Genuine Service dispatch and encrypted reopen for the observed public routes.
use super::super::tests::{Root, bootstrap, call};
use super::*;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ring::signature::{Ed25519KeyPair, KeyPair};

type TestResult<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;

fn mount(service: &mut Service, admin: &str, namespace: &str) -> TestResult<String> {
    assert_eq!(
        service
            .handle_at(
                "POST",
                "sys/auth/legacy-api",
                namespace,
                admin,
                json!({"type":"userpass"}),
                100
            )
            .status,
        204
    );
    service
        .state
        .as_ref()
        .ok_or("state")?
        .auth
        .mount_accessor(namespace, "legacy-api")
        .map_err(|_| "actual auth accessor".into())
}
fn entity(service: &mut Service, admin: &str, name: &str) -> TestResult<String> {
    let response = call(
        service,
        "POST",
        "identity/entity",
        admin,
        json!({"name":name}),
    );
    assert_eq!(response.status, 200);
    response.body["data"]["id"]
        .as_str()
        .map(str::to_owned)
        .ok_or("actual entity id".into())
}
fn alias_read(service: &mut Service, admin: &str, route: &str, id: &str) -> TestResult<Value> {
    let response = call(
        service,
        "GET",
        &format!("identity/{route}/id/{id}"),
        admin,
        json!({}),
    );
    assert_eq!(response.status, 200);
    Ok(response.body["data"].clone())
}
fn response_id(response: &Response) -> TestResult<String> {
    assert_eq!(response.status, 200);
    response.body["data"]["id"]
        .as_str()
        .map(str::to_owned)
        .ok_or("response id".into())
}

#[test]
fn identity270_modern_alias_uses_actual_partial_priority_implicit_entity_and_closed_parameters()
-> TestResult {
    let root = Root::new();
    let mut service = root.service()?;
    let (_, admin) = bootstrap(&mut service)?;
    let accessor = mount(&mut service, &admin, "")?;
    let one = entity(&mut service, &admin, "modern-one")?;
    let two = entity(&mut service, &admin, "modern-two")?;
    let created = call(
        &mut service,
        "POST",
        "identity/entity-alias",
        &admin,
        json!({"canonical_id":one,"entity_id":two,"name":"modern-subject","mount_accessor":accessor,
            "metadata":{"forged":"provider"},"custom_metadata":{"admin":"retained"}}),
    );
    let id = response_id(&created)?;
    assert_eq!(created.body["data"]["canonical_id"], one);
    let before = alias_read(&mut service, &admin, "entity-alias", &id)?;
    assert_eq!(before.as_object().ok_or("alias object")?.len(), 13);
    assert_eq!(before["metadata"], Value::Null);
    assert_eq!(before["merged_from_canonical_ids"], Value::Null);
    assert_eq!(before["mount_path"], "auth/legacy-api/");
    assert_eq!(before["mount_type"], "userpass");
    assert_eq!(before["namespace_id"], "root");
    assert_eq!(
        call(
            &mut service,
            "POST",
            &format!("identity/entity-alias/id/{id}"),
            &admin,
            json!({"name":"renamed"})
        )
        .status,
        200
    );
    let renamed = alias_read(&mut service, &admin, "entity-alias", &id)?;
    assert_eq!(renamed["canonical_id"], one);
    assert_eq!(renamed["mount_accessor"], accessor);
    assert_eq!(renamed["custom_metadata"], json!({"admin":"retained"}));
    let digest = service.state_digest;
    assert_eq!(
        call(
            &mut service,
            "POST",
            &format!("identity/entity-alias/id/{id}"),
            &admin,
            json!({"metadata":{"forged":"provider"}})
        )
        .status,
        204
    );
    assert_eq!(service.state_digest, digest);
    assert_eq!(
        alias_read(&mut service, &admin, "entity-alias", &id)?,
        renamed
    );
    assert_eq!(
        call(
            &mut service,
            "POST",
            &format!("identity/entity-alias/id/{id}"),
            &admin,
            json!({"entity_id":two})
        )
        .status,
        200
    );
    assert_eq!(
        alias_read(&mut service, &admin, "entity-alias", &id)?["canonical_id"],
        two
    );
    let digest = service.state_digest;
    for body in [
        json!({"canonical_id":"missing","entity_id":one}),
        json!({"name":"bad","unknown":true}),
    ] {
        assert_eq!(
            call(
                &mut service,
                "POST",
                &format!("identity/entity-alias/id/{id}"),
                &admin,
                body
            )
            .status,
            400
        );
        assert_eq!(service.state_digest, digest);
    }
    assert_eq!(
        call(
            &mut service,
            "POST",
            &format!("identity/entity-alias/id/{id}?name=duplicate"),
            &admin,
            json!({"name":"duplicate"})
        )
        .status,
        400
    );
    assert_eq!(service.state_digest, digest);
    let implicit = call(
        &mut service,
        "POST",
        "identity/entity-alias",
        &admin,
        json!({"name":"implicit","mount_accessor":accessor}),
    );
    let implicit_id = response_id(&implicit)?;
    let implicit_entity = implicit.body["data"]["canonical_id"]
        .as_str()
        .ok_or("implicit entity")?;
    assert_ne!(implicit_entity, one);
    assert_ne!(implicit_entity, two);
    assert_eq!(
        call(
            &mut service,
            "GET",
            &format!("identity/entity/id/{implicit_entity}"),
            &admin,
            json!({})
        )
        .status,
        200
    );
    assert_eq!(
        alias_read(&mut service, &admin, "entity-alias", &implicit_id)?["custom_metadata"],
        json!({})
    );
    let listed = call(
        &mut service,
        "LIST",
        "identity/entity-alias/id",
        &admin,
        json!({}),
    );
    assert_eq!(listed.status, 200);
    assert_eq!(listed.body["data"]["key_info"][&id]["name"], "renamed");
    assert_eq!(
        listed.body["data"]["key_info"][&id]["mount_path"],
        "auth/legacy-api/"
    );
    Ok(())
}

#[test]
fn identity270_legacy_alias_ignored_fields_share_modern_owner_and_native_deletion() -> TestResult {
    let root = Root::new();
    let mut service = root.service()?;
    let (key, admin) = bootstrap(&mut service)?;
    let accessor = mount(&mut service, &admin, "")?;
    let owner = entity(&mut service, &admin, "legacy-owner")?;
    let created = call(
        &mut service,
        "POST",
        "identity/alias",
        &admin,
        json!({"entity_id":owner,"name":"legacy-subject","mount_accessor":accessor,
            "metadata":{"forged":"provider"},"custom_metadata":{"ignored":"custom"}}),
    );
    let id = response_id(&created)?;
    let before = alias_read(&mut service, &admin, "alias", &id)?;
    assert_eq!(before["canonical_id"], owner);
    assert_eq!(before["custom_metadata"], json!({}));
    assert_eq!(before["metadata"], Value::Null);
    assert_eq!(
        alias_read(&mut service, &admin, "entity-alias", &id)?,
        before
    );
    for body in [
        json!({"metadata":{"forged":"later"}}),
        json!({"custom_metadata":{"ignored":"later"}}),
        json!({"metadata":17,"custom_metadata":[true]}),
    ] {
        let digest = service.state_digest;
        assert_eq!(
            call(
                &mut service,
                "POST",
                &format!("identity/alias/id/{id}"),
                &admin,
                body
            )
            .status,
            204
        );
        assert_eq!(service.state_digest, digest);
        assert_eq!(alias_read(&mut service, &admin, "alias", &id)?, before);
    }
    drop(service);
    let mut service = root.service()?;
    assert_eq!(
        call(&mut service, "POST", "sys/unseal", "", json!({"key":key})).status,
        200
    );
    assert_eq!(alias_read(&mut service, &admin, "alias", &id)?, before);
    assert_eq!(
        call(
            &mut service,
            "POST",
            &format!("identity/alias/id/{id}"),
            &admin,
            json!({"name":"legacy-renamed"})
        )
        .status,
        200
    );
    let renamed = alias_read(&mut service, &admin, "alias", &id)?;
    assert_eq!(renamed["custom_metadata"], Value::Null);
    assert_eq!(renamed["metadata"], Value::Null);
    drop(service);
    let mut service = root.service()?;
    assert_eq!(
        call(&mut service, "POST", "sys/unseal", "", json!({"key":key})).status,
        200
    );
    assert_eq!(alias_read(&mut service, &admin, "alias", &id)?, renamed);
    let listed = call(&mut service, "LIST", "identity/alias/id", &admin, json!({}));
    assert_eq!(listed.status, 200);
    assert_eq!(
        listed.body["data"]["key_info"][&id]["name"],
        "legacy-renamed"
    );
    assert_eq!(
        call(
            &mut service,
            "DELETE",
            &format!("identity/alias/id/{id}"),
            &admin,
            json!({})
        )
        .status,
        204
    );
    assert_eq!(
        call(
            &mut service,
            "GET",
            &format!("identity/entity-alias/id/{id}"),
            &admin,
            json!({})
        )
        .status,
        404
    );
    assert_eq!(
        call(
            &mut service,
            "GET",
            &format!("identity/entity/id/{owner}"),
            &admin,
            json!({})
        )
        .status,
        200
    );
    Ok(())
}

#[test]
fn identity270_alias_live_accessor_and_namespace_fences_precede_ignored_field_noops() -> TestResult
{
    let root = Root::new();
    let mut service = root.service()?;
    let (_, admin) = bootstrap(&mut service)?;
    let root_accessor = mount(&mut service, &admin, "")?;
    let root_entity = entity(&mut service, &admin, "root-owner")?;
    assert_eq!(
        call(
            &mut service,
            "POST",
            "sys/namespaces/legacy-child",
            &admin,
            json!({})
        )
        .status,
        200
    );
    let child_accessor = mount(&mut service, &admin, "legacy-child")?;
    for (namespace, accessor) in [("legacy-child", &root_accessor), ("", &child_accessor)] {
        let digest = service.state_digest;
        for route in ["entity-alias", "alias"] {
            assert_eq!(service.handle_at("POST", &format!("identity/{route}"), namespace, &admin,
                json!({"canonical_id":root_entity,"name":"cross","mount_accessor":accessor}), 100).status, 403);
            assert_eq!(service.state_digest, digest);
        }
    }
    let created = call(
        &mut service,
        "POST",
        "identity/alias",
        &admin,
        json!({"canonical_id":root_entity,"name":"retired","mount_accessor":root_accessor}),
    );
    let id = response_id(&created)?;
    let before = alias_read(&mut service, &admin, "alias", &id)?;
    assert_eq!(
        call(
            &mut service,
            "DELETE",
            "sys/auth/legacy-api",
            &admin,
            json!({})
        )
        .status,
        204
    );
    let digest = service.state_digest;
    for (route, body) in [
        ("entity-alias", json!({"name":"changed"})),
        ("entity-alias", json!({"metadata":{"ignored":"must-fence"}})),
        ("alias", json!({"custom_metadata":{"ignored":"must-fence"}})),
    ] {
        assert_eq!(
            call(
                &mut service,
                "POST",
                &format!("identity/{route}/id/{id}"),
                &admin,
                body
            )
            .status,
            400
        );
        assert_eq!(service.state_digest, digest);
    }
    let retired = alias_read(&mut service, &admin, "alias", &id)?;
    assert_eq!(retired["id"], before["id"]);
    assert_eq!(retired["name"], before["name"]);
    assert_eq!(retired["mount_path"], "");
    let replacement = mount(&mut service, &admin, "")?;
    assert_ne!(replacement, root_accessor);
    assert_eq!(
        call(
            &mut service,
            "POST",
            &format!("identity/alias/id/{id}"),
            &admin,
            json!({"metadata":{"ignored":"old-incarnation"}})
        )
        .status,
        400
    );
    assert_eq!(
        call(
            &mut service,
            "POST",
            &format!("identity/entity-alias/id/{id}"),
            &admin,
            json!({"mount_accessor":replacement})
        )
        .status,
        200
    );
    assert_eq!(
        alias_read(&mut service, &admin, "alias", &id)?["mount_path"],
        "auth/legacy-api/"
    );
    Ok(())
}

#[test]
fn identity270_persona_writes_entity_but_reads_lists_and_deletes_actual_alias() -> TestResult {
    let root = Root::new();
    let mut service = root.service()?;
    let (_, admin) = bootstrap(&mut service)?;
    let accessor = mount(&mut service, &admin, "")?;
    let owner = entity(&mut service, &admin, "persona-alias-owner")?;
    let created_alias = call(
        &mut service,
        "POST",
        "identity/entity-alias",
        &admin,
        json!({"canonical_id":owner,"name":"subject","mount_accessor":accessor,
            "custom_metadata":{"admin":"retained"}}),
    );
    let alias_id = response_id(&created_alias)?;
    let before = alias_read(&mut service, &admin, "entity-alias", &alias_id)?;
    assert_eq!(
        alias_read(&mut service, &admin, "persona", &alias_id)?,
        before
    );
    let persona = call(
        &mut service,
        "POST",
        "identity/persona",
        &admin,
        json!({"name":"persona-owned","entity_id":owner,"mount_accessor":accessor,
            "metadata":{"persona":"first"},"custom_metadata":{"ignored":true}}),
    );
    let persona_id = response_id(&persona)?;
    assert_ne!(persona_id, owner);
    assert_eq!(persona.body["data"]["aliases"], Value::Null);
    assert_eq!(persona.body["data"]["name"], "persona-owned");
    assert_eq!(
        call(
            &mut service,
            "GET",
            &format!("identity/persona/id/{persona_id}"),
            &admin,
            json!({})
        )
        .status,
        404
    );
    let actual_entity = call(
        &mut service,
        "GET",
        &format!("identity/entity/id/{persona_id}"),
        &admin,
        json!({}),
    );
    assert_eq!(actual_entity.status, 200);
    assert_eq!(
        actual_entity.body["data"]["metadata"],
        json!({"persona":"first"})
    );
    assert_eq!(
        call(
            &mut service,
            "POST",
            &format!("identity/persona/id/{persona_id}"),
            &admin,
            json!({"name":"persona-renamed","metadata":{"persona":"later"}})
        )
        .status,
        204
    );
    let changed = call(
        &mut service,
        "GET",
        &format!("identity/entity/id/{persona_id}"),
        &admin,
        json!({}),
    );
    assert_eq!(changed.body["data"]["name"], "persona-renamed");
    assert_eq!(changed.body["data"]["metadata"], json!({"persona":"later"}));
    let digest = service.state_digest;
    let rejected = call(
        &mut service,
        "POST",
        &format!("identity/persona/id/{alias_id}"),
        &admin,
        json!({"name":"cannot-write-alias","metadata":{"forged":"provider"}}),
    );
    assert_eq!(rejected.status, 400);
    assert_eq!(rejected.body["errors"][0], "entity not found from id");
    assert_eq!(service.state_digest, digest);
    assert_eq!(
        alias_read(&mut service, &admin, "entity-alias", &alias_id)?,
        before
    );
    assert_eq!(
        call(
            &mut service,
            "POST",
            "identity/persona",
            &admin,
            json!({"id":persona_id,"metadata":{"persona":"collection"}})
        )
        .status,
        204
    );
    let listed = call(
        &mut service,
        "LIST",
        "identity/persona/id",
        &admin,
        json!({}),
    );
    assert_eq!(listed.status, 200);
    assert_eq!(listed.body["data"]["keys"], json!([alias_id]));
    assert_eq!(
        call(
            &mut service,
            "DELETE",
            &format!("identity/persona/id/{persona_id}"),
            &admin,
            json!({})
        )
        .status,
        204
    );
    assert_eq!(
        call(
            &mut service,
            "GET",
            &format!("identity/entity/id/{persona_id}"),
            &admin,
            json!({})
        )
        .status,
        200
    );
    assert_eq!(
        call(
            &mut service,
            "DELETE",
            &format!("identity/persona/id/{alias_id}"),
            &admin,
            json!({})
        )
        .status,
        204
    );
    assert_eq!(
        call(
            &mut service,
            "GET",
            &format!("identity/entity-alias/id/{alias_id}"),
            &admin,
            json!({})
        )
        .status,
        404
    );
    assert_eq!(
        call(
            &mut service,
            "GET",
            &format!("identity/entity/id/{owner}"),
            &admin,
            json!({})
        )
        .status,
        200
    );
    assert_eq!(
        call(
            &mut service,
            "LIST",
            "identity/persona/id",
            &admin,
            json!({})
        )
        .status,
        404
    );
    let implicit = call(&mut service, "POST", "identity/persona", &admin, json!({}));
    let implicit_id = response_id(&implicit)?;
    assert_eq!(
        call(
            &mut service,
            "GET",
            &format!("identity/entity/id/{implicit_id}"),
            &admin,
            json!({})
        )
        .status,
        200
    );
    Ok(())
}

#[test]
fn identity270_persona_ignored_foreign_fields_keep_namespace_local_owner_and_encrypted_reopen()
-> TestResult {
    let root = Root::new();
    let mut service = root.service()?;
    let (key, admin) = bootstrap(&mut service)?;
    let root_accessor = mount(&mut service, &admin, "")?;
    let root_entity = entity(&mut service, &admin, "persona-root")?;
    assert_eq!(
        call(
            &mut service,
            "POST",
            "sys/namespaces/persona-child",
            &admin,
            json!({})
        )
        .status,
        200
    );
    let created = service.handle_at(
        "POST",
        "identity/persona",
        "persona-child",
        &admin,
        json!({"name":"child-owned","entity_id":root_entity,"mount_accessor":root_accessor,
            "canonical_id":"ignored","metadata":{"scope":"child"}}),
        100,
    );
    let id = response_id(&created)?;
    assert_ne!(id, root_entity);
    let read = service.handle_at(
        "GET",
        &format!("identity/entity/id/{id}"),
        "persona-child",
        &admin,
        json!({}),
        100,
    );
    assert_eq!(read.status, 200);
    assert_eq!(read.body["data"]["metadata"], json!({"scope":"child"}));
    assert_eq!(
        call(
            &mut service,
            "GET",
            &format!("identity/entity/id/{id}"),
            &admin,
            json!({})
        )
        .status,
        404
    );
    drop(service);
    let mut reopened = root.service()?;
    assert_eq!(
        call(&mut reopened, "POST", "sys/unseal", "", json!({"key":key})).status,
        200
    );
    let read_after = reopened.handle_at(
        "GET",
        &format!("identity/entity/id/{id}"),
        "persona-child",
        &admin,
        json!({}),
        100,
    );
    assert_eq!(read_after.status, 200);
    assert_eq!(read_after.body["data"], read.body["data"]);
    assert_eq!(
        reopened
            .handle_at(
                "GET",
                &format!("identity/persona/id/{id}"),
                "persona-child",
                &admin,
                json!({}),
                100
            )
            .status,
        404
    );
    Ok(())
}

#[test]
fn identity270_public_alias_metadata_noop_preserves_actual_signed_provider_observation_and_restart()
-> TestResult {
    let root = Root::new();
    let mut service = root.service()?;
    let (key, admin) = bootstrap(&mut service)?;
    let pair = Ed25519KeyPair::from_seed_unchecked(&[72; 32]).map_err(|_| "test key")?;
    for (path, body) in [
        ("sys/auth/jwt", json!({"type":"jwt"})),
        (
            "auth/jwt/config",
            json!({"issuer":"https://issuer.example","audiences":["service"],
            "keys":[{"kid":"key","algorithm":"EdDSA","key_base64":URL_SAFE_NO_PAD.encode(pair.public_key().as_ref())}]}),
        ),
        (
            "auth/jwt/role/first",
            json!({"role_type":"jwt","user_claim":"sub","bound_audiences":["service"],
            "token_ttl":60,"token_max_ttl":600}),
        ),
    ] {
        assert_eq!(call(&mut service, "POST", path, &admin, body).status, 204);
    }
    let signed = format!("{}.{}", URL_SAFE_NO_PAD.encode(br#"{"alg":"EdDSA","kid":"key"}"#),
        URL_SAFE_NO_PAD.encode(br#"{"iss":"https://issuer.example","aud":"service","sub":"subject","iat":100,"exp":1000}"#));
    let jwt = format!(
        "{signed}.{}",
        URL_SAFE_NO_PAD.encode(pair.sign(signed.as_bytes()).as_ref())
    );
    let issued = call(
        &mut service,
        "POST",
        "auth/jwt/login",
        "",
        json!({"role":"first","jwt":jwt}),
    );
    assert_eq!(issued.status, 200);
    let entity = issued.body["auth"]["entity_id"]
        .as_str()
        .ok_or("issued entity")?;
    let data = call(
        &mut service,
        "GET",
        &format!("identity/entity/id/{entity}"),
        &admin,
        json!({}),
    );
    assert_eq!(data.status, 200);
    let id = data.body["data"]["aliases"]
        .as_array()
        .and_then(|aliases| aliases.first())
        .and_then(|alias| alias["id"].as_str())
        .ok_or("native login alias")?
        .to_owned();
    let before = alias_read(&mut service, &admin, "entity-alias", &id)?;
    assert_eq!(before["metadata"], json!({"role":"first"}));
    let digest = service.state_digest;
    for route in ["entity-alias", "alias"] {
        assert_eq!(
            call(
                &mut service,
                "POST",
                &format!("identity/{route}/id/{id}"),
                &admin,
                json!({"metadata":{"role":"forged"}})
            )
            .status,
            204
        );
        assert_eq!(service.state_digest, digest);
        assert_eq!(
            alias_read(&mut service, &admin, "entity-alias", &id)?,
            before
        );
    }
    drop(service);
    let mut reopened = root.service()?;
    assert_eq!(
        call(&mut reopened, "POST", "sys/unseal", "", json!({"key":key})).status,
        200
    );
    assert_eq!(
        alias_read(&mut reopened, &admin, "entity-alias", &id)?,
        before
    );
    Ok(())
}

#[test]
fn identity270_alias_api_acl_denial_cannot_allocate_implicit_entity_or_mutate_existing_alias()
-> TestResult {
    let root = Root::new();
    let mut service = root.service()?;
    let (_, admin) = bootstrap(&mut service)?;
    let accessor = mount(&mut service, &admin, "")?;
    let owner = entity(&mut service, &admin, "acl-owner")?;
    let created = call(
        &mut service,
        "POST",
        "identity/entity-alias",
        &admin,
        json!({"canonical_id":owner,"name":"acl-subject","mount_accessor":accessor}),
    );
    let id = response_id(&created)?;
    for (path, body) in [
        (
            "sys/policies/acl/alias-reader",
            json!({"policy":
            "path \"identity/*\" { capabilities = [\"read\", \"list\"] }"}),
        ),
        (
            "auth/legacy-api/users/viewer",
            json!({"password":"fixture-password",
            "policies":["alias-reader"]}),
        ),
    ] {
        assert_eq!(call(&mut service, "POST", path, &admin, body).status, 204);
    }
    let issued = call(
        &mut service,
        "POST",
        "auth/legacy-api/login/viewer",
        "",
        json!({"password":"fixture-password"}),
    );
    assert_eq!(issued.status, 200);
    let token = issued.body["auth"]["client_token"]
        .as_str()
        .ok_or("native limited token")?;
    assert_eq!(
        call(
            &mut service,
            "GET",
            &format!("identity/alias/id/{id}"),
            token,
            json!({})
        )
        .status,
        200
    );
    let digest = service.state_digest;
    for (path, body) in [
        (
            "identity/alias".to_owned(),
            json!({"name":"forbidden-implicit","mount_accessor":accessor}),
        ),
        (
            format!("identity/entity-alias/id/{id}"),
            json!({"metadata":{"ignored":"must-authorize"}}),
        ),
        (
            format!("identity/persona/id/{owner}"),
            json!({"metadata":{"forbidden":"entity"}}),
        ),
    ] {
        assert_eq!(call(&mut service, "POST", &path, token, body).status, 403);
        assert_eq!(service.state_digest, digest);
    }
    Ok(())
}
