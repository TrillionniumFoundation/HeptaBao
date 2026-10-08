//! Actual Service authentication/publication, not forged token JSON or an ACL renderer grant.
use super::tests::{Root, bootstrap_unmounted};
use super::*;
use ssh_key::{Certificate, HashAlg, PublicKey};
use std::time::{Duration, Instant};
type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

fn owned(
    service: &mut Service,
    namespace: &str,
    token: &str,
    method: &str,
    path: &str,
    body: Value,
) -> Response {
    let execution = service.begin_request_before(
        ServiceRequest {
            method,
            path,
            namespace,
            token,
            body,
            wrap_ttl_seconds: None,
            origin_peer: None,
            client_certificates: None,
        },
        Instant::now() + Duration::from_secs(15),
        false,
    );
    service.finish_synchronous_request(execution)
}
fn text(body: &Value, path: &str) -> TestResult<String> {
    Ok(body
        .pointer(path)
        .and_then(Value::as_str)
        .ok_or("actual response string")?
        .to_owned())
}
struct Fixture {
    root: Root,
    service: Service,
    admin: String,
    key: String,
    token: String,
    entity: String,
    issuer: String,
}
fn fixture() -> TestResult<Fixture> {
    let root = Root::new();
    let mut service = root.service()?;
    let (key, admin) = bootstrap_unmounted(&mut service)?;
    assert_eq!(
        owned(
            &mut service,
            "",
            &admin,
            "POST",
            "sys/mounts/ssh",
            json!({"type":"ssh"})
        )
        .status,
        204
    );
    let ca = owned(
        &mut service,
        "",
        &admin,
        "POST",
        "ssh/config/ca",
        json!({"key_type":"ed25519"}),
    );
    assert_eq!(ca.status, 200);
    let issuer = text(&ca.body, "/data/public_key")?;
    assert_eq!(
        owned(
            &mut service,
            "",
            &admin,
            "POST",
            "sys/policies/acl/ssh-user",
            json!({"policy":
        r#"path "ssh/sign/*" { capabilities = ["update"] }
path "ssh/issue/*" { capabilities = ["update"] }"#})
        )
        .status,
        204
    );
    assert_eq!(
        owned(
            &mut service,
            "",
            &admin,
            "POST",
            "sys/auth/people",
            json!({"type":"userpass"})
        )
        .status,
        204
    );
    assert_eq!(
        owned(
            &mut service,
            "",
            &admin,
            "POST",
            "auth/people/users/subject",
            json!({"password":"synthetic-SSH-password","token_policies":["ssh-user"]})
        )
        .status,
        204
    );
    let login = owned(
        &mut service,
        "",
        "",
        "POST",
        "auth/people/login/subject",
        json!({"password":"synthetic-SSH-password"}),
    );
    assert_eq!(login.status, 200);
    let token = text(&login.body, "/auth/client_token")?;
    let entity = text(&login.body, "/auth/entity_id")?;
    assert!(!entity.is_empty());
    assert_eq!(
        owned(
            &mut service,
            "",
            &admin,
            "POST",
            &format!("identity/entity/id/{entity}"),
            json!({"name":"request-subject","metadata":{"login":"alice"}})
        )
        .status,
        204
    );
    Ok(Fixture {
        root,
        service,
        admin,
        key,
        token,
        entity,
        issuer,
    })
}
fn certify(response: Response, issuer: &str) -> TestResult<Certificate> {
    assert_eq!(response.status, 200);
    let certificate = Certificate::from_openssh(&text(&response.body, "/data/signed_key")?)?;
    let public = PublicKey::from_openssh(issuer)?;
    certificate.validate_at(
        certificate.valid_after() + 1,
        [&public.fingerprint(HashAlg::Sha256)],
    )?;
    Ok(certificate)
}
fn template_role() -> Value {
    json!({"key_type":"ca","allow_user_certificates":true,
        "default_user":"{{identity.entity.metadata.login}}","default_user_template":true,
        "allowed_users":"{{identity.groups.names.team@ops.metadata.users}}","allowed_users_template":true,
        "default_extensions_template":true,
        "default_extensions":{"subject":"{{identity.entity.id}}","team":"{{identity.groups.names.team@ops.name}}"},
        "ttl":"60s"})
}
#[test]
fn ssh115_authenticated_current_entity_groups_and_original_admission_are_enforced() -> TestResult {
    let mut f = fixture()?;
    let group = owned(
        &mut f.service,
        "",
        &f.admin,
        "POST",
        "identity/group",
        json!({"name":"team@ops","type":"internal","member_entity_ids":[f.entity],"metadata":{"users":"alice"}}),
    );
    assert_eq!(group.status, 200);
    let group = text(&group.body, "/data/id")?;
    assert_eq!(
        owned(
            &mut f.service,
            "",
            &f.admin,
            "POST",
            "ssh/roles/operators",
            template_role()
        )
        .status,
        204
    );
    let issued = owned(
        &mut f.service,
        "",
        &f.token,
        "POST",
        "ssh/issue/operators",
        json!({"key_type":"ed25519","entity_id":"caller-forged-entity"}),
    );
    let certificate = certify(issued, &f.issuer)?;
    assert_eq!(certificate.valid_principals(), &["alice".to_owned()]);
    assert_eq!(
        certificate.extensions().get("subject").map(String::as_str),
        Some(f.entity.as_str())
    );
    assert_eq!(
        certificate.extensions().get("team").map(String::as_str),
        Some("team@ops")
    );
    assert_eq!(
        owned(
            &mut f.service,
            "",
            &f.admin,
            "POST",
            &format!("identity/entity/id/{}", f.entity),
            json!({"metadata":{"login":"bob"}})
        )
        .status,
        204
    );
    let denied = owned(
        &mut f.service,
        "",
        &f.token,
        "POST",
        "ssh/issue/operators",
        json!({"key_type":"ed25519"}),
    );
    assert_eq!(denied.status, 400);
    assert!(denied.body.get("data").is_none());
    assert_eq!(
        owned(
            &mut f.service,
            "",
            &f.admin,
            "POST",
            &format!("identity/group/id/{group}"),
            json!({"metadata":{"users":"bob"}})
        )
        .status,
        204
    );
    let updated = certify(
        owned(
            &mut f.service,
            "",
            &f.token,
            "POST",
            "ssh/issue/operators",
            json!({"key_type":"ed25519"}),
        ),
        &f.issuer,
    )?;
    assert_eq!(updated.valid_principals(), &["bob".to_owned()]);
    assert_eq!(
        owned(
            &mut f.service,
            "",
            &f.admin,
            "POST",
            &format!("identity/group/id/{group}"),
            json!({"member_entity_ids":[]})
        )
        .status,
        204
    );
    assert_eq!(
        owned(
            &mut f.service,
            "",
            &f.token,
            "POST",
            "ssh/issue/operators",
            json!({"key_type":"ed25519"})
        )
        .status,
        400
    );
    assert_eq!(
        owned(
            &mut f.service,
            "",
            &f.admin,
            "POST",
            &format!("identity/group/id/{group}"),
            json!({"member_entity_ids":[f.entity]})
        )
        .status,
        204
    );
    assert_eq!(
        owned(
            &mut f.service,
            "",
            "",
            "POST",
            "ssh/issue/operators",
            json!({"key_type":"ed25519"})
        )
        .status,
        403
    );
    assert_eq!(
        owned(
            &mut f.service,
            "",
            &f.admin,
            "POST",
            &format!("identity/entity/id/{}", f.entity),
            json!({"disabled":true})
        )
        .status,
        204
    );
    let disabled = owned(
        &mut f.service,
        "",
        &f.token,
        "POST",
        "ssh/issue/operators",
        json!({"key_type":"ed25519"}),
    );
    assert_eq!(disabled.status, 403);
    assert!(disabled.body.get("data").is_none());
    assert_eq!(
        owned(
            &mut f.service,
            "",
            &f.admin,
            "POST",
            &format!("identity/entity/id/{}", f.entity),
            json!({"disabled":false})
        )
        .status,
        204
    );
    let execution = f.service.begin_request_before(
        ServiceRequest {
            method: "POST",
            path: "ssh/issue/operators",
            namespace: "",
            token: &f.token,
            body: json!({"key_type":"ed25519"}),
            wrap_ttl_seconds: None,
            origin_peer: None,
            client_certificates: None,
        },
        Instant::now() - Duration::from_millis(1),
        false,
    );
    let expired = f.service.finish_synchronous_request(execution);
    assert_eq!(expired.status, 503);
    assert!(expired.body.get("data").is_none());
    Ok(())
}
#[test]
fn ssh115_same_namespace_retained_alias_is_data_and_survives_real_encrypted_reopen() -> TestResult {
    let mut f = fixture()?;
    assert_eq!(
        owned(
            &mut f.service,
            "",
            &f.admin,
            "POST",
            "sys/auth/retained",
            json!({"type":"userpass"})
        )
        .status,
        204
    );
    let mounts = owned(&mut f.service, "", &f.admin, "GET", "sys/auth", json!({}));
    assert_eq!(mounts.status, 200);
    let accessor = text(&mounts.body, "/data/retained~1/accessor")?;
    let alias = owned(
        &mut f.service,
        "",
        &f.admin,
        "POST",
        "identity/entity-alias",
        json!({"name":"retained-data","canonical_id":f.entity,"mount_accessor":accessor,"custom_metadata":{"login":"alice"}}),
    );
    assert_eq!(alias.status, 200);
    let alias = text(&alias.body, "/data/id")?;
    let selector = format!("{{{{identity.entity.aliases.{accessor}.custom_metadata.login}}}}");
    assert_eq!(
        owned(
            &mut f.service,
            "",
            &f.admin,
            "POST",
            "ssh/roles/retained",
            json!({"key_type":"ca","allow_user_certificates":true,"allowed_users":"alice",
            "default_user_template":true,"default_user":selector,"ttl":"60s"})
        )
        .status,
        204
    );
    assert_eq!(
        owned(
            &mut f.service,
            "",
            &f.admin,
            "DELETE",
            "sys/auth/retained",
            json!({})
        )
        .status,
        204
    );
    assert_eq!(
        owned(
            &mut f.service,
            "",
            &f.admin,
            "GET",
            "sys/auth/retained",
            json!({})
        )
        .status,
        404
    );
    assert_eq!(
        owned(
            &mut f.service,
            "",
            &f.admin,
            "GET",
            &format!("identity/entity-alias/id/{alias}"),
            json!({})
        )
        .status,
        200
    );
    let certificate = certify(
        owned(
            &mut f.service,
            "",
            &f.token,
            "POST",
            "ssh/issue/retained",
            json!({"key_type":"ed25519"}),
        ),
        &f.issuer,
    )?;
    assert_eq!(certificate.valid_principals(), &["alice".to_owned()]);
    let Fixture {
        root,
        service,
        admin,
        key,
        token,
        entity,
        issuer,
    } = f;
    drop(service);
    let mut service = root.service()?;
    assert_eq!(
        owned(
            &mut service,
            "",
            "",
            "POST",
            "sys/unseal",
            json!({"key":key})
        )
        .status,
        200
    );
    assert_eq!(
        service.state.as_ref().ok_or("reopened State")?.schema,
        SSH_CA_STATE_SCHEMA
    );
    let certificate = certify(
        owned(
            &mut service,
            "",
            &token,
            "POST",
            "ssh/issue/retained",
            json!({"key_type":"ed25519"}),
        ),
        &issuer,
    )?;
    assert_eq!(certificate.valid_principals(), &["alice".to_owned()]);
    let retained = owned(
        &mut service,
        "",
        &admin,
        "GET",
        &format!("identity/entity-alias/id/{alias}"),
        json!({}),
    );
    assert_eq!(retained.status, 200);
    assert_eq!(retained.body["data"]["canonical_id"], entity);
    assert_eq!(
        owned(
            &mut service,
            "",
            &admin,
            "DELETE",
            &format!("identity/entity-alias/id/{alias}"),
            json!({})
        )
        .status,
        204
    );
    let missing = owned(
        &mut service,
        "",
        &token,
        "POST",
        "ssh/issue/retained",
        json!({"key_type":"ed25519"}),
    );
    assert_eq!(missing.status, 500);
    assert!(missing.body.get("data").is_none());
    Ok(())
}
#[test]
fn ssh115_no_entity_literal_default_extensions_warning_and_legacy_request_path() -> TestResult {
    let mut f = fixture()?;
    assert_eq!(owned(&mut f.service,"",&f.admin,"POST","ssh/roles/no-entity",
        json!({"key_type":"ca","allow_user_certificates":true,"allowed_users":"*",
            "default_user_template":true,"default_user":"{{identity.entity.name}}",
            "default_extensions_template":true,"default_extensions":{"literal":"static","skip":"{{identity.entity.id}}"},
            "ttl":"60s"})).status,204);
    let response = owned(
        &mut f.service,
        "",
        &f.admin,
        "POST",
        "ssh/issue/no-entity",
        json!({"key_type":"ed25519"}),
    );
    assert_eq!(response.status, 200);
    assert_eq!(
        response.body["warnings"]
            .as_array()
            .ok_or("real warning")?
            .len(),
        1
    );
    let certificate = certify(response, &f.issuer)?;
    assert_eq!(
        certificate.valid_principals(),
        &["{{identity.entity.name}}".to_owned()]
    );
    assert_eq!(
        certificate.extensions().get("literal").map(String::as_str),
        Some("static")
    );
    assert!(certificate.extensions().get("skip").is_none());

    // A separate actual RSA issuer drives the newly enabled authenticated route.
    assert_eq!(
        owned(
            &mut f.service,
            "",
            &f.admin,
            "POST",
            "sys/mounts/legacy",
            json!({"type":"ssh"})
        )
        .status,
        204
    );
    let ca = owned(
        &mut f.service,
        "",
        &f.admin,
        "POST",
        "legacy/config/ca",
        json!({"key_type":"rsa","key_bits":2048}),
    );
    assert_eq!(ca.status, 200);
    assert_eq!(owned(&mut f.service,"",&f.admin,"POST","legacy/roles/operators",
        json!({"key_type":"ca","allow_user_certificates":true,"allowed_users":"alice","default_user":"alice",
            "algorithm_signer":"ssh-rsa","ttl":"60s"})).status,204);
    let response = owned(
        &mut f.service,
        "",
        &f.admin,
        "POST",
        "legacy/issue/operators",
        json!({"key_type":"ed25519"}),
    );
    assert_eq!(response.status, 200);
    assert!(
        text(&response.body, "/data/signed_key")?.starts_with("ssh-ed25519-cert-v01@openssh.com ")
    );
    assert!(text(&response.body, "/data/signed_key")?.ends_with('\n'));
    assert!(!text(&response.body, "/data/private_key")?.is_empty());
    // Real SHA1/trusted-CA verification and all original wire fields are tested in the private producer.
    let issuer = owned(
        &mut f.service,
        "",
        &f.admin,
        "GET",
        "legacy/config/ca",
        json!({}),
    );
    assert_eq!(issuer.status, 200);
    assert_eq!(
        issuer.body["data"]["public_key"],
        ca.body["data"]["public_key"]
    );
    Ok(())
}
