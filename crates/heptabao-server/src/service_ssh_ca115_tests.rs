//! Actual encrypted Service publication and typed public HTTP custody.
use super::tests::{Root, bootstrap_unmounted, call};
use super::*;
use ssh_key::{Certificate, HashAlg, PublicKey};
type TestResult = Result<(), Box<dyn std::error::Error>>;

fn mount(service: &mut Service, admin: &str) {
    assert_eq!(
        call(
            service,
            "POST",
            "sys/mounts/ssh",
            admin,
            json!({"type":"ssh"})
        )
        .status,
        204
    );
}
fn ca(service: &mut Service, admin: &str) -> Response {
    call(
        service,
        "POST",
        "ssh/config/ca",
        admin,
        json!({"key_type":"ed25519"}),
    )
}
#[test]
fn ssh115_encrypted_reopen_real_signature_and_deleted_ca_sticky_restore_floor() -> TestResult {
    let directory = Root::new();
    let mut service = directory.service()?;
    let (unseal, admin) = bootstrap_unmounted(&mut service)?;
    mount(&mut service, &admin);
    let before = Zeroizing::new(service.durable.as_ref().ok_or("durable")?.export_backup()?);
    let created = ca(&mut service, &admin);
    assert_eq!(created.status, 200);
    let public = created.body["data"]["public_key"]
        .as_str()
        .ok_or("CA public")?
        .to_owned();
    assert_eq!(
        call(
            &mut service,
            "POST",
            "ssh/roles/operators",
            &admin,
            json!({"key_type":"ca","allow_user_certificates":true,"allowed_users":"alice",
            "default_user":"alice","ttl":"60s"})
        )
        .status,
        204
    );
    assert_eq!(
        service.state.as_ref().ok_or("state")?.schema,
        SSH_CA_STATE_SCHEMA
    );
    assert!(service.prepare_snapshot_restore(&before).is_err());
    drop(service);
    let mut service = directory.service()?;
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
    let issued = call(
        &mut service,
        "POST",
        "ssh/issue/operators",
        &admin,
        json!({"key_type":"ed25519"}),
    );
    assert_eq!(issued.status, 200);
    let certificate = Certificate::from_openssh(
        issued.body["data"]["signed_key"]
            .as_str()
            .ok_or("certificate")?,
    )?;
    certificate.validate_at(
        100,
        [&PublicKey::from_openssh(&public)?.fingerprint(HashAlg::Sha256)],
    )?;
    assert_eq!(
        call(&mut service, "DELETE", "ssh/config/ca", &admin, json!({})).status,
        200
    );
    assert_eq!(
        call(
            &mut service,
            "DELETE",
            "ssh/roles/operators",
            &admin,
            json!({})
        )
        .status,
        204
    );
    assert_eq!(
        call(&mut service, "DELETE", "sys/mounts/ssh", &admin, json!({})).status,
        204
    );
    let state = service.state.as_ref().ok_or("deleted CA state")?;
    assert_eq!(state.schema, SSH_CA_STATE_SCHEMA);
    assert!(state.engines.has_ssh_ca_state());
    assert!(service.prepare_snapshot_restore(&before).is_err());
    Ok(())
}
#[test]
fn ssh115_public_key_actual_mount_typed_raw_positive_wrap_and_anonymous_admin_denial() -> TestResult
{
    let directory = Root::new();
    let mut service = directory.service()?;
    let (_, admin) = bootstrap_unmounted(&mut service)?;
    mount(&mut service, &admin);
    let created = ca(&mut service, &admin);
    assert_eq!(created.status, 200);
    let public = created.body["data"]["public_key"]
        .as_str()
        .ok_or("public")?
        .to_owned();
    let issuer = created.body["data"]["issuer_id"]
        .as_str()
        .ok_or("issuer")?
        .to_owned();
    assert_eq!(
        call(&mut service, "GET", "ssh/config/ca", "", json!({})).status,
        403
    );
    for (sequence, path) in [
        "ssh/public_key".to_owned(),
        format!("ssh/issuer/{issuer}/public_key"),
    ]
    .iter()
    .enumerate()
    {
        let _ingress = crate::auth::IngressReplyScope::listener(&[0xc0 + sequence as u8; 16]);
        let response = call(&mut service, "GET", path, "", json!({}));
        assert_eq!(response.status, 200);
        let origin = response
            .unwrapped_json
            .as_ref()
            .ok_or("typed public transport")?;
        assert_eq!(
            origin.raw_http_transport(&response.body)?,
            Some((200, "text/plain"))
        );
        assert_eq!(
            origin.raw_bytes(&response.body)?.ok_or("public bytes")?,
            public.as_bytes()
        );
    }
    let wrapper = {
        let _ingress = crate::auth::IngressReplyScope::listener(&[0xc2; 16]);
        let mut request = ServiceRequest::new("GET", "ssh/public_key", "", &admin, json!({}));
        request.wrap_ttl_seconds = Some(60);
        let response = service.handle_request_at(request, 100);
        assert_eq!(response.status, 200);
        assert!(response.unwrapped_json.is_none());
        response.body["wrap_info"]["token"]
            .as_str()
            .ok_or("wrapper")?
            .to_owned()
    };
    let _ingress = crate::auth::IngressReplyScope::listener(&[0xc3; 16]);
    let response = call(
        &mut service,
        "POST",
        "sys/wrapping/unwrap",
        &admin,
        json!({"token":wrapper}),
    );
    assert_eq!(response.status, 200);
    let origin = response
        .unwrapped_json
        .as_ref()
        .ok_or("unwrapped public transport")?;
    assert_eq!(
        origin.raw_http_transport(&response.body)?,
        Some((200, "text/plain"))
    );
    assert_eq!(
        origin.raw_bytes(&response.body)?.ok_or("public bytes")?,
        public.as_bytes()
    );
    Ok(())
}
#[test]
fn ssh115_invalid_subject_does_not_publish_and_low_schema_or_missing_marker_rejected() -> TestResult
{
    let directory = Root::new();
    let mut service = directory.service()?;
    let (_, admin) = bootstrap_unmounted(&mut service)?;
    mount(&mut service, &admin);
    assert_eq!(ca(&mut service, &admin).status, 200);
    assert_eq!(
        call(
            &mut service,
            "POST",
            "ssh/roles/operators",
            &admin,
            json!({"key_type":"ca","allow_user_certificates":true,"allowed_users":"alice"})
        )
        .status,
        204
    );
    let original = service
        .current_state_identity()
        .map_err(|_| "current state identity")?;
    assert_eq!(
        call(
            &mut service,
            "POST",
            "ssh/sign/operators",
            &admin,
            json!({"public_key":"malformed","valid_principals":"alice"})
        )
        .status,
        400
    );
    assert_eq!(
        service
            .current_state_identity()
            .map_err(|_| "current state identity")?,
        original
    );
    let current = service.state.as_ref().ok_or("current")?.clone();
    let mut lower = current.clone();
    lower.schema = SSH_CA_STATE_SCHEMA - 1;
    assert!(lower.validate_publication_schema(Some(&current)).is_err());
    assert!(lower.validate_format().is_err());
    let mut value = serde_json::to_value(&*current.engines)?;
    value
        .as_object_mut()
        .ok_or("engine object")?
        .remove("ssh_ca_format");
    let absent: engines::EngineState = serde_json::from_value(value)?;
    assert!(absent.validate_ssh_ca_format().is_err());
    Ok(())
}
