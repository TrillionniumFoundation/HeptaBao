//! Native retired-issuer oracle: PKI/native-external-retired-official-r03-data.
//! Distinct real Transit keys preserve their original KMS/signature owner.
use super::*;
use openssl::x509::{X509, X509Crl};

fn second_signer(remote: &RemoteTransit, service: &mut Service, admin: &str) -> TestResult {
    assert_eq!(
        call(
            &mut *remote.service.lock().map_err(|_| "remote lock")?,
            "POST",
            "transit/keys/second",
            &remote.admin,
            json!({"type":"ed25519"})
        )
        .status,
        200
    );
    for (path, body) in [
        (
            "sys/external-keys/configs/remote/keys/v3",
            json!({"verify":false,"name":"second","version":1}),
        ),
        (
            "sys/external-keys/configs/remote/keys/v3/grants/external-ca",
            json!({}),
        ),
    ] {
        assert_eq!(call(service, "POST", path, admin, body).status, 204);
    }
    Ok(())
}
fn root_request(reference: &str, name: &str) -> Value {
    json!({"external_key_ref":reference,"common_name":format!("{name}.example.test"),"ttl":"1h","issuer_name":name,"key_name":name})
}
fn cert(response: &Response) -> TestResult<X509> {
    Ok(X509::from_pem(
        response.body["data"]["certificate"]
            .as_str()
            .ok_or("signed certificate")?
            .as_bytes(),
    )?)
}
fn leaf(service: &mut Service, admin: &str, path: &str) -> Response {
    call(
        service,
        "POST",
        path,
        admin,
        json!({"common_name":"leaf.example.test","ttl":"10m"}),
    )
}

#[test]
fn pki_history94_distinct_real_signers_default_alias_retired_crls_and_encrypted_restart()
-> TestResult {
    let remote = RemoteTransit::new_kind("ed25519")?;
    let (root, mut service, unseal, admin) = pki_fixture(&remote)?;
    let first = call(
        &mut service,
        "POST",
        "external-ca/root/generate/kms",
        &admin,
        root_request("remote:v2", "first"),
    );
    assert_eq!(first.status, 200);
    let first_id = first.body["data"]["issuer_id"]
        .as_str()
        .ok_or("first ID")?
        .to_owned();
    let first_cert = cert(&first)?;
    let first_public = first_cert.public_key()?;
    assert_eq!(
        call(
            &mut service,
            "POST",
            "external-ca/roles/leaf",
            &admin,
            json!({"allow_any_name":true,"key_type":"ed25519","ttl":"10m","max_ttl":"30m"})
        )
        .status,
        200
    );
    let original = service.state.as_ref().ok_or("actual predecessor")?.clone();
    assert_eq!(original.schema, PKI_ROLE_NAMES_STATE_SCHEMA);
    assert!(!original.engines.has_external_pki_signer_history());
    let backup = Zeroizing::new(service.durable.as_ref().ok_or("durable")?.export_backup()?);
    let old_leaf = leaf(&mut service, &admin, "external-ca/issue/leaf");
    assert_eq!(old_leaf.status, 200);
    assert!(cert(&old_leaf)?.verify(&first_public)?);
    second_signer(&remote, &mut service, &admin)?;
    let before = remote.calls()?;
    let second = call(
        &mut service,
        "POST",
        "external-ca/root/generate/kms",
        &admin,
        root_request("remote:v3", "second"),
    );
    assert_eq!(second.status, 200);
    assert_eq!(remote.calls()?, before + 4);
    let second_id = second.body["data"]["issuer_id"]
        .as_str()
        .ok_or("second ID")?
        .to_owned();
    let second_public = cert(&second)?.public_key()?;
    assert_ne!(
        first_public.public_key_to_der()?,
        second_public.public_key_to_der()?
    );
    let current = service.state.as_ref().ok_or("actual history")?;
    assert_eq!(current.schema, EXTERNAL_PKI_SIGNER_HISTORY_STATE_SCHEMA);
    assert!(current.validate_format().is_ok());
    assert_eq!(
        call(
            &mut service,
            "GET",
            "external-ca/config/issuers",
            &admin,
            json!({})
        )
        .body["data"]["default"],
        first_id
    );
    assert_eq!(
        call(
            &mut service,
            "POST",
            "external-ca/config/issuers",
            &admin,
            json!({"default":second_id})
        )
        .status,
        200
    );
    let fresh = leaf(&mut service, &admin, "external-ca/issue/leaf");
    assert_eq!(fresh.status, 200);
    assert!(cert(&fresh)?.verify(&second_public)?);
    assert!(!cert(&fresh)?.verify(&first_public)?);
    let explicit = leaf(
        &mut service,
        &admin,
        &format!("external-ca/issuer/{first_id}/issue/leaf"),
    );
    assert_eq!(
        explicit.status, 200,
        "safe public errors: {:?}",
        explicit.body["errors"]
    );
    assert!(cert(&explicit)?.verify(&first_public)?);
    assert!(!cert(&explicit)?.verify(&second_public)?);
    let old_serial = old_leaf.body["data"]["serial_number"].clone();
    assert_eq!(
        call(
            &mut service,
            "POST",
            "external-ca/revoke",
            &admin,
            json!({"serial_number":old_serial})
        )
        .status,
        200
    );
    for (id, public, wrong, revoked) in [
        (&first_id, &first_public, &second_public, true),
        (&second_id, &second_public, &first_public, false),
    ] {
        let response = call(
            &mut service,
            "GET",
            &format!("external-ca/issuer/{id}/crl"),
            "",
            json!({}),
        );
        assert_eq!(response.status, 200);
        let crl = X509Crl::from_pem(
            response.body["data"]["crl"]
                .as_str()
                .ok_or("actual issuer CRL")?
                .as_bytes(),
        )?;
        assert!(crl.verify(public)?);
        assert!(!crl.verify(wrong)?);
        assert_eq!(crl.get_revoked().is_some(), revoked);
    }
    assert!(service.prepare_snapshot_restore(&backup).is_err());
    let mut lower = service.state.as_ref().ok_or("current")?.clone();
    lower.schema = 93;
    assert_eq!(lower.writer_schema(), 94);
    assert!(lower.validate_format().is_err());
    assert!(lower.validate_publication_schema(Some(&original)).is_err());
    drop(service);
    let mut reopened = root.service()?;
    reopened.install_outbound_endpoints(vec![remote.endpoint()])?;
    assert_eq!(
        call(
            &mut reopened,
            "POST",
            "sys/unseal",
            "",
            json!({"key":unseal})
        )
        .status,
        200
    );
    assert_eq!(reopened.state.as_ref().ok_or("restart")?.schema, 94);
    let old_again = leaf(&mut reopened, &admin, "external-ca/issuer/first/issue/leaf");
    assert_eq!(old_again.status, 200);
    assert!(cert(&old_again)?.verify(&first_public)?);
    let before = remote.calls()?;
    assert_eq!(
        call(
            &mut reopened,
            "DELETE",
            "external-ca/root",
            &admin,
            json!({})
        )
        .status,
        200
    );
    assert_eq!(remote.calls()?, before);
    let after_delete = call(
        &mut reopened,
        "POST",
        "external-ca/revoke",
        &admin,
        json!({"serial_number":old_again.body["data"]["serial_number"]}),
    );
    assert_eq!(after_delete.status, 200);
    assert_eq!(
        remote.calls()?,
        before,
        "no signing credential can be recovered from public archive"
    );
    assert!(reopened.prepare_snapshot_restore(&backup).is_err());
    assert_eq!(reopened.state.as_ref().ok_or("retired floor")?.schema, 94);
    Ok(())
}

#[test]
fn pki_history94_private_reference_tamper_and_current_grant_revocation_fail_before_effect()
-> TestResult {
    let remote = RemoteTransit::new_kind("ed25519")?;
    let (_root, mut service, _unseal, admin) = pki_fixture(&remote)?;
    let first = call(
        &mut service,
        "POST",
        "external-ca/root/generate/kms",
        &admin,
        root_request("remote:v2", "first"),
    );
    assert_eq!(first.status, 200);
    assert_eq!(
        call(
            &mut service,
            "POST",
            "external-ca/roles/leaf",
            &admin,
            json!({"allow_any_name":true,"key_type":"ed25519","ttl":"10m","max_ttl":"30m"})
        )
        .status,
        200
    );
    second_signer(&remote, &mut service, &admin)?;
    let second = call(
        &mut service,
        "POST",
        "external-ca/root/generate/kms",
        &admin,
        root_request("remote:v3", "second"),
    );
    assert_eq!(second.status, 200);
    let second_id = second.body["data"]["issuer_id"]
        .as_str()
        .ok_or("second ID")?;
    let current = service.state.as_ref().ok_or("current")?;
    let mut tampered = serde_json::to_value(current)?;
    let entries = &mut tampered["engines"]["namespaces"][""]["mounts"]["external-ca/"]["backend"]["Pki"]
        ["external"]["signer_history"]["other"];
    let entry = entries
        .as_object_mut()
        .and_then(|entries| entries.get_mut(second_id))
        .ok_or("actual private signer entry")?;
    entry["key"]["reference"] = json!("remote:v2");
    let hostile: State = serde_json::from_value(tampered)?;
    assert!(
        hostile.validate_format().is_err(),
        "original private owner binds the reference as well as actual signed CA"
    );
    let before = remote.calls()?;
    assert_eq!(
        call(
            &mut service,
            "DELETE",
            "sys/external-keys/configs/remote/keys/v3/grants/external-ca",
            &admin,
            json!({})
        )
        .status,
        204
    );
    let response = leaf(&mut service, &admin, "external-ca/issuer/second/issue/leaf");
    assert_eq!(response.status, 500);
    assert_eq!(
        remote.calls()?,
        before,
        "history retains reference, never a reusable grant"
    );
    assert_eq!(
        leaf(&mut service, &admin, "external-ca/issuer/first/issue/leaf").status,
        200
    );
    Ok(())
}
