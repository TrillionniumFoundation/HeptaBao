//! Genuine 270 TLS oracle: native-external-intermediate-official-r03-data.
use super::*;
use openssl::x509::{X509, X509Crl, X509Req};

fn parent(service: &mut Service, admin: &str) -> TestResult<Response> {
    assert_eq!(
        call(
            service,
            "POST",
            "sys/mounts/parent",
            admin,
            json!({"type":"pki"})
        )
        .status,
        204
    );
    let root = call(
        service,
        "POST",
        "parent/root/generate/internal",
        admin,
        json!({"common_name":"parent.example.test","key_type":"ed25519","ttl":"4h"}),
    );
    assert_eq!(root.status, 200);
    Ok(root)
}
fn certificate(response: &Response) -> TestResult<X509> {
    Ok(X509::from_pem(
        response.body["data"]["certificate"]
            .as_str()
            .ok_or("actual certificate")?
            .as_bytes(),
    )?)
}
fn generate(service: &mut Service, admin: &str) -> TestResult<Response> {
    let response = call(
        service,
        "POST",
        "external-ca/intermediate/generate/kms",
        admin,
        json!({"external_key_ref":"remote:v2","common_name":"child.example.test","key_name":"child"}),
    );
    assert_eq!(response.status, 200);
    Ok(response)
}
fn sign(service: &mut Service, admin: &str, csr: &Response) -> TestResult<Response> {
    let response = call(
        service,
        "POST",
        "parent/root/sign-intermediate",
        admin,
        json!({"csr":csr.body["data"]["csr"],"use_csr_values":true,"ttl":"2h","max_path_length":1}),
    );
    assert_eq!(response.status, 200);
    Ok(response)
}
fn bundle(child: &Response, parent: &Response) -> TestResult<Value> {
    Ok(
        json!({"certificate":format!("{}\n{}",child.body["data"]["certificate"].as_str().ok_or("child")?,parent.body["data"]["certificate"].as_str().ok_or("parent")?)}),
    )
}

#[test]
fn pki_external_intermediate94_all_seven_keys_signed_chain_leaf_crl_restart_and_floor() -> TestResult
{
    for kind in [
        "ed25519",
        "ecdsa-p256",
        "ecdsa-p384",
        "ecdsa-p521",
        "rsa-2048",
        "rsa-3072",
        "rsa-4096",
    ] {
        let remote = RemoteTransit::new_kind(kind)?;
        let (root, mut service, unseal, admin) = pki_fixture(&remote)?;
        let parent = parent(&mut service, &admin)?;
        let parent_key = certificate(&parent)?.public_key()?;
        let csr = generate(&mut service, &admin)?;
        let request = X509Req::from_pem(csr.body["data"]["csr"].as_str().ok_or("CSR")?.as_bytes())?;
        let request_public = request.public_key()?;
        assert!(request.verify(&request_public)?);
        let predecessor = service
            .state
            .as_ref()
            .ok_or("actual pending predecessor")?
            .clone();
        assert!(!predecessor.engines.has_external_pki_signer_history());
        let signed = sign(&mut service, &admin, &csr)?;
        let child = certificate(&signed)?;
        assert!(child.verify(&parent_key)?);
        assert_eq!(
            child.public_key()?.public_key_to_der()?,
            request.public_key()?.public_key_to_der()?
        );
        let before = remote.calls()?;
        let installed = call(
            &mut service,
            "POST",
            "external-ca/intermediate/set-signed",
            &admin,
            bundle(&signed, &parent)?,
        );
        assert_eq!(
            installed.status, 200,
            "safe errors {:?}",
            installed.body["errors"]
        );
        assert_eq!(
            remote.calls()?,
            before + 3,
            "same original pending reference metadata and two CRLs"
        );
        let mapping = installed.body["data"]["mapping"]
            .as_object()
            .ok_or("actual mapping")?;
        assert_eq!(mapping.len(), 2);
        let issuer = mapping
            .iter()
            .find(|(_, key)| **key == csr.body["data"]["key_id"])
            .map(|(id, _)| id.clone())
            .ok_or("actual owned issuer")?;
        let current = service.state.as_ref().ok_or("actual imported owner")?;
        assert_eq!(current.schema, 94);
        assert!(current.validate_format().is_ok());
        let mut lower = current.clone();
        lower.schema = 93;
        assert_eq!(lower.writer_schema(), 94);
        assert!(lower.validate_format().is_err());
        assert!(
            lower
                .validate_publication_schema(Some(&predecessor))
                .is_err()
        );
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
        let path = format!("external-ca/issuer/{issuer}/issue/leaf");
        let leaf = call(
            &mut service,
            "POST",
            &path,
            &admin,
            json!({"common_name":"leaf.example.test","ttl":"10m"}),
        );
        assert_eq!(leaf.status, 200, "safe errors {:?}", leaf.body["errors"]);
        let actual = certificate(&leaf)?;
        let child_key = child.public_key()?;
        assert!(actual.verify(&child_key)?);
        assert!(!actual.verify(&parent_key)?);
        assert_eq!(
            leaf.body["data"]["ca_chain"]
                .as_array()
                .ok_or("chain")?
                .len(),
            2
        );
        assert_eq!(
            call(
                &mut service,
                "POST",
                "external-ca/revoke",
                &admin,
                json!({"serial_number":leaf.body["data"]["serial_number"]})
            )
            .status,
            200
        );
        let crl = call(
            &mut service,
            "GET",
            &format!("external-ca/issuer/{issuer}/crl"),
            "",
            json!({}),
        );
        assert_eq!(crl.status, 200);
        let crl = X509Crl::from_pem(
            crl.body["data"]["crl"]
                .as_str()
                .ok_or("actual CRL")?
                .as_bytes(),
        )?;
        assert!(crl.verify(&child_key)?);
        assert!(!crl.verify(&parent_key)?);
        assert_eq!(crl.get_revoked().ok_or("actual revoked leaf")?.len(), 1);
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
        let again = call(
            &mut reopened,
            "POST",
            &path,
            &admin,
            json!({"common_name":"again.example.test","ttl":"10m"}),
        );
        assert_eq!(again.status, 200);
        assert!(certificate(&again)?.verify(&child_key)?);
    }
    Ok(())
}

#[test]
fn pki_external_intermediate94_wrong_key_bad_parent_and_revoked_grant_have_no_effect() -> TestResult
{
    let remote = RemoteTransit::new_kind("ed25519")?;
    let (_root, mut service, _unseal, admin) = pki_fixture(&remote)?;
    let parent = parent(&mut service, &admin)?;
    let csr = generate(&mut service, &admin)?;
    let signed = sign(&mut service, &admin, &csr)?;
    for certificate in [
        parent.body["data"]["certificate"].clone(),
        signed.body["data"]["certificate"].clone(),
    ] {
        let before = remote.calls()?;
        let response = call(
            &mut service,
            "POST",
            "external-ca/intermediate/set-signed",
            &admin,
            json!({"certificate":certificate}),
        );
        assert_eq!(response.status, 400);
        assert_eq!(remote.calls()?, before);
        assert!(
            !service
                .state
                .as_ref()
                .ok_or("unpublished")?
                .engines
                .has_external_pki_signer_history()
        );
    }
    assert_eq!(
        call(
            &mut service,
            "DELETE",
            "sys/external-keys/configs/remote/keys/v2/grants/external-ca",
            &admin,
            json!({})
        )
        .status,
        204
    );
    let before = remote.calls()?;
    let response = call(
        &mut service,
        "POST",
        "external-ca/intermediate/set-signed",
        &admin,
        bundle(&signed, &parent)?,
    );
    assert_eq!(response.status, 400);
    assert_eq!(remote.calls()?, before);
    assert!(
        !service
            .state
            .as_ref()
            .ok_or("unpublished")?
            .engines
            .has_external_pki_signer_history()
    );
    Ok(())
}

fn local_child_csr(service: &mut Service, admin: &str) -> TestResult<Response> {
    assert_eq!(
        call(
            service,
            "POST",
            "sys/mounts/child",
            admin,
            json!({"type":"pki"})
        )
        .status,
        204
    );
    let csr = call(
        service,
        "POST",
        "child/intermediate/generate/internal",
        admin,
        json!({"common_name":"child.example.test","key_type":"ed25519"}),
    );
    assert_eq!(csr.status, 200);
    Ok(csr)
}
#[test]
fn pki_external_intermediate94_seven_remote_parents_sign_current_csr_and_restart() -> TestResult {
    for kind in [
        "ed25519",
        "ecdsa-p256",
        "ecdsa-p384",
        "ecdsa-p521",
        "rsa-2048",
        "rsa-3072",
        "rsa-4096",
    ] {
        let remote = RemoteTransit::new_kind(kind)?;
        let (root, mut service, unseal, admin) = pki_fixture(&remote)?;
        let parent = call(
            &mut service,
            "POST",
            "external-ca/root/generate/kms",
            &admin,
            json!({"external_key_ref":"remote:v2","common_name":"parent.example.test","ttl":"4h","issuer_name":"parent"}),
        );
        assert_eq!(parent.status, 200);
        let csr = local_child_csr(&mut service, &admin)?;
        let prior = service.state.as_ref().ok_or("actual predecessor")?.clone();
        assert!(!prior.engines.has_external_pki_signer_history());
        let id = parent.body["data"]["issuer_id"]
            .as_str()
            .ok_or("parent issuer")?;
        let path = format!("external-ca/issuer/{id}/sign-intermediate");
        let before = remote.calls()?;
        let signed = call(
            &mut service,
            "POST",
            &path,
            &admin,
            json!({"csr":csr.body["data"]["csr"],"use_csr_values":true,"ttl":"2h","max_path_length":1}),
        );
        assert_eq!(
            signed.status, 200,
            "safe errors {:?}",
            signed.body["errors"]
        );
        assert_eq!(
            remote.calls()?,
            before + 2,
            "same selected provider metadata and one CA signature"
        );
        let child = certificate(&signed)?;
        let parent_key = certificate(&parent)?.public_key()?;
        assert!(child.verify(&parent_key)?);
        let request = X509Req::from_pem(csr.body["data"]["csr"].as_str().ok_or("CSR")?.as_bytes())?;
        assert_eq!(
            child.public_key()?.public_key_to_der()?,
            request.public_key()?.public_key_to_der()?
        );
        let current = service.state.as_ref().ok_or("actual CA owner")?;
        assert_eq!(current.schema, 94);
        assert!(current.validate_format().is_ok());
        let mut lower = current.clone();
        lower.schema = 93;
        assert_eq!(lower.writer_schema(), 94);
        assert!(lower.validate_format().is_err());
        let installed = call(
            &mut service,
            "POST",
            "child/intermediate/set-signed",
            &admin,
            bundle(&signed, &parent)?,
        );
        assert_eq!(installed.status, 200);
        assert_eq!(
            call(
                &mut service,
                "POST",
                "child/roles/leaf",
                &admin,
                json!({"allow_any_name":true,"key_type":"ed25519","ttl":"10m","max_ttl":"30m"})
            )
            .status,
            200
        );
        let leaf = call(
            &mut service,
            "POST",
            "child/issue/leaf",
            &admin,
            json!({"common_name":"leaf.example.test","ttl":"10m"}),
        );
        assert_eq!(leaf.status, 200);
        let child_public = child.public_key()?;
        assert!(certificate(&leaf)?.verify(&child_public)?);
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
        let signed_again = call(
            &mut reopened,
            "POST",
            "external-ca/issuer/parent/sign-intermediate",
            &admin,
            json!({"csr":csr.body["data"]["csr"],"use_csr_values":true,"ttl":"1h","max_path_length":0}),
        );
        assert_eq!(signed_again.status, 200);
        assert!(certificate(&signed_again)?.verify(&parent_key)?);
    }
    Ok(())
}
#[test]
fn pki_external_intermediate94_selected_parent_grant_revocation_precedes_signing() -> TestResult {
    let remote = RemoteTransit::new_kind("ed25519")?;
    let (_root, mut service, _unseal, admin) = pki_fixture(&remote)?;
    assert_eq!(
        call(
            &mut service,
            "POST",
            "external-ca/root/generate/kms",
            &admin,
            body()
        )
        .status,
        200
    );
    let csr = local_child_csr(&mut service, &admin)?;
    assert_eq!(
        call(
            &mut service,
            "DELETE",
            "sys/external-keys/configs/remote/keys/v2/grants/external-ca",
            &admin,
            json!({})
        )
        .status,
        204
    );
    let before = remote.calls()?;
    let response = call(
        &mut service,
        "POST",
        "external-ca/root/sign-intermediate",
        &admin,
        json!({"csr":csr.body["data"]["csr"],"ttl":"1h"}),
    );
    assert_eq!(response.status, 400);
    assert_eq!(remote.calls()?, before);
    assert!(
        !service
            .state
            .as_ref()
            .ok_or("unpublished")?
            .engines
            .has_external_pki_signer_history()
    );
    Ok(())
}
