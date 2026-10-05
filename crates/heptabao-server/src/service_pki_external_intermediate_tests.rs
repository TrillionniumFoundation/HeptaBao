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
        "external-ca/intermediate/generate/kms-remote",
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
    assert_eq!(
        response.status, 200,
        "parent sign errors={}",
        response.body["errors"]
    );
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
        assert_eq!(
            signed_again.status, 200,
            "kind={kind} restart parent sign errors={}",
            signed_again.body["errors"]
        );
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

// Genuine ca305 ca_util.go::generateCSRBundle and actual R11 seven-SPKI
// mismatch: the standard kms endpoint owns a fresh local key after metadata.
#[test]
fn pki_native_kms_csr_seven_types_local_owner_without_sign_grant_import_and_restart() -> TestResult
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
        let parent_public = certificate(&parent)?.public_key()?;
        let before = remote.calls()?;
        let csr = call(
            &mut service,
            "POST",
            "external-ca/intermediate/generate/kms",
            &admin,
            json!({"external_key_ref":"remote:v2","common_name":"native-child.example.test","key_name":"native-child"}),
        );
        assert_eq!(csr.status, 200, "native CSR public status");
        assert_eq!(
            remote.calls()?,
            before + 1,
            "metadata only, no remote signature"
        );
        let request = X509Req::from_pem(
            csr.body["data"]["csr"]
                .as_str()
                .ok_or("native CSR")?
                .as_bytes(),
        )?;
        let public = request.public_key()?;
        assert!(request.verify(&public)?);
        let mut provider = remote.service.lock().map_err(|_| "provider lock")?;
        let metadata = call(
            &mut provider,
            "GET",
            "transit/keys/remote",
            &remote.admin,
            json!({}),
        );
        drop(provider);
        let remote_public = crate::engines::ExternalPkiPublicKey::from_metadata(
            kind,
            metadata.body["data"]["keys"]["2"]["public_key"]
                .as_str()
                .ok_or("actual remote public")?,
        )?;
        assert_ne!(
            public.public_key_to_der()?,
            remote_public.spki()?,
            "new local CSR cannot claim the provider's private key"
        );
        if kind.starts_with("ecdsa-") {
            assert_eq!(public.bits(), 256, "actual native producer default EC size");
        }
        assert!(
            !service
                .state
                .as_ref()
                .ok_or("pending")?
                .engines
                .has_external_pki_signer_history()
        );
        assert!(
            service
                .state
                .as_ref()
                .ok_or("pending")?
                .validate_format()
                .is_ok()
        );
        let signed = sign(&mut service, &admin, &csr)?;
        let child = certificate(&signed)?;
        let child_public = child.public_key()?;
        assert!(child.verify(&parent_public)?);
        let before = remote.calls()?;
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
        let installed = call(
            &mut service,
            "POST",
            "external-ca/intermediate/set-signed",
            &admin,
            bundle(&signed, &parent)?,
        );
        assert_eq!(
            installed.status, 200,
            "public CA import uses its actual local pending owner"
        );
        assert_eq!(
            remote.calls()?,
            before,
            "no provider effect or signing grant for a locally owned key"
        );
        let issuer = installed.body["data"]["mapping"]
            .as_object()
            .ok_or("mapping")?
            .iter()
            .find(|(_, k)| **k == csr.body["data"]["key_id"])
            .map(|(id, _)| id.clone())
            .ok_or("local imported issuer")?;
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
        let leaf = call(
            &mut service,
            "POST",
            &format!("external-ca/issuer/{issuer}/issue/leaf"),
            &admin,
            json!({"common_name":"leaf.example.test","ttl":"10m"}),
        );
        assert_eq!(leaf.status, 200);
        assert!(certificate(&leaf)?.verify(&child_public)?);
        assert!(!certificate(&leaf)?.verify(&parent_public)?);
        assert_eq!(
            remote.calls()?,
            before,
            "local issuer key signs locally with revoked remote grant"
        );
        drop(service);
        let mut reopened = root.service()?;
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
        let after = call(
            &mut reopened,
            "POST",
            &format!("external-ca/issuer/{issuer}/issue/leaf"),
            &admin,
            json!({"common_name":"restart.example.test","ttl":"10m"}),
        );
        assert_eq!(
            after.status, 200,
            "durable local owner needs no provider enrollment on restart"
        );
        assert!(certificate(&after)?.verify(&child_public)?);
    }
    Ok(())
}

#[test]
fn pki_native_kms_csr_multiple_pending_distinct_keys_and_explicit_types_reject_before_entry()
-> TestResult {
    let remote = RemoteTransit::new_kind("ed25519")?;
    let (_root, mut service, _unseal, admin) = pki_fixture(&remote)?;
    let parent = parent(&mut service, &admin)?;
    let before = remote.calls()?;
    for field in ["key_type", "key_bits"] {
        let mut body = json!({"external_key_ref":"remote:v2","common_name":"native.example.test"});
        body[field] = if field == "key_type" {
            json!("ed25519")
        } else {
            json!(0)
        };
        assert_eq!(
            call(
                &mut service,
                "POST",
                "external-ca/intermediate/generate/kms",
                &admin,
                body
            )
            .status,
            400
        );
    }
    assert_eq!(remote.calls()?, before);
    let mut pending = Vec::new();
    for name in ["first", "second"] {
        let csr = call(
            &mut service,
            "POST",
            "external-ca/intermediate/generate/kms",
            &admin,
            json!({"external_key_ref":"remote:v2","common_name":format!("{name}.example.test"),"key_name":name}),
        );
        assert_eq!(csr.status, 200);
        pending.push(csr);
    }
    assert_ne!(
        pending[0].body["data"]["key_id"],
        pending[1].body["data"]["key_id"]
    );
    let before = remote.calls()?;
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
    for csr in pending.iter().rev() {
        let signed = sign(&mut service, &admin, csr)?;
        let installed = call(
            &mut service,
            "POST",
            "external-ca/intermediate/set-signed",
            &admin,
            bundle(&signed, &parent)?,
        );
        assert_eq!(
            installed.status, 200,
            "each original pending key owns its matching signed CA"
        );
        assert!(
            installed.body["data"]["mapping"]
                .as_object()
                .ok_or("mapping")?
                .values()
                .any(|k| *k == csr.body["data"]["key_id"])
        );
    }
    assert_eq!(remote.calls()?, before);
    assert!(
        service
            .state
            .as_ref()
            .ok_or("installed")?
            .validate_format()
            .is_ok()
    );
    Ok(())
}

#[test]
fn pki_external_signed_ca94_seven_parent_certificate_revoke_crl_rotation_restart_retirement()
-> TestResult {
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
            json!({"external_key_ref":"remote:v2","common_name":"old-parent.example.test","ttl":"4h","issuer_name":"old-parent"}),
        );
        assert_eq!(parent.status, 200);
        let parent_public = certificate(&parent)?.public_key()?;
        let parent_id = parent.body["data"]["issuer_id"]
            .as_str()
            .ok_or("actual parent id")?
            .to_owned();
        let csr = local_child_csr(&mut service, &admin)?;
        let signed = call(
            &mut service,
            "POST",
            &format!("external-ca/issuer/{parent_id}/sign-intermediate"),
            &admin,
            json!({"csr":csr.body["data"]["csr"],"use_csr_values":true,"ttl":"2h","max_path_length":1}),
        );
        assert_eq!(signed.status, 200);
        let child = certificate(&signed)?;
        let child_public = child.public_key()?;
        assert!(child.verify(&parent_public)?);
        let serial = signed.body["data"]["serial_number"]
            .as_str()
            .ok_or("signed CA serial")?
            .to_owned();
        let cert_path = format!("external-ca/cert/{serial}");
        let fetched = call(&mut service, "GET", &cert_path, "", json!({}));
        assert_eq!(fetched.status, 200);
        assert_eq!(certificate(&fetched)?.to_der()?, child.to_der()?);
        let before = remote.calls()?;
        let revoked = call(
            &mut service,
            "POST",
            "external-ca/revoke",
            &admin,
            json!({"serial_number":serial}),
        );
        assert_eq!(
            revoked.status, 200,
            "actual externally signed CA index must be revocable"
        );
        assert_eq!(
            remote.calls()?,
            before + 3,
            "original parent metadata plus full/delta signatures"
        );
        let crl_path = format!("external-ca/issuer/{parent_id}/crl");
        let read_crl = |service: &mut Service| -> TestResult<X509Crl> {
            let response = call(service, "GET", &crl_path, "", json!({}));
            assert_eq!(response.status, 200);
            Ok(X509Crl::from_pem(
                response.body["data"]["crl"]
                    .as_str()
                    .ok_or("actual parent CRL")?
                    .as_bytes(),
            )?)
        };
        let crl = read_crl(&mut service)?;
        assert!(crl.verify(&parent_public)?);
        assert!(!crl.verify(&child_public)?);
        let entries = crl.get_revoked().ok_or("actual revoked CA")?;
        assert_eq!(entries.len(), 1);
        assert_eq!(
            entries[0].serial_number().to_bn()?.to_vec(),
            child.serial_number().to_bn()?.to_vec()
        );
        assert!(
            service
                .state
                .as_ref()
                .ok_or("revocation state")?
                .validate_format()
                .is_ok()
        );
        let next = call(
            &mut service,
            "POST",
            "external-ca/root/generate/kms",
            &admin,
            json!({"external_key_ref":"remote:v2","common_name":"new-parent.example.test","ttl":"4h","issuer_name":"new-parent"}),
        );
        assert_eq!(next.status, 200);
        assert_ne!(
            next.body["data"]["issuer_id"],
            parent.body["data"]["issuer_id"]
        );
        let old = read_crl(&mut service)?;
        // Root rotation rebuilds the original parent's CRL as part of the
        // same multi-signer transaction; the number/signature advance.
        assert!(old.verify(&parent_public)?);
        assert!(!old.verify(&child_public)?);
        assert_eq!(old.issuer_name().to_der()?, crl.issuer_name().to_der()?);
        let old_entries = old
            .get_revoked()
            .ok_or("rotated original parent's revoked CA")?;
        assert_eq!(old_entries.len(), 1);
        assert_eq!(
            old_entries[0].serial_number().to_bn()?.to_vec(),
            child.serial_number().to_bn()?.to_vec()
        );
        let rotated_crl = old.to_der()?;
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
        assert_eq!(read_crl(&mut reopened)?.to_der()?, rotated_crl);
        let retired = call(
            &mut reopened,
            "DELETE",
            &format!("external-ca/issuer/{parent_id}"),
            &admin,
            json!({}),
        );
        assert_eq!(
            retired.status, 204,
            "retirement errors={}",
            retired.body["errors"]
        );
        let defaults = call(
            &mut reopened,
            "GET",
            "external-ca/config/issuers",
            &admin,
            json!({}),
        );
        assert_eq!(defaults.status, 200);
        assert_eq!(defaults.body["data"]["default"], "");
        let next_id = next.body["data"]["issuer_id"]
            .as_str()
            .ok_or("remaining actual signer")?;
        let sibling = call(
            &mut reopened,
            "POST",
            &format!("external-ca/issuer/{next_id}/sign-intermediate"),
            &admin,
            json!({"csr":csr.body["data"]["csr"],"ttl":"1h","use_csr_values":true,"max_path_length":0}),
        );
        assert_eq!(
            sibling.status, 200,
            "kind={kind} sibling errors={}",
            sibling.body["errors"]
        );
        let sibling_public = certificate(&next)?.public_key()?;
        assert!(certificate(&sibling)?.verify(&sibling_public)?);
        let before = remote.calls()?;
        assert_eq!(
            call(
                &mut reopened,
                "POST",
                "external-ca/revoke",
                &admin,
                json!({"serial_number":serial})
            )
            .status,
            404,
            "retired original private parent is not recreated from the public CA"
        );
        assert_eq!(remote.calls()?, before);
        assert!(
            reopened
                .state
                .as_ref()
                .ok_or("retirement")?
                .validate_format()
                .is_ok()
        );
        let still_public = call(&mut reopened, "GET", &cert_path, "", json!({}));
        assert_eq!(still_public.status, 200);
        assert_eq!(certificate(&still_public)?.to_der()?, child.to_der()?);
        drop(reopened);
        let mut retired_reopen = root.service()?;
        retired_reopen.install_outbound_endpoints(vec![remote.endpoint()])?;
        assert_eq!(
            call(
                &mut retired_reopen,
                "POST",
                "sys/unseal",
                "",
                json!({"key":unseal})
            )
            .status,
            200
        );
        let still_public = call(&mut retired_reopen, "GET", &cert_path, "", json!({}));
        assert_eq!(still_public.status, 200);
        assert_eq!(certificate(&still_public)?.to_der()?, child.to_der()?);
        let before = remote.calls()?;
        assert_eq!(
            call(
                &mut retired_reopen,
                "POST",
                "external-ca/revoke",
                &admin,
                json!({"serial_number":serial})
            )
            .status,
            404
        );
        assert_eq!(
            remote.calls()?,
            before,
            "encrypted reopen retains no original private signer"
        );
    }
    Ok(())
}

#[test]
fn pki_signed_ca_canonical_http_serial_resolves_original_zero_prefix_records_and_restart()
-> TestResult {
    let remote = RemoteTransit::new_kind("ed25519")?;
    let (root, mut service, unseal, admin) = pki_fixture(&remote)?;
    parent(&mut service, &admin)?;
    let mut candidate = service.state.as_ref().ok_or("actual parent state")?.clone();
    candidate
        .engines
        .install_canonical_pki_serial_fixture("", "parent/", 100)?;
    candidate.schema = candidate.writer_schema();
    candidate
        .validate_format()
        .map_err(|_| "canonical fixture format rejected")?;
    let before = remote.calls()?;
    service
        .commit_state(&mut candidate)
        .map_err(|_| "canonical fixture commit rejected")?;
    service.state = Some(candidate);
    for canonical in [
        "0123456789abcdef112233445566778899aabbcc",
        "8123456789abcdef112233445566778899aabbcc",
    ] {
        let read = call(
            &mut service,
            "GET",
            &format!("parent/cert/{canonical}"),
            "",
            json!({}),
        );
        assert_eq!(read.status, 200);
        let cert = certificate(&read)?;
        assert_eq!(
            cert.serial_number().to_bn()?.to_vec(),
            (0..canonical.len())
                .step_by(2)
                .map(|i| u8::from_str_radix(&canonical[i..i + 2], 16))
                .collect::<std::result::Result<Vec<_>, _>>()?
        );
        let raw = call(
            &mut service,
            "GET",
            &format!("parent/cert/{canonical}/raw"),
            "",
            json!({}),
        );
        assert_eq!(raw.status, 200);
        let revoked = call(
            &mut service,
            "POST",
            "parent/revoke",
            &admin,
            json!({"serial_number":canonical}),
        );
        assert_eq!(revoked.status, 200);
        let original = call(
            &mut service,
            "GET",
            &format!("parent/cert/00{canonical}"),
            "",
            json!({}),
        );
        assert_eq!(original.status, 200);
        assert_eq!(
            original.body["data"]["certificate"],
            read.body["data"]["certificate"]
        );
        assert_eq!(
            original.body["data"]["revocation_time"],
            revoked.body["data"]["revocation_time"]
        );
    }
    assert_eq!(
        remote.calls()?,
        before,
        "local old issuer never uses remote signing authority"
    );
    drop(service);
    let mut reopened = root.service()?;
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
    for canonical in [
        "0123456789abcdef112233445566778899aabbcc",
        "8123456789abcdef112233445566778899aabbcc",
    ] {
        let read = call(
            &mut reopened,
            "GET",
            &format!("parent/cert/{canonical}"),
            "",
            json!({}),
        );
        assert_eq!(read.status, 200);
        assert_eq!(read.body["data"]["revocation_time"], 100);
        let original = call(
            &mut reopened,
            "GET",
            &format!("parent/cert/00{canonical}"),
            "",
            json!({}),
        );
        assert_eq!(read.body["data"], original.body["data"]);
    }
    assert_eq!(
        call(
            &mut reopened,
            "GET",
            "parent/cert/0223456789abcdef112233445566778899aabbcc",
            "",
            json!({})
        )
        .status,
        404
    );
    drop(reopened);
    drop(remote);
    drop(root);
    Ok(())
}

// The actual genuine full-DN oracle accepts a changed subject with the same CSR
// SPKI. The original remote key and imported certificate still own every CRL.
#[test]
fn pki_full_dn98_remote_import_leaf_full_delta_revoke_capture_and_restart() -> TestResult {
    for kind in ["ed25519", "rsa-2048"] {
        let remote = RemoteTransit::new_kind(kind)?;
        let (root, mut service, unseal, admin) = pki_fixture(&remote)?;
        let parent = parent(&mut service, &admin)?;
        let csr = generate(&mut service, &admin)?;
        let signed = call(
            &mut service,
            "POST",
            "parent/root/sign-intermediate",
            &admin,
            json!({"csr":csr.body["data"]["csr"],"use_csr_values":false,"common_name":"renamed-child.example.test","organization":["Actual Full DN Issuer"],"ou":["PKI Proof","Remote Owner"],"country":["CN"],"ttl":"2h","max_path_length":1}),
        );
        assert_eq!(signed.status, 200);
        let child = certificate(&signed)?;
        let public = child.public_key()?;
        let parent_public = certificate(&parent)?.public_key()?;
        assert!(child.verify(&parent_public)?);
        let request = X509Req::from_pem(
            csr.body["data"]["csr"]
                .as_str()
                .ok_or("actual CSR")?
                .as_bytes(),
        )?;
        assert_eq!(
            request.public_key()?.public_key_to_der()?,
            public.public_key_to_der()?
        );
        assert_ne!(
            request.subject_name().to_der()?,
            child.subject_name().to_der()?
        );
        let predecessor = service
            .state
            .as_ref()
            .ok_or("actual pre-full-DN producer")?
            .clone();
        assert_eq!(
            call(
                &mut service,
                "POST",
                "external-ca/intermediate/set-signed",
                &admin,
                bundle(&signed, &parent)?
            )
            .status,
            200
        );
        let owned = service.state.as_ref().ok_or("owned imported signer")?;
        assert_eq!(owned.schema, 98);
        owned
            .validate_format()
            .map_err(|_| "actual full-DN signer invalid")?;
        assert!(Service::validate_snapshot_protected_floor(owned, &predecessor).is_err());
        assert!(
            !serde_json::to_string(&owned.engines)?.contains("\"issuer_name_der\""),
            "effect-only Name creates no new durable key"
        );
        let mut removed = owned.clone();
        removed
            .engines
            .alter_external_crl_issuer_for_test("external-ca/", None)?;
        assert!(
            removed.validate_format().is_ok(),
            "the original signed DER recovers its Name without a new durable field"
        );
        let mut wrong = owned.clone();
        wrong.engines.alter_external_crl_issuer_for_test(
            "external-ca/",
            Some(certificate(&parent)?.subject_name().to_der()?),
        )?;
        assert!(
            wrong.validate_format().is_err(),
            "parent subject never owns child CRL"
        );
        let mut lowered = owned.clone();
        lowered.schema = 93;
        assert!(lowered.validate_format().is_err());
        assert_eq!(lowered.writer_schema(), 98);
        assert!(
            lowered
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
        let leaf = call(
            &mut service,
            "POST",
            "external-ca/issue/leaf",
            &admin,
            json!({"common_name":"leaf.example.test","ttl":"10m"}),
        );
        assert_eq!(leaf.status, 200);
        let issued = certificate(&leaf)?;
        assert_eq!(
            issued.issuer_name().to_der()?,
            child.subject_name().to_der()?
        );
        assert!(issued.verify(&public)?);
        assert!(!issued.verify(&parent_public)?);
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
        for (path, field) in [
            ("external-ca/issuer/default/crl", "crl"),
            ("external-ca/cert/delta-crl", "certificate"),
        ] {
            let response = call(&mut service, "GET", path, "", json!({}));
            assert_eq!(response.status, 200);
            let crl = X509Crl::from_pem(
                response.body["data"][field]
                    .as_str()
                    .ok_or("actual CRL")?
                    .as_bytes(),
            )?;
            assert_eq!(crl.issuer_name().to_der()?, child.subject_name().to_der()?);
            assert!(crl.verify(&public)?);
            assert!(!crl.verify(&parent_public)?);
            if path.ends_with("default/crl") {
                assert_eq!(crl.get_revoked().ok_or("actual revoked leaf")?.len(), 1);
            }
        }
        drop(service);
        let mut reopened = root.service()?;
        reopened.install_outbound_endpoints(vec![remote.endpoint()])?;
        assert_eq!(
            call(
                &mut reopened,
                "PUT",
                "sys/unseal",
                "",
                json!({"key":unseal})
            )
            .status,
            200
        );
        for rotate in [false, true] {
            if rotate {
                assert_eq!(
                    call(
                        &mut reopened,
                        "GET",
                        "external-ca/crl/rotate",
                        &admin,
                        json!({})
                    )
                    .status,
                    200
                );
            }
            let response = call(
                &mut reopened,
                "GET",
                "external-ca/issuer/default/crl",
                "",
                json!({}),
            );
            assert_eq!(response.status, 200);
            let crl = X509Crl::from_pem(
                response.body["data"]["crl"]
                    .as_str()
                    .ok_or("reopened CRL")?
                    .as_bytes(),
            )?;
            assert_eq!(crl.issuer_name().to_der()?, child.subject_name().to_der()?);
            assert!(crl.verify(&public)?);
        }
        let before = remote.calls()?;
        assert_eq!(
            call(
                &mut reopened,
                "DELETE",
                "sys/external-keys/configs/remote/keys/v2/grants/external-ca",
                &admin,
                json!({})
            )
            .status,
            204
        );
        let denied = call(
            &mut reopened,
            "GET",
            "external-ca/crl/rotate",
            &admin,
            json!({}),
        );
        assert_eq!(denied.status, 500);
        assert!(denied.body.get("data").is_none());
        assert_eq!(remote.calls()?, before);
        assert_eq!(
            call(
                &mut reopened,
                "DELETE",
                "sys/mounts/external-ca",
                &admin,
                json!({})
            )
            .status,
            204
        );
        let retired = reopened.state.as_ref().ok_or("actual full-DN retirement")?;
        assert!(!retired.engines.has_full_dn_crl_state());
        assert_eq!(retired.schema, 98);
        assert_eq!(retired.writer_schema(), 98);
        assert!(Service::validate_snapshot_protected_floor(retired, &predecessor).is_err());
    }
    Ok(())
}
