//! Six genuine ca305 external KMS outputs: root and CSR, PEM/PEM bundle/DER.
//! Native originals are in native-external-ca-official-r01 (SHA256 3c7d4cf9...).
use super::*;
use openssl::x509::{X509, X509Req};

#[test]
fn pki_external_formats270_real_tls_root_three_native_shapes_and_encrypted_public_readback()
-> TestResult {
    let remote = RemoteTransit::new_kind("ed25519")?;
    for format in ["pem", "pem_bundle", "der"] {
        let (root, mut service, unseal, admin) = pki_fixture(&remote)?;
        let before = remote.calls()?;
        let mut request = body();
        request["format"] = json!(format);
        let response = call(
            &mut service,
            "POST",
            "external-ca/root/generate/kms",
            &admin,
            request,
        );
        assert_eq!(response.status, 200, "native root output {format}");
        assert!(response.body["data"].get("private_key").is_none());
        let public = response.body["data"]["certificate"]
            .as_str()
            .ok_or("actual root output")?;
        assert_eq!(response.body["data"]["issuing_ca"], public);
        let certificate = if format == "der" {
            let bytes = BASE64.decode(public)?;
            X509::from_der(&bytes)?
        } else {
            assert!(public.ends_with("-----END CERTIFICATE-----") && !public.ends_with('\n'));
            X509::from_pem(public.as_bytes())?
        };
        let actual_public = certificate.public_key()?;
        assert!(certificate.verify(&actual_public)?);
        assert_eq!(
            remote.calls()?,
            before + 4,
            "one metadata plus root/full/delta signatures"
        );
        assert_eq!(
            response.body["warnings"],
            json!([
                "This mount hasn't configured any authority information access (AIA) fields; this may make it harder for systems to find missing certificates in the chain or to validate revocation status of certificates. Consider updating /config/urls or the newly generated issuer with this information."
            ])
        );
        let signed_der = certificate.to_der()?;
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
        let stored = call(&mut reopened, "GET", "external-ca/cert/ca", "", json!({}));
        assert_eq!(
            stored.status, 200,
            "format selection never changes stored public certificate"
        );
        let stored = X509::from_pem(
            stored.body["data"]["certificate"]
                .as_str()
                .ok_or("stored public root")?
                .as_bytes(),
        )?;
        assert_eq!(stored.to_der()?, signed_der);
        assert_eq!(
            remote.calls()?,
            before + 4,
            "restart/readback never repeats signing"
        );
    }
    Ok(())
}

#[test]
fn pki_external_formats270_real_tls_csr_three_native_shapes_and_verified_original_spki()
-> TestResult {
    let remote = RemoteTransit::new_kind("ed25519")?;
    for format in ["pem", "pem_bundle", "der"] {
        let (_root, mut service, _unseal, admin) = pki_fixture(&remote)?;
        let before = remote.calls()?;
        let mut request = body();
        request["format"] = json!(format);
        let response = call(
            &mut service,
            "POST",
            "external-ca/intermediate/generate/kms-remote",
            &admin,
            request,
        );
        assert_eq!(response.status, 200, "native CSR output {format}");
        assert!(response.body["data"].get("private_key").is_none());
        let public = response.body["data"]["csr"]
            .as_str()
            .ok_or("actual public CSR")?;
        let request = if format == "der" {
            let bytes = BASE64.decode(public)?;
            X509Req::from_der(&bytes)?
        } else {
            assert!(
                public.ends_with("-----END CERTIFICATE REQUEST-----") && !public.ends_with('\n')
            );
            X509Req::from_pem(public.as_bytes())?
        };
        let actual_public = request.public_key()?;
        assert!(request.verify(&actual_public)?);
        let descriptor = call(
            &mut *remote.service.lock().map_err(|_| "actual provider lock")?,
            "GET",
            "transit/keys/remote",
            &remote.admin,
            json!({}),
        );
        assert_eq!(descriptor.status, 200);
        assert_eq!(
            actual_public.raw_public_key()?,
            BASE64.decode(
                descriptor.body["data"]["keys"]["2"]["public_key"]
                    .as_str()
                    .ok_or("actual pinned provider public key")?
            )?
        );
        assert_eq!(
            remote.calls()?,
            before + 2,
            "one metadata plus one original CSR signature"
        );
        assert_eq!(
            response.body["warnings"],
            json!([
                "This mount hasn't configured any authority information access (AIA) fields; this may make it harder for systems to find missing certificates in the chain or to validate revocation status of certificates. Consider updating /config/urls or the newly generated issuer with this information. Since this certificate is an intermediate, it might be useful to regenerate this certificate after fixing this problem for the root mount."
            ])
        );
    }
    Ok(())
}
