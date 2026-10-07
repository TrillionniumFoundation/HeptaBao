//! Genuine ca305 config/urls input and signed DER contract from the real TLS
//! native-pki-urls-official-r02-data oracle; no request body supplies authority.
use super::*;
use openssl::x509::{X509, X509Crl};
use x509_parser::prelude::{CertificateRevocationList, FromDer};
fn verify(certificate: &X509, issuer: &X509) -> TestResult<bool> {
    let public = issuer.public_key()?;
    Ok(certificate.verify(&public)?)
}
fn verify_crl(crl: &X509Crl, issuer: &X509) -> TestResult<bool> {
    let public = issuer.public_key()?;
    Ok(crl.verify(&public)?)
}
fn freshest(crl: &X509Crl) -> TestResult {
    let der = crl.to_der()?;
    let (_, parsed) = CertificateRevocationList::from_der(&der)?;
    let extension = parsed
        .extensions()
        .iter()
        .find(|extension| extension.oid.to_id_string() == "2.5.29.46")
        .ok_or("actual FreshestCRL")?;
    assert!(!extension.critical);
    assert!(
        extension
            .value
            .windows(b"http://ca.example.test/delta".len())
            .any(|bytes| bytes == b"http://ca.example.test/delta")
    );
    Ok(())
}
fn config() -> Value {
    json!({"issuing_certificates":["https://ca.example.test/issuer"],"crl_distribution_points":["http://ca.example.test/full"],"delta_crl_distribution_points":["http://ca.example.test/delta"],"ocsp_servers":["https://ca.example.test/ocsp"]})
}
fn cert(response: &Response) -> TestResult<X509> {
    Ok(X509::from_pem(
        response.body["data"]["certificate"]
            .as_str()
            .ok_or("actual certificate")?
            .as_bytes(),
    )?)
}
fn urls(certificate: &X509, issuer: &str) -> TestResult {
    let text = String::from_utf8(certificate.to_text()?)?;
    for value in [
        "OCSP - URI:https://ca.example.test/ocsp",
        issuer,
        "URI:http://ca.example.test/full",
        "URI:http://ca.example.test/delta",
    ] {
        assert!(text.contains(value), "actual DER lacks {value}");
    }
    Ok(())
}
#[test]
fn pki_url97_partial_input_clear_invalid_atomic_and_sticky_received_floor() -> TestResult {
    let root = Root::new();
    let mut service = root.service()?;
    let (unseal, admin) = bootstrap(&mut service)?;
    assert_eq!(
        call(
            &mut service,
            "POST",
            "sys/mounts/ca",
            &admin,
            json!({"type":"pki"})
        )
        .status,
        204
    );
    let original = service.state.as_ref().ok_or("predecessor")?.clone();
    assert!(!original.engines.has_pki_url_state());
    let defaults = call(&mut service, "GET", "ca/config/urls", &admin, json!({}));
    assert_eq!(defaults.status, 200);
    assert_eq!(defaults.body["data"]["enable_templating"], false);
    for field in [
        "issuing_certificates",
        "crl_distribution_points",
        "delta_crl_distribution_points",
        "ocsp_servers",
    ] {
        assert_eq!(defaults.body["data"][field], json!([]));
    }
    assert_eq!(
        call(&mut service, "POST", "ca/config/urls", &admin, config()).status,
        200
    );
    assert_eq!(
        call(
            &mut service,
            "POST",
            "ca/config/urls",
            &admin,
            json!({"ocsp_servers":"https://second.example.test/ocsp"})
        )
        .status,
        200
    );
    let before =
        call(&mut service, "GET", "ca/config/urls", &admin, json!({})).body["data"].clone();
    assert_eq!(
        call(
            &mut service,
            "POST",
            "ca/config/urls",
            &admin,
            json!({"issuing_certificates":"/relative","ocsp_servers":[]})
        )
        .status,
        400
    );
    assert_eq!(
        call(&mut service, "GET", "ca/config/urls", &admin, json!({})).body["data"],
        before
    );
    assert_eq!(call(&mut service,"POST","ca/config/urls",&admin,json!({"issuing_certificates":"","crl_distribution_points":[],"delta_crl_distribution_points":"","ocsp_servers":[]})).status,200);
    let current = service.state.as_ref().ok_or("current97")?;
    assert_eq!(current.schema, 97);
    assert!(current.engines.has_pki_url_state());
    current
        .validate_format()
        .map_err(|_| "URL-owned format rejected")?;
    let mut lowered = current.clone();
    lowered.schema = 95;
    assert_eq!(lowered.writer_schema(), 97);
    assert!(lowered.validate_format().is_err());
    assert!(Service::validate_snapshot_protected_floor(current, &original).is_err());
    drop(service);
    let mut reopened = root.service()?;
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
    assert_eq!(reopened.state.as_ref().ok_or("reopened")?.schema, 97);
    assert_eq!(
        call(&mut reopened, "DELETE", "sys/mounts/ca", &admin, json!({})).status,
        204
    );
    let retired = reopened.state.as_ref().ok_or("retired")?;
    assert!(!retired.engines.has_pki_url_state());
    assert_eq!(retired.writer_schema(), 97);
    assert!(Service::validate_snapshot_protected_floor(retired, &original).is_err());
    Ok(())
}
#[test]
fn pki_url97_local_root_leaf_full_crl_signed_ca_and_changed_configuration_restart() -> TestResult {
    let root = Root::new();
    let mut service = root.service()?;
    let (unseal, admin) = bootstrap(&mut service)?;
    for mount in ["ca", "child"] {
        assert_eq!(
            call(
                &mut service,
                "POST",
                &format!("sys/mounts/{mount}"),
                &admin,
                json!({"type":"pki"})
            )
            .status,
            204
        );
    }
    assert_eq!(
        call(&mut service, "POST", "ca/config/urls", &admin, config()).status,
        200
    );
    let ca = call(
        &mut service,
        "POST",
        "ca/root/generate/internal",
        &admin,
        json!({"common_name":"configured.example.test","key_type":"ed25519","ttl":"4h","organization":["Actual URL owner"]}),
    );
    assert_eq!(ca.status, 200, "errors={}", ca.body["errors"]);
    assert!(ca.body.get("warnings").is_none());
    let parent = cert(&ca)?;
    urls(&parent, "CA Issuers - URI:https://ca.example.test/issuer")?;
    assert!(verify(&parent, &parent)?);
    let mut erased = service.state.as_ref().ok_or("actual URL owner")?.clone();
    erased.engines.remove_root_url_capture_for_test("", "ca/")?;
    assert!(
        erased.validate_format().is_err(),
        "actual URL DER cannot shed its local generated capture even at header97"
    );

    assert_eq!(
        call(
            &mut service,
            "POST",
            "ca/roles/leaf",
            &admin,
            json!({"allow_any_name":true,"key_type":"ed25519","ttl":"10m","max_ttl":"1h"})
        )
        .status,
        200
    );
    let leaf = call(
        &mut service,
        "POST",
        "ca/issue/leaf",
        &admin,
        json!({"common_name":"leaf.example.test","ttl":"10m"}),
    );
    assert_eq!(leaf.status, 200);
    urls(
        &cert(&leaf)?,
        "CA Issuers - URI:https://ca.example.test/issuer",
    )?;
    assert!(verify(&cert(&leaf)?, &parent)?);
    let crl = call(&mut service, "GET", "ca/issuer/default/crl", "", json!({}));
    assert_eq!(crl.status, 200);
    let crl = X509Crl::from_pem(
        crl.body["data"]["crl"]
            .as_str()
            .ok_or("actual CRL")?
            .as_bytes(),
    )?;
    assert!(verify_crl(&crl, &parent)?);
    freshest(&crl)?;
    let csr = call(
        &mut service,
        "POST",
        "child/intermediate/generate/internal",
        &admin,
        json!({"common_name":"child.example.test","key_type":"ed25519"}),
    );
    assert_eq!(csr.status, 200);
    let signed = call(
        &mut service,
        "POST",
        "ca/root/sign-intermediate",
        &admin,
        json!({"csr":csr.body["data"]["csr"],"use_csr_values":true,"ttl":"1h","max_path_length":0}),
    );
    assert_eq!(signed.status, 200);
    urls(
        &cert(&signed)?,
        "CA Issuers - URI:https://ca.example.test/issuer",
    )?;
    assert_eq!(
        signed.body["warnings"]
            .as_array()
            .ok_or("pathlen warning")?
            .len(),
        1
    );
    assert_eq!(
        call(
            &mut service,
            "POST",
            "ca/config/urls",
            &admin,
            json!({"issuing_certificates":"https://changed.example.test/issuer"})
        )
        .status,
        200
    );
    service
        .state
        .as_ref()
        .ok_or("current")?
        .validate_format()
        .map_err(|_| "URL-owned format rejected")?;
    drop(service);
    let mut reopened = root.service()?;
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
    let later = call(
        &mut reopened,
        "POST",
        "ca/issue/leaf",
        &admin,
        json!({"common_name":"later.example.test","ttl":"10m"}),
    );
    assert_eq!(later.status, 200);
    urls(
        &cert(&later)?,
        "CA Issuers - URI:https://changed.example.test/issuer",
    )?;
    reopened
        .state
        .as_ref()
        .ok_or("reopen current")?
        .validate_format()
        .map_err(|_| "URL-owned format rejected")?;
    Ok(())
}
#[test]
fn pki_url97_seven_remote_keys_root_leaf_crl_original_grant_and_capture() -> TestResult {
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
        assert_eq!(
            call(
                &mut service,
                "POST",
                "external-ca/config/urls",
                &admin,
                config()
            )
            .status,
            200
        );
        let parent = call(
            &mut service,
            "POST",
            "external-ca/root/generate/kms",
            &admin,
            json!({"external_key_ref":"remote:v2","common_name":"remote.example.test","ttl":"4h"}),
        );
        assert_eq!(
            parent.status, 200,
            "kind={kind} errors={}",
            parent.body["errors"]
        );
        assert!(parent.body.get("warnings").is_none());
        let parent = cert(&parent)?;
        urls(&parent, "CA Issuers - URI:https://ca.example.test/issuer")?;
        assert!(verify(&parent, &parent)?);
        assert_eq!(
            call(
                &mut service,
                "POST",
                "external-ca/roles/leaf",
                &admin,
                json!({"allow_any_name":true,"key_type":"ed25519","ttl":"10m","max_ttl":"1h"})
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
        assert_eq!(
            leaf.status, 200,
            "kind={kind} errors={}",
            leaf.body["errors"]
        );
        urls(
            &cert(&leaf)?,
            "CA Issuers - URI:https://ca.example.test/issuer",
        )?;
        assert!(verify(&cert(&leaf)?, &parent)?);
        let crl = call(
            &mut service,
            "GET",
            "external-ca/issuer/default/crl",
            "",
            json!({}),
        );
        assert_eq!(crl.status, 200);
        let crl = X509Crl::from_pem(
            crl.body["data"]["crl"]
                .as_str()
                .ok_or("actual remote CRL")?
                .as_bytes(),
        )?;
        assert!(verify_crl(&crl, &parent)?);
        freshest(&crl)?;
        assert_eq!(
            call(
                &mut service,
                "POST",
                "external-ca/config/urls",
                &admin,
                json!({"issuing_certificates":[]})
            )
            .status,
            200
        );
        service
            .state
            .as_ref()
            .ok_or("captured")?
            .validate_format()
            .map_err(|_| "URL-owned format rejected")?;
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
        let denied = call(
            &mut service,
            "POST",
            "external-ca/issue/leaf",
            &admin,
            json!({"common_name":"denied.example.test","ttl":"10m"}),
        );
        assert_eq!(denied.status, 500, "current consumption grant is required");
        assert!(denied.body.get("data").is_none());
        assert_eq!(remote.calls()?, before);
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
        assert_eq!(reopened.state.as_ref().ok_or("restored")?.schema, 97);
        reopened
            .state
            .as_ref()
            .ok_or("restored")?
            .validate_format()
            .map_err(|_| "URL-owned format rejected")?;
    }
    Ok(())
}

// Actual native-pki-urls-official-r05 observed root template-ignore warning,
// current issuer rendering, cluster-local paths and invalid-template 500.
#[test]
fn pki_url97_templates_use_current_issuer_cluster_paths_and_fail_before_publication() -> TestResult
{
    let root = Root::new();
    let mut service = root.service()?;
    let (_, admin) = bootstrap(&mut service)?;
    assert_eq!(
        call(
            &mut service,
            "POST",
            "sys/mounts/ca",
            &admin,
            json!({"type":"pki"})
        )
        .status,
        204
    );
    assert_eq!(call(&mut service, "POST", "ca/config/urls", &admin, json!({"issuing_certificates":"https://issuer.example.test/{{issuer_id}}","enable_templating":true})).status, 200);
    let generated = call(
        &mut service,
        "POST",
        "ca/root/generate/internal",
        &admin,
        json!({"common_name":"template-root.example.test","key_type":"ec","key_bits":256,"ttl":"48h"}),
    );
    assert_eq!(generated.status, 200);
    assert_eq!(
        generated.body["warnings"],
        json!([
            "When generating root CA, found global AIA configuration with issuer_id template unsuitable for root generation. This AIA configuration has been ignored. To include AIA on this root CA, set the global AIA configuration to not include issuer_id and instead to refer to a static issuer name.",
            "This mount hasn't configured any authority information access (AIA) fields; this may make it harder for systems to find missing certificates in the chain or to validate revocation status of certificates. Consider updating /config/urls or the newly generated issuer with this information."
        ])
    );
    let parent = cert(&generated)?;
    let text = String::from_utf8(parent.to_text()?)?;
    assert!(!text.contains("Authority Information Access"));
    let issuer_id = generated.body["data"]["issuer_id"]
        .as_str()
        .ok_or("current issuer")?;
    assert_eq!(
        call(
            &mut service,
            "POST",
            "ca/roles/leaf",
            &admin,
            json!({"allow_any_name":true,"ttl":"10m","max_ttl":"1h"})
        )
        .status,
        200
    );
    assert_eq!(call(&mut service, "POST", "ca/config/cluster", &admin, json!({"path":"https://cluster.example.test/pki","aia_path":"https://aia.example.test/pki"})).status, 200);
    assert_eq!(call(&mut service, "POST", "ca/config/urls", &admin, json!({"issuing_certificates":"{{cluster_aia_path}}/issuer/{{issuer_id}}","crl_distribution_points":"{{cluster_path}}/issuer/{{issuer_id}}/crl","ocsp_servers":"{{cluster_path}}/ocsp"})).status, 200);
    let leaf = call(
        &mut service,
        "POST",
        "ca/issue/leaf",
        &admin,
        json!({"common_name":"templated.example.test","ttl":"10m"}),
    );
    assert_eq!(leaf.status, 200);
    assert!(verify(&cert(&leaf)?, &parent)?);
    let text = String::from_utf8(cert(&leaf)?.to_text()?)?;
    for uri in [
        format!("https://aia.example.test/pki/issuer/{issuer_id}"),
        format!("https://cluster.example.test/pki/issuer/{issuer_id}/crl"),
        "https://cluster.example.test/pki/ocsp".into(),
    ] {
        assert!(text.contains(&uri), "actual DER lacks rendered issuer URL");
    }
    let configured = call(
        &mut service,
        "POST",
        "ca/config/urls",
        &admin,
        json!({"issuing_certificates":"relative"}),
    );
    assert_eq!(configured.status, 200);
    assert_eq!(
        configured.body["warnings"],
        json!([
            "issuance may fail: error validating templated issuing_certificates; invalid URI: relative\n\nConsider setting the cluster-local address if it is not already set."
        ])
    );
    let before = serde_json::to_value(
        &service
            .state
            .as_ref()
            .ok_or("before rejected issuance")?
            .engines,
    )?;
    let denied = call(
        &mut service,
        "POST",
        "ca/issue/leaf",
        &admin,
        json!({"common_name":"denied.example.test","ttl":"10m"}),
    );
    assert_eq!(denied.status, 500);
    assert_eq!(
        denied.body["errors"],
        json!([
            "1 error occurred:\n\t* error fetching CA certificate: unable to fetch AIA URL information: error validating templated issuing_certificates; invalid URI: relative\n\n"
        ])
    );
    assert!(denied.body.get("data").is_none());
    assert!(
        serde_json::to_value(
            &service
                .state
                .as_ref()
                .ok_or("after rejected issuance")?
                .engines
        )? == before,
        "invalid template publishes no engine state"
    );
    service
        .state
        .as_ref()
        .ok_or("URL owner")?
        .validate_format()
        .map_err(|_| "template URL owner invalid")?;
    Ok(())
}
