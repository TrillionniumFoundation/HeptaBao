//! Actual local and remote issuer signatures, captured DER and retirement.
//! Algorithm DER constants come from the nine genuine OpenBao 2.7.0 leaves
//! archived in rsa-public-certificates-original.json (SHA256 d70d5385c2e6bfb3
//! 280e06166ba42e39e5282288dae3a3809d7388212b8af90b), not this producer.
use super::*;

const SHA256_RSA: &str = "300d06092a864886f70d01010b0500";
const SHA384_RSA: &str = "300d06092a864886f70d01010c0500";
const SHA512_RSA: &str = "300d06092a864886f70d01010d0500";
const SHA256_PSS: &str = "304106092a864886f70d01010a3034a00f300d06096086480165030402010500a11c301a06092a864886f70d010108300d06096086480165030402010500a203020120";
const SHA384_PSS: &str = "304106092a864886f70d01010a3034a00f300d06096086480165030402020500a11c301a06092a864886f70d010108300d06096086480165030402020500a203020130";
const SHA512_PSS: &str = "304106092a864886f70d01010a3034a00f300d06096086480165030402030500a11c301a06092a864886f70d010108300d06096086480165030402030500a203020140";
const NATIVE: [(i64, bool, &str); 9] = [
    (0, false, SHA256_RSA),
    (256, false, SHA256_RSA),
    (384, false, SHA384_RSA),
    (512, false, SHA512_RSA),
    (0, true, SHA256_PSS),
    (256, true, SHA256_PSS),
    (384, true, SHA384_PSS),
    (512, true, SHA512_PSS),
    (123, false, SHA256_RSA),
];

fn actual_algorithm(response: &Response, issuer: &X509, native_hex: &str) -> TestResult<Vec<u8>> {
    let certificate = signed_leaf(response, issuer)?;
    let bytes = certificate.to_der()?;
    let (_, parsed) = X509Certificate::from_der(&bytes).map_err(|_| "actual signed DER")?;
    let expected = (0..native_hex.len())
        .step_by(2)
        .map(|index| u8::from_str_radix(&native_hex[index..index + 2], 16))
        .collect::<Result<Vec<_>, _>>()?;
    let (rest, expected) = x509_parser::x509::AlgorithmIdentifier::from_der(&expected)
        .map_err(|_| "native algorithm DER")?;
    assert!(rest.is_empty());
    assert_eq!(parsed.signature_algorithm, expected);
    assert_eq!(parsed.tbs_certificate.signature, expected);
    Ok(bytes)
}

#[test]
fn pki_signatures93_local_native_nine_algorithms_real_csr_owner_and_retired_reopen() -> TestResult {
    let (root, mut service, unseal, admin, _) = local_fixture()?;
    assert_eq!(
        call(
            &mut service,
            "POST",
            "sys/mounts/ca/tune",
            &admin,
            json!({"default_lease_ttl":"5m","max_lease_ttl":"10m"})
        )
        .status,
        204
    );
    let generated = call(
        &mut service,
        "POST",
        "ca/root/generate/internal",
        &admin,
        json!({"common_name":"rsa.example.test","key_type":"rsa","key_bits":2048,"ttl":"4h"}),
    );
    assert_eq!(generated.status, 200);
    assert_eq!(generated.body["data"]["expiration"], 700);
    assert_eq!(
        generated.body["warnings"][0],
        "TTL \"4h0m0s\" is longer than permitted maxTTL \"10m0s\", so maxTTL is being used"
    );
    let issuer = X509::from_pem(
        generated.body["data"]["certificate"]
            .as_str()
            .ok_or("actual RSA issuer")?
            .as_bytes(),
    )?;
    let issuer_id = generated.body["data"]["issuer_id"]
        .as_str()
        .ok_or("actual issuer ID")?
        .to_owned();
    let (csr, public) = actual_csr_fixture()?;
    let mut leaves = Vec::new();
    for (bits, pss, native) in NATIVE {
        named_role(
            &mut service,
            &admin,
            json!({"signature_bits":bits,"use_pss":pss,"issuer_ref":issuer_id}),
        )?;
        let descriptor = call(&mut service, "GET", "ca/roles/time", &admin, json!({}));
        assert_eq!(descriptor.body["data"]["signature_bits"], bits);
        assert_eq!(descriptor.body["data"]["use_pss"], pss);
        for (path, body) in [
            (
                "ca/issue/time",
                json!({"common_name":"leaf.example.test","ttl":"5m"}),
            ),
            ("ca/sign/time", json!({"csr":csr,"ttl":"5m"})),
        ] {
            let response = call(&mut service, "POST", path, &admin, body);
            let der = actual_algorithm(&response, &issuer, native)?;
            if path.contains("/sign/") {
                assert!(response.body["data"].get("private_key").is_none());
                assert_eq!(
                    X509::from_der(&der)?.public_key()?.public_key_to_der()?,
                    public
                );
            }
            leaves.push((
                response.body["data"]["serial_number"]
                    .as_str()
                    .ok_or("actual leaf serial")?
                    .to_owned(),
                der,
                native,
            ));
        }
    }
    service
        .state
        .as_ref()
        .ok_or("actual RSA state")?
        .validate_format()
        .map_err(|_| "RSA signed owner validation")?;
    let before = service.state.as_ref().ok_or("actual state")?.clone();
    let mut tampered = CarrierBody(serde_json::to_value(&before.engines)?);
    let issued = tampered.0["namespaces"][""]["mounts"]["ca/"]["backend"]["Pki"]["issued"]
        .as_object_mut()
        .ok_or("issued capture")?;
    let changed = issued
        .values_mut()
        .find(|leaf| leaf["role_leaf_profile"]["role_name_policy"]["use_pss"] == true)
        .ok_or("actual PSS captured owner")?;
    changed["role_leaf_profile"]["role_name_policy"]["use_pss"] = json!(false);
    let mut received = before.clone();
    received.engines = serde_json::from_value(tampered.0.clone())?;
    assert!(
        received.validate_format().is_err(),
        "captured padding substitution cannot reinterpret original signed DER"
    );
    assert_eq!(
        call(&mut service, "POST", "ca/root/delete", &admin, json!({})).status,
        200
    );
    service
        .state
        .as_ref()
        .ok_or("retired RSA")?
        .validate_format()
        .map_err(|_| "retired RSA signed owner")?;
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
    for (serial, original, native) in leaves {
        let response = call(
            &mut reopened,
            "GET",
            &format!("ca/cert/{serial}"),
            &admin,
            json!({}),
        );
        assert_eq!(actual_algorithm(&response, &issuer, native)?, original);
    }
    reopened
        .state
        .as_ref()
        .ok_or("reopened RSA")?
        .validate_format()
        .map_err(|_| "reopened RSA owner")?;
    Ok(())
}

#[test]
fn pki_signatures93_external_native_nine_algorithms_real_csr_and_retired_reopen() -> TestResult {
    let remote = RemoteTransit::new_kind("rsa-2048")?;
    let (root, mut service, unseal, admin) = pki_fixture(&remote)?;
    let generated = call(
        &mut service,
        "POST",
        "external-ca/root/generate/kms",
        &admin,
        body(),
    );
    assert_eq!(generated.status, 200);
    let issuer = X509::from_pem(
        generated.body["data"]["certificate"]
            .as_str()
            .ok_or("actual remote issuer")?
            .as_bytes(),
    )?;
    let (csr, public) = actual_csr_fixture()?;
    let mut leaves = Vec::new();
    for (bits, pss, native) in NATIVE {
        let mut role = role_body(&default_profile());
        role["signature_bits"] = json!(bits);
        role["use_pss"] = json!(pss);
        role["ttl"] = json!("10m");
        assert_eq!(
            call(
                &mut service,
                "POST",
                "external-ca/roles/signature",
                &admin,
                role
            )
            .status,
            200
        );
        for (path, body) in [
            (
                "external-ca/issue/signature",
                json!({"common_name":"leaf.example.test","ttl":"5m"}),
            ),
            ("external-ca/sign/signature", json!({"csr":csr,"ttl":"5m"})),
        ] {
            let response = call(&mut service, "POST", path, &admin, body);
            let der = actual_algorithm(&response, &issuer, native)?;
            if path.contains("/sign/") {
                assert!(response.body["data"].get("private_key").is_none());
                assert_eq!(
                    X509::from_der(&der)?.public_key()?.public_key_to_der()?,
                    public
                );
            }
            leaves.push((
                response.body["data"]["serial_number"]
                    .as_str()
                    .ok_or("actual remote leaf serial")?
                    .to_owned(),
                der,
                native,
            ));
        }
    }
    assert_eq!(
        call(
            &mut service,
            "POST",
            "external-ca/root/delete",
            &admin,
            json!({})
        )
        .status,
        200
    );
    let calls = remote.calls()?;
    service
        .state
        .as_ref()
        .ok_or("retired RSA")?
        .validate_format()
        .map_err(|_| "retired remote RSA owner")?;
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
    for (serial, original, native) in leaves {
        let response = call(
            &mut reopened,
            "GET",
            &format!("external-ca/cert/{serial}"),
            &admin,
            json!({}),
        );
        assert_eq!(actual_algorithm(&response, &issuer, native)?, original);
    }
    assert_eq!(
        remote.calls()?,
        calls,
        "retired reads verify public evidence without entering remote private effects"
    );
    reopened
        .state
        .as_ref()
        .ok_or("reopened RSA")?
        .validate_format()
        .map_err(|_| "reopened remote RSA owner")?;
    Ok(())
}
