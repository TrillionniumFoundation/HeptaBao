//! Actual role/leaf ownership, signatures, historical migration and sticky88.
//! Typed predecessor fixtures are authenticated inputs, never old-binary claims.
use super::*;
use crate::http::ocsp::CarrierBody;
use crate::service::tests::{bootstrap_unmounted, commit_legacy_state_fixture};
use openssl::{pkey::PKey, x509::X509};
#[path = "service_pki_external_retired_owner_tests.rs"]
mod retired_owner_tests;

const FIELDS: [&str; 15] = [
    "server_flag",
    "client_flag",
    "code_signing_flag",
    "email_protection_flag",
    "key_usage",
    "ext_key_usage",
    "ext_key_usage_oids",
    "country",
    "province",
    "locality",
    "street_address",
    "postal_code",
    "organization",
    "ou",
    "basic_constraints_valid_for_non_ca",
];

fn custom_profile() -> Value {
    json!({"server_flag":false,"client_flag":false,"code_signing_flag":true,
        "email_protection_flag":true,"key_usage":["DigitalSignature","KeyEncipherment","DecipherOnly","ignored"],
        "ext_key_usage":["TimeStamping","OCSPSigning","ignored"],"ext_key_usage_oids":["1.2.3"],
        "country":["Alpha","Beta","Alpha",""],"province":["Zhejiang"],"locality":["杭州"],
        "street_address":["Lane 1"],"postal_code":["310000"],"organization":["Hepta"],
        "ou":["Ops","Ops",""],"basic_constraints_valid_for_non_ca":true})
}

fn role_body(profile: &Value) -> Value {
    let mut body = profile.clone();
    body["allowed_domains"] = json!(["example.test"]);
    body["allow_subdomains"] = json!(true);
    body["key_type"] = json!("ec");
    body["key_bits"] = json!(256);
    body["max_ttl"] = json!("1h");
    body
}

fn assert_role(response: &Response, expected: &Value) {
    assert!(response.status == 200, "actual public role response");
    for field in FIELDS {
        assert!(
            response.body["data"][field] == expected[field],
            "actual typed role field"
        );
    }
}

fn default_profile() -> Value {
    json!({"server_flag":true,"client_flag":true,"code_signing_flag":false,
        "email_protection_flag":false,"key_usage":["DigitalSignature","KeyAgreement","KeyEncipherment"],
        "ext_key_usage":[],"ext_key_usage_oids":[],"country":[],"province":[],"locality":[],
        "street_address":[],"postal_code":[],"organization":[],"ou":[],
        "basic_constraints_valid_for_non_ca":false})
}

fn local_fixture() -> TestResult<(Root, Service, String, String, X509)> {
    let root = Root::new();
    let mut service = root.service()?;
    let (unseal, admin) = bootstrap_unmounted(&mut service)?;
    assert!(
        call(
            &mut service,
            "POST",
            "sys/mounts/ca",
            &admin,
            json!({"type":"pki"})
        )
        .status
            == 204,
        "real local PKI mount"
    );
    let generated = call(
        &mut service,
        "POST",
        "ca/root/generate/internal",
        &admin,
        json!({"common_name":"ca.example.test","key_type":"ec","key_bits":256,"ttl":"4h"}),
    );
    assert!(generated.status == 200, "actual local root producer");
    let issuer = X509::from_pem(
        generated.body["data"]["certificate"]
            .as_str()
            .ok_or("actual CA PEM")?
            .as_bytes(),
    )?;
    let issuer_public = issuer.public_key()?;
    assert!(
        issuer.verify(&issuer_public)?,
        "actual owned root self signature"
    );
    Ok((root, service, unseal, admin, issuer))
}

fn profile_leaf(response: &Response, issuer: &X509, custom: bool) -> TestResult<(String, String)> {
    assert!(response.status == 200, "actual leaf delivery");
    let pem = response.body["data"]["certificate"]
        .as_str()
        .ok_or("leaf PEM")?;
    for field in ["certificate", "issuing_ca", "private_key"] {
        assert!(
            !response.body["data"][field]
                .as_str()
                .ok_or("PEM response field")?
                .ends_with('\n'),
            "official issuance PEM response omits final LF"
        );
    }
    assert!(
        response.body["data"]["ca_chain"]
            .as_array()
            .ok_or("actual CA chain")?
            .iter()
            .all(|value| value.as_str().is_some_and(|pem| !pem.ends_with('\n'))),
        "official issuance chain PEM omits final LF"
    );
    let leaf = X509::from_pem(pem.as_bytes())?;
    let issuer_public = issuer.public_key()?;
    assert!(
        leaf.verify(&issuer_public)?,
        "independent actual issuer signature"
    );
    let private = PKey::private_key_from_pem(
        response.body["data"]["private_key"]
            .as_str()
            .ok_or("private leaf output")?
            .as_bytes(),
    )?;
    assert!(
        leaf.public_key()?.public_key_to_der()? == private.public_key_to_der()?,
        "maintained private parser binds exact signed public key"
    );
    let der = Zeroizing::new(leaf.to_der()?);
    let (rest, parsed) = X509Certificate::from_der(&der).map_err(|_| "complete leaf DER")?;
    assert!(rest.is_empty(), "actual DER consumes complete certificate");
    let extensions = parsed.extensions();
    let oids: Vec<_> = extensions
        .iter()
        .map(|extension| extension.oid.to_id_string())
        .collect();
    assert!(
        oids == if custom {
            vec![
                "2.5.29.15",
                "2.5.29.37",
                "2.5.29.19",
                "2.5.29.14",
                "2.5.29.35",
                "2.5.29.17",
            ]
        } else {
            vec![
                "2.5.29.15",
                "2.5.29.37",
                "2.5.29.14",
                "2.5.29.35",
                "2.5.29.17",
            ]
        },
        "independent observed extension order and omission"
    );
    assert!(
        extensions[0].critical
            && extensions[0].value
                == if custom {
                    &[0x03, 0x03, 0x07, 0xa0, 0x80][..]
                } else {
                    &[0x03, 0x02, 0x03, 0xa8][..]
                },
        "actual role key usage DER"
    );
    // Fixed independent known EKU OIDs from the captured official contract.
    let expected_eku: &[u8] = if custom {
        &[
            0x30, 0x2c, 0x06, 0x08, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x03, 0x06, 0x08,
            0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x04, 0x06, 0x08, 0x2b, 0x06, 0x01, 0x05,
            0x05, 0x07, 0x03, 0x08, 0x06, 0x08, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x09,
            0x06, 0x02, 0x2a, 0x03,
        ]
    } else {
        &[
            0x30, 0x14, 0x06, 0x08, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x01, 0x06, 0x08,
            0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x02,
        ]
    };
    assert!(
        !extensions[1].critical && extensions[1].value == expected_eku,
        "actual flags, extended names and custom OID DER"
    );
    if custom {
        assert!(
            extensions[2].critical && extensions[2].value == [0x30, 0x00],
            "actual critical non-CA basic constraints"
        );
        let subjects: Vec<_> = parsed
            .subject()
            .iter_attributes()
            .map(|attribute| {
                attribute
                    .as_str()
                    .map(|value| (attribute.attr_type().to_id_string(), value.to_owned()))
            })
            .collect::<Result<_, _>>()
            .map_err(|_| "actual UTF8/Printable subject")?;
        assert!(
            subjects
                == [
                    ("2.5.4.6".to_owned(), "Beta".to_owned()),
                    ("2.5.4.6".to_owned(), "Alpha".to_owned()),
                    ("2.5.4.8".to_owned(), "Zhejiang".to_owned()),
                    ("2.5.4.7".to_owned(), "杭州".to_owned()),
                    ("2.5.4.9".to_owned(), "Lane 1".to_owned()),
                    ("2.5.4.17".to_owned(), "310000".to_owned()),
                    ("2.5.4.10".to_owned(), "Hepta".to_owned()),
                    ("2.5.4.11".to_owned(), "Ops".to_owned()),
                    ("2.5.4.3".to_owned(), "leaf.example.test".to_owned())
                ],
            "all seven subject fields, exact deduplication and DER set ordering"
        );
    }
    Ok((
        response.body["data"]["serial_number"]
            .as_str()
            .ok_or("actual serial")?
            .to_owned(),
        pem.to_owned(),
    ))
}

fn assert_profile_capture(
    service: &Service,
    mount: &str,
    serial: &str,
    external: bool,
) -> TestResult {
    let state = service.state.as_ref().ok_or("actual active state")?;
    assert!(
        state.schema == PKI_ROLE_LEAF_PROFILE_STATE_SCHEMA
            && state.writer_schema() == PKI_ROLE_LEAF_PROFILE_STATE_SCHEMA
            && state.engines.has_pki_role_leaf_profile_state()
            && state.validate_format().is_ok(),
        "actual private owner and signed public evidence protect88"
    );
    let encoded = CarrierBody(serde_json::to_value(&state.engines)?);
    let pki = &encoded.0["namespaces"][""]["mounts"][mount]["backend"]["Pki"];
    let compact = serial.replace(':', "");
    assert!(
        pki["issued"][&compact]["role_leaf_profile"]["profile"] == custom_profile(),
        "issued owner captures exact typed first15"
    );
    if external {
        assert!(
            pki["external"]["issued_public"][&compact]["role_leaf_profile"] == custom_profile(),
            "actual external public projection owns the same profile"
        );
    } else {
        assert!(
            pki["issued"][&compact]["local_issuer_id"]
                .as_str()
                .is_some_and(|value| !value.is_empty()),
            "actual local issuer identity owns the signed evidence"
        );
    }
    Ok(())
}

#[test]
fn pki_profile88_local_first15_sign_private_binding_reopen_and_revocation() -> TestResult {
    let (root, mut service, unseal, admin, issuer) = local_fixture()?;
    let profile = custom_profile();
    assert_role(
        &call(
            &mut service,
            "POST",
            "ca/roles/profile",
            &admin,
            role_body(&profile),
        ),
        &profile,
    );
    assert_role(
        &call(&mut service, "GET", "ca/roles/profile", &admin, json!({})),
        &profile,
    );
    let issued = call(
        &mut service,
        "POST",
        "ca/issue/profile",
        &admin,
        json!({"common_name":"leaf.example.test","alt_names":["second.example.test"],"ttl":"10m"}),
    );
    let (serial, pem) = profile_leaf(&issued, &issuer, true)?;
    assert_profile_capture(&service, "ca/", &serial, false)?;
    let bytes =
        crate::secret_serde::to_vec(service.state.as_ref().ok_or("state")?, MAX_STATE_BYTES)
            .map_err(|_| "private owner bytes")?;
    let private = issued.body["data"]["private_key"]
        .as_str()
        .ok_or("private output")?;
    assert!(
        !bytes
            .windows(private.len())
            .any(|window| window == private.as_bytes()),
        "released leaf private key absent from persisted owner"
    );
    drop(service);
    let mut reopened = root.service()?;
    assert!(
        call(
            &mut reopened,
            "POST",
            "sys/unseal",
            "",
            json!({"key":unseal})
        )
        .status
            == 200,
        "actual encrypted88 reopen"
    );
    assert_role(
        &call(&mut reopened, "GET", "ca/roles/profile", &admin, json!({})),
        &profile,
    );
    let read = call(
        &mut reopened,
        "GET",
        &format!("ca/cert/{serial}"),
        &admin,
        json!({}),
    );
    assert!(
        read.status == 200 && read.body["data"]["certificate"] == pem,
        "exact signed DER retained through encrypted reopen"
    );
    assert_profile_capture(&reopened, "ca/", &serial, false)?;
    let next = call(
        &mut reopened,
        "POST",
        "ca/issue/profile",
        &admin,
        json!({"common_name":"leaf.example.test","ttl":"10m"}),
    );
    profile_leaf(&next, &issuer, true)?;
    assert!(
        call(
            &mut reopened,
            "POST",
            "ca/revoke",
            &admin,
            json!({"serial_number":serial})
        )
        .status
            == 200,
        "actual revocation retains protected signed evidence"
    );
    assert!(
        call(
            &mut reopened,
            "DELETE",
            "ca/roles/profile",
            &admin,
            json!({})
        )
        .status
            == 204,
        "role retirement"
    );
    assert_profile_capture(&reopened, "ca/", &serial, false)?;
    reopened
        .maintain_lifetimes_at(800)
        .map_err(|_| "actual expiry maintenance")?;
    let expired = CarrierBody(serde_json::to_value(
        &reopened.state.as_ref().ok_or("expired state")?.engines,
    )?);
    let leaf = &expired.0["namespaces"][""]["mounts"]["ca/"]["backend"]["Pki"]["issued"]
        [serial.replace(':', "")];
    assert!(
        leaf["expires"]
            .as_u64()
            .is_some_and(|expiration| expiration <= 800)
            && leaf["revoked_at"].as_u64().is_some(),
        "actual expired revoked evidence remains stored"
    );
    assert_profile_capture(&reopened, "ca/", &serial, false)?;
    Ok(())
}

#[test]
fn pki_profile88_external_first15_real_provider_sign_projection_and_reopen() -> TestResult {
    let remote = RemoteTransit::new_kind("ecdsa-p256")?;
    let (root, mut service, unseal, admin) = pki_fixture(&remote)?;
    let generated = call(
        &mut service,
        "POST",
        "external-ca/root/generate/kms",
        &admin,
        body(),
    );
    assert!(generated.status == 200, "real external root and CRLs");
    let issuer = X509::from_pem(
        generated.body["data"]["certificate"]
            .as_str()
            .ok_or("external CA")?
            .as_bytes(),
    )?;
    let profile = custom_profile();
    assert_role(
        &call(
            &mut service,
            "POST",
            "external-ca/roles/profile",
            &admin,
            role_body(&profile),
        ),
        &profile,
    );
    let sign_count = || -> TestResult<usize> {
        Ok(remote
            .trace
            .lock()
            .map_err(|_| "actual remote trace")?
            .iter()
            .filter(|path| path.as_str() == "/v1/transit/sign/remote")
            .count())
    };
    let before = remote.calls()?;
    let before_signs = sign_count()?;
    let issued = call(
        &mut service,
        "POST",
        "external-ca/issue/profile",
        &admin,
        json!({"common_name":"leaf.example.test","ttl":"10m"}),
    );
    let (serial, pem) = profile_leaf(&issued, &issuer, true)?;
    assert!(
        remote.calls()? == before + 2 && sign_count()? == before_signs + 1,
        "one real metadata read and one actual remote leaf signature"
    );
    assert_profile_capture(&service, "external-ca/", &serial, true)?;
    drop(service);
    let mut reopened = root.service()?;
    reopened.install_outbound_endpoints(vec![remote.endpoint()])?;
    assert!(
        call(
            &mut reopened,
            "POST",
            "sys/unseal",
            "",
            json!({"key":unseal})
        )
        .status
            == 200,
        "actual encrypted external profile reopen"
    );
    assert_role(
        &call(
            &mut reopened,
            "GET",
            "external-ca/roles/profile",
            &admin,
            json!({}),
        ),
        &profile,
    );
    let before = remote.calls()?;
    let read = call(
        &mut reopened,
        "GET",
        &format!("external-ca/cert/{serial}"),
        &admin,
        json!({}),
    );
    assert!(
        read.status == 200 && read.body["data"]["certificate"] == pem && remote.calls()? == before,
        "public cached signature is retained without provider rebuilding"
    );
    assert_profile_capture(&reopened, "external-ca/", &serial, true)?;
    // Separate retired-owner tests exercise actual root deletion, independent
    // private/public issuer capture and mixed historical signers.
    Ok(())
}

#[test]
fn pki_profile88_patch_weak_inputs_nulls_and_failure_do_not_publish() -> TestResult {
    let (_root, mut service, _unseal, admin, issuer) = local_fixture()?;
    let profile = custom_profile();
    assert_role(
        &call(
            &mut service,
            "PUT",
            "ca/roles/profile",
            &admin,
            role_body(&profile),
        ),
        &profile,
    );
    let patched = call(
        &mut service,
        "PATCH",
        "ca/roles/profile",
        &admin,
        json!({"server_flag":"TRUE","client_flag":"1","code_signing_flag":null,
        "email_protection_flag":false,"key_usage":null,"ext_key_usage":[],"ext_key_usage_oids":[],
        "basic_constraints_valid_for_non_ca":null}),
    );
    let mut expected = profile.clone();
    expected["server_flag"] = json!(true);
    expected["client_flag"] = json!(true);
    expected["code_signing_flag"] = json!(false);
    expected["email_protection_flag"] = json!(false);
    expected["key_usage"] = json!([]);
    expected["ext_key_usage"] = json!([]);
    expected["ext_key_usage_oids"] = json!([]);
    expected["basic_constraints_valid_for_non_ca"] = json!(false);
    assert_role(&patched, &expected);
    assert_role(
        &call(&mut service, "GET", "ca/roles/profile", &admin, json!({})),
        &expected,
    );
    let issued = call(
        &mut service,
        "POST",
        "ca/issue/profile",
        &admin,
        json!({"common_name":"leaf.example.test","ttl":"10m"}),
    );
    assert!(issued.status == 200, "patched role real issuance");
    let leaf = X509::from_pem(
        issued.body["data"]["certificate"]
            .as_str()
            .ok_or("patched leaf")?
            .as_bytes(),
    )?;
    let issuer_public = issuer.public_key()?;
    assert!(
        leaf.verify(&issuer_public)?,
        "patched profile actual signature"
    );
    let der = Zeroizing::new(leaf.to_der()?);
    let (_, parsed) = X509Certificate::from_der(&der).map_err(|_| "patched DER")?;
    assert!(
        parsed.extensions().iter().all(|extension| !matches!(
            extension.oid.to_id_string().as_str(),
            "2.5.29.15" | "2.5.29.19"
        )),
        "null and empty fields remove actual KU and BC extensions"
    );
    let identity = service.current_state_identity().map_err(|_| "identity")?;
    assert!(
        call(
            &mut service,
            "PATCH",
            "ca/roles/profile",
            &admin,
            json!({"server_flag":"invalid"})
        )
        .status
            == 400,
        "actual weak bool failure"
    );
    assert!(
        call(
            &mut service,
            "PATCH",
            "ca/roles/profile",
            &admin,
            json!({"ext_key_usage_oids":["bad"]})
        )
        .status
            == 400,
        "actual role OID parse failure"
    );
    assert!(
        call(&mut service, "PATCH", "ca/roles/missing", &admin, json!({})).body["errors"][0]
            == "Unable to fetch role entry to patch",
        "actual missing PATCH role error"
    );
    assert!(
        service.current_state_identity().map_err(|_| "identity")? == identity,
        "rejected role writes publish no private owner"
    );
    Ok(())
}

#[test]
fn pki_profile88_tampered_local_and_external_evidence_is_rejected_without_publication() -> TestResult
{
    for external in [false, true] {
        let remote = if external {
            Some(RemoteTransit::new_kind("ecdsa-p256")?)
        } else {
            None
        };
        let (_root, mut service, _unseal, admin, _issuer) = if let Some(remote) = &remote {
            let (root, mut service, unseal, admin) = pki_fixture(remote)?;
            let ca = call(
                &mut service,
                "POST",
                "external-ca/root/generate/kms",
                &admin,
                body(),
            );
            let issuer = X509::from_pem(
                ca.body["data"]["certificate"]
                    .as_str()
                    .ok_or("external issuer")?
                    .as_bytes(),
            )?;
            (root, service, unseal, admin, issuer)
        } else {
            local_fixture()?
        };
        let mount = if external { "external-ca" } else { "ca" };
        let profile = custom_profile();
        assert_role(
            &call(
                &mut service,
                "POST",
                &format!("{mount}/roles/profile"),
                &admin,
                role_body(&profile),
            ),
            &profile,
        );
        let issued = call(
            &mut service,
            "POST",
            &format!("{mount}/issue/profile"),
            &admin,
            json!({"common_name":"leaf.example.test","ttl":"10m"}),
        );
        assert!(
            issued.status == 200,
            "actual signed evidence before tampering"
        );
        let serial = issued.body["data"]["serial_number"]
            .as_str()
            .ok_or("actual serial")?
            .replace(':', "");
        let original = service.state.as_ref().ok_or("actual state")?.clone();
        let identity = service.current_state_identity().map_err(|_| "identity")?;
        for invalid in [json!("true"), json!(1), json!([])] {
            let mut typed = CarrierBody(serde_json::to_value(&original.engines)?);
            typed.0["namespaces"][""]["mounts"][format!("{mount}/")]["backend"]["Pki"]["roles"]["profile"]
                ["role_leaf_profile"]["server_flag"] = invalid;
            let bytes = Zeroizing::new(serde_json::to_vec(&typed.0)?);
            assert!(
                serde_json::from_slice::<EngineState>(&bytes).is_err(),
                "durable bool refuses public weak conversions"
            );
        }
        let mut unknown = CarrierBody(serde_json::to_value(&original.engines)?);
        unknown.0["namespaces"][""]["mounts"][format!("{mount}/")]["backend"]["Pki"]["roles"]["profile"]
            ["role_leaf_profile"]["unknown_field"] = json!(true);
        let bytes = Zeroizing::new(serde_json::to_vec(&unknown.0)?);
        assert!(
            serde_json::from_slice::<EngineState>(&bytes).is_err(),
            "typed captured profile rejects unknown persisted fields"
        );
        for change in 0..4 {
            let mut encoded = CarrierBody(serde_json::to_value(&original.engines)?);
            let pki =
                &mut encoded.0["namespaces"][""]["mounts"][format!("{mount}/")]["backend"]["Pki"];
            match change {
                0 => {
                    pki["issued"][&serial]["role_leaf_profile"]["profile"]["country"] =
                        json!(["changed"]);
                }
                1 => {
                    pki["issued"][&serial]["role_leaf_profile"]["not_before"] = json!(99);
                }
                2 => {
                    let bytes = pki["issued"][&serial]["certificate_der"]
                        .as_array_mut()
                        .ok_or("actual DER bytes")?;
                    let last = bytes.last_mut().ok_or("actual signature byte")?;
                    *last = json!(last.as_u64().ok_or("signature octet")? ^ 1);
                }
                _ => {
                    pki["issued"][&serial]["role_leaf_profile"]["profile"]["country"] =
                        json!(["changed"]);
                    if external {
                        pki["external"]["issued_public"][&serial]["role_leaf_profile"]["country"] =
                            json!(["changed"]);
                    } else {
                        pki["issued"][&serial]["local_issuer_id"] =
                            json!("00000000-0000-4000-8000-000000000000");
                    }
                }
            }
            let bytes = Zeroizing::new(serde_json::to_vec(&encoded.0)?);
            let mut rejected = original.clone();
            rejected.engines = serde_json::from_slice(&bytes)?;
            assert!(
                rejected.validate_format().is_err() && service.commit_state(&rejected).is_err(),
                "signature, captured TBS and actual issuer owner reject tampering"
            );
            assert!(
                service.current_state_identity().map_err(|_| "identity")? == identity,
                "tampered public evidence publishes no owner"
            );
        }
    }
    Ok(())
}

fn install_historical85_role(
    service: &mut Service,
    namespace: &str,
    mount: &str,
) -> TestResult<State> {
    let mut predecessor = service
        .state
        .as_ref()
        .ok_or("real pre-profile state")?
        .clone();
    assert!(
        !predecessor.engines.has_pki_role_leaf_profile_state() && predecessor.schema < 85,
        "fixture begins before actual profile or protected85 publication"
    );
    predecessor.engines.fixture_insert_historical_pki_role(
        namespace,
        mount,
        "historical",
        &json!({"allowed_domains":["example.test"],"allow_subdomains":true,"allow_ip_sans":false,
            "max_ttl":3600,"generate_lease":false}),
    )?;
    predecessor
        .engines
        .fixture_promote_historical_pki_role_to85(namespace, mount, "historical")?;
    predecessor.schema = PKI_ROLE_WILDCARD_STATE_SCHEMA;
    assert!(
        predecessor.validate_format().is_ok()
            && predecessor.writer_schema() == 85
            && predecessor.engines.has_pki_role_wildcard_state()
            && !predecessor.engines.has_pki_role_leaf_profile_state(),
        "authenticated original85 role shape without later evidence"
    );
    service
        .commit_state(&predecessor)
        .map_err(|_| "actual85 graph publication")?;
    service.state = Some(predecessor.clone());
    Ok(predecessor)
}

#[test]
fn pki_profile88_namespace_final_restore_record_gate_and_last_owner_sticky_reopen() -> TestResult {
    let root = Root::new();
    let mut service = root.service()?;
    let (unseal, admin) = bootstrap_unmounted(&mut service)?;
    assert!(
        call(
            &mut service,
            "POST",
            "sys/namespaces/team",
            &admin,
            json!({})
        )
        .status
            == 200,
        "actual namespace admission"
    );
    assert!(
        service
            .handle_at(
                "POST",
                "sys/mounts/ca",
                "team",
                &admin,
                json!({"type":"pki"}),
                100
            )
            .status
            == 204,
        "actual namespaced PKI mount"
    );
    let predecessor = install_historical85_role(&mut service, "team", "ca/")?;
    let old85 = Zeroizing::new(service.durable.as_ref().ok_or("durable")?.export_backup()?);
    let mut active_restore = Some(
        service
            .prepare_snapshot_restore(&old85)
            .map_err(|_| "prepare actual85")?,
    );
    let mut retired_restore = Some(
        service
            .prepare_snapshot_restore(&old85)
            .map_err(|_| "prepare retired actual85")?,
    );
    let old_record = service
        .prepare_record_plan(&predecessor)
        .map_err(|_| "captured actual85 record plan")?;
    let upgraded = service.handle_at(
        "PATCH",
        "ca/roles/historical",
        "team",
        &admin,
        custom_profile(),
        100,
    );
    assert_role(&upgraded, &custom_profile());
    for retired in [false, true] {
        if retired {
            assert!(
                service
                    .handle_at(
                        "DELETE",
                        "ca/roles/historical",
                        "team",
                        &admin,
                        json!({}),
                        100
                    )
                    .status
                    == 204,
                "delete the only stored profile without touching old input"
            );
        }
        let current = service.state.as_ref().ok_or("actual88")?.clone();
        assert!(
            current.schema == 88
                && current.writer_schema() == 88
                && current.engines.has_pki_role_leaf_profile_state() != retired,
            "active owner and last-owner retirement both retain actual88"
        );
        let identity = service
            .current_state_identity()
            .map_err(|_| "actual identity")?;
        assert!(
            predecessor
                .validate_publication_schema(Some(&current))
                .is_err()
                && service.prepare_record_plan(&predecessor).is_err()
                && service.commit_state(&predecessor).is_err(),
            "real85 owner cannot publish over live or retired88"
        );
        assert!(
            service
                .prepare_snapshot_restore(&old85)
                .err()
                .is_some_and(|error| error.status == 400),
            "authenticated actual85 snapshot rejected before materialization"
        );
        let mut reader = std::io::Cursor::new(old85.as_slice());
        assert!(
            service
                .prepare_snapshot_restore_from_reader(&mut reader, old85.len() as u64)
                .err()
                .is_some_and(|error| error.status == 400),
            "same streamed85 snapshot rejected"
        );
        let mut prepared = if retired {
            retired_restore.take()
        } else {
            active_restore.take()
        }
        .ok_or("affine captured85 restore plan")?;
        prepared.fixture_rebind_base_for_protected_floor(identity);
        let principal = service
            .state
            .as_mut()
            .ok_or("state")?
            .auth
            .authenticate_from(&admin, 100, None)
            .map_err(|_| "actual snapshot principal")?;
        let snapshot_body = json!({});
        let request = RequestView {
            method: "POST",
            path: "sys/storage/raft/snapshot-force",
            namespace: "",
            token: &admin,
            body: &snapshot_body,
            now: 100,
            admission_started: std::time::Instant::now(),
            allow_forward: false,
            enforce_namespace: true,
            wrap_ttl_seconds: None,
            origin_peer: None,
            client_certificates: None,
        };
        let rejected = service.commit_snapshot_restore(prepared, &principal, &request);
        assert!(
            rejected.status == 400
                && rejected.body["errors"][0] == "snapshot would downgrade PKI role leaf profiles",
            "final authenticated85 restore gate independently rejects sticky88 downgrade"
        );
        assert!(
            service.current_state_identity().map_err(|_| "identity")? == identity,
            "every rejected path keeps actual complete encrypted graph"
        );
    }
    assert!(
        service
            .install_received_record_state(predecessor, old_record)
            .is_err(),
        "captured original85 record receiver cannot downgrade retired88"
    );
    drop(service);
    let mut reopened = root.service()?;
    assert!(
        call(
            &mut reopened,
            "POST",
            "sys/unseal",
            "",
            json!({"key":unseal})
        )
        .status
            == 200,
        "retired88 authenticated encrypted reopen"
    );
    let retired = reopened.state.as_ref().ok_or("retired reopened")?;
    assert!(
        retired.schema == 88
            && retired.writer_schema() == 88
            && !retired.engines.has_pki_role_leaf_profile_state(),
        "no remaining profile cannot erase sticky88 on restart"
    );
    assert!(
        reopened.prepare_snapshot_restore(&old85).is_err(),
        "retired reopen still refuses real85 backup"
    );
    Ok(())
}

#[test]
fn pki_profile88_received_record_actual85_to88_persists_and_reopens() -> TestResult {
    let root = Root::new();
    let mut service = root.service()?;
    let (unseal, admin) = bootstrap_unmounted(&mut service)?;
    assert!(
        call(
            &mut service,
            "POST",
            "sys/mounts/ca",
            &admin,
            json!({"type":"pki"})
        )
        .status
            == 204,
        "actual record-backed PKI mount"
    );
    let predecessor = install_historical85_role(&mut service, "", "ca/")?;
    let old_plan = service
        .prepare_record_plan(&predecessor)
        .map_err(|_| "real85 record plan")?;
    let mut received = predecessor.clone();
    let result = received
        .engines
        .handle("", "PATCH", "ca/roles/historical", &custom_profile(), 100)?
        .ok_or("actual typed engine role route")?;
    assert!(
        result.status == 200 && result.mutated,
        "actual profile mutation in received owned candidate"
    );
    received.schema = received.writer_schema();
    received.replay_epoch += 3;
    assert!(
        received.schema == 88 && received.validate_format().is_ok(),
        "real future88 complete received graph"
    );
    let plan = service
        .prepare_record_plan(&received)
        .map_err(|_| "captured88 complete records")?;
    service
        .install_received_record_state(received, plan)
        .map_err(|_| "actual receiver graph persistence")?;
    let identity = service
        .current_state_identity()
        .map_err(|_| "received identity")?;
    assert!(
        service.state.as_ref().ok_or("received state")?.replay_epoch == 3
            && service
                .durable
                .as_ref()
                .ok_or("received durable")?
                .replay_epoch()
                == 3,
        "real missed-epoch receiving path persisted the actual88 owner"
    );
    assert_role(
        &call(
            &mut service,
            "GET",
            "ca/roles/historical",
            &admin,
            json!({}),
        ),
        &custom_profile(),
    );
    assert!(
        service
            .install_received_record_state(predecessor, old_plan)
            .is_err()
            && service
                .current_state_identity()
                .map_err(|_| "received identity")?
                == identity,
        "original captured85 input cannot replace actual88 receiver state"
    );
    drop(service);
    let mut reopened = root.service()?;
    assert!(
        call(
            &mut reopened,
            "POST",
            "sys/unseal",
            "",
            json!({"key":unseal})
        )
        .status
            == 200,
        "actual received record encrypted reopen"
    );
    assert_role(
        &call(
            &mut reopened,
            "GET",
            "ca/roles/historical",
            &admin,
            json!({}),
        ),
        &custom_profile(),
    );
    assert!(
        reopened.state.as_ref().ok_or("reopened")?.schema == 88
            && reopened.state.as_ref().ok_or("reopened")?.replay_epoch == 3,
        "received88 persisted schema, role owner and epoch survive restart"
    );
    // The cfg(test) receiver exercises complete local record publication; it
    // does not claim a Raft ReadIndex witness or production HA authority.
    Ok(())
}

#[test]
fn pki_profile88_legacy_none_get_future_defaults_real_identity_and_old_signature_survive()
-> TestResult {
    let root = Root::new();
    let mut service = root.service()?;
    let (unseal, admin) = bootstrap_unmounted(&mut service)?;
    assert!(
        call(
            &mut service,
            "POST",
            "sys/mounts/ca",
            &admin,
            json!({"type":"pki"})
        )
        .status
            == 204,
        "ordinary65 writer before historical input"
    );
    let mut historical = service.state.as_ref().ok_or("ordinary writer")?.clone();
    let generated = historical
        .engines
        .handle(
            "",
            "POST",
            "ca/root/generate/internal",
            &json!({"common_name":"ca.example.test","key_type":"ed25519","ttl":"4h"}),
            100,
        )?
        .ok_or("actual root engine producer")?;
    assert!(
        generated.status == 200,
        "real private root generated inside owned old input"
    );
    let issuer = X509::from_pem(
        generated.body["data"]["certificate"]
            .as_str()
            .ok_or("original root PEM")?
            .as_bytes(),
    )?;
    historical
        .engines
        .fixture_prepare_historical_pki_root("", "ca/")?;
    historical.engines.fixture_insert_historical_pki_role(
        "",
        "ca/",
        "historical",
        &json!({"allowed_domains":["example.test"],"allow_subdomains":true,"allow_ip_sans":false,
            "max_ttl":3600,"generate_lease":false}),
    )?;
    let principal = historical
        .auth
        .authenticate_from(&admin, 100, None)
        .map_err(|_| "real old input actor")?;
    let owner = historical
        .auth
        .typed_lease_issuer(&principal, "", 100)
        .map_err(|_| "real old service owner")?;
    assert!(
        owner.expires_at.is_none(),
        "old fixture root issuer has no invented expiry authority"
    );
    let old = historical.engines.fixture_issue_historical_pki_leaf(
        "",
        "ca/",
        &json!({"common_name":"old.example.test","ttl":"10m"}),
        &owner.owner,
        100,
    )?;
    let old_pem = old.body["data"]["certificate"]
        .as_str()
        .ok_or("actual old leaf PEM")?
        .to_owned();
    let old_serial = old.body["data"]["serial_number"]
        .as_str()
        .ok_or("old serial")?
        .to_owned();
    let old_leaf = X509::from_pem(old_pem.as_bytes())?;
    let issuer_public = issuer.public_key()?;
    assert!(
        old_leaf.verify(&issuer_public)?,
        "actual original None leaf signature"
    );
    let old_der = Zeroizing::new(old_leaf.to_der()?);
    let (_, old_certificate) = X509Certificate::from_der(&old_der).map_err(|_| "old DER")?;
    assert!(
        old_certificate
            .extensions()
            .iter()
            .any(|extension| extension.oid.to_id_string() == "2.5.29.15"
                && extension.value == [0x03, 0x02, 0x07, 0x80])
            && old_certificate
                .extensions()
                .iter()
                .all(|extension| extension.oid.to_id_string() != "2.5.29.37"),
        "old None signature retains genuine legacy KU and absent EKU"
    );
    historical.schema = 57;
    assert!(
        historical.validate_format().is_ok()
            && !historical.engines.has_pki_role_leaf_profile_state()
            && !historical.engines.has_local_pki_identifier_state(),
        "genuine original typed57 owner input"
    );
    commit_legacy_state_fixture(&mut service, &historical)
        .map_err(|_| "authenticated old57 writer input")?;
    drop(service);
    let mut reopened = root.service()?;
    assert!(
        call(
            &mut reopened,
            "POST",
            "sys/unseal",
            "",
            json!({"key":unseal})
        )
        .status
            == 200,
        "actual encrypted historical57 reopen"
    );
    assert_role(
        &call(
            &mut reopened,
            "GET",
            "ca/roles/historical",
            &admin,
            json!({}),
        ),
        &default_profile(),
    );
    assert!(
        !reopened
            .state
            .as_ref()
            .ok_or("old reopened")?
            .engines
            .has_pki_role_leaf_profile_state(),
        "old GET defaults do not retrofit stored signed evidence"
    );
    let issued = call(
        &mut reopened,
        "POST",
        "ca/issue/historical",
        &admin,
        json!({"common_name":"leaf.example.test","ttl":"10m"}),
    );
    profile_leaf(&issued, &issuer, false)?;
    let migrated = reopened.state.as_ref().ok_or("actual migrated")?;
    assert!(
        migrated.schema == 88 && migrated.validate_format().is_ok(),
        "actual future Some upgrades protected owner88"
    );
    let encoded = CarrierBody(serde_json::to_value(&migrated.engines)?);
    let pki = &encoded.0["namespaces"][""]["mounts"]["ca/"]["backend"]["Pki"];
    let new_serial = issued.body["data"]["serial_number"]
        .as_str()
        .ok_or("future serial")?
        .replace(':', "");
    let root_id = pki["root"]["issuer_id"]
        .as_str()
        .ok_or("actual promoted issuer")?;
    let key_id = pki["root"]["key_id"]
        .as_str()
        .ok_or("actual promoted key")?;
    assert!(
        !root_id.is_empty()
            && !key_id.is_empty()
            && root_id != key_id
            && pki["issued"][&new_serial]["local_issuer_id"] == root_id
            && pki["issued"][old_serial.replace(':', "")]["local_issuer_id"] == root_id,
        "same actual old signer and verified old leaf get real promoted identities"
    );
    assert!(
        pki["roles"]["historical"]
            .get("role_leaf_profile")
            .is_none()
            && pki["issued"][old_serial.replace(':', "")]
                .get("role_leaf_profile")
                .is_none()
            && pki["issued"][&new_serial]["role_leaf_profile"]["profile"] == default_profile(),
        "old None bytes stay None while future leaf captures effective official defaults"
    );
    let read = call(
        &mut reopened,
        "GET",
        &format!("ca/cert/{old_serial}"),
        &admin,
        json!({}),
    );
    assert!(
        read.status == 200 && read.body["data"]["certificate"] == old_pem,
        "actual old signed DER remains identical after genuine identity promotion"
    );
    drop(reopened);
    let mut final_reopen = root.service()?;
    assert!(
        call(
            &mut final_reopen,
            "POST",
            "sys/unseal",
            "",
            json!({"key":unseal})
        )
        .status
            == 200,
        "migrated88 encrypted reopen"
    );
    assert_role(
        &call(
            &mut final_reopen,
            "GET",
            "ca/roles/historical",
            &admin,
            json!({}),
        ),
        &default_profile(),
    );
    assert!(
        call(
            &mut final_reopen,
            "GET",
            &format!("ca/cert/{old_serial}"),
            &admin,
            json!({})
        )
        .body["data"]["certificate"]
            == old_pem,
        "old signature survives migration and a second encrypted restart"
    );
    Ok(())
}
