//! Native name/SAN/no-store cases and genuine protected format publication.
use super::*;
#[path = "service_pki_role_key_policy_tests.rs"]
mod key_policy;
#[path = "service_pki_role_signature_tests.rs"]
mod signature_policy;

fn named_role(service: &mut Service, admin: &str, extra: Value) -> TestResult {
    timed_role(service, admin, json!({"ttl":"10m"}))?;
    assert_eq!(
        call(service, "PATCH", "ca/roles/time", admin, extra).status,
        200
    );
    Ok(())
}

fn signed_leaf(response: &Response, issuer: &X509) -> TestResult<X509> {
    assert_eq!(response.status, 200, "actual admitted issuance");
    let certificate = X509::from_pem(
        response.body["data"]["certificate"]
            .as_str()
            .ok_or("certificate")?
            .as_bytes(),
    )?;
    assert!(
        {
            let public = issuer.public_key()?;
            certificate.verify(&public)?
        },
        "independent original signer verification"
    );
    Ok(certificate)
}

#[test]
fn pki_names93_localhost_allow_disable_and_actual_role_reopen() -> TestResult {
    let (root, mut service, unseal, admin, issuer) = local_fixture()?;
    named_role(&mut service, &admin, json!({}))?;
    let role = call(&mut service, "GET", "ca/roles/time", &admin, json!({}));
    assert_eq!(role.body["data"]["allow_localhost"], true);
    for name in ["localhost", "localhost.localdomain"] {
        let leaf = call(
            &mut service,
            "POST",
            "ca/issue/time",
            &admin,
            json!({"common_name":name}),
        );
        let cert = signed_leaf(&leaf, &issuer)?;
        assert!(
            cert.subject_alt_names()
                .ok_or("DNS SAN")?
                .iter()
                .any(|entry| entry.dnsname() == Some(name))
        );
    }
    assert_eq!(
        call(
            &mut service,
            "PATCH",
            "ca/roles/time",
            &admin,
            json!({"allow_localhost":false})
        )
        .status,
        200
    );
    let rejected = call(
        &mut service,
        "POST",
        "ca/issue/time",
        &admin,
        json!({"common_name":"localhost"}),
    );
    assert_eq!(rejected.status, 400);
    assert_eq!(
        rejected.body["errors"],
        json!(["common name localhost not allowed by this role"])
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
    assert_eq!(
        call(&mut reopened, "GET", "ca/roles/time", &admin, json!({})).body["data"]["allow_localhost"],
        false
    );
    reopened
        .state
        .as_ref()
        .ok_or("reopened")?
        .validate_format()
        .map_err(|_| "name state invalid")?;
    Ok(())
}

#[test]
fn pki_names93_optional_cn_and_disabled_subject_capture_exact_der() -> TestResult {
    let (_root, mut service, _unseal, admin, issuer) = local_fixture()?;
    named_role(&mut service, &admin, json!({}))?;
    let rejected = call(
        &mut service,
        "POST",
        "ca/issue/time",
        &admin,
        json!({"alt_names":"leaf.example.test"}),
    );
    assert_eq!(rejected.status, 400);
    assert_eq!(
        rejected.body["errors"],
        json!([
            r#"the common_name field is required, or must be provided in a CSR with "use_csr_common_name" set to true, unless "require_cn" is set to false"#
        ])
    );
    assert_eq!(
        call(
            &mut service,
            "PATCH",
            "ca/roles/time",
            &admin,
            json!({"require_cn":false})
        )
        .status,
        200
    );
    let leaf = call(
        &mut service,
        "POST",
        "ca/issue/time",
        &admin,
        json!({"alt_names":"leaf.example.test"}),
    );
    let cert = signed_leaf(&leaf, &issuer)?;
    let der = cert.to_der()?;
    let (_, parsed) = X509Certificate::from_der(&der).map_err(|_| "actual empty-subject DER")?;
    assert!(
        parsed
            .extensions()
            .iter()
            .any(|extension| extension.oid.to_id_string() == "2.5.29.17" && extension.critical),
        "native empty subject makes SAN critical"
    );

    assert!(
        cert.subject_name()
            .entries_by_nid(openssl::nid::Nid::COMMONNAME)
            .next()
            .is_none()
    );
    assert!(
        cert.subject_alt_names()
            .ok_or("optional CN DNS SAN")?
            .iter()
            .any(|entry| entry.dnsname() == Some("leaf.example.test"))
    );

    assert_eq!(
        call(
            &mut service,
            "PATCH",
            "ca/roles/time",
            &admin,
            json!({"organization":["actual organization"]})
        )
        .status,
        200
    );
    let organizational = call(
        &mut service,
        "POST",
        "ca/issue/time",
        &admin,
        json!({"alt_names":"leaf.example.test"}),
    );
    let cert = signed_leaf(&organizational, &issuer)?;
    let der = cert.to_der()?;
    let (_, parsed) = X509Certificate::from_der(&der)
        .map_err(|_| "actual nonempty organizational subject DER")?;
    assert!(
        parsed
            .extensions()
            .iter()
            .any(|extension| extension.oid.to_id_string() == "2.5.29.17" && !extension.critical),
        "nonempty organization keeps SAN noncritical when CN absent"
    );
    assert_eq!(
        call(
            &mut service,
            "PATCH",
            "ca/roles/time",
            &admin,
            json!({"organization":[]})
        )
        .status,
        200
    );
    assert_eq!(
        call(
            &mut service,
            "PATCH",
            "ca/roles/time",
            &admin,
            json!({"allow_any_name":true,"cn_validations":["disabled"],"enforce_hostnames":false})
        )
        .status,
        200
    );
    let leaf = call(
        &mut service,
        "POST",
        "ca/issue/time",
        &admin,
        json!({"common_name":"this is a subject"}),
    );
    let cert = signed_leaf(&leaf, &issuer)?;
    assert_eq!(
        cert.subject_name()
            .entries_by_nid(openssl::nid::Nid::COMMONNAME)
            .next()
            .ok_or("CN")?
            .data()
            .to_string()?,
        "this is a subject"
    );
    assert!(
        cert.subject_alt_names().is_none(),
        "non-host subject is not forged as DNS SAN"
    );
    service
        .state
        .as_ref()
        .ok_or("state")?
        .validate_format()
        .map_err(|_| "captured non-host subject validation")?;
    Ok(())
}

#[test]
fn pki_names93_glob_ip_cidr_uri_authorization_signed_sans_and_tamper_rejection() -> TestResult {
    let (_root, mut service, _unseal, admin, issuer) = local_fixture()?;
    named_role(
        &mut service,
        &admin,
        json!({"allowed_domains":["foo*.example.test"],"allow_glob_domains":true,"allow_subdomains":false,"allowed_ip_sans_cidr":["127.1.2.3/8","2001:db8::5/32"],"allowed_uri_sans":["spiffe://example.test/*"]}),
    )?;
    let body = json!({"common_name":"foo1.example.test","ip_sans":"127.0.0.1,2001:db8::1","uri_sans":"spiffe://example.test/test"});
    let leaf = call(&mut service, "POST", "ca/issue/time", &admin, body.clone());
    let cert = signed_leaf(&leaf, &issuer)?;
    let sans = cert.subject_alt_names().ok_or("actual SANs")?;
    assert!(
        sans.iter()
            .any(|entry| entry.dnsname() == Some("foo1.example.test"))
    );
    assert!(
        sans.iter()
            .any(|entry| entry.ipaddress() == Some(&[127, 0, 0, 1]))
    );
    assert!(
        sans.iter()
            .any(|entry| entry.uri() == Some("spiffe://example.test/test"))
    );
    let mut bad_ip = body.clone();
    bad_ip["ip_sans"] = json!("10.0.0.1");
    let rejected = call(&mut service, "POST", "ca/issue/time", &admin, bad_ip);
    assert_eq!(rejected.status, 400);
    assert_eq!(
        rejected.body["errors"],
        json!(["the IP address \"10.0.0.1\" is not allowed in this role"])
    );
    let mut bad_uri = body;
    bad_uri["uri_sans"] = json!("spiffe://other.test/test");
    let rejected = call(&mut service, "POST", "ca/issue/time", &admin, bad_uri);
    assert_eq!(rejected.status, 400);
    assert_eq!(
        rejected.body["errors"],
        json!([
            "URI Subject Alternative Names were provided via the API which are not valid for this role"
        ])
    );
    let original = service.state.as_ref().ok_or("state")?;
    original
        .validate_format()
        .map_err(|_| "real signed URI evidence invalid")?;
    let mut damaged = CarrierBody(serde_json::to_value(original)?);
    let issued =
        damaged.0["engines"]["namespaces"][""]["mounts"]["ca/"]["backend"]["Pki"]["issued"]
            .as_object_mut()
            .ok_or("real issued map")?;
    let stored = issued.values_mut().next().ok_or("stored leaf")?;
    stored["role_leaf_profile"]["uri_sans"] = json!(["spiffe://example.test/substituted"]);
    let damaged: State = serde_json::from_value(damaged.0.clone())?;
    assert!(
        damaged.validate_format().is_err(),
        "captured URI change cannot relabel actual signed DER"
    );
    assert_eq!(
        call(
            &mut service,
            "PATCH",
            "ca/roles/time",
            &admin,
            json!({"allow_glob_domains":false,"allowed_domains":["example.test"]})
        )
        .status,
        200
    );
    assert_eq!(
        call(
            &mut service,
            "POST",
            "ca/issue/time",
            &admin,
            json!({"common_name":"foo1.example.test"})
        )
        .status,
        400
    );
    Ok(())
}

#[test]
fn pki_names93_no_store_real_delivery_no_lease_no_index_and_restart() -> TestResult {
    let (root, mut service, unseal, admin, issuer) = local_fixture()?;
    named_role(
        &mut service,
        &admin,
        json!({"no_store":true,"generate_lease":true}),
    )?;
    let role = call(&mut service, "GET", "ca/roles/time", &admin, json!({}));
    assert_eq!(role.body["data"]["generate_lease"], false);
    let leaf = call(
        &mut service,
        "POST",
        "ca/issue/time",
        &admin,
        json!({"common_name":"leaf.example.test"}),
    );
    signed_leaf(&leaf, &issuer)?;
    assert_eq!(leaf.body["lease_id"], "");
    assert_eq!(leaf.body["lease_duration"], 0);
    let serial = leaf.body["data"]["serial_number"]
        .as_str()
        .ok_or("delivered serial")?
        .to_owned();
    assert_eq!(
        call(
            &mut service,
            "GET",
            &format!("ca/cert/{serial}"),
            &admin,
            json!({})
        )
        .status,
        404
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
    assert_eq!(
        call(
            &mut reopened,
            "GET",
            &format!("ca/cert/{serial}"),
            &admin,
            json!({})
        )
        .status,
        404
    );
    let state = reopened.state.as_ref().ok_or("no-store persisted role")?;
    assert!(state.schema == 93 && state.engines.has_pki_role_names_state());
    state
        .validate_format()
        .map_err(|_| "persisted no-store state invalid")?;
    Ok(())
}

#[test]
fn pki_names93_actual_predecessor_backup_floor_last_owner_retirement() -> TestResult {
    let (root, mut service, unseal, admin, _issuer) = local_fixture()?;
    let original = service.state.as_ref().ok_or("pre-name state")?.clone();
    assert!(original.schema < 93 && !original.engines.has_pki_role_names_state());
    let backup = Zeroizing::new(
        service
            .durable
            .as_ref()
            .ok_or("actual old durable")?
            .export_backup()?,
    );
    named_role(&mut service, &admin, json!({"no_store":true}))?;
    let current = service.state.as_ref().ok_or("actual names")?;
    assert!(
        current.schema == 93
            && current.writer_schema() == 93
            && current.engines.has_pki_role_names_state()
    );
    let mut lower = current.clone();
    lower.schema = 90;
    assert!(
        lower.validate_format().is_err()
            && lower.validate_publication_schema(Some(&original)).is_err()
    );
    assert_eq!(lower.writer_schema(), 93);
    assert!(
        service.prepare_snapshot_restore(&backup).is_err(),
        "authenticated actual predecessor cannot replace names93 graph"
    );
    assert_eq!(
        call(&mut service, "DELETE", "ca/roles/time", &admin, json!({})).status,
        204
    );
    let retired = service.state.as_ref().ok_or("retired")?;
    assert!(
        retired.schema == 93
            && retired.writer_schema() == 93
            && !retired.engines.has_pki_role_names_state()
    );
    assert!(
        service.prepare_snapshot_restore(&backup).is_err(),
        "retirement retains original protected floor"
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
    assert_eq!(reopened.state.as_ref().ok_or("reopened93")?.schema, 93);
    Ok(())
}

#[test]
fn pki_names93_external_uri_signed_owner_retirement_and_no_store_no_orphan_projection() -> TestResult
{
    let remote = RemoteTransit::new_kind("ecdsa-p256")?;
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
            .ok_or("CA")?
            .as_bytes(),
    )?;
    let mut role = role_body(&default_profile());
    role["ttl"] = json!("10m");
    role["allowed_uri_sans"] = json!(["spiffe://example.test/*"]);
    role["require_cn"] = json!(false);
    assert_eq!(
        call(
            &mut service,
            "POST",
            "external-ca/roles/names",
            &admin,
            role
        )
        .status,
        200
    );
    let request =
        json!({"alt_names":"leaf.example.test","uri_sans":"spiffe://example.test/external"});
    assert_eq!(
        call(
            &mut service,
            "PATCH",
            "external-ca/roles/names",
            &admin,
            json!({"no_store":true})
        )
        .status,
        200
    );
    let ephemeral = call(
        &mut service,
        "POST",
        "external-ca/issue/names",
        &admin,
        request.clone(),
    );
    signed_leaf(&ephemeral, &issuer)?;
    let ephemeral_serial = ephemeral.body["data"]["serial_number"]
        .as_str()
        .ok_or("no-store serial")?
        .to_owned();
    assert_eq!(
        call(
            &mut service,
            "GET",
            &format!("external-ca/cert/{ephemeral_serial}"),
            &admin,
            json!({})
        )
        .status,
        404
    );
    let stored = pki_value(&service, "", "external-ca/")?;
    assert!(
        stored.0["issued"]
            .as_object()
            .ok_or("private records")?
            .is_empty()
    );
    assert!(
        stored.0["external"].get("issued_public").is_none(),
        "no-store has no serialized public records"
    );
    assert!(
        stored.0["external"].get("archived_issuers").is_none(),
        "no-store has no serialized archives"
    );
    assert_eq!(
        call(
            &mut service,
            "PATCH",
            "external-ca/roles/names",
            &admin,
            json!({"no_store":false})
        )
        .status,
        200
    );
    let leaf = call(
        &mut service,
        "POST",
        "external-ca/issue/names",
        &admin,
        request,
    );
    let cert = signed_leaf(&leaf, &issuer)?;
    let der = cert.to_der()?;
    let (_, parsed) =
        X509Certificate::from_der(&der).map_err(|_| "actual external empty subject DER")?;
    assert!(
        parsed
            .extensions()
            .iter()
            .any(|extension| extension.oid.to_id_string() == "2.5.29.17" && extension.critical),
        "external empty subject makes signed SAN critical"
    );

    assert!(
        cert.subject_alt_names()
            .ok_or("URI SAN")?
            .iter()
            .any(|entry| entry.uri() == Some("spiffe://example.test/external"))
    );
    let serial = leaf.body["data"]["serial_number"]
        .as_str()
        .ok_or("stored serial")?
        .to_owned();
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
    let before = remote.calls()?;
    assert_eq!(
        call(
            &mut service,
            "GET",
            &format!("external-ca/cert/{serial}"),
            &admin,
            json!({})
        )
        .body["data"]["certificate"],
        leaf.body["data"]["certificate"]
    );
    assert_eq!(
        remote.calls()?,
        before,
        "archived proof reads have no live signer dependency"
    );
    service
        .state
        .as_ref()
        .ok_or("retired")?
        .validate_format()
        .map_err(|_| "archived URI signed ownership")?;
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
    let read = call(
        &mut reopened,
        "GET",
        &format!("external-ca/cert/{serial}"),
        &admin,
        json!({}),
    );
    signed_leaf(&read, &issuer)?;
    assert_eq!(reopened.state.as_ref().ok_or("reopen93")?.schema, 93);
    Ok(())
}

fn extended_fields() -> Value {
    json!({"allowed_serial_numbers":["client-*"],"allowed_user_ids":["team-*"],
        "allowed_other_sans":["1.2.3.4;UTF8:role-*"],
        "policy_identifiers":[r#"{"oid":"1.2.3.4","notice":"actual public policy notice","cps":"https://example.test/cps"}"#]})
}
fn extended_request() -> Value {
    json!({"common_name":"leaf.example.test","serial_number":"client-42","user_ids":["team-42","team-43"],"other_sans":["1.2.3.4;UTF8:role-42"]})
}
fn check_extended_der(response: &Response, issuer: &X509) -> TestResult {
    let cert = signed_leaf(response, issuer)?;
    let der = cert.to_der()?;
    let (_, parsed) = X509Certificate::from_der(&der).map_err(|_| "structured subject DER")?;
    let attributes = parsed
        .subject()
        .iter_attributes()
        .map(|attribute| {
            attribute
                .as_str()
                .map(|value| (attribute.attr_type().to_id_string(), value.to_owned()))
        })
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(|_| "structured subject attributes")?;
    for expected in [
        ("2.5.4.5", "client-42"),
        ("0.9.2342.19200300.100.1.1", "team-42"),
        ("0.9.2342.19200300.100.1.1", "team-43"),
    ] {
        assert!(
            attributes
                .iter()
                .any(|(oid, value)| oid == expected.0 && value == expected.1),
            "independent ASN.1 subject attributes"
        );
    }
    let extension_ids = parsed
        .extensions()
        .iter()
        .map(|extension| extension.oid.to_id_string())
        .collect::<Vec<_>>();
    let san_at = extension_ids
        .iter()
        .position(|oid| oid == "2.5.29.17")
        .ok_or("actual SAN")?;
    let policy_at = extension_ids
        .iter()
        .position(|oid| oid == "2.5.29.32")
        .ok_or("actual policies")?;
    assert!(
        san_at < policy_at,
        "native qualified policy follows the SDK otherName extension"
    );
    let other_name = parsed
        .extensions()
        .iter()
        .find_map(|extension| {
            if let x509_parser::extensions::ParsedExtension::SubjectAlternativeName(san) =
                extension.parsed_extension()
            {
                san.general_names.iter().find_map(|name| {
                    if let x509_parser::extensions::GeneralName::OtherName(oid, value) = name
                        && oid.to_id_string() == "1.2.3.4"
                    {
                        Some(*value)
                    } else {
                        None
                    }
                })
            } else {
                None
            }
        })
        .ok_or("actual parsed otherName OID")?;
    assert_eq!(
        other_name, b"\xa0\x09\x0c\x07role-42",
        "independent parser retains complete explicit UTF8 otherName value"
    );
    // The vendored OpenSSL text printer reports unknown otherName OIDs as
    // unsupported. Its system CLI counterpart independently decodes this OID
    // and value in the actual native comparison; compare ASN.1 here instead.
    let text = String::from_utf8(cert.to_text()?)?
        .split_whitespace()
        .collect::<String>();
    for actual in [
        "Policy: 1.2.3.4",
        "CPS: https://example.test/cps",
        "Explicit Text: actual public policy notice",
    ] {
        assert!(
            text.contains(&actual.split_whitespace().collect::<String>()),
            "independent public certificate parser requires {actual}"
        );
    }
    Ok(())
}

#[test]
fn pki_names93_real_subject_serial_uid_othername_policy_and_received_tamper_fail_closed()
-> TestResult {
    let (root, mut service, unseal, admin, issuer) = local_fixture()?;
    named_role(&mut service, &admin, extended_fields())?;
    let leaf = call(
        &mut service,
        "POST",
        "ca/issue/time",
        &admin,
        extended_request(),
    );
    check_extended_der(&leaf, &issuer)?;
    let serial = leaf.body["data"]["serial_number"]
        .as_str()
        .ok_or("serial")?
        .replace(':', "");
    let original = service.state.as_ref().ok_or("original")?;
    original
        .validate_format()
        .map_err(|_| "original signed subject capture")?;
    for field in [
        "serial_number",
        "user_ids",
        "other_sans",
        "policy_identifiers",
    ] {
        let mut altered = CarrierBody(serde_json::to_value(original)?);
        let captured = &mut altered.0["engines"]["namespaces"][""]["mounts"]["ca/"]["backend"]["Pki"]
            ["issued"][&serial]["role_leaf_profile"]["profile"]["leaf_subject_evidence"];
        captured[field] = match field {
            "serial_number" => json!("client-substituted"),
            "user_ids" => json!(["team-substituted"]),
            "other_sans" => json!({"1.2.3.4":["role-substituted"]}),
            _ => json!(["1.2.3.5"]),
        };
        let altered: State = serde_json::from_value(altered.0.clone())?;
        assert!(
            altered.validate_format().is_err(),
            "received {field} cannot relabel actual signed DER"
        );
    }
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
    let read = call(
        &mut reopened,
        "GET",
        &format!("ca/cert/{serial}"),
        &admin,
        json!({}),
    );
    check_extended_der(&read, &issuer)?;
    assert_eq!(reopened.state.as_ref().ok_or("reopened")?.schema, 93);
    Ok(())
}

#[test]
fn pki_names93_subject_permission_native_errors_and_invalid_policy_no_publication() -> TestResult {
    let (_root, mut service, _unseal, admin, _issuer) = local_fixture()?;
    named_role(&mut service, &admin, json!({}))?;
    for (inputs, message) in [
        (
            json!({"serial_number":"client-42"}),
            "serial_number client-42 not allowed by this role",
        ),
        (
            json!({"user_ids":["alice"]}),
            "user_id alice is not allowed by this role",
        ),
        (
            json!({"other_sans":["1.2.3.4;UTF8:role-42"]}),
            "other SAN OID 1.2.3.4 not allowed by this role",
        ),
    ] {
        let mut request = inputs;
        request["common_name"] = json!("leaf.example.test");
        let rejected = call(&mut service, "POST", "ca/issue/time", &admin, request);
        assert_eq!(rejected.status, 400);
        assert_eq!(rejected.body["errors"], json!([message]));
    }
    let identity = service.current_state_identity().map_err(|_| "identity")?;
    let failed = call(
        &mut service,
        "PATCH",
        "ca/roles/time",
        &admin,
        json!({"policy_identifiers":["invalid"]}),
    );
    assert_eq!(failed.status, 500);
    assert_eq!(
        service
            .current_state_identity()
            .map_err(|_| "preserved identity")?,
        identity
    );
    assert_eq!(
        call(&mut service, "GET", "ca/roles/time", &admin, json!({})).body["data"]["policy_identifiers"],
        json!([])
    );
    assert_eq!(call(&mut service, "PATCH", "ca/roles/time", &admin,
        json!({"require_cn":false,"allowed_other_sans":["1.2.3.4;UTF8:role-*"],"policy_identifiers":["1.2.3.4"]})).status,200);
    let leaf = call(
        &mut service,
        "POST",
        "ca/issue/time",
        &admin,
        json!({"alt_names":"leaf.example.test","other_sans":["1.2.3.4;UTF8:role-42"]}),
    );
    let cert = signed_leaf(&leaf, &_issuer)?;
    let der = cert.to_der()?;
    let (_, parsed) = X509Certificate::from_der(&der).map_err(|_| "simple policy otherName DER")?;
    assert!(parsed.subject().iter_attributes().next().is_none());
    let ids = parsed
        .extensions()
        .iter()
        .map(|extension| extension.oid.to_id_string())
        .collect::<Vec<_>>();
    assert!(
        ids.iter()
            .position(|oid| oid == "2.5.29.32")
            .ok_or("policy")?
            < ids.iter().position(|oid| oid == "2.5.29.17").ok_or("SAN")?
    );
    assert!(
        !parsed
            .extensions()
            .iter()
            .find(|extension| extension.oid.to_id_string() == "2.5.29.17")
            .ok_or("SAN")?
            .critical,
        "native otherName override remains noncritical with empty subject"
    );
    Ok(())
}

#[test]
fn pki_names93_external_structured_subject_and_policy_survive_real_signer_retirement() -> TestResult
{
    let remote = RemoteTransit::new_kind("ecdsa-p256")?;
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
            .ok_or("CA")?
            .as_bytes(),
    )?;
    let mut role = role_body(&default_profile());
    role["ttl"] = json!("10m");
    for (field, value) in extended_fields().as_object().ok_or("fields")? {
        role[field] = value.clone();
    }
    assert_eq!(
        call(
            &mut service,
            "POST",
            "external-ca/roles/subject",
            &admin,
            role
        )
        .status,
        200
    );
    let leaf = call(
        &mut service,
        "POST",
        "external-ca/issue/subject",
        &admin,
        extended_request(),
    );
    check_extended_der(&leaf, &issuer)?;
    let serial = leaf.body["data"]["serial_number"]
        .as_str()
        .ok_or("serial")?
        .to_owned();
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
    let before = remote.calls()?;
    let read = call(
        &mut service,
        "GET",
        &format!("external-ca/cert/{serial}"),
        &admin,
        json!({}),
    );
    check_extended_der(&read, &issuer)?;
    assert_eq!(remote.calls()?, before);
    service
        .state
        .as_ref()
        .ok_or("retired")?
        .validate_format()
        .map_err(|_| "retired subject owner")?;
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
    let read = call(
        &mut reopened,
        "GET",
        &format!("external-ca/cert/{serial}"),
        &admin,
        json!({}),
    );
    check_extended_der(&read, &issuer)?;
    Ok(())
}

fn actual_csr_fixture() -> TestResult<(String, Vec<u8>)> {
    let group = openssl::ec::EcGroup::from_curve_name(openssl::nid::Nid::X9_62_PRIME256V1)?;
    let key = PKey::from_ec_key(openssl::ec::EcKey::generate(&group)?)?;
    let mut name = openssl::x509::X509Name::builder()?;
    name.append_entry_by_text("CN", "csr.example.test")?;
    let mut request = openssl::x509::X509Req::builder()?;
    request.set_subject_name(&name.build())?;
    request.set_pubkey(&key)?;
    let extension = openssl::x509::extension::SubjectAlternativeName::new()
        .dns("csr-san.example.test")
        .build(&request.x509v3_context(None))?;
    let mut extensions = openssl::stack::Stack::new()?;
    extensions.push(extension)?;
    request.add_extensions(&extensions)?;
    request.sign(&key, openssl::hash::MessageDigest::sha256())?;
    Ok((
        String::from_utf8(request.build().to_pem()?)?,
        key.public_key_to_der()?,
    ))
}

fn check_actual_csr_leaf(
    response: &Response,
    issuer: &X509,
    public: &[u8],
    cn: &str,
    dns: &[&str],
) -> TestResult<String> {
    let cert = signed_leaf(response, issuer)?;
    assert!(
        response.body["data"].get("private_key").is_none()
            && response.body["data"].get("private_key_type").is_none(),
        "sign releases no new private key"
    );
    assert_eq!(
        cert.public_key()?.public_key_to_der()?,
        public,
        "actual CSR SPKI is the signed subject key"
    );
    let der = cert.to_der()?;
    let (_, parsed) = X509Certificate::from_der(&der).map_err(|_| "CSR signed DER")?;
    assert_eq!(
        parsed
            .subject()
            .iter_common_name()
            .next()
            .ok_or("CN")?
            .as_str()?,
        cn
    );
    let names = cert
        .subject_alt_names()
        .ok_or("CSR signed SAN")?
        .iter()
        .filter_map(|name| name.dnsname().map(str::to_owned))
        .collect::<Vec<_>>();
    assert_eq!(
        names, dns,
        "actual native CSR/API SAN precedence and ordering"
    );
    assert_eq!(parsed.validity().not_before.timestamp(), 55);
    assert_eq!(parsed.validity().not_after.timestamp(), 700);
    Ok(response.body["data"]["serial_number"]
        .as_str()
        .ok_or("serial")?
        .to_owned())
}

#[test]
fn pki_csr93_real_signature_spki_native_precedence_rejections_and_encrypted_reopen() -> TestResult {
    let (root, mut service, unseal, admin, issuer) = local_fixture()?;
    let (csr, public) = actual_csr_fixture()?;
    let mut last = String::new();
    for (flags, inputs, cn, names, warnings) in [
        (
            json!({}),
            json!({"common_name":"api.example.test","alt_names":"api-san.example.test"}),
            "csr.example.test",
            vec!["csr-san.example.test", "csr.example.test"],
            json!([
                "the common_name field was provided but the role is set with \"use_csr_common_name\" set to true",
                "the alt_names field was provided but the role is set with \"use_csr_sans\" set to true"
            ]),
        ),
        (
            json!({"use_csr_common_name":false}),
            json!({"common_name":"api.example.test","alt_names":"api-san.example.test"}),
            "api.example.test",
            vec!["csr-san.example.test", "api.example.test"],
            json!([
                "the alt_names field was provided but the role is set with \"use_csr_sans\" set to true"
            ]),
        ),
        (
            json!({"use_csr_sans":false}),
            json!({"common_name":"api.example.test","alt_names":"api-san.example.test"}),
            "csr.example.test",
            vec!["csr.example.test", "api-san.example.test"],
            json!([
                "the common_name field was provided but the role is set with \"use_csr_common_name\" set to true"
            ]),
        ),
    ] {
        let mut flags = flags;
        flags["not_before_duration"] = json!("45s");
        named_role(&mut service, &admin, flags)?;
        let mut request = inputs;
        request["csr"] = json!(csr);
        let response = call(&mut service, "POST", "ca/sign/time", &admin, request);
        last = check_actual_csr_leaf(&response, &issuer, &public, cn, &names)?;
        assert_eq!(response.body["warnings"], warnings);
        service
            .state
            .as_ref()
            .ok_or("signed CSR state")?
            .validate_format()
            .map_err(|_| "CSR durable signed ownership")?;
    }
    named_role(&mut service, &admin, json!({"use_csr_common_name":false}))?;
    let identity = service
        .current_state_identity()
        .map_err(|_| "before CSR rejection")?;
    let rejected = call(
        &mut service,
        "POST",
        "ca/sign/time",
        &admin,
        json!({"csr":csr}),
    );
    assert_eq!(rejected.status, 400);
    assert_eq!(
        rejected.body["errors"],
        json!([
            r#"the common_name field is required, or must be provided in a CSR with "use_csr_common_name" set to true, unless "require_cn" is set to false"#
        ])
    );
    let mut corrupt = openssl::x509::X509Req::from_pem(csr.as_bytes())?.to_der()?;
    *corrupt.last_mut().ok_or("CSR signature byte")? ^= 1;
    let corrupt = format!(
        "-----BEGIN CERTIFICATE REQUEST-----\n{}\n-----END CERTIFICATE REQUEST-----\n",
        base64::Engine::encode(&BASE64, &corrupt)
    );
    assert_eq!(
        call(
            &mut service,
            "POST",
            "ca/sign/time",
            &admin,
            json!({"csr":corrupt,"common_name":"api.example.test"})
        )
        .status,
        400
    );
    assert_eq!(
        service
            .current_state_identity()
            .map_err(|_| "after CSR rejection")?,
        identity
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
    let stored = call(
        &mut reopened,
        "GET",
        &format!("ca/cert/{last}"),
        &admin,
        json!({}),
    );
    let cert = signed_leaf(&stored, &issuer)?;
    assert_eq!(cert.public_key()?.public_key_to_der()?, public);
    assert_eq!(
        call(&mut reopened, "GET", "ca/roles/time", &admin, json!({})).body["data"]["use_csr_common_name"],
        false
    );
    Ok(())
}

#[test]
fn pki_csr93_external_issuer_alias_real_key_custody_no_store_and_retirement() -> TestResult {
    let remote = RemoteTransit::new_kind("ecdsa-p256")?;
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
            .ok_or("CA")?
            .as_bytes(),
    )?;
    let issuer_id = generated.body["data"]["issuer_id"]
        .as_str()
        .ok_or("actual issuer")?
        .to_owned();
    let mut role = role_body(&default_profile());
    role["ttl"] = json!("10m");
    role["not_before_duration"] = json!("45s");
    assert_eq!(
        call(&mut service, "POST", "external-ca/roles/csr", &admin, role).status,
        200
    );
    let (csr, public) = actual_csr_fixture()?;
    let response = call(
        &mut service,
        "POST",
        &format!("external-ca/issuer/{issuer_id}/sign/csr"),
        &admin,
        json!({"csr":csr}),
    );
    let serial = check_actual_csr_leaf(
        &response,
        &issuer,
        &public,
        "csr.example.test",
        &["csr-san.example.test", "csr.example.test"],
    )?;
    assert_eq!(
        call(
            &mut service,
            "PATCH",
            "external-ca/roles/csr",
            &admin,
            json!({"no_store":true})
        )
        .status,
        200
    );
    let delivered = call(
        &mut service,
        "POST",
        "external-ca/sign/csr",
        &admin,
        json!({"csr":csr}),
    );
    let not_stored = check_actual_csr_leaf(
        &delivered,
        &issuer,
        &public,
        "csr.example.test",
        &["csr-san.example.test", "csr.example.test"],
    )?;
    assert_eq!(
        call(
            &mut service,
            "GET",
            &format!("external-ca/cert/{not_stored}"),
            &admin,
            json!({})
        )
        .status,
        404
    );
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
    let before = remote.calls()?;
    let stored = call(
        &mut service,
        "GET",
        &format!("external-ca/cert/{serial}"),
        &admin,
        json!({}),
    );
    assert_eq!(
        signed_leaf(&stored, &issuer)?
            .public_key()?
            .public_key_to_der()?,
        public
    );
    assert_eq!(remote.calls()?, before);
    service
        .state
        .as_ref()
        .ok_or("retired CSR")?
        .validate_format()
        .map_err(|_| "archived true CSR public owner")?;
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
    let stored = call(
        &mut reopened,
        "GET",
        &format!("external-ca/cert/{serial}"),
        &admin,
        json!({}),
    );
    assert_eq!(
        signed_leaf(&stored, &issuer)?
            .public_key()?
            .public_key_to_der()?,
        public
    );
    Ok(())
}

#[test]
fn pki_csr93_small_rsa_native_bad_request_after_actual_signature_and_no_publication() -> TestResult
{
    let (_root, mut service, _, admin, _) = local_fixture()?;
    named_role(
        &mut service,
        &admin,
        json!({"key_type":"rsa","key_bits":2048}),
    )?;
    let key = PKey::from_rsa(openssl::rsa::Rsa::generate(1024)?)?;
    let mut name = openssl::x509::X509Name::builder()?;
    name.append_entry_by_text("CN", "csr.example.test")?;
    let mut request = openssl::x509::X509Req::builder()?;
    request.set_subject_name(&name.build())?;
    request.set_pubkey(&key)?;
    request.sign(&key, openssl::hash::MessageDigest::sha256())?;
    let request = request.build();
    assert!(request.verify(&key)?);
    let identity = service
        .current_state_identity()
        .map_err(|_| "before small CSR")?;
    let rejected = call(
        &mut service,
        "POST",
        "ca/sign/time",
        &admin,
        json!({"csr":String::from_utf8(request.to_pem()?)?}),
    );
    assert_eq!(rejected.status, 400);
    assert_eq!(
        rejected.body["errors"],
        json!(["role requires a minimum of a 2048-bit key, but CSR's key is 1024 bits"])
    );
    let mut corrupt = request.to_der()?;
    *corrupt.last_mut().ok_or("small CSR signature byte")? ^= 1;
    let corrupt = format!(
        "-----BEGIN CERTIFICATE REQUEST-----\n{}\n-----END CERTIFICATE REQUEST-----\n",
        base64::Engine::encode(&BASE64, &corrupt)
    );
    let rejected = call(
        &mut service,
        "POST",
        "ca/sign/time",
        &admin,
        json!({"csr":corrupt}),
    );
    assert_eq!(rejected.status, 400);
    assert_eq!(
        rejected.body["errors"],
        json!(["request signature invalid"])
    );
    assert_eq!(
        service
            .current_state_identity()
            .map_err(|_| "after small CSR rejection")?,
        identity
    );
    Ok(())
}

fn actual_template_identity(
    service: &mut Service,
    admin: &str,
) -> TestResult<(String, String, String)> {
    assert_eq!(
        call(
            service,
            "POST",
            "sys/auth/pki-userpass",
            admin,
            json!({"type":"userpass"})
        )
        .status,
        204
    );
    let mounts = call(service, "GET", "sys/auth", admin, json!({}));
    assert_eq!(mounts.status, 200);
    let accessor = mounts.body["data"]["pki-userpass/"]["accessor"]
        .as_str()
        .ok_or("actual accessor")?
        .to_owned();
    let entity = call(
        service,
        "POST",
        "identity/entity",
        admin,
        json!({
            "name":"entity.example.test","metadata":{"dns":"domain.example.test","team":"demo","wildcard":"*.example.test"}
        }),
    );
    assert_eq!(entity.status, 200);
    let entity_id = entity.body["data"]["id"]
        .as_str()
        .ok_or("canonical entity ID")?
        .to_owned();
    assert_eq!(
        call(
            service,
            "POST",
            "identity/entity-alias",
            admin,
            json!({
                "name":"pki-fixture","canonical_id":entity_id,"mount_accessor":accessor
            })
        )
        .status,
        200
    );
    let policy = r#"path "ca/issue/*" { capabilities = ["update"] }
path "ca/sign/*" { capabilities = ["update"] }
path "external-ca/issue/*" { capabilities = ["update"] }
path "external-ca/sign/*" { capabilities = ["update"] }"#;
    assert_eq!(
        call(
            service,
            "PUT",
            "sys/policies/acl/pki-entity",
            admin,
            json!({"policy":policy})
        )
        .status,
        204
    );
    assert_eq!(call(service, "POST", "auth/pki-userpass/users/pki-fixture", admin, json!({
        "password":"actual ephemeral template fixture password","token_policies":["pki-entity"]
    })).status, 204);
    let login = call(
        service,
        "POST",
        "auth/pki-userpass/login/pki-fixture",
        "",
        json!({
            "password":"actual ephemeral template fixture password"
        }),
    );
    assert_eq!(login.status, 200);
    assert_eq!(login.body["auth"]["entity_id"], entity_id);
    let token = login.body["auth"]["client_token"]
        .as_str()
        .ok_or("actual entity token")?
        .to_owned();
    Ok((token, entity_id, accessor))
}

fn actual_template_signed_csr(
    service: &mut Service,
    issuer: &X509,
    token: &str,
    csr: &str,
    public: &[u8],
    path: &str,
    uri: &str,
) -> TestResult {
    let response = call(
        service,
        "POST",
        path,
        token,
        json!({"csr":csr,"uri_sans":uri}),
    );
    let cert = signed_leaf(&response, issuer)?;
    assert_eq!(cert.public_key()?.public_key_to_der()?, public);
    assert!(response.body["data"].get("private_key").is_none());
    assert!(
        cert.subject_alt_names()
            .ok_or("actual template CSR URI")?
            .iter()
            .any(|name| name.uri() == Some(uri))
    );
    Ok(())
}

#[test]
fn pki_templates93_native_entity_alias_metadata_glob_and_fresh_private_projection() -> TestResult {
    let (root, mut service, unseal, admin, issuer) = local_fixture()?;
    let (token, entity_id, accessor) = actual_template_identity(&mut service, &admin)?;
    for (changes, request, status, error) in [
        (
            json!({"allowed_domains":["{{identity.entity.name}}"],"allowed_domains_template":true,"allow_bare_domains":true}),
            json!({"common_name":"entity.example.test"}),
            200,
            "",
        ),
        (
            json!({"allowed_domains":["{{identity.entity.name}}"],"allowed_domains_template":false,"allow_bare_domains":true}),
            json!({"common_name":"entity.example.test"}),
            400,
            "common name entity.example.test not allowed by this role",
        ),
        (
            json!({"allowed_domains":["{{identity.entity.metadata.dns}}"],"allowed_domains_template":true}),
            json!({"common_name":"leaf.domain.example.test"}),
            200,
            "",
        ),
        (
            json!({"allowed_domains":[format!("{{{{identity.entity.aliases.{accessor}.name}}}}.example.test")],"allowed_domains_template":true,"allow_bare_domains":true}),
            json!({"common_name":"pki-fixture.example.test"}),
            200,
            "",
        ),
        (
            json!({"allowed_uri_sans":["spiffe://example.test/{{identity.entity.metadata.team}}/*"],"allowed_uri_sans_template":true}),
            json!({"common_name":"leaf.example.test","uri_sans":"spiffe://example.test/demo/service"}),
            200,
            "",
        ),
        (
            json!({"allowed_uri_sans":["spiffe://example.test/{{identity.entity.metadata.team}}/*"],"allowed_uri_sans_template":false}),
            json!({"common_name":"leaf.example.test","uri_sans":"spiffe://example.test/demo/service"}),
            400,
            "URI Subject Alternative Names were provided via the API which are not valid for this role",
        ),
        (
            json!({"allowed_domains":["{{identity.entity.metadata.wildcard}}"],"allowed_domains_template":true,"allow_glob_domains":true}),
            json!({"common_name":"leaf.example.test"}),
            400,
            "common name leaf.example.test not allowed by this role",
        ),
        (
            json!({"allowed_domains":["{{identity.entity.metadata.wildcard}}"],"allowed_domains_template":true,"allow_glob_domains":true,"allow_globs_in_identity_templates":true}),
            json!({"common_name":"leaf.example.test"}),
            200,
            "",
        ),
    ] {
        named_role(&mut service, &admin, changes)?;
        let before = service
            .current_state_identity()
            .map_err(|_| "before native template")?;
        let response = call(&mut service, "POST", "ca/issue/time", &token, request);
        assert_eq!(response.status, status, "native entity template outcome");
        if status == 200 {
            signed_leaf(&response, &issuer)?;
            service
                .state
                .as_ref()
                .ok_or("template state")?
                .validate_format()
                .map_err(|_| "signed template state")?;
        } else {
            assert_eq!(response.body["errors"], json!([error]));
            assert_eq!(
                service
                    .current_state_identity()
                    .map_err(|_| "after native template rejection")?,
                before
            );
        }
    }
    named_role(
        &mut service,
        &admin,
        json!({
            "allowed_uri_sans":["spiffe://example.test/{{identity.entity.metadata.team}}/*"],"allowed_uri_sans_template":true
        }),
    )?;
    let (csr, public) = actual_csr_fixture()?;
    assert_eq!(
        call(
            &mut service,
            "PATCH",
            "ca/roles/time",
            &admin,
            json!({"use_csr_sans":false})
        )
        .status,
        200
    );
    actual_template_signed_csr(
        &mut service,
        &issuer,
        &token,
        &csr,
        &public,
        "ca/sign/time",
        "spiffe://example.test/demo/service",
    )?;
    assert_eq!(call(&mut service, "POST", &format!("identity/entity/id/{entity_id}"), &admin,
        json!({"metadata":{"dns":"domain.example.test","team":"next","wildcard":"*.example.test"}})).status, 204);
    assert_eq!(call(&mut service, "POST", "ca/issue/time", &token,
        json!({"common_name":"leaf.example.test","uri_sans":"spiffe://example.test/demo/service"})).status, 400);
    assert_eq!(
        call(
            &mut service,
            "POST",
            "ca/sign/time",
            &token,
            json!({"csr":csr,"uri_sans":"spiffe://example.test/demo/service"})
        )
        .status,
        400
    );
    actual_template_signed_csr(
        &mut service,
        &issuer,
        &token,
        &csr,
        &public,
        "ca/sign/time",
        "spiffe://example.test/next/service",
    )?;
    let admitted = call(
        &mut service,
        "POST",
        "ca/issue/time",
        &token,
        json!({"common_name":"leaf.example.test","uri_sans":"spiffe://example.test/next/service"}),
    );
    let cert = signed_leaf(&admitted, &issuer)?;
    assert!(
        cert.subject_alt_names()
            .ok_or("actual URI SAN")?
            .iter()
            .any(|name| name.uri() == Some("spiffe://example.test/next/service"))
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
    assert_eq!(
        call(&mut reopened, "GET", "ca/roles/time", &admin, json!({})).body["data"]["allowed_uri_sans_template"],
        true
    );
    let admitted = call(
        &mut reopened,
        "POST",
        "ca/issue/time",
        &token,
        json!({"common_name":"leaf.example.test","uri_sans":"spiffe://example.test/next/service"}),
    );
    signed_leaf(&admitted, &issuer)?;
    actual_template_signed_csr(
        &mut reopened,
        &issuer,
        &token,
        &csr,
        &public,
        "ca/sign/time",
        "spiffe://example.test/next/service",
    )?;
    assert_eq!(
        call(
            &mut reopened,
            "POST",
            &format!("identity/entity/id/{entity_id}"),
            &admin,
            json!({"disabled":true})
        )
        .status,
        204
    );
    assert_eq!(call(&mut reopened, "POST", "ca/issue/time", &token,
        json!({"common_name":"leaf.example.test","uri_sans":"spiffe://example.test/next/service"})).status, 403);
    assert_eq!(
        call(
            &mut reopened,
            "POST",
            "ca/sign/time",
            &token,
            json!({"csr":csr,"uri_sans":"spiffe://example.test/next/service"})
        )
        .status,
        403
    );
    Ok(())
}

#[test]
fn pki_templates93_external_signed_uri_owner_retirement_and_encrypted_reopen() -> TestResult {
    let remote = RemoteTransit::new_kind("ecdsa-p256")?;
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
            .ok_or("actual KMS CA")?
            .as_bytes(),
    )?;
    let (token, _, _) = actual_template_identity(&mut service, &admin)?;
    let mut role = role_body(&default_profile());
    role["allowed_uri_sans"] = json!(["spiffe://example.test/{{identity.entity.metadata.team}}/*"]);
    role["allowed_uri_sans_template"] = json!(true);
    assert_eq!(
        call(
            &mut service,
            "POST",
            "external-ca/roles/template",
            &admin,
            role
        )
        .status,
        200
    );
    let response = call(
        &mut service,
        "POST",
        "external-ca/issue/template",
        &token,
        json!({"common_name":"leaf.example.test","uri_sans":"spiffe://example.test/demo/service"}),
    );
    let (csr, public) = actual_csr_fixture()?;
    assert_eq!(
        call(
            &mut service,
            "PATCH",
            "external-ca/roles/template",
            &admin,
            json!({"use_csr_sans":false})
        )
        .status,
        200
    );
    actual_template_signed_csr(
        &mut service,
        &issuer,
        &token,
        &csr,
        &public,
        "external-ca/sign/template",
        "spiffe://example.test/demo/service",
    )?;
    let certificate = signed_leaf(&response, &issuer)?;
    assert!(
        certificate
            .subject_alt_names()
            .ok_or("external actual URI")?
            .iter()
            .any(|name| name.uri() == Some("spiffe://example.test/demo/service"))
    );
    let serial = response.body["data"]["serial_number"]
        .as_str()
        .ok_or("serial")?
        .to_owned();
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
    let stored = call(
        &mut service,
        "GET",
        &format!("external-ca/cert/{serial}"),
        &admin,
        json!({}),
    );
    assert_eq!(
        signed_leaf(&stored, &issuer)?.to_der()?,
        certificate.to_der()?
    );
    assert_eq!(remote.calls()?, calls);
    service
        .state
        .as_ref()
        .ok_or("retired template")?
        .validate_format()
        .map_err(|_| "actual template public owner")?;
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
    let stored = call(
        &mut reopened,
        "GET",
        &format!("external-ca/cert/{serial}"),
        &admin,
        json!({}),
    );
    assert_eq!(
        signed_leaf(&stored, &issuer)?.to_der()?,
        certificate.to_der()?
    );
    reopened
        .state
        .as_ref()
        .ok_or("reopened template")?
        .validate_format()
        .map_err(|_| "template reopened owner")?;
    Ok(())
}
