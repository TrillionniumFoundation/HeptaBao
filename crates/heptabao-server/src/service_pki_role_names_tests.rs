//! Native name/SAN/no-store cases and genuine protected format publication.
use super::*;

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
