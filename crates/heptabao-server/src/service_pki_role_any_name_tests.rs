//! Actual PKI role semantics, signed issuance, encrypted reopen and reader floor.
use super::*;
use crate::service::tests::bootstrap_unmounted;
use openssl::x509::X509;

#[test]
fn pki_role_any_name_signs_actual_unlisted_dns_names_and_reopens() -> TestResult {
    let root = Root::new();
    let mut service = root.service()?;
    let (unseal, admin) = bootstrap_unmounted(&mut service)?;
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
    let ca = call(
        &mut service,
        "POST",
        "ca/root/generate/internal",
        &admin,
        json!({"common_name":"ca.example.test","key_type":"ec","key_bits":256,"ttl":"4h"}),
    );
    assert_eq!(ca.status, 200, "actual EC root");
    let cert = X509::from_pem(
        ca.body["data"]["certificate"]
            .as_str()
            .ok_or("CA PEM missing")?
            .as_bytes(),
    )?;
    let public = cert.public_key()?;
    assert!(cert.verify(&public)?, "actual root self signature");
    let role = call(
        &mut service,
        "POST",
        "ca/roles/any",
        &admin,
        json!({"allow_any_name":true,"key_type":"ec","key_bits":256,"max_ttl":"1h"}),
    );
    assert_eq!(
        role.status, 200,
        "actual allow_any_name role without invented domains"
    );
    assert_eq!(role.body["data"]["allow_any_name"], true);
    assert_eq!(role.body["data"]["allowed_domains"], json!([]));
    let leaf = call(
        &mut service,
        "POST",
        "ca/issue/any",
        &admin,
        json!({"common_name":"outside.other.test","alt_names":["second.unlisted.test"],"ttl":"10m"}),
    );
    assert_eq!(
        leaf.status, 200,
        "actual authenticated unlisted DNS issuance"
    );
    let leaf = X509::from_pem(
        leaf.body["data"]["certificate"]
            .as_str()
            .ok_or("leaf PEM missing")?
            .as_bytes(),
    )?;
    assert!(
        leaf.verify(&public)?,
        "issued certificate signed by actual owned root"
    );
    let names = leaf.subject_alt_names().ok_or("SAN missing")?;
    assert!(
        names
            .iter()
            .any(|n| n.dnsname() == Some("outside.other.test"))
    );
    assert!(
        names
            .iter()
            .any(|n| n.dnsname() == Some("second.unlisted.test"))
    );
    let active = service.state.as_ref().ok_or("active state")?;
    assert_eq!(active.schema, PKI_ROLE_LEAF_PROFILE_STATE_SCHEMA);
    assert!(active.engines.has_pki_role_wildcard_state());
    assert!(active.engines.has_pki_role_any_name_state());
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
        200,
        "actual encrypted reopen"
    );
    assert_eq!(
        call(&mut reopened, "GET", "ca/roles/any", &admin, json!({})).body["data"]["allow_any_name"],
        true
    );
    let leaf = call(
        &mut reopened,
        "POST",
        "ca/issue/any",
        &admin,
        json!({"common_name":"third.unlisted.test","ttl":"10m"}),
    );
    assert_eq!(leaf.status, 200);
    let leaf = X509::from_pem(
        leaf.body["data"]["certificate"]
            .as_str()
            .ok_or("reopened leaf PEM missing")?
            .as_bytes(),
    )?;
    assert!(leaf.verify(&public)?, "reopened real private owner signs");
    Ok(())
}

#[test]
fn pki_role_any_name_preserves_dns_ip_constraints_and_false_legacy_bytes() -> TestResult {
    let root = Root::new();
    let mut service = root.service()?;
    let (_, admin) = bootstrap_unmounted(&mut service)?;
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
    assert_eq!(
        call(
            &mut service,
            "POST",
            "ca/root/generate/internal",
            &admin,
            json!({"common_name":"ca.example.test","key_type":"ec","key_bits":256,"ttl":"4h"})
        )
        .status,
        200
    );
    let scoped = json!({"allowed_domains":["example.test"],"allow_subdomains":true,"key_type":"ec","key_bits":256});
    assert_eq!(
        call(
            &mut service,
            "POST",
            "ca/roles/scoped",
            &admin,
            scoped.clone()
        )
        .status,
        200
    );
    assert_eq!(
        call(&mut service, "GET", "ca/roles/scoped", &admin, json!({})).body["data"]["allow_any_name"],
        false
    );
    let before =
        crate::secret_serde::to_vec(service.state.as_ref().ok_or("state")?, MAX_STATE_BYTES)
            .map_err(|_| "state bytes")?;
    let mut explicit = scoped.clone();
    explicit["allow_any_name"] = json!(false);
    assert_eq!(
        call(&mut service, "POST", "ca/roles/scoped", &admin, explicit).status,
        200
    );
    let after =
        crate::secret_serde::to_vec(service.state.as_ref().ok_or("state")?, MAX_STATE_BYTES)
            .map_err(|_| "state bytes")?;
    assert!(
        before == after,
        "default false preserves complete actual legacy state bytes"
    );
    assert_eq!(
        call(
            &mut service,
            "POST",
            "ca/issue/scoped",
            &admin,
            json!({"common_name":"outside.other.test"})
        )
        .status,
        400
    );
    for invalid in [json!("not_bool"), json!(2), json!([]), json!({})] {
        let mut body = scoped.clone();
        body["allow_any_name"] = invalid;
        assert_eq!(
            call(&mut service, "POST", "ca/roles/invalid", &admin, body).status,
            400,
            "actual framework boolean conversion refuses unsupported values"
        );
    }
    assert_eq!(
        call(
            &mut service,
            "POST",
            "ca/roles/any",
            &admin,
            json!({"allow_any_name":true,"allow_ip_sans":false,"key_type":"ec","key_bits":256})
        )
        .status,
        200
    );
    for name in ["bad name.test", "-bad.test", "bad..test", "bad/test"] {
        assert_eq!(
            call(
                &mut service,
                "POST",
                "ca/issue/any",
                &admin,
                json!({"common_name":name})
            )
            .status,
            400,
            "any DNS domain does not bypass hostname validation"
        );
    }
    assert_eq!(
        call(
            &mut service,
            "POST",
            "ca/issue/any",
            &admin,
            json!({"common_name":"outside.other.test","ip_sans":["192.0.2.1"]})
        )
        .status,
        400,
        "allow_any_name retains independent IP SAN permission"
    );
    assert_eq!(call(&mut service,"POST","ca/roles/any",&admin,json!({"allow_any_name":true,"allowed_domains":["bad domain"],"key_type":"ec","key_bits":256})).status,400,"supplied malformed domains still refused");
    Ok(())
}

#[test]
fn pki_role_any_name_raises_all_namespace_floor_and_retirement_rejects_restore() -> TestResult {
    let root = Root::new();
    let mut service = root.service()?;
    let (unseal, admin) = bootstrap_unmounted(&mut service)?;
    assert_eq!(
        call(
            &mut service,
            "POST",
            "sys/namespaces/team",
            &admin,
            json!({})
        )
        .status,
        200
    );
    assert_eq!(
        service
            .handle_at(
                "POST",
                "sys/mounts/ca",
                "team",
                &admin,
                json!({"type":"pki"}),
                100
            )
            .status,
        204
    );
    let previous = service.state.clone().ok_or("previous")?;
    let backup = Zeroizing::new(service.durable.as_ref().ok_or("durable")?.export_backup()?);
    assert_eq!(
        service
            .handle_at(
                "POST",
                "ca/roles/any",
                "team",
                &admin,
                json!({"allow_any_name":true,"key_type":"ec","key_bits":256}),
                100
            )
            .status,
        200
    );
    let active = service.state.clone().ok_or("active")?;
    assert_eq!(active.schema, PKI_ROLE_TIME_STATE_SCHEMA);
    assert!(active.engines.has_pki_role_wildcard_state());
    assert!(active.engines.has_pki_role_any_name_state());
    assert!(active.engines.has_pki_role_time_state());
    let identity = service.current_state_identity().map_err(|_| "identity")?;
    let mut lower = active.clone();
    lower.schema = TOKEN_ROLE_STATE_SCHEMA;
    assert_eq!(lower.writer_schema(), PKI_ROLE_TIME_STATE_SCHEMA);
    assert!(lower.validate_format().is_err());
    assert!(service.commit_state(&mut lower).is_err());
    assert!(Service::validate_snapshot_protected_floor(&active, &lower).is_err());
    for schema in [81, 86, 87] {
        let mut integrated_lower = active.clone();
        integrated_lower.schema = schema;
        assert_eq!(
            integrated_lower.writer_schema(),
            PKI_ROLE_TIME_STATE_SCHEMA,
            "supported earlier readers still require the actual profile88 and time89 owners"
        );
        assert!(
            integrated_lower.validate_format().is_err()
                && integrated_lower
                    .validate_publication_schema(Some(&active))
                    .is_err()
                && service.commit_state(&mut integrated_lower).is_err(),
            "integrated readers cannot relabel a actual profile88 and time89 graph"
        );
    }
    for schema in [82, MAX_SUPPORTED_STATE_SCHEMA + 1] {
        let mut unsupported = active.clone();
        unsupported.schema = schema;
        assert_eq!(
            unsupported.writer_schema(),
            schema,
            "unintegrated formats not silently normalized"
        );
        assert!(unsupported.validate_format().is_err());
        assert!(
            unsupported
                .validate_publication_schema(Some(&active))
                .is_err()
        );
    }
    assert!(service.prepare_snapshot_restore(&backup).is_err());
    assert_eq!(
        service
            .current_state_identity()
            .map_err(|_| "unchanged identity")?,
        identity
    );
    assert_eq!(
        service
            .handle_at("DELETE", "ca/roles/any", "team", &admin, json!({}), 100)
            .status,
        204
    );
    let retired = service.state.as_ref().ok_or("retired")?;
    assert!(!retired.engines.has_pki_role_any_name_state());
    assert_eq!(retired.schema, PKI_ROLE_TIME_STATE_SCHEMA);
    assert_eq!(retired.writer_schema(), PKI_ROLE_TIME_STATE_SCHEMA);
    assert!(previous.validate_publication_schema(Some(retired)).is_err());
    assert!(Service::validate_snapshot_protected_floor(retired, &previous).is_err());
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
        reopened.state.as_ref().ok_or("reopened")?.schema,
        PKI_ROLE_TIME_STATE_SCHEMA
    );
    assert!(
        !reopened
            .state
            .as_ref()
            .ok_or("reopened")?
            .engines
            .has_pki_role_any_name_state()
    );
    assert!(reopened.prepare_snapshot_restore(&backup).is_err());
    Ok(())
}

#[test]
fn pki_role_default_ip_sans_signs_ipv4_ipv6_and_retains_explicit_false_on_reopen() -> TestResult {
    let root = Root::new();
    let mut service = root.service()?;
    let (unseal, admin) = bootstrap_unmounted(&mut service)?;
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
    let ca = call(
        &mut service,
        "POST",
        "ca/root/generate/internal",
        &admin,
        json!({"common_name":"ca.example.test","key_type":"ec","key_bits":256,"ttl":"4h"}),
    );
    assert_eq!(ca.status, 200, "actual issuer creation");
    let ca = X509::from_pem(
        ca.body["data"]["certificate"]
            .as_str()
            .ok_or("CA PEM")?
            .as_bytes(),
    )?;
    let public = ca.public_key()?;
    assert!(ca.verify(&public)?, "actual issuer signature");
    let scoped = json!({"allowed_domains":["example.test"],"allow_subdomains":true,"key_type":"ec","key_bits":256,"max_ttl":"1h"});
    let role = call(
        &mut service,
        "POST",
        "ca/roles/default-ip",
        &admin,
        scoped.clone(),
    );
    assert_eq!(role.status, 200);
    assert_eq!(
        role.body["data"]["allow_ip_sans"], true,
        "real create default from OpenBao 2.7.0"
    );
    let mut deny = scoped.clone();
    deny["allow_ip_sans"] = json!(false);
    assert_eq!(
        call(
            &mut service,
            "POST",
            "ca/roles/deny-ip",
            &admin,
            deny.clone()
        )
        .status,
        200
    );
    let request =
        json!({"common_name":"api.example.test","ip_sans":["192.0.2.1","2001:db8::1"],"ttl":"10m"});
    let ipv4 = std::net::Ipv4Addr::new(192, 0, 2, 1).octets();
    let ipv6 = "2001:db8::1".parse::<std::net::Ipv6Addr>()?.octets();
    for reopened in [false, true] {
        if reopened {
            drop(service);
            service = root.service()?;
            assert_eq!(
                call(
                    &mut service,
                    "POST",
                    "sys/unseal",
                    "",
                    json!({"key":unseal})
                )
                .status,
                200,
                "actual encrypted owner reopen"
            );
        }
        assert_eq!(
            call(
                &mut service,
                "GET",
                "ca/roles/default-ip",
                &admin,
                json!({})
            )
            .body["data"]["allow_ip_sans"],
            true
        );
        assert_eq!(
            call(&mut service, "GET", "ca/roles/deny-ip", &admin, json!({})).body["data"]["allow_ip_sans"],
            false,
            "stored explicit false is not replaced by new create default"
        );
        let issued = call(
            &mut service,
            "POST",
            "ca/issue/default-ip",
            &admin,
            request.clone(),
        );
        assert_eq!(issued.status, 200, "default role actually issues IP SANs");
        let leaf = X509::from_pem(
            issued.body["data"]["certificate"]
                .as_str()
                .ok_or("leaf PEM")?
                .as_bytes(),
        )?;
        assert!(
            leaf.verify(&public)?,
            "original actual issuer signs both address families"
        );
        let names = leaf.subject_alt_names().ok_or("SAN missing")?;
        assert!(
            names
                .iter()
                .any(|name| name.ipaddress() == Some(ipv4.as_slice())),
            "actual IPv4 SAN bytes"
        );
        assert!(
            names
                .iter()
                .any(|name| name.ipaddress() == Some(ipv6.as_slice())),
            "actual IPv6 SAN bytes"
        );
        assert_eq!(
            call(
                &mut service,
                "POST",
                "ca/issue/deny-ip",
                &admin,
                request.clone()
            )
            .status,
            400,
            "explicit false continues denying actual IPv4 and IPv6 issuance"
        );
        assert_eq!(
            call(
                &mut service,
                "POST",
                "ca/issue/default-ip",
                &admin,
                json!({"common_name":"api.example.test","ip_sans":["not-an-ip"]})
            )
            .status,
            400,
            "default true does not accept malformed addresses"
        );
        assert_eq!(
            call(
                &mut service,
                "POST",
                "ca/issue/default-ip",
                &admin,
                json!({"common_name":"outside.other.test","ip_sans":["192.0.2.1"]})
            )
            .status,
            400,
            "IP permission does not widen the independently owned DNS domains"
        );
        let state = service.state.as_ref().ok_or("state")?;
        assert!(
            !state.engines.has_pki_role_any_name_state()
                && state.engines.has_pki_role_bare_domain_state()
                && state.engines.has_pki_role_wildcard_state()
                && state.schema == PKI_ROLE_LEAF_PROFILE_STATE_SCHEMA,
            "existing IP permission and actual separate base-domain owner keep distinct semantics"
        );
    }
    let state = service.state.as_ref().ok_or("state")?;
    let bytes = crate::secret_serde::to_vec(state, MAX_STATE_BYTES).map_err(|_| "state bytes")?;
    let decoded = serde_json::from_slice::<State>(&bytes).map_err(|_| "state decode")?;
    assert!(
        crate::secret_serde::to_vec(&decoded, MAX_STATE_BYTES).map_err(|_| "state roundtrip")?
            == bytes,
        "actual stored booleans roundtrip without default rewrites"
    );
    for wrong_type in [json!("not_bool"), json!(2), json!([]), json!({})] {
        let mut invalid = scoped.clone();
        invalid["allow_ip_sans"] = wrong_type;
        assert_eq!(
            call(&mut service, "POST", "ca/roles/invalid-ip", &admin, invalid).status,
            400,
            "invalid public boolean conversion cannot publish role permission"
        );
    }
    Ok(())
}

#[test]
fn pki_role_bare_domain_default_denies_base_and_explicit_permission_reopens() -> TestResult {
    let root = Root::new();
    let mut service = root.service()?;
    let (unseal, admin) = bootstrap_unmounted(&mut service)?;
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
    let ca = call(
        &mut service,
        "POST",
        "ca/root/generate/internal",
        &admin,
        json!({"common_name":"ca.example.test","key_type":"ec","key_bits":256,"ttl":"4h"}),
    );
    assert_eq!(ca.status, 200);
    let ca = X509::from_pem(
        ca.body["data"]["certificate"]
            .as_str()
            .ok_or("CA PEM")?
            .as_bytes(),
    )?;
    let public = ca.public_key()?;
    let role = json!({"allowed_domains":["example.test"],"allow_subdomains":true,"key_type":"ec","key_bits":256});
    assert_eq!(
        call(
            &mut service,
            "POST",
            "ca/roles/default-bare",
            &admin,
            role.clone()
        )
        .status,
        200
    );
    let mut allowed = role.clone();
    allowed["allow_bare_domains"] = json!(true);
    assert_eq!(
        call(
            &mut service,
            "POST",
            "ca/roles/allowed-bare",
            &admin,
            allowed
        )
        .status,
        200
    );
    let base = json!({"common_name":"example.test","ttl":"10m"});
    for reopen in [false, true] {
        if reopen {
            drop(service);
            service = root.service()?;
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
        }
        assert_eq!(
            call(
                &mut service,
                "GET",
                "ca/roles/default-bare",
                &admin,
                json!({})
            )
            .body["data"]["allow_bare_domains"],
            false
        );
        assert_eq!(
            call(
                &mut service,
                "GET",
                "ca/roles/allowed-bare",
                &admin,
                json!({})
            )
            .body["data"]["allow_bare_domains"],
            true
        );
        let denied = call(
            &mut service,
            "POST",
            "ca/issue/default-bare",
            &admin,
            base.clone(),
        );
        assert_eq!(
            denied.status, 400,
            "a new default role cannot issue its base domain"
        );
        assert!(denied.body.get("data").is_none());
        for (path, name) in [
            ("ca/issue/allowed-bare", "example.test"),
            ("ca/issue/default-bare", "leaf.example.test"),
        ] {
            let leaf = call(
                &mut service,
                "POST",
                path,
                &admin,
                json!({"common_name":name,"ttl":"10m"}),
            );
            assert_eq!(leaf.status, 200, "actual explicitly scoped issuance");
            let cert = X509::from_pem(
                leaf.body["data"]["certificate"]
                    .as_str()
                    .ok_or("leaf PEM")?
                    .as_bytes(),
            )?;
            assert!(cert.verify(&public)?, "actual owned issuer signature");
        }
        assert_eq!(
            call(
                &mut service,
                "POST",
                "ca/issue/allowed-bare",
                &admin,
                json!({"common_name":"outside.test"})
            )
            .status,
            400
        );
    }
    let active = service.state.clone().ok_or("state")?;
    assert!(
        active.schema == PKI_ROLE_TIME_STATE_SCHEMA
            && active.engines.has_pki_role_bare_domain_state()
            && active.engines.has_pki_role_wildcard_state()
            && active.engines.has_pki_role_time_state()
    );
    for label in [80, 83, 84] {
        let mut lower = active.clone();
        lower.schema = label;
        assert_eq!(lower.writer_schema(), PKI_ROLE_TIME_STATE_SCHEMA);
        assert!(lower.validate_format().is_err() && service.commit_state(&mut lower).is_err());
        assert!(Service::validate_snapshot_protected_floor(&active, &lower).is_err());
    }
    Ok(())
}

#[test]
fn pki_wildcard_actual_signed_cn_san_and_explicit_disabled_precedence() -> TestResult {
    let root = Root::new();
    let mut service = root.service()?;
    let (_, admin) = bootstrap_unmounted(&mut service)?;
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
    let ca = call(
        &mut service,
        "POST",
        "ca/root/generate/internal",
        &admin,
        json!({"common_name":"ca.example.test","key_type":"ec","key_bits":256,"ttl":"4h"}),
    );
    assert_eq!(ca.status, 200);
    let issuer = X509::from_pem(
        ca.body["data"]["certificate"]
            .as_str()
            .ok_or("CA")?
            .as_bytes(),
    )?;
    let public = issuer.public_key()?;
    assert!(issuer.verify(&public)?);
    assert_eq!(call(&mut service,"POST","ca/roles/wild",&admin,
        json!({"allowed_domains":["example.test"],"allow_subdomains":true,"key_type":"ec","key_bits":256})).status,200);
    for (cn, expected_san) in [
        ("*.example.test", Some("*.example.test")),
        ("f*o.example.test", None),
    ] {
        let leaf = call(
            &mut service,
            "POST",
            "ca/issue/wild",
            &admin,
            json!({"common_name":cn,"ttl":"10m"}),
        );
        assert_eq!(leaf.status, 200, "actual wildcard certificate");
        let cert = X509::from_pem(
            leaf.body["data"]["certificate"]
                .as_str()
                .ok_or("leaf")?
                .as_bytes(),
        )?;
        assert!(cert.verify(&public)?, "actual issuer signature");
        let name = cert
            .subject_name()
            .entries_by_nid(openssl::nid::Nid::COMMONNAME)
            .next()
            .ok_or("CN")?;
        assert_eq!(name.data().as_slice(), cn.as_bytes());
        let names: Vec<_> = cert
            .subject_alt_names()
            .map(|names| {
                names
                    .iter()
                    .filter_map(|n| n.dnsname().map(str::to_owned))
                    .collect()
            })
            .unwrap_or_default();
        assert_eq!(
            names,
            expected_san
                .into_iter()
                .map(str::to_owned)
                .collect::<Vec<_>>()
        );
    }
    let san_only = call(
        &mut service,
        "POST",
        "ca/issue/wild",
        &admin,
        json!({"common_name":"web.example.test","alt_names":["*.example.test"],"ttl":"10m"}),
    );
    assert_eq!(san_only.status, 200);
    let cert = X509::from_pem(
        san_only.body["data"]["certificate"]
            .as_str()
            .ok_or("SAN-only leaf")?
            .as_bytes(),
    )?;
    assert!(cert.verify(&public)?);
    let names: Vec<_> = cert
        .subject_alt_names()
        .ok_or("SAN-only names")?
        .iter()
        .filter_map(|name| name.dnsname().map(str::to_owned))
        .collect();
    assert_eq!(names, vec!["web.example.test", "*.example.test"]);
    assert_eq!(
        call(&mut service, "DELETE", "ca/roles/wild", &admin, json!({})).status,
        204
    );
    let issued_only = service.state.as_ref().ok_or("issued wildcard owner")?;
    assert!(!issued_only.engines.has_pki_role_bare_domain_state());
    assert!(
        issued_only.engines.has_pki_role_wildcard_state(),
        "actual issued CN/SAN retains owner after role deletion"
    );
    let mut lower = issued_only.clone();
    lower.schema = PKI_ROLE_BARE_DOMAIN_STATE_SCHEMA;
    assert_eq!(
        lower
            .validate_format()
            .err()
            .ok_or("issued wildcard relabeled as84")?
            .status,
        503
    );
    assert_eq!(
        call(
            &mut service,
            "POST",
            "ca/roles/disabled",
            &admin,
            json!({"allow_any_name":true,"allow_wildcard_certificates":false})
        )
        .status,
        200
    );
    let before = serde_json::to_vec(service.state.as_ref().ok_or("state")?)?;
    let rejected = call(
        &mut service,
        "POST",
        "ca/issue/disabled",
        &admin,
        json!({"common_name":"*.unlisted.test"}),
    );
    assert_eq!(rejected.status, 400);
    assert_eq!(
        rejected.body["errors"][0],
        "common name *.unlisted.test not allowed by this role"
    );
    assert_eq!(
        before,
        serde_json::to_vec(service.state.as_ref().ok_or("state")?)?
    );
    Ok(())
}

#[test]
fn pki_profile_real_owner_schema88_keeps_historical83_84_85_and_retired_fences() -> TestResult {
    let root = Root::new();
    let mut service = root.service()?;
    let (unseal, admin) = bootstrap_unmounted(&mut service)?;
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
    let created = call(
        &mut service,
        "POST",
        "ca/roles/owner",
        &admin,
        json!({"allowed_domains":["example.test"],"allow_subdomains":true}),
    );
    assert_eq!(created.status, 200);
    assert_eq!(created.body["data"]["allow_wildcard_certificates"], true);
    let active = service.state.as_ref().ok_or("state")?.clone();
    assert!(active.engines.has_pki_role_wildcard_state());
    assert!(active.engines.has_pki_role_leaf_profile_state());
    assert!(active.engines.has_pki_role_time_state());
    assert_eq!(active.schema, PKI_ROLE_TIME_STATE_SCHEMA);
    for floor in [80, 83, 84, 85] {
        let mut disguised = active.clone();
        disguised.schema = floor;
        assert_eq!(disguised.writer_schema(), PKI_ROLE_TIME_STATE_SCHEMA);
        assert_eq!(
            disguised
                .validate_format()
                .err()
                .ok_or("format accepted downgrade")?
                .status,
            503
        );
        assert_eq!(
            disguised
                .validate_publication_schema(Some(&active))
                .err()
                .ok_or("publication accepted downgrade")?
                .status,
            503
        );
        assert_eq!(
            Service::validate_snapshot_protected_floor(&active, &disguised)
                .err()
                .ok_or("snapshot accepted downgrade")?
                .status,
            400
        );
    }
    assert!(
        [0, 82, MAX_SUPPORTED_STATE_SCHEMA + 1]
            .into_iter()
            .all(|schema| !supported_reader_schema(schema))
    );
    assert!(
        (1..=80).all(supported_reader_schema)
            && [81, 83, 84, 85, 86, 87, 88, 89]
                .into_iter()
                .all(supported_reader_schema)
    );
    // A separate old typed-role format fixture, never a publication of the
    // active state, proves that the real historical84 reader still works.
    let mut encoded85 = serde_json::to_value(&active.engines)?;
    let role85 = encoded85
        .pointer_mut("/namespaces//mounts/ca~1/backend/Pki/roles/owner")
        .and_then(Value::as_object_mut)
        .ok_or("historical85 role-only fixture")?;
    assert!(role85.remove("role_leaf_profile").is_some());
    // This independent typed format fixture uses the predecessor's actual
    // 24-hour maximum and no Time89 policy. It is never a saved backup or
    // a publication of the current default-max=0 role above.
    assert_eq!(role85["max_ttl"], json!(0));
    role85.insert("max_ttl".to_owned(), json!(24 * 3600));
    role85.remove("role_time_policy");
    let mut historical85 = active.clone();
    historical85.engines = serde_json::from_value(encoded85.clone())?;
    historical85.schema = PKI_ROLE_WILDCARD_STATE_SCHEMA;
    assert!(historical85.engines.has_pki_role_wildcard_state());
    assert!(!historical85.engines.has_pki_role_leaf_profile_state());
    assert_eq!(historical85.writer_schema(), PKI_ROLE_WILDCARD_STATE_SCHEMA);
    assert!(historical85.validate_format().is_ok());
    let bytes85 = crate::secret_serde::to_vec(&historical85, MAX_STATE_BYTES)
        .map_err(|_| "historical85 bytes")?;
    let reopened85: State = serde_json::from_slice(&bytes85)?;
    assert!(reopened85.validate_format().is_ok());
    assert!(
        bytes85
            == crate::secret_serde::to_vec(&reopened85, MAX_STATE_BYTES)
                .map_err(|_| "historical85 roundtrip")?
    );
    let mut encoded = encoded85;
    let old_role = encoded
        .pointer_mut("/namespaces//mounts/ca~1/backend/Pki/roles/owner")
        .and_then(Value::as_object_mut)
        .ok_or("old typed role")?;
    assert_eq!(
        old_role.remove("allow_wildcard_certificates"),
        Some(json!(true))
    );
    let mut historical = active.clone();
    historical.engines = serde_json::from_value(encoded)?;
    historical.schema = PKI_ROLE_BARE_DOMAIN_STATE_SCHEMA;
    assert!(
        historical.engines.has_pki_role_bare_domain_state()
            && !historical.engines.has_pki_role_wildcard_state()
    );
    assert_eq!(
        historical.writer_schema(),
        PKI_ROLE_BARE_DOMAIN_STATE_SCHEMA
    );
    assert!(historical.validate_format().is_ok());
    let bytes = serde_json::to_vec(&historical)?;
    let reopened: State = serde_json::from_slice(&bytes)?;
    assert_eq!(bytes, serde_json::to_vec(&reopened)?);
    assert!(reopened.validate_format().is_ok());
    // A separate historical83 typed fixture contains genuine AnyName but
    // neither later optional role owner. It is never committed over the current schema89.
    let mut encoded83 = serde_json::to_value(&historical.engines)?;
    let role83 = encoded83
        .pointer_mut("/namespaces//mounts/ca~1/backend/Pki/roles/owner")
        .and_then(Value::as_object_mut)
        .ok_or("historical83 role")?;
    assert_eq!(role83.remove("allow_bare_domains"), Some(json!(false)));
    assert!(!role83.contains_key("allow_wildcard_certificates"));
    role83.insert("allow_any_name".to_owned(), json!(true));
    let mut historical83 = historical.clone();
    historical83.engines = serde_json::from_value(encoded83)?;
    historical83.schema = PKI_ROLE_ANY_NAME_STATE_SCHEMA;
    assert!(historical83.engines.has_pki_role_any_name_state());
    assert!(!historical83.engines.has_pki_role_bare_domain_state());
    assert!(!historical83.engines.has_pki_role_wildcard_state());
    assert_eq!(historical83.writer_schema(), PKI_ROLE_ANY_NAME_STATE_SCHEMA);
    assert!(historical83.validate_format().is_ok());
    let bytes83 = serde_json::to_vec(&historical83)?;
    let reopened83: State = serde_json::from_slice(&bytes83)?;
    assert!(reopened83.validate_format().is_ok());
    assert_eq!(bytes83, serde_json::to_vec(&reopened83)?);
    assert!(
        historical83
            .validate_publication_schema(Some(&active))
            .is_err()
    );
    assert!(Service::validate_snapshot_protected_floor(&active, &historical83).is_err());
    drop(service);
    let mut service = root.service()?;
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
    assert_eq!(
        service.state.as_ref().ok_or("reopened")?.schema,
        PKI_ROLE_TIME_STATE_SCHEMA
    );
    assert_eq!(
        call(&mut service, "DELETE", "sys/mounts/ca", &admin, json!({})).status,
        204
    );
    let retired = service.state.as_ref().ok_or("retired")?;
    assert!(!retired.engines.has_pki_role_wildcard_state());
    assert_eq!(retired.schema, PKI_ROLE_TIME_STATE_SCHEMA);
    assert_eq!(retired.writer_schema(), PKI_ROLE_TIME_STATE_SCHEMA);
    let mut lower = retired.clone();
    lower.schema = PKI_ROLE_BARE_DOMAIN_STATE_SCHEMA;
    assert_eq!(
        lower
            .validate_publication_schema(Some(retired))
            .err()
            .ok_or("retired floor rolled back")?
            .status,
        503
    );
    assert_eq!(
        Service::validate_snapshot_protected_floor(retired, &lower)
            .err()
            .ok_or("retired snapshot floor rolled back")?
            .status,
        400
    );
    Ok(())
}
