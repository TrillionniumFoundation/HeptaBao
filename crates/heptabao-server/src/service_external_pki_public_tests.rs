//! Bounded public projections retain normal Service lifecycle and audit gates.
//! Private output, credentials and serialized owner state are never formatted.
use super::*;

fn full_ram_state_identity(service: &Service) -> TestResult<[u8; 32]> {
    let encoded = zeroize::Zeroizing::new(serde_json::to_vec(
        service.state.as_ref().ok_or("RAM state identity")?,
    )?);
    let digest = ring::digest::digest(&ring::digest::SHA256, encoded.as_slice());
    let mut bytes = [0; 32];
    bytes.copy_from_slice(digest.as_ref());
    Ok(bytes)
}

fn provider_sign_entries(remote: &RemoteTransit) -> TestResult<usize> {
    Ok(remote
        .trace
        .lock()
        .map_err(|_| "provider trace lock")?
        .iter()
        .filter(|path| path.as_str() == "/v1/transit/sign/remote")
        .count())
}

fn issued_public_fixture(
    remote: &RemoteTransit,
) -> TestResult<(Root, Service, String, String, String)> {
    let (root, mut service, unseal, admin) = leaf_fixture(remote)?;
    let leaf = call(
        &mut service,
        "POST",
        "external-ca/issue/leaf",
        &admin,
        json!({"common_name":"public-leaf.example.test","ttl":"10m"}),
    );
    assert!(
        leaf.status == 200,
        "public leaf fixture is genuinely issued"
    );
    let serial = leaf.body["data"]["serial_number"]
        .as_str()
        .ok_or("issued serial")?
        .to_owned();
    Ok((root, service, unseal, admin, serial))
}

#[test]
fn external_pki270_public_projections_ignore_bearer_without_business_mutation_or_sign() -> TestResult
{
    let remote = RemoteTransit::new_kind("ed25519")?;
    let (root, mut service, _unseal, admin, serial) = issued_public_fixture(&remote)?;
    let finite = call(
        &mut service,
        "POST",
        "auth/token/create",
        &admin,
        json!({"policies":["default"],"num_uses":1,"ttl":600}),
    );
    assert!(finite.status == 200, "finite credential fixture");
    let finite_token = finite.body["auth"]["client_token"]
        .as_str()
        .ok_or("finite credential")?;
    let expired = service.handle_at(
        "POST",
        "auth/token/create",
        "",
        &admin,
        json!({"policies":["default"],"ttl":1}),
        90,
    );
    assert!(expired.status == 200, "expired credential fixture");
    let expired_token = expired.body["auth"]["client_token"]
        .as_str()
        .ok_or("expired credential")?;
    assert!(
        service
            .state
            .as_ref()
            .ok_or("state")?
            .auth
            .clone()
            .authenticate(expired_token, 100)
            .is_err(),
        "the expired bearer fixture is actually expired"
    );
    let mut wrap_request = ServiceRequest::new(
        "POST",
        "sys/wrapping/wrap",
        "",
        &admin,
        json!({"synthetic":"public-read-use-boundary"}),
    );
    wrap_request.wrap_ttl_seconds = Some(60);
    let wrapped = service.handle_request_at(wrap_request, 100);
    assert!(wrapped.status == 200, "wrapping credential fixture");
    let wrapper = wrapped.body["wrap_info"]["token"]
        .as_str()
        .ok_or("wrapping credential")?;
    for token in [finite_token, wrapper] {
        let lookup = call(
            &mut service,
            "POST",
            "auth/token/lookup",
            &admin,
            json!({"token":token}),
        );
        assert!(
            lookup.status == 200 && lookup.body["data"]["num_uses"] == 1,
            "the finite and wrapper fixtures each have one remaining use"
        );
    }
    let routes = [
        ("GET", format!("external-ca/cert/{serial}")),
        ("GET", format!("external-ca/cert/{serial}/raw")),
        ("GET", format!("external-ca/cert/{serial}/raw/pem")),
        ("GET", "external-ca/cert/ca".into()),
        ("GET", "external-ca/ca".into()),
        ("GET", "external-ca/ca/pem".into()),
        ("GET", "external-ca/cert/ca_chain".into()),
        ("GET", "external-ca/ca_chain".into()),
        ("GET", "external-ca/cert/crl".into()),
        ("GET", "external-ca/crl".into()),
        ("GET", "external-ca/crl/pem".into()),
        ("GET", "external-ca/cert/delta-crl".into()),
        ("GET", "external-ca/crl/delta".into()),
        ("GET", "external-ca/crl/delta/pem".into()),
        ("LIST", "external-ca/issuers".into()),
        // GET?list=true is parsed to the same closed LIST capability at HTTP.
        ("LIST", "external-ca/issuers".into()),
        ("GET", "external-ca/issuer/default/json".into()),
    ];
    let before = service.current_state_identity().map_err(|_| "identity")?;
    let ram_before = full_ram_state_identity(&service)?;
    let generation = service
        .external_effect_generation()
        .map_err(|_| "generation")?;
    let provider_entries = remote.calls()?;
    let audit_before = fs::read_to_string(root.path.join("audit.jsonl"))?
        .lines()
        .count();
    // The API token parameter represents both absent and explicitly empty
    // bearer headers as empty; the HTTP profile retains both distinct rows.
    for token in [
        "",
        "synthetic-invalid-bearer",
        expired_token,
        finite_token,
        wrapper,
    ] {
        for (method, path) in &routes {
            let response = call(&mut service, method, path, token, json!({}));
            assert!(
                response.status == 200,
                "closed public projection ignores bearer admission"
            );
            assert!(
                response.body["data"].get("private_key").is_none(),
                "public projection never contains private material"
            );
        }
    }
    let after = service.current_state_identity().map_err(|_| "identity")?;
    assert!(
        before == after,
        "reads at the existing clock floor do not publish maintenance"
    );
    assert!(
        full_ram_state_identity(&service)? == ram_before,
        "actual serialized RAM state, uses and wrapper clocks remain equal"
    );
    assert!(
        service
            .external_effect_generation()
            .map_err(|_| "generation")?
            == generation,
        "public reads do not publish a durable state transition"
    );
    assert!(
        remote.calls()? == provider_entries,
        "public cache reads enter no provider operation"
    );
    let audit_after = fs::read_to_string(root.path.join("audit.jsonl"))?
        .lines()
        .count();
    assert!(
        audit_after - audit_before == 2 * 5 * routes.len(),
        "every public read has request and response audit"
    );
    Ok(())
}

#[test]
fn external_pki270_public_capability_cannot_authorize_sensitive_routes_or_cross_namespace()
-> TestResult {
    let remote = RemoteTransit::new_kind("ed25519")?;
    let (_root, mut service, _unseal, admin, serial) = issued_public_fixture(&remote)?;
    assert!(
        call(
            &mut service,
            "POST",
            "sys/namespaces/isolated",
            &admin,
            json!({})
        )
        .status
            == 200,
        "isolated namespace fixture"
    );
    let before = service
        .external_effect_generation()
        .map_err(|_| "generation")?;
    let provider_entries = remote.calls()?;
    for (method, path, body, expected_status) in [
        (
            "POST",
            "external-ca/issue/leaf",
            json!({"common_name":"public-leaf.example.test"}),
            403,
        ),
        (
            "POST",
            "external-ca/revoke",
            json!({"serial_number":serial}),
            403,
        ),
        ("GET", "external-ca/crl/rotate", json!({}), 403),
        ("GET", "external-ca/config/crl", json!({}), 403),
        ("GET", "external-ca/roles/leaf", json!({}), 403),
        ("GET", "external-ca-other/cert/ca", json!({}), 403),
        ("GET", "external-ca/cert/ca/../roles/leaf", json!({}), 400),
    ] {
        assert!(
            call(&mut service, method, path, "", body).status == expected_status,
            "public read authority stays closed"
        );
    }
    assert!(
        service
            .handle_at("GET", "external-ca/cert/ca", "isolated", "", json!({}), 100)
            .status
            == 403,
        "namespace resolution cannot disclose a different namespace issuer"
    );
    assert!(
        remote.calls()? == provider_entries,
        "rejected anonymous operations never enter provider"
    );
    assert!(
        service
            .external_effect_generation()
            .map_err(|_| "generation")?
            == before,
        "rejected public capability cannot publish a mutation"
    );
    Ok(())
}

#[test]
fn external_pki270_public_cache_owner_revocation_never_rebuilds() -> TestResult {
    let remote = RemoteTransit::new_kind("ed25519")?;
    let (_root, mut service, _unseal, admin) = leaf_fixture(&remote)?;
    let _unused_last_use = limited_token(
        &mut service,
        &admin,
        "path \"external-ca/issue/leaf\" { capabilities = [\"update\"] }",
    )?;
    let owner = call(
        &mut service,
        "POST",
        "auth/token/create",
        &admin,
        json!({"policies":["scoped"],"no_default_policy":true}),
    );
    assert!(owner.status == 200, "live original leaf owner");
    let token = owner.body["auth"]["client_token"]
        .as_str()
        .ok_or("leaf owner")?;
    assert!(
        call(
            &mut service,
            "POST",
            "external-ca/issue/leaf",
            token,
            json!({"common_name":"owned-public.example.test","ttl":"10m"})
        )
        .status
            == 200,
        "actual owned leaf sign and publication"
    );
    assert!(
        call(
            &mut service,
            "POST",
            "auth/token/revoke",
            &admin,
            json!({"token":token})
        )
        .status
            == 204,
        "original owner revocation commits through normal admission"
    );
    let generation_before = service
        .external_effect_generation()
        .map_err(|_| "generation")?;
    let provider_entries = remote.calls()?;
    let observed = call(&mut service, "GET", "external-ca/crl", "", json!({}));
    assert!(
        observed.status == 503 && observed.body.get("data").is_none(),
        "owner revocation is reconciled before anonymous disclosure"
    );
    let generation = service
        .external_effect_generation()
        .map_err(|_| "generation")?;
    assert!(
        generation != generation_before,
        "owner revocation safety maintenance is durably committed"
    );
    let ram_after_maintenance = full_ram_state_identity(&service)?;
    for path in [
        "external-ca/cert/crl",
        "external-ca/crl",
        "external-ca/crl/delta",
    ] {
        let read = call(&mut service, "GET", path, "", json!({}));
        assert!(
            read.status == 503 && read.body.get("data").is_none(),
            "anonymous reads cannot serve stale owner-revoked CRLs"
        );
    }
    assert!(
        full_ram_state_identity(&service)? == ram_after_maintenance,
        "repeated reads at the same floor need no further reconciliation"
    );
    assert!(
        service
            .external_effect_generation()
            .map_err(|_| "generation")?
            == generation,
        "already reconciled public reads do not publish further maintenance"
    );
    assert!(
        remote.calls()? == provider_entries,
        "anonymous cache rejection never signs or retries"
    );
    Ok(())
}

#[test]
fn external_pki270_public_reads_keep_audit_and_seal_gates() -> TestResult {
    let remote = RemoteTransit::new_kind("ed25519")?;
    let (_root, mut service, _unseal, admin, _serial) = issued_public_fixture(&remote)?;
    assert!(
        call(&mut service, "GET", "external-ca/cert/ca", "", json!({})).status == 200,
        "live public read"
    );
    service.audit_failed = true;
    assert!(
        call(&mut service, "GET", "external-ca/cert/ca", "", json!({})).status == 503,
        "failed mandatory audit fences public disclosure"
    );
    service.audit_failed = false;
    assert!(
        call(&mut service, "POST", "sys/seal", &admin, json!({})).status == 204,
        "seal fixture"
    );
    assert!(
        call(&mut service, "GET", "external-ca/cert/ca", "", json!({})).status == 503,
        "sealed public read is unavailable"
    );
    Ok(())
}

#[test]
fn external_pki270_public_crl_expiry_survives_clock_rollback_and_encrypted_restart() -> TestResult {
    let remote = RemoteTransit::new_kind("ed25519")?;
    let (root, mut service, unseal, _admin) = leaf_fixture(&remote)?;
    let provider_entries = remote.calls()?;
    for path in ["external-ca/crl", "external-ca/crl/delta"] {
        assert!(
            service
                .handle_at("GET", path, "", "", json!({}), 100)
                .status
                == 200,
            "fresh owner and genuinely valid signed cache"
        );
    }
    let future = 100 + 72 * 3600 + 1;
    let before = service
        .external_effect_generation()
        .map_err(|_| "generation")?;
    assert!(
        service
            .handle_at("GET", "external-ca/crl", "", "", json!({}), future)
            .status
            == 503,
        "a genuine cache expiry is observed without prior owner revocation"
    );
    assert!(
        service
            .state
            .as_ref()
            .ok_or("clock state")?
            .engines
            .lease_clock()
            >= future
            && service
                .external_effect_generation()
                .map_err(|_| "generation")?
                != before,
        "the safety maintenance commits its monotonic floor before disclosure"
    );
    for path in [
        "external-ca/crl",
        "external-ca/crl/delta",
        "external-ca/cert/crl",
    ] {
        let rollback = service.handle_at("GET", path, "", "", json!({}), 101);
        assert!(
            rollback.status == 503 && rollback.body.get("data").is_none(),
            "observed expiry cannot be reversed by clock rollback"
        );
    }
    assert!(
        remote.calls()? == provider_entries,
        "expired cache is never re-signed"
    );
    drop(service);
    let mut reopened = root.service()?;
    reopened.install_outbound_endpoints(vec![remote.endpoint()])?;
    assert!(
        reopened
            .handle_at("POST", "sys/unseal", "", "", json!({"key":unseal}), 101)
            .status
            == 200,
        "the monotonic floor survives the encrypted owner restart"
    );
    for path in [
        "external-ca/crl",
        "external-ca/crl/delta",
        "external-ca/cert/crl",
    ] {
        let response = reopened.handle_at("GET", path, "", "", json!({}), 101);
        assert!(
            response.status == 503 && response.body.get("data").is_none(),
            "restart plus clock rollback cannot resurrect observed-expired cache"
        );
    }
    assert!(
        remote.calls()? == provider_entries,
        "restart never enters remote signing"
    );
    Ok(())
}

#[test]
fn external_pki270_public_issuer_and_certificate_shapes_bind_original_public_material() -> TestResult
{
    let remote = RemoteTransit::new_kind("ed25519")?;
    let (_root, mut service, _unseal, admin, serial) = issued_public_fixture(&remote)?;
    let before = remote.calls()?;
    let signs_before = provider_sign_entries(&remote)?;
    let ca = call(&mut service, "GET", "external-ca/cert/ca", "", json!({}));
    let certificate = ca.body["data"]["certificate"].as_str().ok_or("public CA")?;
    let ca_der = decode_pem(certificate)?;
    let canonical_certificate = format!("{certificate}\n");
    let issuer = call(
        &mut service,
        "GET",
        "external-ca/issuer/default/json",
        "",
        json!({}),
    );
    let id = issuer.body["data"]["issuer_id"]
        .as_str()
        .ok_or("public issuer identifier")?;
    assert!(
        issuer.body["data"]["ca_chain"]
            .as_array()
            .is_some_and(|chain| chain.len() == 1 && chain[0] == canonical_certificate),
        "default issuer chain is a one-certificate array"
    );
    assert!(
        issuer.body["data"]["issuer_name"] == "",
        "default issuer metadata retains the actual stored empty name"
    );
    let chain = call(
        &mut service,
        "GET",
        "external-ca/cert/ca_chain",
        "",
        json!({}),
    );
    assert!(
        chain.body["data"]["ca_chain"] == certificate
            && chain.body["data"]["certificate"] == certificate,
        "cert/ca_chain has the exact String contract"
    );
    let list = call(&mut service, "LIST", "external-ca/issuers", "", json!({}));
    let info = &list.body["data"]["key_info"][id];
    assert!(
        list.body["data"]["keys"] == json!([id])
            && info["is_default"] == true
            && info["issuer_name"] == "",
        "issuer enumeration is bound to the original root metadata"
    );
    let fields = info
        .as_object()
        .ok_or("public issuer info")?
        .keys()
        .map(String::as_str)
        .collect::<Vec<_>>();
    assert!(
        fields == ["is_default", "issuer_name", "key_id", "serial_number"],
        "issuer info fields match the pinned public contract"
    );
    assert!(
        info["key_id"]
            .as_str()
            .is_some_and(|value| !value.is_empty()),
        "public key identifier remains bound and nonempty"
    );
    let leaf = call(
        &mut service,
        "GET",
        &format!("external-ca/cert/{serial}"),
        "",
        json!({}),
    );
    assert!(
        leaf.body["data"]
            .as_object()
            .ok_or("public certificate shape")?
            .keys()
            .map(String::as_str)
            .collect::<Vec<_>>()
            == ["certificate", "revocation_time", "revocation_time_rfc3339"]
            && leaf.body["data"]["revocation_time"] == 0
            && leaf.body["data"]["revocation_time_rfc3339"] == "",
        "native certificate shape retains actual signed bytes and unrevoked state"
    );
    for (path, expected) in [
        ("external-ca/ca".to_owned(), ca_der),
        (
            format!("external-ca/cert/{serial}/raw"),
            decode_pem(
                leaf.body["data"]["certificate"]
                    .as_str()
                    .ok_or("public leaf")?,
            )?,
        ),
    ] {
        let raw = call(&mut service, "GET", &path, "", json!({}));
        let decoded = BASE64.decode(
            raw.body["__heptabao_pki_certificate"]
                .as_str()
                .ok_or("public raw envelope")?,
        )?;
        assert!(
            decoded == expected && raw.body["format"] == "der",
            "raw certificate bytes bind the same original public certificate"
        );
    }
    for (path, expected, format) in [
        ("external-ca/ca/pem".to_owned(), certificate, "pem"),
        (
            format!("external-ca/cert/{serial}/raw/pem"),
            leaf.body["data"]["certificate"]
                .as_str()
                .ok_or("public leaf PEM")?,
            "pem",
        ),
        ("external-ca/ca_chain".to_owned(), certificate, "chain"),
    ] {
        let raw = call(&mut service, "GET", &path, "", json!({}));
        let decoded = BASE64.decode(
            raw.body["__heptabao_pki_certificate"]
                .as_str()
                .ok_or("public PEM envelope")?,
        )?;
        assert!(
            decoded == expected.as_bytes() && raw.body["format"] == format,
            "raw PEM binds the exact pinned trailing LF contract for its endpoint"
        );
    }
    let revoked = call(
        &mut service,
        "POST",
        "external-ca/revoke",
        &admin,
        json!({"serial_number":serial}),
    );
    assert!(
        revoked.status == 200,
        "actual grant-authorized leaf revocation"
    );
    let revoked_entries = remote.calls()?;
    assert!(
        revoked_entries == before + 3 && provider_sign_entries(&remote)? == signs_before + 2,
        "revoke binds one public descriptor and exactly full and delta provider signatures"
    );
    let read = call(
        &mut service,
        "GET",
        &format!("external-ca/cert/{serial}"),
        "",
        json!({}),
    );
    assert!(
        read.body["data"]["revocation_time"] == 100
            && read.body["data"]["revocation_time_rfc3339"] == "1970-01-01T00:01:40Z",
        "revocation RFC3339 and seconds are exact projections of the original observation"
    );
    let delta = call(
        &mut service,
        "GET",
        "external-ca/cert/delta-crl",
        "",
        json!({}),
    );
    assert!(
        delta.status == 200
            && delta.body["data"]["revocation_time"] == 0
            && delta.body["data"]["revocation_time_rfc3339"] == "",
        "delta JSON is a public signed cache projection"
    );
    for (json_path, raw_path) in [
        ("external-ca/cert/crl", "external-ca/crl/pem"),
        ("external-ca/cert/delta-crl", "external-ca/crl/delta/pem"),
    ] {
        let read = call(&mut service, "GET", json_path, "", json!({}));
        let stored = read.body["data"]["certificate"]
            .as_str()
            .ok_or("public CRL PEM")?;
        assert!(
            read.status == 200 && !stored.ends_with('\n'),
            "public CRL JSON has the exact pinned final LF contract"
        );
        let raw = call(&mut service, "GET", raw_path, "", json!({}));
        let encoded = BASE64.decode(
            raw.body["__heptabao_pki_crl"]
                .as_str()
                .ok_or("public raw CRL")?,
        )?;
        assert!(
            raw.status == 200 && encoded == stored.as_bytes() && raw.body["pem"] == true,
            "raw CRL binds the exact same public signed PEM bytes"
        );
    }
    assert!(
        remote.calls()? == revoked_entries,
        "public shape and alias reads enter no additional external provider operation"
    );
    Ok(())
}

#[test]
fn external_pki270_public_clock_maintenance_keeps_irreversible_schema66_and_real_crypto()
-> TestResult {
    let remote = RemoteTransit::new_kind("ed25519")?;
    let (root, mut service, unseal, admin) = leaf_fixture(&remote)?;
    assert!(
        call(
            &mut service,
            "POST",
            "sys/mounts/safe",
            &admin,
            json!({"type":"transit"})
        )
        .status
            == 204,
        "safe Transit fixture mount"
    );
    assert!(
        call(
            &mut service,
            "POST",
            "safe/keys/key",
            &admin,
            json!({"derived":true,"convergent_encryption":true,"heptabao_convergent_version":1})
        )
        .status
            == 200,
        "actual AAD-bound convergent material activates the irreversible reader fence"
    );
    let body = json!({"plaintext":BASE64.encode(b"public-maintenance-schema66-readback"),
        "context":BASE64.encode(b"public-schema-owner"),"associated_data":BASE64.encode(b"public-schema-aad")});
    let encrypted = call(
        &mut service,
        "POST",
        "safe/encrypt/key",
        &admin,
        body.clone(),
    );
    assert!(
        encrypted.status == 200,
        "actual protected Transit encryption"
    );
    let cipher = encrypted.body["data"]["ciphertext"]
        .as_str()
        .ok_or("protected ciphertext")?
        .to_owned();
    assert!(
        service.state.as_ref().ok_or("state")?.schema == PKI_ROLE_LEAF_PROFILE_STATE_SCHEMA,
        "real AAD material and existing new role require88 before maintenance"
    );
    let provider_entries = remote.calls()?;
    assert!(
        service
            .handle_at("GET", "external-ca/crl", "", "", json!({}), 101)
            .status
            == 200,
        "fresh public cache advances existing monotonic maintenance"
    );
    assert!(
        service.state.as_ref().ok_or("state")?.schema == PKI_ROLE_LEAF_PROFILE_STATE_SCHEMA,
        "necessary public maintenance cannot downgrade the writer schema"
    );
    let expired = service.handle_at(
        "GET",
        "external-ca/crl",
        "",
        "",
        json!({}),
        100 + 72 * 3600 + 1,
    );
    assert!(
        expired.status == 503,
        "observed cache expiry is unavailable"
    );
    assert!(
        service.state.as_ref().ok_or("state")?.schema == PKI_ROLE_LEAF_PROFILE_STATE_SCHEMA,
        "negative expiry publication retains the role88 floor"
    );
    drop(service);
    let mut reopened = root.service()?;
    reopened.install_outbound_endpoints(vec![remote.endpoint()])?;
    assert!(
        reopened
            .handle_at("POST", "sys/unseal", "", "", json!({"key":unseal}), 102)
            .status
            == 200,
        "new reader authenticates the actual persisted safe store after rollback"
    );
    assert!(
        reopened.state.as_ref().ok_or("state")?.schema == PKI_ROLE_LEAF_PROFILE_STATE_SCHEMA,
        "encrypted restart retains the actual role88 floor"
    );
    assert!(
        reopened
            .handle_at("GET", "external-ca/crl", "", "", json!({}), 102)
            .status
            == 503,
        "encrypted restart plus rollback cannot resurrect observed-expired cache"
    );
    let readback = call(
        &mut reopened,
        "POST",
        "safe/decrypt/key",
        &admin,
        json!({"ciphertext":cipher,"context":body["context"],"associated_data":body["associated_data"]}),
    );
    assert!(
        readback.status == 200 && readback.body["data"]["plaintext"] == body["plaintext"],
        "persisted safe material performs real cryptographic readback without a downgrade"
    );
    assert!(
        remote.calls()? == provider_entries,
        "public clock safety never enters remote Sign"
    );
    Ok(())
}

#[test]
fn external_pki270_standard_root_delete_warning_public_leaf_and_empty_crl_are_native() -> TestResult
{
    let remote = RemoteTransit::new_kind("ed25519")?;
    let (_root, mut service, _unseal, admin, serial) = issued_public_fixture(&remote)?;
    let old = call(
        &mut service,
        "GET",
        &format!("external-ca/cert/{serial}"),
        "",
        json!({}),
    );
    assert!(old.status == 200, "actual signed predecessor leaf");
    let before = remote.calls()?;
    let deleted = call(
        &mut service,
        "DELETE",
        "external-ca/root",
        &admin,
        json!({}),
    );
    assert!(
        deleted.status == 200
            && deleted.body["warnings"]
                == json!([
                    "DELETE /root deletes all keys and issuers; prefer the new DELETE /key/:key_ref and DELETE /issuer/:issuer_ref for finer granularity, unless removal of all keys and issuers is desired."
                ]),
        "native standard root deletion warning"
    );
    let retained = call(
        &mut service,
        "GET",
        &format!("external-ca/cert/{serial}"),
        "",
        json!({}),
    );
    assert!(
        retained.status == 200 && retained.body["data"] == old.body["data"],
        "native original three-field public leaf survives actual issuer deletion"
    );
    for (path, pem) in [("external-ca/crl", false), ("external-ca/crl/pem", true)] {
        let empty = call(&mut service, "GET", path, "", json!({}));
        assert!(
            empty.status == 204 && empty.body == json!({"__heptabao_pki_crl":"","pem":pem}),
            "native deleted root raw CRL response is empty with closed transport type"
        );
    }
    assert!(
        remote.calls()? == before,
        "public retirement reads and root deletion never acquire KMS authority"
    );
    service
        .state
        .as_ref()
        .ok_or("retired root state")?
        .validate_format()
        .map_err(|_| "retired actual issuer graph")?;
    Ok(())
}
