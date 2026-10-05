//! Real native HTTPS Transit service signs. No assertion prints crypto material.
use super::*;
use openssl::{
    pkey::PKey,
    x509::{X509, X509Crl},
};

#[test]
fn external_pki270_typed67_active_and_retired_snapshot_floor_and_final_commit() -> TestResult {
    let remote = RemoteTransit::new_kind("ecdsa-p256")?;
    let (_root, mut service, _unseal, admin) = pki_fixture(&remote)?;
    let old65 =
        zeroize::Zeroizing::new(service.durable.as_ref().ok_or("durable")?.export_backup()?);
    let mut state66 = service.state.clone().ok_or("state")?;
    state66.schema = AAD_BOUND_STATE_SCHEMA;
    service
        .commit_state(&mut state66)
        .map_err(|_| "fixture66 publication")?;
    service.state = Some(state66);
    let old66 =
        zeroize::Zeroizing::new(service.durable.as_ref().ok_or("durable")?.export_backup()?);
    let mut prepared = service
        .prepare_snapshot_restore(&old66)
        .map_err(|_| "prepare66 before typing")?;
    let retired_prepared = service
        .prepare_snapshot_restore(&old66)
        .map_err(|_| "prepare66 for retirement")?;
    let mut retired_prepared = Some(retired_prepared);
    assert!(
        call(
            &mut service,
            "POST",
            "external-ca/root/generate/kms",
            &admin,
            body()
        )
        .status
            == 200,
        "actual typed CA"
    );
    let state = service.state.as_mut().ok_or("state")?;
    let principal = state
        .auth
        .authenticate_from(&admin, 100, None)
        .map_err(|_| "snapshot actor")?;
    let snapshot_body = json!({});
    let request = RequestView {
        method: "POST",
        path: "sys/storage/raft/snapshot-force",
        namespace: "",
        token: &admin,
        body: &snapshot_body,
        now: 100,
        admission_started: std::time::Instant::now(),
        token_clock: None,
        allow_forward: false,
        enforce_namespace: true,
        wrap_ttl_seconds: None,
        origin_peer: None,
        client_certificates: None,
    };
    // Internal fault construction isolates the final protected-floor check:
    // even a matching activation/base cannot normalize an incoming old label.
    let identity = service
        .current_state_identity()
        .map_err(|_| "typed identity")?;
    prepared.fixture_rebind_base_for_protected_floor(identity);
    let generation = service
        .external_effect_generation()
        .map_err(|_| "generation")?;
    let calls = remote.calls()?;
    assert!(
        service
            .commit_snapshot_restore(prepared, &principal, &request)
            .status
            == 400,
        "final force publication rejects old66"
    );
    assert!(
        service
            .current_state_identity()
            .map_err(|_| "final rejection identity")?
            == identity
            && service
                .external_effect_generation()
                .map_err(|_| "final rejection generation")?
                == generation,
        "final floor rejection publishes nothing"
    );
    for retired in [false, true] {
        if retired {
            assert!(
                call(
                    &mut service,
                    "POST",
                    "external-ca/root/delete",
                    &admin,
                    json!({})
                )
                .status
                    == 200,
                "typed retirement"
            );
            let retired_identity = service
                .current_state_identity()
                .map_err(|_| "retired identity")?;
            let retired_generation = service
                .external_effect_generation()
                .map_err(|_| "retired generation")?;
            let mut retired_plan = retired_prepared.take().ok_or("retired affine plan")?;
            retired_plan.fixture_rebind_base_for_protected_floor(retired_identity);
            assert!(
                service
                    .commit_snapshot_restore(retired_plan, &principal, &request)
                    .status
                    == 400,
                "final force gate rejects retired67 to66"
            );
            assert!(
                service
                    .current_state_identity()
                    .map_err(|_| "retired final identity")?
                    == retired_identity
                    && service
                        .external_effect_generation()
                        .map_err(|_| "retired final generation")?
                        == retired_generation,
                "retired final rejection publishes nothing"
            );
        }
        let before = service
            .current_state_identity()
            .map_err(|_| "before restore")?;
        let before_generation = service
            .external_effect_generation()
            .map_err(|_| "before generation")?;
        for backup in [&old65, &old66] {
            assert!(
                service
                    .prepare_snapshot_restore(backup)
                    .err()
                    .is_some_and(|response| response.status == 400),
                "authenticated old snapshot rejects active and retired67"
            );
            let mut reader = std::io::Cursor::new(backup.as_slice());
            assert!(
                service
                    .prepare_snapshot_restore_from_reader(&mut reader, backup.len() as u64)
                    .err()
                    .is_some_and(|response| response.status == 400),
                "native streamed prepare also rejects67 downgrade"
            );
        }
        assert!(
            service
                .current_state_identity()
                .map_err(|_| "after restore")?
                == before
                && service
                    .external_effect_generation()
                    .map_err(|_| "after generation")?
                    == before_generation,
            "snapshot rejection publishes no state"
        );
        assert!(
            service.state.as_ref().ok_or("retained")?.schema == TYPED_PKI_STATE_SCHEMA,
            "protected67 stays sticky"
        );
    }
    assert!(
        identity
            != service
                .current_state_identity()
                .map_err(|_| "retirement identity")?,
        "retirement is an explicit publication"
    );
    assert!(
        service
            .external_effect_generation()
            .map_err(|_| "retirement generation")?
            != generation,
        "retirement advances durable publication"
    );
    assert!(
        remote.calls()? == calls,
        "no provider effect on restore rejection or retirement"
    );
    Ok(())
}

#[test]
fn external_pki270_all_six_remote_keys_root_leaf_crl_encrypted_restart_and_schema67() -> TestResult
{
    for kind in [
        "ecdsa-p256",
        "ecdsa-p384",
        "ecdsa-p521",
        "rsa-2048",
        "rsa-3072",
        "rsa-4096",
    ] {
        let remote = RemoteTransit::new_kind(kind)?;
        let (root, mut service, unseal, admin) = pki_fixture(&remote)?;
        let generated = call(
            &mut service,
            "POST",
            "external-ca/root/generate/kms",
            &admin,
            body(),
        );
        assert!(generated.status == 200, "actual asymmetric root generation");
        assert!(
            remote.calls()? == 4,
            "one metadata read and exactly root/full/delta signatures"
        );
        let descriptor = call(
            &mut *remote.service.lock().map_err(|_| "remote lock")?,
            "GET",
            "transit/keys/remote",
            &remote.admin,
            json!({}),
        );
        let public = descriptor.body["data"]["keys"]["2"]["public_key"]
            .as_str()
            .ok_or("public descriptor")?;
        let public = PKey::public_key_from_pem(public.as_bytes())?;
        let cert = X509::from_pem(
            generated.body["data"]["certificate"]
                .as_str()
                .ok_or("root certificate")?
                .as_bytes(),
        )?;
        let canonical_root = cert.to_pem()?;
        let root_response = generated.body["data"]["certificate"]
            .as_str()
            .ok_or("root response PEM")?;
        assert!(
            root_response.as_bytes()
                == canonical_root
                    .strip_suffix(b"\n")
                    .ok_or("canonical root LF")?
                && generated.body["data"]["issuing_ca"].as_str() == Some(root_response),
            "external root response has the exact official PEM representation"
        );
        assert!(
            cert.verify(&public)?,
            "remote root actual signature verified"
        );
        assert!(
            cert.public_key()?.public_key_to_der()? == public.public_key_to_der()?,
            "root exact remote SPKI binding"
        );
        assert!(
            service.state.as_ref().ok_or("typed state")?.schema == TYPED_PKI_STATE_SCHEMA,
            "typed writer schema67"
        );
        let mut lower = service.state.as_ref().ok_or("typed state")?.clone();
        lower.schema = 66;
        assert!(
            lower.validate_format().is_err(),
            "typed key cannot be relabeled66"
        );
        assert!(
            lower
                .validate_publication_schema(service.state.as_ref())
                .is_err(),
            "active typed downgrade publication rejected"
        );
        assert!(call(&mut service,"POST","external-ca/roles/leaf",&admin,json!({"allowed_domains":["example.test"],"allow_subdomains":true,"max_ttl":"30m","generate_lease":true,"key_type":"ed25519"})).status==200,"leaf owner role");
        let issued = call(
            &mut service,
            "POST",
            "external-ca/issue/leaf",
            &admin,
            json!({"common_name":"leaf.example.test","ttl":"10m"}),
        );
        assert!(
            issued.status == 200,
            "actual asymmetric CA leaf consumption"
        );
        let data = &issued.body["data"];
        let leaf = X509::from_pem(
            data["certificate"]
                .as_str()
                .ok_or("leaf certificate")?
                .as_bytes(),
        )?;
        let private = PKey::private_key_from_pem(
            data["private_key"]
                .as_str()
                .ok_or("owned leaf private output")?
                .as_bytes(),
        )?;
        assert!(
            leaf.verify(&public)?,
            "remote leaf actual signature verified"
        );
        assert!(
            leaf.public_key()?.public_key_to_der()? == private.public_key_to_der()?,
            "returned standard private key bound to leaf"
        );
        let canonical_leaf = leaf.to_pem()?;
        let canonical_private = zeroize::Zeroizing::new(private.private_key_to_pem_pkcs8()?);
        assert!(
            data["certificate"]
                .as_str()
                .ok_or("leaf response PEM")?
                .as_bytes()
                == canonical_leaf
                    .strip_suffix(b"\n")
                    .ok_or("canonical leaf LF")?
                && data["private_key"]
                    .as_str()
                    .ok_or("private response PEM")?
                    .as_bytes()
                    == canonical_private
                        .strip_suffix(b"\n")
                        .ok_or("canonical private LF")?
                && data["issuing_ca"].as_str() == Some(root_response)
                && data["ca_chain"].as_array().is_some_and(
                    |chain| chain.len() == 1 && chain[0].as_str() == Some(root_response)
                ),
            "all six external algorithms retain exact response PEM and original private binding"
        );
        let read = call(
            &mut service,
            "GET",
            &format!(
                "external-ca/cert/{}",
                data["serial_number"].as_str().ok_or("readback serial")?
            ),
            &admin,
            json!({}),
        );
        assert!(
            read.status == 200
                && read.body["data"]["certificate"] == data["certificate"]
                && read.body["data"].get("private_key").is_none(),
            "issued certificate equals its public stored response without a private key"
        );
        let serial = data["serial_number"]
            .as_str()
            .ok_or("owned serial")?
            .to_owned();
        assert!(
            call(
                &mut service,
                "POST",
                "external-ca/revoke",
                &admin,
                json!({"serial_number":serial})
            )
            .status
                == 200,
            "real full/delta revoke publication"
        );
        let full = crl_bytes(&mut service, &admin, false)?;
        let delta = crl_bytes(&mut service, &admin, true)?;
        for bytes in [&full, &delta] {
            assert!(
                X509Crl::from_der(bytes)?.verify(&public)?,
                "actual maintained remote CRL verification"
            );
        }
        let retained = service.state.as_ref().ok_or("typed retained state")?;
        assert!(
            retained.schema == PKI_ROLE_NAMES_STATE_SCHEMA
                && retained.engines.has_typed_external_pki_state()
                && retained.engines.has_pki_role_bare_domain_state()
                && retained.validate_format().is_ok(),
            "real typed key and new name role validate together at93"
        );
        let encoded = zeroize::Zeroizing::new(serde_json::to_vec(retained)?);
        assert!(
            !encoded
                .windows(data["private_key"].as_str().ok_or("private output")?.len())
                .any(|window| window == data["private_key"].as_str().unwrap_or("").as_bytes()),
            "private leaf output absent from durable state"
        );
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
            "typed encrypted restart"
        );
        assert!(
            reopened
                .state
                .as_ref()
                .ok_or("typed reopened state")?
                .schema
                == PKI_ROLE_NAMES_STATE_SCHEMA,
            "typed key and new role retain88 on encrypted restart"
        );
        let read = call(
            &mut reopened,
            "GET",
            &format!("external-ca/cert/{serial}"),
            &admin,
            json!({}),
        );
        assert!(
            read.status == 200
                && read.body["data"]["certificate"] == data["certificate"]
                && read.body["data"].get("private_key").is_none(),
            "all six encrypted restarts retain the exact issued public certificate"
        );
        assert!(
            crl_bytes(&mut reopened, &admin, false)? == full
                && crl_bytes(&mut reopened, &admin, true)? == delta,
            "typed CRL cache restart identity"
        );
        assert!(
            call(
                &mut reopened,
                "POST",
                "external-ca/root/delete",
                &admin,
                json!({})
            )
            .status
                == 200,
            "explicit typed retirement"
        );
        let retired = reopened.state.as_ref().ok_or("retired typed state")?;
        assert!(
            !retired.engines.has_typed_external_pki_state()
                && retired.engines.has_pki_role_bare_domain_state()
                && retired.schema == PKI_ROLE_NAMES_STATE_SCHEMA
                && retired.writer_schema() == PKI_ROLE_NAMES_STATE_SCHEMA,
            "retired typed key retains the real role and sticky88"
        );
        let mut lowered = retired.clone();
        lowered.schema = 66;
        assert!(
            lowered.validate_publication_schema(Some(retired)).is_err(),
            "retired67 to66 universally rejected"
        );
        lowered.schema = 65;
        assert!(
            lowered.validate_publication_schema(Some(retired)).is_err(),
            "retired67 to65 universally rejected"
        );
        let mut unsupported = retired.clone();
        unsupported.schema = MAX_SUPPORTED_STATE_SCHEMA + 1;
        assert!(
            unsupported.writer_schema() == MAX_SUPPORTED_STATE_SCHEMA + 1
                && unsupported.validate_format().is_err(),
            "unknown writer schema preserved and rejected"
        );
        drop(reopened);
        let mut retired_reopen = root.service()?;
        assert!(
            call(
                &mut retired_reopen,
                "POST",
                "sys/unseal",
                "",
                json!({"key":unseal})
            )
            .status
                == 200,
            "retired typed encrypted restart"
        );
        assert!(
            retired_reopen
                .state
                .as_ref()
                .ok_or("retired reopen")?
                .schema
                == PKI_ROLE_NAMES_STATE_SCHEMA,
            "retirement cannot lower writer format on restart"
        );
    }
    Ok(())
}

#[test]
fn external_pki270_asymmetric_real_signed_result_grant_aba_and_ack_only_fail_closed() -> TestResult
{
    let remote = RemoteTransit::new_kind("ecdsa-p384")?;
    let (_root, mut service, _unseal, admin) = pki_fixture(&remote)?;
    let pending = pki_staged(&mut service, &admin, "external-ca/root/generate/kms")?;
    let result = pending.execute();
    assert!(
        matches!(&result, ExternalEffectResult::ExternalPki(Ok(_))),
        "three actual remote signatures completed before ABA"
    );
    let count = remote.calls()?;
    let grant = "sys/external-keys/configs/remote/keys/v2/grants/external-ca";
    assert!(
        call(&mut service, "DELETE", grant, &admin, json!({})).status == 204,
        "original grant deleted"
    );
    assert!(
        call(&mut service, "POST", grant, &admin, json!({})).status == 204,
        "identical grant restored"
    );
    let response = service.finish_external_request(pending, result);
    assert!(
        response.status == 503 && response.body.get("data").is_none(),
        "original generation withholds completed asymmetric result"
    );
    assert!(
        remote.calls()? == count,
        "fenced asymmetric result never replays provider"
    );
    assert!(
        call(
            &mut service,
            "GET",
            "external-ca/cert/ca",
            &admin,
            json!({})
        )
        .status
            == 404,
        "fenced root was not published"
    );
    remote.ack_only.store(true, Ordering::SeqCst);
    let response = call(
        &mut service,
        "POST",
        "external-ca/root/generate/kms",
        &admin,
        body(),
    );
    assert!(
        response.status == 503 && response.body.get("data").is_none(),
        "synthetic acknowledgement cannot be asymmetric crypto success"
    );
    Ok(())
}
