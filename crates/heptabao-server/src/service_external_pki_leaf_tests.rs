use super::*;

#[test]
fn external_pki270_delayed_committed_leaf_never_delivers_expired_private_and_updates_remaining_ttl()
-> TestResult {
    for outcome in 0..3 {
        let expired = outcome == 0;
        let deadline = outcome == 2;
        let remote = RemoteTransit::new_kind("ed25519")?;
        let (root, mut service, unseal, admin) = leaf_fixture(&remote)?;
        let clock = crate::service::external_pki::PublicationClockScope::enter(
            std::time::Duration::from_millis(if expired { 100_750 } else { 100_250 }),
            std::time::Instant::now(),
        );
        let delay = crate::service::external_pki::PublicationDelayScope::enter(
            std::time::Duration::from_millis(if expired || deadline { 400 } else { 600 }),
        );
        let deadline_scope = deadline.then(|| {
            crate::request_deadline::RequestDeadlineScope::enter(
                std::time::Instant::now() + std::time::Duration::from_millis(250),
            )
        });
        let before = remote.calls()?;
        let response = call(
            &mut service,
            "POST",
            "external-ca/issue/leaf",
            &admin,
            json!({"common_name":"leaf.example.test","ttl":if expired {"1s"} else {"10m"}}),
        );
        drop(delay);
        drop(clock);
        drop(deadline_scope);
        if deadline {
            assert!(
                response.status == 503 && response.body.get("data").is_none(),
                "committed leaf private key is withheld after original request deadline"
            );
        } else if expired {
            assert!(
                response.status == 403 && response.body.get("data").is_none(),
                "already committed but now-expired leaf private key is withheld"
            );
        } else {
            assert!(
                response.status == 200 && response.body["lease_duration"] == 599,
                "remaining certificate TTL is recomputed after delayed publication"
            );
        }
        let audit = fs::read_to_string(root.path.join("audit.jsonl"))?;
        let records = audit
            .lines()
            .map(serde_json::from_str::<Value>)
            .collect::<Result<Vec<_>, _>>()?;
        let last = records.last().ok_or("delivery audit record")?;
        if expired || deadline {
            let planned = records
                .iter()
                .rev()
                .nth(1)
                .ok_or("planned response audit")?;
            assert!(
                planned["event"]["kind"] == "response"
                    && planned["event"]["status"] == 200
                    && last["event"]["kind"] == "external-pki-delivery-veto"
                    && last["event"]["status"] == if deadline { 503 } else { 403 }
                    && planned["event"]["path_digest"] == last["event"]["path_digest"],
                "audit distinguishes the committed planned success from actual delivery veto"
            );
        } else {
            assert!(
                last["event"]["kind"] == "response" && last["event"]["status"] == 200,
                "successful final delivery retains its one original response audit"
            );
        }
        assert!(
            remote.calls()? == before + 2,
            "delay never replays provider metadata or signing"
        );
        let mut committed = serde_json::to_value(service.state.as_ref().ok_or("committed state")?)?;
        let serial = committed["engines"]["namespaces"][""]["mounts"]["external-ca/"]["backend"]
            ["Pki"]["issued"]
            .as_object()
            .and_then(|issued| issued.keys().next())
            .ok_or("committed public certificate index")?
            .to_owned();
        erase_json(&mut committed);
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
            "encrypted committed certificate restart"
        );
        let read = call(
            &mut reopened,
            "GET",
            &format!("external-ca/cert/{serial}"),
            &admin,
            json!({}),
        );
        assert!(
            read.status == 200 && read.body["data"].get("private_key").is_none(),
            "committed public certificate survives while private key is never retained"
        );
        assert!(
            remote.calls()? == before + 2,
            "restart and readback never retry signing"
        );
    }
    Ok(())
}

#[test]
fn external_pki270_own_publication_checkpoint_rejects_postcommit_grant_aba() -> TestResult {
    for fail_veto_audit in [false, true] {
        let remote = RemoteTransit::new_kind("ed25519")?;
        let (_root, mut service, _unseal, admin) = leaf_fixture(&remote)?;
        let pending = match service.begin_at_mode(RequestDispatch {
            method: "POST",
            path: "external-ca/issue/leaf",
            namespace: "",
            token: &admin,
            body: json!({"common_name":"leaf.example.test","ttl":"10m"}),
            now: 100,
            allow_forward: true,
            enforce_namespace: false,
            wrap_ttl_seconds: None,
            origin_peer: None,
            client_certificates: None,
        }) {
            RequestExecution::External(pending) => *pending,
            RequestExecution::Complete(_) => return Err("leaf signing did not stage".into()),
        };
        let before = remote.calls()?;
        let result = pending.execute();
        let (mut plan, result) = match (pending.effect, result) {
            (ExternalEffectPlan::ExternalPki(plan), ExternalEffectResult::ExternalPki(result)) => {
                (plan, result)
            }
            _ => return Err("leaf observation type".into()),
        };
        let response = service.finalize_external_pki(&mut plan, result);
        assert!(
            response.status == 200,
            "real leaf is encrypted and committed before delivery checkpoint"
        );
        let checkpoint_identity = service
            .current_state_identity()
            .map_err(|_| "published identity")?;
        for (method, status) in [("DELETE", 204), ("POST", 204)] {
            assert!(
                call(
                    &mut service,
                    method,
                    "sys/external-keys/configs/remote/keys/v2/grants/external-ca",
                    &admin,
                    json!({})
                )
                .status
                    == status,
                "grant deletion and restoration after committed leaf"
            );
        }
        assert!(
            service
                .current_state_identity()
                .is_ok_and(|identity| identity == checkpoint_identity),
            "ABA restores content while durable generation advances"
        );
        let response =
            service.audit_completed_response(&pending.fingerprint, pending.now, response);
        let sequence = service.audit_sequence;
        if fail_veto_audit {
            service.audit_capacity = service.audit.metadata()?.len();
        }
        let response =
            service.complete_external_pki_delivery(&mut plan, response, &pending.fingerprint);
        assert!(
            response.status == 503 && response.body.get("data").is_none(),
            "postpublication generation ABA cannot deliver committed private response"
        );
        assert!(
            remote.calls()? == before + 2,
            "delivery fence never replays actual remote signing"
        );
        if fail_veto_audit {
            assert!(
                service.recovery_required && service.audit_sequence == sequence,
                "failed negative audit closes recovery without secret delivery or replay"
            );
        } else {
            assert!(
                !service.recovery_required && service.audit_sequence == sequence + 1,
                "one negative delivery observation follows the planned response audit"
            );
        }
    }
    Ok(())
}

#[test]
fn external_pki270_real_leaf_reports_remaining_validity_at_original_subsecond_clock() -> TestResult
{
    let remote = RemoteTransit::new_kind("ed25519")?;
    let (_root, mut service, _unseal, admin) = leaf_fixture(&remote)?;
    let _scope = crate::service::external_pki::PublicationClockScope::enter(
        std::time::Duration::from_millis(100_750),
        std::time::Instant::now(),
    );
    let leaf = call(
        &mut service,
        "POST",
        "external-ca/issue/leaf",
        &admin,
        json!({"common_name":"leaf.example.test","ttl":"10m"}),
    );
    assert!(
        leaf.status == 200,
        "actual remote-signed leaf under original fractional clock"
    );
    assert!(
        leaf.body["lease_duration"] == 599,
        "remaining validity uses nearest whole second"
    );
    assert!(
        leaf.body["data"]["expiration"] == 700,
        "requested certificate validity is unchanged"
    );
    Ok(())
}

#[test]
fn external_pki270_owner_revocation_withholds_stale_crl_until_explicit_real_rebuild() -> TestResult
{
    let remote = RemoteTransit::new_kind("ed25519")?;
    let (_root, mut service, _unseal, admin) = leaf_fixture(&remote)?;
    let _last_use = limited_token(
        &mut service,
        &admin,
        "path \"external-ca/issue/leaf\" { capabilities = [\"update\"] }",
    )?;
    let created = call(
        &mut service,
        "POST",
        "auth/token/create",
        &admin,
        json!({"policies":["scoped"],"no_default_policy":true}),
    );
    assert!(created.status == 200, "live leaf owner fixture");
    let token = created.body["auth"]["client_token"]
        .as_str()
        .ok_or("owner token")?
        .to_owned();
    let leaf = call(
        &mut service,
        "POST",
        "external-ca/issue/leaf",
        &token,
        json!({"common_name":"leaf.example.test","ttl":"10m"}),
    );
    assert!(leaf.status == 200, "real owned leaf publication");
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
        "original owner revocation"
    );
    let before = remote.calls()?;
    for path in [
        "external-ca/crl",
        "external-ca/crl/delta",
        "external-ca/cert/crl",
    ] {
        assert!(
            call(&mut service, "GET", path, &admin, json!({})).status == 503,
            "missing owner revocation cannot be served from signed cache"
        );
    }
    assert!(
        remote.calls()? == before,
        "public reads never sign or retry"
    );
    assert!(
        call(
            &mut service,
            "GET",
            "external-ca/crl/rotate",
            &admin,
            json!({})
        )
        .status
            == 200,
        "explicit current-grant rebuild publishes complete signatures"
    );
    assert!(
        remote.calls()? == before + 3,
        "one metadata read and two real CRL signatures"
    );
    let descriptor = call(
        &mut *remote.service.lock().map_err(|_| "remote lock")?,
        "GET",
        "transit/keys/remote",
        &remote.admin,
        json!({}),
    );
    let public = BASE64.decode(
        descriptor.body["data"]["keys"]["2"]["public_key"]
            .as_str()
            .ok_or("remote public")?,
    )?;
    verify_crl(
        &public,
        &crl_bytes(&mut service, &admin, false)?,
        3,
        1,
        false,
    )?;
    verify_crl(&public, &crl_bytes(&mut service, &admin, true)?, 4, 0, true)?;
    Ok(())
}

#[test]
fn external_pki270_reader_rejects_crl_signature_and_leaf_public_projection_tampering() -> TestResult
{
    let remote = RemoteTransit::new_kind("ed25519")?;
    let (_root, mut service, _unseal, admin) = leaf_fixture(&remote)?;
    let leaf = call(
        &mut service,
        "POST",
        "external-ca/issue/leaf",
        &admin,
        json!({"common_name":"leaf.example.test","ttl":"10m"}),
    );
    assert!(leaf.status == 200, "actual leaf before reader checks");
    let original = serde_json::to_value(service.state.as_ref().ok_or("state")?)?;
    for mutation in ["crl-signature", "leaf-public", "private-injection"] {
        let mut changed = original.clone();
        let external = &mut changed["engines"]["namespaces"][""]["mounts"]["external-ca/"]["backend"]
            ["Pki"]["external"];
        if mutation == "crl-signature" {
            let bytes = external["crls"]["full"]["der"]
                .as_array_mut()
                .ok_or("CRL state")?;
            let last = bytes.last_mut().ok_or("CRL state signature")?;
            *last = json!(last.as_u64().ok_or("CRL signature byte")? ^ 1);
        } else if mutation == "leaf-public" {
            let projection = external["issued_public"]
                .as_object_mut()
                .ok_or("leaf projection")?
                .values_mut()
                .next()
                .ok_or("leaf public")?;
            let byte = &mut projection["public_key"][0];
            *byte = json!(byte.as_u64().ok_or("leaf public byte")? ^ 1);
        } else {
            external["crls"]["private_key"] = json!("synthetic-forbidden-material");
        }
        let rejected = match serde_json::from_value::<State>(changed) {
            Ok(state) => state.validate_format().is_err(),
            Err(_) => true,
        };
        assert!(
            rejected,
            "reader rejects forged public authority and private material"
        );
    }
    Ok(())
}

#[test]
fn external_pki270_partial_root_and_revoke_signing_effects_never_publish_synthetic_crl()
-> TestResult {
    let remote = RemoteTransit::new_kind("ed25519")?;
    let (_root, mut service, _unseal, admin) = pki_fixture(&remote)?;
    let before = remote.calls()?;
    remote.ack_at_call.store(before + 3, Ordering::SeqCst);
    let result = call(
        &mut service,
        "POST",
        "external-ca/root/generate/kms",
        &admin,
        body(),
    );
    assert!(
        result.status == 503 && result.body.get("data").is_none(),
        "genuine root signature plus synthetic CRL cannot publish"
    );
    assert!(
        remote.calls()? == before + 3,
        "first invalid CRL stops effects without retry"
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
        "partial external root is absent"
    );
    remote.ack_at_call.store(0, Ordering::SeqCst);
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
        "new explicit root request has complete crypto"
    );
    assert!(call(&mut service,"POST","external-ca/roles/leaf",&admin,json!({"allowed_domains":["example.test"],"allow_subdomains":true,"max_ttl":"1h","generate_lease":true})).status==200,"leaf role");
    let leaf = call(
        &mut service,
        "POST",
        "external-ca/issue/leaf",
        &admin,
        json!({"common_name":"leaf.example.test","ttl":"10m"}),
    );
    assert!(leaf.status == 200, "real leaf before failed revoke");
    let serial = leaf.body["data"]["serial_number"]
        .as_str()
        .ok_or("leaf serial")?;
    let full = crl_bytes(&mut service, &admin, false)?;
    let delta = crl_bytes(&mut service, &admin, true)?;
    let before = remote.calls()?;
    remote.ack_at_call.store(before + 3, Ordering::SeqCst);
    let result = call(
        &mut service,
        "POST",
        "external-ca/revoke",
        &admin,
        json!({"serial_number":serial}),
    );
    assert!(
        result.status == 503 && result.body.get("data").is_none(),
        "full CRL plus invalid delta withholds revoke publication"
    );
    assert!(
        remote.calls()? == before + 3,
        "failed second CRL effect never retries"
    );
    let read = call(
        &mut service,
        "GET",
        &format!("external-ca/cert/{serial}"),
        &admin,
        json!({}),
    );
    assert!(
        read.body["data"]["revocation_time"] == 0,
        "failed revoke preserves original certificate authority"
    );
    assert!(
        crl_bytes(&mut service, &admin, false)? == full
            && crl_bytes(&mut service, &admin, true)? == delta,
        "failed revoke preserves both signed caches"
    );
    Ok(())
}

#[test]
fn external_pki270_leaf_owner_and_each_consumption_grant_are_required_before_entry() -> TestResult {
    let remote = RemoteTransit::new_kind("ed25519")?;
    let (_root, mut service, _unseal, admin) = leaf_fixture(&remote)?;
    let token = limited_token(
        &mut service,
        &admin,
        "path \"external-ca/issue/leaf\" { capabilities = [\"update\"] }",
    )?;
    let before = remote.calls()?;
    let rejected = call(
        &mut service,
        "POST",
        "external-ca/issue/leaf",
        &token,
        json!({"common_name":"leaf.example.test","ttl":"10m"}),
    );
    assert!(
        rejected.status == 403 && rejected.body.get("data").is_none(),
        "retired final-use token cannot own a durable leaf lease"
    );
    assert!(
        remote.calls()? == before,
        "invalid lease owner never enters provider"
    );
    assert!(
        call(
            &mut service,
            "DELETE",
            "sys/external-keys/configs/remote/keys/v2/grants/external-ca",
            &admin,
            json!({})
        )
        .status
            == 204,
        "consumer grant removal"
    );
    let before = remote.calls()?;
    for (method, path, body) in [
        (
            "POST",
            "external-ca/issue/leaf",
            json!({"common_name":"leaf.example.test","ttl":"10m"}),
        ),
        ("GET", "external-ca/crl/rotate", json!({})),
    ] {
        let result = call(&mut service, method, path, &admin, body);
        assert!(
            result.status == 500 && result.body.get("data").is_none(),
            "every signing consumer requires a current mount grant"
        );
    }
    assert!(
        remote.calls()? == before,
        "missing consumer grant performs no metadata or sign"
    );
    Ok(())
}

#[test]
fn external_pki270_ed_response_pem_matches_issue_read_and_encrypted_restart() -> TestResult {
    use openssl::{pkey::PKey, x509::X509};
    let remote = RemoteTransit::new_kind("ed25519")?;
    let (root, mut service, unseal, admin) = pki_fixture(&remote)?;
    let generated = call(
        &mut service,
        "POST",
        "external-ca/root/generate/kms",
        &admin,
        body(),
    );
    assert!(
        generated.status == 200,
        "actual Ed provider root publication"
    );
    let root_pem = generated.body["data"]["certificate"]
        .as_str()
        .ok_or("root response")?;
    let root_cert = X509::from_pem(root_pem.as_bytes())?;
    let canonical_root = root_cert.to_pem()?;
    assert!(
        root_pem.as_bytes()
            == canonical_root
                .strip_suffix(b"\n")
                .ok_or("canonical root LF")?
            && generated.body["data"]["issuing_ca"].as_str() == Some(root_pem),
        "Ed root bundle omits exactly its canonical final LF"
    );
    assert!(call(&mut service,"POST","external-ca/roles/leaf",&admin,
        json!({"allowed_domains":["example.test"],"allow_subdomains":true,"max_ttl":"30m","generate_lease":true,"key_type":"ed25519"})).status == 200,
        "actual leaf role");
    let issued = call(
        &mut service,
        "POST",
        "external-ca/issue/leaf",
        &admin,
        json!({"common_name":"leaf.example.test","ttl":"10m"}),
    );
    assert!(issued.status == 200, "actual Ed remote-signed leaf");
    let data = &issued.body["data"];
    let leaf_pem = data["certificate"].as_str().ok_or("leaf response")?;
    let leaf_cert = X509::from_pem(leaf_pem.as_bytes())?;
    let private_pem = data["private_key"].as_str().ok_or("private response")?;
    let private = PKey::private_key_from_pem(private_pem.as_bytes())?;
    let root_public = root_cert.public_key()?;
    let canonical_leaf = leaf_cert.to_pem()?;
    let canonical_private = zeroize::Zeroizing::new(private.private_key_to_pem_pkcs8()?);
    assert!(
        leaf_pem.as_bytes()
            == canonical_leaf
                .strip_suffix(b"\n")
                .ok_or("canonical leaf LF")?
            && private_pem.as_bytes()
                == canonical_private
                    .strip_suffix(b"\n")
                    .ok_or("canonical private LF")?
            && data["issuing_ca"].as_str() == Some(root_pem)
            && data["ca_chain"]
                .as_array()
                .is_some_and(|chain| chain.len() == 1 && chain[0].as_str() == Some(root_pem))
            && leaf_cert.public_key()?.public_key_to_der()? == private.public_key_to_der()?
            && leaf_cert.verify(&root_public)?,
        "Ed response representation preserves exact certificate and private-key binding"
    );
    let route = format!(
        "external-ca/cert/{}",
        data["serial_number"].as_str().ok_or("readback serial")?
    );
    let read = call(&mut service, "GET", &route, &admin, json!({}));
    assert!(
        read.status == 200
            && read.body["data"]["certificate"] == data["certificate"]
            && read.body["data"].get("private_key").is_none(),
        "Ed public read equals its exact issued PEM"
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
        "Ed encrypted restart"
    );
    let read = call(&mut reopened, "GET", &route, &admin, json!({}));
    assert!(
        read.status == 200
            && read.body["data"]["certificate"] == data["certificate"]
            && read.body["data"].get("private_key").is_none(),
        "Ed restart retains exact public certificate only"
    );
    Ok(())
}
