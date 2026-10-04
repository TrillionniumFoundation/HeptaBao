//! Issuer selection never replaces the original ACL, audit or durable lease path.
//! Real provider operations and maintained key parsers supply the crypto evidence.
use super::*;
use openssl::{pkey::PKey, x509::X509};

fn issuer_issue_fixture(
    remote: &RemoteTransit,
) -> TestResult<(Root, Service, String, String, String)> {
    issuer_issue_fixture_with_role(remote, false)
}

fn issuer_issue_historical_role_fixture(
    remote: &RemoteTransit,
) -> TestResult<(Root, Service, String, String, String)> {
    issuer_issue_fixture_with_role(remote, true)
}

fn issuer_issue_fixture_with_role(
    remote: &RemoteTransit,
    historical_role: bool,
) -> TestResult<(Root, Service, String, String, String)> {
    let (root, mut service, unseal, admin) = pki_fixture(remote)?;
    let mut named = body();
    named["issuer_name"] = json!("primary");
    let generated = call(
        &mut service,
        "POST",
        "external-ca/root/generate/kms",
        &admin,
        named,
    );
    assert!(generated.status == 200, "real named external issuer");
    let id = generated.body["data"]["issuer_id"]
        .as_str()
        .ok_or("issuer identifier")?
        .to_owned();
    let prior = service.state.as_ref().ok_or("actual pre-role named root")?;
    assert!(
        prior.schema
            == if prior.engines.has_typed_external_pki_state() {
                67
            } else {
                65
            }
            && !prior.engines.has_pki_role_bare_domain_state(),
        "actual old root floor before role"
    );
    if historical_role {
        // Authenticated typed predecessor fixture; no claim of an old binary.
        // Publish it before any new-role84 commit, without lowering a protected store.
        let mut encoded = serde_json::to_value(prior)?;
        encoded["engines"]["namespaces"][""]["mounts"]["external-ca/"]["backend"]["Pki"]["roles"]
            ["leaf"] = json!({
            "allowed_domains":["example.test"],"allow_subdomains":true,
            "allow_ip_sans":false,"max_ttl":1800,"generate_lease":true
        });
        let predecessor: State = serde_json::from_value(encoded)?;
        assert!(
            predecessor.schema == prior.schema
                && predecessor.writer_schema() == prior.schema
                && !predecessor.engines.has_pki_role_bare_domain_state()
                && !predecessor.engines.has_pki_role_any_name_state()
                && predecessor.validate_format().is_ok(),
            "genuine historical None role is readable at the original root floor"
        );
        service
            .commit_state(&predecessor)
            .map_err(|_| "typed historical role fixture publication")?;
        service.state = Some(predecessor);
        return Ok((root, service, unseal, admin, id));
    }
    assert!(
        call(
            &mut service,
            "POST",
            "external-ca/roles/leaf",
            &admin,
            json!({"allowed_domains":["example.test"],"allow_subdomains":true,
            "max_ttl":"30m","generate_lease":true,"key_type":"ed25519"})
        )
        .status
            == 200,
        "original bounded leaf role"
    );
    let published = service.state.as_ref().ok_or("actual new named role")?;
    assert!(
        published.schema == PKI_ROLE_BARE_DOMAIN_STATE_SCHEMA
            && published.engines.has_pki_role_bare_domain_state(),
        "actual API role carries its84 owner"
    );
    Ok((root, service, unseal, admin, id))
}

fn issue_body() -> Value {
    json!({"common_name":"leaf.example.test","ttl":"10m"})
}

fn issue_signs(remote: &RemoteTransit) -> TestResult<usize> {
    Ok(remote
        .trace
        .lock()
        .map_err(|_| "provider trace")?
        .iter()
        .filter(|path| path.as_str() == "/v1/transit/sign/remote")
        .count())
}

fn staged_issue(
    service: &mut Service,
    token: &str,
    path: &str,
) -> TestResult<PendingExternalRequest> {
    match service.begin_at_mode(RequestDispatch {
        method: "POST",
        path,
        namespace: "",
        token,
        body: issue_body(),
        now: 100,
        allow_forward: true,
        enforce_namespace: false,
        wrap_ttl_seconds: None,
        origin_peer: None,
        client_certificates: None,
    }) {
        RequestExecution::External(pending) => Ok(*pending),
        RequestExecution::Complete(_) => Err("issuer-path leaf did not stage".into()),
    }
}

#[test]
fn external_pki270_issuer_issue_seven_real_kinds_original_paths_private_binding_and_restart()
-> TestResult {
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
        let (root, mut service, unseal, admin, id) = issuer_issue_fixture(&remote)?;
        assert!(
            issue_signs(&remote)? == 3,
            "root includes real full and delta CRL signatures"
        );
        let ca = call(&mut service, "GET", "external-ca/cert/ca", "", json!({}));
        let ca = X509::from_pem(
            ca.body["data"]["certificate"]
                .as_str()
                .ok_or("CA certificate")?
                .as_bytes(),
        )?;
        let public = ca.public_key()?;
        assert!(ca.verify(&public)?, "actual remote root self-signature");
        let prior_schema = service.state.as_ref().ok_or("state")?.schema;
        assert!(
            prior_schema == PKI_ROLE_BARE_DOMAIN_STATE_SCHEMA
                && service
                    .state
                    .as_ref()
                    .ok_or("new role")?
                    .engines
                    .has_pki_role_bare_domain_state(),
            "ordinary new-role path requires84 before alias publication"
        );
        let mut readbacks = Vec::new();
        for reference in ["default", id.as_str(), "primary"] {
            let path = format!("external-ca/issuer/{reference}/issue/leaf");
            let fingerprint = service.request_fingerprint("POST", &path, "", &admin);
            let before = issue_signs(&remote)?;
            let (mut issued, lower, upper) = timed_leaf_delivery(
                &mut service,
                &admin,
                &path,
                issue_body(),
                std::time::Duration::from_secs(100),
                std::time::Instant::now(),
            )?;
            assert!(
                issued.status == 200 && issue_signs(&remote)? == before + 1,
                "one actual provider signature per selected leaf"
            );
            let data = &issued.body["data"];
            let leaf = X509::from_pem(data["certificate"].as_str().ok_or("leaf PEM")?.as_bytes())?;
            let private = PKey::private_key_from_pem(
                data["private_key"]
                    .as_str()
                    .ok_or("owned private output")?
                    .as_bytes(),
            )?;
            assert!(
                leaf.verify(&public)?
                    && leaf.public_key()?.public_key_to_der()? == private.public_key_to_der()?,
                "maintained private parser binds the actually remote-signed leaf"
            );
            assert!(
                issued.body["renewable"] == false
                    && issued.body["lease_duration"]
                        .as_u64()
                        .is_some_and(|ttl| { (lower..=upper).contains(&ttl) && ttl <= 600 }),
                "lease duration retains actual elapsed time within the final delivery interval"
            );
            let serial = data["serial_number"].as_str().ok_or("serial")?.to_owned();
            let groups = serial.split(':').collect::<Vec<_>>();
            assert!(
                groups.len() == 20
                    && groups.iter().all(|group| group.len() == 2
                        && group
                            .bytes()
                            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())),
                "external serial is exactly twenty lowercase hexadecimal byte pairs"
            );
            let raw_serial = groups.concat();
            let certificate_serial = leaf
                .serial_number()
                .to_bn()?
                .to_hex_str()?
                .to_ascii_lowercase();
            assert!(
                certificate_serial.trim_start_matches('0') == raw_serial.trim_start_matches('0'),
                "maintained certificate serial equals the response serial value"
            );
            let lease = issued.body["lease_id"]
                .as_str()
                .ok_or("lease ID")?
                .to_owned();
            assert!(
                lease == format!("{path}/{}", raw_serial),
                "lease identifier retains original selected issuer path"
            );
            let lookup = call(
                &mut service,
                "PUT",
                "sys/leases/lookup",
                &admin,
                json!({"lease_id":lease}),
            );
            assert!(
                lookup.status == 200
                    && lookup.body["data"]["path"] == path
                    && lookup.body["data"]["id"] == lease,
                "root lease lookup binds exact original path and identifier"
            );
            let records = fs::read_to_string(root.path.join("audit.jsonl"))?
                .lines()
                .map(serde_json::from_str::<Value>)
                .collect::<Result<Vec<_>, _>>()?;
            assert!(
                records
                    .iter()
                    .filter(|record| record["event"]["path_digest"] == fingerprint)
                    .count()
                    == 2,
                "request and response audit fingerprint bind original method, token and issuer path"
            );
            let state = service.state.as_ref().ok_or("published state")?;
            assert!(
                state.schema == PKI_ROLE_BARE_DOMAIN_STATE_SCHEMA
                    && state.engines.has_issuer_path_pki_state()
                    && state.engines.has_pki_role_bare_domain_state()
                    && state.validate_format().is_ok(),
                "real alias71 owner and new role84 coexist without lowering either"
            );
            let mut encoded = serde_json::to_value(state)?;
            let pki =
                &encoded["engines"]["namespaces"][""]["mounts"]["external-ca/"]["backend"]["Pki"];
            assert!(
                pki["issued"]
                    .as_object()
                    .is_some_and(|entries| entries.len() == readbacks.len() + 1)
                    && pki["external"]["issued_public"]
                        .as_object()
                        .is_some_and(|entries| entries.len() == readbacks.len() + 1),
                "one bounded issued record and one public projection per real leaf"
            );
            erase_json(&mut encoded);
            readbacks.push((
                serial,
                data["certificate"]
                    .as_str()
                    .ok_or("public leaf")?
                    .to_owned(),
                lease,
            ));
            erase_json(&mut issued.body);
        }
        let before = remote.calls()?;
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
            "encrypted alias-state restart"
        );
        assert!(
            reopened.state.as_ref().ok_or("reopened state")?.schema
                == PKI_ROLE_BARE_DOMAIN_STATE_SCHEMA,
            "encrypted restart keeps the real alias and new role84 floor"
        );
        for (serial, certificate, lease) in readbacks {
            let read = call(
                &mut reopened,
                "GET",
                &format!("external-ca/cert/{serial}"),
                "",
                json!({}),
            );
            assert!(
                read.status == 200
                    && read.body["data"]["certificate"] == certificate
                    && read.body["data"].get("private_key").is_none(),
                "encrypted readback retains exact public certificate without private material"
            );
            let lookup = call(
                &mut reopened,
                "PUT",
                "sys/leases/lookup",
                &admin,
                json!({"lease_id":lease}),
            );
            assert!(
                lookup.status == 200 && lookup.body["data"]["id"] == lease,
                "original alias lease survives encrypted restart"
            );
        }
        assert!(
            remote.calls()? == before,
            "reopen and public readback never enter provider"
        );
    }
    Ok(())
}

#[test]
fn external_pki270_issuer_issue_original_acl_unknown_names_namespace_and_methods() -> TestResult {
    let remote = RemoteTransit::new_kind("ed25519")?;
    let (_root, mut service, _unseal, admin, id) = issuer_issue_fixture(&remote)?;
    let path = format!("external-ca/issuer/{id}/issue/leaf");
    let _last_use = limited_token(
        &mut service,
        &admin,
        &format!("path \"{path}\" {{ capabilities = [\"update\"] }}"),
    )?;
    let owner = call(
        &mut service,
        "POST",
        "auth/token/create",
        &admin,
        json!({"policies":["scoped"],"no_default_policy":true}),
    );
    assert!(owner.status == 200, "exact issuer-path policy owner");
    let token = owner.body["auth"]["client_token"]
        .as_str()
        .ok_or("scoped actor")?;
    let before = issue_signs(&remote)?;
    let mut allowed = call(&mut service, "POST", &path, token, issue_body());
    assert!(
        allowed.status == 200 && issue_signs(&remote)? == before + 1,
        "ID-specific ACL allows its one real leaf"
    );
    erase_json(&mut allowed.body);
    let before = remote.calls()?;
    for denied_path in [
        "external-ca/issuer/default/issue/leaf",
        "external-ca/issuer/primary/issue/leaf",
        "external-ca/issue/leaf",
    ] {
        let denied = call(&mut service, "POST", denied_path, token, issue_body());
        assert!(
            denied.status == 403 && denied.body.get("data").is_none(),
            "issuer selection never substitutes a canonical ACL path"
        );
    }
    for reference in [
        "unknown-issuer",
        "00000000-0000-4000-8000-000000000000",
        "Primary",
        "Default",
    ] {
        let denied = call(
            &mut service,
            "POST",
            &format!("external-ca/issuer/{reference}/issue/leaf"),
            &admin,
            issue_body(),
        );
        assert!(
            denied.status == 500 && denied.body.get("data").is_none(),
            "unknown issuer never falls back to default before signing"
        );
    }
    for method in ["GET", "DELETE", "LIST"] {
        let denied = call(&mut service, method, &path, &admin, issue_body());
        assert!(
            denied.status != 200 && denied.body.get("data").is_none(),
            "closed issuer issue grammar grants no read or other mutation"
        );
    }
    for token in ["", "synthetic.invalid.bearer"] {
        assert!(
            call(&mut service, "POST", &path, token, issue_body()).status == 403,
            "anonymous and invalid actors cannot issue"
        );
    }
    assert!(
        service
            .handle_at(
                "POST",
                &path,
                "missing-namespace",
                &admin,
                issue_body(),
                100
            )
            .status
            != 200,
        "issuer ID cannot cross namespace ownership"
    );
    assert!(
        remote.calls()? == before,
        "all denied paths enter no provider operation"
    );
    Ok(())
}

#[test]
fn external_pki270_issuer_issue_grant_rejection_and_completed_effect_aba_never_replay() -> TestResult
{
    let remote = RemoteTransit::new_kind("ed25519")?;
    let (_root, mut service, _unseal, admin, id) = issuer_issue_fixture(&remote)?;
    let path = format!("external-ca/issuer/{id}/issue/leaf");
    let grant = "sys/external-keys/configs/remote/keys/v2/grants/external-ca";
    assert!(
        call(&mut service, "DELETE", grant, &admin, json!({})).status == 204,
        "delete original grant"
    );
    let count = remote.calls()?;
    let denied = call(&mut service, "POST", &path, &admin, issue_body());
    assert!(
        denied.status == 500 && denied.body.get("data").is_none() && remote.calls()? == count,
        "each alias consumption needs live mount grant"
    );
    assert!(
        call(&mut service, "POST", grant, &admin, json!({})).status == 204,
        "restore original grant"
    );
    let pending = staged_issue(&mut service, &admin, &path)?;
    let result = pending.execute();
    assert!(
        matches!(&result, ExternalEffectResult::ExternalPki(Ok(_))),
        "actual remote leaf signature before grant ABA"
    );
    let count = remote.calls()?;
    for (method, status) in [("DELETE", 204), ("POST", 204)] {
        assert!(
            call(&mut service, method, grant, &admin, json!({})).status == status,
            "grant delete and exact restoration"
        );
    }
    let identity = service.current_state_identity().map_err(|_| "identity")?;
    let response = service.finish_external_request(pending, result);
    assert!(
        response.status == 503 && response.body.get("data").is_none(),
        "captured generation withholds completed private result after ABA"
    );
    assert!(
        service.current_state_identity().map_err(|_| "identity")? == identity
            && remote.calls()? == count,
        "ABA veto publishes no leaf and never replays provider"
    );
    assert!(
        !service
            .state
            .as_ref()
            .ok_or("state")?
            .engines
            .has_issuer_path_pki_state(),
        "vetoed alias result does not activate71"
    );
    Ok(())
}

#[test]
fn external_pki270_issuer_issue_final_delivery_clock_withholds_expired_private() -> TestResult {
    let remote = RemoteTransit::new_kind("ed25519")?;
    let (root, mut service, _unseal, admin, id) = issuer_issue_fixture(&remote)?;
    let path = format!("external-ca/issuer/{id}/issue/leaf");
    let started = std::time::Instant::now();
    let delay = crate::service::external_pki::PublicationDelayScope::until(
        started + std::time::Duration::from_millis(60_250),
    );
    let before = issue_signs(&remote)?;
    let (response, _, _) = timed_leaf_delivery(
        &mut service,
        &admin,
        &path,
        json!({"common_name":"leaf.example.test","ttl":"60s"}),
        std::time::Duration::from_millis(100_750),
        started,
    )?;
    drop(delay);
    assert!(
        response.status == 403
            && response.body.get("data").is_none()
            && issue_signs(&remote)? == before + 1,
        "original final clock gate withholds already-committed expired alias private output without retry"
    );
    let records = fs::read_to_string(root.path.join("audit.jsonl"))?
        .lines()
        .map(serde_json::from_str::<Value>)
        .collect::<Result<Vec<_>, _>>()?;
    let negative = records.last().ok_or("delivery veto")?;
    let planned = records.iter().rev().nth(1).ok_or("planned success")?;
    assert!(
        negative["event"]["kind"] == "external-pki-delivery-veto"
            && negative["event"]["status"] == 403
            && planned["event"]["status"] == 200
            && negative["event"]["path_digest"] == planned["event"]["path_digest"],
        "original issuer fingerprint records committed success and actual negative delivery separately"
    );
    Ok(())
}

#[test]
fn external_pki270_issuer_issue_schema71_active_retired_record_and_snapshot_fences() -> TestResult {
    let remote = RemoteTransit::new_kind("ed25519")?;
    let (root, mut service, unseal, admin, id) = issuer_issue_historical_role_fixture(&remote)?;
    let mut predecessor = service.state.clone().ok_or("predecessor")?;
    predecessor.schema = TRANSIT_BYOK_STATE_SCHEMA;
    service
        .commit_state(&predecessor)
        .map_err(|_| "native codec70 fixture publication")?;
    service.state = Some(predecessor);
    // Authenticated native-codec predecessor input, not evidence of an old binary.
    let old70 =
        zeroize::Zeroizing::new(service.durable.as_ref().ok_or("durable")?.export_backup()?);
    let mut active_plan = service
        .prepare_snapshot_restore(&old70)
        .map_err(|_| "prepare before alias")?;
    let mut retired_plan = service
        .prepare_snapshot_restore(&old70)
        .map_err(|_| "prepare before retirement")?;
    let path = format!("external-ca/issuer/{id}/issue/leaf");
    let mut issued = call(&mut service, "POST", &path, &admin, issue_body());
    assert!(issued.status == 200, "actual alias activates71");
    let lease = issued.body["lease_id"]
        .as_str()
        .ok_or("alias lease")?
        .to_owned();
    erase_json(&mut issued.body);
    let principal = service
        .state
        .as_mut()
        .ok_or("state")?
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
        allow_forward: false,
        enforce_namespace: true,
        wrap_ttl_seconds: None,
        origin_peer: None,
        client_certificates: None,
    };
    let identity = service
        .current_state_identity()
        .map_err(|_| "active identity")?;
    active_plan.fixture_rebind_base_for_protected_floor(identity);
    assert!(
        service
            .commit_snapshot_restore(active_plan, &principal, &request)
            .status
            == 400,
        "final commit independently rejects authenticated old70 after alias activation"
    );
    for retired in [false, true] {
        if retired {
            assert!(
                call(
                    &mut service,
                    "PUT",
                    "sys/leases/revoke",
                    &admin,
                    json!({"lease_id":lease})
                )
                .status
                    == 204,
                "alias owner lease revocation"
            );
            assert!(
                call(
                    &mut service,
                    "DELETE",
                    "sys/mounts/external-ca",
                    &admin,
                    json!({})
                )
                .status
                    == 204,
                "explicitly remove last alias graph"
            );
        }
        let state = service.state.as_ref().ok_or("protected state")?;
        assert!(
            state.schema == 71 && state.writer_schema() == 71 && state.validate_format().is_ok(),
            "retirement never lowers sticky71"
        );
        assert!(
            state.engines.has_issuer_path_pki_state() != retired,
            "feature predicate distinguishes retained graph from sticky label"
        );
        let mut lower = state.clone();
        lower.schema = 70;
        assert!(
            lower.validate_publication_schema(Some(state)).is_err(),
            "active and retired previous71 block writer downgrade"
        );
        if !retired {
            assert!(
                lower.validate_format().is_err(),
                "alias graph cannot disguise its outer label as70"
            );
        }
        let before = service.current_state_identity().map_err(|_| "identity")?;
        let generation = service
            .external_effect_generation()
            .map_err(|_| "generation")?;
        assert!(
            service
                .prepare_record_plan(&lower)
                .err()
                .is_some_and(|response| response.status == 503),
            "record preflight rejects downgrade before materialization"
        );
        assert!(
            service
                .commit_state(&lower)
                .err()
                .is_some_and(|response| response.status == 503),
            "direct durable publication rejects downgrade"
        );
        assert!(
            service
                .prepare_snapshot_restore(&old70)
                .err()
                .is_some_and(|response| response.status == 400),
            "snapshot prepare rejects old70"
        );
        let mut reader = std::io::Cursor::new(old70.as_slice());
        assert!(
            service
                .prepare_snapshot_restore_from_reader(&mut reader, old70.len() as u64)
                .err()
                .is_some_and(|response| response.status == 400),
            "streamed prepare rejects same authenticated old70"
        );
        assert!(
            service.current_state_identity().map_err(|_| "identity")? == before
                && service
                    .external_effect_generation()
                    .map_err(|_| "generation")?
                    == generation,
            "all rejected paths preserve original publication"
        );
    }
    retired_plan.fixture_rebind_base_for_protected_floor(
        service
            .current_state_identity()
            .map_err(|_| "retired identity")?,
    );
    assert!(
        service
            .commit_snapshot_restore(retired_plan, &principal, &request)
            .status
            == 400,
        "final retired floor rejects old70"
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
            == 200
            && reopened.state.as_ref().ok_or("retired reopened")?.schema == 71,
        "encrypted retired reopen retains71 without any alias graph"
    );
    Ok(())
}

#[test]
fn external_pki270_issuer_issue_all_namespace_retained_predicate_and_closed_grammar() -> TestResult
{
    let remote = RemoteTransit::new_kind("ed25519")?;
    let (_root, mut service, _unseal, admin, id) = issuer_issue_historical_role_fixture(&remote)?;
    let path = format!("external-ca/issuer/{id}/issue/leaf");
    let mut issued = call(&mut service, "POST", &path, &admin, issue_body());
    assert!(issued.status == 200, "real alias graph for predicate test");
    erase_json(&mut issued.body);
    let mut encoded = serde_json::to_value(service.state.as_ref().ok_or("state")?)?;
    let namespace = encoded["engines"]["namespaces"]
        .as_object_mut()
        .ok_or("namespace map")?
        .remove("")
        .ok_or("source namespace")?;
    encoded["engines"]["namespaces"]["isolated"] = namespace;
    // Predicate-only placement input: no claim of a published owner graph.
    let mut elsewhere: State = serde_json::from_value(encoded.clone())?;
    elsewhere.schema = 70;
    assert!(
        elsewhere.engines.has_issuer_path_pki_state()
            && elsewhere.writer_schema() == 71
            && elsewhere.validate_format().is_err(),
        "all-namespace scan cannot hide an alias graph behind outer70"
    );
    let pki = &mut encoded["engines"]["namespaces"]["isolated"]["mounts"]["external-ca/"]["backend"]
        ["Pki"];
    for issued in pki["issued"]
        .as_object_mut()
        .ok_or("issued graph")?
        .values_mut()
    {
        issued["revoked_at"] = json!(100);
    }
    let revoked: State = serde_json::from_value(encoded.clone())?;
    assert!(
        revoked.engines.has_issuer_path_pki_state(),
        "revoked alias records remain format-bearing"
    );
    erase_json(&mut encoded);
    let before = remote.calls()?;
    for relative in [
        "issuer//issue/leaf",
        "issuer/default/issue/",
        "issuer/default/issue/leaf/extra",
        "issuer/default/issue/leaf?x=1",
        "issuer/default/sign/leaf",
    ] {
        let response = call(
            &mut service,
            "POST",
            &format!("external-ca/{relative}"),
            &admin,
            issue_body(),
        );
        assert!(
            response.status != 200 && response.body.get("data").is_none(),
            "closed route grammar rejects extra or missing components"
        );
    }
    assert!(
        remote.calls()? == before,
        "malformed alias paths never enter provider"
    );
    Ok(())
}
