//! Public time inputs, independently verified signed DER, and sticky reader89.
use super::*;
fn pki_value(service: &Service, namespace: &str, mount: &str) -> TestResult<CarrierBody> {
    let state = service.state.as_ref().ok_or("actual time state")?;
    let engines = CarrierBody(serde_json::to_value(&state.engines)?);
    Ok(CarrierBody(
        engines.0["namespaces"][namespace]["mounts"][mount]["backend"]["Pki"].clone(),
    ))
}

fn timed_role(service: &mut Service, admin: &str, fields: Value) -> TestResult {
    let mut body = role_body(&default_profile());
    for (key, value) in fields.as_object().ok_or("time fields")? {
        body[key] = value.clone();
    }
    let response = call(service, "POST", "ca/roles/time", admin, body);
    assert!(
        response.status == 200,
        "actual role time publication: {:?}",
        response.body
    );
    Ok(())
}

fn signed_times(
    response: &Response,
    issuer: &X509,
    before: i64,
    after: i64,
) -> TestResult<(String, String)> {
    let result = profile_leaf(response, issuer, false)?;
    let leaf = X509::from_pem(result.1.as_bytes())?;
    let der = Zeroizing::new(leaf.to_der()?);
    let (rest, parsed) = X509Certificate::from_der(&der).map_err(|_| "signed time DER")?;
    assert!(
        rest.is_empty()
            && parsed.validity().not_before.timestamp() == before
            && parsed.validity().not_after.timestamp() == after,
        "independent actual signed certificate times"
    );
    assert!(
        response.body["data"]["not_before"] == before
            && response.body["data"]["expiration"] == after,
        "public integer times equal actual signed DER"
    );
    Ok(result)
}

#[test]
fn pki_time89_role_ttl_backdate_cap_warning_and_exact_signed_validity() -> TestResult {
    let (_root, mut service, _unseal, admin, issuer) = local_fixture()?;
    timed_role(
        &mut service,
        &admin,
        json!({"ttl":"10m","not_before_duration":"45s"}),
    )?;
    let role = call(&mut service, "GET", "ca/roles/time", &admin, json!({}));
    assert!(
        role.status == 200
            && role.body["data"]["ttl"] == 600
            && role.body["data"]["not_before_duration"] == 45
            && role.body["data"]["not_before"] == ""
            && role.body["data"]["not_after"] == ""
            && role.body["data"]["not_before_bound"] == "permit"
            && role.body["data"]["not_after_bound"] == "permit",
        "actual six role GET fields"
    );
    let leaf = call(
        &mut service,
        "POST",
        "ca/issue/time",
        &admin,
        json!({"common_name":"leaf.example.test"}),
    );
    signed_times(&leaf, &issuer, 55, 700)?;
    assert!(
        leaf.body.get("warnings").is_none(),
        "uncapped request has no invented warning"
    );
    let capped = call(
        &mut service,
        "POST",
        "ca/issue/time",
        &admin,
        json!({"common_name":"leaf.example.test","ttl":"2h"}),
    );
    signed_times(&capped, &issuer, 55, 3700)?;
    assert!(
        capped.body["warnings"]
            == json!([
                "TTL \"2h0m0s\" is longer than permitted maxTTL \"1h0m0s\", so maxTTL is being used"
            ]),
        "official TTL cap warning from actual over-limit issuance"
    );
    let state = service.state.as_ref().ok_or("actual time state")?;
    assert!(
        state.schema == 89 && state.writer_schema() == 89 && state.validate_format().is_ok(),
        "stored role and private signed leaf raise reader89"
    );
    Ok(())
}

#[test]
fn pki_time89_future_request_without_role_policy_binds_private_public_owner_and_reopens()
-> TestResult {
    let (root, mut service, unseal, admin, issuer) = local_fixture()?;
    timed_role(&mut service, &admin, json!({}))?;
    assert!(
        service.state.as_ref().ok_or("ordinary role")?.schema == 88,
        "captured real predecessor88"
    );
    let leaf = call(
        &mut service,
        "POST",
        "ca/issue/time",
        &admin,
        json!({"common_name":"leaf.example.test","ttl":"10m","not_before":"1970-01-01T00:02:00Z"}),
    );
    let (serial, _pem) = signed_times(&leaf, &issuer, 120, 700)?;
    let serial = serial.replace(':', "");
    let state = service.state.as_ref().ok_or("time request state")?;
    assert!(
        state.schema == 89 && state.engines.has_pki_role_time_state(),
        "actual request-owned future validity requires89"
    );
    let stored = pki_value(&service, "", "ca/")?;
    assert!(
        stored.0["roles"]["time"].get("role_time_policy").is_none()
            && stored.0["issued"][&serial]["role_time_owned"] == true
            && stored.0["issued"][&serial]["role_leaf_profile"]["role_time_owned"] == true,
        "request time has independent private and signed public ownership without a fabricated role policy"
    );
    let mut false_owner = serde_json::to_value(state)?;
    false_owner["engines"]["namespaces"][""]["mounts"]["ca/"]["backend"]["Pki"]["issued"]
        [&serial]["role_time_owned"] = json!(false);
    let false_owner: State = serde_json::from_value(false_owner)?;
    assert!(
        false_owner.validate_format().is_err(),
        "received graph cannot erase one side of actual time ownership"
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
        "actual encrypted time state reopens"
    );
    let persisted = pki_value(&reopened, "", "ca/")?;
    assert!(
        reopened.state.as_ref().ok_or("reopened")?.schema == 89
            && persisted.0["issued"][&serial]["role_time_owned"] == true,
        "private time owner and sticky reader survive encrypted restart"
    );
    Ok(())
}

#[test]
fn pki_time89_request_bounds_role_override_and_ttl_mutual_exclusion() -> TestResult {
    let (_root, mut service, _unseal, admin, issuer) = local_fixture()?;
    timed_role(
        &mut service,
        &admin,
        json!({"ttl":"10m","not_before_bound":"forbid","not_after_bound":"forbid"}),
    )?;
    for fields in [
        json!({"not_before":"1970-01-01T00:01:11Z"}),
        json!({"not_after":"1970-01-01T00:11:00Z"}),
    ] {
        let identity = service
            .current_state_identity()
            .map_err(|_| "before rejected time")?;
        let mut body = fields;
        body["common_name"] = json!("leaf.example.test");
        let rejected = call(&mut service, "POST", "ca/issue/time", &admin, body);
        assert!(
            rejected.status == 400
                && service
                    .current_state_identity()
                    .map_err(|_| "after rejected time")?
                    == identity,
            "forbidden actual time request leaves complete graph unchanged"
        );
    }
    timed_role(
        &mut service,
        &admin,
        json!({"ttl":"10m","not_before_bound":"duration"}),
    )?;
    let old = call(
        &mut service,
        "POST",
        "ca/issue/time",
        &admin,
        json!({"common_name":"leaf.example.test","not_before":"1970-01-01T00:01:09Z"}),
    );
    assert!(
        old.status == 400,
        "actual requested backdate older than 30 seconds rejected"
    );
    let accepted = call(
        &mut service,
        "POST",
        "ca/issue/time",
        &admin,
        json!({"common_name":"leaf.example.test","not_before":"1970-01-01T00:01:11Z"}),
    );
    signed_times(&accepted, &issuer, 71, 700)?;
    timed_role(
        &mut service,
        &admin,
        json!({"ttl":"10m","not_before":"1970-01-01T00:00:40Z","not_before_bound":"forbid",
        "not_after":"1970-01-01T00:15:00Z","not_after_bound":"ttl-limited"}),
    )?;
    let override_leaf = call(
        &mut service,
        "POST",
        "ca/issue/time",
        &admin,
        json!({"common_name":"leaf.example.test","not_before":"unparsed request","not_after":"unparsed request"}),
    );
    signed_times(&override_leaf, &issuer, 40, 900)?;
    let conflict = call(
        &mut service,
        "POST",
        "ca/issue/time",
        &admin,
        json!({"common_name":"leaf.example.test","ttl":"1m"}),
    );
    assert!(
        conflict.status == 400,
        "request TTL and fixed role notAfter are mutually exclusive in the primary producer"
    );
    timed_role(
        &mut service,
        &admin,
        json!({"ttl":"10m","not_after_bound":"ttl-limited"}),
    )?;
    let beyond = call(
        &mut service,
        "POST",
        "ca/issue/time",
        &admin,
        json!({"common_name":"leaf.example.test","not_after":"1970-01-01T00:15:00Z"}),
    );
    assert!(
        beyond.status == 400,
        "explicit request notAfter is limited by resolved TTL"
    );
    let invalid_write = call(
        &mut service,
        "PATCH",
        "ca/roles/time",
        &admin,
        json!({"not_before":"later-invalid-at-issuance"}),
    );
    assert!(
        invalid_write.status == 200,
        "primary role write preserves an absolute time for issuance-time parsing"
    );
    let invalid_issue = call(
        &mut service,
        "POST",
        "ca/issue/time",
        &admin,
        json!({"common_name":"leaf.example.test"}),
    );
    assert!(
        invalid_issue.status == 400,
        "actual issuance rejects malformed fixed role time"
    );
    Ok(())
}

#[test]
fn pki_time89_actual88_backup_record_and_final_floor_survive_last_owner_tidy() -> TestResult {
    let (root, mut service, unseal, admin, issuer) = local_fixture()?;
    timed_role(&mut service, &admin, json!({}))?;
    let predecessor = service.state.as_ref().ok_or("original88")?.clone();
    assert!(
        predecessor.schema == 88 && !predecessor.engines.has_pki_role_time_state(),
        "capture actual original88 before mutation"
    );
    let old88 = Zeroizing::new(service.durable.as_ref().ok_or("durable")?.export_backup()?);
    let mut old_restore = service
        .prepare_snapshot_restore(&old88)
        .map_err(|_| "prepared original88")?;
    let old_plan = service
        .prepare_record_plan(&mut predecessor.clone())
        .map_err(|_| "original88 record plan")?;
    assert!(
        call(
            &mut service,
            "PATCH",
            "ca/roles/time",
            &admin,
            json!({"ttl":"10m"})
        )
        .status
            == 200,
        "actual role time upgrade"
    );
    let issued = call(
        &mut service,
        "POST",
        "ca/issue/time",
        &admin,
        json!({"common_name":"leaf.example.test"}),
    );
    signed_times(&issued, &issuer, 70, 700)?;
    assert!(
        call(&mut service, "DELETE", "ca/roles/time", &admin, json!({})).status == 204,
        "last role removed"
    );
    assert!(
        service
            .state
            .as_ref()
            .ok_or("leaf owner")?
            .engines
            .has_pki_role_time_state(),
        "signed private leaf remains the actual last owner"
    );
    assert!(
        service
            .handle_at(
                "POST",
                "ca/tidy",
                "",
                &admin,
                json!({"safety_buffer":"0s"}),
                701
            )
            .status
            == 204,
        "actual expired certificate and zero-buffer tidy remove last time owner"
    );
    let retired = service.state.as_ref().ok_or("retired89")?.clone();
    assert!(
        retired.schema == 89
            && retired.writer_schema() == 89
            && !retired.engines.has_pki_role_time_state()
            && retired.validate_format().is_ok(),
        "reader89 persists after actual last owner removal"
    );
    let identity = service
        .current_state_identity()
        .map_err(|_| "retired identity")?;
    assert!(
        predecessor
            .validate_publication_schema(Some(&retired))
            .is_err()
            && service.prepare_record_plan(&mut predecessor.clone()).is_err()
            && service.commit_state(&mut predecessor.clone()).is_err()
            && service.prepare_snapshot_restore(&old88).is_err(),
        "original authenticated88 cannot replace retired89 through ordinary gates"
    );
    let mut reader = old88.as_slice();
    assert!(
        service
            .prepare_snapshot_restore_from_reader(&mut reader, old88.len() as u64)
            .is_err(),
        "original streamed88 backup retains its own real label"
    );
    old_restore.fixture_rebind_base_for_protected_floor(identity);
    let principal = service
        .state
        .as_mut()
        .ok_or("state")?
        .auth
        .authenticate_from(&admin, 701, None)
        .map_err(|_| "actual final restore principal")?;
    let body = json!({});
    let request = RequestView {
        token_clock: None,
        method: "POST",
        path: "sys/storage/raft/snapshot-force",
        namespace: "",
        token: &admin,
        body: &body,
        now: 701,
        admission_started: std::time::Instant::now(),
        allow_forward: false,
        enforce_namespace: true,
        wrap_ttl_seconds: None,
        origin_peer: None,
        client_certificates: None,
    };
    let rejected = service.commit_snapshot_restore(old_restore, &principal, &request);
    assert!(
        rejected.status == 400
            && rejected.body["errors"][0] == "snapshot would downgrade PKI role time ownership",
        "held authenticated actual88 restore reaches final reader89 gate after tidy"
    );
    assert!(
        service
            .install_received_record_state(predecessor, old_plan)
            .is_err()
            && service.current_state_identity().map_err(|_| "identity")? == identity,
        "captured original88 receiver cannot replace actual retired89 graph"
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
            && reopened.state.as_ref().ok_or("restart")?.schema == 89
            && reopened.state.as_ref().ok_or("restart")?.writer_schema() == 89,
        "sticky89 survives encrypted last-owner restart"
    );
    Ok(())
}

#[test]
fn pki_time89_received_actual88_to89_records_persist_and_reopen() -> TestResult {
    let (root, mut service, unseal, admin, _issuer) = local_fixture()?;
    timed_role(&mut service, &admin, json!({}))?;
    let predecessor = service.state.as_ref().ok_or("actual88")?.clone();
    assert!(
        predecessor.schema == 88,
        "captured actual88 record predecessor"
    );
    let old_plan = service
        .prepare_record_plan(&mut predecessor.clone())
        .map_err(|_| "captured88 plan")?;
    let mut received = predecessor.clone();
    let response = received
        .engines
        .handle(
            "",
            "PATCH",
            "ca/roles/time",
            &json!({"ttl":"10m","not_before_duration":"45s"}),
            100,
        )?
        .ok_or("actual received route")?;
    assert!(
        response.status == 200 && response.mutated,
        "actual candidate typed time route"
    );
    received.schema = received.writer_schema();
    received.replay_epoch += 3;
    assert!(
        received.schema == 89 && received.validate_format().is_ok(),
        "complete received time owner graph requires89"
    );
    let plan = service
        .prepare_record_plan(&mut received)
        .map_err(|_| "received89 plan")?;
    service
        .install_received_record_state(received, plan)
        .map_err(|_| "received89 persist")?;
    let identity = service
        .current_state_identity()
        .map_err(|_| "received identity")?;
    assert!(
        service
            .install_received_record_state(predecessor, old_plan)
            .is_err()
            && service
                .current_state_identity()
                .map_err(|_| "received identity")?
                == identity,
        "actual captured88 cannot downgrade received89 owner"
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
        "actual received records encrypted reopen"
    );
    let role = call(&mut reopened, "GET", "ca/roles/time", &admin, json!({}));
    assert!(
        role.status == 200
            && role.body["data"]["ttl"] == 600
            && role.body["data"]["not_before_duration"] == 45
            && reopened.state.as_ref().ok_or("reopened")?.schema == 89
            && reopened.state.as_ref().ok_or("reopened")?.replay_epoch == 3,
        "received time policy, reader89 and epoch survive restart"
    );
    Ok(())
}

#[test]
fn pki_time89_mount_default_and_positive_role_max_follow_actual_native_priority() -> TestResult {
    let (_root, mut service, _unseal, admin, issuer) = local_fixture()?;
    assert!(
        call(
            &mut service,
            "POST",
            "sys/mounts/ca/tune",
            &admin,
            json!({"default_lease_ttl":"5m","max_lease_ttl":"10m"})
        )
        .status
            == 204,
        "actual mount TTL publication"
    );
    timed_role(
        &mut service,
        &admin,
        json!({"ttl":0,"max_ttl":0,"not_before_duration":"45s"}),
    )?;
    let fallback = call(
        &mut service,
        "POST",
        "ca/issue/time",
        &admin,
        json!({"common_name":"leaf.example.test"}),
    );
    signed_times(&fallback, &issuer, 55, 400)?;
    timed_role(
        &mut service,
        &admin,
        json!({"ttl":"20m","max_ttl":"1h","not_before_duration":"45s"}),
    )?;
    let override_max = call(
        &mut service,
        "POST",
        "ca/issue/time",
        &admin,
        json!({"common_name":"leaf.example.test"}),
    );
    signed_times(&override_max, &issuer, 55, 1300)?;
    assert!(
        override_max.body.get("warnings").is_none(),
        "positive role max supersedes mount max as native"
    );
    Ok(())
}

#[test]
fn pki_time89_local_issuer_three_modes_bound_order_captured_owner_and_restart() -> TestResult {
    let (root, mut service, unseal, admin, _long_issuer) = local_fixture()?;
    let short = call(
        &mut service,
        "POST",
        "ca/root/generate/internal",
        &admin,
        json!({"common_name":"short-ca.example.test","key_type":"ec","key_bits":256,"ttl":"10m"}),
    );
    assert!(short.status == 200, "actual shorter CA producer");
    let issuer = X509::from_pem(
        short.body["data"]["certificate"]
            .as_str()
            .ok_or("short CA")?
            .as_bytes(),
    )?;
    let id = short.body["data"]["issuer_id"]
        .as_str()
        .ok_or("short CA identity")?;
    let route = format!("ca/issuer/{id}");
    let issue_route = format!("ca/issuer/{id}/issue/time");
    timed_role(&mut service, &admin, json!({"ttl":"20m"}))?;
    for invalid in [json!("invalid"), json!(""), Value::Null] {
        let identity = service
            .current_state_identity()
            .map_err(|_| "before invalid mode")?;
        let rejected = call(
            &mut service,
            "POST",
            &route,
            &admin,
            json!({"leaf_not_after_behavior":invalid}),
        );
        assert!(
            rejected.status == 400
                && rejected.body["errors"][0]
                    == "Unknown value for field `leaf_not_after_behavior`. Possible values are `err`, `truncate`, and `permit`."
                && service
                    .current_state_identity()
                    .map_err(|_| "after invalid mode")?
                    == identity,
            "native invalid enum errors preserve complete state"
        );
    }
    let err = call(
        &mut service,
        "POST",
        &route,
        &admin,
        json!({"leaf_not_after_behavior":"err"}),
    );
    assert!(
        err.status == 200 && err.body["data"]["leaf_not_after_behavior"] == "err",
        "actual issuer err policy"
    );
    let identity = service
        .current_state_identity()
        .map_err(|_| "err policy identity")?;
    let rejected = call(
        &mut service,
        "POST",
        &issue_route,
        &admin,
        json!({"common_name":"leaf.example.test"}),
    );
    assert!(
        rejected.status == 400
            && service
                .current_state_identity()
                .map_err(|_| "rejected CA identity")?
                == identity,
        "err rejects actual leaf beyond signed CA expiry without publication"
    );
    assert!(
        call(
            &mut service,
            "POST",
            &route,
            &admin,
            json!({"leaf_not_after_behavior":"permit"})
        )
        .status
            == 200,
        "actual issuer permit policy"
    );
    let permitted = call(
        &mut service,
        "POST",
        &issue_route,
        &admin,
        json!({"common_name":"leaf.example.test"}),
    );
    let (serial, pem) = signed_times(&permitted, &issuer, 70, 1300)?;
    let serial = serial.replace(':', "");
    assert!(
        call(
            &mut service,
            "POST",
            &route,
            &admin,
            json!({"leaf_not_after_behavior":"truncate"})
        )
        .status
            == 200,
        "actual issuer truncate policy"
    );
    let truncated = call(
        &mut service,
        "POST",
        &issue_route,
        &admin,
        json!({"common_name":"leaf.example.test"}),
    );
    signed_times(&truncated, &issuer, 70, 700)?;
    timed_role(
        &mut service,
        &admin,
        json!({"ttl":"20m","not_after_bound":"1970-01-01T00:12:30Z"}),
    )?;
    let capped_before_bound = call(
        &mut service,
        "POST",
        &issue_route,
        &admin,
        json!({"common_name":"leaf.example.test"}),
    );
    signed_times(&capped_before_bound, &issuer, 70, 700)?;
    assert!(
        call(
            &mut service,
            "POST",
            &route,
            &admin,
            json!({"leaf_not_after_behavior":"permit"})
        )
        .status
            == 200,
        "switch policy after original signed permit leaf"
    );
    assert!(
        call(
            &mut service,
            "POST",
            &issue_route,
            &admin,
            json!({"common_name":"leaf.example.test"})
        )
        .status
            == 400,
        "permit leaves actual expiry beyond absolute role bound rejected"
    );
    assert!(
        call(
            &mut service,
            "POST",
            &route,
            &admin,
            json!({"leaf_not_after_behavior":"err"})
        )
        .status
            == 200,
        "current issuer error policy cannot erase captured older permit authority"
    );
    let state = service.state.as_ref().ok_or("actual three-mode state")?;
    assert!(
        state.schema == 89 && state.validate_format().is_ok(),
        "captured permit leaf survives issuer policy update"
    );
    let stored = pki_value(&service, "", "ca/")?;
    assert!(
        stored.0["issued"][&serial]["issuer_not_after_behavior"] == "permit"
            && stored.0["issued"][&serial]["role_leaf_profile"]["issuer_not_after_behavior"]
                == "permit",
        "actual independent private and signed public owner retain original policy"
    );
    let mut false_owner = serde_json::to_value(state)?;
    false_owner["engines"]["namespaces"][""]["mounts"]["ca/"]["backend"]["Pki"]["issued"]
        [&serial]["issuer_not_after_behavior"] = json!("err");
    let false_owner: State = serde_json::from_value(false_owner)?;
    assert!(
        false_owner.validate_format().is_err(),
        "received owner cannot erase captured beyond-CA permit"
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
        "encrypted actual issuer policy state reopens"
    );
    let read = call(
        &mut reopened,
        "GET",
        &format!("ca/cert/{serial}"),
        &admin,
        json!({}),
    );
    assert!(
        read.status == 200
            && read.body["data"]["certificate"] == pem
            && reopened
                .state
                .as_ref()
                .ok_or("reopened issuer state")?
                .validate_format()
                .is_ok(),
        "original signed permit leaf exact DER and owner survive policy changes and restart"
    );
    Ok(())
}

#[test]
fn pki_time89_external_permit_owner_survives_real_signer_retirement_and_last_tidy() -> TestResult {
    let remote = RemoteTransit::new_kind("ecdsa-p256")?;
    let (root, mut service, unseal, admin) = pki_fixture(&remote)?;
    let mut ca_body = body();
    ca_body["ttl"] = json!("10m");
    let generated = call(
        &mut service,
        "POST",
        "external-ca/root/generate/kms",
        &admin,
        ca_body,
    );
    assert!(generated.status == 200, "actual external shorter CA");
    let issuer = X509::from_pem(
        generated.body["data"]["certificate"]
            .as_str()
            .ok_or("actual external CA")?
            .as_bytes(),
    )?;
    let id = generated.body["data"]["issuer_id"]
        .as_str()
        .ok_or("actual external CA ID")?;
    assert!(
        call(
            &mut service,
            "POST",
            &format!("external-ca/issuer/{id}"),
            &admin,
            json!({"leaf_not_after_behavior":"permit"})
        )
        .status
            == 200,
        "actual external issuer policy"
    );
    let mut role = role_body(&default_profile());
    role["ttl"] = json!("20m");
    assert!(
        call(&mut service, "POST", "external-ca/roles/time", &admin, role).status == 200,
        "actual external time role"
    );
    let leaf = call(
        &mut service,
        "POST",
        "external-ca/issue/time",
        &admin,
        json!({"common_name":"leaf.example.test"}),
    );
    let (serial, pem) = signed_times(&leaf, &issuer, 70, 1300)?;
    let serial = serial.replace(':', "");
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
        "actual signer retirement retains leaf owner"
    );
    let stored = pki_value(&service, "", "external-ca/")?;
    assert!(
        stored.0["root"].is_null()
            && stored.0["issued"][&serial]["issuer_not_after_behavior"] == "permit"
            && stored.0["external"]["issued_public"][&serial]["issuer_not_after_behavior"]
                == "permit"
            && stored.0["issued"][&serial]["external_issuer_owner"]["issuer_id"] == id,
        "retired signer and independently captured time policy remain precisely owned"
    );
    let before = remote.calls()?;
    let read = call(
        &mut service,
        "GET",
        &format!("external-ca/cert/{serial}"),
        &admin,
        json!({}),
    );
    assert!(
        read.status == 200 && read.body["data"]["certificate"] == pem && remote.calls()? == before,
        "historical permit leaf reads actual signed bytes without KMS access"
    );
    let state = service.state.as_ref().ok_or("actual retired time owner")?;
    assert!(
        state.validate_format().is_ok(),
        "actual retired beyond-CA leaf validates against original archived issuer"
    );
    let mut altered = serde_json::to_value(state)?;
    altered["engines"]["namespaces"][""]["mounts"]["external-ca/"]["backend"]["Pki"]["external"]
        ["issued_public"][&serial]["issuer_not_after_behavior"] = json!("err");
    assert!(
        serde_json::from_value::<State>(altered)?
            .validate_format()
            .is_err(),
        "received external projection cannot replace independently captured permit"
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
        "retired original issuer and permit owner reopen encrypted"
    );
    let read = call(
        &mut reopened,
        "GET",
        &format!("external-ca/cert/{serial}"),
        &admin,
        json!({}),
    );
    assert!(
        read.status == 200 && read.body["data"]["certificate"] == pem,
        "retired permit leaf persists"
    );
    assert!(
        call(
            &mut reopened,
            "DELETE",
            "external-ca/roles/time",
            &admin,
            json!({})
        )
        .status
            == 204,
        "last time role removed"
    );
    assert!(
        reopened
            .handle_at(
                "POST",
                "external-ca/tidy",
                "",
                &admin,
                json!({"safety_buffer":"0s"}),
                1301
            )
            .status
            == 204,
        "actual expiry removes last retired policy owner"
    );
    let state = reopened.state.as_ref().ok_or("retired89 floor")?;
    assert!(
        state.schema == 89
            && state.writer_schema() == 89
            && !state.engines.has_pki_role_time_state()
            && state.validate_format().is_ok(),
        "sticky reader89 survives actual last issuer policy owner removal"
    );
    Ok(())
}
