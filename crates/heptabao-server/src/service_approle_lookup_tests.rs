//! Real Service reads, durable identity, mandatory audit, and original-owner vetoes.
use super::*;
use crate::service::tests::{Root, bootstrap};
type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

fn clock(now: u64) -> TestResult<RequestClock> {
    Ok(RequestClock::anchored(
        Duration::new(now, 1),
        Instant::now(),
    )?)
}
struct Operation<'a> {
    namespace: &'a str,
    token: &'a str,
    method: &'a str,
    path: &'a str,
    body: Value,
    wrap: Option<u64>,
}
fn request(service: &mut Service, now: u64, operation: Operation<'_>) -> TestResult<Response> {
    let started = Instant::now();
    let _scope =
        crate::request_deadline::RequestDeadlineScope::enter(started + Duration::from_secs(15));
    let at = clock(now)?;
    let execution = service.begin_at_mode_precise(
        RequestDispatch {
            method: operation.method,
            path: operation.path,
            namespace: operation.namespace,
            token: operation.token,
            body: operation.body,
            now,
            allow_forward: true,
            enforce_namespace: true,
            wrap_ttl_seconds: operation.wrap,
            origin_peer: None,
            client_certificates: None,
        },
        at,
    );
    Ok(service.finish_synchronous_request(execution))
}
fn write(
    service: &mut Service,
    admin: &str,
    namespace: &str,
    path: &str,
    body: Value,
) -> TestResult<Response> {
    request(
        service,
        100,
        Operation {
            namespace,
            token: admin,
            method: "POST",
            path,
            body,
            wrap: None,
        },
    )
}
fn fixture(service: &mut Service, admin: &str) -> TestResult {
    // This real namespace publication creates a record-backed graph before reads.
    assert_eq!(
        write(service, admin, "", "sys/namespaces/lookupchild", json!({}))?.status,
        200
    );
    for namespace in ["", "lookupchild"] {
        for mount in ["lookup", "other"] {
            assert_eq!(
                write(
                    service,
                    admin,
                    namespace,
                    &format!("sys/auth/{mount}"),
                    json!({"type":"approle"})
                )?
                .status,
                204
            );
            for role in ["owner", "wrong"] {
                assert_eq!(
                    write(
                        service,
                        admin,
                        namespace,
                        &format!("auth/{mount}/role/{role}"),
                        json!({"secret_id_ttl":0,"token_ttl":60})
                    )?
                    .status,
                    204
                );
            }
        }
    }
    assert!(service.record_root.is_some());
    assert!(
        !service
            .state
            .as_ref()
            .ok_or("state")?
            .has_token_api_precision_state()
    );
    Ok(())
}
fn issue(
    service: &mut Service,
    admin: &str,
    namespace: &str,
    ttl: u64,
) -> TestResult<(String, String)> {
    let response = write(
        service,
        admin,
        namespace,
        "auth/lookup/role/owner/secret-id",
        json!({"ttl":ttl,"metadata":r#"{"build":"lookup-owner"}"#}),
    )?;
    assert_eq!(response.status, 200);
    Ok((
        response.body["data"]["secret_id"]
            .as_str()
            .ok_or("actual SID")?
            .to_owned(),
        response.body["data"]["secret_id_accessor"]
            .as_str()
            .ok_or("actual accessor")?
            .to_owned(),
    ))
}
fn lookup(
    service: &mut Service,
    admin: &str,
    namespace: &str,
    mount: &str,
    role: &str,
    pair: &(String, String),
    accessor: bool,
) -> TestResult<Response> {
    let path = format!(
        "auth/{mount}/role/{role}/{}",
        if accessor {
            "secret-id-accessor/lookup"
        } else {
            "secret-id/lookup"
        }
    );
    request(
        service,
        200,
        Operation {
            namespace,
            token: admin,
            method: "POST",
            path: &path,
            body: if accessor {
                json!({"secret_id_accessor":pair.1})
            } else {
                json!({"secret_id":pair.0})
            },
            wrap: None,
        },
    )
}
fn fast(
    service: &mut Service,
    admin: &str,
    pair: &(String, String),
    at: RequestClock,
) -> TestResult<Response> {
    let body = json!({"secret_id":pair.0});
    let request = RequestView {
        method: "POST",
        path: "auth/lookup/role/owner/secret-id/lookup",
        namespace: "",
        token: admin,
        body: &body,
        now: at.admitted_at().seconds(),
        admission_started: at.started(),
        token_clock: Some(at),
        allow_forward: true,
        enforce_namespace: true,
        wrap_ttl_seconds: None,
        origin_peer: None,
        client_certificates: None,
    };
    let response = service
        .immutable_approle_lookup_response(&request)
        .ok_or("actual immutable dispatch")?;
    assert!(
        service
            .pending_ordinary_kv_authority
            .as_ref()
            .is_some_and(|owner| owner.is_approle_lookup())
    );
    Ok(response)
}
fn finish_fast(
    service: &mut Service,
    response: Response,
    at: RequestClock,
) -> TestResult<Response> {
    let response = service.audit_completed_response(
        "lookup-real-audit",
        at.admitted_at().seconds(),
        Some(at),
        response,
    );
    let owner = service
        .pending_ordinary_kv_authority
        .take()
        .ok_or("actual audited owner")?;
    Ok(service.complete_ordinary_kv_delivery(owner, response, "lookup-real-audit"))
}
fn auth_bytes(service: &Service) -> TestResult<Zeroizing<Vec<u8>>> {
    Ok(owner_store::serialize_owner(
        &service.state.as_ref().ok_or("state")?.auth,
    )?)
}
fn state_bytes(service: &Service) -> TestResult<Zeroizing<Vec<u8>>> {
    Ok(owner_store::serialize_owner(
        service.state.as_ref().ok_or("state")?,
    )?)
}
fn fingerprint_state(
    service: &Service,
) -> TestResult<(crate::state_record_root::StateIdentity, u64)> {
    Ok((
        service.current_state_identity().map_err(|_| "identity")?,
        service.durable.as_ref().ok_or("durable")?.generation(),
    ))
}
#[test]
fn approle_lookup_actual_populated_borrowed_reads_keep_auth_state_identity_and_generation()
-> TestResult {
    let files = Root::new();
    let mut service = files.service()?;
    let (_, admin) = bootstrap(&mut service)?;
    fixture(&mut service, &admin)?;
    let mut pairs = Vec::new();
    for _ in 0..257 {
        pairs.push(issue(&mut service, &admin, "", 1)?);
    }
    let auth_before = auth_bytes(&service)?;
    let state_before = state_bytes(&service)?;
    let identity = fingerprint_state(&service)?;
    let at = clock(200)?;
    // Already expired stored SIDs remain administratively visible until genuine tidy.
    let projected = fast(&mut service, &admin, &pairs[0], at)?;
    assert_eq!(projected.status, 200);
    assert_eq!(projected.body["data"]["metadata"]["build"], "lookup-owner");
    assert_eq!(finish_fast(&mut service, projected, at)?.status, 200);
    for pair in &pairs {
        assert_eq!(
            lookup(&mut service, &admin, "", "lookup", "owner", pair, false)?.status,
            200
        );
        assert_eq!(
            lookup(&mut service, &admin, "", "lookup", "owner", pair, true)?.status,
            200
        );
    }
    assert!(auth_bytes(&service)?.as_slice() == auth_before.as_slice());
    assert!(state_bytes(&service)?.as_slice() == state_before.as_slice());
    assert_eq!(fingerprint_state(&service)?, identity);
    assert!(service.pending_ordinary_kv_authority.is_none());
    let audit = std::fs::read_to_string(files.path.join("audit.jsonl"))?;
    assert!(
        audit
            .lines()
            .filter_map(|line| serde_json::from_str::<Value>(line).ok())
            .any(|row| row["event"]["kind"] == "response" && row["event"]["status"] == 200)
    );
    Ok(())
}
#[test]
fn approle_lookup_wrong_role_204_requires_present_same_mount_accessor_and_deleted_404() -> TestResult
{
    let files = Root::new();
    let mut service = files.service()?;
    let (_, admin) = bootstrap(&mut service)?;
    fixture(&mut service, &admin)?;
    let pair = issue(&mut service, &admin, "", 0)?;
    let child = issue(&mut service, &admin, "lookupchild", 0)?;
    let before = state_bytes(&service)?;
    let identity = fingerprint_state(&service)?;
    assert_eq!(
        lookup(&mut service, &admin, "", "lookup", "wrong", &pair, true)?.status,
        204
    );
    assert_eq!(
        lookup(&mut service, &admin, "", "other", "owner", &pair, true)?.status,
        404
    );
    assert_eq!(
        lookup(
            &mut service,
            &admin,
            "lookupchild",
            "lookup",
            "owner",
            &pair,
            true
        )?
        .status,
        404
    );
    assert_eq!(
        lookup(&mut service, &admin, "", "lookup", "owner", &child, true)?.status,
        404
    );
    assert_eq!(
        lookup(
            &mut service,
            &admin,
            "lookupchild",
            "lookup",
            "owner",
            &child,
            true
        )?
        .status,
        200
    );
    assert_eq!(
        lookup(&mut service, &admin, "", "lookup", "owner", &pair, false)?.status,
        200
    );
    assert!(state_bytes(&service)?.as_slice() == before.as_slice());
    assert_eq!(fingerprint_state(&service)?, identity);
    assert_eq!(
        write(
            &mut service,
            &admin,
            "",
            "auth/lookup/role/owner/secret-id/destroy",
            json!({"secret_id":pair.0})
        )?
        .status,
        204
    );
    assert_eq!(
        lookup(&mut service, &admin, "", "lookup", "wrong", &pair, true)?.status,
        404
    );
    assert_eq!(
        lookup(&mut service, &admin, "", "lookup", "owner", &pair, true)?.status,
        404
    );
    assert_eq!(
        lookup(&mut service, &admin, "", "lookup", "owner", &pair, false)?.status,
        204
    );
    assert_eq!(
        lookup(
            &mut service,
            &admin,
            "lookupchild",
            "lookup",
            "owner",
            &child,
            true
        )?
        .status,
        200
    );
    Ok(())
}
#[test]
fn approle_lookup_update_acl_unknown_fields_invalid_and_revoked_actor_still_deny() -> TestResult {
    let files = Root::new();
    let mut service = files.service()?;
    let (_, admin) = bootstrap(&mut service)?;
    fixture(&mut service, &admin)?;
    let pair = issue(&mut service, &admin, "", 0)?;
    let path = "auth/lookup/role/owner/secret-id/lookup";
    for body in [json!({"secret_id":pair.0,"after":"fake"}), json!({})] {
        assert_eq!(write(&mut service, &admin, "", path, body)?.status, 400);
    }
    assert_eq!(
        request(
            &mut service,
            100,
            Operation {
                namespace: "",
                token: "hvs.invalid",
                method: "POST",
                path,
                body: json!({"secret_id":pair.0}),
                wrap: None
            }
        )?
        .status,
        403
    );
    assert_eq!(
        request(
            &mut service,
            100,
            Operation {
                namespace: "",
                token: &admin,
                method: "GET",
                path,
                body: json!({"secret_id":pair.0}),
                wrap: None
            }
        )?
        .status,
        404
    );
    assert_eq!(write(&mut service,&admin,"","sys/policies/acl/lookup-reader",
        json!({"policy":r#"path "auth/lookup/role/owner/secret-id/lookup" { capabilities=["read"] }"#}))?.status,204);
    let token = write(
        &mut service,
        &admin,
        "",
        "auth/token/create",
        json!({"policies":["lookup-reader"],"no_default_policy":true,"ttl":"10m"}),
    )?;
    assert_eq!(token.status, 200);
    let actor = token.body["auth"]["client_token"].as_str().ok_or("actor")?;
    assert_eq!(
        lookup(&mut service, actor, "", "lookup", "owner", &pair, false)?.status,
        403
    );
    assert_eq!(
        write(
            &mut service,
            &admin,
            "",
            "auth/token/revoke",
            json!({"token":actor})
        )?
        .status,
        204
    );
    assert_eq!(
        lookup(&mut service, actor, "", "lookup", "owner", &pair, false)?.status,
        403
    );
    Ok(())
}
#[test]
fn approle_lookup_finite_actor_wrap_and_precise_floor_keep_original_mutating_path() -> TestResult {
    let files = Root::new();
    let mut service = files.service()?;
    let (_, admin) = bootstrap(&mut service)?;
    fixture(&mut service, &admin)?;
    let pair = issue(&mut service, &admin, "", 0)?;
    let path = "auth/lookup/role/owner/secret-id/lookup";
    assert_eq!(write(&mut service,&admin,"","sys/policies/acl/lookup-updater",
        json!({"policy":r#"path "auth/lookup/role/owner/secret-id/lookup" { capabilities=["update"] }"#}))?.status,204);
    let created = write(
        &mut service,
        &admin,
        "",
        "auth/token/create",
        json!({"policies":["lookup-updater"],"no_default_policy":true,"num_uses":1,"ttl":"10m"}),
    )?;
    assert_eq!(created.status, 200);
    let actor = created.body["auth"]["client_token"]
        .as_str()
        .ok_or("finite actor")?;
    let before = fingerprint_state(&service)?;
    assert_eq!(
        lookup(&mut service, actor, "", "lookup", "owner", &pair, false)?.status,
        200
    );
    assert_eq!(
        lookup(&mut service, actor, "", "lookup", "owner", &pair, false)?.status,
        403
    );
    assert!(
        service
            .state
            .as_ref()
            .ok_or("precise state")?
            .has_token_api_precision_state()
    );
    assert!(fingerprint_state(&service)?.1 > before.1);
    let wrapped = request(
        &mut service,
        200,
        Operation {
            namespace: "",
            token: &admin,
            method: "POST",
            path,
            body: json!({"secret_id":pair.0}),
            wrap: Some(60),
        },
    )?;
    assert_eq!(wrapped.status, 200);
    let wrapper = wrapped.body["wrap_info"]["token"]
        .as_str()
        .ok_or("actual wrapper")?;
    let unwrapped = request(
        &mut service,
        200,
        Operation {
            namespace: "",
            token: wrapper,
            method: "POST",
            path: "sys/wrapping/unwrap",
            body: json!({}),
            wrap: None,
        },
    )?;
    assert_eq!(unwrapped.status, 200);
    assert_eq!(unwrapped.body["data"]["metadata"]["build"], "lookup-owner");
    assert_eq!(
        request(
            &mut service,
            200,
            Operation {
                namespace: "",
                token: wrapper,
                method: "POST",
                path: "sys/wrapping/unwrap",
                body: json!({}),
                wrap: None
            }
        )?
        .status,
        400
    );
    Ok(())
}
#[test]
fn approle_lookup_private_response_is_erased_after_real_cow_mount_tune_or_recreate() -> TestResult {
    for scenario in [
        "cow",
        "tune",
        "recreate",
        "revoke",
        "sealed",
        "target-delete",
        "target-role-update",
    ] {
        let files = Root::new();
        let mut service = files.service()?;
        let (_, admin) = bootstrap(&mut service)?;
        fixture(&mut service, &admin)?;
        let pair = issue(&mut service, &admin, "", 0)?;
        let at = clock(200)?;
        let response = fast(&mut service, &admin, &pair, at)?;
        assert_eq!(response.status, 200);
        let owner = service
            .pending_ordinary_kv_authority
            .take()
            .ok_or("held original owner")?;
        match scenario {
            "cow" => {
                assert_eq!(
                    write(
                        &mut service,
                        &admin,
                        "",
                        "secret/data/unrelated",
                        json!({"data":{"current":"other"}})
                    )?
                    .status,
                    200
                );
            }
            "tune" => {
                assert_eq!(
                    write(
                        &mut service,
                        &admin,
                        "",
                        "sys/auth/lookup/tune",
                        json!({"description":"changed lookup mount"})
                    )?
                    .status,
                    204
                );
            }
            "recreate" => {
                assert_eq!(
                    request(
                        &mut service,
                        100,
                        Operation {
                            namespace: "",
                            token: &admin,
                            method: "DELETE",
                            path: "sys/auth/lookup",
                            body: json!({}),
                            wrap: None
                        }
                    )?
                    .status,
                    204
                );
                assert_eq!(
                    write(
                        &mut service,
                        &admin,
                        "",
                        "sys/auth/lookup",
                        json!({"type":"approle"})
                    )?
                    .status,
                    204
                );
            }
            "target-delete" => {
                assert_eq!(
                    write(
                        &mut service,
                        &admin,
                        "",
                        "auth/lookup/role/owner/secret-id/destroy",
                        json!({"secret_id":pair.0})
                    )?
                    .status,
                    204
                );
            }
            "target-role-update" => {
                assert_eq!(
                    write(
                        &mut service,
                        &admin,
                        "",
                        "auth/lookup/role/owner",
                        json!({"token_ttl":120})
                    )?
                    .status,
                    204
                );
            }
            "revoke" => {
                assert_eq!(
                    write(
                        &mut service,
                        &admin,
                        "",
                        "auth/token/revoke-self",
                        json!({})
                    )?
                    .status,
                    204
                );
            }
            _ => {
                assert_eq!(
                    write(&mut service, &admin, "", "sys/seal", json!({}))?.status,
                    204
                );
            }
        }
        service.pending_ordinary_kv_authority = Some(owner);
        let delivered = finish_fast(&mut service, response, at)?;
        assert_eq!(delivered.status, 503);
        assert!(delivered.body.get("data").is_none());
        assert!(delivered.consistency_index.is_none());
    }
    Ok(())
}
#[test]
fn approle_lookup_successfully_captured_original_deadline_cannot_be_rearmed_at_delivery()
-> TestResult {
    let files = Root::new();
    let mut service = files.service()?;
    let (_, admin) = bootstrap(&mut service)?;
    fixture(&mut service, &admin)?;
    let pair = issue(&mut service, &admin, "", 0)?;
    let deadline = Instant::now() + Duration::from_secs(2);
    let response = {
        let _scope = crate::request_deadline::RequestDeadlineScope::enter(deadline);
        fast(&mut service, &admin, &pair, clock(200)?)?
    };
    assert_eq!(response.status, 200);
    assert!(Instant::now() < deadline);
    let identity = fingerprint_state(&service)?;
    while Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(5));
    }
    let delivered = finish_fast(&mut service, response, clock(200)?)?;
    assert_eq!(delivered.status, 503);
    assert!(delivered.body.get("data").is_none());
    assert_eq!(fingerprint_state(&service)?, identity);
    Ok(())
}
#[test]
fn approle_lookup_response_audit_failure_fences_and_erases_the_borrowed_result() -> TestResult {
    let files = Root::new();
    let mut service = files.service()?;
    let (_, admin) = bootstrap(&mut service)?;
    fixture(&mut service, &admin)?;
    let pair = issue(&mut service, &admin, "", 0)?;
    let at = clock(200)?;
    let response = fast(&mut service, &admin, &pair, at)?;
    let identity = fingerprint_state(&service)?;
    service.audit_capacity = service.audit.metadata()?.len();
    let delivered = finish_fast(&mut service, response, at)?;
    assert_eq!(delivered.status, 503);
    assert!(delivered.body.get("data").is_none());
    assert!(service.recovery_required);
    assert_eq!(fingerprint_state(&service)?, identity);
    Ok(())
}
#[test]
fn approle_lookup_fixed_ha_owner_rejects_same_node_returned_in_a_real_higher_term() -> TestResult {
    let files = Root::new();
    let mut service = files.service()?;
    let (_, admin) = bootstrap(&mut service)?;
    fixture(&mut service, &admin)?;
    let pair = issue(&mut service, &admin, "", 0)?;
    let cluster_id = service.state.as_ref().ok_or("state")?.cluster_id.clone();
    let cluster =
        crate::ha::snapshot_test_support::Cluster::new(&files.path.join("raft"), &cluster_id)?;
    service.ha = Some(Arc::clone(&cluster.processes[0]));
    service.sync_from_ha().map_err(|_| "actual HA prefix")?;
    let at = clock(200)?;
    let response = fast(&mut service, &admin, &pair, at)?;
    let before = cluster.processes[0]
        .lock()
        .map_err(|_| "HA")?
        .leader_status()?;
    let identity = fingerprint_state(&service)?;
    let next = cluster.processes[0]
        .lock()
        .map_err(|_| "first HA")?
        .step_down()?;
    assert_ne!(next, 1);
    let returned = cluster.processes[(next - 1) as usize]
        .lock()
        .map_err(|_| "next HA")?
        .step_down()?;
    assert_eq!(returned, 1);
    let after = cluster.processes[0]
        .lock()
        .map_err(|_| "HA")?
        .leader_status()?;
    assert!(after.local_is_leader && after.leader == Some(1) && after.term > before.term);
    let delivered = finish_fast(&mut service, response, at)?;
    assert_eq!(delivered.status, 503);
    assert!(delivered.body.get("data").is_none());
    assert_eq!(fingerprint_state(&service)?, identity);
    Ok(())
}

#[test]
fn approle_lookup_historical_owner_retains_legacy_projection_without_record_grant() -> TestResult {
    let files = Root::new();
    let mut service = files.service()?;
    let (key, admin) = crate::service::tests::bootstrap_unmounted(&mut service)?;
    assert!(service.record_root.is_none());
    // Explicit historical V4 writer input. Current Service mount mutations
    // publish a record graph, so use actual Auth routes to produce the old
    // payload before its normal authenticated AEAD publication and reopen.
    // The existing root token authenticates this producer; no principal or
    // record grant is synthesized and no current record owner is discarded.
    let mut historical = service.state.clone().ok_or("historical V4 state")?;
    assert!(historical.engines.record_root().is_none());
    let principal = historical
        .auth
        .authenticate(&admin, 100)
        .map_err(|_| "historical producer authentication")?;
    for (path, body) in [
        ("sys/auth/lookup", json!({"type":"approle"})),
        ("auth/lookup/role/owner", json!({"secret_id_ttl":0})),
    ] {
        let result = historical
            .auth
            .handle(Some(&principal), "", "POST", path, &body, 100)
            .map_err(|_| "historical authenticated Auth route")?
            .ok_or("historical Auth route response")?;
        assert_eq!(result.status, 204);
        assert!(result.mutated);
    }
    let mut issued = historical
        .auth
        .handle(
            Some(&principal),
            "",
            "POST",
            "auth/lookup/role/owner/secret-id",
            &json!({"ttl":0,"metadata":r#"{"build":"lookup-owner"}"#}),
            100,
        )
        .map_err(|_| "historical actual SID producer")?
        .ok_or("historical SID response")?;
    assert_eq!(issued.status, 200);
    assert!(issued.mutated);
    let pair = (
        issued.body["data"]["secret_id"]
            .as_str()
            .ok_or("historical actual SID")?
            .to_owned(),
        issued.body["data"]["secret_id_accessor"]
            .as_str()
            .ok_or("historical actual accessor")?
            .to_owned(),
    );
    erase_json(&mut issued.body);
    historical
        .validate_format()
        .map_err(|_| "historical V4 format")?;
    crate::service::tests::commit_legacy_state_fixture(&mut service, &historical)
        .map_err(|_| "historical authenticated V4 publication")?;
    service.state = Some(historical);
    assert!(service.record_root.is_none());
    drop(service);
    let mut service = files.service()?;
    assert_eq!(
        request(
            &mut service,
            100,
            Operation {
                namespace: "",
                token: "",
                method: "PUT",
                path: "sys/unseal",
                body: json!({"key":key}),
                wrap: None,
            },
        )?
        .status,
        200
    );
    assert!(service.record_root.is_none());
    let before = auth_bytes(&service)?;
    let identity = fingerprint_state(&service)?;
    assert_eq!(
        lookup(&mut service, &admin, "", "lookup", "owner", &pair, false)?.status,
        200
    );
    assert_eq!(
        lookup(&mut service, &admin, "", "lookup", "owner", &pair, true)?.status,
        200
    );
    assert!(auth_bytes(&service)?.as_slice() == before.as_slice());
    assert_eq!(fingerprint_state(&service)?, identity);
    assert!(service.pending_ordinary_kv_authority.is_none());
    Ok(())
}
