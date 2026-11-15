//! Normal NativeV6Raft startup, actual three-node OpenRaft and pinned peer TLS.
//! Service::handle is the public dispatcher; no public HTTPS listener or
//! physical-host failure qualification is claimed by these process-local tests.
use super::formal_fixture::FormalPipeline;
use super::*;
use crate::service::native_raft_observation::tests::AuditFault;

const READS: [&str; 5] = [
    "sys/storage/raft/configuration",
    "sys/storage/raft/snapshot-status",
    "sys/storage/raft/linearizable-read",
    "sys/storage/raft/autopilot/state",
    "sys/storage/raft/autopilot/configuration",
];

impl FormalPipeline {
    fn token(
        &self,
        index: usize,
        name: &str,
        capabilities: &str,
        ttl: &str,
    ) -> TestResult<Zeroizing<String>> {
        let policy = format!("path \"sys/storage/raft/*\" {{ capabilities = [{capabilities}] }}");
        expect(
            self.call(
                index,
                "PUT",
                &format!("sys/policies/acl/{name}"),
                self.admin(),
                json!({"policy":policy}),
            )?,
            204,
            "formal-Raft-read-policy",
        )?;
        let mut issued = expect(self.call(index, "POST", "auth/token/create", self.admin(),
            json!({"policies":[name],"no_default_policy":true,"ttl":ttl,"explicit_max_ttl":ttl}))?,
            200, "formal-Raft-scoped-token")?;
        let token = secret_field(&mut issued, "/auth/client_token")?;
        erase_json(&mut issued.body);
        Ok(token)
    }

    fn read_all(&self, index: usize, leader: usize, token: &str) -> TestResult {
        let before = self.with_service(index, |service| {
            Ok(service.native_root.as_ref().ok_or("native root")?.clone())
        })?;
        for path in READS {
            let response = expect(self.call(index, "GET", path, token, json!({}))?, 200, path)?;
            assert!(response.body["data"].is_object(), "{path}");
            assert!(response.body.get("auth").is_none());
            match path {
                "sys/storage/raft/configuration" => {
                    let config = &response.body["data"]["config"];
                    assert_eq!(config["committed"], true);
                    assert_eq!(config["joint"], false);
                    assert!(config["index"].as_u64().is_some_and(|index| index > 0));
                    let servers = config["servers"]
                        .as_array()
                        .ok_or("configuration servers")?;
                    assert_eq!(servers.len(), 3);
                    for (node, server) in servers.iter().enumerate() {
                        assert_eq!(server["node_id"], (node + 1).to_string());
                        assert_eq!(server["leader"], node == leader);
                        assert_eq!(server["voter"], true);
                        assert_eq!(server["enrolled"], true);
                    }
                }
                "sys/storage/raft/linearizable-read" => {
                    assert_eq!(response.body["data"]["linearizable"], true);
                    assert_eq!(response.body["data"]["leader"], (leader + 1) as u64);
                    assert_eq!(
                        response.body["data"]["observation_scope"],
                        "native-raft-ReadIndex"
                    );
                    for field in ["term", "applied_index", "membership_index"] {
                        assert!(
                            response.body["data"][field]
                                .as_u64()
                                .is_some_and(|value| value > 0)
                        );
                    }
                }
                "sys/storage/raft/snapshot-status" => {
                    for field in ["applied_index", "membership_index"] {
                        assert!(
                            response.body["data"][field]
                                .as_u64()
                                .is_some_and(|value| value > 0)
                        );
                    }
                    for field in ["snapshot_index", "purged_index"] {
                        assert!(response.body["data"].get(field).is_some());
                    }
                }
                "sys/storage/raft/autopilot/state" => {
                    assert_eq!(response.body["data"]["committed"], true);
                    assert_eq!(response.body["data"]["joint"], false);
                    assert_eq!(response.body["data"]["voters"], json!(["1", "2", "3"]));
                    assert_eq!(response.body["data"]["leader"], (leader + 1).to_string());
                    assert_eq!(
                        response.body["data"]["servers"]
                            .as_object()
                            .ok_or("autopilot servers")?
                            .len(),
                        3
                    );
                }
                "sys/storage/raft/autopilot/configuration" => {
                    assert_eq!(
                        response.body["data"],
                        json!({
                            "cleanup_dead_servers":false,"last_contact_threshold":"10s",
                            "dead_server_last_contact_threshold":"86400s","max_trailing_logs":1000,
                            "min_quorum":3,"server_stabilization_time":"10s"
                        })
                    );
                }
                _ => return Err("unexpected Raft observation route".into()),
            }
        }
        self.with_service(index, |service| {
            native_auth::auth_only_root_change(
                &before,
                service.native_root.as_ref().ok_or("native root")?,
                false,
            )
            .map_err(|_| "Raft observation mutated a business owner")?;
            assert!(
                service
                    .state
                    .as_ref()
                    .ok_or("state")?
                    .raft_admin
                    .is_default()
            );
            assert!(service.pending_native_auth_delivery.is_none());
            assert!(!service.recovery_required);
            Ok(())
        })
    }
}

#[test]
fn formal_native_raft_five_reads_survive_forwarding_election_and_cold_rejoin() -> TestResult {
    let mut pipeline = FormalPipeline::start()?;
    let first = pipeline.ready_leader()?;
    for index in 0..3 {
        pipeline.read_all(index, first, pipeline.admin())?;
    }
    pipeline.stop_process(first)?;
    let next = pipeline.ready_leader()?;
    assert_ne!(next, first);
    pipeline.read_all(next, next, pipeline.admin())?;
    pipeline.assert_history(next, &[(1, "seed-v5")])?;
    pipeline.start_formal_process(first)?;
    pipeline.wait_cold_native_readindex_ready(first)?;
    pipeline.unseal(first)?;
    let current = pipeline.ready_leader()?;
    pipeline.read_all(first, current, pipeline.admin())?;
    pipeline.assert_history(first, &[(1, "seed-v5")])?;
    Ok(())
}

#[test]
fn formal_native_raft_read_acl_shape_and_clock_delivery_keep_all_writers_closed() -> TestResult {
    let pipeline = FormalPipeline::start()?;
    let leader = pipeline.ready_leader()?;
    let read = pipeline.token(leader, "raft-read-only", "\"read\"", "300s")?;
    let sudo = pipeline.token(leader, "raft-sudo-only", "\"sudo\"", "300s")?;
    let both = pipeline.token(leader, "raft-read-and-sudo", "\"read\",\"sudo\"", "300s")?;
    for path in READS {
        for token in ["", read.as_str(), sudo.as_str()] {
            let response = expect(
                pipeline.call(leader, "GET", path, token, json!({}))?,
                403,
                "read-and-sudo-required",
            )?;
            assert!(response.body.get("data").is_none());
        }
        for body in [json!({"unexpected":true}), json!("not-an-object")] {
            let response = expect(
                pipeline.call(leader, "GET", path, &both, body)?,
                400,
                "read-shape",
            )?;
            assert!(response.body.get("data").is_none());
        }
        for method in ["POST", "PUT"] {
            let response = expect(
                pipeline.call(leader, method, path, pipeline.admin(), json!({}))?,
                501,
                "no-Raft-writer-grant",
            )?;
            assert!(response.body.get("data").is_none());
        }
    }
    // A bounded actor drives the real terminal clock observation. Repeated
    // successful reads must retain business roots while consuming only that
    // actual Auth receipt; a fabricated generation is never supplied.
    pipeline.read_all(leader, leader, &both)?;
    pipeline.read_all(leader, leader, &both)?;
    let until = Instant::now() + REQUEST_BUDGET;
    let _scope = RequestDeadlineScope::enter(until);
    let mut writer = lock_until(pipeline.services[leader].as_ref().ok_or("service")?, until)
        .map_err(|_| "wrapped observation lock")?;
    let mut request = ServiceRequest::new("GET", READS[0], "", &both, json!({}));
    request.wrap_ttl_seconds = Some(30);
    let response = writer.handle_request(request);
    assert_eq!(response.status, 501);
    assert!(response.body.get("data").is_none() && response.body.get("wrap_info").is_none());
    Ok(())
}

#[test]
fn formal_native_raft_read_cannot_return_after_original_deadline_expires_at_audit() -> TestResult {
    let pipeline = FormalPipeline::start()?;
    let leader = pipeline.ready_leader()?;
    let fault = AuditFault::install(|_| {
        let until = crate::request_deadline::current();
        assert!(until.is_some(), "original request deadline");
        if let Some(until) = until {
            thread::sleep(
                until.saturating_duration_since(Instant::now()) + Duration::from_millis(20),
            );
        }
    });
    let until = Instant::now() + REQUEST_BUDGET;
    let _scope = RequestDeadlineScope::enter(until);
    let mut writer = lock_until(pipeline.services[leader].as_ref().ok_or("service")?, until)
        .map_err(|_| "deadline observation lock")?;
    let response = writer.handle("GET", READS[0], "", pipeline.admin(), json!({}));
    assert!(
        fault.reached(),
        "the actual successful response audit must precede expiry"
    );
    assert_eq!(response.status, 503);
    assert!(response.body.get("data").is_none());
    assert!(response.consistency_index.is_none());
    assert!(writer.pending_native_auth_delivery.is_none());
    Ok(())
}

#[test]
fn formal_native_raft_read_rechecks_original_actor_after_actual_audit() -> TestResult {
    let pipeline = FormalPipeline::start()?;
    let leader = pipeline.ready_leader()?;
    let token = pipeline.token(leader, "raft-expiring-read", "\"read\",\"sudo\"", "2s")?;
    let fault = AuditFault::install(|_| thread::sleep(Duration::from_millis(2100)));
    let response = pipeline.call(leader, "GET", READS[2], &token, json!({}))?;
    assert!(
        fault.reached(),
        "the actor must survive through the actual response audit"
    );
    assert_eq!(response.status, 403);
    assert!(response.body.get("data").is_none());
    assert!(response.consistency_index.is_none());
    Ok(())
}

#[test]
fn formal_native_raft_read_vetoes_warm_policy_tampering_after_actual_audit() -> TestResult {
    fn change_min_quorum(service: &mut Service) -> TestResult {
        let state = service.state.as_mut().ok_or("installed state")?;
        let mut policy = serde_json::to_value(&state.raft_admin)?;
        policy["config"]["min_quorum"] = json!(4);
        state.raft_admin = serde_json::from_value::<raft_admin::RaftAdminState>(policy)?.into();
        Ok(())
    }
    let pipeline = FormalPipeline::start()?;
    let leader = pipeline.ready_leader()?;
    let fault = AuditFault::install(|service| {
        assert!(
            change_min_quorum(service).is_ok(),
            "valid synthetic policy mutation"
        );
    });
    let response = pipeline.call(leader, "GET", READS[4], pipeline.admin(), json!({}))?;
    assert!(fault.reached());
    assert_eq!(response.status, 503);
    assert!(response.body.get("data").is_none());
    assert!(response.consistency_index.is_none());
    Ok(())
}

#[test]
fn formal_native_raft_five_reads_reject_actual_lost_quorum() -> TestResult {
    let mut pipeline = FormalPipeline::start()?;
    let leader = pipeline.ready_leader()?;
    pipeline.read_all(leader, leader, pipeline.admin())?;
    for index in (0..3).filter(|index| *index != leader) {
        pipeline.stop_process(index)?;
    }
    for path in READS {
        let response = expect(
            pipeline.call(leader, "GET", path, pipeline.admin(), json!({}))?,
            503,
            "actual-quorum-lost",
        )?;
        assert!(response.body.get("data").is_none());
        assert!(response.consistency_index.is_none());
    }
    Ok(())
}

#[test]
fn formal_native_raft_audited_reply_status_tampering_cannot_bypass_delivery_custody() -> TestResult
{
    let pipeline = FormalPipeline::start()?;
    let leader = pipeline.ready_leader()?;
    let fault = AuditFault::install_reply(|response| {
        // This is the original successful response after its actual mandatory
        // audit. Change only its status; retaining data must never make an
        // error-shaped reply eligible for the unowned early-return exception.
        assert_eq!(response.status, 200);
        assert!(response.body.get("data").is_some());
        response.status = 503;
    });
    let response = pipeline.call(leader, "GET", READS[0], pipeline.admin(), json!({}))?;
    assert!(fault.reached());
    assert_eq!(response.status, 503);
    assert!(response.body.get("data").is_none());
    assert!(response.consistency_index.is_none());
    pipeline.with_service(leader, |service| {
        assert!(service.pending_native_auth_delivery.is_none());
        assert!(!service.recovery_required);
        Ok(())
    })?;
    Ok(())
}
