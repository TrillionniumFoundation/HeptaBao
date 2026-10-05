//! Real three-node Raft/application commit + Service audit. The fixture does
//! not claim mTLS networking; unchanged native HA runner covers that separately.
use super::super::tests::{Root, bootstrap, call};
use super::*;
use crate::ha_forward_completion::{CompletionWire, digest, response_digest};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;
type TestCompletion = (Response, CompletionWire, Vec<u8>, [u8; 32], Instant);

fn clock() -> TestResult<RequestClock> {
    Ok(RequestClock::anchored(
        SystemTime::now().duration_since(UNIX_EPOCH)?,
        Instant::now(),
    )?)
}
fn native(service: &mut Service, method: &str, path: &str, token: &str, body: Value) -> Response {
    let execution = service.begin_request_before(
        ServiceRequest {
            method,
            path,
            namespace: "",
            token,
            body,
            wrap_ttl_seconds: None,
            origin_peer: None,
            client_certificates: None,
        },
        Instant::now() + Duration::from_secs(10),
        true,
    );
    service.finish_synchronous_request(execution)
}
fn prepare_with_ttl(
    root: &Root,
    ttl: &str,
) -> TestResult<(
    Service,
    crate::ha::snapshot_test_support::Cluster,
    String,
    String,
)> {
    let (service, cluster, actor, accessor, _) = prepare_with_ttl_and_root(root, ttl)?;
    Ok((service, cluster, actor, accessor))
}
fn prepare_with_ttl_and_root(
    root: &Root,
    ttl: &str,
) -> TestResult<(
    Service,
    crate::ha::snapshot_test_support::Cluster,
    String,
    String,
    String,
)> {
    let mut service = root.service()?;
    let (_, token) = bootstrap(&mut service)?;
    assert_eq!(
        call(
            &mut service,
            "PUT",
            "sys/policies/acl/forward-test",
            &token,
            json!({"policy":r#"path "secret/data/completion" {capabilities=["read"]}"#})
        )
        .status,
        204
    );
    assert_eq!(
        call(
            &mut service,
            "PUT",
            "secret/data/completion",
            &token,
            json!({"data":{"value":"completed-on-leader"}})
        )
        .status,
        200
    );
    let id = service.state.as_ref().ok_or("state")?.cluster_id.clone();
    let cluster = crate::ha::snapshot_test_support::Cluster::new(&root.path.join("raft"), &id)?;
    service.ha = Some(Arc::clone(&cluster.processes[0]));
    service.sync_from_ha().map_err(|_| "initial HA state")?;
    let minted = native(
        &mut service,
        "POST",
        "auth/token/create",
        &token,
        json!({"ttl":ttl,"num_uses":2,"policies":["forward-test"],"no_default_policy":true}),
    );
    assert_eq!(minted.status, 200, "{}", minted.body);
    assert!(
        service
            .state
            .as_ref()
            .ok_or("state")?
            .has_token_api_precision_state()
    );
    let actor = minted.body["auth"]["client_token"]
        .as_str()
        .ok_or("actor")?
        .to_owned();
    let accessor = minted.body["auth"]["accessor"]
        .as_str()
        .ok_or("accessor")?
        .to_owned();
    Ok((service, cluster, actor, accessor, token))
}
fn prepare(
    root: &Root,
) -> TestResult<(
    Service,
    crate::ha::snapshot_test_support::Cluster,
    String,
    String,
)> {
    prepare_with_ttl(root, "10m")
}
fn leader_completion(service: &mut Service, actor: &str) -> TestResult<TestCompletion> {
    let nonce = crate::crypto::random::<32>()?;
    let cluster = service.state.as_ref().ok_or("state")?.cluster_id.clone();
    let body = json!({});
    let request = crate::ha_forward::encode_completed_index_request_for_cluster(
        &cluster,
        (2, 1),
        &crate::ha_forward::ForwardContext {
            method: "GET",
            path: "secret/data/completion",
            namespace: "",
            token: actor,
            body: &body,
            wrap_ttl_seconds: None,
            client_certificates: None,
            origin_peer: None,
            caller_deadline: None,
        },
        Some(nonce),
    )?;
    let deadline = Instant::now() + Duration::from_secs(10);
    let scope = CompletionScope::enter(Some(nonce), &request, deadline, &cluster, 1, false);
    let response = native(service, "GET", "secret/data/completion", actor, json!({}));
    assert_eq!(response.status, 200, "{}", response.body);
    service.seal_forward_completion(&response);
    let wire = scope
        .finish()
        .ok_or("genuine Service completion is absent")?;
    assert!(scope.finish().is_none(), "same completion is affine");
    assert!(wire.precise && wire.floor.is_some() && wire.audit_sequence > 0);
    Ok((response, wire, request, nonce, deadline))
}
fn uses(service: &Service, accessor: &str) -> TestResult<u64> {
    let auth = serde_json::to_value(&service.state.as_ref().ok_or("state")?.auth)?;
    Ok(auth["tokens"]
        .as_object()
        .ok_or("tokens")?
        .values()
        .find(|token| token["accessor"] == accessor)
        .and_then(|token| token["uses_remaining"].as_u64())
        .ok_or("uses")?)
}
#[test]
fn completed_forward_precise_follower_audits_without_second_floor_or_use() -> TestResult {
    let files = Root::new();
    let (mut service, cluster, actor, accessor) = prepare(&files)?;
    let (response, wire, request, nonce, deadline) = leader_completion(&mut service, &actor)?;
    let cluster_id = service.state.as_ref().ok_or("state")?.cluster_id.clone();
    let receipt = CompletedForwardReceipt::verified(
        wire,
        crate::ha_forward_completion::CompletedExchange {
            cluster: cluster_id,
            source: 1,
            target: 2,
            deadline,
            nonce,
            request: &request,
            response_digest: response_digest(&response)?,
        },
    )?;
    assert_eq!(uses(&service, &accessor)?, 1);
    service.ha = Some(Arc::clone(&cluster.processes[1]));
    let authority = service
        .stage_forward_delivery(
            receipt,
            Arc::clone(&cluster.processes[1]),
            "",
            Some(clock()?),
            100,
        )
        .map_err(|_| "follower original owner")?;
    service.pending_forward_delivery = Some(PendingForwardDelivery::Completed(Box::new(authority)));
    let before = serde_json::to_vec(service.state.as_ref().ok_or("state")?)?;
    let floor = service
        .state
        .as_ref()
        .ok_or("state")?
        .auth
        .terminal_token_clock_floor();
    let sequence = service.audit_sequence;
    let raft = cluster.processes[1]
        .lock()
        .map_err(|_| "HA")?
        .leader_status()?
        .committed_index;
    let response =
        service.audit_completed_response("original-forward-fixture", 100, Some(clock()?), response);
    let response = service.complete_forward_delivery(response, "original-forward-fixture");
    assert_eq!(response.status, 200, "{}", response.body);
    assert_eq!(
        response.body["data"]["data"]["value"],
        "completed-on-leader"
    );
    assert_eq!(
        service.audit_sequence,
        sequence + 1,
        "follower mandatory audit remains"
    );
    assert_eq!(
        serde_json::to_vec(service.state.as_ref().ok_or("state")?)?,
        before
    );
    assert_eq!(
        service
            .state
            .as_ref()
            .ok_or("state")?
            .auth
            .terminal_token_clock_floor(),
        floor
    );
    assert_eq!(
        uses(&service, &accessor)?,
        1,
        "no second finite-use consume"
    );
    assert_eq!(
        cluster.processes[1]
            .lock()
            .map_err(|_| "HA")?
            .leader_status()?
            .committed_index,
        raft
    );
    assert!(service.pending_forward_delivery.is_none());
    drop(service);
    drop(cluster);
    Ok(())
}
#[test]
fn completed_forward_nonce_payload_and_deadline_reject_real_completion() -> TestResult {
    let files = Root::new();
    let (mut service, cluster, actor, _accessor) = prepare(&files)?;
    let (response, wire, request, nonce, deadline) = leader_completion(&mut service, &actor)?;
    let cluster_id = service.state.as_ref().ok_or("state")?.cluster_id.clone();
    let raw = serde_json::to_vec(&wire)?;
    let decoded = || -> TestResult<CompletionWire> { Ok(serde_json::from_slice(&raw)?) };
    let mut wrong_nonce = nonce;
    wrong_nonce[0] ^= 1;
    assert!(
        CompletedForwardReceipt::verified(
            decoded()?,
            crate::ha_forward_completion::CompletedExchange {
                cluster: cluster_id.clone(),
                source: 1,
                target: 2,
                deadline,
                nonce: wrong_nonce,
                request: &request,
                response_digest: response_digest(&response)?
            }
        )
        .is_err()
    );
    assert!(
        CompletedForwardReceipt::verified(
            decoded()?,
            crate::ha_forward_completion::CompletedExchange {
                cluster: cluster_id.clone(),
                source: 1,
                target: 2,
                deadline,
                nonce,
                request: b"another request",
                response_digest: response_digest(&response)?
            }
        )
        .is_err()
    );
    assert!(
        CompletedForwardReceipt::verified(
            decoded()?,
            crate::ha_forward_completion::CompletedExchange {
                cluster: cluster_id.clone(),
                source: 1,
                target: 2,
                deadline,
                nonce,
                request: &request,
                response_digest: digest(b"different response")
            }
        )
        .is_err()
    );
    assert!(
        CompletedForwardReceipt::verified(
            decoded()?,
            crate::ha_forward_completion::CompletedExchange {
                cluster: cluster_id,
                source: 1,
                target: 2,
                deadline: Instant::now() - Duration::from_millis(1),
                nonce,
                request: &request,
                response_digest: response_digest(&response)?
            }
        )
        .is_err()
    );
    drop(service);
    drop(cluster);
    Ok(())
}
#[test]
fn completed_forward_original_unseal_owner_vetoes_after_local_audit() -> TestResult {
    let files = Root::new();
    let (mut service, cluster, actor, accessor) = prepare(&files)?;
    let (response, wire, request, nonce, deadline) = leader_completion(&mut service, &actor)?;
    let cluster_id = service.state.as_ref().ok_or("state")?.cluster_id.clone();
    let receipt = CompletedForwardReceipt::verified(
        wire,
        crate::ha_forward_completion::CompletedExchange {
            cluster: cluster_id,
            source: 1,
            target: 2,
            deadline,
            nonce,
            request: &request,
            response_digest: response_digest(&response)?,
        },
    )?;
    service.ha = Some(Arc::clone(&cluster.processes[1]));
    let authority = service
        .stage_forward_delivery(
            receipt,
            Arc::clone(&cluster.processes[1]),
            "",
            Some(clock()?),
            100,
        )
        .map_err(|_| "owner")?;
    service.pending_forward_delivery = Some(PendingForwardDelivery::Completed(Box::new(authority)));
    let response =
        service.audit_completed_response("original-forward-fixture", 100, Some(clock()?), response);
    service.rotate_unseal_nonce()?;
    let withheld = service.complete_forward_delivery(response, "original-forward-fixture");
    assert_eq!(withheld.status, 503);
    assert!(withheld.body["data"].is_null());
    assert_eq!(uses(&service, &accessor)?, 1);
    assert!(service.pending_forward_delivery.is_none());
    drop(service);
    drop(cluster);
    Ok(())
}

#[test]
fn completed_forward_missing_proof_audits_without_raft_and_clears_private_rejection() -> TestResult
{
    let files = Root::new();
    let (mut service, cluster, _actor, _accessor) = prepare(&files)?;
    service.ha = Some(Arc::clone(&cluster.processes[1]));
    let before = serde_json::to_vec(service.state.as_ref().ok_or("state")?)?;
    let sequence = service.audit_sequence;
    let raft = cluster.processes[1]
        .lock()
        .map_err(|_| "HA")?
        .leader_status()?
        .committed_index;
    service.pending_forward_delivery = Some(PendingForwardDelivery::Rejected);
    let response = service.audit_completed_response(
        "missing-forward-proof",
        100,
        Some(clock()?),
        Response::error(503, "missing proof"),
    );
    let response = service.complete_forward_delivery(response, "missing-forward-proof");
    assert_eq!(response.status, 503);
    assert!(response.body["data"].is_null());
    assert_eq!(service.audit_sequence, sequence + 1);
    assert!(service.pending_forward_delivery.is_none());
    assert_eq!(
        serde_json::to_vec(service.state.as_ref().ok_or("state")?)?,
        before
    );
    assert_eq!(
        cluster.processes[1]
            .lock()
            .map_err(|_| "HA")?
            .leader_status()?
            .committed_index,
        raft
    );
    Ok(())
}

#[test]
fn completed_forward_long_local_mandatory_audit_withholds_expired_original_actor() -> TestResult {
    let files = Root::new();
    let (mut service, cluster, actor, accessor) = prepare_with_ttl(&files, "1s")?;
    let (response, wire, request, nonce, deadline) = leader_completion(&mut service, &actor)?;
    assert!(
        wire.actor.is_some(),
        "real original affine Actor gate captured"
    );
    let cluster_id = service.state.as_ref().ok_or("state")?.cluster_id.clone();
    let receipt = CompletedForwardReceipt::verified(
        wire,
        crate::ha_forward_completion::CompletedExchange {
            cluster: cluster_id,
            source: 1,
            target: 2,
            deadline,
            nonce,
            request: &request,
            response_digest: response_digest(&response)?,
        },
    )?;
    service.ha = Some(Arc::clone(&cluster.processes[1]));
    let original_clock = clock()?;
    let authority = service
        .stage_forward_delivery(
            receipt,
            Arc::clone(&cluster.processes[1]),
            "",
            Some(original_clock),
            100,
        )
        .map_err(|_| "owner")?;
    service.pending_forward_delivery = Some(PendingForwardDelivery::Completed(Box::new(authority)));
    let before = serde_json::to_vec(service.state.as_ref().ok_or("state")?)?;
    let response = service.audit_completed_response_with_receipt(
        "late-forward-original-actor",
        100,
        Some(original_clock),
        response,
        || std::thread::sleep(Duration::from_millis(1100)),
    );
    let response = service.complete_forward_delivery(response, "late-forward-original-actor");
    assert_eq!(response.status, 403, "{}", response.body);
    assert!(response.body["data"].is_null());
    assert!(response.response_headers.is_empty());
    assert!(response.consistency_index.is_none());
    assert_eq!(
        uses(&service, &accessor)?,
        1,
        "admitted use is not refunded or consumed twice"
    );
    assert_eq!(
        serde_json::to_vec(service.state.as_ref().ok_or("state")?)?,
        before
    );
    assert!(service.pending_forward_delivery.is_none());
    Ok(())
}
#[test]
fn completed_forward_receipt_identity_and_floor_must_match_actual_replica_graph() -> TestResult {
    let files = Root::new();
    let (mut service, cluster, actor, _) = prepare(&files)?;
    let (response, wire, request, nonce, deadline) = leader_completion(&mut service, &actor)?;
    let raw = serde_json::to_vec(&wire)?;
    let cluster_id = service.state.as_ref().ok_or("state")?.cluster_id.clone();
    service.ha = Some(Arc::clone(&cluster.processes[1]));
    for wrong_floor in [false, true] {
        let mut wrong: CompletionWire = serde_json::from_slice(&raw)?;
        if wrong_floor {
            wrong.floor = Some(crate::auth::Timestamp::whole(1)?);
        } else {
            wrong.identity = crate::state_record_root::StateIdentity::Legacy([9; 32]);
        }
        let receipt = CompletedForwardReceipt::verified(
            wrong,
            crate::ha_forward_completion::CompletedExchange {
                cluster: cluster_id.clone(),
                source: 1,
                target: 2,
                deadline,
                nonce,
                request: &request,
                response_digest: response_digest(&response)?,
            },
        )?;
        assert!(
            service
                .stage_forward_delivery(
                    receipt,
                    Arc::clone(&cluster.processes[1]),
                    "",
                    Some(clock()?),
                    100
                )
                .is_err()
        );
        assert!(service.pending_forward_delivery.is_none());
    }
    Ok(())
}

#[test]
fn completed_forward_step_down_preserves_real_handoff_without_second_local_capsule() -> TestResult {
    let files = Root::new();
    let mut service = files.service()?;
    let (_, root) = bootstrap(&mut service)?;
    assert_eq!(
        call(
            &mut service,
            "PUT",
            "sys/policies/acl/forward-step-down",
            &root,
            json!({"policy":r#"path "sys/step-down" {capabilities=["update","sudo"]}"#})
        )
        .status,
        204
    );
    let cluster_id = service.state.as_ref().ok_or("state")?.cluster_id.clone();
    let cluster =
        crate::ha::snapshot_test_support::Cluster::new(&files.path.join("raft"), &cluster_id)?;
    service.ha = Some(Arc::clone(&cluster.processes[0]));
    service.sync_from_ha().map_err(|_| "initial HA state")?;
    let minted = native(
        &mut service,
        "POST",
        "auth/token/create",
        &root,
        json!({"ttl":"10m","num_uses":1,"policies":["forward-step-down"],"no_default_policy":true}),
    );
    assert_eq!(minted.status, 200, "{}", minted.body);
    let actor = minted.body["auth"]["client_token"]
        .as_str()
        .ok_or("actor")?
        .to_owned();
    let accessor = minted.body["auth"]["accessor"]
        .as_str()
        .ok_or("accessor")?
        .to_owned();
    let nonce = crate::crypto::random::<32>()?;
    let body = json!({});
    let request = crate::ha_forward::encode_completed_index_request_for_cluster(
        &cluster_id,
        (2, 1),
        &crate::ha_forward::ForwardContext {
            method: "POST",
            path: "sys/step-down",
            namespace: "",
            token: &actor,
            body: &body,
            wrap_ttl_seconds: None,
            client_certificates: None,
            origin_peer: None,
            caller_deadline: None,
        },
        Some(nonce),
    )?;
    let deadline = Instant::now() + Duration::from_secs(10);
    let scope = CompletionScope::enter(Some(nonce), &request, deadline, &cluster_id, 1, false);
    let response = native(&mut service, "POST", "sys/step-down", &actor, json!({}));
    assert_eq!(response.status, 204, "{}", response.body);
    assert!(response.body.is_null());
    assert!(service.ha_activation.is_none());
    assert_eq!(
        uses(&service, &accessor)?,
        0,
        "original final use is consumed"
    );
    let successor = cluster.processes[0]
        .lock()
        .map_err(|_| "HA")?
        .leader()?
        .ok_or("leader")?;
    assert_ne!(successor, 1, "genuine handoff took place before completion");
    service.seal_forward_completion(&response);
    let wire = scope
        .finish()
        .ok_or("genuine step-down completion absent")?;
    assert!(
        !wire.acknowledgement_only,
        "step-down retains original actor final gate"
    );
    let receipt = CompletedForwardReceipt::verified(
        wire,
        crate::ha_forward_completion::CompletedExchange {
            cluster: cluster_id,
            source: 1,
            target: 2,
            deadline,
            nonce,
            request: &request,
            response_digest: response_digest(&response)?,
        },
    )?;
    service.ha = Some(Arc::clone(&cluster.processes[1]));
    let authority = service
        .stage_forward_delivery(
            receipt,
            Arc::clone(&cluster.processes[1]),
            "",
            Some(clock()?),
            100,
        )
        .map_err(|_| "follower original owner")?;
    service.pending_forward_delivery = Some(PendingForwardDelivery::Completed(Box::new(authority)));
    let expected = service.expects_local_ha_step_down("sys/step-down", &response);
    assert!(
        !expected,
        "the held completed proof supplies the original capsule"
    );
    let before = serde_json::to_vec(service.state.as_ref().ok_or("state")?)?;
    let audit = service.audit_sequence;
    let committed = cluster.processes[1]
        .lock()
        .map_err(|_| "HA")?
        .leader_status()?
        .committed_index;
    let response = service.audit_completed_response(
        "original-forward-step-down",
        100,
        Some(clock()?),
        response,
    );
    let response =
        service.complete_ha_step_down(expected, None, response, "original-forward-step-down");
    let response = service.complete_forward_delivery(response, "original-forward-step-down");
    assert_eq!(response.status, 204, "{}", response.body);
    assert!(response.body.is_null() && response.response_headers.is_empty());
    assert!(!service.recovery_required);
    assert!(service.pending_forward_delivery.is_none());
    assert_eq!(
        service.audit_sequence,
        audit + 1,
        "follower mandatory audit remains"
    );
    assert_eq!(
        serde_json::to_vec(service.state.as_ref().ok_or("state")?)?,
        before
    );
    assert_eq!(uses(&service, &accessor)?, 0, "no second use or refund");
    assert_eq!(
        cluster.processes[1]
            .lock()
            .map_err(|_| "HA")?
            .leader_status()?
            .committed_index,
        committed
    );
    assert_eq!(
        cluster.processes[0].lock().map_err(|_| "HA")?.leader()?,
        Some(successor),
        "no second handoff"
    );
    service.pending_forward_delivery = Some(PendingForwardDelivery::Rejected);
    assert!(
        service.expects_local_ha_step_down("sys/step-down", &response),
        "missing proof never replaces local capsule"
    );
    service.pending_forward_delivery = None;
    assert!(service.expects_local_ha_step_down("sys/step-down", &response));
    drop(service);
    drop(cluster);
    Ok(())
}

/// Current prefix and owner implementation retains a genuine completed prefix
/// after an unrelated real native request advances the same leader's clock.
/// The graph and original Actor remain independently authenticated; no second use.
#[test]
fn completed_forward_later_real_leader_floor_retains_original_authority() -> TestResult {
    let files = Root::new();
    let (mut service, cluster, actor, accessor, root_token) =
        prepare_with_ttl_and_root(&files, "10m")?;
    let (response, wire, request, nonce, deadline) = leader_completion(&mut service, &actor)?;
    let receipt_identity = wire.identity;
    let receipt_floor = wire.floor.ok_or("original precise floor")?;
    let receipt_index = wire.applied_index;
    assert_eq!(uses(&service, &accessor)?, 1);
    std::thread::sleep(Duration::from_millis(3));
    let mut control = native(
        &mut service,
        "GET",
        "auth/token/lookup-self",
        &root_token,
        json!({}),
    );
    assert_eq!(control.status, 200);
    erase_json(&mut control.body);
    control.response_headers.clear();
    let later_identity = service
        .current_state_identity()
        .map_err(|_| "later identity")?;
    let later_floor = service
        .state
        .as_ref()
        .ok_or("state")?
        .auth
        .terminal_token_clock_floor()
        .ok_or("later floor")?;
    assert_ne!(later_identity, receipt_identity);
    assert!(later_floor > receipt_floor);
    service
        .state
        .as_ref()
        .ok_or("state")?
        .auth
        .validate_forward_actor(
            wire.actor.as_ref().ok_or("original actor witness")?,
            AuthorityTime::Precise(clock()?.observed_at()?),
        )?;
    assert_eq!(
        uses(&service, &accessor)?,
        1,
        "root lookup did not consume the original actor"
    );
    let leader_seen = cluster.processes[0]
        .lock()
        .map_err(|_| "HA")?
        .leader_status()?;
    assert!(
        leader_seen
            .committed_index
            .is_some_and(|i| i > receipt_index)
    );
    assert!(leader_seen.applied_index.is_some_and(|i| i > receipt_index));
    let cluster_id = service.state.as_ref().ok_or("state")?.cluster_id.clone();
    let receipt = CompletedForwardReceipt::verified(
        wire,
        crate::ha_forward_completion::CompletedExchange {
            cluster: cluster_id,
            source: 1,
            target: 2,
            deadline,
            nonce,
            request: &request,
            response_digest: response_digest(&response)?,
        },
    )?;
    service.ha = Some(Arc::clone(&cluster.processes[1]));
    let authority = service
        .stage_forward_delivery(
            receipt,
            Arc::clone(&cluster.processes[1]),
            "",
            Some(clock()?),
            100,
        )
        .map_err(|_| "true completed prefix was rejected")?;
    service.pending_forward_delivery = Some(PendingForwardDelivery::Completed(Box::new(authority)));
    let response =
        service.audit_completed_response("later-floor-prefix", 100, Some(clock()?), response);
    let response = service.complete_forward_delivery(response, "later-floor-prefix");
    assert_eq!(response.status, 200, "{}", response.body);
    assert_eq!(
        response.body["data"]["data"]["value"],
        "completed-on-leader"
    );
    assert_eq!(
        service
            .current_state_identity()
            .map_err(|_| "synced identity")?,
        later_identity
    );
    assert_eq!(
        service
            .state
            .as_ref()
            .ok_or("state")?
            .auth
            .terminal_token_clock_floor(),
        Some(later_floor)
    );
    let follower_seen = cluster.processes[1]
        .lock()
        .map_err(|_| "HA")?
        .leader_status()?;
    assert!(
        follower_seen
            .committed_index
            .is_some_and(|i| i > receipt_index)
    );
    assert!(
        follower_seen
            .applied_index
            .is_some_and(|i| i > receipt_index)
    );
    assert_eq!(uses(&service, &accessor)?, 1, "no second admission or use");
    assert!(service.pending_forward_delivery.is_none());
    drop(service);
    drop(cluster);
    Ok(())
}

/// A quorum snapshot does not authorize an altered completed prefix or owner.
#[test]
fn completed_forward_altered_prefix_and_owner_withhold_genuine_response() -> TestResult {
    let files = Root::new();
    let (mut service, cluster, actor, accessor) = prepare(&files)?;
    let (response, wire, request, nonce, deadline) = leader_completion(&mut service, &actor)?;
    let original = serde_json::to_value(&wire)?;
    let cluster_id = service.state.as_ref().ok_or("state")?.cluster_id.clone();
    service.ha = Some(Arc::clone(&cluster.processes[1]));
    for kind in ["prefix", "owner"] {
        let mut encoded = original.clone();
        if kind == "prefix" {
            encoded["prefix"]["term"] = json!(u64::MAX);
        } else {
            let value = encoded["owner_projection"][0].as_u64().ok_or("digest")?;
            encoded["owner_projection"][0] = json!(value ^ 1);
        }
        let altered: CompletionWire = serde_json::from_value(encoded.clone())?;
        erase_json(&mut encoded);
        let receipt = CompletedForwardReceipt::verified(
            altered,
            crate::ha_forward_completion::CompletedExchange {
                cluster: cluster_id.clone(),
                source: 1,
                target: 2,
                deadline,
                nonce,
                request: &request,
                response_digest: response_digest(&response)?,
            },
        )?;
        let rejected = service.stage_forward_delivery(
            receipt,
            Arc::clone(&cluster.processes[1]),
            "",
            Some(clock()?),
            100,
        );
        assert!(matches!(rejected, Err(ref veto) if veto.status == 503));
        assert!(service.pending_forward_delivery.is_none());
        assert_eq!(uses(&service, &accessor)?, 1, "no re-admission or refund");
    }
    drop(service);
    drop(cluster);
    Ok(())
}

/// A genuinely committed ACL change cannot be treated as a clock extension.
#[test]
fn completed_forward_real_policy_change_withholds_original_response() -> TestResult {
    let files = Root::new();
    let (mut service, cluster, actor, accessor, root_token) =
        prepare_with_ttl_and_root(&files, "10m")?;
    let (response, wire, request, nonce, deadline) = leader_completion(&mut service, &actor)?;
    let mut changed = native(
        &mut service,
        "PUT",
        "sys/policies/acl/forward-test",
        &root_token,
        json!({"policy":r#"path "secret/data/completion" {capabilities=["deny"]}"#}),
    );
    assert_eq!(changed.status, 204, "{}", changed.body);
    erase_json(&mut changed.body);
    changed.response_headers.clear();
    let cluster_id = service.state.as_ref().ok_or("state")?.cluster_id.clone();
    let receipt = CompletedForwardReceipt::verified(
        wire,
        crate::ha_forward_completion::CompletedExchange {
            cluster: cluster_id,
            source: 1,
            target: 2,
            deadline,
            nonce,
            request: &request,
            response_digest: response_digest(&response)?,
        },
    )?;
    service.ha = Some(Arc::clone(&cluster.processes[1]));
    let rejected = service.stage_forward_delivery(
        receipt,
        Arc::clone(&cluster.processes[1]),
        "",
        Some(clock()?),
        100,
    );
    assert!(matches!(rejected, Err(ref veto) if veto.status == 503));
    assert_eq!(uses(&service, &accessor)?, 1);
    assert!(service.pending_forward_delivery.is_none());
    drop(service);
    drop(cluster);
    Ok(())
}

#[test]
fn completed_forward_real_raft_after_peer_budget_keeps_original_business_deadline() -> TestResult {
    let files = Root::new();
    let (mut service, cluster, actor, accessor) = prepare(&files)?;
    let cluster_id = service.state.as_ref().ok_or("state")?.cluster_id.clone();
    let body = json!({});
    let nonce = crate::crypto::random::<32>()?;
    let request = crate::ha_forward::encode_completed_index_request_for_cluster(
        &cluster_id,
        (2, 1),
        &crate::ha_forward::ForwardContext {
            method: "GET",
            path: "secret/data/completion",
            namespace: "",
            token: &actor,
            body: &body,
            wrap_ttl_seconds: None,
            origin_peer: None,
            client_certificates: None,
            caller_deadline: None,
        },
        Some(nonce),
    )?;
    let admitted = Instant::now();
    let budgets = crate::ha::InboundPeerDeadlines::new(
        admitted,
        Duration::from_millis(500),
        Duration::from_secs(5),
    );
    let scope = CompletionScope::enter(
        Some(nonce),
        &request,
        budgets.forward_request,
        &cluster_id,
        1,
        false,
    );
    // A real elapsed queue delay precedes the original Service admission.
    // All three durable Raft nodes continue running; no successful RPC is mocked.
    std::thread::sleep(Duration::from_millis(650));
    assert!(Instant::now() >= budgets.read_rpc);
    let execution = service.begin_request_before(
        ServiceRequest {
            method: "GET",
            path: "secret/data/completion",
            namespace: "",
            token: &actor,
            body: json!({}),
            wrap_ttl_seconds: None,
            origin_peer: None,
            client_certificates: None,
        },
        budgets.forward_request,
        true,
    );
    let response = service.finish_synchronous_request(execution);
    assert_eq!(response.status, 200, "real Raft/business response rejected");
    assert_eq!(
        response.body["data"]["data"]["value"],
        "completed-on-leader"
    );
    service.seal_forward_completion(&response);
    let wire = scope.finish().ok_or("real completion after 500ms absent")?;
    assert!(wire.precise && wire.audit_sequence > 0 && wire.floor.is_some());
    assert_eq!(uses(&service, &accessor)?, 1);
    assert!(Instant::now() < budgets.forward_request);
    drop(scope);
    // A later entry must retain an already elapsed original business deadline.
    // It cannot consume the second finite use or manufacture another completion.
    let late = crate::ha::InboundPeerDeadlines::new(
        Instant::now() - Duration::from_secs(6),
        Duration::from_millis(500),
        Duration::from_secs(5),
    );
    let scope = CompletionScope::enter(
        Some(nonce),
        &request,
        late.forward_request,
        &cluster_id,
        1,
        false,
    );
    let execution = service.begin_request_before(
        ServiceRequest {
            method: "GET",
            path: "secret/data/completion",
            namespace: "",
            token: &actor,
            body: json!({}),
            wrap_ttl_seconds: None,
            origin_peer: None,
            client_certificates: None,
        },
        late.forward_request,
        true,
    );
    let response = service.finish_synchronous_request(execution);
    assert_eq!(response.status, 503);
    service.seal_forward_completion(&response);
    assert!(scope.finish().is_none());
    assert_eq!(
        uses(&service, &accessor)?,
        1,
        "late entry must not consume/refund"
    );
    drop(service);
    drop(cluster);
    Ok(())
}
