//! Real Raft publication plus strict lossless historical profile regressions.
use super::*;
use crate::service::tests::{Root, bootstrap_unmounted};
type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;
fn historical(root: &Root) -> TestResult<(Service, String, String)> {
    let mut service = root.service()?;
    let (key, token) = bootstrap_unmounted(&mut service)?;
    let original = service.state.as_ref().ok_or("state")?;
    let mut auth = CheckedJson(serde_json::from_slice(
        &owner_store::serialize_owner(&original.auth).map_err(|_| "auth bytes")?,
    )?);
    let keep = [
        "tokens",
        "policies",
        "users",
        "roles",
        "mounted_users",
        "mounted_roles",
        "auth_mounts",
        "jwt_mounts",
    ];
    let extra = object(&auth.0)
        .map_err(|_| "auth object")?
        .keys()
        .filter(|key| !keep.contains(&key.as_str()))
        .cloned()
        .collect::<Vec<_>>();
    for key in extra {
        discard(&mut auth.0, &key).map_err(|_| "auth field")?;
    }
    for ns in auth.0["auth_mounts"]
        .as_object_mut()
        .ok_or("mounts")?
        .values_mut()
    {
        for mount in ns.as_object_mut().ok_or("namespace")?.values_mut() {
            let fields = mount
                .as_object()
                .ok_or("mount")?
                .keys()
                .filter(|key| !["kind", "description"].contains(&key.as_str()))
                .cloned()
                .collect::<Vec<_>>();
            for field in fields {
                discard(mount, &field).map_err(|_| "mount field")?;
            }
        }
    }
    let mut value = CheckedJson(json!({"schema":1,"cluster_id":original.cluster_id,
        "auth":&auth.0,"engines":{"namespaces":{"":{"mounts":{
        "secret/":{"description":"Versioned secrets","backend":{"Kv2":{
            "config":{"max_versions":0,"cas_required":false,"delete_version_after":0},"entries":{}}}},
        "transit/":{"description":"Cryptographic operations","backend":{"Transit":{"keys":{},"disable_upsert":false}}}
    }}}}}));
    let state: State = serde_json::from_slice(
        &owner_store::serialize_owner(&value.0).map_err(|_| "fixture bytes")?,
    )?;
    erase_json(&mut value.0);
    state.validate_format().map_err(|_| "historical state")?;
    let bytes = checked_bytes(&state).map_err(|_| "historical profile")?;
    // A fixture constructs an actual old-format graph before attachment; it does
    // not downgrade an existing production graph or move an admission clock.
    service.state = None;
    service
        .persist_local_with_prepared_plan(&state, &bytes, "legacy-upgrade-fixture", 1, 0, None)
        .map_err(|_| "fixture durable publication")?;
    service.state_digest = Some(crypto::digest(&bytes));
    service.state = Some(state);
    Ok((service, key, token))
}
fn request(
    service: &mut Service,
    method: &str,
    token: &str,
    body: Value,
    deadline: Instant,
) -> Response {
    let plan = service.begin_request_before(
        ServiceRequest {
            method,
            path: "secret/data/bridge",
            namespace: "",
            token,
            body,
            wrap_ttl_seconds: None,
            origin_peer: None,
            client_certificates: None,
        },
        deadline,
        false,
    );
    service.finish_synchronous_request(plan)
}
fn prepare(
    root: &Root,
) -> TestResult<(
    Service,
    crate::ha::snapshot_test_support::Cluster,
    String,
    String,
)> {
    let (mut service, key, token) = historical(root)?;
    let bytes = checked_bytes(service.state.as_ref().ok_or("state")?).map_err(|_| "old bytes")?;
    let cluster = crate::ha::snapshot_test_support::Cluster::new(
        &root.path.join("raft"),
        &service.state.as_ref().ok_or("state")?.cluster_id,
    )?;
    cluster.processes[0]
        .lock()
        .map_err(|_| "HA")?
        .seed_legacy_upgrade_fixture(&bytes)?;
    cluster.processes[0]
        .lock()
        .map_err(|_| "HA")?
        .set_legacy_peer_v1_for_test(true);
    service.ha = Some(Arc::clone(&cluster.processes[0]));
    service
        .sync_from_ha()
        .map_err(|_| "actual original HBSR1")?;
    Ok((service, cluster, key, token))
}
#[test]
fn legacy_upgrade_wire_real_quorum_commit_keeps_hbsr1_and_current_local_owner_digest() -> TestResult
{
    let root = Root::new();
    let (mut service, cluster, key, token) = prepare(&root)?;
    let result = request(
        &mut service,
        "POST",
        &token,
        json!({"data":{"value":"actual-successor"}}),
        Instant::now() + Duration::from_secs(10),
    );
    assert_eq!(result.status, 200, "{}", result.body);
    assert!(service.record_root.is_none());
    assert!(
        service
            .state
            .as_ref()
            .ok_or("state")?
            .engines
            .record_root()
            .is_none()
    );
    assert!(service.pending_ordinary_kv_authority.is_none());
    let bytes = checked_bytes(service.state.as_ref().ok_or("state")?).map_err(|_| "new profile")?;
    let actual = cluster.processes[0]
        .lock()
        .map_err(|_| "HA")?
        .latest_committed_state()?
        .ok_or("committed")?;
    assert_eq!(actual.bytes.as_slice(), bytes.as_slice());
    assert_eq!(
        service.current_state_digest().map_err(|_| "digest")?,
        crypto::digest(&bytes)
    );
    service.ha = Some(Arc::clone(&cluster.processes[1]));
    cluster.processes[1]
        .lock()
        .map_err(|_| "HA")?
        .set_legacy_peer_v1_for_test(true);
    let read = request(
        &mut service,
        "GET",
        &token,
        json!({}),
        Instant::now() + Duration::from_secs(10),
    );
    assert_eq!(read.status, 200, "{}", read.body);
    assert_eq!(read.body["data"]["data"]["value"], "actual-successor");
    drop(service);
    let mut reopened = root.service()?;
    reopened.ha = Some(Arc::clone(&cluster.processes[1]));
    let plan = reopened.begin_request_before(
        ServiceRequest {
            method: "PUT",
            path: "sys/unseal",
            namespace: "",
            token: "",
            body: json!({"key":key}),
            wrap_ttl_seconds: None,
            origin_peer: None,
            client_certificates: None,
        },
        Instant::now() + Duration::from_secs(10),
        false,
    );
    assert_eq!(reopened.finish_synchronous_request(plan).status, 200);
    let read = request(
        &mut reopened,
        "GET",
        &token,
        json!({}),
        Instant::now() + Duration::from_secs(10),
    );
    assert_eq!(read.status, 200, "{}", read.body);
    assert_eq!(read.body["data"]["data"]["value"], "actual-successor");
    drop(reopened);
    drop(cluster);
    Ok(())
}
#[test]
fn legacy_upgrade_wire_real_quorum_loss_and_expired_original_budget_do_not_publish() -> TestResult {
    let root = Root::new();
    let (mut service, cluster, _key, token) = prepare(&root)?;
    let identity = service.current_state_identity().map_err(|_| "identity")?;
    let generation = service.durable.as_ref().ok_or("durable")?.generation();
    cluster.isolate_all_peers(true);
    let result = request(
        &mut service,
        "POST",
        &token,
        json!({"data":{"value":"withheld"}}),
        Instant::now() + Duration::from_millis(350),
    );
    assert_eq!(result.status, 503);
    assert!(result.body["data"].is_null());
    assert_eq!(
        service.current_state_identity().map_err(|_| "identity")?,
        identity
    );
    assert_eq!(
        service.durable.as_ref().ok_or("durable")?.generation(),
        generation
    );
    cluster.isolate_all_peers(false);
    let result = request(
        &mut service,
        "POST",
        &token,
        json!({"data":{"value":"expired"}}),
        Instant::now() - Duration::from_millis(1),
    );
    assert_eq!(result.status, 503);
    assert_eq!(
        service.current_state_identity().map_err(|_| "identity")?,
        identity
    );
    drop(service);
    drop(cluster);
    Ok(())
}
#[test]
fn legacy_upgrade_wire_profile_preserves_neutral_defaults_but_rejects_real_mount_incarnation()
-> TestResult {
    let root = Root::new();
    let (service, _key, _token) = historical(&root)?;
    let state = service.state.as_ref().ok_or("state")?;
    let original = checked_bytes(state).map_err(|_| "profile")?;
    let mut wire = CheckedJson(serde_json::from_slice(&original)?);
    wire.0["engines"]["namespaces"][""]["mounts"]["secret/"]["incarnation"] = json!(2);
    let altered: State =
        serde_json::from_slice(&owner_store::serialize_owner(&wire.0).map_err(|_| "bytes")?)?;
    assert!(checked_bytes(&altered).is_err());
    wire.0["engines"]["namespaces"][""]["mounts"]["secret/"]["incarnation"] = json!(1);
    let restored: State =
        serde_json::from_slice(&owner_store::serialize_owner(&wire.0).map_err(|_| "bytes")?)?;
    assert_eq!(checked_bytes(&restored).map_err(|_| "profile")?, original);
    Ok(())
}
#[test]
fn legacy_upgrade_wire_profile_does_not_drop_cubbyhole_acl_or_metadata_cas_owners() -> TestResult {
    let root = Root::new();
    let (service, _key, _token) = historical(&root)?;
    let original = checked_bytes(service.state.as_ref().ok_or("state")?).map_err(|_| "profile")?;
    let mut wire = CheckedJson(serde_json::from_slice(&original)?);
    let digest = object(&wire.0["auth"]["tokens"])
        .map_err(|_| "tokens")?
        .keys()
        .next()
        .ok_or("token")?
        .clone();
    wire.0["auth"]["tokens"][&digest]["cubbyhole"] =
        json!({"namespaces":{"":{"held":"must-not-disappear"}}});
    let changed: State =
        serde_json::from_slice(&owner_store::serialize_owner(&wire.0).map_err(|_| "bytes")?)?;
    assert!(checked_bytes(&changed).is_err());
    let mut wire = CheckedJson(serde_json::from_slice(&original)?);
    wire.0["engines"]["namespaces"][""]["mounts"]["secret/"]["backend"]["Kv2"]["config"]["metadata_cas_required"] =
        json!(true);
    let changed: State =
        serde_json::from_slice(&owner_store::serialize_owner(&wire.0).map_err(|_| "bytes")?)?;
    assert!(checked_bytes(&changed).is_err());
    let mut wire = CheckedJson(serde_json::from_slice(&original)?);
    wire.0["auth"]["policies"][""]["advanced"] = json!({"source":"path x {}", "rules":[
        {"path":"x","capabilities":["read"],"required_parameters":["restricted"]}]});
    let changed: State =
        serde_json::from_slice(&owner_store::serialize_owner(&wire.0).map_err(|_| "bytes")?)?;
    assert!(checked_bytes(&changed).is_err());
    Ok(())
}

#[test]
fn legacy_upgrade_wire_real_quorum_then_expired_original_budget_fences_without_local_publish()
-> TestResult {
    let root = Root::new();
    let (mut service, cluster, _key, token) = prepare(&root)?;
    let digest = service.current_state_digest().map_err(|_| "digest")?;
    let generation = service.durable.as_ref().ok_or("durable")?.generation();
    AFTER_QUORUM_DELAY_MS.with(|delay| delay.set(2100));
    let result = request(
        &mut service,
        "POST",
        &token,
        json!({"data":{"value":"quorum-committed"}}),
        Instant::now() + Duration::from_secs(2),
    );
    assert_eq!(
        AFTER_QUORUM_DELAY_MS.with(std::cell::Cell::get),
        0,
        "real quorum hook must have run"
    );
    assert_eq!(result.status, 503);
    assert_eq!(result.body["retry_allowed"], false);
    assert!(service.recovery_required);
    assert_eq!(
        service.durable.as_ref().ok_or("durable")?.generation(),
        generation
    );
    assert_eq!(
        service.current_state_digest().map_err(|_| "digest")?,
        digest
    );
    let actual = cluster.processes[0]
        .lock()
        .map_err(|_| "HA")?
        .latest_committed_state()?
        .ok_or("actualcommit")?;
    assert_ne!(
        crypto::digest(&actual.bytes),
        digest,
        "already quorum-committed effect is not undone"
    );
    drop(service);
    drop(cluster);
    Ok(())
}
#[test]
fn legacy_upgrade_wire_real_commit_with_bad_receipt_is_uncertain_and_fenced() -> TestResult {
    let root = Root::new();
    let (mut service, cluster, _key, token) = prepare(&root)?;
    let digest = service.current_state_digest().map_err(|_| "digest")?;
    let generation = service.durable.as_ref().ok_or("durable")?.generation();
    crate::ha::HaProcess::reject_next_legacy_receipt_for_test();
    let result = request(
        &mut service,
        "POST",
        &token,
        json!({"data":{"value":"receipt-withheld"}}),
        Instant::now() + Duration::from_secs(10),
    );
    assert_eq!(result.status, 503);
    assert_eq!(result.body["retry_allowed"], false);
    assert!(service.recovery_required);
    assert_eq!(
        service.durable.as_ref().ok_or("durable")?.generation(),
        generation
    );
    let actual = cluster.processes[0]
        .lock()
        .map_err(|_| "HA")?
        .latest_committed_state()?
        .ok_or("actualcommit")?;
    assert_ne!(
        crypto::digest(&actual.bytes),
        digest,
        "unknown receipt cannot relabel real effect unused"
    );
    drop(service);
    drop(cluster);
    Ok(())
}
