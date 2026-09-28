//! Initial HA leader publication must use the existing durable state exactly once.
use super::tests::{Root, bootstrap};
use super::*;
use crate::ha::snapshot_test_support::Cluster;

type TestResult = Result<(), Box<dyn std::error::Error>>;

#[test]
fn initial_ha_leader_unseal_anchors_existing_durable_state() -> TestResult {
    let root = Root::new();
    let mut local = root.service()?;
    let (key, _) = bootstrap(&mut local)?;
    let cluster_id = local
        .state
        .as_ref()
        .ok_or("local state")?
        .cluster_id
        .clone();
    drop(local);

    // Membership is committed but the Raft application log is still empty,
    // matching a deployment converted from an initialized single node.
    let cluster = Cluster::new(&root.path.join("raft"), &cluster_id)?;
    assert!(
        cluster.processes[0]
            .lock()
            .map_err(|_| "HA poisoned")?
            .is_leader()?
    );
    let mut leader = Service::new_with_ha(
        root.path.join("data"),
        &root.path.join("audit.jsonl"),
        Arc::clone(&cluster.processes[0]),
    )?;
    let response = leader.handle("POST", "sys/unseal", "", "", json!({"key":key}));
    assert_eq!(response.status, 200);
    assert!(leader.state.is_some());
    assert!(!leader.recovery_required);
    Ok(())
}

#[test]
fn initial_ha_unseal_retries_only_prepublication_authority_loss() -> TestResult {
    let root = Root::new();
    let mut service = root.service()?;
    let mut sync_attempts = 0;
    service
        .synchronize_ha_after_unseal_with(
            |_| Ok(true),
            |_| {
                sync_attempts += 1;
                if sync_attempts < 3 {
                    Err(Response::error(503, "HA linearizable state is unavailable"))
                } else {
                    Ok(())
                }
            },
            || {},
        )
        .map_err(|_| "transient HA synchronization did not recover")?;
    assert_eq!(sync_attempts, 3);

    let mut roles = [true, false].into_iter();
    let mut role_loss_syncs = 0;
    service
        .synchronize_ha_after_unseal_with(
            |_| {
                roles
                    .next()
                    .ok_or_else(|| Response::error(500, "role sequence exhausted"))
            },
            |_| {
                role_loss_syncs += 1;
                Err(Response::error(503, "HA linearizable state is unavailable"))
            },
            || {},
        )
        .map_err(|_| "leadership transfer did not release the old initial anchor")?;
    assert_eq!(role_loss_syncs, 1, "new leader owns the initial anchor");

    let mut role_attempts = 0;
    let mut role_syncs = 0;
    service
        .synchronize_ha_after_unseal_with(
            |_| {
                role_attempts += 1;
                if role_attempts < 3 {
                    Err(Response::error(503, "HA role is unavailable during unseal"))
                } else {
                    Ok(true)
                }
            },
            |_| {
                role_syncs += 1;
                Ok(())
            },
            || {},
        )
        .map_err(|_| "transient HA role observation did not recover")?;
    assert_eq!(role_attempts, 3);
    assert_eq!(role_syncs, 1);

    let mut post_read_role_attempts = 0;
    service
        .synchronize_ha_after_unseal_with(
            |_| Ok(true),
            |_| {
                post_read_role_attempts += 1;
                if post_read_role_attempts == 1 {
                    Err(Response::error(503, "HA role is unavailable"))
                } else {
                    Ok(())
                }
            },
            || {},
        )
        .map_err(|_| "post-read HA role observation did not recover")?;
    assert_eq!(post_read_role_attempts, 2);

    let mut terminal_attempts = 0;
    let terminal = service
        .synchronize_ha_after_unseal_with(
            |_| Ok(true),
            |_| {
                terminal_attempts += 1;
                Err(Response::error(
                    503,
                    "HA committed state but local durable publication failed",
                ))
            },
            || {},
        )
        .err()
        .ok_or("non-transient publication error was ignored")?;
    assert_eq!(terminal.status, 503);
    assert_eq!(terminal_attempts, 1);
    Ok(())
}
