//! Genuine three-node no-write failures, never a completed HA authority.
use super::*;
use crate::service::tests::{Root, bootstrap_unmounted};
use std::time::{Duration, Instant};

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn anchored(
    root: &Root,
) -> Result<(Service, crate::ha::snapshot_test_support::Cluster), Box<dyn std::error::Error>> {
    let mut service = root.service()?;
    bootstrap_unmounted(&mut service)?;
    let cluster_id = service.state.as_ref().ok_or("state")?.cluster_id.clone();
    let cluster =
        crate::ha::snapshot_test_support::Cluster::new(&root.path.join("raft"), &cluster_id)?;
    service.ha = Some(Arc::clone(&cluster.processes[0]));
    service
        .sync_from_ha()
        .map_err(|_| "initial authenticated anchor")?;
    Ok((service, cluster))
}

fn local_files(root: &Path) -> Result<BTreeMap<PathBuf, Vec<u8>>, std::io::Error> {
    let mut files = BTreeMap::new();
    for entry in fs::read_dir(root)? {
        let entry = entry?;
        if entry.file_type()?.is_file() {
            files.insert(entry.path(), fs::read(entry.path())?);
        }
    }
    Ok(files)
}

fn rejected_response(response: &Response) {
    assert_eq!(response.status, 503);
    assert_eq!(
        response.body,
        json!({"errors":["HA recovery application identity is not current"]})
    );
    assert!(response.response_headers.is_empty());
    assert!(response.consistency_index.is_none());
}

#[test]
fn unchanged_shamir_no_write_real_quorum_loss_retains_only_buffers() -> TestResult {
    let root = Root::new();
    let (mut service, cluster) = anchored(&root)?;
    let identity = service.current_state_identity().map_err(|_| "identity")?;
    let generation = service.durable.as_ref().ok_or("durable")?.generation();
    let before = local_files(&root.path)?;
    let deadline = Instant::now() + Duration::from_secs(2);
    let failure = {
        let _scope = crate::request_deadline::RequestDeadlineScope::enter(deadline);
        service
            .reconcile_ha_recovery_index_with_context_and_observer(
                Some(deadline),
                HaRecoveryIndexOwnerContext::Unchanged,
                |_| cluster.isolate_all_peers(true),
            )
            .err()
            .ok_or("quorum loss admitted")?
    };
    rejected_response(&failure);
    assert!(cluster.blocked_probes() > 0);
    assert!(service.state.is_some());
    assert!(service.durable.is_some());
    assert!(service.barrier_key.is_some());
    assert!(!service.recovery_required);
    assert!(service.ha_activation.is_none());
    assert!(service.ha_read_cache.is_none());
    assert_eq!(
        service
            .current_state_identity()
            .map_err(|_| "retained identity")?,
        identity
    );
    assert_eq!(
        service
            .durable
            .as_ref()
            .ok_or("retained durable")?
            .generation(),
        generation
    );
    assert_eq!(local_files(&root.path)?, before);

    // Retained local bytes cannot satisfy even another actual unavailable
    // ReadIndex. This is a separate no-effect request, never a business retry.
    let second = Instant::now() + Duration::from_millis(300);
    {
        let _scope = crate::request_deadline::RequestDeadlineScope::enter(second);
        assert!(
            service
                .reconcile_unchanged_ha_recovery_index(Some(second))
                .is_err()
        );
    }
    assert!(service.state.is_some());
    cluster.isolate_all_peers(false);
    std::thread::sleep(Duration::from_secs(2));
    let fresh = Instant::now() + Duration::from_secs(5);
    {
        let _scope = crate::request_deadline::RequestDeadlineScope::enter(fresh);
        service
            .sync_from_ha()
            .map_err(|_| "fresh independent quorum sync")?;
        service
            .reconcile_unchanged_ha_recovery_index(Some(fresh))
            .map_err(|_| "fresh independent index admission")?;
    }
    assert!(!service.recovery_required);
    Ok(())
}

#[test]
fn unchanged_shamir_expired_no_write_is_negative_only() -> TestResult {
    let root = Root::new();
    let (mut service, _cluster) = anchored(&root)?;
    let before = local_files(&root.path)?;
    let identity = service.current_state_identity().map_err(|_| "identity")?;
    let deadline = Instant::now() + Duration::from_secs(2);
    let failure = {
        let _scope = crate::request_deadline::RequestDeadlineScope::enter(deadline);
        service
            .reconcile_ha_recovery_index_with_context_and_observer(
                Some(deadline),
                HaRecoveryIndexOwnerContext::Unchanged,
                |_| {
                    let remaining = deadline.saturating_duration_since(Instant::now());
                    std::thread::sleep(remaining + Duration::from_millis(10));
                },
            )
            .err()
            .ok_or("expired request admitted")?
    };
    rejected_response(&failure);
    assert!(live(Some(deadline)).is_err());
    assert!(service.state.is_some());
    assert!(!service.recovery_required);
    assert!(service.ha_activation.is_none());
    assert!(service.ha_read_cache.is_none());
    assert_eq!(
        service.current_state_identity().map_err(|_| "identity")?,
        identity
    );
    assert_eq!(local_files(&root.path)?, before);
    // No returned witness, response data, header, index write or new deadline.
    Ok(())
}

fn changed_owner(case: &str) -> TestResult {
    let root = Root::new();
    let (mut service, cluster) = anchored(&root)?;
    let deadline = Instant::now() + Duration::from_secs(5);
    // Establish the intact baseline before the independent damage/change.
    let proof = ha_received::UnchangedShamirLocalOwner::capture(&mut service, Some(deadline))
        .map_err(|_| "baseline capture")?
        .ok_or("baseline Shamir owner")?;
    proof
        .verify_negative(&mut service, Some(deadline))
        .map_err(|_| "intact baseline")?;
    let mut mutation_failed = false;
    let failure = {
        let _scope = crate::request_deadline::RequestDeadlineScope::enter(deadline);
        service
            .reconcile_ha_recovery_index_with_context_and_observer(
                Some(deadline),
                HaRecoveryIndexOwnerContext::Unchanged,
                |service| {
                    cluster.isolate_all_peers(true);
                    match case {
                        "durable" => {
                            let request = PutRequest::new(
                                "unchanged-shamir-damage",
                                "system",
                                "actual-damaged-state",
                                "state",
                                crypto::digest(b"actual-damaged-state"),
                                match Secret::new(b"actual-damaged-state".to_vec()) {
                                    Ok(value) => value,
                                    Err(_) => {
                                        mutation_failed = true;
                                        return;
                                    }
                                },
                            );
                            match request {
                                Ok(request) => {
                                    mutation_failed = service
                                        .durable
                                        .as_mut()
                                        .is_none_or(|durable| durable.put(request).is_err());
                                }
                                Err(_) => mutation_failed = true,
                            }
                        }
                        "nonce" => service.unseal_nonce.push('x'),
                        "index" => {
                            if let Some(current) = service.seal.clone() {
                                let mut target = current.clone();
                                target.generation = target.generation.saturating_add(1);
                                mutation_failed = !matches!(
                                    service.publish_ha_recovery_index(
                                        &current,
                                        &target,
                                        Some(deadline)
                                    ),
                                    Ok(LocalRecoveryIndexPublication::KnownWritten { .. })
                                );
                            } else {
                                mutation_failed = true;
                            }
                        }
                        _ => mutation_failed = true,
                    }
                },
            )
            .err()
            .ok_or("changed owner admitted")?
    };
    assert!(!mutation_failed);
    assert_eq!(failure.status, 503);
    assert!(service.recovery_required);
    assert!(service.state.is_none());
    assert!(service.durable.is_none());
    assert!(service.barrier_key.is_none());
    assert!(service.ha_activation.is_none());
    assert!(service.ha_read_cache.is_none());
    Ok(())
}

#[test]
fn unchanged_shamir_actual_durable_damage_still_fences() -> TestResult {
    changed_owner("durable")
}
#[test]
fn unchanged_shamir_original_nonce_change_still_fences() -> TestResult {
    changed_owner("nonce")
}
#[test]
fn unchanged_shamir_actual_index_write_still_fences() -> TestResult {
    changed_owner("index")
}
