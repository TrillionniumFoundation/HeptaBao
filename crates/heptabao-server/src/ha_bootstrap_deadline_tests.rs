//! Actual committed bootstrap learners under the public health deadline.
use super::*;
use crate::service::{RequestExecution, Service, ServiceRequest};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

struct Root(PathBuf);
impl Root {
    fn new() -> TestResult<Self> {
        let path = std::env::temp_dir().join(format!(
            "heptabao-bootstrap-health-deadline-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)?
                .as_nanos()
        ));
        fs::create_dir(&path)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o700))?;
        }
        Ok(Self(path))
    }
}
impl Drop for Root {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

#[test]
fn health_bootstrap_deadline_retains_committed_learners_and_recovers_without_reenrollment()
-> TestResult {
    let root = Root::new()?;
    let cluster_id = "bootstrap-health-deadline";
    let voters = BTreeSet::from([1, 2, 3]);
    let cluster = snapshot_test_support::Cluster::uninitialized(&root.0.join("raft"), cluster_id)?;
    cluster.isolate_all_peers(true);
    let before = {
        let mut first = cluster.processes[0].lock().map_err(|_| "HA poisoned")?;
        let node = first.node.as_ref().ok_or("leader node")?;
        let untouched = first.runtime.block_on(node.membership_observation())?;
        let expired = crate::request_deadline::RequestDeadlineScope::enter(Instant::now());
        assert!(!reconcile_bootstrap_membership(
            &first.runtime,
            node,
            true,
            1,
            &voters,
        ));
        drop(expired);
        let still_untouched = first.runtime.block_on(node.membership_observation())?;
        assert_eq!(still_untouched.membership_index, untouched.membership_index);
        assert_eq!(still_untouched.nodes, untouched.nodes);
        assert_eq!(still_untouched.voters, untouched.voters);
        first.runtime.block_on(async {
            node.initialize_single().await?;
            tokio::time::timeout(Duration::from_secs(8), async {
                while node.current_leader().await != Some(1) {
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
                node.enroll_learner(2).await?;
                node.enroll_learner(3).await
            })
            .await??;
            Ok::<_, Box<dyn std::error::Error>>(())
        })?;
        let before = first.runtime.block_on(node.membership_observation())?;
        assert!(before.committed && !before.joint);
        assert_eq!(before.nodes, voters);
        assert_eq!(before.voters, BTreeSet::from([1]));
        first.bootstrap_admission = Some(BootstrapAdmission::create_pending(
            &first.storage_dir,
            cluster_id,
            &voters,
        )?);
        first.bootstrap_voters = Some(voters.clone());
        first.bootstrap_owner = true;
        first
            .bootstrap_history_complete
            .store(false, Ordering::Release);
        first.bootstrap_ready.store(false, Ordering::Release);
        before
    };
    let mut service = Service::new_with_ha(
        root.0.join("data"),
        &root.0.join("audit.jsonl"),
        Arc::clone(&cluster.processes[0]),
    )?;
    for budget in [Duration::from_millis(200), Duration::from_millis(30)] {
        let started = Instant::now();
        let response = service.begin_request_before(
            ServiceRequest::new("GET", "sys/health", "", "", serde_json::json!({})),
            started + budget,
            false,
        );
        assert!(
            started.elapsed() < budget + Duration::from_millis(400),
            "an unavailable bootstrap learner must not consume a fresh two-second wait"
        );
        let RequestExecution::Complete(response) = response else {
            return Err("health created an external effect".into());
        };
        assert_ne!(response.status, 200);
        assert_eq!(response.body["ha_active"], false);
        assert_eq!(response.body["ha_application_ready"], false);
        assert!(crate::request_deadline::current().is_none());
        let first = cluster.processes[0].lock().map_err(|_| "HA poisoned")?;
        let observed = first.runtime.block_on(
            first
                .node
                .as_ref()
                .ok_or("leader node")?
                .membership_observation(),
        )?;
        assert_eq!(observed.membership_index, before.membership_index);
        assert_eq!(observed.nodes, before.nodes);
        assert_eq!(observed.voters, before.voters);
        assert!(observed.committed && !observed.joint);
        assert!(!first.bootstrap_ready.load(Ordering::Acquire));
        assert!(!first.bootstrap_history_complete.load(Ordering::Acquire));
        assert_eq!(
            BootstrapAdmission::load(&first.storage_dir, cluster_id, &voters)?
                .ok_or("pending bootstrap marker")?
                .1,
            BootstrapMarkerState::Pending
        );
    }
    assert!(cluster.blocked_probes() > 0);

    // No caller deadline remains. The original startup path can observe the
    // same committed learners catching up, then complete exactly one voter
    // transition. No failed health probe discarded or reenrolled them.
    cluster.isolate_all_peers(false);
    let first = cluster.processes[0].lock().map_err(|_| "HA poisoned")?;
    let node = first.node.as_ref().ok_or("leader node")?;
    first.runtime.block_on(async {
        node.wait_for_learner_replication(2, Duration::from_secs(8))
            .await?;
        node.wait_for_learner_replication(3, Duration::from_secs(8))
            .await
    })?;
    assert!(crate::request_deadline::current().is_none());
    assert!(first.bootstrap_ready());
    let completed = first.runtime.block_on(node.membership_observation())?;
    assert!(completed.committed && !completed.joint);
    assert_eq!(completed.voters, voters);
    assert!(completed.membership_index > before.membership_index);
    assert_eq!(
        BootstrapAdmission::load(&first.storage_dir, cluster_id, &voters)?
            .ok_or("complete bootstrap marker")?
            .1,
        BootstrapMarkerState::Complete
    );
    assert!(first.bootstrap_ready());
    assert_eq!(
        first
            .runtime
            .block_on(node.membership_observation())?
            .membership_index,
        completed.membership_index
    );
    Ok(())
}
