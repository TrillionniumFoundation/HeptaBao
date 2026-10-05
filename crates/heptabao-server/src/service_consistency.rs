//! Index prerequisites and response metadata use existing authenticated paths.
//! A watermark never grants authentication, application read authority or replay.
use super::*;
use crate::http::consistency::{IndexValue, Observation};
use std::time::Instant;

impl Service {
    pub(crate) fn consistency_observation(&self) -> Result<Option<Observation>, Response> {
        let (Some(ha), Some(state)) = (&self.ha, &self.state) else {
            return Ok(None);
        };
        let ha = ha
            .lock_for_request()
            .map_err(|_| Response::error(503, "consistency HA lock is unavailable"))?;
        if ha.cluster_id() != state.cluster_id {
            return Err(Response::error(
                503,
                "consistency cluster identity differs from admitted state",
            ));
        }
        let seen = ha
            .leader_status()
            .map_err(|_| Response::error(503, "consistency observation is unavailable"))?;
        Ok(Some(Observation {
            cluster: state.cluster_id.clone(),
            standby: seen.leader != Some(seen.local_id),
            committed: seen.committed_index,
            applied: seen.applied_index,
        }))
    }

    pub(super) fn stamp_consistency_index(&self, response: &mut Response) {
        if response.consistency_index.is_some()
            || !(200..300).contains(&response.status)
            || self.state.is_none()
            || self.recovery_required
            || self.audit_failed
        {
            return;
        }
        let Some(ha) = &self.ha else {
            return;
        };
        let now = Instant::now();
        let limit = now + Duration::from_millis(250);
        let deadline = crate::request_deadline::current().map_or(limit, |outer| outer.min(limit));
        if now >= deadline {
            return;
        }
        let _scope = crate::request_deadline::RequestDeadlineScope::enter(deadline);
        let Ok(ha) = ha.lock_for_request() else {
            return;
        };
        if !self
            .state
            .as_ref()
            .is_some_and(|state| state.cluster_id == ha.cluster_id())
        {
            return;
        }
        // An optional header cannot turn a committed business result into a
        // failed mutation. No retries or new effect intents are introduced.
        if ha.ensure_linearizable().is_err() {
            return;
        }
        let Ok(observed) = ha.leader_status() else {
            return;
        };
        if observed.leader != Some(observed.local_id) {
            return;
        }
        let (Some(committed), Some(applied)) = (observed.committed_index, observed.applied_index)
        else {
            return;
        };
        let index = committed.min(applied);
        if index != 0 {
            response.consistency_index = IndexValue::for_raft(ha.cluster_id(), index).wire();
        }
    }
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;
    use crate::http::consistency;
    fn at_initial_standby_frontier(
        seen: &heptabao_raft_runtime::LocalLeaderObservation,
        leader: u64,
        committed: u64,
    ) -> bool {
        seen.local_id != leader
            && seen.leader == Some(leader)
            && seen.committed_index == Some(committed)
            && seen.applied_index == Some(committed)
    }

    #[test]
    fn consistency270_fixture_rejects_incomplete_membership_frontiers() {
        use heptabao_raft_runtime::LocalLeaderObservation;
        let ready = LocalLeaderObservation {
            local_id: 2,
            term: 1,
            local_is_leader: false,
            leader: Some(1),
            committed_index: Some(5),
            applied_index: Some(5),
        };
        assert!(at_initial_standby_frontier(&ready, 1, 5));
        // Reproduce the actual failed full-workspace observation: the leader
        // had committed final membership 5 while this replica still reported 4.
        for observed in [
            LocalLeaderObservation {
                committed_index: Some(4),
                applied_index: Some(4),
                ..ready
            },
            LocalLeaderObservation {
                applied_index: Some(4),
                ..ready
            },
            LocalLeaderObservation {
                committed_index: None,
                ..ready
            },
            LocalLeaderObservation {
                leader: None,
                ..ready
            },
            LocalLeaderObservation {
                leader: Some(2),
                ..ready
            },
            LocalLeaderObservation {
                local_id: 1,
                ..ready
            },
            LocalLeaderObservation {
                committed_index: Some(6),
                applied_index: Some(6),
                ..ready
            },
        ] {
            assert!(!at_initial_standby_frontier(&observed, 1, 5));
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn consistency270_real_raft_wait_rejects_before_token_use_or_application_effect()
    -> Result<(), Box<dyn std::error::Error>> {
        use crate::service::tests::{Root, bootstrap, call};
        let root = Root::new();
        let mut service = root.service()?;
        let (_, token) = bootstrap(&mut service)?;
        let issued = call(
            &mut service,
            "POST",
            "auth/token/create",
            &token,
            json!({"policies":["default"],"num_uses":2,"ttl":600}),
        );
        assert_eq!(issued.status, 200);
        let limited = issued.body["auth"]["client_token"]
            .as_str()
            .ok_or("limited token")?
            .to_owned();
        let cluster_id = service.state.as_ref().ok_or("state")?.cluster_id.clone();
        let cluster =
            crate::ha::snapshot_test_support::Cluster::new(&root.path.join("raft"), &cluster_id)?;
        // Cluster::new waits for the leader's final membership and ReadIndex,
        // not this follower's application of that commit. Anchor that exact
        // setup commit before measuring whether the middleware changes state.
        // This is fixture setup only: the 1s transport, 25ms wait, 750ms response
        // bound, and exact unchanged-frontier assertions below are unchanged.
        let leader = cluster.processes[0]
            .lock()
            .map_err(|_| "raft")?
            .leader_status()?;
        assert_eq!(leader.leader, Some(leader.local_id));
        let initial_commit = leader.committed_index.ok_or("initial membership commit")?;
        assert_eq!(leader.applied_index, Some(initial_commit));
        let setup_deadline = Instant::now() + Duration::from_secs(15);
        loop {
            let seen = cluster.processes[1]
                .lock()
                .map_err(|_| "raft")?
                .leader_status()?;
            if at_initial_standby_frontier(&seen, leader.local_id, initial_commit) {
                break;
            }
            if Instant::now() >= setup_deadline {
                return Err("initial standby membership did not converge".into());
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        let state_before = service.current_state_digest().map_err(|_| "state digest")?;
        let generation_before = service.durable.as_ref().ok_or("durable")?.generation();
        let audit_before = service.audit_sequence;
        service.ha = Some(Arc::clone(&cluster.processes[1]));
        let shared = Arc::new(Mutex::new(service));
        let index = consistency::IndexValue::for_raft(&cluster_id, u64::MAX)
            .wire()
            .ok_or("index")?;
        let headers = consistency::test_headers(index.as_str(), &["await-state"])?;
        let before = cluster.processes[1]
            .lock()
            .map_err(|_| "raft")?
            .leader_status()?;
        assert!(at_initial_standby_frontier(
            &before,
            leader.local_id,
            initial_commit
        ));
        let start = Instant::now();
        let result = consistency::admit(
            &shared,
            &headers,
            consistency::Settings::default(),
            start + Duration::from_secs(1),
        );
        assert!(matches!(result,Err(ref response) if response.status==429));
        assert!(start.elapsed() >= Duration::from_millis(25));
        assert!(start.elapsed() < Duration::from_millis(750));
        let after = cluster.processes[1]
            .lock()
            .map_err(|_| "raft")?
            .leader_status()?;
        assert_eq!(before.committed_index, after.committed_index);
        assert_eq!(before.applied_index, after.applied_index);
        assert_eq!(before.leader, after.leader);
        // Restore the preexisting standalone owner only for independent token readback.
        let mut service = shared.lock().map_err(|_| "service")?;
        assert_eq!(
            service.current_state_digest().map_err(|_| "state digest")?,
            state_before
        );
        assert_eq!(
            service.durable.as_ref().ok_or("durable")?.generation(),
            generation_before
        );
        assert_eq!(service.audit_sequence, audit_before);
        service.ha = None;
        let lookup = call(
            &mut service,
            "POST",
            "auth/token/lookup",
            &token,
            json!({"token":limited}),
        );
        assert_eq!(lookup.status, 200);
        assert_eq!(lookup.body["data"]["num_uses"], 2);
        drop(service);
        let lock = shared.lock().map_err(|_| "service")?;
        let start = Instant::now();
        let result = consistency::admit(
            &shared,
            &headers,
            consistency::Settings::default(),
            start + Duration::from_millis(80),
        );
        assert!(matches!(result,Err(ref response) if response.status==503));
        assert!(start.elapsed() < Duration::from_millis(400));
        drop(lock);
        Ok(())
    }
}
