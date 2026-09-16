//! Consensus owns membership; Service owns the persisted autopilot policy.
//! Observed monotonic stabilization is advisory and resets on leadership/config
//! change. Neither a peer configuration nor a queued RPC is admission evidence.
use super::*;
use heptabao_raft_runtime::MembershipObservation;
use std::{
    collections::BTreeSet,
    time::{Duration, Instant},
};

#[derive(Clone, Serialize, Deserialize, Debug, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(super) struct AutopilotConfig {
    cleanup_dead_servers: bool,
    last_contact_threshold: u64,
    dead_server_last_contact_threshold: u64,
    max_trailing_logs: u64,
    min_quorum: usize,
    server_stabilization_time: u64,
}
impl Default for AutopilotConfig {
    fn default() -> Self {
        Self {
            cleanup_dead_servers: false,
            last_contact_threshold: 10,
            dead_server_last_contact_threshold: 86400,
            max_trailing_logs: 1000,
            min_quorum: 3,
            server_stabilization_time: 10,
        }
    }
}
#[derive(Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(super) struct RaftAdminState {
    config: AutopilotConfig,
    promote: BTreeSet<u64>,
}
impl RaftAdminState {
    pub(super) fn is_default(&self) -> bool {
        self == &Self::default()
    }
    pub(super) fn validate(&self) -> Result<(), Response> {
        let c = &self.config;
        if !(1..=60).contains(&c.last_contact_threshold)
            || !(60..=86400).contains(&c.dead_server_last_contact_threshold)
            || c.dead_server_last_contact_threshold < c.last_contact_threshold
            || !(3..=9).contains(&c.min_quorum)
            || c.max_trailing_logs > 10000
            || !(1..=600).contains(&c.server_stabilization_time)
            || self.promote.len() > 9
            || self.promote.contains(&0)
        {
            return Err(Response::error(400, "invalid bounded autopilot policy"));
        }
        Ok(())
    }
}
#[derive(Default)]
pub(super) struct Stabilization {
    term: Option<u64>,
    index: Option<u64>,
    configuration: Option<AutopilotConfig>,
    healthy_since: BTreeMap<u64, Instant>,
}
fn healthy(o: &MembershipObservation, id: u64, c: &AutopilotConfig) -> bool {
    if id == o.local_id {
        return o.leader == Some(id) && o.committed && !o.joint;
    }
    o.peer_contact_ms
        .get(&id)
        .and_then(|v| *v)
        .is_some_and(|ms| ms <= c.last_contact_threshold * 1000)
        && o.peer_matched.get(&id).and_then(|v| *v).is_some_and(|i| {
            o.applied_index
                .is_some_and(|applied| applied.saturating_sub(i) <= c.max_trailing_logs)
        })
}
fn seconds(v: &Value) -> Option<u64> {
    if let Some(s) = v.as_str() {
        let (n, m) = if let Some(n) = s.strip_suffix('s') {
            (n, 1)
        } else if let Some(n) = s.strip_suffix('m') {
            (n, 60)
        } else if let Some(n) = s.strip_suffix('h') {
            (n, 3600)
        } else {
            (s, 1)
        };
        n.parse::<u64>().ok()?.checked_mul(m)
    } else {
        v.as_u64()
    }
}
fn config_body(c: &AutopilotConfig) -> Value {
    json!({"cleanup_dead_servers":c.cleanup_dead_servers,"last_contact_threshold":format!("{}s",c.last_contact_threshold),"dead_server_last_contact_threshold":format!("{}s",c.dead_server_last_contact_threshold),"max_trailing_logs":c.max_trailing_logs,"min_quorum":c.min_quorum,"server_stabilization_time":format!("{}s",c.server_stabilization_time)})
}
impl Stabilization {
    fn observe(&mut self, o: &MembershipObservation, c: &AutopilotConfig, now: Instant) {
        if self.term != Some(o.term)
            || self.index != o.membership_index
            || self.configuration.as_ref() != Some(c)
        {
            self.healthy_since.clear();
        }
        self.term = Some(o.term);
        self.index = o.membership_index;
        self.configuration = Some(c.clone());
        self.healthy_since
            .retain(|id, _| o.nodes.contains(id) && healthy(o, *id, c));
        for id in &o.nodes {
            if healthy(o, *id, c) {
                self.healthy_since.entry(*id).or_insert(now);
            }
        }
    }
    fn stabilized(&self, id: u64, c: &AutopilotConfig, now: Instant) -> bool {
        self.healthy_since.get(&id).is_some_and(|t| {
            now.checked_duration_since(*t)
                .is_some_and(|d| d >= Duration::from_secs(c.server_stabilization_time))
        })
    }
}
impl Service {
    pub(super) fn is_raft_admin_path(path: &str) -> bool {
        matches!(
            path,
            "sys/storage/raft/configuration"
                | "sys/storage/raft/join"
                | "sys/storage/raft/remove-peer"
                | "sys/storage/raft/demote"
                | "sys/storage/raft/promote"
                | "sys/storage/raft/snapshot-status"
                | "sys/storage/raft/linearizable-read"
                | "sys/storage/raft/autopilot/state"
                | "sys/storage/raft/autopilot/configuration"
        )
    }
    pub(super) fn raft_admin_route(
        &mut self,
        mut state: State,
        p: Option<&Principal>,
        r: &RequestView<'_>,
    ) -> Response {
        let run = (|| -> Result<Response, Response> {
            let RequestView {
                namespace,
                method,
                path,
                body,
                now,
                wrap_ttl_seconds,
                ..
            } = r;
            if !namespace.is_empty() {
                return Err(Response::error(
                    403,
                    "Raft administration is root-namespace scoped",
                ));
            }
            let p = p.ok_or_else(|| Response::error(403, "missing client token"))?;
            state
                .auth
                .authorize_sudo_request(
                    p,
                    namespace,
                    path,
                    if *method == "GET" { "read" } else { "update" },
                    *now,
                )
                .map_err(|e| Response::error(e.status, &e.message))?;
            if wrap_ttl_seconds.is_some() {
                return Err(Response::error(
                    501,
                    "consensus administration cannot be response-wrapped",
                ));
            }
            let ha = self
                .ha
                .clone()
                .ok_or_else(|| Response::error(400, "HA is not enabled"))?;
            let ha = ha
                .lock()
                .map_err(|_| Response::error(503, "HA lock unavailable"))?;
            let o = ha
                .membership()
                .map_err(|_| Response::error(503, "current consensus observation unavailable"))?;
            let object = body
                .as_object()
                .ok_or_else(|| Response::error(400, "object required"))?;
            if *method == "GET" {
                if !object.is_empty() {
                    return Err(Response::error(400, "read operation has no body fields"));
                }
                return match *path {
                    "sys/storage/raft/autopilot/configuration" => Ok(Response::ok(
                        json!({"data":config_body(&state.raft_admin.config)}),
                    )),
                    "sys/storage/raft/autopilot/state" => {
                        let mut value = Self::autopilot_body(&o, &state.raft_admin);
                        if let Some(servers) =
                            value.get_mut("servers").and_then(Value::as_object_mut)
                        {
                            for (id, server) in servers {
                                let stabilized = id.parse::<u64>().ok().is_some_and(|id| {
                                    self.raft_stabilization.index == o.membership_index
                                        && self.raft_stabilization.term == Some(o.term)
                                        && self.raft_stabilization.configuration.as_ref()
                                            == Some(&state.raft_admin.config)
                                        && healthy(&o, id, &state.raft_admin.config)
                                        && self.raft_stabilization.stabilized(
                                            id,
                                            &state.raft_admin.config,
                                            Instant::now(),
                                        )
                                });
                                server["stabilized"] = json!(stabilized);
                            }
                        }
                        Ok(Response::ok(json!({"data":value})))
                    }
                    "sys/storage/raft/configuration" => Ok(Response::ok(
                        json!({"data":{"config":{"index":o.membership_index,"committed":o.committed,"joint":o.joint,"servers":o.nodes.iter().map(|id|json!({"node_id":id.to_string(),"leader":o.leader==Some(*id),"voter":o.voters.contains(id),"enrolled":ha.enrolled(*id)})).collect::<Vec<_>>()}}}),
                    )),
                    "sys/storage/raft/snapshot-status" => Ok(Response::ok(
                        json!({"data":{"applied_index":o.applied_index,"snapshot_index":o.snapshot_index,"purged_index":o.purged_index,"membership_index":o.membership_index}}),
                    )),
                    "sys/storage/raft/linearizable-read" => {
                        Ok(Response::ok(linearizable_read_body(&o)))
                    }
                    _ => Err(Response::error(405, "Raft mutation requires POST or PUT")),
                };
            }
            if !matches!(*method, "POST" | "PUT") {
                return Err(Response::error(405, "unsupported Raft method"));
            }
            if *path == "sys/storage/raft/autopilot/configuration" {
                let c = &mut state.raft_admin.config;
                for (k, v) in object {
                    match k.as_str() {
                        "cleanup_dead_servers" => {
                            c.cleanup_dead_servers = v
                                .as_bool()
                                .ok_or_else(|| Response::error(400, "boolean required"))?
                        }
                        "last_contact_threshold" => {
                            c.last_contact_threshold = seconds(v)
                                .ok_or_else(|| Response::error(400, "invalid contact threshold"))?
                        }
                        "dead_server_last_contact_threshold" => {
                            c.dead_server_last_contact_threshold = seconds(v).ok_or_else(|| {
                                Response::error(400, "invalid dead-server threshold")
                            })?
                        }
                        "max_trailing_logs" => {
                            c.max_trailing_logs = v
                                .as_u64()
                                .ok_or_else(|| Response::error(400, "invalid log bound"))?
                        }
                        "min_quorum" => {
                            c.min_quorum = v
                                .as_u64()
                                .and_then(|v| usize::try_from(v).ok())
                                .ok_or_else(|| Response::error(400, "invalid minimum quorum"))?
                        }
                        "server_stabilization_time" => {
                            c.server_stabilization_time = seconds(v)
                                .ok_or_else(|| Response::error(400, "invalid stabilization time"))?
                        }
                        _ => return Err(Response::error(400, "unsupported autopilot field")),
                    }
                }
                state.raft_admin.validate()?;
                drop(ha);
                self.publish_raft_policy(state)?;
                self.raft_stabilization = Stabilization::default();
                return Ok(Response {
                    status: 204,
                    body: Value::Null,
                });
            }
            if object
                .keys()
                .any(|k| !matches!(k.as_str(), "server_id" | "expected_index" | "non_voter"))
            {
                return Err(Response::error(
                    400,
                    "only pre-enrolled peer admission with exact expected_index is supported",
                ));
            }
            let target = match body.get("server_id") {
                Some(Value::String(s)) => s.parse::<u64>().ok(),
                Some(v) => v.as_u64(),
                None => None,
            }
            .filter(|id| *id > 0)
            .ok_or_else(|| Response::error(400, "numeric server_id required"))?;
            let index = body
                .get("expected_index")
                .and_then(Value::as_u64)
                .ok_or_else(|| Response::error(400, "expected_index is required"))?;
            if !ha.enrolled(target) || target == o.local_id {
                return Err(Response::error(
                    400,
                    "peer is not an eligible enrolled target",
                ));
            }
            if o.membership_index != Some(index) || !o.committed || o.joint {
                return Err(Response::error(
                    409,
                    "membership frontier changed or is joint; observe again",
                ));
            }
            let operation = match *path {
                "sys/storage/raft/join" => "add_learner",
                "sys/storage/raft/promote" => "promote",
                "sys/storage/raft/demote" => "demote",
                "sys/storage/raft/remove-peer" => "remove",
                _ => return Err(Response::error(405, "read-only Raft operation")),
            };
            let non_voter = body
                .get("non_voter")
                .map(|v| {
                    v.as_bool()
                        .ok_or_else(|| Response::error(400, "non_voter must be boolean"))
                })
                .transpose()?
                .unwrap_or(false);
            if operation != "add_learner" && body.get("non_voter").is_some() {
                return Err(Response::error(400, "non_voter is a join-only option"));
            }
            if matches!(operation, "remove" | "demote")
                && o.voters.contains(&target)
                && o.voters.len() <= state.raft_admin.config.min_quorum
            {
                return Err(Response::error(409, "minimum quorum guard forbids removal"));
            }
            if operation == "add_learner" && o.nodes.contains(&target) {
                return Err(Response::error(409, "peer is already a member"));
            }
            if operation == "promote" {
                self.raft_stabilization
                    .observe(&o, &state.raft_admin.config, Instant::now());
                if !self.raft_stabilization.stabilized(
                    target,
                    &state.raft_admin.config,
                    Instant::now(),
                ) {
                    return Err(Response::error(
                        409,
                        "learner has not completed observed stabilization",
                    ));
                }
            }
            if operation == "add_learner" && !non_voter {
                state.raft_admin.promote.insert(target);
            } else {
                state.raft_admin.promote.remove(&target);
            }
            // Persist desired promotion/demotion policy before the native effect.
            drop(ha);
            self.publish_raft_policy(state)?;
            let ha = self
                .ha
                .as_ref()
                .ok_or_else(|| Response::error(503, "HA disappeared"))?
                .lock()
                .map_err(|_| Response::error(503, "HA lock unavailable"))?;
            let observed=ha.modify_membership(index,target,operation).map_err(|_|Response{status:503,body:json!({"errors":["membership completion unknown; re-read configuration before retry"],"reconcile_required":true,"server_id":target.to_string()})})?;
            Ok(Response::ok(
                json!({"data":{"joined":operation=="add_learner","membership_index":observed.membership_index,"voters":observed.voters,"nodes":observed.nodes,"committed":observed.committed,"joint":observed.joint}}),
            ))
        })();
        run.unwrap_or_else(|e| e)
    }
    fn publish_raft_policy(&mut self, mut state: State) -> Result<(), Response> {
        state.schema = CURRENT_STATE_SCHEMA;
        state.validate_format()?;
        self.commit_state(&state)?;
        self.state = Some(state);
        Ok(())
    }

    fn linearizable_read_body(o: &MembershipObservation) -> Response {
        Response::ok(json!({"data": {
            "linearizable": true,
            "leader": o.leader,
            "term": o.term,
            "membership_index": o.membership_index,
            "applied_index": o.applied_index,
            "observation_scope": "native-raft-ReadIndex"
        }}))
    }

    fn autopilot_body(o: &MembershipObservation, state: &RaftAdminState) -> Value {
        let c = &state.config;
        let healthy_voters = o.voters.iter().filter(|id| healthy(o, **id, c)).count();
        let quorum = o.voters.len() / 2 + 1;
        let servers:BTreeMap<String,Value>=o.nodes.iter().map(|id|{
            let alive=healthy(o,*id,c);let contact=if *id==o.local_id{Some(0)}else{o.peer_contact_ms.get(id).copied().flatten()};
            (id.to_string(),json!({"id":id.to_string(),"healthy":alive,"node_status":if alive{"alive"}else{"unhealthy"},"last_contact_ms":contact,"last_index":if *id==o.local_id{o.applied_index}else{o.peer_matched.get(id).copied().flatten()},"status":if o.leader==Some(*id){"leader"}else if o.voters.contains(id){"voter"}else{"non-voter"},"pending_promotion":state.promote.contains(id)}))
        }).collect();
        json!({"healthy":o.committed&&!o.joint&&healthy_voters==o.voters.len(),"failure_tolerance":healthy_voters.saturating_sub(quorum),"leader":o.leader.map(|v|v.to_string()),"voters":o.voters.iter().map(u64::to_string).collect::<Vec<_>>(),"servers":servers,"membership_index":o.membership_index,"committed":o.committed,"joint":o.joint,"observation_scope":"current-leader-ReadIndex-and-replication-metrics; not remote-disk-or-process-health-attestation"})
    }
    /// One guarded change per tick. No force removal, no guessed failure time,
    /// no promotion based on a timestamp carried in a network request.
    pub(super) fn maintain_raft_admin(&mut self) -> Result<bool, &'static str> {
        if self.state.is_none() || self.recovery_required || self.audit_failed {
            return Ok(false);
        }
        let Some(ha) = self.ha.clone() else {
            return Ok(false);
        };
        let ha = ha.lock().map_err(|_| "HA lock unavailable")?;
        if !ha.is_leader().map_err(|_| "HA leader unavailable")? {
            return Ok(false);
        }
        let o = ha.membership().map_err(|_| "HA frontier unavailable")?;
        if !o.committed || o.joint {
            return Ok(false);
        }
        drop(ha);
        self.sync_from_ha()
            .map_err(|_| "HA application frontier unavailable")?;
        let state = self.state.as_ref().ok_or("sealed")?;
        let policy = state.raft_admin.clone();
        let now = Instant::now();
        self.raft_stabilization.observe(&o, &policy.config, now);
        let promote = policy.promote.iter().copied().find(|id| {
            o.nodes.contains(id)
                && !o.voters.contains(id)
                && self.raft_stabilization.stabilized(*id, &policy.config, now)
        });
        let remove =
            if policy.config.cleanup_dead_servers && o.voters.len() > policy.config.min_quorum {
                o.voters.iter().copied().find(|id| {
                    *id != o.local_id
                        && o.peer_contact_ms
                            .get(id)
                            .and_then(|v| *v)
                            .is_some_and(|ms| {
                                ms >= policy.config.dead_server_last_contact_threshold * 1000
                            })
                })
            } else {
                None
            };
        let Some((id, operation)) = promote
            .map(|id| (id, "promote"))
            .or_else(|| remove.map(|id| (id, "remove")))
        else {
            return Ok(false);
        };
        let wall = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| "wall clock unavailable")?
            .as_secs();
        let fingerprint = self.request_fingerprint("INTERNAL", "raft/autopilot", "", "");
        self.audit_event("autopilot-request", &fingerprint, wall, None)
            .map_err(|_| "autopilot audit unavailable")?;
        let result = self
            .ha
            .as_ref()
            .ok_or("HA disappeared")?
            .lock()
            .map_err(|_| "HA lock unavailable")?
            .modify_membership(
                o.membership_index.ok_or("membership absent")?,
                id,
                operation,
            );
        if self
            .audit_event(
                "autopilot-response",
                &fingerprint,
                wall,
                Some(if result.is_ok() { 200 } else { 503 }),
            )
            .is_err()
        {
            self.recovery_required = true;
            return Err("autopilot result audit failed");
        }
        result.map_err(|_| "autopilot transition indeterminate")?;
        self.raft_stabilization = Stabilization::default();
        Ok(true)
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    fn observation() -> MembershipObservation {
        MembershipObservation {
            local_id: 1,
            leader: Some(1),
            term: 2,
            membership_index: Some(8),
            committed: true,
            joint: false,
            voters: BTreeSet::from([1, 2, 3]),
            nodes: BTreeSet::from([1, 2, 3, 4]),
            applied_index: Some(20),
            snapshot_index: Some(10),
            purged_index: Some(10),
            peer_matched: BTreeMap::from([(2, Some(20)), (3, Some(20)), (4, Some(20))]),
            peer_contact_ms: BTreeMap::from([(2, Some(0)), (3, Some(0)), (4, Some(0))]),
        }
    }
    #[test]
    fn health_cannot_invent_contact_or_replication() {
        let mut o = observation();
        let c = AutopilotConfig::default();
        assert!(healthy(&o, 4, &c));
        o.peer_contact_ms.insert(4, None);
        assert!(!healthy(&o, 4, &c));
        o.peer_contact_ms.insert(4, Some(0));
        o.peer_matched.insert(4, None);
        assert!(!healthy(&o, 4, &c));
    }
    #[test]
    fn stabilization_resets_on_gap_leadership_or_policy_change() {
        let mut s = Stabilization::default();
        let mut o = observation();
        let c = AutopilotConfig::default();
        let start = Instant::now();
        s.observe(&o, &c, start);
        assert!(!s.stabilized(4, &c, start));
        assert!(s.stabilized(4, &c, start + Duration::from_secs(10)));
        o.peer_contact_ms.insert(4, None);
        s.observe(&o, &c, start + Duration::from_secs(11));
        assert!(!s.stabilized(4, &c, start + Duration::from_secs(30)));
        o.peer_contact_ms.insert(4, Some(0));
        s.observe(&o, &c, start + Duration::from_secs(31));
        o.term += 1;
        s.observe(&o, &c, start + Duration::from_secs(40));
        assert!(!s.stabilized(4, &c, start + Duration::from_secs(41)));
    }
    #[test]
    fn linearizable_read_route_is_admitted_as_admin_path() {
        assert!(Service::is_raft_admin_path(
            "sys/storage/raft/linearizable-read"
        ));
    }

    #[test]
    fn linearizable_read_body_declares_read_index_observation() {
        let body = Service::linearizable_read_body(&observation()).body;
        assert_eq!(body["data"]["linearizable"], true);
        assert_eq!(body["data"]["observation_scope"], "native-raft-ReadIndex");
        assert_eq!(body["data"]["leader"], 1);
        assert_eq!(body["data"]["applied_index"], 20);
    }

    fn policy_bounds_and_failure_tolerance_are_conservative() {
        let mut p = RaftAdminState::default();
        assert!(p.validate().is_ok());
        p.config.min_quorum = 2;
        assert!(p.validate().is_err());
        let mut o = observation();
        o.peer_contact_ms.insert(3, None);
        assert_eq!(
            Service::autopilot_body(&o, &RaftAdminState::default())["failure_tolerance"],
            0
        );
        assert_eq!(
            Service::autopilot_body(&o, &RaftAdminState::default())["healthy"],
            false
        );
    }
}
