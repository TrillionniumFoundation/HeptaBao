//! `/sys/leader` is a local, unauthenticated diagnostic endpoint, like the
//! dedicated OpenBao 2.6.2 HTTP handler. It cannot admit any application effect.
use super::*;

impl Service {
    pub(super) fn leader_response(&self, method: &str) -> Response {
        if method != "GET" {
            return Response {
                status: 405,
                body: json!({"errors": []}),
            };
        }
        let Some(process) = self.ha.as_ref() else {
            // Upstream checks HA availability before seal/initialization.
            return Response::ok(json!({"ha_enabled": false}));
        };
        if self.state.is_none() {
            return Response::error(503, "Vault is sealed");
        }
        let process = match process.lock_for_request() {
            Ok(process) => process,
            Err(_) => return Response::error(503, "HA process lock is unavailable"),
        };
        let observation = match process.leader_status() {
            Ok(observation) => observation,
            Err(_) => return Response::error(500, "HA leader observation is unavailable"),
        };
        let mut body = json!({"ha_enabled": true});
        if observation.leader == Some(observation.local_id) {
            body["is_self"] = json!(true);
        }
        if let Some(address) = observation
            .leader
            .and_then(|leader| process.api_address(leader))
        {
            body["leader_address"] = json!(address);
        }
        if let Some(index) = observation.committed_index.filter(|index| *index != 0) {
            body["raft_committed_index"] = json!(index);
        }
        if let Some(index) = observation.applied_index.filter(|index| *index != 0) {
            body["raft_applied_index"] = json!(index);
        }
        // No fabricated active_time or OpenBao cluster API address. The Raft
        // peer socket is a different protocol, not a leader_cluster_address.
        Response::ok(body)
    }
}

#[cfg(test)]
#[path = "service_leader_tests.rs"]
mod tests;
