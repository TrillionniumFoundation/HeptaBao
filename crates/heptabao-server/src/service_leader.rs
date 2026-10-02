//! `/sys/leader` is a local, unauthenticated diagnostic endpoint, like the
//! dedicated OpenBao 2.7.0 HTTP handler. It cannot admit any application effect.
use super::*;

impl Service {
    pub(super) fn leader_response(&mut self, method: &str) -> Response {
        if method != "GET" {
            return Response {
                consistency_index: None,
                status: 405,
                body: json!({"errors": []}),
            };
        }
        let Some(process) = self.ha.as_ref().cloned() else {
            // Upstream checks HA availability before seal/initialization.
            self.ha_activation = None;
            return Response::ok(json!({"ha_enabled": false}));
        };
        if self.state.is_none() {
            self.ha_activation = None;
            return Response::error(503, "Vault is sealed");
        }
        let process = match process.lock_for_request() {
            Ok(process) => process,
            Err(_) => {
                self.ha_activation = None;
                return Response::error(503, "HA process lock is unavailable");
            }
        };
        let observation = match process.leader_status() {
            Ok(observation) => observation,
            Err(_) => {
                self.ha_activation = None;
                return Response::error(500, "HA leader observation is unavailable");
            }
        };
        let mut body = json!({
            "ha_enabled": true,
            "is_self": observation.leader == Some(observation.local_id),
        });
        if let Some(address) = observation
            .leader
            .and_then(|leader| process.api_address(leader))
        {
            body["leader_address"] = json!(address);
        }
        if let Some(address) = observation
            .leader
            .and_then(|leader| process.cluster_address(leader))
        {
            body["leader_cluster_address"] = json!(address);
        }
        if let Some(index) = observation.committed_index.filter(|index| *index != 0) {
            body["raft_committed_index"] = json!(index);
        }
        if let Some(index) = observation.applied_index.filter(|index| *index != 0) {
            body["raft_applied_index"] = json!(index);
        }
        let key = ha_activation::ActivationKey::from_observation(observation);
        if !self.ha_activation_permitted()
            || key.is_none()
            || self
                .ha_activation
                .as_ref()
                .is_some_and(|activation| key.is_none_or(|key| !activation.matches(key)))
        {
            self.ha_activation = None;
        }
        if let Some(time) = key.and_then(|key| {
            self.ha_activation
                .as_ref()
                .and_then(|activation| activation.active_time(key))
        }) {
            body["active_time"] = json!(time);
        }
        Response::ok(body)
    }
}

#[cfg(test)]
#[path = "service_leader_tests.rs"]
mod tests;
