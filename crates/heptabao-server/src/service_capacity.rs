use super::*;

impl Service {
    /// Raft has already committed this effect. A local capacity or I/O failure
    /// cannot be relabelled as an operation rejected before entry.
    pub(super) fn ha_committed_local_failure(response: Response) -> Response {
        let mut body = json!({
            "errors": ["HA state committed but local persistence incomplete; reopen and reconcile; do not blindly retry"],
            "recovery_required": true,
            "retry_allowed": false
        });
        if let Some(reference) = response
            .body
            .get("recovery_reference")
            .and_then(Value::as_str)
        {
            body["recovery_reference"] = json!(reference);
        }
        Response { status: 503, body }
    }

    /// Root-namespace operator observation, behind ordinary request/result
    /// auditing. Counts refer to the serving leader's local durable owner.
    pub(super) fn capacity_response(&self, method: &str, body: &Value) -> Response {
        if method != "GET" {
            return Response::error(405, "capacity observation requires GET");
        }
        if body.as_object().is_none_or(|object| !object.is_empty()) {
            return Response::error(400, "capacity observation accepts an empty JSON object");
        }
        let Some(durable) = self.durable.as_ref() else {
            return Response::error(503, "server is sealed");
        };
        let capacity = match durable.capacity() {
            Ok(value) => value,
            Err(_) => return Response::error(503, "durable capacity observation unavailable"),
        };
        #[cfg(not(test))]
        let state_limit = MAX_STATE_BYTES;
        #[cfg(test)]
        let state_limit = self.state_capacity;

        // `DurableService::capacity().logical_payload_bytes` measures all bytes
        // currently owned by the local durable store. The V4 owner-addressed
        // state layout can retain reusable chunks plus the current manifest, so
        // physical durable bytes can exceed the serialized application-state
        // bound even while the current State remains admissible. The public
        // `state_*` fields are an application-state contract, not a physical
        // storage-amplification counter; derive them from the exact in-memory
        // State that would be passed to commit_state_bytes().
        let state_bytes = match self.state.as_ref() {
            Some(state) => match owner_store::serialize_owner(state) {
                Ok(bytes) => bytes.len(),
                Err(_) => return Response::error(503, "server state serialization unavailable"),
            },
            None => return Response::error(503, "server is sealed"),
        };
        if state_bytes > state_limit {
            return Response::error(503, "committed server state exceeds configured capacity");
        }

        // The Service admits one bounded serialized logical application state.
        // Local durability uses the V4 owner-scoped, content-defined chunk
        // manifest while HA still proposes the complete serialized state. This
        // is not a per-secret quota and it is not a record-oriented scale claim.
        Response::ok(json!({"data": {
            "profile": "bounded-owner-state-v4",
            "scope": "serving-leader-local",
            "state_schema": CURRENT_STATE_SCHEMA,
            "state_storage_format": owner_store::STATE_STORAGE_FORMAT,
            "state_chunk_target_bytes": owner_store::STATE_CHUNK_BYTES,
            "kv_read_only_dispatches": self.kv_read_only_dispatches,
            "state_bytes": state_bytes,
            "state_limit_bytes": state_limit,
            "state_remaining_bytes": state_limit - state_bytes,
            "generation": capacity.generation,
            "retained_operations": capacity.retained_requests,
            "operation_limit": capacity.max_retained_requests,
            "operations_remaining": capacity.max_retained_requests.saturating_sub(capacity.retained_requests),
            "journal_bytes": capacity.journal_bytes,
            "journal_limit_bytes": capacity.journal_limit_bytes,
            "journal_compaction": "before-entry-capacity-only",
            "compaction_reclaims_operation_identities": false,
            "admission_reserved": false,
            "full_openbao_compatibility": false,
            "production_qualified": false
        }}))
    }
}

#[cfg(test)]
mod tests {
    use super::super::tests::{Root, bootstrap, call, limited_token};
    use super::*;

    #[test]
    fn committed_ha_capacity_failure_is_reconcile_only_and_preserves_reference() {
        let refused =
            Service::ha_committed_local_failure(Response::error(507, "capacity exhausted"));
        assert_eq!(refused.status, 503);
        assert_eq!(refused.body["retry_allowed"], false);
        assert_eq!(refused.body["recovery_required"], true);
        let unknown = Service::ha_committed_local_failure(Response {
            status: 503,
            body: json!({"recovery_reference":"synthetic-reference", "unexpected":"must-not-propagate"}),
        });
        assert_eq!(unknown.body["recovery_reference"], "synthetic-reference");
        assert!(unknown.body.get("unexpected").is_none());
    }

    #[test]
    fn capacity_is_root_namespace_only_and_does_not_mutate()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = Root::new();
        let mut service = root.service()?;
        let (_, token) = bootstrap(&mut service)?;
        let generation = service
            .durable
            .as_ref()
            .ok_or("durable missing")?
            .generation();
        let response = call(
            &mut service,
            "GET",
            "sys/internal/capacity",
            &token,
            json!({}),
        );
        assert_eq!(response.status, 200);
        let data = &response.body["data"];
        assert_eq!(data["state_limit_bytes"], MAX_STATE_BYTES);
        assert_eq!(
            data["state_storage_format"],
            owner_store::STATE_STORAGE_FORMAT
        );
        assert_eq!(
            data["state_chunk_target_bytes"],
            owner_store::STATE_CHUNK_BYTES
        );
        assert_eq!(data["profile"], "bounded-owner-state-v4");
        assert_eq!(data["operation_limit"], MAX_OPERATIONS);
        assert_eq!(data["admission_reserved"], false);
        assert_eq!(data["compaction_reclaims_operation_identities"], false);
        assert_eq!(data["generation"], generation);
        assert_eq!(
            service
                .durable
                .as_ref()
                .ok_or("durable missing")?
                .generation(),
            generation
        );
        assert_eq!(
            service
                .handle_at(
                    "GET",
                    "sys/internal/capacity",
                    "tenant",
                    &token,
                    json!({}),
                    100
                )
                .status,
            403
        );
        assert_eq!(
            call(&mut service, "GET", "sys/internal/capacity", "", json!({})).status,
            403
        );
        let encoded = serde_json::to_string(&response.body)?;
        assert!(!encoded.contains(&token));
        assert!(!encoded.contains(root.path.to_str().ok_or("path encoding")?));
        Ok(())
    }

    #[test]
    fn capacity_reports_serialized_application_state_not_physical_chunk_bytes()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = Root::new();
        let mut service = root.service()?;
        let (_, token) = bootstrap(&mut service)?;
        service.state_capacity = 1024 * 1024;

        // Growing writes exercise V4 owner-scoped chunk replacement/reuse. The physical
        // durable payload can be larger than the currently serialized State even
        // though the application state itself remains admissible.
        let value = "x".repeat(280 * 1024);
        for index in 0..3 {
            let response = call(
                &mut service,
                "POST",
                &format!("secret/data/capacity-logical-{index}"),
                &token,
                json!({"data": {"synthetic": value}}),
            );
            assert_eq!(response.status, 200, "write {index} unexpectedly failed");
        }

        let durable_bytes = service
            .durable
            .as_ref()
            .ok_or("durable missing")?
            .capacity()?
            .logical_payload_bytes;
        let logical_bytes =
            serde_json::to_vec(service.state.as_ref().ok_or("state missing")?)?.len();
        assert!(durable_bytes > logical_bytes + 1);
        // V4 retires obsolete owner chunks instead of retaining an alternating slot.
        // Put the test-only bound between actual logical and physical sizes;
        // growth must not depend on the amount of historical garbage retained.
        service.state_capacity = logical_bytes + (durable_bytes - logical_bytes) / 2;
        let response = call(
            &mut service,
            "GET",
            "sys/internal/capacity",
            &token,
            json!({}),
        );
        assert_eq!(response.status, 200);
        let data = &response.body["data"];
        let state_bytes = data["state_bytes"].as_u64().ok_or("state bytes missing")? as usize;
        let state_limit = data["state_limit_bytes"]
            .as_u64()
            .ok_or("state limit missing")? as usize;
        let remaining = data["state_remaining_bytes"]
            .as_u64()
            .ok_or("remaining missing")? as usize;
        assert_eq!(state_limit, service.state_capacity);
        assert!(state_bytes < state_limit);
        assert_eq!(remaining, state_limit - state_bytes);
        assert!(durable_bytes > state_bytes);
        assert!(durable_bytes > state_limit);
        Ok(())
    }

    #[test]
    fn capacity_rejects_bad_method_payload_and_nonroot_even_with_sudo()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = Root::new();
        let mut service = root.service()?;
        let (_, token) = bootstrap(&mut service)?;
        assert_eq!(
            call(
                &mut service,
                "POST",
                "sys/internal/capacity",
                &token,
                json!({})
            )
            .status,
            405
        );
        assert_eq!(
            call(
                &mut service,
                "GET",
                "sys/internal/capacity",
                &token,
                json!({"reset": true})
            )
            .status,
            400
        );
        let limited = limited_token(
            &mut service,
            &token,
            r#"path "sys/internal/capacity" { capabilities = ["read", "sudo"] }"#,
        )?;
        assert_eq!(
            call(
                &mut service,
                "GET",
                "sys/internal/capacity",
                &limited,
                json!({})
            )
            .status,
            403
        );
        assert_eq!(
            call(
                &mut service,
                "GET",
                "sys/internal/capacity",
                &limited,
                json!({})
            )
            .status,
            403
        );
        Ok(())
    }

    #[test]
    fn capacity_reports_reopen_and_compaction_without_reclaiming_replay()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = Root::new();
        let mut service = root.service()?;
        let (key, token) = bootstrap(&mut service)?;
        assert_eq!(
            call(
                &mut service,
                "POST",
                "secret/data/capacity",
                &token,
                json!({"data": {"v": "synthetic"}})
            )
            .status,
            200
        );
        let before = call(
            &mut service,
            "GET",
            "sys/internal/capacity",
            &token,
            json!({}),
        );
        let generation = before.body["data"]["generation"].clone();
        let retained = before.body["data"]["retained_operations"].clone();
        assert_eq!(
            call(
                &mut service,
                "POST",
                "sys/storage/raft/compact",
                &token,
                json!({})
            )
            .status,
            200
        );
        drop(service);
        let mut service = root.service()?;
        assert_eq!(
            call(
                &mut service,
                "GET",
                "sys/internal/capacity",
                &token,
                json!({})
            )
            .status,
            503
        );
        assert_eq!(
            call(&mut service, "POST", "sys/unseal", "", json!({"key": key})).status,
            200
        );
        let after = call(
            &mut service,
            "GET",
            "sys/internal/capacity",
            &token,
            json!({}),
        );
        assert_eq!(after.status, 200);
        assert_eq!(after.body["data"]["generation"], generation);
        assert_eq!(after.body["data"]["retained_operations"], retained);
        assert_eq!(
            after.body["data"]["state_bytes"],
            before.body["data"]["state_bytes"]
        );
        Ok(())
    }
}
