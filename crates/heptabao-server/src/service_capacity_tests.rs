use super::*;

#[test]
fn capacity_observation_is_root_only_audited_and_nonmutating()
-> Result<(), Box<dyn std::error::Error>> {
    let root = std::env::temp_dir().join(format!(
        "heptabao-capacity-{}-{}",
        std::process::id(),
        hex(&crypto::random::<16>()?)
    ));
    private_directory(&root)?;
    let result = (|| -> Result<(), Box<dyn std::error::Error>> {
        let mut service = Service::new(root.join("data"), &root.join("audit.jsonl"))?;
        let init = service.handle_at(
            "POST",
            "sys/init",
            "",
            "",
            json!({"secret_shares": 1, "secret_threshold": 1}),
            100,
        );
        assert_eq!(init.status, 200);
        let key = init.body["keys_base64"][0].as_str().ok_or("missing key")?;
        let token = init.body["root_token"].as_str().ok_or("missing token")?;
        assert_eq!(
            service
                .handle_at("POST", "sys/unseal", "", "", json!({"key": key}), 100)
                .status,
            200
        );
        let initial = service
            .durable
            .as_ref()
            .ok_or("missing durable")?
            .capacity_status();
        let path = "sys/internal/storage/capacity";
        let response = service.handle_at("GET", path, "", token, Value::Null, 100);
        assert_eq!(response.status, 200);
        assert_eq!(response.body["data"]["state_limit_bytes"], MAX_STATE_BYTES);
        assert_eq!(response.body["data"]["replay_id_eviction"], false);
        assert_eq!(
            response.body["data"]["retained_requests"],
            initial.retained_requests
        );
        assert!(!serde_json::to_string(&response.body)?.contains(token));
        assert_eq!(
            service
                .handle_at("GET", path, "", "invalid-token", Value::Null, 100)
                .status,
            403
        );
        assert_eq!(
            service
                .handle_at("GET", path, "tenant", token, Value::Null, 100)
                .status,
            403
        );
        assert_eq!(
            service
                .handle_at("POST", path, "", token, json!({}), 100)
                .status,
            405
        );
        assert_eq!(
            service
                .handle_at("GET", path, "", token, json!({"unexpected": true}), 100)
                .status,
            400
        );
        let current = service
            .durable
            .as_ref()
            .ok_or("missing durable")?
            .capacity_status();
        assert_eq!(initial, current);
        assert!(fs::metadata(root.join("audit.jsonl"))?.len() > 0);
        Ok(())
    })();
    let _ = fs::remove_dir_all(&root);
    result
}

#[test]
fn exhausted_local_operation_budget_rejects_before_new_state_effect()
-> Result<(), Box<dyn std::error::Error>> {
    let root = std::env::temp_dir().join(format!(
        "heptabao-capacity-preflight-{}-{}",
        std::process::id(),
        hex(&crypto::random::<16>()?)
    ));
    private_directory(&root)?;
    let result = (|| -> Result<(), Box<dyn std::error::Error>> {
        let mut service = Service::new(root.join("data"), &root.join("audit.jsonl"))?;
        let init = service.handle_at(
            "POST",
            "sys/init",
            "",
            "",
            json!({"secret_shares": 1, "secret_threshold": 1}),
            100,
        );
        let key = init.body["keys_base64"][0].as_str().ok_or("missing key")?;
        let token = init.body["root_token"].as_str().ok_or("missing token")?;
        assert_eq!(
            service
                .handle_at("POST", "sys/unseal", "", "", json!({"key": key}), 100)
                .status,
            200
        );
        service.durable = None;
        let barrier_key = **service.barrier_key.as_ref().ok_or("missing barrier")?;
        service.durable = Some(DurableService::reopen(
            &service.data_dir,
            AeadBarrier::new(barrier_key)?,
            1,
        )?);
        let before = service
            .current_state_digest()
            .map_err(|_| "digest unavailable")?;
        let result = service.handle_at(
            "POST",
            "secret/data/capacity",
            "",
            token,
            json!({"data": {"value": "must-not-commit"}}),
            100,
        );
        assert_eq!(result.status, 507);
        assert_eq!(
            before,
            service
                .current_state_digest()
                .map_err(|_| "digest unavailable")?
        );
        assert!(!service.recovery_required);
        Ok(())
    })();
    let _ = fs::remove_dir_all(&root);
    result
}

#[test]
fn replay_retirement_is_root_only_and_state_commits_continue_in_new_epoch()
-> Result<(), Box<dyn std::error::Error>> {
    let root = std::env::temp_dir().join(format!(
        "heptabao-replay-retirement-{}-{}",
        std::process::id(),
        hex(&crypto::random::<16>()?)
    ));
    private_directory(&root)?;
    let result = (|| -> Result<(), Box<dyn std::error::Error>> {
        let mut service = Service::new(root.join("data"), &root.join("audit.jsonl"))?;
        let init = service.handle_at(
            "POST",
            "sys/init",
            "",
            "",
            json!({"secret_shares": 1, "secret_threshold": 1}),
            100,
        );
        assert_eq!(init.status, 200);
        let key = init.body["keys_base64"][0].as_str().ok_or("missing key")?;
        let token = init.body["root_token"].as_str().ok_or("missing token")?;
        assert_eq!(
            service
                .handle_at("POST", "sys/unseal", "", "", json!({"key": key}), 100)
                .status,
            200
        );
        let retire = "sys/storage/raft/replay-retire";
        assert_eq!(
            service
                .handle_at("POST", retire, "", "invalid-token", json!({}), 100)
                .status,
            403
        );
        let before = service
            .durable
            .as_ref()
            .ok_or("missing durable")?
            .retained_request_count();
        assert!(before > 0);
        let retired = service.handle_at("POST", retire, "", token, json!({}), 100);
        assert_eq!(retired.status, 200);
        assert_eq!(retired.body["data"]["previous_epoch"], 0);
        assert_eq!(retired.body["data"]["replay_epoch"], 1);
        assert!(
            retired.body["data"]["retired_requests"]
                .as_u64()
                .is_some_and(|n| n > 0)
        );
        let durable = service.durable.as_ref().ok_or("missing durable")?;
        assert_eq!(durable.replay_epoch(), 1);
        assert_eq!(durable.retained_request_count(), 1);
        assert_eq!(
            service.state.as_ref().ok_or("missing state")?.replay_epoch,
            1
        );

        // This mutation exercises Service::persist_state_batch. If it accidentally
        // rebinds to legacy epoch zero, the request fails before durable entry.
        let write = service.handle_at(
            "POST",
            "secret/data/post-retirement",
            "",
            token,
            json!({"data": {"value": "commits-in-epoch-one"}}),
            101,
        );
        assert_eq!(write.status, 200);
        let durable = service.durable.as_ref().ok_or("missing durable")?;
        assert_eq!(durable.replay_epoch(), 1);
        assert_eq!(durable.retained_request_count(), 2);
        Ok(())
    })();
    let _ = fs::remove_dir_all(&root);
    result
}

#[test]
fn replay_epoch_transition_bypasses_full_ledger_and_restart_preserves_frontier()
-> Result<(), Box<dyn std::error::Error>> {
    let root = std::env::temp_dir().join(format!(
        "heptabao-replay-full-{}-{}",
        std::process::id(),
        hex(&crypto::random::<16>()?)
    ));
    private_directory(&root)?;
    let result = (|| -> Result<(), Box<dyn std::error::Error>> {
        let data = root.join("data");
        let audit = root.join("audit.jsonl");
        let mut service = Service::new(data.clone(), &audit)?;
        let init = service.handle_at(
            "POST",
            "sys/init",
            "",
            "",
            json!({"secret_shares": 1, "secret_threshold": 1}),
            100,
        );
        assert_eq!(init.status, 200);
        let key = init.body["keys_base64"][0]
            .as_str()
            .ok_or("missing key")?
            .to_owned();
        let token = init.body["root_token"]
            .as_str()
            .ok_or("missing token")?
            .to_owned();
        assert_eq!(
            service
                .handle_at("POST", "sys/unseal", "", "", json!({"key": key}), 100)
                .status,
            200
        );

        // Reopen with a one-record active ledger. Initialization already occupies
        // that record, so an ordinary mutation must refuse while retirement must
        // remain available as the authenticated capacity escape hatch.
        service.durable = None;
        let barrier_key = **service.barrier_key.as_ref().ok_or("missing barrier")?;
        service.durable = Some(DurableService::reopen(
            &service.data_dir,
            AeadBarrier::new(barrier_key)?,
            1,
        )?);
        assert!(matches!(
            service
                .durable
                .as_ref()
                .ok_or("missing durable")?
                .preflight_new_identity(),
            Err(ServiceError::RequestCapacityExhausted)
        ));

        let retired = service.handle_at(
            "POST",
            "sys/storage/raft/replay-retire",
            "",
            &token,
            json!({}),
            101,
        );
        assert_eq!(retired.status, 200);
        assert_eq!(retired.body["data"]["replay_epoch"], 1);
        assert_eq!(
            service.state.as_ref().ok_or("missing state")?.replay_epoch,
            1
        );
        drop(service);

        let mut reopened = Service::new(data, &audit)?;
        assert_eq!(
            reopened
                .handle_at("POST", "sys/unseal", "", "", json!({"key": key}), 102)
                .status,
            200
        );
        assert_eq!(
            reopened.state.as_ref().ok_or("missing state")?.replay_epoch,
            1
        );
        assert_eq!(
            reopened
                .durable
                .as_ref()
                .ok_or("missing durable")?
                .replay_epoch(),
            1
        );
        Ok(())
    })();
    let _ = fs::remove_dir_all(&root);
    result
}

#[test]
fn ha_catch_up_epoch_transition_retires_local_ledger_before_state_publication()
-> Result<(), Box<dyn std::error::Error>> {
    let root = std::env::temp_dir().join(format!(
        "heptabao-replay-ha-apply-{}-{}",
        std::process::id(),
        hex(&crypto::random::<16>()?)
    ));
    private_directory(&root)?;
    let result = (|| -> Result<(), Box<dyn std::error::Error>> {
        let mut service = Service::new(root.join("data"), &root.join("audit.jsonl"))?;
        let init = service.handle_at(
            "POST",
            "sys/init",
            "",
            "",
            json!({"secret_shares": 1, "secret_threshold": 1}),
            100,
        );
        let key = init.body["keys_base64"][0].as_str().ok_or("missing key")?;
        assert_eq!(
            service
                .handle_at("POST", "sys/unseal", "", "", json!({"key": key}), 100)
                .status,
            200
        );
        let mut committed = service.state.clone().ok_or("missing state")?;
        committed.schema = CURRENT_STATE_SCHEMA;
        committed.replay_epoch = 1;
        let bytes = serde_json::to_vec(&committed)?;
        let before = service
            .durable
            .as_ref()
            .ok_or("missing durable")?
            .retained_request_count();
        assert!(before > 0);
        service
            .persist_local(
                &bytes,
                "hasync-epoch-transition",
                committed.schema,
                committed.replay_epoch,
            )
            .map_err(|_| "HA catch-up persistence failed")?;
        let durable = service.durable.as_ref().ok_or("missing durable")?;
        assert_eq!(durable.replay_epoch(), 1);
        assert_eq!(
            durable.retired_through_generation() + 1,
            durable.generation()
        );
        assert_eq!(durable.retained_request_count(), 1);
        Ok(())
    })();
    let _ = fs::remove_dir_all(&root);
    result
}

#[test]
fn ha_catch_up_can_advance_across_multiple_committed_replay_epochs_without_widening_local_writes()
-> Result<(), Box<dyn std::error::Error>> {
    let root = std::env::temp_dir().join(format!(
        "heptabao-replay-ha-multi-epoch-{}-{}",
        std::process::id(),
        hex(&crypto::random::<16>()?)
    ));
    private_directory(&root)?;
    let result = (|| -> Result<(), Box<dyn std::error::Error>> {
        let mut service = Service::new(root.join("data"), &root.join("audit.jsonl"))?;
        let init = service.handle_at(
            "POST",
            "sys/init",
            "",
            "",
            json!({"secret_shares": 1, "secret_threshold": 1}),
            100,
        );
        let key = init.body["keys_base64"][0].as_str().ok_or("missing key")?;
        assert_eq!(
            service
                .handle_at("POST", "sys/unseal", "", "", json!({"key": key}), 100)
                .status,
            200
        );
        let mut committed = service.state.clone().ok_or("missing state")?;
        committed.schema = CURRENT_STATE_SCHEMA;
        committed.replay_epoch = 3;
        let bytes = serde_json::to_vec(&committed)?;

        // An ordinary local publication must not acquire the authority to skip
        // replay epochs merely because the serialized state asks for it.
        assert!(
            service
                .persist_local(
                    &bytes,
                    "local-epoch-skip",
                    committed.schema,
                    committed.replay_epoch
                )
                .is_err()
        );
        assert_eq!(
            service
                .durable
                .as_ref()
                .ok_or("missing durable")?
                .replay_epoch(),
            0
        );

        // Authoritative HA catch-up may have missed several committed retirement
        // transitions while this node was offline. Advance the local replay
        // ledger monotonically through every missing epoch before publishing the
        // already-committed application state.
        service
            .persist_local_with_epoch_policy(
                &bytes,
                "hasync-multi-epoch",
                committed.schema,
                committed.replay_epoch,
                true,
            )
            .map_err(|_| "multi-epoch HA catch-up persistence failed")?;
        let durable = service.durable.as_ref().ok_or("missing durable")?;
        assert_eq!(durable.replay_epoch(), 3);
        assert_eq!(durable.retained_request_count(), 1);
        assert_eq!(
            durable.retired_through_generation() + 1,
            durable.generation()
        );
        Ok(())
    })();
    let _ = fs::remove_dir_all(&root);
    result
}

#[test]
fn failed_state_publication_after_epoch_retirement_fences_service()
-> Result<(), Box<dyn std::error::Error>> {
    let root = std::env::temp_dir().join(format!(
        "heptabao-replay-fence-{}-{}",
        std::process::id(),
        hex(&crypto::random::<16>()?)
    ));
    private_directory(&root)?;
    let result = (|| -> Result<(), Box<dyn std::error::Error>> {
        let mut service = Service::new(root.join("data"), &root.join("audit.jsonl"))?;
        let init = service.handle_at(
            "POST",
            "sys/init",
            "",
            "",
            json!({"secret_shares": 1, "secret_threshold": 1}),
            100,
        );
        let key = init.body["keys_base64"][0].as_str().ok_or("missing key")?;
        assert_eq!(
            service
                .handle_at("POST", "sys/unseal", "", "", json!({"key": key}), 100)
                .status,
            200
        );
        let mut target = service.state.clone().ok_or("missing state")?;
        target.schema = CURRENT_STATE_SCHEMA;
        target.replay_epoch = 1;
        let bytes = serde_json::to_vec(&target)?;

        // The invalid request identity is rejected only after the durable epoch
        // retirement has published. The wrapper must therefore fence the process.
        let response = service.persist_local(
            &bytes,
            "invalid request id",
            target.schema,
            target.replay_epoch,
        );
        assert!(response.is_err());
        assert_eq!(
            service
                .durable
                .as_ref()
                .ok_or("missing durable")?
                .replay_epoch(),
            1
        );
        assert!(service.recovery_required);
        Ok(())
    })();
    let _ = fs::remove_dir_all(&root);
    result
}
