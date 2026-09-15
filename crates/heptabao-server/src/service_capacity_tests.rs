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
