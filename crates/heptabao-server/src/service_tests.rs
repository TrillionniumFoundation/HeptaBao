use super::*;
use std::sync::atomic::{AtomicU64, Ordering};
static ROOT_SEQUENCE: AtomicU64 = AtomicU64::new(1);
struct Root {
    path: PathBuf,
}
impl Root {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "heptabao-service-test-{}-{}",
            std::process::id(),
            ROOT_SEQUENCE.fetch_add(1, Ordering::Relaxed)
        ));
        Self { path }
    }
    fn service(&self) -> Result<Service, Box<dyn std::error::Error>> {
        if !self.path.exists() {
            private_directory(&self.path)?;
        }
        Service::new(self.path.join("data"), &self.path.join("audit.jsonl")).map_err(Into::into)
    }
}
impl Drop for Root {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}
fn call(service: &mut Service, method: &str, path: &str, token: &str, body: Value) -> Response {
    service.handle_at(method, path, "", token, body, 100)
}
fn bootstrap(service: &mut Service) -> Result<(String, String), Box<dyn std::error::Error>> {
    let response = call(
        service,
        "PUT",
        "sys/init",
        "",
        json!({"secret_shares":1,"secret_threshold":1}),
    );
    assert_eq!(response.status, 200);
    let key = response.body["keys_base64"][0]
        .as_str()
        .ok_or("missing key")?
        .to_owned();
    let token = response.body["root_token"]
        .as_str()
        .ok_or("missing token")?
        .to_owned();
    assert!(service.state.is_none());
    assert_eq!(
        call(service, "PUT", "sys/unseal", "", json!({"key":key})).status,
        200
    );
    Ok((key, token))
}
fn limited_token(
    service: &mut Service,
    root: &str,
    policy: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    let policy_response = call(
        service,
        "PUT",
        "sys/policies/acl/scoped",
        root,
        json!({"policy":policy}),
    );
    assert!(policy_response.status < 300);
    let response = call(
        service,
        "POST",
        "auth/token/create",
        root,
        json!({"policies":["scoped"],"no_default_policy":true,"num_uses":1}),
    );
    assert_eq!(response.status, 200);
    Ok(response.body["auth"]["client_token"]
        .as_str()
        .ok_or("missing limited token")?
        .to_owned())
}

#[test]
fn initialization_recovery_survives_response_loss_and_requires_root_ack()
-> Result<(), Box<dyn std::error::Error>> {
    let root = Root::new();
    let mut service = root.service()?;
    let secret = STANDARD.encode([93_u8; 32]);
    let body = json!({"secret_shares":3,"secret_threshold":2,"recovery_nonce":secret});
    let initialized = call(&mut service, "POST", "sys/init", "", body.clone());
    assert_eq!(initialized.status, 200);
    assert_eq!(initialized.body["init_ack_required"], true);
    let expected = initialized.body.clone();
    let keys = expected["keys_base64"].as_array().ok_or("missing shares")?;
    let token = expected["root_token"]
        .as_str()
        .ok_or("missing root token")?;
    let recovery_path = root.path.join("data").join(INIT_RECOVERY_FILE);
    for directory in [&root.path, &root.path.join("data")] {
        for entry in fs::read_dir(directory)? {
            let entry = entry?;
            if !entry.file_type()?.is_file() {
                continue;
            }
            let bytes = fs::read(entry.path())?;
            for credential in [
                secret.as_str(),
                token,
                keys[0].as_str().ok_or("missing first share")?,
            ] {
                assert!(
                    !bytes
                        .windows(credential.len())
                        .any(|window| window == credential.as_bytes())
                );
            }
        }
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            fs::metadata(&recovery_path)?.permissions().mode() & 0o777,
            0o600
        );
    }
    // Simulate losing the entire response and the process after publication.
    drop(initialized);
    drop(service);
    let mut service = root.service()?;
    let recovered = call(&mut service, "POST", "sys/init", "", body.clone());
    assert_eq!(recovered.status, 200);
    assert_eq!(recovered.body, expected);
    assert_eq!(
        call(&mut service, "GET", "sys/init", "", json!({})).body,
        json!({"initialized":true})
    );
    assert_eq!(
        call(
            &mut service,
            "POST",
            "sys/init",
            "",
            json!({"secret_shares":3,"secret_threshold":2})
        )
        .status,
        400
    );
    let mut wrong = body.clone();
    wrong["recovery_nonce"] = json!(STANDARD.encode([94_u8; 32]));
    assert_eq!(
        call(&mut service, "POST", "sys/init", "", wrong).status,
        403
    );
    let mut unknown = body.clone();
    unknown["unknown"] = json!(true);
    assert_eq!(
        call(&mut service, "POST", "sys/init", "", unknown).status,
        400
    );
    assert_eq!(
        service
            .handle_at("POST", "sys/init", "team", "", body.clone(), 100)
            .status,
        400
    );
    assert_eq!(
        call(&mut service, "POST", "sys/init/ack", token, json!({})).status,
        503
    );
    for key in keys.iter().take(2) {
        assert_eq!(
            call(&mut service, "POST", "sys/unseal", "", json!({"key":key})).status,
            200
        );
    }
    assert!(service.state.is_some());
    assert_eq!(
        call(&mut service, "POST", "sys/rekey/init", token, json!({})).status,
        409
    );
    assert_eq!(
        call(&mut service, "POST", "sys/init/ack", "", json!({})).status,
        403
    );
    assert_eq!(
        service
            .handle_at("POST", "sys/init/ack", "team", token, json!({}), 100)
            .status,
        403
    );
    let limited = limited_token(
        &mut service,
        token,
        r#"path "auth/token/lookup-self" { capabilities = ["read"] }"#,
    )?;
    assert_eq!(
        call(&mut service, "POST", "sys/init", &limited, body.clone()).body,
        expected
    );
    // Recovering with the client secret does not authenticate or consume this token.
    assert_eq!(
        call(
            &mut service,
            "GET",
            "auth/token/lookup-self",
            &limited,
            json!({})
        )
        .status,
        200
    );
    assert_eq!(
        call(&mut service, "POST", "sys/init/ack", token, json!({})).status,
        204
    );
    assert!(!recovery_path.exists());
    assert_eq!(
        call(&mut service, "POST", "sys/init/ack", token, json!({})).status,
        204
    );
    assert_eq!(
        call(&mut service, "POST", "sys/init", "", body.clone()).status,
        409
    );
    drop(service);
    let mut service = root.service()?;
    assert_eq!(call(&mut service, "POST", "sys/init", "", body).status, 409);
    for key in keys.iter().take(2) {
        assert_eq!(
            call(&mut service, "POST", "sys/unseal", "", json!({"key":key})).status,
            200
        );
    }
    assert_eq!(
        call(&mut service, "POST", "sys/rekey/init", token, json!({})).status,
        200
    );
    Ok(())
}

#[test]
fn initialization_recovery_rejects_tampering_wrong_seal_and_invalid_secret()
-> Result<(), Box<dyn std::error::Error>> {
    let root = Root::new();
    let mut service = root.service()?;
    for secret in [
        json!(null),
        json!(0),
        json!("short"),
        json!(STANDARD.encode([0_u8; 32])),
        json!("f".repeat(63)),
    ] {
        assert_eq!(
            call(
                &mut service,
                "POST",
                "sys/init",
                "",
                json!({"recovery_nonce":secret})
            )
            .status,
            400
        );
        assert!(!service.initialized());
    }
    let body = json!({"secret_shares":1,"secret_threshold":1,"recovery_nonce":"a3".repeat(32)});
    let response = call(&mut service, "POST", "sys/init", "", body.clone());
    assert_eq!(response.status, 200);
    let path = root.path.join("data").join(INIT_RECOVERY_FILE);
    let original = fs::read(&path)?;
    let mut tampered = original.clone();
    *tampered.last_mut().ok_or("empty recovery ciphertext")? ^= 1;
    fs::write(&path, tampered)?;
    assert_eq!(
        call(&mut service, "POST", "sys/init", "", body.clone()).status,
        403
    );
    fs::write(&path, &original)?;
    let seal_path = root.path.join("data").join(SEAL_METADATA_FILE);
    let original_seal = fs::read(&seal_path)?;
    let mut seal: SealMetadata = serde_json::from_slice(&original_seal)?;
    seal.generation += 1;
    fs::write(&seal_path, serde_json::to_vec(&seal)?)?;
    assert_eq!(
        call(&mut service, "POST", "sys/init", "", body.clone()).status,
        503
    );
    drop(service);
    let mut service = root.service()?;
    assert_eq!(
        call(&mut service, "POST", "sys/init", "", body.clone()).status,
        403
    );
    fs::write(&seal_path, &original_seal)?;
    drop(service);
    let mut service = root.service()?;
    fs::write(&path, vec![0_u8; INIT_RECOVERY_LIMIT as usize + 1])?;
    assert_eq!(
        call(&mut service, "POST", "sys/init", "", body.clone()).status,
        503
    );
    fs::write(&path, &original)?;
    #[cfg(unix)]
    {
        fs::remove_file(&path)?;
        std::os::unix::fs::symlink(&seal_path, &path)?;
        assert_eq!(
            call(&mut service, "POST", "sys/init", "", body.clone()).status,
            503
        );
        fs::remove_file(&path)?;
        fs::write(&path, &original)?;
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600))?;
    }
    assert_eq!(
        call(&mut service, "POST", "sys/init", "", body).body,
        response.body
    );
    Ok(())
}

#[test]
fn initialization_ack_directory_sync_failure_fences_and_retry_resyncs()
-> Result<(), Box<dyn std::error::Error>> {
    let root = Root::new();
    let mut service = root.service()?;
    let response = call(
        &mut service,
        "POST",
        "sys/init",
        "",
        json!({"secret_shares":1,"secret_threshold":1,"recovery_nonce":STANDARD.encode([92_u8;32])}),
    );
    assert_eq!(response.status, 200);
    let key = response.body["keys_base64"][0]
        .as_str()
        .ok_or("missing key")?;
    let token = response.body["root_token"]
        .as_str()
        .ok_or("missing root token")?;
    assert_eq!(
        call(&mut service, "POST", "sys/unseal", "", json!({"key":key})).status,
        200
    );
    let failed = service.ack_initialization_with_sync("POST", &json!({}), |_| {
        Err(io::Error::other("injected directory sync failure"))
    });
    assert_eq!(failed.status, 503);
    assert!(service.recovery_required);
    assert!(!root.path.join("data").join(INIT_RECOVERY_FILE).exists());
    assert_eq!(
        call(
            &mut service,
            "GET",
            "auth/token/lookup-self",
            token,
            json!({})
        )
        .status,
        503
    );
    assert_eq!(
        call(&mut service, "POST", "sys/unseal", "", json!({"key":key})).status,
        200
    );
    let resynced = std::cell::Cell::new(false);
    let retry = service.ack_initialization_with_sync("POST", &json!({}), |path| {
        resynced.set(true);
        File::open(path)?.sync_all()
    });
    assert_eq!(retry.status, 204);
    assert!(resynced.get());
    Ok(())
}

#[test]
fn initialization_without_recovery_secret_never_creates_escrow_and_legacy_is_rejected()
-> Result<(), Box<dyn std::error::Error>> {
    let root = Root::new();
    let mut service = root.service()?;
    let response = call(
        &mut service,
        "POST",
        "sys/init",
        "",
        json!({"secret_shares":1,"secret_threshold":1}),
    );
    assert_eq!(response.status, 200);
    assert!(response.body.get("init_ack_required").is_none());
    assert!(!initialization_recovery_pending(&service.data_dir)?);
    assert_eq!(call(&mut service, "POST", "sys/init", "", json!({"secret_shares":1,"secret_threshold":1,"recovery_nonce":STANDARD.encode([91_u8;32])})).status, 409);
    drop(service);
    fs::write(
        root.path.join("audit.jsonl.init-escrow"),
        b"legacy-audit-key-ciphertext",
    )?;
    assert!(root.service().is_err());
    Ok(())
}

#[test]
fn shamir_threshold_unseal_and_online_rekey_preserve_the_barrier_key()
-> Result<(), Box<dyn std::error::Error>> {
    let root = Root::new();
    let mut service = root.service()?;
    let initialized = call(
        &mut service,
        "PUT",
        "sys/init",
        "",
        json!({"secret_shares":5,"secret_threshold":3}),
    );
    assert_eq!(initialized.status, 200);
    let old_keys = initialized.body["keys_base64"]
        .as_array()
        .ok_or("missing Shamir shares")?
        .iter()
        .map(|value| {
            value
                .as_str()
                .ok_or("invalid Shamir share")
                .map(str::to_owned)
        })
        .collect::<Result<Vec<_>, _>>()?;
    let root_token = initialized.body["root_token"]
        .as_str()
        .ok_or("missing root token")?
        .to_owned();
    assert_eq!(old_keys.len(), 5);

    let first = call(
        &mut service,
        "PUT",
        "sys/unseal",
        "",
        json!({"key":old_keys[0]}),
    );
    assert_eq!(first.status, 200);
    assert_eq!(first.body["sealed"], true);
    assert_eq!(first.body["progress"], 1);
    let nonce = first.body["nonce"].as_str().ok_or("missing unseal nonce")?;
    let duplicate = call(
        &mut service,
        "PUT",
        "sys/unseal",
        "",
        json!({"key":old_keys[0]}),
    );
    assert_eq!(duplicate.body["progress"], 1);
    assert_eq!(duplicate.body["nonce"], nonce);
    assert_eq!(
        call(
            &mut service,
            "PUT",
            "sys/unseal",
            "",
            json!({"key":old_keys[2]}),
        )
        .body["progress"],
        2
    );
    let unsealed = call(
        &mut service,
        "PUT",
        "sys/unseal",
        "",
        json!({"key":old_keys[4]}),
    );
    assert_eq!(unsealed.status, 200);
    assert_eq!(unsealed.body["sealed"], false);

    assert_eq!(
        call(
            &mut service,
            "PUT",
            "secret/data/rekey",
            &root_token,
            json!({"data":{"value":"survives-rekey"}}),
        )
        .status,
        200
    );
    let start = call(
        &mut service,
        "POST",
        "sys/rekey/init",
        &root_token,
        json!({"secret_shares":4,"secret_threshold":2,"require_verification":false}),
    );
    assert_eq!(start.status, 200);
    let rekey_nonce = start.body["nonce"]
        .as_str()
        .ok_or("missing rekey nonce")?
        .to_owned();
    let first_update = call(
        &mut service,
        "POST",
        "sys/rekey/update",
        &root_token,
        json!({"nonce":rekey_nonce,"key":old_keys[1]}),
    );
    assert_eq!(first_update.status, 200);
    assert_eq!(first_update.body["complete"], false);
    let second_update = call(
        &mut service,
        "POST",
        "sys/rekey/update",
        &root_token,
        json!({"nonce":rekey_nonce,"key":old_keys[3]}),
    );
    assert_eq!(second_update.status, 200);
    assert_eq!(second_update.body["complete"], false);
    let completed = call(
        &mut service,
        "POST",
        "sys/rekey/update",
        &root_token,
        json!({"nonce":rekey_nonce,"key":old_keys[4]}),
    );
    assert_eq!(completed.status, 200);
    assert_eq!(completed.body["complete"], true);
    let new_keys = completed.body["keys_base64"]
        .as_array()
        .ok_or("missing rekey shares")?
        .iter()
        .map(|value| {
            value
                .as_str()
                .ok_or("invalid rekey share")
                .map(str::to_owned)
        })
        .collect::<Result<Vec<_>, _>>()?;
    assert_eq!(new_keys.len(), 4);

    assert_eq!(
        call(&mut service, "PUT", "sys/seal", &root_token, json!({})).status,
        204
    );
    assert_eq!(
        call(
            &mut service,
            "PUT",
            "sys/unseal",
            "",
            json!({"key":old_keys[0]}),
        )
        .status,
        400
    );
    assert_eq!(
        call(
            &mut service,
            "PUT",
            "sys/unseal",
            "",
            json!({"key":new_keys[0]}),
        )
        .body["progress"],
        1
    );
    assert_eq!(
        call(
            &mut service,
            "PUT",
            "sys/unseal",
            "",
            json!({"key":new_keys[2]}),
        )
        .body["sealed"],
        false
    );
    assert_eq!(
        call(
            &mut service,
            "GET",
            "secret/data/rekey",
            &root_token,
            json!({}),
        )
        .body["data"]["data"]["value"],
        "survives-rekey"
    );
    drop(service);

    let mut service = root.service()?;
    assert_eq!(
        call(
            &mut service,
            "PUT",
            "sys/unseal",
            "",
            json!({"key":new_keys[1]}),
        )
        .body["progress"],
        1
    );
    assert_eq!(
        call(
            &mut service,
            "PUT",
            "sys/unseal",
            "",
            json!({"key":new_keys[3]}),
        )
        .body["sealed"],
        false
    );
    Ok(())
}

#[test]
fn verified_rekey_survives_response_loss_restart_and_cancel()
-> Result<(), Box<dyn std::error::Error>> {
    let root = Root::new();
    let mut service = root.service()?;
    let initialized = call(
        &mut service,
        "PUT",
        "sys/init",
        "",
        json!({"secret_shares":5,"secret_threshold":3}),
    );
    assert_eq!(initialized.status, 200);
    let old_keys = initialized.body["keys_base64"]
        .as_array()
        .ok_or("missing original shares")?
        .iter()
        .map(|value| value.as_str().ok_or("invalid share").map(str::to_owned))
        .collect::<Result<Vec<_>, _>>()?;
    let root_token = initialized.body["root_token"]
        .as_str()
        .ok_or("missing root token")?
        .to_owned();
    for index in [0, 2, 4] {
        let response = call(
            &mut service,
            "PUT",
            "sys/unseal",
            "",
            json!({"key":old_keys[index]}),
        );
        assert_eq!(response.status, 200);
    }
    assert!(service.state.is_some());
    assert_eq!(
        call(
            &mut service,
            "PUT",
            "secret/data/verified-rekey",
            &root_token,
            json!({"data":{"value":"survives-verified-rekey"}}),
        )
        .status,
        200
    );

    let started = call(
        &mut service,
        "POST",
        "sys/rekey/init",
        &root_token,
        json!({"secret_shares":4,"secret_threshold":2}),
    );
    let authorization_nonce = started.body["nonce"]
        .as_str()
        .ok_or("missing rekey authorization nonce")?
        .to_owned();
    for index in [1, 3] {
        let response = call(
            &mut service,
            "POST",
            "sys/rekey/update",
            &root_token,
            json!({"nonce":authorization_nonce,"key":old_keys[index]}),
        );
        assert_eq!(response.status, 200);
        assert_eq!(response.body["complete"], false);
    }
    let staged = call(
        &mut service,
        "POST",
        "sys/rekey/update",
        &root_token,
        json!({"nonce":authorization_nonce,"key":old_keys[4]}),
    );
    assert_eq!(staged.status, 200);
    assert_eq!(staged.body["complete"], true);
    assert_eq!(staged.body["verification_required"], true);
    let verification_nonce = staged.body["verification_nonce"]
        .as_str()
        .ok_or("missing rekey verification nonce")?
        .to_owned();
    let new_keys = staged.body["keys_base64"]
        .as_array()
        .ok_or("missing candidate shares")?
        .iter()
        .map(|value| value.as_str().ok_or("invalid share").map(str::to_owned))
        .collect::<Result<Vec<_>, _>>()?;
    assert_eq!(new_keys.len(), 4);
    assert_eq!(
        service
            .seal
            .as_ref()
            .ok_or("missing active seal")?
            .generation,
        1
    );
    let pending_path = root.path.join("data").join(PENDING_REKEY_FILE);
    assert!(pending_path.is_file());
    let pending_text = fs::read_to_string(&pending_path)?;
    assert!(old_keys.iter().all(|share| !pending_text.contains(share)));
    assert!(new_keys.iter().all(|share| !pending_text.contains(share)));

    // Losing the response or process cannot activate keys that have not been
    // independently verified. The original shares remain authoritative.
    drop(staged);
    drop(service);
    let mut service = root.service()?;
    assert_eq!(
        call(
            &mut service,
            "PUT",
            "sys/unseal",
            "",
            json!({"key":new_keys[0]}),
        )
        .status,
        400
    );
    for index in [0, 1, 2] {
        assert_eq!(
            call(
                &mut service,
                "PUT",
                "sys/unseal",
                "",
                json!({"key":old_keys[index]}),
            )
            .status,
            200
        );
    }
    let status = call(
        &mut service,
        "GET",
        "sys/rekey/init",
        &root_token,
        json!({}),
    );
    assert_eq!(status.body["verification_required"], true);
    assert_eq!(status.body["verification_nonce"], verification_nonce);
    assert_eq!(status.body["verification_progress"], 0);
    let first_verify = call(
        &mut service,
        "POST",
        "sys/rekey/update",
        &root_token,
        json!({"nonce":verification_nonce,"key":new_keys[0]}),
    );
    assert_eq!(first_verify.status, 200);
    assert_eq!(first_verify.body["verification_progress"], 1);

    // Verification progress may be replayed after restart, but the pending
    // candidate and its nonce survive without changing the active seal.
    drop(service);
    let mut service = root.service()?;
    for index in [0, 2, 4] {
        assert_eq!(
            call(
                &mut service,
                "PUT",
                "sys/unseal",
                "",
                json!({"key":old_keys[index]}),
            )
            .status,
            200
        );
    }
    let resumed = call(
        &mut service,
        "GET",
        "sys/rekey/init",
        &root_token,
        json!({}),
    );
    assert_eq!(resumed.body["verification_nonce"], verification_nonce);
    assert_eq!(resumed.body["verification_progress"], 0);
    assert_eq!(
        call(
            &mut service,
            "POST",
            "sys/rekey/update",
            &root_token,
            json!({"nonce":verification_nonce,"key":new_keys[1]}),
        )
        .body["verification_progress"],
        1
    );
    let verified = call(
        &mut service,
        "POST",
        "sys/rekey/update",
        &root_token,
        json!({"nonce":verification_nonce,"key":new_keys[3]}),
    );
    assert_eq!(verified.status, 200);
    assert_eq!(verified.body["verification_required"], false);
    assert_eq!(
        service
            .seal
            .as_ref()
            .ok_or("missing promoted seal")?
            .generation,
        2
    );
    assert!(!pending_path.exists());

    assert_eq!(
        call(&mut service, "PUT", "sys/seal", &root_token, json!({})).status,
        204
    );
    assert_eq!(
        call(
            &mut service,
            "PUT",
            "sys/unseal",
            "",
            json!({"key":old_keys[0]}),
        )
        .status,
        400
    );
    for index in [0, 2] {
        assert_eq!(
            call(
                &mut service,
                "PUT",
                "sys/unseal",
                "",
                json!({"key":new_keys[index]}),
            )
            .status,
            200
        );
    }
    assert_eq!(
        call(
            &mut service,
            "GET",
            "secret/data/verified-rekey",
            &root_token,
            json!({}),
        )
        .body["data"]["data"]["value"],
        "survives-verified-rekey"
    );

    // A second staged generation can be cancelled durably. Its unpublished
    // shares never displace the currently active generation.
    let started = call(
        &mut service,
        "POST",
        "sys/rekey/init",
        &root_token,
        json!({"secret_shares":3,"secret_threshold":2,"require_verification":true}),
    );
    let nonce = started.body["nonce"]
        .as_str()
        .ok_or("missing nonce")?
        .to_owned();
    let partial = call(
        &mut service,
        "POST",
        "sys/rekey/update",
        &root_token,
        json!({"nonce":nonce,"key":new_keys[0]}),
    );
    assert_eq!(partial.body["complete"], false);
    let staged = call(
        &mut service,
        "POST",
        "sys/rekey/update",
        &root_token,
        json!({"nonce":nonce,"key":new_keys[2]}),
    );
    let cancelled_keys = staged.body["keys_base64"]
        .as_array()
        .ok_or("missing cancelled candidate shares")?
        .iter()
        .map(|value| value.as_str().ok_or("invalid share").map(str::to_owned))
        .collect::<Result<Vec<_>, _>>()?;
    assert!(pending_path.exists());
    assert_eq!(
        call(
            &mut service,
            "DELETE",
            "sys/rekey/init",
            &root_token,
            json!({}),
        )
        .status,
        204
    );
    assert!(!pending_path.exists());
    assert_eq!(
        call(&mut service, "PUT", "sys/seal", &root_token, json!({})).status,
        204
    );
    assert_eq!(
        call(
            &mut service,
            "PUT",
            "sys/unseal",
            "",
            json!({"key":cancelled_keys[0]}),
        )
        .status,
        400
    );
    for index in [1, 3] {
        assert_eq!(
            call(
                &mut service,
                "PUT",
                "sys/unseal",
                "",
                json!({"key":new_keys[index]}),
            )
            .status,
            200
        );
    }
    Ok(())
}

#[test]
fn init_seal_wrong_key_root_policy_kv_restart_and_no_plaintext_disk()
-> Result<(), Box<dyn std::error::Error>> {
    let root = Root::new();
    let mut service = root.service()?;
    let (key, token) = bootstrap(&mut service)?;
    assert_eq!(
        call(
            &mut service,
            "PUT",
            "secret/data/app",
            &token,
            json!({"data":{"password":"synthetic-private-secret"}})
        )
        .status,
        200
    );
    let reader = limited_token(
        &mut service,
        &token,
        r#"path "secret/data/app" { capabilities = ["read"] }"#,
    )?;
    let read = call(&mut service, "GET", "secret/data/app", &reader, json!({}));
    assert_eq!(read.status, 200);
    assert_eq!(
        read.body["data"]["data"]["password"],
        "synthetic-private-secret"
    );
    assert_eq!(
        call(&mut service, "PUT", "sys/seal", &token, json!({})).status,
        204
    );
    assert_eq!(
        call(&mut service, "GET", "secret/data/app", &token, json!({})).status,
        503
    );
    assert_eq!(
        call(
            &mut service,
            "PUT",
            "sys/unseal",
            "",
            json!({"key":STANDARD.encode([5;32])})
        )
        .status,
        400
    );
    assert!(service.state.is_none());
    drop(service);
    let mut service = root.service()?;
    assert_eq!(
        call(&mut service, "GET", "sys/seal-status", "", json!({})).body["sealed"],
        true
    );
    assert_eq!(
        call(&mut service, "PUT", "sys/unseal", "", json!({"key":key})).status,
        200
    );
    assert_eq!(
        call(&mut service, "GET", "secret/data/app", &token, json!({})).body["data"]["data"]["password"],
        "synthetic-private-secret"
    );
    assert_eq!(
        call(&mut service, "GET", "secret/data/app", &reader, json!({})).status,
        403
    );
    for file in [
        "data/state.hbs",
        "data/journal.hbj",
        "data/ledger.hbl",
        "data/seal.json",
        "audit.jsonl",
    ] {
        let bytes = fs::read(root.path.join(file))?;
        for secret in ["synthetic-private-secret", token.as_str(), key.as_str()] {
            assert!(!bytes.windows(secret.len()).any(|b| b == secret.as_bytes()));
        }
    }
    Ok(())
}

#[test]
fn finite_use_is_committed_for_acl_denial_and_state_capacity_rejection()
-> Result<(), Box<dyn std::error::Error>> {
    let root = Root::new();
    let mut service = root.service()?;
    let (key, token) = bootstrap(&mut service)?;
    let denied = limited_token(
        &mut service,
        &token,
        r#"path "secret/data/allowed" { capabilities = ["read"] }"#,
    )?;
    assert_eq!(
        call(
            &mut service,
            "GET",
            "secret/data/forbidden",
            &denied,
            json!({})
        )
        .status,
        403
    );
    drop(service);
    let mut service = root.service()?;
    assert_eq!(
        call(&mut service, "PUT", "sys/unseal", "", json!({"key":key})).status,
        200
    );
    assert_eq!(
        call(
            &mut service,
            "GET",
            "secret/data/allowed",
            &denied,
            json!({})
        )
        .status,
        403
    );
    let writer = limited_token(
        &mut service,
        &token,
        r#"path "secret/data/large" { capabilities = ["create", "update", "read"] }"#,
    )?;
    service.state_capacity =
        serde_json::to_vec(service.state.as_ref().ok_or("missing state")?)?.len();
    assert_eq!(
        call(
            &mut service,
            "PUT",
            "secret/data/large",
            &writer,
            json!({"data":{"value":"x".repeat(4000)}})
        )
        .status,
        507
    );
    service.state_capacity = MAX_STATE_BYTES;
    assert_eq!(
        call(&mut service, "GET", "secret/data/large", &writer, json!({})).status,
        403
    );
    assert_eq!(
        call(&mut service, "GET", "secret/data/large", &token, json!({})).status,
        404
    );
    drop(service);
    let mut service = root.service()?;
    assert_eq!(
        call(&mut service, "PUT", "sys/unseal", "", json!({"key":key})).status,
        200
    );
    assert_eq!(
        call(&mut service, "GET", "secret/data/large", &writer, json!({})).status,
        403
    );
    Ok(())
}

#[test]
fn unknown_commit_releases_no_secret_and_recovers_written_value()
-> Result<(), Box<dyn std::error::Error>> {
    let root = Root::new();
    let mut service = root.service()?;
    let (key, token) = bootstrap(&mut service)?;
    fs::create_dir(root.path.join("data/ledger.tmp"))?;
    let result = call(
        &mut service,
        "PUT",
        "secret/data/uncertain",
        &token,
        json!({"data":{"value":"uncertain-secret"}}),
    );
    assert_eq!(result.status, 503);
    assert!(result.body["recovery_reference"].is_string());
    assert!(!result.body.to_string().contains("uncertain-secret"));
    assert!(service.recovery_required);
    assert_eq!(
        call(
            &mut service,
            "GET",
            "secret/data/uncertain",
            &token,
            json!({})
        )
        .status,
        503
    );
    drop(service);
    fs::remove_dir(root.path.join("data/ledger.tmp"))?;
    let mut service = root.service()?;
    assert_eq!(
        call(&mut service, "PUT", "sys/unseal", "", json!({"key":key})).status,
        200
    );
    assert_eq!(
        call(
            &mut service,
            "GET",
            "secret/data/uncertain",
            &token,
            json!({})
        )
        .body["data"]["data"]["value"],
        "uncertain-secret"
    );
    Ok(())
}

#[test]
fn failed_engine_and_auth_transactions_leave_only_the_durable_token_consumption()
-> Result<(), Box<dyn std::error::Error>> {
    let root = Root::new();
    let mut service = root.service()?;
    let (_key, token) = bootstrap(&mut service)?;
    assert_eq!(
        call(
            &mut service,
            "PUT",
            "secret/data/app",
            &token,
            json!({"data":{"value":"first"}})
        )
        .status,
        200
    );
    let finite = limited_token(
        &mut service,
        &token,
        r#"path "secret/data/app" { capabilities = ["read", "update"] }"#,
    )?;
    assert_eq!(
        call(
            &mut service,
            "PUT",
            "secret/data/app",
            &finite,
            json!({"data":{"value":"bad-change"},"options":{"cas":99}})
        )
        .status,
        400
    );
    assert_eq!(
        call(&mut service, "GET", "secret/data/app", &finite, json!({})).status,
        403
    );
    assert_eq!(
        call(&mut service, "GET", "secret/data/app", &token, json!({})).body["data"]["data"]["value"],
        "first"
    );
    let state_before = serde_json::to_vec(service.state.as_ref().ok_or("missing state")?)?;
    let response = call(
        &mut service,
        "PUT",
        "auth/userpass/users/broken",
        &token,
        json!({"password":"synthetic-password","token_ttl":"not-a-duration"}),
    );
    assert_eq!(response.status, 400);
    assert_eq!(
        serde_json::to_vec(service.state.as_ref().ok_or("missing state")?)?,
        state_before
    );
    Ok(())
}

#[test]
fn all_failed_routes_are_audited_and_authenticated_audit_rejects_tampering()
-> Result<(), Box<dyn std::error::Error>> {
    let root = Root::new();
    let mut service = root.service()?;
    let (key, token) = bootstrap(&mut service)?;
    for (method, path, token, body, status) in [
        ("GET", "../invalid", "", json!({}), 400),
        ("GET", "secret/data/app", "invalid-token", json!({}), 403),
        ("PUT", "sys/init", "", json!({}), 400),
    ] {
        let sequence = service.audit_sequence;
        assert_eq!(call(&mut service, method, path, token, body).status, status);
        assert_eq!(service.audit_sequence, sequence + 2);
    }
    assert_eq!(
        call(&mut service, "PUT", "sys/seal", &token, json!({})).status,
        204
    );
    let sequence = service.audit_sequence;
    assert_eq!(
        call(
            &mut service,
            "PUT",
            "sys/unseal",
            "",
            json!({"key":"wrong"})
        )
        .status,
        400
    );
    assert_eq!(service.audit_sequence, sequence + 2);
    assert_eq!(
        call(&mut service, "PUT", "sys/unseal", "", json!({"key":key})).status,
        200
    );
    assert!(root.service().is_err()); // A second audit writer is fenced.
    drop(service);
    let path = root.path.join("audit.jsonl");
    let mut bytes = fs::read(&path)?;
    let index = bytes
        .windows(7)
        .position(|b| b == b"request")
        .ok_or("missing audit request")?;
    bytes[index] = b'X';
    fs::write(path, bytes)?;
    assert!(root.service().is_err());
    Ok(())
}

#[test]
fn result_audit_failure_withholds_plaintext_and_preserves_consumed_token_after_reopen()
-> Result<(), Box<dyn std::error::Error>> {
    let root = Root::new();
    let mut service = root.service()?;
    let (key, token) = bootstrap(&mut service)?;
    assert_eq!(
        call(
            &mut service,
            "PUT",
            "secret/data/app",
            &token,
            json!({"data":{"value":"withhold-this-plaintext"}})
        )
        .status,
        200
    );
    let finite = limited_token(
        &mut service,
        &token,
        r#"path "secret/data/app" { capabilities = ["read"] }"#,
    )?;
    // Reserve exactly the encoded next request audit record, leaving no room for
    // the result record. Admission and token consumption succeed before failure.
    let fingerprint = service.request_fingerprint("GET", "secret/data/app", "", &finite);
    let event = AuditUnsigned {
        schema: 2,
        sequence: service.audit_sequence + 1,
        previous: STANDARD.encode(service.audit_previous),
        time: 100,
        kind: "request".into(),
        path_digest: fingerprint,
        status: None,
    };
    let payload = serde_json::to_vec(&event)?;
    let mac = STANDARD.encode(hmac::sign(&service.audit_key, &payload).as_ref());
    let next = serde_json::to_vec(&AuditRecord { event, mac })?.len() + 1;
    service.audit_capacity = service.audit.metadata()?.len() + next as u64;
    let result = call(&mut service, "GET", "secret/data/app", &finite, json!({}));
    assert_eq!(result.status, 503);
    assert!(!result.body.to_string().contains("withhold-this-plaintext"));
    assert!(service.recovery_required);
    drop(service);
    let mut service = root.service()?;
    assert_eq!(
        call(&mut service, "PUT", "sys/unseal", "", json!({"key":key})).status,
        200
    );
    assert_eq!(
        call(&mut service, "GET", "secret/data/app", &finite, json!({})).status,
        403
    );
    assert_eq!(
        call(&mut service, "GET", "secret/data/app", &token, json!({})).body["data"]["data"]["value"],
        "withhold-this-plaintext"
    );
    Ok(())
}

#[test]
fn wire_rejections_are_audited_without_request_material() -> Result<(), Box<dyn std::error::Error>>
{
    let root = Root::new();
    let mut service = root.service()?;
    let before = service.audit_sequence;
    let response = service.handle_wire_rejection(
        &[7; 16],
        WireRejection::ParseRejected,
        400,
        "invalid wire request",
    );
    assert_eq!(response.status, 400);
    assert_eq!(service.audit_sequence, before + 2);
    drop(service);
    let audit = fs::read(root.path.join("audit.jsonl"))?;
    for forbidden in [
        "secret/data/private",
        "bearer-secret",
        "request-body-secret",
    ] {
        assert!(
            !audit
                .windows(forbidden.len())
                .any(|bytes| bytes == forbidden.as_bytes())
        );
    }
    let _ = root.service()?;
    Ok(())
}

#[test]
fn initialization_response_audit_failure_publishes_no_state_and_is_retryable()
-> Result<(), Box<dyn std::error::Error>> {
    let root = Root::new();
    let mut service = root.service()?;
    let body = json!({"secret_shares":3,"secret_threshold":2,"recovery_nonce":STANDARD.encode([73_u8;32])});
    let fingerprint = service.request_fingerprint("PUT", "sys/init", "", "");
    let event = AuditUnsigned {
        schema: 2,
        sequence: service.audit_sequence + 1,
        previous: STANDARD.encode(service.audit_previous),
        time: 100,
        kind: "request".into(),
        path_digest: fingerprint,
        status: None,
    };
    let payload = serde_json::to_vec(&event)?;
    let mac = STANDARD.encode(hmac::sign(&service.audit_key, &payload).as_ref());
    let next = serde_json::to_vec(&AuditRecord { event, mac })?.len() + 1;
    service.audit_capacity = service.audit.metadata()?.len() + next as u64;
    let response = call(&mut service, "PUT", "sys/init", "", body.clone());
    assert_eq!(response.status, 503);
    assert!(!service.initialized());
    assert!(service.seal.is_none());
    assert!(!root.path.join("data").exists());
    assert!(
        fs::read_dir(&root.path)?
            .filter_map(Result::ok)
            .all(|entry| !entry
                .file_name()
                .to_string_lossy()
                .starts_with(".heptabao-init-"))
    );
    drop(service);

    let mut service = root.service()?;
    let response = call(&mut service, "PUT", "sys/init", "", body);
    assert_eq!(response.status, 200);
    let key = response.body["keys_base64"][0]
        .as_str()
        .ok_or("missing retry key")?
        .to_owned();
    assert!(response.body["root_token"].as_str().is_some());
    assert!(service.initialized());
    assert_eq!(
        call(&mut service, "PUT", "sys/unseal", "", json!({"key":key})).status,
        200
    );
    Ok(())
}

#[test]
fn root_maintenance_routes_compact_snapshot_restore_and_reconcile()
-> Result<(), Box<dyn std::error::Error>> {
    let root = Root::new();
    let mut service = root.service()?;
    let (key, token) = bootstrap(&mut service)?;
    assert_eq!(
        call(
            &mut service,
            "PUT",
            "secret/data/maintenance",
            &token,
            json!({"data":{"value":"before-snapshot"}}),
        )
        .status,
        200
    );
    let snapshot_response = call(
        &mut service,
        "GET",
        "sys/storage/raft/snapshot",
        &token,
        json!({}),
    );
    assert_eq!(snapshot_response.status, 200);
    let snapshot = snapshot_response.body["data"]["snapshot"]
        .as_str()
        .ok_or("missing encrypted snapshot")?
        .to_owned();
    assert_eq!(
        snapshot_response.body["data"]["format"],
        "heptabao-encrypted-backup-v1"
    );

    assert_eq!(
        call(
            &mut service,
            "PUT",
            "secret/data/maintenance",
            &token,
            json!({"data":{"value":"after-snapshot"}}),
        )
        .status,
        200
    );
    assert_eq!(
        call(
            &mut service,
            "POST",
            "sys/storage/raft/snapshot",
            &token,
            json!({"snapshot":snapshot.clone()}),
        )
        .status,
        400
    );
    let restored = call(
        &mut service,
        "POST",
        "sys/storage/raft/snapshot-force",
        &token,
        json!({"snapshot":snapshot}),
    );
    assert_eq!(restored.status, 200);
    assert_eq!(restored.body["data"]["rollback"], true);
    assert_eq!(
        call(
            &mut service,
            "GET",
            "secret/data/maintenance",
            &token,
            json!({}),
        )
        .body["data"]["data"]["value"],
        "before-snapshot"
    );

    for number in 0..8 {
        assert_eq!(
            call(
                &mut service,
                "PUT",
                &format!("secret/data/compact-{number}"),
                &token,
                json!({"data":{"number":number}}),
            )
            .status,
            200
        );
    }
    let compacted = call(
        &mut service,
        "POST",
        "sys/storage/raft/compact",
        &token,
        json!({}),
    );
    assert_eq!(compacted.status, 200);
    assert!(
        compacted.body["data"]["journal_bytes_after"]
            .as_u64()
            .ok_or("missing compacted journal size")?
            < compacted.body["data"]["journal_bytes_before"]
                .as_u64()
                .ok_or("missing original journal size")?
    );

    let recovery_reference = match service
        .durable
        .as_mut()
        .ok_or("missing durable service")?
        .put(PutRequest::new(
            "maintenance-test",
            "system",
            "recovery-lookup",
            "maintenance-probe",
            crypto::digest(b"maintenance-probe"),
            Secret::new(b"probe".to_vec())?,
        )?)? {
        heptabao_durable_service::MutationOutcome::Committed {
            recovery_reference, ..
        } => recovery_reference,
        _ => return Err("unexpected duplicate maintenance probe".into()),
    };
    let lookup = call(
        &mut service,
        "GET",
        &format!("sys/internal/recovery/{recovery_reference}"),
        &token,
        json!({}),
    );
    assert_eq!(lookup.status, 200);
    assert_eq!(lookup.body["data"]["status"], "committed");
    assert_eq!(
        call(
            &mut service,
            "GET",
            "sys/internal/recovery/00000000000000000000000000000000",
            &token,
            json!({}),
        )
        .status,
        404
    );

    assert_eq!(
        call(&mut service, "PUT", "sys/seal", &token, json!({})).status,
        204
    );
    drop(service);
    let mut service = root.service()?;
    assert_eq!(
        call(&mut service, "PUT", "sys/unseal", "", json!({"key":key})).status,
        200
    );
    assert_eq!(
        call(
            &mut service,
            "GET",
            "secret/data/maintenance",
            &token,
            json!({}),
        )
        .body["data"]["data"]["value"],
        "before-snapshot"
    );
    Ok(())
}

#[test]
fn legacy_unkeyed_audit_and_partial_audit_tail_are_rejected()
-> Result<(), Box<dyn std::error::Error>> {
    let root = Root::new();
    private_directory(&root.path)?;
    let audit = root.path.join("audit.jsonl");
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(&audit)?;
    file.write_all(b"{\"schema\":1}\n")?;
    drop(file);
    assert!(root.service().is_err());
    fs::remove_file(&audit)?;
    let mut service = root.service()?;
    assert_eq!(
        call(&mut service, "GET", "sys/init", "", json!({})).status,
        200
    );
    drop(service);
    let length = fs::metadata(&audit)?.len();
    OpenOptions::new()
        .write(true)
        .open(&audit)?
        .set_len(length - 2)?;
    assert!(root.service().is_err());
    Ok(())
}
