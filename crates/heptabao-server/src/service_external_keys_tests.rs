//! OpenBao 2.7 External Keys registry on the existing durable owner.
use super::tests::{Root, bootstrap, call, limited_token};
use super::*;
type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

use sha2::{Digest, Sha256};
use std::os::unix::fs::PermissionsExt;

struct VerificationProvider {
    plugin_path: PathBuf,
    plugin_sha256: String,
    sandbox_path: PathBuf,
    sandbox_sha256: String,
    trace_path: PathBuf,
}

impl VerificationProvider {
    fn install(root: &Path) -> TestResult<Self> {
        let directory = root.join("external-key-verification-provider");
        fs::create_dir_all(&directory)?;
        fs::set_permissions(&directory, fs::Permissions::from_mode(0o700))?;
        let plugin_path = directory.join("plugin");
        let sandbox_path = directory.join("sandbox.py");
        let trace_path = directory.join("trace.jsonl");
        let plugin = b"#!/bin/sh\nexit 0\n";
        let trace_literal = serde_json::to_string(
            trace_path
                .to_str()
                .ok_or_else(|| io::Error::other("provider trace path is not UTF-8"))?,
        )?;
        let sandbox = concat!(
            "#!/usr/bin/python3\n",
            "import json, struct, sys\n",
            "TRACE = __TRACE__\n",
            "data = sys.stdin.buffer.read()\n",
            "if len(data) < 11 or data[:4] != b'HBP1': sys.exit(2)\n",
            "length = struct.unpack('>I', data[7:11])[0]\n",
            "payload = data[11:]\n",
            "if length != len(payload): sys.exit(3)\n",
            "request = json.loads(payload.decode('utf-8'))\n",
            "action = request.get('action')\n",
            "if action not in ('verify_config', 'verify_key'): sys.exit(4)\n",
            "values = request.get('values') or {}\n",
            "config_values = request.get('config_values') or {}\n",
            "key_values = request.get('key_values') or {}\n",
            "reject = bool(values.get('provider_reject') or config_values.get('provider_reject') or key_values.get('provider_reject'))\n",
            "response = {'verified': not reject, 'namespace': request.get('namespace'), 'action': action, 'plugin': request.get('plugin'), 'config': request.get('config')}\n",
            "if action == 'verify_key': response['key'] = request.get('key')\n",
            "with open(TRACE, 'a', encoding='utf-8') as output:\n",
            "    output.write(json.dumps({'action': action, 'config': request.get('config'), 'key': request.get('key')}, separators=(',', ':')) + '\\n')\n",
            "encoded = json.dumps(response, separators=(',', ':')).encode('utf-8')\n",
            "sys.stdout.buffer.write(b'HBR1' + struct.pack('>I', len(encoded)) + encoded)\n",
        )
        .replace("__TRACE__", &trace_literal);
        fs::write(&plugin_path, plugin)?;
        fs::write(&sandbox_path, sandbox.as_bytes())?;
        fs::set_permissions(&plugin_path, fs::Permissions::from_mode(0o700))?;
        fs::set_permissions(&sandbox_path, fs::Permissions::from_mode(0o700))?;
        Ok(Self {
            plugin_sha256: hex(&Sha256::digest(plugin)),
            sandbox_sha256: hex(&Sha256::digest(sandbox.as_bytes())),
            plugin_path,
            sandbox_path,
            trace_path,
        })
    }

    fn config(&self, id: &str, enabled: bool) -> PluginKmsConfig {
        PluginKmsConfig {
            id: id.to_owned(),
            command: self.plugin_path.to_string_lossy().into_owned(),
            command_sha256: self.plugin_sha256.clone(),
            sandbox_provider_id: "external_keys_test_sandbox".into(),
            sandbox_command: self.sandbox_path.to_string_lossy().into_owned(),
            sandbox_command_sha256: self.sandbox_sha256.clone(),
            sandbox_profile_id: "external_keys_test_profile".into(),
            key_id: "external_keys_test_key".into(),
            key_version: 1,
            capabilities: vec!["wrap".into()],
            enabled,
            maximum_request_bytes: 256 * 1024,
            maximum_response_bytes: 1024 * 1024,
            timeout_ms: 5_000,
        }
    }

    fn trace(&self) -> TestResult<Vec<Value>> {
        if !self.trace_path.exists() {
            return Ok(Vec::new());
        }
        fs::read_to_string(&self.trace_path)?
            .lines()
            .map(|line| serde_json::from_str(line).map_err(Into::into))
            .collect()
    }
}

fn stage_external_key(
    service: &mut Service,
    token: &str,
    path: &'static str,
    body: Value,
) -> TestResult<PendingExternalRequest> {
    match service.begin_at_mode(RequestDispatch {
        method: "POST",
        path,
        namespace: "",
        token,
        body,
        now: 100,
        allow_forward: false,
        enforce_namespace: true,
        wrap_ttl_seconds: None,
        origin_peer: None,
        client_certificates: None,
    }) {
        RequestExecution::External(pending) => {
            if !matches!(pending.effect, ExternalEffectPlan::ExternalKey(_)) {
                return Err("request staged the wrong external effect".into());
            }
            Ok(*pending)
        }
        RequestExecution::Complete(response) => Err(format!(
            "external key verification did not stage: {}",
            response.status
        )
        .into()),
    }
}

#[test]
fn external_keys270_registry_is_durable_and_schema_fenced() -> TestResult {
    let root = Root::new();
    let mut service = root.service()?;
    let (unseal, admin) = bootstrap(&mut service)?;
    let empty = call(
        &mut service,
        "LIST",
        "sys/external-keys/configs",
        &admin,
        json!({}),
    );
    assert_eq!(empty.status, 404);
    assert_eq!(empty.body, json!({"errors":[]}));

    let created = call(
        &mut service,
        "POST",
        "sys/external-keys/configs/demo",
        &admin,
        json!({"plugin":"transit","verify":false,"address":"https://127.0.0.1:1",
            "token":"synthetic-never-used","mount_path":"transit","namespace":""}),
    );
    assert_eq!(created.status, 204);
    let state = service.state.as_ref().ok_or("state")?;
    assert_eq!(state.schema, CURRENT_STATE_SCHEMA);
    assert!(state.engines.has_external_key_state());

    let config = call(
        &mut service,
        "GET",
        "sys/external-keys/configs/demo",
        &admin,
        json!({}),
    );
    assert_eq!(config.status, 200);
    assert_eq!(config.body["data"]["plugin"], "transit");
    assert_eq!(config.body["data"]["token"], "(redacted)");
    assert_eq!(
        call(
            &mut service,
            "PATCH",
            "sys/external-keys/configs/demo",
            &admin,
            json!({"verify":false,"mount_path":"remote-transit","namespace":"team/"})
        )
        .status,
        204
    );
    let config = call(
        &mut service,
        "GET",
        "sys/external-keys/configs/demo",
        &admin,
        json!({}),
    );
    assert_eq!(config.body["data"]["mount_path"], "remote-transit");
    assert_eq!(config.body["data"]["namespace"], "team/");

    assert_eq!(
        call(
            &mut service,
            "POST",
            "sys/external-keys/configs/demo/keys/key1",
            &admin,
            json!({"verify":false,"name":"external","version":3})
        )
        .status,
        204
    );
    let key = call(
        &mut service,
        "GET",
        "sys/external-keys/configs/demo/keys/key1",
        &admin,
        json!({}),
    );
    assert_eq!(key.body["data"]["name"], "external");
    assert_eq!(key.body["data"]["version"], 3);
    for _ in 0..2 {
        assert_eq!(
            call(
                &mut service,
                "POST",
                "sys/external-keys/configs/demo/keys/key1/grants/pki",
                &admin,
                json!({})
            )
            .status,
            204
        );
    }
    let grants = call(
        &mut service,
        "LIST",
        "sys/external-keys/configs/demo/keys/key1/grants",
        &admin,
        json!({}),
    );
    assert_eq!(grants.body["data"]["keys"], json!(["pki/"]));

    let mut disguised = service.state.clone().ok_or("state")?;
    disguised.schema = 62;
    let denied = disguised
        .validate_format()
        .err()
        .ok_or("missing schema fence")?;
    assert_eq!(
        denied.body["errors"][0],
        "External Keys registry requires schema 63"
    );
    drop(service);

    let mut service = root.service()?;
    assert_eq!(
        call(
            &mut service,
            "POST",
            "sys/unseal",
            "",
            json!({"key":unseal})
        )
        .status,
        200
    );
    assert_eq!(
        call(
            &mut service,
            "GET",
            "sys/external-keys/configs/demo/keys/key1",
            &admin,
            json!({})
        )
        .body["data"]["version"],
        3
    );
    assert_eq!(
        call(
            &mut service,
            "DELETE",
            "sys/external-keys/configs/demo",
            &admin,
            json!({})
        )
        .status,
        204
    );
    let missing = call(
        &mut service,
        "GET",
        "sys/external-keys/configs/demo/keys/key1",
        &admin,
        json!({}),
    );
    assert_eq!(missing.status, 400);
    assert_eq!(missing.body["errors"][0], "key \"key1\" not found");
    let empty = call(
        &mut service,
        "LIST",
        "sys/external-keys/configs",
        &admin,
        json!({}),
    );
    assert_eq!(empty.status, 404);
    assert_eq!(empty.body, json!({"errors":[]}));
    Ok(())
}

#[test]
fn external_keys270_rejections_are_atomic_acl_bound_and_namespace_isolated() -> TestResult {
    let root = Root::new();
    let mut service = root.service()?;
    let (unseal, admin) = bootstrap(&mut service)?;

    let before = serde_json::to_vec(service.state.as_ref().ok_or("state")?)?;
    let verification = call(
        &mut service,
        "POST",
        "sys/external-keys/configs/rejected",
        &admin,
        json!({"plugin":"transit","token":"synthetic"}),
    );
    assert_eq!(verification.status, 501);
    assert!(
        serde_json::to_vec(service.state.as_ref().ok_or("state")?)? == before,
        "rejected registry write changed durable state"
    );
    let unknown = call(
        &mut service,
        "POST",
        "sys/external-keys/configs/rejected",
        &admin,
        json!({"plugin":"unknown","verify":false,"password":"must-not-persist"}),
    );
    assert_eq!(unknown.status, 400);
    assert!(
        serde_json::to_vec(service.state.as_ref().ok_or("state")?)? == before,
        "rejected registry write changed durable state"
    );

    let reader = limited_token(
        &mut service,
        &admin,
        r#"path "sys/external-keys/configs/*" { capabilities = ["read", "list"] }"#,
    )?;
    // Authentication precedes ACL evaluation. A rejected write must retain
    // exactly the accepted finite-use debit, not refund the credential.
    let mut expected = service.state.clone().ok_or("state")?;
    expected
        .auth
        .authenticate(&reader, 100)
        .map_err(|_| "expected authentication")?;
    let denied = call(
        &mut service,
        "POST",
        "sys/external-keys/configs/denied",
        &reader,
        json!({"plugin":"transit","verify":false,"token":"synthetic"}),
    );
    assert_eq!(denied.status, 403);
    assert!(
        serde_json::to_vec(service.state.as_ref().ok_or("state")?)?
            == serde_json::to_vec(&expected)?,
        "ACL denial changed state beyond the authenticated finite-use debit"
    );
    assert_eq!(
        call(
            &mut service,
            "GET",
            "sys/external-keys/configs/denied",
            &admin,
            json!({})
        )
        .status,
        400
    );
    assert_eq!(
        call(
            &mut service,
            "LIST",
            "sys/external-keys/configs",
            &reader,
            json!({})
        )
        .status,
        403
    );
    drop(service);
    let mut service = root.service()?;
    assert_eq!(
        call(
            &mut service,
            "POST",
            "sys/unseal",
            "",
            json!({"key":unseal})
        )
        .status,
        200
    );
    assert_eq!(
        call(
            &mut service,
            "LIST",
            "sys/external-keys/configs",
            &reader,
            json!({})
        )
        .status,
        403
    );
    assert_eq!(
        call(
            &mut service,
            "GET",
            "sys/external-keys/configs/denied",
            &admin,
            json!({})
        )
        .status,
        400
    );

    assert_eq!(
        call(
            &mut service,
            "POST",
            "sys/external-keys/configs/root-key",
            &admin,
            json!({"plugin":"pkcs11","verify":false,"pin":"synthetic-pin"}),
        )
        .status,
        204
    );
    let root_config = call(
        &mut service,
        "GET",
        "sys/external-keys/configs/root-key",
        &admin,
        json!({}),
    );
    assert_eq!(root_config.body["data"]["pin"], "(redacted)");

    assert_eq!(
        call(
            &mut service,
            "POST",
            "sys/namespaces/team",
            &admin,
            json!({"custom_metadata":{"owner":"external-keys-test"}}),
        )
        .status,
        200
    );
    assert_eq!(
        service
            .handle_at(
                "POST",
                "sys/external-keys/configs/team-key",
                "team",
                &admin,
                json!({"plugin":"transit","verify":false,"token":"team-secret"}),
                100,
            )
            .status,
        204
    );
    let root_list = call(
        &mut service,
        "LIST",
        "sys/external-keys/configs",
        &admin,
        json!({}),
    );
    assert_eq!(root_list.body["data"]["keys"], json!(["root-key"]));
    let team_list = service.handle_at(
        "LIST",
        "sys/external-keys/configs",
        "team",
        &admin,
        json!({}),
        100,
    );
    assert_eq!(team_list.body["data"]["keys"], json!(["team-key"]));
    assert_eq!(
        service
            .handle_at(
                "GET",
                "sys/external-keys/configs/root-key",
                "team",
                &admin,
                json!({}),
                100,
            )
            .status,
        400
    );
    Ok(())
}

#[test]
fn external_keys270_alias_only_acl_cannot_modify_the_canonical_config() -> TestResult {
    let root = Root::new();
    let mut service = root.service()?;
    let (_, admin) = bootstrap(&mut service)?;
    assert_eq!(
        call(
            &mut service,
            "POST",
            "sys/external-keys/configs/victim",
            &admin,
            json!({"plugin":"transit", "verify":false, "mount_path":"original"})
        )
        .status,
        204
    );
    let alias_actor = limited_token(
        &mut service,
        &admin,
        r#"path "sys/external-keys/configsvictim" { capabilities = ["update"] }"#,
    )?;
    let mut expected = service.state.clone().ok_or("state")?;
    expected
        .auth
        .authenticate(&alias_actor, 100)
        .map_err(|_| "expected authentication")?;
    let rejected = call(
        &mut service,
        "POST",
        "sys/external-keys/configsvictim",
        &alias_actor,
        json!({"plugin":"transit", "verify":false, "mount_path":"forbidden"}),
    );
    assert_eq!(rejected.status, 404);
    assert!(
        serde_json::to_vec(service.state.as_ref().ok_or("state")?)?
            == serde_json::to_vec(&expected)?,
        "alias request changed canonical state"
    );
    let readback = call(
        &mut service,
        "GET",
        "sys/external-keys/configs/victim",
        &admin,
        json!({}),
    );
    assert_eq!(readback.status, 200);
    assert_eq!(readback.body["data"]["mount_path"], "original");
    Ok(())
}

#[test]
fn external_keys270_client_private_key_redaction_survives_real_service_reopen() -> TestResult {
    let root = Root::new();
    let mut service = root.service()?;
    let (unseal, admin) = bootstrap(&mut service)?;
    let path = "sys/external-keys/configs/client-key";
    let canary = "synthetic-private-client-key-persistent-canary";
    assert_eq!(
        call(
            &mut service,
            "POST",
            path,
            &admin,
            json!({
                "plugin":"transit", "verify":false, "tls_client_key_bytes":canary,
                "tls_client_cert_bytes":"public-client-certificate"
            })
        )
        .status,
        204
    );
    for phase in 0..2 {
        if phase == 1 {
            drop(service);
            service = root.service()?;
            assert_eq!(
                call(
                    &mut service,
                    "POST",
                    "sys/unseal",
                    "",
                    json!({"key":unseal})
                )
                .status,
                200
            );
        }
        let before = Zeroizing::new(serde_json::to_vec(service.state.as_ref().ok_or("state")?)?);
        let response = call(&mut service, "GET", path, &admin, json!({}));
        assert_eq!(response.status, 200);
        assert!(
            response.body["data"]["tls_client_key_bytes"] == "(redacted)",
            "private client key was not redacted"
        );
        assert!(
            !serde_json::to_string(&response.body)?.contains(canary),
            "response exposed synthetic private key"
        );
        assert_eq!(
            response.body["data"]["tls_client_cert_bytes"],
            "public-client-certificate"
        );
        assert!(
            before.as_slice() == serde_json::to_vec(service.state.as_ref().ok_or("state")?)?,
            "read changed stored state"
        );
    }
    let reader = limited_token(
        &mut service,
        &admin,
        r#"path "sys/external-keys/configs/client-key" { capabilities = ["read"] }"#,
    )?;
    let response = call(&mut service, "GET", path, &reader, json!({}));
    assert_eq!(response.status, 200);
    assert!(response.body["data"]["tls_client_key_bytes"] == "(redacted)");
    assert!(!serde_json::to_string(&response.body)?.contains(canary));
    Ok(())
}

#[test]
fn external_keys270_oversized_patch_preserves_durable_config_key_and_grant() -> TestResult {
    let root = Root::new();
    let mut service = root.service()?;
    let (unseal, admin) = bootstrap(&mut service)?;
    let config = "sys/external-keys/configs/limit";
    let key = "sys/external-keys/configs/limit/keys/key1";
    let grant = "sys/external-keys/configs/limit/keys/key1/grants/pki";
    assert_eq!(call(&mut service, "POST", config, &admin,
        json!({"plugin":"transit","verify":false,"token":"original synthetic","namespace":"before/"})).status, 204);
    assert_eq!(
        call(
            &mut service,
            "POST",
            key,
            &admin,
            json!({"verify":false,"name":"before","version":1})
        )
        .status,
        204
    );
    assert_eq!(
        call(&mut service, "POST", grant, &admin, json!({})).status,
        204
    );
    let before = service.state_digest;
    for path in [config, key] {
        let rejected = call(
            &mut service,
            "PATCH",
            path,
            &admin,
            json!({"verify":false,"token":"x".repeat(64 * 1024),"namespace":"uncommitted/"}),
        );
        assert_eq!(rejected.status, 400);
        assert_eq!(service.state_digest, before);
    }
    drop(service);
    let mut service = root.service()?;
    assert_eq!(
        call(
            &mut service,
            "POST",
            "sys/unseal",
            "",
            json!({"key":unseal})
        )
        .status,
        200
    );
    let configuration = call(&mut service, "GET", config, &admin, json!({}));
    assert_eq!(configuration.status, 200);
    assert_eq!(configuration.body["data"]["namespace"], "before/");
    assert_eq!(configuration.body["data"]["token"], "(redacted)");
    let mapping = call(&mut service, "GET", key, &admin, json!({}));
    assert_eq!(mapping.status, 200);
    assert_eq!(mapping.body["data"]["name"], "before");
    assert_eq!(mapping.body["data"]["version"], 1);
    let grants = call(
        &mut service,
        "LIST",
        "sys/external-keys/configs/limit/keys/key1/grants",
        &admin,
        json!({}),
    );
    assert_eq!(grants.status, 200);
    assert_eq!(grants.body["data"]["keys"], json!(["pki/"]));
    Ok(())
}

#[test]
fn external_keys270_verify_true_uses_admitted_provider_before_atomic_publication() -> TestResult {
    let root = Root::new();
    let mut service = root.service()?;
    let provider = VerificationProvider::install(&root.path)?;
    service.install_kms_plugins(vec![provider.config("transit", true)])?;
    let (unseal, admin) = bootstrap(&mut service)?;

    let config = "sys/external-keys/configs/verified";
    let key = "sys/external-keys/configs/verified/keys/signing";
    assert_eq!(
        call(
            &mut service,
            "POST",
            config,
            &admin,
            json!({
                "plugin":"transit",
                "address":"https://kms.invalid",
                "token":"synthetic-provider-credential"
            })
        )
        .status,
        204
    );
    assert_eq!(
        call(
            &mut service,
            "POST",
            key,
            &admin,
            json!({"name":"remote-signing-key","version":7})
        )
        .status,
        204
    );
    let trace = provider.trace()?;
    assert_eq!(trace.len(), 2);
    assert_eq!(
        trace[0],
        json!({"action":"verify_config","config":"verified","key":null})
    );
    assert_eq!(
        trace[1],
        json!({"action":"verify_key","config":"verified","key":"signing"})
    );
    assert!(!fs::read_to_string(&provider.trace_path)?.contains("synthetic-provider-credential"));

    let readback = call(&mut service, "GET", config, &admin, json!({}));
    assert_eq!(readback.status, 200);
    assert_eq!(readback.body["data"]["token"], "(redacted)");
    assert_eq!(
        call(
            &mut service,
            "POST",
            "sys/external-keys/configs/verified/keys/signing/grants/pki",
            &admin,
            json!({})
        )
        .status,
        204
    );
    assert_eq!(
        provider.trace()?.len(),
        2,
        "grant mutation contacted provider"
    );

    drop(service);
    let mut service = root.service()?;
    service.install_kms_plugins(vec![provider.config("transit", true)])?;
    assert_eq!(
        call(
            &mut service,
            "POST",
            "sys/unseal",
            "",
            json!({"key":unseal})
        )
        .status,
        200
    );
    let mapping = call(&mut service, "GET", key, &admin, json!({}));
    assert_eq!(mapping.status, 200);
    assert_eq!(mapping.body["data"]["name"], "remote-signing-key");
    assert_eq!(mapping.body["data"]["version"], 7);
    assert_eq!(
        provider.trace()?.len(),
        2,
        "reopen replayed provider effect"
    );
    Ok(())
}

#[test]
fn external_keys270_provider_rejection_and_state_race_never_publish_candidate() -> TestResult {
    let root = Root::new();
    let mut service = root.service()?;
    let provider = VerificationProvider::install(&root.path)?;
    service.install_kms_plugins(vec![provider.config("transit", true)])?;
    let (_, admin) = bootstrap(&mut service)?;

    let before = service.state_digest;
    let rejected = call(
        &mut service,
        "POST",
        "sys/external-keys/configs/rejected",
        &admin,
        json!({"plugin":"transit","provider_reject":true}),
    );
    assert_eq!(rejected.status, 503);
    assert_eq!(service.state_digest, before);
    assert_ne!(
        call(
            &mut service,
            "GET",
            "sys/external-keys/configs/rejected",
            &admin,
            json!({})
        )
        .status,
        200
    );
    assert_eq!(provider.trace()?.len(), 1);

    assert_eq!(
        call(
            &mut service,
            "POST",
            "sys/external-keys/configs/unverified",
            &admin,
            json!({"plugin":"transit","verify":false,"provider_reject":true})
        )
        .status,
        204
    );
    assert_eq!(
        provider.trace()?.len(),
        1,
        "verify=false contacted provider"
    );

    let pending = stage_external_key(
        &mut service,
        &admin,
        "sys/external-keys/configs/stale",
        json!({"plugin":"transit","token":"stale-candidate-secret"}),
    )?;
    let observation = pending.execute();
    assert_eq!(provider.trace()?.len(), 2);
    assert_eq!(
        call(
            &mut service,
            "POST",
            "sys/external-keys/configs/concurrent",
            &admin,
            json!({"plugin":"transit","verify":false})
        )
        .status,
        204
    );
    let withheld = service.finish_external_request(pending, observation);
    assert_eq!(withheld.status, 503);
    assert!(
        withheld.body["errors"][0]
            .as_str()
            .is_some_and(|message| message.contains("state changed"))
    );
    assert_ne!(
        call(
            &mut service,
            "GET",
            "sys/external-keys/configs/stale",
            &admin,
            json!({})
        )
        .status,
        200
    );
    assert_eq!(
        call(
            &mut service,
            "GET",
            "sys/external-keys/configs/concurrent",
            &admin,
            json!({})
        )
        .status,
        200
    );
    Ok(())
}

#[test]
fn external_keys270_missing_or_disabled_provider_fails_closed_without_publication() -> TestResult {
    for scenario in ["missing", "disabled"] {
        let root = Root::new();
        let mut service = root.service()?;
        let provider = VerificationProvider::install(&root.path)?;
        if scenario == "disabled" {
            service.install_kms_plugins(vec![provider.config("transit", false)])?;
        }
        let (_, admin) = bootstrap(&mut service)?;
        let before = service.state_digest;
        let response = call(
            &mut service,
            "POST",
            "sys/external-keys/configs/blocked",
            &admin,
            json!({"plugin":"transit","token":"must-not-persist"}),
        );
        assert_eq!(
            response.status,
            if scenario == "missing" { 501 } else { 403 }
        );
        assert_eq!(service.state_digest, before, "scenario={scenario}");
        assert_ne!(
            call(
                &mut service,
                "GET",
                "sys/external-keys/configs/blocked",
                &admin,
                json!({})
            )
            .status,
            200,
            "scenario={scenario}"
        );
        assert!(provider.trace()?.is_empty(), "scenario={scenario}");
    }
    Ok(())
}

#[test]
fn external_keys270_verified_result_is_withheld_after_grant_delete_restore_aba() -> TestResult {
    let root = Root::new();
    let mut service = root.service()?;
    let provider = VerificationProvider::install(&root.path)?;
    service.install_kms_plugins(vec![provider.config("transit", true)])?;
    let (unseal, admin) = bootstrap(&mut service)?;
    let config = "sys/external-keys/configs/aba";
    let key = "sys/external-keys/configs/aba/keys/signing";
    let grant = "sys/external-keys/configs/aba/keys/signing/grants/transit";
    assert_eq!(
        call(
            &mut service,
            "POST",
            config,
            &admin,
            json!({"plugin":"transit","verify":false})
        )
        .status,
        204
    );
    assert_eq!(
        call(
            &mut service,
            "POST",
            key,
            &admin,
            json!({"verify":false,"name":"original","version":1})
        )
        .status,
        204
    );
    assert_eq!(
        call(&mut service, "POST", grant, &admin, json!({})).status,
        204
    );
    let identity = service
        .current_state_identity()
        .map_err(|response| format!("identity status {}", response.status))?;
    let generation = service.durable.as_ref().ok_or("durable")?.generation();
    let pending = stage_external_key(
        &mut service,
        &admin,
        key,
        json!({"name":"replacement","version":2}),
    )?;
    let observation = pending.execute();
    assert_eq!(
        provider.trace()?.len(),
        1,
        "provider did not actually execute"
    );
    assert_eq!(
        call(&mut service, "DELETE", grant, &admin, json!({})).status,
        204
    );
    assert_eq!(
        call(&mut service, "POST", grant, &admin, json!({})).status,
        204
    );
    assert_eq!(
        service
            .current_state_identity()
            .map_err(|response| format!("identity status {}", response.status))?,
        identity,
        "fixture did not restore identical content"
    );
    assert!(service.durable.as_ref().ok_or("durable")?.generation() > generation);
    let withheld = service.finish_external_request(pending, observation);
    assert_eq!(
        withheld.status, 503,
        "stale provider result survived a durable ABA"
    );
    assert_eq!(
        call(&mut service, "GET", key, &admin, json!({})).body["data"]["version"],
        1
    );
    drop(service);
    let mut service = root.service()?;
    assert_eq!(
        call(
            &mut service,
            "POST",
            "sys/unseal",
            "",
            json!({"key":unseal})
        )
        .status,
        200
    );
    let mapping = call(&mut service, "GET", key, &admin, json!({}));
    assert_eq!(mapping.body["data"]["name"], "original");
    assert_eq!(mapping.body["data"]["version"], 1);
    assert_eq!(
        provider.trace()?.len(),
        1,
        "restart replayed a provider effect"
    );
    Ok(())
}
#[test]
fn external_keys270_verified_result_is_withheld_after_raft_term_cycle_without_state_change()
-> TestResult {
    let root = Root::new();
    let mut service = root.service()?;
    let provider = VerificationProvider::install(&root.path)?;
    service.install_kms_plugins(vec![provider.config("transit", true)])?;
    let (unseal, admin) = bootstrap(&mut service)?;
    let config = "sys/external-keys/configs/term-cycle";
    let key = "sys/external-keys/configs/term-cycle/keys/signing";
    assert_eq!(
        call(
            &mut service,
            "POST",
            config,
            &admin,
            json!({"plugin":"transit","verify":false})
        )
        .status,
        204
    );
    assert_eq!(
        call(
            &mut service,
            "POST",
            key,
            &admin,
            json!({"verify":false,"name":"original","version":1})
        )
        .status,
        204
    );
    let cluster_id = service.state.as_ref().ok_or("state")?.cluster_id.clone();
    let cluster =
        crate::ha::snapshot_test_support::Cluster::new(&root.path.join("raft"), &cluster_id)?;
    service.ha = Some(Arc::clone(&cluster.processes[0]));
    service.sync_from_ha().map_err(|response| {
        format!(
            "initial anchor status {}: {}",
            response.status,
            response.body["errors"][0]
                .as_str()
                .unwrap_or("unclassified")
        )
    })?;
    let identity = service
        .current_state_identity()
        .map_err(|response| format!("identity status {}", response.status))?;
    let generation = service.durable.as_ref().ok_or("durable")?.generation();
    let frontier = service
        .consistency_observation()
        .map_err(|response| format!("frontier status {}", response.status))?
        .ok_or("frontier")?;
    let pending = stage_external_key(
        &mut service,
        &admin,
        key,
        json!({"name":"replacement","version":2}),
    )?;
    let observation = pending.execute();
    assert_eq!(
        provider.trace()?.len(),
        1,
        "provider did not actually execute"
    );
    // Both transitions are genuine quorum elections. The original Service,
    // unseal activation and durable owner remain the same throughout.
    let successor = cluster.processes[0].lock().map_err(|_| "HA")?.step_down()?;
    assert_ne!(successor, 1);
    let returned = cluster.processes[(successor - 1) as usize]
        .lock()
        .map_err(|_| "HA")?
        .step_down()?;
    assert_eq!(
        returned, 1,
        "fixture did not return authority to the same process"
    );
    service
        .sync_from_ha()
        .map_err(|response| format!("sync status {}", response.status))?;
    assert_eq!(
        service
            .current_state_identity()
            .map_err(|response| format!("identity status {}", response.status))?,
        identity
    );
    assert_eq!(
        service.durable.as_ref().ok_or("durable")?.generation(),
        generation,
        "fixture changed local publication"
    );
    let current = service
        .consistency_observation()
        .map_err(|response| format!("frontier status {}", response.status))?
        .ok_or("frontier")?;
    assert_ne!(
        (current.committed, current.applied),
        (frontier.committed, frontier.applied),
        "fixture did not advance real Raft frontier"
    );
    let withheld = service.finish_external_request(pending, observation);
    assert_eq!(
        withheld.status, 503,
        "stale result survived Raft authority loss and return"
    );
    assert_eq!(
        call(&mut service, "GET", key, &admin, json!({})).body["data"]["version"],
        1
    );
    drop(service);
    let mut service = root.service()?;
    assert_eq!(
        call(
            &mut service,
            "POST",
            "sys/unseal",
            "",
            json!({"key":unseal})
        )
        .status,
        200
    );
    let mapping = call(&mut service, "GET", key, &admin, json!({}));
    assert_eq!(mapping.body["data"]["name"], "original");
    assert_eq!(mapping.body["data"]["version"], 1);
    assert_eq!(
        provider.trace()?.len(),
        1,
        "restart replayed provider effect"
    );
    Ok(())
}
