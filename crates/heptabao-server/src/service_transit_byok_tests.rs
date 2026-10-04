//! Wrapped AES material and conditional reader-floor tests through the real Service.
use super::tests::{Root, bootstrap};
use super::*;
use aws_lc_rs::key_wrap::{AES_256, AesKek, KeyWrapPadded};
use base64::engine::general_purpose::STANDARD as BASE64;
use openssl::{encrypt::Encrypter, hash::MessageDigest, pkey::PKey, rsa::Padding};
use zeroize::Zeroizing;

type TestResult<T = ()> = Result<T, &'static str>;

fn call(
    service: &mut Service,
    ns: &str,
    method: &str,
    path: &str,
    token: &str,
    body: Value,
) -> Response {
    service.handle_at(method, path, ns, token, body, 100)
}

fn wrap(public: &str, material: &[u8]) -> TestResult<String> {
    let public =
        PKey::public_key_from_pem(public.as_bytes()).map_err(|_| "test_public_parse_failed")?;
    let mut encrypter = Encrypter::new(&public).map_err(|_| "test_encrypter_failed")?;
    encrypter
        .set_rsa_padding(Padding::PKCS1_OAEP)
        .map_err(|_| "test_padding_failed")?;
    encrypter
        .set_rsa_oaep_md(MessageDigest::sha256())
        .map_err(|_| "test_digest_failed")?;
    encrypter
        .set_rsa_mgf1_md(MessageDigest::sha256())
        .map_err(|_| "test_mgf_failed")?;
    let mut envelope = vec![0; 512];
    assert!(
        encrypter
            .encrypt(&[0x41; 32], &mut envelope)
            .map_err(|_| "test_rsa_wrap_failed")?
            == 512
    );
    let kek = AesKek::new(&AES_256, &[0x41; 32]).map_err(|_| "test_kek_failed")?;
    let mut output = vec![0; material.len() + 15];
    envelope.extend_from_slice(
        kek.wrap_with_padding(material, &mut output)
            .map_err(|_| "test_kwp_failed")?,
    );
    Ok(BASE64.encode(envelope))
}

#[test]
fn byok_ordinary_service_retains_schema65_and_omitted_fields() -> TestResult {
    let root = Root::new();
    let mut service = root.service().map_err(|_| "test_service_failed")?;
    let (_, admin) = bootstrap(&mut service).map_err(|_| "test_bootstrap_failed")?;
    let admin = Zeroizing::new(admin);
    assert!(
        call(
            &mut service,
            "",
            "POST",
            "sys/mounts/ordinary",
            &admin,
            json!({"type":"transit"})
        )
        .status
            == 204
    );
    assert!(
        call(
            &mut service,
            "",
            "POST",
            "ordinary/keys/key",
            &admin,
            json!({})
        )
        .status
            == 200
    );
    let state = service.state.as_ref().ok_or("test_state_missing")?;
    assert!(state.schema == CURRENT_STATE_SCHEMA && state.writer_schema() == CURRENT_STATE_SCHEMA);
    assert!(!state.engines.has_transit_byok_state());
    let raw =
        Zeroizing::new(serde_json::to_vec(&state.engines).map_err(|_| "test_encoding_failed")?);
    assert!(
        !raw.windows(b"\"wrapping_key\"".len())
            .any(|window| window == b"\"wrapping_key\"")
    );
    assert!(
        !raw.windows(b"\"byok\"".len())
            .any(|window| window == b"\"byok\"")
    );
    Ok(())
}

#[test]
fn byok_tenant_imports_encrypted_restart_and_retirement_keep70() -> TestResult {
    let root = Root::new();
    let mut service = root.service().map_err(|_| "test_service_failed")?;
    let (unseal, admin) = bootstrap(&mut service).map_err(|_| "test_bootstrap_failed")?;
    let unseal = Zeroizing::new(unseal);
    let admin = Zeroizing::new(admin);
    assert!(
        call(
            &mut service,
            "",
            "POST",
            "sys/namespaces/team",
            &admin,
            json!({})
        )
        .status
            == 200
    );
    assert!(
        call(
            &mut service,
            "team",
            "POST",
            "sys/mounts/imported",
            &admin,
            json!({"type":"transit"})
        )
        .status
            == 204
    );
    let wrapping = call(
        &mut service,
        "team",
        "GET",
        "imported/wrapping_key",
        &admin,
        json!({}),
    );
    assert!(
        wrapping.status == 200,
        "public wrapping read commits the private custody"
    );
    let public = wrapping.body["data"]["public_key"]
        .as_str()
        .ok_or("test_public_missing")?
        .to_owned();
    let mut saved = Vec::new();
    for (name, kind, length) in [("a128", "aes128-gcm96", 16), ("a256", "aes256-gcm96", 32)] {
        let imported = call(
            &mut service,
            "team",
            "POST",
            &format!("imported/keys/{name}/import"),
            &admin,
            json!({"type":kind,"ciphertext":wrap(&public,&vec![0x50;length])?}),
        );
        assert!(
            imported.status == 204,
            "actual Service imports the wrapped AES key"
        );
        let plaintext = BASE64.encode(b"PUBLIC_BYOK_SERVICE_FIXTURE");
        let encrypted = call(
            &mut service,
            "team",
            "POST",
            &format!("imported/encrypt/{name}"),
            &admin,
            json!({"plaintext":plaintext}),
        );
        assert!(encrypted.status == 200, "actual imported AES encryption");
        let ciphertext = Zeroizing::new(
            encrypted.body["data"]["ciphertext"]
                .as_str()
                .ok_or("test_ciphertext_missing")?
                .to_owned(),
        );
        let payload = Zeroizing::new(
            BASE64
                .decode(
                    ciphertext
                        .strip_prefix("vault:v1:")
                        .ok_or("test_ciphertext_version_failed")?,
                )
                .map_err(|_| "test_ciphertext_decode_failed")?,
        );
        assert!(payload.len() >= 28, "AES-GCM payload has nonce and tag");
        let cipher = if length == 16 {
            openssl::symm::Cipher::aes_128_gcm()
        } else {
            openssl::symm::Cipher::aes_256_gcm()
        };
        let recovered = Zeroizing::new(
            openssl::symm::decrypt_aead(
                cipher,
                &vec![0x50; length],
                Some(&payload[..12]),
                &[],
                &payload[12..payload.len() - 16],
                &payload[payload.len() - 16..],
            )
            .map_err(|_| "independent_aes_failed")?,
        );
        assert!(
            recovered.as_slice() == b"PUBLIC_BYOK_SERVICE_FIXTURE",
            "independent maintained AES-GCM verifier binds imported material"
        );
        saved.push((name, ciphertext, plaintext));
    }
    let state = service.state.as_ref().ok_or("test_state_missing")?;
    assert!(state.schema == TRANSIT_BYOK_STATE_SCHEMA && state.engines.has_transit_byok_state());
    assert!(
        state.validate_format().is_ok(),
        "actual imported state admits the exact70 reader"
    );
    drop(service);
    let mut service = root.service().map_err(|_| "test_reopen_failed")?;
    assert!(
        call(
            &mut service,
            "",
            "POST",
            "sys/unseal",
            "",
            json!({"key":unseal.as_str()})
        )
        .status
            == 200,
        "actual encrypted restart unseals70"
    );
    let reloaded = call(
        &mut service,
        "team",
        "GET",
        "imported/wrapping_key",
        &admin,
        json!({}),
    );
    assert!(
        reloaded.status == 200 && reloaded.body["data"]["public_key"] == public,
        "encrypted restart preserves wrapping custody"
    );
    for (name, ciphertext, plaintext) in saved {
        let decoded = call(
            &mut service,
            "team",
            "POST",
            &format!("imported/decrypt/{name}"),
            &admin,
            json!({"ciphertext":ciphertext.as_str()}),
        );
        assert!(
            decoded.status == 200 && decoded.body["data"]["plaintext"] == plaintext,
            "encrypted restart preserves imported key versions"
        );
    }
    assert!(
        call(
            &mut service,
            "team",
            "DELETE",
            "sys/mounts/imported",
            &admin,
            json!({})
        )
        .status
            == 204
    );
    let before_rejected_namespace_delete = service
        .current_state_identity()
        .map_err(|_| "test_identity_failed")?;
    assert!(
        call(
            &mut service,
            "",
            "DELETE",
            "sys/namespaces/team",
            &admin,
            json!({})
        )
        .status
            == 409,
        "existing conservative namespace owner fence is preserved"
    );
    assert!(
        service
            .current_state_identity()
            .map_err(|_| "test_identity_failed")?
            == before_rejected_namespace_delete,
        "rejected populated namespace deletion preserves authoritative identity"
    );
    assert!(
        call(
            &mut service,
            "",
            "POST",
            "sys/namespaces/empty",
            &admin,
            json!({})
        )
        .status
            == 200
    );
    assert!(
        call(
            &mut service,
            "",
            "DELETE",
            "sys/namespaces/empty",
            &admin,
            json!({})
        )
        .status
            == 200,
        "actual empty namespace deletion remains available at retired schema70"
    );
    let current = service.state.as_ref().ok_or("test_state_missing")?;
    assert!(
        !current.engines.has_transit_byok_state() && current.schema == TRANSIT_BYOK_STATE_SCHEMA,
        "retired tenant custody keeps the reader floor sticky"
    );
    let mut lower = current.clone();
    lower.schema = JWT_PEM_KEYSET_STATE_SCHEMA;
    let identity = service
        .current_state_identity()
        .map_err(|_| "test_identity_failed")?;
    assert!(
        service.commit_state(&mut lower).is_err(),
        "retired70 publication rejects69"
    );
    assert!(
        service
            .current_state_identity()
            .map_err(|_| "test_identity_failed")?
            == identity,
        "rejected retired downgrade preserves the authoritative identity"
    );
    Ok(())
}

#[test]
fn byok_mixed_pem69_authenticated_restore_prepare_and_commit_reject_active_retired70_to69()
-> TestResult {
    let root = Root::new();
    let mut service = root.service().map_err(|_| "test_service_failed")?;
    let (_, admin) = bootstrap(&mut service).map_err(|_| "test_bootstrap_failed")?;
    let admin = Zeroizing::new(admin);
    assert!(
        call(
            &mut service,
            "",
            "POST",
            "sys/auth/pemjwt",
            &admin,
            json!({"type":"jwt"})
        )
        .status
            == 204
    );
    let key = PKey::generate_ed25519().map_err(|_| "test_ed_key_failed")?;
    let public = String::from_utf8(
        key.public_key_to_pem()
            .map_err(|_| "test_public_encoding_failed")?,
    )
    .map_err(|_| "test_public_encoding_failed")?;
    assert!(
        call(
            &mut service,
            "",
            "POST",
            "auth/pemjwt/config",
            &admin,
            json!({"bound_issuer":"https://issuer.example",
        "jwt_validation_pubkeys":[public],"jwt_supported_algs":["EdDSA"]})
        )
        .status
            == 204
    );
    assert!(
        service.state.as_ref().ok_or("test_state_missing")?.schema == JWT_PEM_KEYSET_STATE_SCHEMA,
        "real PEM configuration establishes69 predecessor"
    );
    let old69 = Zeroizing::new(
        service
            .durable
            .as_ref()
            .ok_or("test_durable_missing")?
            .export_backup()
            .map_err(|_| "test_backup_failed")?,
    );
    let first = service
        .prepare_snapshot_restore(&old69)
        .map_err(|_| "test_pre_feature_prepare_failed")?;
    let second = service
        .prepare_snapshot_restore(&old69)
        .map_err(|_| "test_pre_feature_prepare_failed")?;
    let mut plans = [first, second].into_iter();
    assert!(
        call(
            &mut service,
            "",
            "POST",
            "sys/mounts/imported",
            &admin,
            json!({"type":"transit"})
        )
        .status
            == 204
    );
    assert!(
        call(
            &mut service,
            "",
            "GET",
            "imported/wrapping_key",
            &admin,
            json!({})
        )
        .status
            == 200
    );
    let principal = service
        .state
        .as_mut()
        .ok_or("test_state_missing")?
        .auth
        .authenticate_from(&admin, 100, None)
        .map_err(|_| "test_actor_failed")?;
    let body = json!({});
    let request = RequestView {
        method: "POST",
        path: "sys/storage/raft/snapshot-force",
        namespace: "",
        token: &admin,
        body: &body,
        now: 100,
        admission_started: std::time::Instant::now(),
        allow_forward: false,
        enforce_namespace: true,
        wrap_ttl_seconds: None,
        origin_peer: None,
        client_certificates: None,
    };
    for retired in [false, true] {
        if retired {
            assert!(
                call(
                    &mut service,
                    "",
                    "DELETE",
                    "sys/mounts/imported",
                    &admin,
                    json!({})
                )
                .status
                    == 204
            );
        }
        let current = service.state.as_ref().ok_or("test_state_missing")?;
        assert!(
            current.schema == TRANSIT_BYOK_STATE_SCHEMA && current.auth.has_jwt_pem_keyset_state()
        );
        assert!(
            current.validate_format().is_ok(),
            "reader70 retains the real69 decoder"
        );
        let identity = service
            .current_state_identity()
            .map_err(|_| "test_identity_failed")?;
        let generation = service
            .external_effect_generation()
            .map_err(|_| "test_generation_failed")?;
        let before =
            Zeroizing::new(serde_json::to_vec(current).map_err(|_| "test_ram_encoding_failed")?);
        assert!(
            service
                .prepare_snapshot_restore(&old69)
                .err()
                .is_some_and(|error| error.status == 400)
        );
        assert!(
            service
                .prepare_snapshot_restore_from_reader(
                    &mut std::io::Cursor::new(old69.as_slice()),
                    old69.len() as u64
                )
                .err()
                .is_some_and(|error| error.status == 400)
        );
        let mut plan = plans.next().ok_or("test_affine_plan_missing")?;
        plan.fixture_rebind_base_for_protected_floor(identity);
        assert!(
            service
                .commit_snapshot_restore(plan, &principal, &request)
                .status
                == 400,
            "final active/retired70 to69 restore gate closes after genuine preparation"
        );
        let after = Zeroizing::new(
            serde_json::to_vec(service.state.as_ref().ok_or("test_state_missing")?)
                .map_err(|_| "test_ram_encoding_failed")?,
        );
        assert!(
            service
                .current_state_identity()
                .map_err(|_| "test_identity_failed")?
                == identity
                && service
                    .external_effect_generation()
                    .map_err(|_| "test_generation_failed")?
                    == generation
                && before.as_slice() == after.as_slice(),
            "rejected restore preserves complete RAM serialization and durable publication identity"
        );
    }
    assert!(
        plans.next().is_none(),
        "each genuine affine plan is consumed once"
    );
    Ok(())
}
