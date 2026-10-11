//! Wrapped AES material and conditional reader-floor tests through the real Service.
use super::tests::{Root, bootstrap};
use super::*;
use aws_lc_rs::key_wrap::{AES_256, AesKek, KeyWrapPadded};
use base64::engine::general_purpose::STANDARD as BASE64;
use ml_dsa::Keypair as _;
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
    let retired70 = service
        .state
        .as_ref()
        .ok_or("actual last BYOK mount retired")?
        .clone();
    assert!(
        !retired70.engines.has_transit_byok_state()
            && retired70.schema == TRANSIT_BYOK_STATE_SCHEMA
    );
    let mut lower69 = retired70.clone();
    lower69.schema = JWT_PEM_KEYSET_STATE_SCHEMA;
    assert!(
        service.commit_state(&mut lower69).is_err(),
        "the actual retired70 owner cannot publish69 before namespace retirement"
    );
    let before_owned_namespace_delete = service
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
            == 200,
        "the cleaned local namespace owner can retire without resurrecting a BYOK key"
    );
    assert!(
        service
            .current_state_identity()
            .map_err(|_| "test_identity_failed")?
            != before_owned_namespace_delete,
        "actual namespace retirement publishes a new authoritative identity"
    );
    let pending = service.state.as_ref().ok_or("pending team deletion")?;
    assert!(
        pending.namespaces.contains("team") && pending.namespace_is_tainted("team"),
        "the accepted deletion keeps the original namespace tainted until real cleanup"
    );
    super::tests::finish_namespace_deletion_fixture(
        &mut service,
        "team",
        std::time::Duration::from_secs(100),
    )
    .map_err(|_| "actual native team cleanup failed")?;
    assert!(
        service
            .state
            .as_ref()
            .ok_or("retired team state")?
            .namespaces
            .incarnation("team")
            .is_none(),
        "actual cleaned tenant is absent"
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
    super::tests::finish_namespace_deletion_fixture(
        &mut service,
        "empty",
        std::time::Duration::from_secs(100),
    )
    .map_err(|_| "actual native empty cleanup failed")?;
    let current = service.state.as_ref().ok_or("test_state_missing")?;
    assert!(
        !current.engines.has_transit_byok_state()
            && current.schema == NAMESPACE_DELETION_STATE_SCHEMA
            && current.namespaces.has_custody_state()
            && current.has_namespace_deletion_state(),
        "real terminal namespace cleanup retains custody81, BYOK70 and the actual deletion106 owner floor"
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
        token_clock: None,
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

fn mldsa_fixture() -> TestResult<(Zeroizing<Vec<u8>>, String, String)> {
    use ml_dsa::pkcs8::{EncodePrivateKey, EncodePublicKey};
    let seed = Zeroizing::new(
        ml_dsa::Seed::try_from([0x50; 32].as_slice()).map_err(|_| "fixture_seed_failed")?,
    );
    let private = ml_dsa::SigningKey::<ml_dsa::MlDsa44>::from_seed(&seed);
    let der = private
        .to_pkcs8_der()
        .map_err(|_| "fixture_private_encoding_failed")?;
    let public = private
        .verifying_key()
        .to_public_key_der()
        .map_err(|_| "fixture_public_encoding_failed")?;
    let encoded = BASE64.encode(public.as_bytes());
    let mut pem = String::from("-----BEGIN PUBLIC KEY-----\n");
    for line in encoded.as_bytes().chunks(64) {
        pem.push_str(std::str::from_utf8(line).map_err(|_| "fixture_pem_failed")?);
        pem.push('\n');
    }
    pem.push_str("-----END PUBLIC KEY-----\n");
    let signature = private
        .expanded_key()
        .sign_randomized(b"public fixture", b"", &mut getrandom::SysRng)
        .map_err(|_| "fixture_signing_failed")?;
    Ok((
        Zeroizing::new(der.as_bytes().to_vec()),
        pem,
        format!("vault:v1:{}", BASE64.encode(signature.encode())),
    ))
}

#[test]
fn mldsa270_public_import_encrypted_restart_completion_and_retirement_keep116() -> TestResult {
    let root = Root::new();
    let mut service = root.service().map_err(|_| "service_failed")?;
    let (unseal, admin) = bootstrap(&mut service).map_err(|_| "bootstrap_failed")?;
    let unseal = Zeroizing::new(unseal);
    let admin = Zeroizing::new(admin);
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
    let old = Zeroizing::new(
        service
            .durable
            .as_ref()
            .ok_or("durable_missing")?
            .export_backup()
            .map_err(|_| "backup_failed")?,
    );
    let (private, public, signature) = mldsa_fixture()?;
    assert!(
        call(
            &mut service,
            "",
            "POST",
            "imported/keys/key/import",
            &admin,
            json!({"type":"mldsa-44","public_key":public})
        )
        .status
            == 204
    );
    let state = service.state.as_ref().ok_or("state_missing")?;
    assert!(
        state.schema == MLDSA_IMPORT_STATE_SCHEMA
            && state.writer_schema() == MLDSA_IMPORT_STATE_SCHEMA
            && state.engines.has_mldsa_import_state()
            && !state.engines.has_ssh_ca_state()
    );
    assert!(state.validate_format().is_ok());
    for schema in [
        CURRENT_STATE_SCHEMA,
        TRANSIT_BYOK_STATE_SCHEMA,
        SSH_CA_STATE_SCHEMA,
    ] {
        let mut lower = state.clone();
        lower.schema = schema;
        assert!(lower.validate_format().is_err());
        assert!(lower.validate_publication_schema(Some(state)).is_err());
    }
    assert!(
        service
            .prepare_snapshot_restore(&old)
            .err()
            .is_some_and(|e| e.status == 400)
    );
    drop(service);
    let mut service = root.service().map_err(|_| "reopen_failed")?;
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
            == 200
    );
    let verified = call(
        &mut service,
        "",
        "POST",
        "imported/verify/key",
        &admin,
        json!({"input":BASE64.encode(b"public fixture"),"signature":signature}),
    );
    assert!(verified.status == 200 && verified.body["data"]["valid"] == true);
    assert!(
        call(
            &mut service,
            "",
            "POST",
            "imported/sign/key",
            &admin,
            json!({"input":BASE64.encode(b"public fixture")})
        )
        .status
            >= 400
    );
    let public_wrap = call(
        &mut service,
        "",
        "GET",
        "imported/wrapping_key",
        &admin,
        json!({}),
    );
    let wrapping = public_wrap.body["data"]["public_key"]
        .as_str()
        .ok_or("wrapping_missing")?;
    let ciphertext = wrap(wrapping, &private)?;
    assert!(
        call(
            &mut service,
            "",
            "POST",
            "imported/keys/key/import_version",
            &admin,
            json!({"ciphertext":ciphertext})
        )
        .status
            == 204
    );
    let descriptor = call(
        &mut service,
        "",
        "GET",
        "imported/keys/key",
        &admin,
        json!({}),
    );
    assert!(descriptor.status == 200 && descriptor.body["data"]["latest_version"] == 1);
    let signed = call(
        &mut service,
        "",
        "POST",
        "imported/sign/key",
        &admin,
        json!({"input":BASE64.encode(b"public fixture")}),
    );
    assert!(signed.status == 200);
    let encoded = signed.body["data"]["signature"]
        .as_str()
        .and_then(|value| value.strip_prefix("vault:v1:"))
        .ok_or("signature_missing")?;
    let bytes = BASE64
        .decode(encoded)
        .map_err(|_| "signature_decoding_failed")?;
    let signature = ml_dsa::Signature::<ml_dsa::MlDsa44>::try_from(bytes.as_slice())
        .map_err(|_| "signature_parse_failed")?;
    let seed = ml_dsa::Seed::try_from([0x50; 32].as_slice()).map_err(|_| "seed_failed")?;
    assert!(
        ml_dsa::SigningKey::<ml_dsa::MlDsa44>::from_seed(&seed)
            .verifying_key()
            .verify_with_context(b"public fixture", b"", &signature)
    );
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
    let retired = service.state.as_ref().ok_or("retired_missing")?.clone();
    assert!(
        !retired.engines.has_mldsa_import_state() && retired.schema == MLDSA_IMPORT_STATE_SCHEMA
    );
    assert!(retired.validate_format().is_ok());
    let mut lower = retired.clone();
    lower.schema = CURRENT_STATE_SCHEMA;
    let identity = service
        .current_state_identity()
        .map_err(|_| "identity_failed")?;
    assert!(service.commit_state(&mut lower).is_err());
    assert!(
        service
            .prepare_snapshot_restore(&old)
            .err()
            .is_some_and(|e| e.status == 400)
    );
    assert!(
        service
            .current_state_identity()
            .map_err(|_| "identity_failed")?
            == identity
    );
    drop(service);
    let mut service = root.service().map_err(|_| "retired_reopen_failed")?;
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
            == 200
    );
    assert!(
        service
            .state
            .as_ref()
            .ok_or("retired_state_missing")?
            .schema
            == MLDSA_IMPORT_STATE_SCHEMA
    );
    Ok(())
}

#[test]
fn mldsa270_mixed116_retired_ssh_marker_cannot_be_erased_by_publication_or_restore() -> TestResult {
    let root = Root::new();
    let mut service = root.service().map_err(|_| "service_failed")?;
    let (_, admin) = bootstrap(&mut service).map_err(|_| "bootstrap_failed")?;
    let admin = Zeroizing::new(admin);
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
    let (_, public, _) = mldsa_fixture()?;
    assert!(
        call(
            &mut service,
            "",
            "POST",
            "imported/keys/key/import",
            &admin,
            json!({"type":"mldsa-44","public_key":public})
        )
        .status
            == 204
    );
    let pure116 = Zeroizing::new(
        service
            .durable
            .as_ref()
            .ok_or("durable_missing")?
            .export_backup()
            .map_err(|_| "backup_failed")?,
    );
    let mut plan = service
        .prepare_snapshot_restore(&pure116)
        .map_err(|_| "pure116_prepare_failed")?;
    assert!(
        call(
            &mut service,
            "",
            "POST",
            "sys/mounts/ssh",
            &admin,
            json!({"type":"ssh"})
        )
        .status
            == 204
    );
    assert!(
        call(
            &mut service,
            "",
            "POST",
            "ssh/config/ca",
            &admin,
            json!({"key_type":"ed25519"})
        )
        .status
            == 200
    );
    assert!(service.state.as_ref().ok_or("mixed_missing")?.schema == MLDSA_IMPORT_STATE_SCHEMA);
    assert!(
        call(
            &mut service,
            "",
            "DELETE",
            "sys/mounts/ssh",
            &admin,
            json!({})
        )
        .status
            == 204
    );
    let retired = service.state.as_ref().ok_or("retired_missing")?.clone();
    assert!(
        retired.engines.has_ssh_ca_state()
            && retired.engines.has_mldsa_import_state()
            && retired.schema == MLDSA_IMPORT_STATE_SCHEMA
            && retired.validate_format().is_ok()
    );
    let mut stripped = retired.clone();
    let mut value =
        serde_json::to_value(&stripped.engines).map_err(|_| "engine_encoding_failed")?;
    value
        .as_object_mut()
        .ok_or("engine_object_missing")?
        .remove("ssh_ca_format");
    stripped.engines = serde_json::from_value(value).map_err(|_| "engine_decoding_failed")?;
    assert!(!stripped.engines.has_ssh_ca_state());
    assert!(
        stripped
            .validate_publication_schema(Some(&retired))
            .is_err()
    );
    assert!(Service::validate_snapshot_protected_floor(&retired, &stripped).is_err());
    let identity = service
        .current_state_identity()
        .map_err(|_| "identity_failed")?;
    assert!(service.commit_state(&mut stripped).is_err());
    assert!(
        service
            .prepare_snapshot_restore(&pure116)
            .err()
            .is_some_and(|e| e.status == 400)
    );
    let principal = service
        .state
        .as_mut()
        .ok_or("state_missing")?
        .auth
        .authenticate_from(&admin, 100, None)
        .map_err(|_| "actor_failed")?;
    let body = json!({});
    let request = RequestView {
        method: "POST",
        path: "sys/storage/raft/snapshot-force",
        namespace: "",
        token: &admin,
        body: &body,
        now: 100,
        admission_started: std::time::Instant::now(),
        token_clock: None,
        allow_forward: false,
        enforce_namespace: true,
        wrap_ttl_seconds: None,
        origin_peer: None,
        client_certificates: None,
    };
    plan.fixture_rebind_base_for_protected_floor(identity);
    assert!(
        service
            .commit_snapshot_restore(plan, &principal, &request)
            .status
            == 400
    );
    assert!(
        service
            .current_state_identity()
            .map_err(|_| "identity_failed")?
            == identity
    );
    assert!(
        service
            .state
            .as_ref()
            .ok_or("final_state_missing")?
            .engines
            .has_ssh_ca_state()
    );
    Ok(())
}

#[test]
fn mldsa270_existing115_ssh_history_survives_upgrade_to116_and_mount_retirement() -> TestResult {
    let root = Root::new();
    let mut service = root.service().map_err(|_| "service_failed")?;
    let (_, admin) = bootstrap(&mut service).map_err(|_| "bootstrap_failed")?;
    let admin = Zeroizing::new(admin);
    assert!(
        call(
            &mut service,
            "",
            "POST",
            "sys/mounts/ssh",
            &admin,
            json!({"type":"ssh"})
        )
        .status
            == 204
    );
    assert!(
        call(
            &mut service,
            "",
            "POST",
            "ssh/config/ca",
            &admin,
            json!({"key_type":"ed25519"})
        )
        .status
            == 200
    );
    let original115 = service.state.as_ref().ok_or("original115_missing")?.clone();
    assert!(original115.schema == SSH_CA_STATE_SCHEMA && original115.engines.has_ssh_ca_state());
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
    let (_, public, _) = mldsa_fixture()?;
    assert!(
        call(
            &mut service,
            "",
            "POST",
            "imported/keys/key/import",
            &admin,
            json!({"type":"mldsa-44","public_key":public})
        )
        .status
            == 204
    );
    assert!(
        call(
            &mut service,
            "",
            "DELETE",
            "sys/mounts/ssh",
            &admin,
            json!({})
        )
        .status
            == 204
    );
    let retired116 = service.state.as_ref().ok_or("retired116_missing")?.clone();
    assert!(
        retired116.schema == MLDSA_IMPORT_STATE_SCHEMA
            && retired116.engines.has_ssh_ca_state()
            && retired116.engines.has_mldsa_import_state()
    );
    assert!(
        retired116
            .validate_publication_schema(Some(&original115))
            .is_ok()
    );
    let mut stripped = retired116.clone();
    let mut value =
        serde_json::to_value(&stripped.engines).map_err(|_| "engine_encoding_failed")?;
    value
        .as_object_mut()
        .ok_or("engine_object_missing")?
        .remove("ssh_ca_format");
    stripped.engines = serde_json::from_value(value).map_err(|_| "engine_decoding_failed")?;
    assert!(
        stripped
            .validate_publication_schema(Some(&original115))
            .is_err()
    );
    assert!(
        stripped
            .validate_publication_schema(Some(&retired116))
            .is_err()
    );
    assert!(Service::validate_snapshot_protected_floor(&retired116, &stripped).is_err());
    assert!(service.commit_state(&mut stripped).is_err());
    assert!(
        service
            .state
            .as_ref()
            .ok_or("final_missing")?
            .engines
            .has_ssh_ca_state()
    );
    Ok(())
}

#[test]
fn asymmetric270_public_import_real_restart_private_completion_and_retirement_keep117() -> TestResult
{
    use openssl::sign::{Signer, Verifier};
    let root = Root::new();
    let mut service = root.service().map_err(|_| "service_failed")?;
    let (unseal, admin) = bootstrap(&mut service).map_err(|_| "bootstrap_failed")?;
    let unseal = Zeroizing::new(unseal);
    let admin = Zeroizing::new(admin);
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
    let old = Zeroizing::new(
        service
            .durable
            .as_ref()
            .ok_or("durable_missing")?
            .export_backup()
            .map_err(|_| "old_backup_failed")?,
    );
    let pair = PKey::generate_ed25519().map_err(|_| "Ed_generation_failed")?;
    let private = Zeroizing::new(
        pair.private_key_to_pkcs8()
            .map_err(|_| "private_PKCS8_failed")?,
    );
    let public = String::from_utf8(pair.public_key_to_pem().map_err(|_| "public_PEM_failed")?)
        .map_err(|_| "PEM_UTF8_failed")?;
    let message = b"standard public fixture";
    let signature = Signer::new_without_digest(&pair)
        .map_err(|_| "independent_signer_failed")?
        .sign_oneshot_to_vec(message)
        .map_err(|_| "independent_sign_failed")?;
    let wrapped_signature = format!("vault:v1:{}", BASE64.encode(&signature));
    assert!(
        call(
            &mut service,
            "",
            "POST",
            "imported/keys/key/import",
            &admin,
            json!({"type":"ed25519","public_key":public,"exportable":true})
        )
        .status
            == 204
    );
    let state = service.state.as_ref().ok_or("state_missing")?;
    assert!(
        state.schema == STANDARD_ASYMMETRIC_IMPORT_STATE_SCHEMA
            && state.writer_schema() == STANDARD_ASYMMETRIC_IMPORT_STATE_SCHEMA
            && state.engines.has_standard_asymmetric_import_state()
    );
    assert!(state.validate_format().is_ok());
    for schema in [
        CURRENT_STATE_SCHEMA,
        TRANSIT_BYOK_STATE_SCHEMA,
        MLDSA_IMPORT_STATE_SCHEMA,
    ] {
        let mut lower = state.clone();
        lower.schema = schema;
        assert!(lower.validate_format().is_err());
        assert!(lower.validate_publication_schema(Some(state)).is_err());
        assert!(Service::validate_snapshot_protected_floor(state, &lower).is_err());
    }
    assert!(
        service
            .prepare_snapshot_restore(&old)
            .err()
            .is_some_and(|e| e.status == 400)
    );
    let hmac = call(
        &mut service,
        "",
        "POST",
        "imported/hmac/key/sha2-256",
        &admin,
        json!({"input":BASE64.encode(message)}),
    );
    assert!(hmac.status == 200);
    let hmac_tag = hmac.body["data"]["hmac"]
        .as_str()
        .ok_or("HMAC_missing")?
        .to_owned();
    drop(service);
    let mut service = root.service().map_err(|_| "reopen_failed")?;
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
            == 200
    );
    let verified = call(
        &mut service,
        "",
        "POST",
        "imported/verify/key/none",
        &admin,
        json!({"input":BASE64.encode(message),"signature":wrapped_signature}),
    );
    assert!(verified.status == 200 && verified.body["data"]["valid"] == json!(true));
    let wrapping = call(
        &mut service,
        "",
        "GET",
        "imported/wrapping_key",
        &admin,
        json!({}),
    );
    assert!(wrapping.status == 200);
    let public_wrapping = wrapping.body["data"]["public_key"]
        .as_str()
        .ok_or("wrapping_missing")?;
    let ciphertext = wrap(public_wrapping, &private)?;
    assert!(
        call(
            &mut service,
            "",
            "POST",
            "imported/keys/key/import_version",
            &admin,
            json!({"ciphertext":ciphertext,"version":1})
        )
        .status
            == 204
    );
    let descriptor = call(
        &mut service,
        "",
        "GET",
        "imported/keys/key",
        &admin,
        json!({}),
    );
    assert!(descriptor.status == 200 && descriptor.body["data"]["latest_version"] == json!(1));
    assert!(
        descriptor.body["data"]["keys"]["1"]["public_key"]
            == json!(BASE64.encode(pair.raw_public_key().map_err(|_| "public_raw_failed")?))
    );
    let signed = call(
        &mut service,
        "",
        "POST",
        "imported/sign/key/none",
        &admin,
        json!({"input":BASE64.encode(message)}),
    );
    assert!(signed.status == 200);
    let signature = signed.body["data"]["signature"]
        .as_str()
        .and_then(|v| v.strip_prefix("vault:v1:"))
        .ok_or("signature_missing")?;
    let signature = BASE64
        .decode(signature)
        .map_err(|_| "signature_decode_failed")?;
    assert!(
        Verifier::new_without_digest(&pair)
            .map_err(|_| "independent_verifier_failed")?
            .verify_oneshot(&signature, message)
            .map_err(|_| "independent_verify_failed")?
    );
    let after_hmac = call(
        &mut service,
        "",
        "POST",
        "imported/verify/key/sha2-256",
        &admin,
        json!({"input":BASE64.encode(message),"hmac":hmac_tag}),
    );
    assert!(after_hmac.status == 200 && after_hmac.body["data"]["valid"] == json!(true));
    assert!(
        service
            .state
            .as_ref()
            .ok_or("completed_state_missing")?
            .validate_format()
            .is_ok()
    );
    drop(service);
    let mut service = root.service().map_err(|_| "private_reopen_failed")?;
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
            == 200
    );
    assert!(
        call(
            &mut service,
            "",
            "POST",
            "imported/sign/key/none",
            &admin,
            json!({"input":BASE64.encode(message)})
        )
        .status
            == 200
    );
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
    let retired = service.state.as_ref().ok_or("retired_missing")?.clone();
    assert!(
        !retired.engines.has_standard_asymmetric_import_state()
            && retired.schema == STANDARD_ASYMMETRIC_IMPORT_STATE_SCHEMA
    );
    assert!(retired.validate_format().is_ok());
    let identity = service
        .current_state_identity()
        .map_err(|_| "identity_failed")?;
    let mut lower = retired.clone();
    lower.schema = MLDSA_IMPORT_STATE_SCHEMA;
    assert!(lower.validate_publication_schema(Some(&retired)).is_err());
    assert!(Service::validate_snapshot_protected_floor(&retired, &lower).is_err());
    assert!(service.commit_state(&mut lower).is_err());
    assert!(
        service
            .prepare_snapshot_restore(&old)
            .err()
            .is_some_and(|e| e.status == 400)
    );
    assert!(
        service
            .current_state_identity()
            .map_err(|_| "after_identity_failed")?
            == identity
    );
    drop(service);
    let mut service = root.service().map_err(|_| "retired_reopen_failed")?;
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
            == 200
    );
    assert!(
        service
            .state
            .as_ref()
            .ok_or("retired_state_missing")?
            .schema
            == STANDARD_ASYMMETRIC_IMPORT_STATE_SCHEMA
    );
    Ok(())
}

#[test]
fn transit270_global_key_config_write_returns_observed_descriptor_with_namespace_acl_and_encrypted_restart()
-> TestResult {
    let root = Root::new();
    let mut service = root.service().map_err(|_| "test_service_failed")?;
    let (unseal, admin) = bootstrap(&mut service).map_err(|_| "test_bootstrap_failed")?;
    let unseal = Zeroizing::new(unseal);
    let admin = Zeroizing::new(admin);
    assert_eq!(
        call(
            &mut service,
            "",
            "POST",
            "sys/namespaces/team",
            &admin,
            json!({})
        )
        .status,
        200
    );
    for namespace in ["", "team"] {
        assert_eq!(
            call(
                &mut service,
                namespace,
                "POST",
                "sys/mounts/global",
                &admin,
                json!({"type":"transit"})
            )
            .status,
            204
        );
        let initial = call(
            &mut service,
            namespace,
            "GET",
            "global/config/keys",
            &admin,
            json!({}),
        );
        assert_eq!(initial.status, 200);
        assert_eq!(initial.body["data"], json!({"disable_upsert":false}));
    }
    let changed = call(
        &mut service,
        "",
        "POST",
        "global/config/keys",
        &admin,
        json!({"disable_upsert":true}),
    );
    assert_eq!(changed.status, 200);
    assert_eq!(changed.body["data"], json!({"disable_upsert":true}));
    let current = call(
        &mut service,
        "",
        "GET",
        "global/config/keys",
        &admin,
        json!({}),
    );
    assert_eq!(current.status, 200);
    assert_eq!(current.body["data"], changed.body["data"]);
    let child = call(
        &mut service,
        "team",
        "GET",
        "global/config/keys",
        &admin,
        json!({}),
    );
    assert_eq!(child.status, 200);
    assert_eq!(child.body["data"], json!({"disable_upsert":false}));

    assert_eq!(
        call(
            &mut service,
            "",
            "PUT",
            "sys/policies/acl/global-read",
            &admin,
            json!({
                "policy":r#"path "global/config/keys" { capabilities = ["read"] }"#
            })
        )
        .status,
        204
    );
    let issued = call(
        &mut service,
        "",
        "POST",
        "auth/token/create",
        &admin,
        json!({
            "policies":["global-read"],"no_default_policy":true,"ttl":"1h"
        }),
    );
    assert_eq!(issued.status, 200);
    let reader = Zeroizing::new(
        issued.body["auth"]["client_token"]
            .as_str()
            .ok_or("test_token_missing")?
            .to_owned(),
    );
    let read = call(
        &mut service,
        "",
        "GET",
        "global/config/keys",
        &reader,
        json!({}),
    );
    assert_eq!(read.status, 200);
    assert_eq!(read.body["data"], json!({"disable_upsert":true}));
    let before = service
        .current_state_identity()
        .map_err(|_| "test_identity_failed")?;
    let state_before = Zeroizing::new(
        serde_json::to_vec(service.state.as_ref().ok_or("test_state_missing")?)
            .map_err(|_| "test_state_encoding_failed")?,
    );
    assert_eq!(
        call(
            &mut service,
            "",
            "POST",
            "global/config/keys",
            &reader,
            json!({"disable_upsert":false})
        )
        .status,
        403
    );
    assert!(
        service
            .current_state_identity()
            .map_err(|_| "test_identity_failed")?
            == before
    );
    let state_after = Zeroizing::new(
        serde_json::to_vec(service.state.as_ref().ok_or("test_state_missing")?)
            .map_err(|_| "test_state_encoding_failed")?,
    );
    assert!(state_after.as_slice() == state_before.as_slice());
    let before = service
        .current_state_identity()
        .map_err(|_| "test_identity_failed")?;
    assert_eq!(
        call(
            &mut service,
            "",
            "POST",
            "global/config/keys",
            &admin,
            json!({"disable_upsert":"false"})
        )
        .status,
        400
    );
    assert!(
        service
            .current_state_identity()
            .map_err(|_| "test_identity_failed")?
            == before
    );
    assert_eq!(
        call(
            &mut service,
            "",
            "GET",
            "global/config/keys",
            &admin,
            json!({})
        )
        .body["data"],
        json!({"disable_upsert":true})
    );

    drop(service);
    let mut service = root.service().map_err(|_| "test_reopen_failed")?;
    assert_eq!(
        call(
            &mut service,
            "",
            "POST",
            "sys/unseal",
            "",
            json!({"key":unseal.as_str()})
        )
        .status,
        200
    );
    let reopened = call(
        &mut service,
        "",
        "GET",
        "global/config/keys",
        &admin,
        json!({}),
    );
    assert_eq!(reopened.status, 200);
    assert_eq!(reopened.body["data"], json!({"disable_upsert":true}));
    let child = call(
        &mut service,
        "team",
        "GET",
        "global/config/keys",
        &admin,
        json!({}),
    );
    assert_eq!(child.status, 200);
    assert_eq!(child.body["data"], json!({"disable_upsert":false}));
    let changed = call(
        &mut service,
        "",
        "POST",
        "global/config/keys",
        &admin,
        json!({"disable_upsert":false}),
    );
    assert_eq!(changed.status, 200);
    assert_eq!(changed.body["data"], json!({"disable_upsert":false}));
    let current = call(
        &mut service,
        "",
        "GET",
        "global/config/keys",
        &admin,
        json!({}),
    );
    assert_eq!(current.status, 200);
    assert_eq!(current.body["data"], changed.body["data"]);
    assert!(
        service
            .state
            .as_ref()
            .ok_or("test_state_missing")?
            .validate_format()
            .is_ok()
    );
    Ok(())
}
