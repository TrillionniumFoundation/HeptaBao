use super::*;
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};

type TestResult = std::result::Result<(), Box<dyn std::error::Error>>;

fn request(
    state: &mut EngineState,
    namespace: &str,
    method: &str,
    path: &str,
    body: Value,
    now: u64,
) -> Result<EngineResponse> {
    state
        .handle(namespace, method, path, &body, now)?
        .ok_or_else(|| error(599, "test route was not owned"))
}

#[test]
fn kv_lifecycle_cas_patch_and_destroy_survive_serialization() -> TestResult {
    let mut state = EngineState::default();
    let first = request(
        &mut state,
        "",
        "POST",
        "secret/data/app",
        json!({"options":{"cas":0},"data":{"password":"first","nested":{"a":1,"b":2},"remove":true}}),
        1700000000,
    )?;
    assert_eq!(first.body["data"]["version"], 1);
    let before_failure = serde_json::to_vec(&state)?;
    assert_eq!(
        request(
            &mut state,
            "",
            "POST",
            "secret/data/app",
            json!({"options":{"cas":0},"data":{"password":"bad"}}),
            1700000001
        )
        .err()
        .map(|e| e.status),
        Some(400)
    );
    assert_eq!(before_failure, serde_json::to_vec(&state)?);
    let second = request(
        &mut state,
        "",
        "PATCH",
        "secret/data/app",
        json!({"options":{"cas":1},"data":{"nested":{"a":null,"c":3},"remove":null}}),
        1700000001,
    )?;
    assert_eq!(second.body["data"]["version"], 2);
    let read = request(
        &mut state,
        "",
        "GET",
        "secret/data/app",
        json!({}),
        1700000002,
    )?;
    assert_eq!(
        read.body["data"]["data"],
        json!({"password":"first","nested":{"b":2,"c":3}})
    );
    request(
        &mut state,
        "",
        "DELETE",
        "secret/data/app",
        json!({}),
        1700000003,
    )?;
    assert_eq!(
        request(
            &mut state,
            "",
            "GET",
            "secret/data/app",
            json!({}),
            1700000004
        )?
        .status,
        404
    );
    request(
        &mut state,
        "",
        "POST",
        "secret/undelete/app",
        json!({"versions":[2]}),
        1700000005,
    )?;
    request(
        &mut state,
        "",
        "PUT",
        "secret/destroy/app",
        json!({"versions":[1]}),
        1700000006,
    )?;
    let mut restored: EngineState = serde_json::from_slice(&serde_json::to_vec(&state)?)?;
    let destroyed = request(
        &mut restored,
        "",
        "GET",
        "secret/data/app?version=1",
        json!({}),
        1700000007,
    )?;
    assert_eq!(destroyed.status, 404);
    assert_eq!(destroyed.body["data"]["metadata"]["destroyed"], true);
    assert_eq!(destroyed.body["data"]["data"], Value::Null);
    assert_eq!(
        request(
            &mut restored,
            "",
            "GET",
            "secret/data/app",
            json!({}),
            1700000007
        )?
        .status,
        200
    );
    request(
        &mut restored,
        "",
        "POST",
        "secret/undelete/app",
        json!({"versions":[1]}),
        1700000008,
    )?;
    assert_eq!(
        request(
            &mut restored,
            "",
            "GET",
            "secret/data/app?version=1",
            json!({}),
            1700000008
        )?
        .status,
        404
    );
    Ok(())
}

#[test]
fn namespace_and_mount_boundaries_are_structural() -> TestResult {
    let mut state = EngineState::default();
    request(
        &mut state,
        "a",
        "POST",
        "secret/data/b/c",
        json!({"data":{"v":"one"}}),
        10,
    )?;
    request(
        &mut state,
        "a/b",
        "POST",
        "secret/data/c",
        json!({"data":{"v":"two"}}),
        10,
    )?;
    assert_eq!(
        request(&mut state, "a", "GET", "secret/data/b/c", json!({}), 10)?.body["data"]["data"]["v"],
        "one"
    );
    assert_eq!(
        request(&mut state, "a/b", "GET", "secret/data/c", json!({}), 10)?.body["data"]["data"]["v"],
        "two"
    );
    assert_eq!(
        request(&mut state, "", "GET", "secret/data/b/c", json!({}), 10)
            .err()
            .map(|e| e.status),
        Some(404)
    );
    request(
        &mut state,
        "a",
        "POST",
        "sys/mounts/team/kv",
        json!({"type":"kv","options":{"version":"2"}}),
        10,
    )?;
    request(
        &mut state,
        "a",
        "POST",
        "team/kv/data/b/c",
        json!({"data":{"v":"three"}}),
        10,
    )?;
    assert_eq!(
        request(&mut state, "a", "GET", "secret/data/b/c", json!({}), 10)?.body["data"]["data"]["v"],
        "one"
    );
    assert_eq!(
        request(&mut state, "a", "GET", "team/kv/data/b/c", json!({}), 10)?.body["data"]["data"]["v"],
        "three"
    );
    assert!(
        state
            .handle("a/b", "GET", "team/kv/data/b/c", &json!({}), 10)?
            .is_none()
    );
    Ok(())
}

#[test]
fn kv_retention_metadata_expiry_and_subkeys() -> TestResult {
    let mut state = EngineState::default();
    request(
        &mut state,
        "",
        "POST",
        "secret/config",
        json!({"max_versions":2,"cas_required":true,"delete_version_after":"1h"}),
        10,
    )?;
    request(
        &mut state,
        "",
        "POST",
        "secret/metadata/app",
        json!({"delete_version_after":"2s","custom_metadata":{"owner":"team"}}),
        10,
    )?;
    assert!(
        request(
            &mut state,
            "",
            "POST",
            "secret/data/app",
            json!({"data":{"v":1}}),
            10
        )
        .is_err()
    );
    for number in 1..=3 {
        request(
            &mut state,
            "",
            "POST",
            "secret/data/app",
            json!({"options":{"cas":number-1},"data":{"nested":{"leaf":"secret"},"array":["secret"],"empty":{}}}),
            10 + number,
        )?;
    }
    assert!(
        request(
            &mut state,
            "",
            "GET",
            "secret/data/app?version=1",
            json!({}),
            13
        )
        .is_err()
    );
    let metadata = request(&mut state, "", "GET", "secret/metadata/app", json!({}), 13)?;
    assert_eq!(metadata.body["data"]["oldest_version"], 2);
    assert_eq!(
        metadata.body["data"]["versions"]
            .as_object()
            .map(|v| v.len()),
        Some(2)
    );
    let subkeys = request(
        &mut state,
        "",
        "GET",
        "secret/subkeys/app?depth=1",
        json!({}),
        13,
    )?;
    assert_eq!(
        subkeys.body["data"]["subkeys"],
        json!({"nested":null,"array":null,"empty":null})
    );
    let expired = request(&mut state, "", "GET", "secret/data/app", json!({}), 15)?;
    assert_eq!(expired.status, 404);
    assert_eq!(
        expired.body["data"]["metadata"]["deletion_time"],
        "1970-01-01T00:00:15Z"
    );
    request(
        &mut state,
        "",
        "POST",
        "secret/undelete/app",
        json!({"versions":[3]}),
        16,
    )?;
    assert_eq!(
        request(&mut state, "", "GET", "secret/data/app", json!({}), 16)?.status,
        200
    );
    request(
        &mut state,
        "",
        "PATCH",
        "secret/metadata/app",
        json!({"custom_metadata":{"owner":null,"new":"yes"}}),
        17,
    )?;
    assert_eq!(
        request(&mut state, "", "GET", "secret/data/app", json!({}), 17)?.body["data"]["metadata"]
            ["custom_metadata"],
        json!({"new":"yes"})
    );
    Ok(())
}

#[test]
fn kv_lists_direct_children_scan_pagination_and_v1() -> TestResult {
    let mut state = EngineState::default();
    for path in ["a", "a/b", "a/c/d", "b"] {
        request(
            &mut state,
            "",
            "POST",
            &format!("secret/data/{path}"),
            json!({"data":{"v":"secret"}}),
            20,
        )?;
    }
    assert_eq!(
        request(&mut state, "", "LIST", "secret/metadata", json!({}), 20)?.body["data"]["keys"],
        json!(["a", "a/", "b"])
    );
    assert_eq!(
        request(
            &mut state,
            "",
            "GET",
            "secret/metadata?list=true&after=a&limit=1",
            json!({}),
            20
        )?
        .body["data"]["keys"],
        json!(["a/"])
    );
    assert_eq!(
        request(&mut state, "", "SCAN", "secret/metadata/a", json!({}), 20)?.body["data"]["keys"],
        json!(["b", "c/d"])
    );
    request(
        &mut state,
        "",
        "POST",
        "sys/mounts/legacy",
        json!({"type":"kv","options":{"version":"1"}}),
        20,
    )?;
    request(
        &mut state,
        "",
        "PUT",
        "legacy/app",
        json!({"token":"one"}),
        20,
    )?;
    request(
        &mut state,
        "",
        "POST",
        "legacy/app",
        json!({"token":"two"}),
        20,
    )?;
    assert_eq!(
        request(&mut state, "", "GET", "legacy/app", json!({}), 20)?.body["data"],
        json!({"token":"two"})
    );
    request(&mut state, "", "DELETE", "legacy/app", json!({}), 20)?;
    assert!(request(&mut state, "", "GET", "legacy/app", json!({}), 20).is_err());
    Ok(())
}

#[test]
fn failed_operations_never_modify_engine_state() -> TestResult {
    let mut state = EngineState::default();
    request(
        &mut state,
        "",
        "POST",
        "secret/data/app",
        json!({"data":{"a":"secret"}}),
        1,
    )?;
    request(&mut state, "", "POST", "transit/keys/app", json!({}), 1)?;
    let before = serde_json::to_vec(&state)?;
    for (path, body) in [
        (
            "secret/metadata/new",
            json!({"cas_required":true,"custom_metadata":{"bad":1}}),
        ),
        ("secret/delete/app", json!({"versions":[1,"bad"]})),
        (
            "secret/config",
            json!({"max_versions":2,"delete_version_after":"-1s"}),
        ),
        (
            "sys/mounts/secret/tune",
            json!({"description":"changed","options":{"version":"1"}}),
        ),
        (
            "transit/keys/app/config",
            json!({"min_decryption_version":3,"deletion_allowed":true}),
        ),
        ("transit/encrypt/new", json!({"plaintext":"invalid!"})),
    ] {
        assert!(request(&mut state, "", "POST", path, body, 2).is_err());
        assert_eq!(before, serde_json::to_vec(&state)?);
    }
    Ok(())
}

#[test]
fn transit_all_aead_algorithms_authenticate_and_roundtrip_after_restart() -> TestResult {
    for kind in ["aes128-gcm96", "aes256-gcm96", "chacha20-poly1305"] {
        let mut state = EngineState::default();
        request(
            &mut state,
            "team",
            "POST",
            "transit/keys/k",
            json!({"type":kind}),
            1,
        )?;
        let plaintext = BASE64.encode([0u8, 1, 255, 10, 32]);
        let associated = BASE64.encode(b"user-bound-context");
        let cipher = request(
            &mut state,
            "team",
            "POST",
            "transit/encrypt/k",
            json!({"plaintext":plaintext,"associated_data":associated}),
            2,
        )?
        .body["data"]["ciphertext"]
            .clone();
        let mut restored: EngineState = serde_json::from_slice(&serde_json::to_vec(&state)?)?;
        let decrypted = request(
            &mut restored,
            "team",
            "POST",
            "transit/decrypt/k",
            json!({"ciphertext":cipher,"associated_data":associated}),
            3,
        )?;
        assert_eq!(decrypted.body["data"]["plaintext"], plaintext);
        assert!(!decrypted.mutated);
        assert_eq!(
            request(
                &mut restored,
                "team",
                "POST",
                "transit/decrypt/k",
                json!({"ciphertext":cipher,"associated_data":BASE64.encode(b"wrong")}),
                3
            )
            .err()
            .map(|e| e.status),
            Some(400)
        );
        let text = cipher.as_str().ok_or("ciphertext string missing")?;
        let (_, payload) = text.rsplit_once(':').ok_or("payload missing")?;
        let mut bytes = BASE64.decode(payload)?;
        let last = bytes.last_mut().ok_or("ciphertext empty")?;
        *last ^= 1;
        assert!(request(&mut restored, "team", "POST", "transit/decrypt/k", json!({"ciphertext":format!("vault:v1:{}",BASE64.encode(bytes)),"associated_data":associated}), 3).is_err());
    }
    Ok(())
}

#[test]
fn transit_aad_rejects_namespace_mount_and_name_transplants() -> TestResult {
    let mut state = EngineState::default();
    request(
        &mut state,
        "a",
        "POST",
        "transit/encrypt/k",
        json!({"plaintext":BASE64.encode(b"isolated")}),
        1,
    )?;
    let ciphertext = request(
        &mut state,
        "a",
        "POST",
        "transit/encrypt/k",
        json!({"plaintext":BASE64.encode(b"isolated")}),
        2,
    )?
    .body["data"]["ciphertext"]
        .clone();
    // Copy exact key material, so these tests prove AAD separation independently
    // of the accidental protection supplied by different randomly generated keys.
    let namespace = state
        .namespaces
        .get("a")
        .cloned()
        .ok_or("namespace missing")?;
    state.namespaces.insert("a/b".into(), namespace.clone());
    assert!(
        request(
            &mut state,
            "a/b",
            "POST",
            "transit/decrypt/k",
            json!({"ciphertext":ciphertext}),
            3
        )
        .is_err()
    );
    let mount = namespace
        .mounts
        .get("transit/")
        .cloned()
        .ok_or("mount missing")?;
    state
        .namespaces
        .get_mut("a")
        .ok_or("namespace missing")?
        .mounts
        .insert("alternate/".into(), mount);
    assert!(
        request(
            &mut state,
            "a",
            "POST",
            "alternate/decrypt/k",
            json!({"ciphertext":ciphertext}),
            3
        )
        .is_err()
    );
    let mut serialized = serde_json::to_value(&state)?;
    serialized["namespaces"]["a"]["mounts"]["transit/"]["backend"]["Transit"]["keys"]["other"] =
        serialized["namespaces"]["a"]["mounts"]["transit/"]["backend"]["Transit"]["keys"]["k"]
            .clone();
    let mut renamed: EngineState = serde_json::from_value(serialized)?;
    assert!(
        request(
            &mut renamed,
            "a",
            "POST",
            "transit/decrypt/other",
            json!({"ciphertext":ciphertext}),
            3
        )
        .is_err()
    );
    Ok(())
}

#[test]
fn transit_rotation_rewrap_minimum_versions_and_soft_delete() -> TestResult {
    let mut state = EngineState::default();
    let plaintext = BASE64.encode(b"must survive rotation");
    let old = request(
        &mut state,
        "",
        "POST",
        "transit/encrypt/key",
        json!({"plaintext":plaintext}),
        1,
    )?
    .body["data"]["ciphertext"]
        .clone();
    request(
        &mut state,
        "",
        "POST",
        "transit/keys/key/rotate",
        json!({}),
        2,
    )?;
    assert_eq!(
        request(
            &mut state,
            "",
            "POST",
            "transit/decrypt/key",
            json!({"ciphertext":old}),
            3
        )?
        .body["data"]["plaintext"],
        plaintext
    );
    let new = request(
        &mut state,
        "",
        "POST",
        "transit/rewrap/key",
        json!({"ciphertext":old}),
        3,
    )?
    .body["data"]["ciphertext"]
        .clone();
    assert!(new.as_str().is_some_and(|s| s.starts_with("vault:v2:")));
    assert_eq!(
        request(
            &mut state,
            "",
            "POST",
            "transit/encrypt/key",
            json!({"plaintext":plaintext,"key_version":1}),
            3
        )?
        .body["data"]["key_version"],
        1
    );
    request(
        &mut state,
        "",
        "POST",
        "transit/keys/key/config",
        json!({"min_decryption_version":2,"min_encryption_version":2}),
        4,
    )?;
    assert!(
        request(
            &mut state,
            "",
            "POST",
            "transit/decrypt/key",
            json!({"ciphertext":old}),
            5
        )
        .is_err()
    );
    assert!(
        request(
            &mut state,
            "",
            "POST",
            "transit/encrypt/key",
            json!({"plaintext":plaintext,"key_version":1}),
            5
        )
        .is_err()
    );
    assert_eq!(
        request(
            &mut state,
            "",
            "POST",
            "transit/decrypt/key",
            json!({"ciphertext":new}),
            5
        )?
        .body["data"]["plaintext"],
        plaintext
    );
    request(
        &mut state,
        "",
        "DELETE",
        "transit/keys/key/soft-delete",
        json!({}),
        6,
    )?;
    assert!(
        request(
            &mut state,
            "",
            "POST",
            "transit/decrypt/key",
            json!({"ciphertext":new}),
            7
        )
        .is_err()
    );
    request(
        &mut state,
        "",
        "POST",
        "transit/keys/key/soft-delete-restore",
        json!({}),
        8,
    )?;
    assert_eq!(
        request(
            &mut state,
            "",
            "POST",
            "transit/decrypt/key",
            json!({"ciphertext":new}),
            9
        )?
        .status,
        200
    );
    assert!(request(&mut state, "", "DELETE", "transit/keys/key", json!({}), 9).is_err());
    request(
        &mut state,
        "",
        "POST",
        "transit/keys/key/config",
        json!({"deletion_allowed":true}),
        9,
    )?;
    request(&mut state, "", "DELETE", "transit/keys/key", json!({}), 9)?;
    assert!(request(&mut state, "", "GET", "transit/keys/key", json!({}), 9).is_err());
    Ok(())
}

#[test]
fn transit_sign_verify_hmac_and_hash_use_real_crypto() -> TestResult {
    let mut state = EngineState::default();
    request(
        &mut state,
        "",
        "POST",
        "transit/keys/signing",
        json!({"type":"ed25519"}),
        1,
    )?;
    let input = BASE64.encode(b"hello");
    let signature = request(
        &mut state,
        "",
        "POST",
        "transit/sign/signing",
        json!({"input":input}),
        2,
    )?
    .body["data"]["signature"]
        .clone();
    assert_eq!(
        request(
            &mut state,
            "",
            "POST",
            "transit/verify/signing",
            json!({"input":input,"signature":signature}),
            2
        )?
        .body["data"]["valid"],
        true
    );
    assert_eq!(
        request(
            &mut state,
            "",
            "POST",
            "transit/verify/signing",
            json!({"input":BASE64.encode(b"tampered"),"signature":signature}),
            2
        )?
        .body["data"]["valid"],
        false
    );
    let mac = request(
        &mut state,
        "",
        "POST",
        "transit/hmac/signing/sha2-512",
        json!({"input":input}),
        2,
    )?
    .body["data"]["hmac"]
        .clone();
    assert_eq!(
        request(
            &mut state,
            "",
            "POST",
            "transit/verify/signing/sha2-512",
            json!({"input":input,"hmac":mac}),
            2
        )?
        .body["data"]["valid"],
        true
    );
    assert_eq!(
        request(
            &mut state,
            "",
            "POST",
            "transit/verify/signing/sha2-512",
            json!({"input":BASE64.encode(b"tampered"),"hmac":mac}),
            2
        )?
        .body["data"]["valid"],
        false
    );
    let hash = request(
        &mut state,
        "",
        "POST",
        "transit/hash/sha2-256",
        json!({"input":input}),
        2,
    )?;
    assert_eq!(
        hash.body["data"]["sum"],
        "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
    );
    let metadata = request(&mut state, "", "GET", "transit/keys/signing", json!({}), 2)?;
    assert_eq!(metadata.body["data"]["supports_signing"], true);
    assert_eq!(metadata.body["data"]["supports_encryption"], false);
    assert_eq!(
        BASE64
            .decode(
                metadata.body["data"]["keys"]["1"]["public_key"]
                    .as_str()
                    .ok_or("public key missing")?
            )?
            .len(),
        32
    );
    Ok(())
}

#[test]
fn transit_hmac_matches_rfc4231_test_case_1() -> TestResult {
    let mut state = EngineState::default();
    request(
        &mut state,
        "",
        "POST",
        "transit/keys/rfc",
        json!({"type":"hmac"}),
        1,
    )?;
    let mut serialized = serde_json::to_value(&state)?;
    serialized["namespaces"][""]["mounts"]["transit/"]["backend"]["Transit"]["keys"]["rfc"]["versions"]
        ["1"]["hmac_material"] = json!(BASE64.encode([0x0b; 20]));
    let mut state: EngineState = serde_json::from_value(serialized)?;
    let hmac = request(
        &mut state,
        "",
        "POST",
        "transit/hmac/rfc",
        json!({"input":BASE64.encode(b"Hi There")}),
        2,
    )?;
    let expected = [
        0xb0, 0x34, 0x4c, 0x61, 0xd8, 0xdb, 0x38, 0x53, 0x5c, 0xa8, 0xaf, 0xce, 0xaf, 0x0b, 0xf1,
        0x2b, 0x88, 0x1d, 0xc2, 0x00, 0xc9, 0x83, 0x3d, 0xa7, 0x26, 0xe9, 0x37, 0x6c, 0x2e, 0x32,
        0xcf, 0xf7,
    ];
    assert_eq!(
        hmac.body["data"]["hmac"],
        format!("vault:v1:{}", BASE64.encode(expected))
    );
    Ok(())
}

#[test]
fn transit_batch_partial_success_mutates_and_failure_does_not_upsert() -> TestResult {
    let mut state = EngineState::default();
    let failure = request(
        &mut state,
        "",
        "POST",
        "transit/encrypt/fail",
        json!({"batch_input":[{"plaintext":"!"}]}),
        1,
    )?;
    assert_eq!(failure.status, 400);
    assert!(!failure.mutated);
    assert!(request(&mut state, "", "GET", "transit/keys/fail", json!({}), 1).is_err());
    let result = request(
        &mut state,
        "",
        "POST",
        "transit/encrypt/batch",
        json!({"batch_input":[{"plaintext":BASE64.encode(b"one"),"reference":"first"},{"plaintext":"!","reference":"second"},{"plaintext":BASE64.encode(b"three")}]}),
        2,
    )?;
    assert_eq!(result.status, 400);
    assert!(result.mutated);
    let items = &result.body["data"]["batch_results"];
    assert_eq!(items[0]["reference"], "first");
    assert!(items[1]["error"].is_string());
    let mut restored: EngineState = serde_json::from_slice(&serde_json::to_vec(&state)?)?;
    assert_eq!(
        request(
            &mut restored,
            "",
            "POST",
            "transit/decrypt/batch",
            json!({"ciphertext":items[2]["ciphertext"]}),
            3
        )?
        .body["data"]["plaintext"],
        BASE64.encode(b"three")
    );
    let before = serde_json::to_vec(&restored)?;
    let nested = request(
        &mut restored,
        "",
        "POST",
        "transit/encrypt/batch",
        json!({"batch_input":[{"batch_input":[{"plaintext":""}]}]}),
        3,
    )?;
    assert_eq!(nested.status, 400);
    assert!(!nested.mutated);
    assert_eq!(before, serde_json::to_vec(&restored)?);
    Ok(())
}

#[test]
fn transit_datakey_export_random_and_unsupported_modes_are_explicit() -> TestResult {
    let mut state = EngineState::default();
    request(
        &mut state,
        "",
        "POST",
        "transit/keys/key",
        json!({"exportable":true}),
        1,
    )?;
    let datakey = request(
        &mut state,
        "",
        "POST",
        "transit/datakey/plaintext/key",
        json!({"bits":256}),
        2,
    )?;
    assert_eq!(
        BASE64
            .decode(
                datakey.body["data"]["plaintext"]
                    .as_str()
                    .ok_or("plaintext missing")?
            )?
            .len(),
        32
    );
    let decrypted = request(
        &mut state,
        "",
        "POST",
        "transit/decrypt/key",
        json!({"ciphertext":datakey.body["data"]["ciphertext"]}),
        2,
    )?;
    assert_eq!(
        decrypted.body["data"]["plaintext"],
        datakey.body["data"]["plaintext"]
    );
    let wrapped = request(
        &mut state,
        "",
        "POST",
        "transit/datakey/wrapped/key",
        json!({}),
        2,
    )?;
    assert!(wrapped.body["data"].get("plaintext").is_none());
    assert_eq!(
        BASE64
            .decode(
                request(
                    &mut state,
                    "",
                    "GET",
                    "transit/export/encryption-key/key/latest",
                    json!({}),
                    3
                )?
                .body["data"]["keys"]["1"]
                    .as_str()
                    .ok_or("key missing")?
            )?
            .len(),
        32
    );
    let random = request(
        &mut state,
        "",
        "POST",
        "transit/random/platform/16",
        json!({"format":"hex"}),
        3,
    )?;
    assert_eq!(
        random.body["data"]["random_bytes"].as_str().map(str::len),
        Some(32)
    );
    for (path, body) in [
        ("transit/keys/derived", json!({"derived":true})),
        ("transit/keys/rsa", json!({"type":"rsa-2048"})),
        (
            "transit/encrypt/key",
            json!({"plaintext":"","nonce":BASE64.encode([0u8;12])}),
        ),
        ("sys/mounts/pki", json!({"type":"pki"})),
    ] {
        assert_eq!(
            request(&mut state, "", "POST", path, body, 3)
                .err()
                .map(|e| e.status),
            Some(501)
        );
    }
    Ok(())
}

#[test]
fn capability_checks_track_create_update_patch_and_soft_deleted_versions() -> TestResult {
    let mut state = EngineState::default();
    assert_eq!(
        state.required_capability("", "POST", "secret/data/app"),
        Some("create")
    );
    request(
        &mut state,
        "",
        "POST",
        "secret/data/app",
        json!({"data":{"a":1}}),
        1,
    )?;
    assert_eq!(
        state.required_capability("", "POST", "secret/data/app"),
        Some("update")
    );
    assert_eq!(
        state.required_capability("", "PATCH", "secret/data/app"),
        Some("patch")
    );
    request(&mut state, "", "DELETE", "secret/data/app", json!({}), 1)?;
    assert_eq!(
        state.required_capability("", "POST", "secret/data/app"),
        Some("update")
    );
    assert_eq!(
        state.required_capability("other", "POST", "secret/data/app"),
        Some("create")
    );
    assert_eq!(
        state.required_capability("", "POST", "transit/encrypt/key"),
        Some("create")
    );
    request(
        &mut state,
        "",
        "POST",
        "transit/encrypt/key",
        json!({"plaintext":""}),
        1,
    )?;
    assert_eq!(
        state.required_capability("", "POST", "transit/encrypt/key"),
        Some("update")
    );
    Ok(())
}

#[test]
fn redacted_debug_and_timestamp_boundaries() -> TestResult {
    let mut state = EngineState::default();
    let response = request(
        &mut state,
        "",
        "POST",
        "secret/data/app",
        json!({"data":{"password":"SUPER_SECRET_SENTINEL"}}),
        1,
    )?;
    assert!(!format!("{state:?}").contains("SUPER_SECRET_SENTINEL"));
    assert!(!format!("{response:?}").contains("SUPER_SECRET_SENTINEL"));
    assert_eq!(timestamp(0), "1970-01-01T00:00:00Z");
    assert_eq!(timestamp(1709164800), "2024-02-29T00:00:00Z");
    assert_eq!(timestamp(253402300799), "9999-12-31T23:59:59Z");
    Ok(())
}

#[test]
fn totp_replay_rejection_survives_restart_reimport_and_clock_rollback() -> TestResult {
    let mut state = EngineState::default();
    request(
        &mut state,
        "",
        "POST",
        "sys/mounts/totp",
        json!({"type":"totp"}),
        59,
    )?;
    let seed = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";
    let definition = json!({"key":seed,"algorithm":"SHA1","digits":8,"skew":0});
    request(
        &mut state,
        "",
        "POST",
        "totp/keys/user",
        definition.clone(),
        59,
    )?;
    let generated = request(&mut state, "", "GET", "totp/code/user", json!({}), 59)?;
    assert_eq!(generated.body["data"]["code"], "94287082");
    assert_eq!(generated.body["data"]["expire_time"], 60);
    assert_eq!(
        request(
            &mut state,
            "",
            "POST",
            "totp/code/user",
            json!({"code":"94287082"}),
            59
        )?
        .body["data"]["valid"],
        true
    );
    let mut state: EngineState = serde_json::from_slice(&serde_json::to_vec(&state)?)?;
    assert_eq!(
        request(
            &mut state,
            "",
            "POST",
            "totp/code/user",
            json!({"code":"94287082"}),
            59
        )?
        .body["data"]["valid"],
        false
    );
    request(&mut state, "", "POST", "totp/keys/user", definition, 59)?;
    assert_eq!(
        request(
            &mut state,
            "",
            "POST",
            "totp/code/user",
            json!({"code":"94287082"}),
            59
        )?
        .body["data"]["valid"],
        false
    );
    let old = request(&mut state, "", "GET", "totp/code/user", json!({}), 29)?.body["data"]["code"]
        .clone();
    assert_eq!(
        request(
            &mut state,
            "",
            "POST",
            "totp/code/user",
            json!({"code":old}),
            29
        )?
        .body["data"]["valid"],
        false
    );
    let next =
        request(&mut state, "", "GET", "totp/code/user", json!({}), 60)?.body["data"]["code"]
            .clone();
    assert_eq!(
        request(
            &mut state,
            "",
            "POST",
            "totp/code/user",
            json!({"code":next}),
            60
        )?
        .body["data"]["valid"],
        true
    );
    Ok(())
}

#[test]
fn totp_replay_state_is_isolated_by_namespace_mount_and_key() -> TestResult {
    let mut state = EngineState::default();
    for namespace in ["a", "a/b"] {
        request(
            &mut state,
            namespace,
            "POST",
            "sys/mounts/totp",
            json!({"type":"totp"}),
            59,
        )?;
        request(
            &mut state,
            namespace,
            "POST",
            "totp/keys/user",
            json!({"key":"GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ","digits":8}),
            59,
        )?;
    }
    request(
        &mut state,
        "a",
        "POST",
        "totp/keys/other",
        json!({"key":"GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ","digits":8}),
        59,
    )?;
    request(
        &mut state,
        "a",
        "POST",
        "sys/mounts/otp",
        json!({"type":"totp"}),
        59,
    )?;
    request(
        &mut state,
        "a",
        "POST",
        "otp/keys/user",
        json!({"key":"GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ","digits":8}),
        59,
    )?;
    for (namespace, path) in [
        ("a", "totp/code/user"),
        ("a/b", "totp/code/user"),
        ("a", "totp/code/other"),
        ("a", "otp/code/user"),
    ] {
        assert_eq!(
            request(
                &mut state,
                namespace,
                "POST",
                path,
                json!({"code":"94287082"}),
                59
            )?
            .body["data"]["valid"],
            true
        );
        assert_eq!(
            request(
                &mut state,
                namespace,
                "POST",
                path,
                json!({"code":"94287082"}),
                59
            )?
            .body["data"]["valid"],
            false
        );
    }
    assert!(
        request(
            &mut state,
            "a",
            "POST",
            "totp/code/user",
            json!({"code":" 94287082"}),
            59
        )
        .is_err()
    );
    Ok(())
}

#[test]
fn totp_url_enrollment_import_metadata_and_deletion() -> TestResult {
    let mut state = EngineState::default();
    request(
        &mut state,
        "",
        "POST",
        "sys/mounts/totp",
        json!({"type":"totp"}),
        100,
    )?;
    let enrolled = request(
        &mut state,
        "",
        "POST",
        "totp/keys/generated",
        json!({"generate":true,"issuer":"Hepta Team","account_name":"user@example.test","algorithm":"SHA256","qr_size":0}),
        100,
    )?;
    let url = enrolled.body["data"]["url"]
        .as_str()
        .ok_or("otpauth URL missing")?;
    assert!(url.starts_with("otpauth://totp/Hepta%20Team:user%40example.test?"));
    request(
        &mut state,
        "",
        "POST",
        "totp/keys/imported",
        json!({"url":url}),
        100,
    )?;
    assert_eq!(
        request(&mut state, "", "GET", "totp/code/generated", json!({}), 100)?.body["data"]["code"],
        request(&mut state, "", "GET", "totp/code/imported", json!({}), 100)?.body["data"]["code"]
    );
    let metadata = request(&mut state, "", "GET", "totp/keys/imported", json!({}), 100)?;
    assert_eq!(metadata.body["data"]["issuer"], "Hepta Team");
    assert_eq!(metadata.body["data"]["algorithm"], "SHA256");
    assert!(metadata.body["data"].get("key").is_none());
    assert!(metadata.body["data"].get("url").is_none());
    assert_eq!(
        request(&mut state, "", "LIST", "totp/keys", json!({}), 100)?.body["data"]["keys"],
        json!(["generated", "imported"])
    );
    request(
        &mut state,
        "",
        "DELETE",
        "totp/keys/imported",
        json!({}),
        100,
    )?;
    assert!(request(&mut state, "", "GET", "totp/code/imported", json!({}), 100).is_err());
    assert_eq!(
        request(
            &mut state,
            "",
            "POST",
            "totp/keys/qr",
            json!({"generate":true,"issuer":"Hepta","account_name":"u"}),
            100
        )
        .err()
        .map(|e| e.status),
        Some(501)
    );
    Ok(())
}

#[test]
fn totp_guessing_limit_is_persisted_and_recovers_next_period() -> TestResult {
    let mut state = EngineState::default();
    request(
        &mut state,
        "",
        "POST",
        "sys/mounts/totp",
        json!({"type":"totp"}),
        59,
    )?;
    request(
        &mut state,
        "",
        "POST",
        "totp/keys/user",
        json!({"key":"GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ","digits":8,"skew":0}),
        59,
    )?;
    for _ in 0..10 {
        let denied = request(
            &mut state,
            "",
            "POST",
            "totp/code/user",
            json!({"code":"00000000"}),
            59,
        )?;
        assert_eq!(denied.body["data"]["valid"], false);
        assert!(denied.mutated);
    }
    let mut state: EngineState = serde_json::from_slice(&serde_json::to_vec(&state)?)?;
    assert_eq!(
        request(
            &mut state,
            "",
            "POST",
            "totp/code/user",
            json!({"code":"94287082"}),
            59
        )
        .err()
        .map(|e| e.status),
        Some(429)
    );
    let next =
        request(&mut state, "", "GET", "totp/code/user", json!({}), 60)?.body["data"]["code"]
            .clone();
    assert_eq!(
        request(
            &mut state,
            "",
            "POST",
            "totp/code/user",
            json!({"code":next}),
            60
        )?
        .body["data"]["valid"],
        true
    );
    Ok(())
}
