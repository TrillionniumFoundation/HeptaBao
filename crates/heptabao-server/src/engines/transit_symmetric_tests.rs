use super::*;

type TestResult = std::result::Result<(), Box<dyn std::error::Error>>;
const KINDS: [&str; 4] = [
    "aes128-gcm96",
    "aes256-gcm96",
    "chacha20-poly1305",
    "xchacha20-poly1305",
];

fn call(transit: &mut Transit, method: &str, path: &str, body: Value) -> Result<EngineResponse> {
    transit.handle("", "transit", method, path, &body, 100)
}

#[test]
fn derived_aead_requires_context_and_isolates_all_four_key_types() -> TestResult {
    for kind in KINDS {
        for convergent in [false, true] {
            let mut transit = Transit::default();
            call(
                &mut transit,
                "POST",
                "keys/key",
                json!({"type":kind,"derived":true,"convergent_encryption":convergent}),
            )?;
            let options = json!({"plaintext":BASE64.encode(b"synthetic message"),"context":BASE64.encode(b"context one"),"associated_data":BASE64.encode(b"AAD")});
            let first = call(&mut transit, "POST", "encrypt/key", options.clone())?;
            let second = call(&mut transit, "POST", "encrypt/key", options.clone())?;
            assert!(
                (first.body["data"]["ciphertext"] == second.body["data"]["ciphertext"])
                    == convergent
            );
            let cipher = first.body["data"]["ciphertext"].clone();
            let success = call(
                &mut transit,
                "POST",
                "decrypt/key",
                json!({"ciphertext":cipher,"context":BASE64.encode(b"context one"),"associated_data":BASE64.encode(b"AAD")}),
            )?;
            assert!(success.body["data"]["plaintext"] == options["plaintext"]);
            for body in [
                json!({"ciphertext":cipher}),
                json!({"ciphertext":cipher,"context":""}),
                json!({"ciphertext":cipher,"context":BASE64.encode(b"wrong"),"associated_data":BASE64.encode(b"AAD")}),
                json!({"ciphertext":cipher,"context":BASE64.encode(b"context one"),"associated_data":BASE64.encode(b"wrong")}),
            ] {
                assert!(
                    call(&mut transit, "POST", "decrypt/key", body)
                        .err()
                        .is_some_and(|error| error.status == 400)
                );
            }
            assert!(transit.keys["key"].versions[&1].encryptions == 2);
        }
    }
    Ok(())
}

#[test]
fn modern_convergent_nonce_cannot_be_selected_by_request_values() -> TestResult {
    for kind in KINDS {
        let mut transit = Transit::default();
        call(
            &mut transit,
            "POST",
            "keys/key",
            json!({"type":kind,"derived":true,"convergent_encryption":true}),
        )?;
        let mut options =
            json!({"plaintext":BASE64.encode(b"synthetic"),"context":BASE64.encode(b"context")});
        let first = call(&mut transit, "POST", "encrypt/key", options.clone())?;
        for nonce in [
            Value::Null,
            json!(""),
            json!(true),
            json!("invalid-base64"),
            json!([1]),
            json!({"a":1}),
            json!(BASE64.encode([0u8; 24])),
        ] {
            options["nonce"] = nonce;
            let encrypted = call(&mut transit, "POST", "encrypt/key", options.clone())?;
            assert!(first.body["data"]["ciphertext"] == encrypted.body["data"]["ciphertext"]);
        }
        options["plaintext"] = json!(BASE64.encode(b"different message"));
        let different = call(&mut transit, "POST", "encrypt/key", options)?;
        assert!(first.body["data"]["ciphertext"] != different.body["data"]["ciphertext"]);
    }
    Ok(())
}

#[test]
fn derived_batch_context_does_not_inherit_and_failed_item_cannot_increment_counter() -> TestResult {
    let mut transit = Transit::default();
    call(&mut transit, "POST", "keys/key", json!({"derived":true}))?;
    let failure = call(
        &mut transit,
        "POST",
        "encrypt/key",
        json!({"context":BASE64.encode(b"outer"),"plaintext":BASE64.encode(b"outer"),"partial_failure_response_code":207,"batch_input":[{"reference":"first","context":BASE64.encode(b"first"),"plaintext":BASE64.encode(b"message")},{"reference":"missing","plaintext":BASE64.encode(b"message")}]}),
    );
    assert!(failure.err().is_some_and(|error| error.status == 400));
    assert!(transit.keys["key"].versions[&1].encryptions == 0);
    Ok(())
}

#[test]
fn upsert_derivation_uses_batch_items_and_rejects_mixed_contexts_without_a_key() -> TestResult {
    let mut transit = Transit::default();
    let result = call(
        &mut transit,
        "POST",
        "encrypt/new",
        json!({"batch_input":[{"context":BASE64.encode(b"one"),"plaintext":BASE64.encode(b"message")},{"context":BASE64.encode(b"two"),"plaintext":BASE64.encode(b"message")}]}),
    )?;
    assert!(result.status == 200 && transit.keys["new"].derived);
    for items in [
        json!([{"plaintext":BASE64.encode(b"message")},{"context":BASE64.encode(b"two"),"plaintext":BASE64.encode(b"message")}]),
        json!([{"context":BASE64.encode(b"one"),"plaintext":BASE64.encode(b"message")},{"plaintext":BASE64.encode(b"message")}]),
    ] {
        let failure = call(
            &mut transit,
            "POST",
            "encrypt/mixed",
            json!({"batch_input":items}),
        );
        assert!(failure.err().is_some_and(|error| error.status == 400));
        assert!(!transit.keys.contains_key("mixed"));
    }
    Ok(())
}

#[test]
fn derived_rotation_serialization_and_minimum_policy_preserve_actual_ciphertexts() -> TestResult {
    for kind in KINDS {
        let mut transit = Transit::default();
        call(
            &mut transit,
            "POST",
            "keys/key",
            json!({"type":kind,"derived":true,"convergent_encryption":true}),
        )?;
        let options =
            json!({"context":BASE64.encode(b"context"),"plaintext":BASE64.encode(b"message")});
        let first = call(&mut transit, "POST", "encrypt/key", options.clone())?;
        call(&mut transit, "POST", "keys/key/rotate", json!({}))?;
        let rewrapped = call(
            &mut transit,
            "POST",
            "rewrap/key",
            json!({"context":options["context"],"ciphertext":first.body["data"]["ciphertext"]}),
        )?;
        assert!(
            rewrapped.body["data"]["ciphertext"]
                .as_str()
                .is_some_and(|value| value.starts_with("vault:v2:"))
        );
        let encoded = Zeroizing::new(serde_json::to_vec(&transit)?);
        let mut reopened: Transit = serde_json::from_slice(&encoded)?;
        assert!(reopened.keys["key"].derived && reopened.keys["key"].convergent_encryption);
        call(
            &mut reopened,
            "POST",
            "keys/key/config",
            json!({"min_decryption_version":2,"min_encryption_version":2}),
        )?;
        assert!(
            call(
                &mut reopened,
                "POST",
                "decrypt/key",
                json!({"context":options["context"],"ciphertext":first.body["data"]["ciphertext"]})
            )
            .err()
            .is_some_and(|error| error.status == 400)
        );
        let decrypted = call(
            &mut reopened,
            "POST",
            "decrypt/key",
            json!({"context":options["context"],"ciphertext":rewrapped.body["data"]["ciphertext"]}),
        )?;
        assert!(decrypted.body["data"]["plaintext"] == options["plaintext"]);
        let descriptor = call(&mut reopened, "GET", "keys/key", json!({}))?;
        assert!(
            descriptor.body["data"]["keys"]
                .as_object()
                .is_some_and(|keys| keys.len() == 1 && keys.contains_key("2"))
        );
    }
    Ok(())
}

#[test]
fn context_and_aad_syntax_failure_is_safe_and_does_not_encrypt() -> TestResult {
    let mut transit = Transit::default();
    call(&mut transit, "POST", "keys/key", json!({"derived":true}))?;
    for value in [
        json!(true),
        json!([1]),
        json!({"a":1}),
        json!(1234.0),
        json!("not-base64"),
    ] {
        assert!(
            call(
                &mut transit,
                "POST",
                "encrypt/key",
                json!({"plaintext":"","context":value})
            )
            .err()
            .is_some_and(|error| error.status == 400)
        );
    }
    assert!(
        call(
            &mut transit,
            "POST",
            "encrypt/key",
            json!({"plaintext":"","context":1234,"associated_data":true})
        )
        .err()
        .is_some_and(|error| error.status == 500)
    );
    assert!(transit.keys["key"].versions[&1].encryptions == 0);
    assert!(
        call(
            &mut transit,
            "POST",
            "encrypt/key",
            json!({"plaintext":"","context":1234,"associated_data":1234})
        )
        .is_ok()
    );
    Ok(())
}

#[test]
fn weak_scalar_parameters_do_not_coerce_float_key_versions_or_boolean_flags() -> TestResult {
    let mut transit = Transit::default();
    for value in [json!(0.0), json!(1.0)] {
        assert!(
            call(&mut transit, "POST", "keys/bad", json!({"derived":value}))
                .err()
                .is_some_and(|error| error.status == 400)
        );
        assert!(!transit.keys.contains_key("bad"));
    }
    call(&mut transit, "POST", "keys/key", json!({"derived":"1"}))?;
    call(&mut transit, "POST", "keys/key/rotate", json!({}))?;
    for version in [json!(true), json!("1"), json!(1)] {
        let encrypted = call(
            &mut transit,
            "POST",
            "encrypt/key",
            json!({"plaintext":"","context":1234,"key_version":version}),
        )?;
        assert!(
            encrypted.body["data"]["ciphertext"]
                .as_str()
                .is_some_and(|value| value.starts_with("vault:v1:"))
        );
    }
    for version in [json!(1.0), json!(-1), json!([1]), json!({})] {
        assert!(
            call(
                &mut transit,
                "POST",
                "encrypt/key",
                json!({"plaintext":"","context":1234,"key_version":version})
            )
            .err()
            .is_some_and(|error| error.status == 400)
        );
    }
    assert!(
        transit.keys["key"].versions[&1].encryptions == 3
            && transit.keys["key"].versions[&2].encryptions == 0
    );
    Ok(())
}

#[test]
fn batch_context_shape_validation_precedes_mutations_and_rewrap_keeps_item_errors() -> TestResult {
    let mut transit = Transit::default();
    call(&mut transit, "POST", "keys/key", json!({"derived":true}))?;
    let good = json!({"plaintext":BASE64.encode(b"message"),"context":BASE64.encode(b"context")});
    for value in [json!(true), json!(1234), json!([1]), json!({})] {
        let bad = json!({"plaintext":BASE64.encode(b"message"),"context":value});
        assert!(
            call(
                &mut transit,
                "POST",
                "encrypt/key",
                json!({"partial_failure_response_code":207,"batch_input":[good.clone(),bad]})
            )
            .err()
            .is_some_and(|error| error.status == 500)
        );
        assert!(transit.keys["key"].versions[&1].encryptions == 0);
    }
    let response = call(
        &mut transit,
        "POST",
        "encrypt/key",
        json!({"partial_failure_response_code":207,"batch_input":[good,{"plaintext":BASE64.encode(b"message"),"context":"invalid-base64"}]}),
    )?;
    assert!(
        response.status == 207 && response.body["data"]["batch_results"][1]["error"].is_string()
    );
    assert!(transit.keys["key"].versions[&1].encryptions == 1);
    let response = call(
        &mut transit,
        "POST",
        "rewrap/key",
        json!({"partial_failure_response_code":207,"batch_input":[{"ciphertext":"vault:v1:invalid-base64","context":BASE64.encode(b"context")}]}),
    )?;
    assert!(
        response.status == 200 && response.body["data"]["batch_results"][0]["error"].is_string()
    );
    assert!(transit.keys["key"].versions[&1].encryptions == 1 && !response.mutated);
    assert!(call(&mut transit,"POST","encrypt/key",json!({"plaintext":"","context":BASE64.encode(b"context"),"associated_data":"invalid-base64"})).err().is_some_and(|error|error.status==500));
    assert!(transit.keys["key"].versions[&1].encryptions == 1);
    Ok(())
}

#[test]
fn ordinary_key_canonical_state_omits_absent_derivation_flags() -> TestResult {
    for kind in KINDS {
        let mut ordinary = Transit::default();
        call(&mut ordinary, "POST", "keys/key", json!({"type":kind}))?;
        let legacy_bytes = Zeroizing::new(serde_json::to_vec(&ordinary)?);
        for field in [
            b"\"derived\":".as_slice(),
            b"\"convergent_encryption\":".as_slice(),
        ] {
            assert!(
                !legacy_bytes
                    .windows(field.len())
                    .any(|window| window == field)
            );
        }
        let reopened: Transit = serde_json::from_slice(legacy_bytes.as_slice())?;
        assert!(*legacy_bytes == *Zeroizing::new(serde_json::to_vec(&reopened)?));
        let key = reopened.keys.get("key").ok_or("ordinary key missing")?;
        assert!(!key.derived && !key.convergent_encryption);

        let mut derived = Transit::default();
        call(
            &mut derived,
            "POST",
            "keys/key",
            json!({"type":kind,"derived":true,"convergent_encryption":true}),
        )?;
        let bytes = Zeroizing::new(serde_json::to_vec(&derived)?);
        for field in [
            b"\"derived\":true".as_slice(),
            b"\"convergent_encryption\":true".as_slice(),
        ] {
            assert!(bytes.windows(field.len()).any(|window| window == field));
        }
        let reopened: Transit = serde_json::from_slice(bytes.as_slice())?;
        let key = reopened.keys.get("key").ok_or("derived key missing")?;
        assert!(key.derived && key.convergent_encryption);
        assert!(*bytes == *Zeroizing::new(serde_json::to_vec(&reopened)?));
    }
    Ok(())
}
