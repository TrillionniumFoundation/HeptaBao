//! Independent SDK vectors and atomic real-route controls.
use super::*;
use openssl::{
    ec::{EcGroup, EcKey},
    hash::MessageDigest,
    nid::Nid,
    pkey::{Id, PKey},
    sign::{Signer, Verifier},
};
type TestResult<T = ()> = std::result::Result<T, &'static str>;
fn call(t: &mut Transit, method: &str, path: &str, body: Value) -> TestResult<EngineResponse> {
    t.handle("team", "transit", method, path, &body, 100)
        .map_err(|_| "transit derivation route failed")
}
fn state(t: &Transit) -> TestResult<Zeroizing<Vec<u8>>> {
    serde_json::to_vec(t)
        .map(Zeroizing::new)
        .map_err(|_| "private custody encoding failed")
}
fn independent_hkdf(input: &[u8], info: &[u8], len: usize) -> TestResult<Zeroizing<Vec<u8>>> {
    fn mac(key: &[u8], message: &[u8]) -> TestResult<Vec<u8>> {
        let key = PKey::hmac(key).map_err(|_| "SDK HMAC key")?;
        let mut signer =
            Signer::new(MessageDigest::sha256(), &key).map_err(|_| "SDK HMAC signer")?;
        signer.update(message).map_err(|_| "SDK HMAC input")?;
        signer.sign_to_vec().map_err(|_| "SDK HMAC output")
    }
    let prk = Zeroizing::new(mac(&[0; 32], input)?);
    let mut first = Zeroizing::new(info.to_vec());
    first.push(1);
    let mut result = Zeroizing::new(mac(&prk, &first)?);
    result.truncate(len);
    Ok(result)
}
fn decoded(value: &Value) -> TestResult<Zeroizing<Vec<u8>>> {
    BASE64
        .decode(value.as_str().ok_or("base64 string missing")?)
        .map(Zeroizing::new)
        .map_err(|_| "base64 decoding failed")
}
#[test]
fn derivation127_context_ed25519_matches_independent_sdk_and_rejects_changed_context_and_message()
-> TestResult {
    let mut t = Transit::default();
    assert!(
        call(
            &mut t,
            "POST",
            "keys/context",
            json!({"type":"ed25519","derived":true,"allow_plaintext_backup":true,"exportable":true})
        )?
        .status
            == 200
    );
    assert!(t.has_derived_ed_state());
    let descriptor_response = call(&mut t, "GET", "keys/context", json!({}))?;
    let descriptor = &descriptor_response.body;
    assert!(descriptor["data"]["keys"]["1"]["public_key"] == "");
    assert!(
        descriptor["data"]["keys"]["1"]["name"] == "ed25519"
            && descriptor["data"]["keys"]["1"]["certificate_chain"] == ""
    );
    assert!(
        descriptor["data"]["supports_derivation"] == true
            && descriptor["data"]["kdf"] == "hkdf_sha256"
    );
    let master = stored_material(&t.keys["context"].versions[&1].material)
        .map_err(|_| "master unavailable")?;
    assert!(master.len() == 64);
    let sdk_master = PKey::private_key_from_raw_bytes(&master[..32], Id::ED25519)
        .map_err(|_| "SDK master seed")?;
    let sdk_private = sdk_master
        .private_key_to_pkcs8()
        .map_err(|_| "SDK master PKCS8")?;
    let sdk_public = sdk_master
        .public_key_to_der()
        .map_err(|_| "SDK master SPKI")?;
    let independent_hmac = stored_material(&t.keys["context"].versions[&1].hmac_material)
        .map_err(|_| "independent HMAC material")?;
    for (category, public) in [("signing-key", false), ("public-key", true)] {
        for format in ["", "raw", "der", "pem"] {
            let response = call(
                &mut t,
                "GET",
                &format!("export/{category}/context"),
                json!({"format":format}),
            )?;
            assert!(
                response.status == 200
                    && response.body["data"]["type"] == "ed25519"
                    && response.body["data"]["name"] == "context"
            );
            let value = &response.body["data"]["keys"]["1"];
            match format {
                "" | "raw" => assert!(
                    decoded(value)?.as_slice()
                        == if public {
                            &master[32..]
                        } else {
                            master.as_slice()
                        }
                ),
                "der" => {
                    let der = decoded(value)?;
                    assert!(
                        der.as_slice()
                            == if public {
                                sdk_public.as_slice()
                            } else {
                                sdk_private.as_slice()
                            }
                    );
                    assert!(der.len() == if public { 44 } else { 48 });
                }
                "pem" => {
                    let pem = value.as_str().ok_or("PEM export missing")?;
                    assert!(!pem.ends_with('\n') && pem.len() == if public { 112 } else { 118 });
                    if public {
                        assert!(pem.starts_with(
                            "-----BEGIN PUBLIC KEY-----
"
                        ));
                        let parsed = PKey::public_key_from_pem(pem.as_bytes())
                            .map_err(|_| "SDK exported public PEM")?;
                        assert!(
                            parsed
                                .raw_public_key()
                                .map_err(|_| "SDK exported public")?
                                .as_slice()
                                == &master[32..]
                        );
                    } else {
                        assert!(pem.starts_with(
                            "-----BEGIN PRIVATE KEY-----
"
                        ));
                        let parsed = PKey::private_key_from_pem(pem.as_bytes())
                            .map_err(|_| "SDK exported private PEM")?;
                        assert!(
                            parsed
                                .raw_private_key()
                                .map_err(|_| "SDK exported seed")?
                                .as_slice()
                                == &master[..32]
                        );
                    }
                }
                _ => return Err("test format not closed"),
            }
        }
    }
    for format in ["", "raw"] {
        let response = call(
            &mut t,
            "GET",
            "export/hmac-key/context",
            json!({"format":format}),
        )?;
        assert!(
            decoded(&response.body["data"]["keys"]["1"])?.as_slice() == independent_hmac.as_slice()
        );
    }
    let before_exports = state(&t)?;
    for format in ["der", "pem"] {
        let failure = t
            .handle(
                "team",
                "transit",
                "GET",
                "export/hmac-key/context",
                &json!({"format":format}),
                100,
            )
            .err()
            .ok_or("HMAC standard format accepted")?;
        assert!(failure.status == 500 && failure.message.contains("unknown format for HMAC key"));
        assert!(state(&t)?.as_slice() == before_exports.as_slice());
    }
    assert!(
        call(
            &mut t,
            "POST",
            "keys/locked",
            json!({"type":"ed25519","derived":true})
        )?
        .status
            == 200
    );
    let before_locked = state(&t)?;
    assert!(
        t.handle(
            "team",
            "transit",
            "GET",
            "export/signing-key/locked",
            &json!({}),
            100
        )
        .err()
        .is_some_and(|e| e.status == 400)
    );
    assert!(
        call(
            &mut t,
            "GET",
            "export/public-key/locked",
            json!({"format":"raw"})
        )?
        .status
            == 200
    );
    assert!(state(&t)?.as_slice() == before_locked.as_slice());
    let message = b"new independent context signature vector";
    let mut signatures = Vec::new();
    for context in [
        b"tenant-one".as_slice(),
        b"tenant-two".as_slice(),
        &[0, 1, 0xff],
    ] {
        let result_response = call(
            &mut t,
            "POST",
            "sign/context",
            json!({"input":BASE64.encode(message),"context":BASE64.encode(context)}),
        )?;
        let result = &result_response.body;
        let seed = independent_hkdf(&master, context, 32)?;
        let sdk =
            PKey::private_key_from_raw_bytes(&seed, Id::ED25519).map_err(|_| "SDK Ed seed")?;
        let public = sdk.raw_public_key().map_err(|_| "SDK Ed public")?;
        let (_, signature) = parse_wrapped(
            result["data"]["signature"]
                .as_str()
                .ok_or("signature missing")?,
        )
        .map_err(|_| "signature envelope")?;
        assert!(decoded(&result["data"]["public_key"])?.as_slice() == public.as_slice());
        let mut signer = Signer::new_without_digest(&sdk).map_err(|_| "SDK Ed signer")?;
        assert!(
            signature.as_slice()
                == signer
                    .sign_oneshot_to_vec(message)
                    .map_err(|_| "SDK Ed signature")?
                    .as_slice()
        );
        let mut verifier = Verifier::new_without_digest(&sdk).map_err(|_| "SDK Ed verifier")?;
        assert!(
            verifier
                .verify_oneshot(&signature, message)
                .map_err(|_| "SDK Ed verify")?
        );
        let request = json!({"input":BASE64.encode(message),"context":BASE64.encode(context),"signature":result["data"]["signature"]});
        assert!(
            call(&mut t, "POST", "verify/context", request.clone())?.body["data"]["valid"] == true
        );
        let mut changed = request.clone();
        changed["context"] = json!(BASE64.encode(b"other tenant"));
        assert!(call(&mut t, "POST", "verify/context", changed)?.body["data"]["valid"] == false);
        let mut changed = request;
        changed["input"] = json!(BASE64.encode(b"changed message"));
        assert!(call(&mut t, "POST", "verify/context", changed)?.body["data"]["valid"] == false);
        signatures.push(signature);
    }
    assert!(signatures[0].as_slice() != signatures[1].as_slice());
    let before = state(&t)?;
    let failure = t
        .handle(
            "team",
            "transit",
            "POST",
            "sign/context",
            &json!({"input":BASE64.encode(message)}),
            100,
        )
        .err()
        .ok_or("missing context accepted")?;
    assert!(failure.status == 500 && failure.message.contains("missing 'context'"));
    assert!(state(&t)?.as_slice() == before.as_slice());
    t.validate_derived_ed_state(None)
        .map_err(|_| "derived owner validation")?;
    Ok(())
}
#[test]
fn derivation127_ed_rotation_backup_restore_preserves_master_versions_and_rejects_partial_custody()
-> TestResult {
    let mut t = Transit::default();
    assert!(
        call(
            &mut t,
            "POST",
            "keys/source",
            json!({"type":"ed25519","derived":true,"allow_plaintext_backup":true})
        )?
        .status
            == 200
    );
    let configured = call(
        &mut t,
        "POST",
        "keys/source/config",
        json!({"deletion_allowed":true}),
    )?;
    assert!(
        configured.status == 200
            && configured.body["data"]["name"] == "source"
            && configured.body["data"]["type"] == "ed25519"
            && configured.body["data"]["derived"] == true
            && configured.body["data"]["latest_version"] == 1
            && configured.body["data"]["deletion_allowed"] == true
    );
    let request = json!({"input":BASE64.encode(b"backup context vector"),"context":BASE64.encode(b"archive tenant")});
    let first = call(&mut t, "POST", "sign/source", request.clone())?.body["data"].clone();
    assert!(call(&mut t, "POST", "keys/source/rotate", json!({}))?.status == 200);
    let second = call(&mut t, "POST", "sign/source", request.clone())?.body["data"].clone();
    assert!(first["signature"] != second["signature"]);
    let encoded = call(&mut t, "GET", "backup/source", json!({}))?.body["data"]["backup"]
        .as_str()
        .ok_or("backup missing")?
        .to_string();
    let raw = BASE64
        .decode(&encoded)
        .map(Zeroizing::new)
        .map_err(|_| "backup decoding")?;
    let wire: Value = serde_json::from_slice(&raw).map_err(|_| "backup private DTO")?;
    assert!(
        wire["policy"]["type"] == 2
            && wire["policy"]["kdf"] == 1
            && wire["policy"]["derived"] == true
    );
    for version in ["1", "2"] {
        let entry = &wire["policy"]["keys"][version];
        let master = decoded(&entry["key"])?;
        assert!(master.len() == 64 && decoded(&entry["public_key"])?.as_slice() == &master[32..]);
    }
    assert!(call(&mut t, "POST", "restore/copy", json!({"backup":encoded}))?.status == 204);
    assert!(call(&mut t, "POST", "sign/copy", request.clone())?.body["data"] == second);
    let mut first_request = request;
    first_request["key_version"] = json!(1);
    assert!(call(&mut t, "POST", "sign/copy", first_request)?.body["data"] == first);
    let before = state(&t)?;
    let mut corrupt = wire;
    corrupt["policy"]["keys"]["2"]["key"] = json!(BASE64.encode([0; 64]));
    corrupt["archived_keys"]["keys"][2]["key"] = corrupt["policy"]["keys"]["2"]["key"].clone();
    let corrupt = serde_json::to_vec(&corrupt)
        .map(Zeroizing::new)
        .map_err(|_| "corrupt synthetic DTO encoding")?;
    assert!(
        t.handle(
            "team",
            "transit",
            "POST",
            "restore/copy",
            &json!({"backup":BASE64.encode(corrupt.as_slice()),"force":true}),
            100
        )
        .is_err()
    );
    assert!(state(&t)?.as_slice() == before.as_slice());
    let reloaded: Transit =
        serde_json::from_slice(&before).map_err(|_| "derived restart decoding")?;
    reloaded
        .validate_derived_ed_state(None)
        .map_err(|_| "derived restart validation")?;
    assert!(state(&reloaded)?.as_slice() == before.as_slice());
    let previous = t.clone();
    assert!(call(&mut t, "DELETE", "keys/source", json!({}))?.status == 204);
    t.derived_ed_format = None;
    assert!(t.validate_derived_ed_state(Some(&previous)).is_err());
    Ok(())
}
#[test]
fn derivation127_ecdh_three_curves_four_aead_keys_match_independent_hkdf_and_atomic_error_paths()
-> TestResult {
    let mut t = Transit::default();
    for (base, curve) in [
        ("ecdsa-p256", Nid::X9_62_PRIME256V1),
        ("ecdsa-p384", Nid::SECP384R1),
        ("ecdsa-p521", Nid::SECP521R1),
    ] {
        assert!(
            call(
                &mut t,
                "POST",
                &format!("keys/{base}"),
                json!({"type":base})
            )?
            .status
                == 200
        );
        let base_config = call(
            &mut t,
            "POST",
            &format!("keys/{base}/config"),
            json!({"min_derivation_version":2}),
        )?;
        assert!(
            base_config.status == 200
                && base_config.body["data"]["name"] == base
                && base_config.body["data"]["type"] == base
                && base_config.body["data"]["exportable"] == false
                && base_config.body["data"]["latest_version"] == 1
        );
        let group = EcGroup::from_curve_name(curve).map_err(|_| "SDK curve")?;
        let peer = PKey::from_ec_key(EcKey::generate(&group).map_err(|_| "SDK peer")?)
            .map_err(|_| "SDK peer PKey")?;
        let public = peer.public_key_to_pem().map_err(|_| "SDK peer PEM")?;
        let public = String::from_utf8(public).map_err(|_| "SDK PEM UTF8")?;
        let base_der =
            stored_material(&t.keys[base].versions[&1].material).map_err(|_| "base material")?;
        let own = PKey::private_key_from_der(&base_der).map_err(|_| "SDK base DER")?;
        let own_public =
            PKey::public_key_from_der(&own.public_key_to_der().map_err(|_| "SDK base SPKI")?)
                .map_err(|_| "SDK base public")?;
        let mut reciprocal = Deriver::new(&peer).map_err(|_| "SDK ECDH reciprocal")?;
        reciprocal
            .set_peer(&own_public)
            .map_err(|_| "SDK ECDH reciprocal peer")?;
        let shared = Zeroizing::new(
            reciprocal
                .derive_to_vec()
                .map_err(|_| "SDK ECDH reciprocal result")?,
        );
        for kind in [
            "aes128-gcm96",
            "aes256-gcm96",
            "chacha20-poly1305",
            "xchacha20-poly1305",
        ] {
            let name = format!("{base}-{kind}");
            let body = json!({"base_key_name":base,"base_key_version":1,"derived_key_type":kind,"key_derivation_algorithm":"ecdh","peer_public_key":public});
            assert!(
                call(&mut t, "POST", &format!("derive-key/{name}"), body.clone())?.status == 204
            );
            let derived_config = call(
                &mut t,
                "POST",
                &format!("keys/{name}/config"),
                json!({"exportable":true}),
            )?;
            assert!(
                derived_config.status == 200
                    && derived_config.body["data"]["name"] == name
                    && derived_config.body["data"]["type"] == kind
                    && derived_config.body["data"]["exportable"] == true
                    && derived_config.body["data"]["latest_version"] == 1
            );
            let exported_response = call(
                &mut t,
                "GET",
                &format!("export/encryption-key/{name}"),
                json!({}),
            )?;
            let exported = &exported_response.body;
            let expected = independent_hkdf(&shared, &[], symmetric::key_len(kind))?;
            assert!(decoded(&exported["data"]["keys"]["1"])?.as_slice() == expected.as_slice());
            let plaintext = BASE64.encode(format!("novel reciprocal vector {name}").as_bytes());
            let encrypted_response = call(
                &mut t,
                "POST",
                &format!("encrypt/{name}"),
                json!({"plaintext":plaintext}),
            )?;
            let encrypted = &encrypted_response.body;
            assert!(
                call(
                    &mut t,
                    "POST",
                    &format!("decrypt/{name}"),
                    json!({"ciphertext":encrypted["data"]["ciphertext"]})
                )?
                .body["data"]["plaintext"]
                    == plaintext
            );
            let old_hmac_response = call(
                &mut t,
                "POST",
                &format!("hmac/{name}"),
                json!({"input":"ZWNkaCBhcmNoaXZl","key_version":1}),
            )?;
            let old_hmac = &old_hmac_response.body;
            let old_key = t.keys[&name].versions[&1].material.clone();
            let second_peer =
                PKey::from_ec_key(EcKey::generate(&group).map_err(|_| "SDK second peer")?)
                    .map_err(|_| "SDK second PKey")?;
            let second_public = String::from_utf8(
                second_peer
                    .public_key_to_pem()
                    .map_err(|_| "SDK second PEM")?,
            )
            .map_err(|_| "SDK second UTF8")?;
            let mut second_request = body.clone();
            second_request["peer_public_key"] = json!(second_public);
            assert!(
                call(
                    &mut t,
                    "POST",
                    &format!("derive-key/{name}"),
                    second_request
                )?
                .status
                    == 204
            );
            let descriptor_response = call(&mut t, "GET", &format!("keys/{name}"), json!({}))?;
            let descriptor = &descriptor_response.body;
            assert!(
                descriptor["data"]["latest_version"] == 2
                    && descriptor["data"]["imported_key"] == true
                    && descriptor["data"]["imported_key_allow_rotation"] == false
                    && descriptor["data"]["derived"] == false
            );
            assert!(t.keys[&name].versions[&1].material == old_key);
            assert!(
                &call(
                    &mut t,
                    "POST",
                    &format!("hmac/{name}"),
                    json!({"input":"ZWNkaCBhcmNoaXZl","key_version":1})
                )?
                .body
                    == old_hmac
            );
            let mut second_agreement =
                Deriver::new(&second_peer).map_err(|_| "SDK second reciprocal")?;
            second_agreement
                .set_peer(&own_public)
                .map_err(|_| "SDK second reciprocal peer")?;
            let second_shared = Zeroizing::new(
                second_agreement
                    .derive_to_vec()
                    .map_err(|_| "SDK second reciprocal result")?,
            );
            let second_expected = independent_hkdf(&second_shared, &[], symmetric::key_len(kind))?;
            assert!(
                stored_material(&t.keys[&name].versions[&2].material)
                    .map_err(|_| "second material")?
                    .as_slice()
                    == second_expected.as_slice()
            );
            let before = state(&t)?;
            for (field, value, status) in [
                ("base_key_version", json!(999), 500),
                (
                    "key_derivation_algorithm",
                    json!("synthetic-unsupported"),
                    400,
                ),
                ("derived_key_type", json!("rsa-2048"), 400),
                ("peer_public_key", json!("not a PEM"), 500),
            ] {
                let mut rejected = body.clone();
                rejected[field] = value;
                let failed = t
                    .handle(
                        "team",
                        "transit",
                        "POST",
                        "derive-key/never-published",
                        &rejected,
                        100,
                    )
                    .err()
                    .ok_or("invalid derive accepted")?;
                assert!(failed.status == status && !t.keys.contains_key("never-published"));
                assert!(state(&t)?.as_slice() == before.as_slice());
            }
        }
        let wrong_group = EcGroup::from_curve_name(if curve == Nid::X9_62_PRIME256V1 {
            Nid::SECP384R1
        } else {
            Nid::X9_62_PRIME256V1
        })
        .map_err(|_| "SDK wrong curve")?;
        let wrong = PKey::from_ec_key(EcKey::generate(&wrong_group).map_err(|_| "SDK wrong peer")?)
            .map_err(|_| "SDK wrong PKey")?;
        let wrong_pem = String::from_utf8(wrong.public_key_to_pem().map_err(|_| "SDK wrong PEM")?)
            .map_err(|_| "SDK wrong UTF8")?;
        let before = state(&t)?;
        let error = t
            .handle(
                "team",
                "transit",
                "POST",
                "derive-key/wrong-curve",
                &json!({"base_key_name":base,"peer_public_key":wrong_pem}),
                100,
            )
            .err()
            .ok_or("wrong curve accepted")?;
        assert!(
            error.status == 500
                && error
                    .message
                    .contains("does not match peer public key curve")
        );
        assert!(!t.keys.contains_key("wrong-curve") && state(&t)?.as_slice() == before.as_slice());
        let default_name = format!("{base}-default");
        assert!(
            call(
                &mut t,
                "POST",
                &format!("derive-key/{default_name}"),
                json!({"base_key_name":base,"peer_public_key":public})
            )?
            .status
                == 204
        );
        let default_response = call(&mut t, "GET", &format!("keys/{default_name}"), json!({}))?;
        let default = &default_response.body;
        assert!(
            default["data"]["type"] == "aes256-gcm96"
                && default["data"]["latest_version"] == 1
                && default["data"]["imported_key"] == true
                && default["data"]["supports_derivation"] == true
        );
    }
    assert!(!t.has_derived_ed_state());
    Ok(())
}
