#![allow(clippy::unwrap_used, clippy::expect_used)]
use super::*;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ring::signature::{Ed25519KeyPair, KeyPair};
use serde_json::json;

fn fixture() -> (JwtVerifier, Ed25519KeyPair, NativeJwtTimePolicy) {
    let pair = Ed25519KeyPair::from_seed_unchecked(&[61; 32]).unwrap();
    let policy =
        TrustPolicy::new("issuer", BTreeSet::from(["service".into()]), None, 0, 3600).unwrap();
    let key = VerificationKey::new(
        "key",
        JwtAlgorithm::Ed25519,
        pair.public_key().as_ref().to_vec(),
    )
    .unwrap();
    (
        JwtVerifier::new(policy, [key]).unwrap(),
        pair,
        NativeJwtTimePolicy {
            clock_skew_seconds: 60,
            legacy_strict_expiry: false,
            expiration_leeway: 0,
            not_before_leeway: 0,
            maximum_token_lifetime_seconds: None,
        },
    )
}

fn signed(pair: &Ed25519KeyPair, times: Value) -> String {
    let mut claims = json!({"iss":"issuer","sub":"alice","aud":"service"});
    claims
        .as_object_mut()
        .unwrap()
        .extend(times.as_object().unwrap().clone());
    let payload = format!(
        "{}.{}",
        URL_SAFE_NO_PAD.encode(br#"{"alg":"EdDSA","kid":"key"}"#),
        URL_SAFE_NO_PAD.encode(serde_json::to_vec(&claims).unwrap())
    );
    format!(
        "{payload}.{}",
        URL_SAFE_NO_PAD.encode(pair.sign(payload.as_bytes()).as_ref())
    )
}

#[test]
fn native_numeric_dates_optional_claims_and_default_synthesis_match_openbao() {
    let (verifier, pair, time) = fixture();
    for (claims, accepted) in [
        (json!({"exp":1120}), true),
        (json!({"exp":1300}), false),
        (json!({"iat":1000}), true),
        (json!({"nbf":1000}), true),
        (json!({"iat":1000,"nbf":1000}), true),
        (json!({}), false),
        (json!({"iat":0,"nbf":0,"exp":0}), false),
        (json!({"iat":null,"nbf":null,"exp":null}), false),
        (json!({"iat":1000,"exp":0}), true),
        (json!({"iat":-1,"exp":1120}), true),
        (json!({"nbf":-1,"exp":1120}), true),
        (json!({"iat":1000.9,"exp":1120.75}), true),
        (json!({"iat":-1.9,"exp":1120.75}), true),
        (json!({"exp":-1}), false),
        (json!({"iat":true,"exp":1120}), false),
        (json!({"iat":"1000","exp":1120}), false),
        (json!({"iat":1000,"exp":8200}), true),
        (json!({"iat":1030,"exp":1120}), true),
        (json!({"iat":1120,"exp":1300}), false),
        (json!({"iat":800,"exp":970}), true),
        (json!({"iat":700,"exp":880}), false),
    ] {
        let token = signed(&pair, claims.clone());
        assert_eq!(
            verifier.verify_native(&token, 1000, time).is_ok(),
            accepted,
            "{claims}"
        );
    }
}

#[test]
fn native_leeways_apply_to_missing_times_and_clock_skew_to_all_times() {
    let (verifier, pair, defaults) = fixture();
    for (claims, clock, expiration, not_before, accepted) in [
        (json!({"iat":800}), 60, 0, 0, true),
        (json!({"iat":760}), 60, 0, 0, false),
        (json!({"iat":995}), 0, -1, 0, false),
        (json!({"iat":800}), 0, 300, 0, true),
        (json!({"exp":1120}), 0, 0, -1, false),
        (json!({"exp":1120}), 0, 0, 300, true),
        (json!({"iat":900,"exp":999}), 0, 999, 0, false),
        (json!({"iat":900,"exp":1000}), 0, 0, 0, true),
        (json!({"iat":1001,"exp":1120}), 0, 0, 0, false),
        (json!({"iat":1090,"exp":1120}), 120, 0, 0, true),
    ] {
        let time = NativeJwtTimePolicy {
            clock_skew_seconds: clock,
            expiration_leeway: expiration,
            not_before_leeway: not_before,
            ..defaults
        };
        assert_eq!(
            verifier
                .verify_native(&signed(&pair, claims.clone()), 1000, time)
                .is_ok(),
            accepted,
            "{claims}"
        );
    }
}

#[test]
fn native_reuse_does_not_relax_the_separate_strict_proof_contract() {
    let (verifier, pair, time) = fixture();
    for jti in [None, Some(json!("")), Some(json!("same-id"))] {
        let mut claims = json!({"exp":1120});
        if let Some(jti) = jti {
            claims["jti"] = jti;
        }
        let token = signed(&pair, claims);
        let first = verifier.verify_native(&token, 1000, time).unwrap();
        assert_eq!(verifier.verify_native(&token, 1000, time).unwrap(), first);
        assert!(verifier.verify(&token, 1000).is_err());
    }
    assert!(
        verifier
            .verify_native(&signed(&pair, json!({"exp":1120,"jti":1})), 1000, time)
            .is_err()
    );
    let token = signed(&pair, json!({"iat":1000,"exp":1120,"jti":"proof"}));
    assert!(verifier.verify(&token, 1000).is_ok());
}

#[test]
fn explicit_maximum_requires_real_signed_dates_and_cannot_use_synthetic_times() {
    let (verifier, pair, time) = fixture();
    let bounded = NativeJwtTimePolicy {
        maximum_token_lifetime_seconds: Some(300),
        ..time
    };
    for (claims, accepted) in [
        (json!({"iat":1000,"exp":1120}), true),
        (json!({"iat":1000,"exp":1400}), false),
        (json!({"exp":1120}), false),
        (json!({"iat":1000}), false),
        (json!({"nbf":1000,"exp":1120}), false),
        (json!({"iat":1000,"exp":0}), false),
        (json!({"iat":-1,"exp":0,"nbf":1000}), false),
        (json!({"iat":-1,"exp":0.9,"nbf":1000}), false),
        (json!({"iat":1000,"exp":999}), false),
    ] {
        assert_eq!(
            verifier
                .verify_native(&signed(&pair, claims.clone()), 1000, bounded)
                .is_ok(),
            accepted,
            "{claims}"
        );
    }
}
