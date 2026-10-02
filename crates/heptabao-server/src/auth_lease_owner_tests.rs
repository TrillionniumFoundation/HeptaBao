use super::*;
use crate::auth::batch::{BatchClaims, BatchKeyAuthority};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use serde_json::json;
use std::collections::{BTreeMap, BTreeSet};
type TestResult = Result<(), Box<dyn std::error::Error>>;

fn claims() -> BatchClaims {
    BatchClaims {
        namespace: "team".into(),
        policies: BTreeSet::from(["default".into()]),
        metadata: BTreeMap::from([("username".into(), "private-user".into())]),
        display_name: "userpass-private-user".into(),
        path: "auth/userpass/login/private-user".into(),
        bound_cidrs: vec!["127.0.0.1".into()],
        issued_at: 100,
        expires_at: 400,
        parent: Some(URL_SAFE_NO_PAD.encode([1; 32])),
        entity_id: Some("e-person".into()),
    }
}

#[test]
fn fixed_historical_service_owner_bytes_and_backend_grammars_are_preserved() -> TestResult {
    // Fixed old bytes, not serialization compared against itself. These are
    // representative enclosing records whose provider digest must not change.
    let old_digest = r#"{"owner":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","phase":"active"}"#;
    #[derive(Serialize, Deserialize)]
    struct Record {
        owner: LeaseOwner,
        phase: String,
    }
    let record: Record = serde_json::from_str(old_digest)?;
    assert_eq!(serde_json::to_string(&record)?, old_digest);
    record
        .owner
        .validate_scope("", ServiceOwnerProfile::CanonicalDigest)?;
    record
        .owner
        .validate_scope("", ServiceOwnerProfile::DigestAlphabet)?;
    let newly_constructed = LeaseOwner::service("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")?;
    assert!(newly_constructed.same_credential(&record.owner));
    let old_ldap = r#"{"owner":"legacy-owner:@tenant","phase":"active"}"#;
    let ldap: Record = serde_json::from_str(old_ldap)?;
    assert_eq!(serde_json::to_string(&ldap)?, old_ldap);
    ldap.owner
        .validate_scope("tenant", ServiceOwnerProfile::Graphic)?;
    assert!(
        ldap.owner
            .validate_scope("tenant", ServiceOwnerProfile::CanonicalDigest)
            .is_err()
    );
    assert!(LeaseOwner::service("legacy-owner:@tenant").is_err());
    // Old SSH/PKI checked alphabet and length, not unused base64 bits. The
    // adapter must not newly reject an authenticated historical store.
    let old_alphabet = format!("\"{}\"", "_".repeat(43));
    let legacy: LeaseOwner = serde_json::from_str(&old_alphabet)?;
    assert_eq!(serde_json::to_string(&legacy)?, old_alphabet);
    legacy.validate_scope("", ServiceOwnerProfile::DigestAlphabet)?;
    assert!(
        legacy
            .validate_scope("", ServiceOwnerProfile::CanonicalDigest)
            .is_err()
    );
    assert!(LeaseOwner::service(&"_".repeat(43)).is_err());
    Ok(())
}

#[test]
fn verified_batch_owner_is_distinct_bounded_and_survives_state_roundtrip() -> TestResult {
    let mut authority = BatchKeyAuthority::new(100)?;
    let token = authority.seal(claims(), 100)?;
    let verified = authority.open(token.as_str(), "team", 100)?;
    let owner = LeaseOwner::from_batch(&verified);
    let bytes = serde_json::to_vec(&owner)?;
    let projected: serde_json::Value = serde_json::from_slice(&bytes)?;
    assert_eq!(projected["kind"], "batch_claims_v1");
    let keys: BTreeSet<&str> = projected
        .as_object()
        .ok_or("owner object")?
        .keys()
        .map(String::as_str)
        .collect();
    assert_eq!(
        keys,
        BTreeSet::from([
            "kind",
            "authority_id",
            "key_id",
            "token_digest",
            "namespace",
            "issued_at",
            "expires_at",
            "parent",
            "entity_id"
        ])
    );
    assert!(bytes.len() < 1024);
    assert!(!String::from_utf8(bytes.clone())?.contains("private-user"));
    assert!(!String::from_utf8(bytes.clone())?.contains(token.as_str()));
    let restored: LeaseOwner = serde_json::from_slice(&bytes)?;
    assert!(restored.same_credential(&owner));
    assert!(restored == owner);
    assert!(restored.service_digest().is_none());
    restored.validate_scope("team", ServiceOwnerProfile::CanonicalDigest)?;
    assert_eq!(
        restored.validate_scope("other", ServiceOwnerProfile::Graphic),
        Err(BatchError::WrongNamespace)
    );
    let projection = restored.batch_claims().ok_or("batch projection")?;
    assert_eq!(
        projection.parent(),
        Some(URL_SAFE_NO_PAD.encode([1; 32])).as_deref()
    );
    assert_eq!(projection.entity_id(), Some("e-person"));
    assert_eq!(projection.token_digest(), verified.token_digest());
    authority.check_lease(projection, "team", 399)?;
    assert_eq!(
        authority.check_lease(projection, "team", 400),
        Err(BatchError::ExpiredOrFuture)
    );
    // Expired persisted owners still load for revocation; wrong namespace or
    // missing key authority cannot gain admission through that distinction.
    authority.validate_lease_authority(projection, "team")?;
    assert_eq!(
        authority.validate_lease_authority(projection, "other"),
        Err(BatchError::WrongNamespace)
    );
    assert_eq!(
        BatchKeyAuthority::new(100)?.validate_lease_authority(projection, "team"),
        Err(BatchError::InvalidAuthority)
    );
    assert_eq!(
        BatchKeyAuthority::new(100)?.check_lease(projection, "team", 100),
        Err(BatchError::InvalidAuthority)
    );
    // Same digest text in a service variant cannot impersonate this batch owner.
    let service = LeaseOwner::service(verified.token_digest())?;
    assert!(!service.same_credential(&owner));
    let second_token = authority.seal(claims(), 100)?;
    let second = LeaseOwner::from_batch(&authority.open(second_token.as_str(), "team", 100)?);
    assert!(!second.same_credential(&owner));
    let set = BTreeSet::from([service, owner, second, restored]);
    assert_eq!(set.len(), 3);
    Ok(())
}

#[test]
fn strict_batch_tag_never_falls_back_to_legacy_string_and_checks_shape() -> TestResult {
    let mut authority = BatchKeyAuthority::new(100)?;
    let token = authority.seal(claims(), 100)?;
    let owner = LeaseOwner::from_batch(&authority.open(token.as_str(), "team", 100)?);
    let original = serde_json::to_value(&owner)?;
    for mutation in [
        "tag",
        "missing_tag",
        "unknown",
        "missing_key",
        "zero_key",
        "zero_authority",
        "digest",
        "namespace",
        "parent",
        "entity",
        "expiry",
        "ttl",
    ] {
        let mut value = original.clone();
        match mutation {
            "tag" => value["kind"] = json!("service"),
            "missing_tag" => {
                value.as_object_mut().ok_or("map")?.remove("kind");
            }
            "unknown" => value["policies"] = json!(["root"]),
            "missing_key" => {
                value.as_object_mut().ok_or("map")?.remove("key_id");
            }
            "zero_key" => value["key_id"] = json!(vec![0; 32]),
            "zero_authority" => value["authority_id"] = json!(vec![0; 16]),
            "digest" => value["token_digest"] = json!("hvb.bearer"),
            "namespace" => value["namespace"] = json!("../escape"),
            "parent" => value["parent"] = json!("hvs.bearer"),
            "entity" => value["entity_id"] = json!("../entity"),
            "expiry" => value["expires_at"] = json!(100),
            "ttl" => value["expires_at"] = json!(100 + crate::auth::MAX_TTL + 1),
            _ => return Err("unknown fixture case".into()),
        }
        assert!(
            serde_json::from_value::<LeaseOwner>(value).is_err(),
            "{mutation}"
        );
    }
    for wrong in [
        json!(null),
        json!(3),
        json!(true),
        json!([]),
        json!({}),
        json!(""),
        json!("with space"),
        json!("x".repeat(129)),
    ] {
        assert!(serde_json::from_value::<LeaseOwner>(wrong).is_err());
    }
    let encoded = serde_json::to_string(&owner)?;
    let duplicate = encoded.replacen("{", "{\"kind\":\"batch_claims_v1\",", 1);
    assert!(serde_json::from_str::<LeaseOwner>(&duplicate).is_err());
    Ok(())
}
