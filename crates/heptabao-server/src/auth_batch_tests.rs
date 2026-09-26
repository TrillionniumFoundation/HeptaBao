use super::*;
use serde_json::json;
type TestResult = Result<(), Box<dyn std::error::Error>>;

fn claims(now: u64, ttl: u64) -> BatchClaims {
    BatchClaims {
        namespace: "team/one".into(),
        policies: BTreeSet::from(["default".into(), "reader".into()]),
        metadata: BTreeMap::from([("username".into(), "alice".into())]),
        display_name: "userpass-alice".into(),
        path: "auth/userpass/login/alice".into(),
        bound_cidrs: vec!["127.0.0.1".into()],
        issued_at: now,
        expires_at: now.saturating_add(ttl),
        parent: Some(URL_SAFE_NO_PAD.encode([1; 32])),
        entity_id: Some("e-00000000000000000000000000000001".into()),
    }
}

fn stored(authority: &BatchKeyAuthority) -> Result<Zeroizing<Vec<u8>>, serde_json::Error> {
    let mut writer = ClaimsWriter(Zeroizing::new(Vec::with_capacity(
        MAX_BATCH_CLAIMS_BYTES + TAG_BYTES,
    )));
    serde_json::to_writer(&mut writer, authority)?;
    Ok(writer.0)
}

fn reframe(envelope: &[u8]) -> Zeroizing<String> {
    let mut result = Zeroizing::new(String::with_capacity(MAX_BATCH_TOKEN_BYTES));
    result.push_str(PREFIX);
    URL_SAFE_NO_PAD.encode_string(envelope, &mut result);
    result
}

fn encrypt_plaintext(
    authority: &BatchKeyAuthority,
    plaintext: &[u8],
) -> Result<Zeroizing<String>, BatchError> {
    let key = authority.keys.first().ok_or(BatchError::InvalidAuthority)?;
    let nonce = [3; NONCE_BYTES];
    let cipher = XChaCha20Poly1305::new_from_slice(key.secret.0.as_slice())
        .map_err(|_| BatchError::InvalidAuthority)?;
    let mut body = Zeroizing::new(plaintext.to_vec());
    let tag = cipher
        .encrypt_in_place_detached(
            XNonce::from_slice(&nonce),
            &associated_data(authority.authority_id, key.id),
            body.as_mut_slice(),
        )
        .map_err(|_| BatchError::InvalidToken)?;
    let mut envelope = Zeroizing::new(Vec::with_capacity(HEADER_BYTES + body.len() + TAG_BYTES));
    envelope.extend_from_slice(MAGIC);
    envelope.extend_from_slice(&authority.authority_id.0);
    envelope.extend_from_slice(&key.id.0);
    envelope.extend_from_slice(&nonce);
    envelope.extend_from_slice(&body);
    envelope.extend_from_slice(&tag);
    Ok(reframe(&envelope))
}

#[test]
fn real_seal_reopen_and_authenticated_projection_preserve_all_claims() -> TestResult {
    let mut authority = BatchKeyAuthority::new(100)?;
    let token = authority.seal(claims(101, 300), 101)?;
    let durable = stored(&authority)?;
    let reopened: BatchKeyAuthority = serde_json::from_slice(&durable)?;
    let verified = reopened.open(token.as_str(), "team/one", 102)?;
    assert_eq!(verified.namespace(), "team/one");
    assert_eq!(verified.issued_at(), 101);
    assert_eq!(verified.expires_at(), 401);
    assert_eq!(
        verified.metadata().get("username").map(String::as_str),
        Some("alice")
    );
    assert_eq!(verified.display_name(), "userpass-alice");
    assert_eq!(verified.path(), "auth/userpass/login/alice");
    assert_eq!(
        verified.policies(),
        &BTreeSet::from(["default".into(), "reader".into()])
    );
    assert_eq!(verified.bound_cidrs(), &["127.0.0.1"]);
    assert_eq!(
        verified.parent(),
        Some(URL_SAFE_NO_PAD.encode([1; 32])).as_deref()
    );
    assert_eq!(
        verified.entity_id(),
        Some("e-00000000000000000000000000000001")
    );
    assert_eq!(verified.token_digest(), super::super::hash(token.as_str()));
    reopened.check_verified(&verified, "team/one", 400)?;
    assert_eq!(
        reopened.check_verified(&verified, "other", 102),
        Err(BatchError::WrongNamespace)
    );
    assert_eq!(
        reopened.check_verified(&verified, "team/one", 401),
        Err(BatchError::ExpiredOrFuture)
    );
    assert!(reopened.open(token.as_str(), "team/one", 100).is_err());
    assert!(reopened.open(token.as_str(), "team/one", 401).is_err());
    // Authentication can recover its signed namespace before request routing;
    // admission must separately compare it to the actual request namespace.
    assert_eq!(
        reopened
            .open_authenticated(token.as_str(), 102)?
            .namespace(),
        "team/one"
    );
    Ok(())
}

#[test]
fn every_envelope_region_and_foreign_authority_fail_authentication() -> TestResult {
    let mut authority = BatchKeyAuthority::new(100)?;
    let token = authority.seal(claims(100, 300), 100)?;
    let envelope = Zeroizing::new(
        URL_SAFE_NO_PAD.decode(token.as_str().strip_prefix(PREFIX).ok_or("prefix")?)?,
    );
    for index in [
        0,
        4,
        4 + AUTHORITY_BYTES,
        HEADER_BYTES - NONCE_BYTES,
        HEADER_BYTES,
        envelope.len() - 1,
    ] {
        let mut changed = envelope.clone();
        changed[index] ^= 1;
        assert!(authority.open(&reframe(&changed), "team/one", 100).is_err());
    }
    for length in [
        0,
        3,
        HEADER_BYTES - 1,
        HEADER_BYTES + TAG_BYTES - 1,
        envelope.len() - 1,
    ] {
        assert!(
            authority
                .open(&reframe(&envelope[..length]), "team/one", 100)
                .is_err()
        );
    }
    let foreign = BatchKeyAuthority::new(100)?;
    assert!(foreign.open(token.as_str(), "team/one", 100).is_err());
    let verified = authority.open(token.as_str(), "team/one", 100)?;
    assert_eq!(
        foreign.check_verified(&verified, "team/one", 100),
        Err(BatchError::InvalidAuthority)
    );
    for bad in [
        format!("{}=", token.as_str()),
        token.as_str().replacen("hvb.", "hvs.", 1),
        "hvb.!".into(),
    ] {
        assert!(authority.open(&bad, "team/one", 100).is_err());
    }
    Ok(())
}

#[test]
fn repeated_seal_has_distinct_nonce_and_no_per_token_durable_registry() -> TestResult {
    let mut authority = BatchKeyAuthority::new(100)?;
    let first = authority.seal(claims(100, 300), 100)?;
    let second = authority.seal(claims(100, 300), 100)?;
    assert!(first.as_str() != second.as_str());
    let after_first = stored(&authority)?;
    for _ in 0..128 {
        let _ = authority.seal(claims(100, 300), 100)?;
    }
    assert!(stored(&authority)?.as_slice() == after_first.as_slice());
    assert_eq!(authority.keys.len(), 1);
    assert!(stored(&authority)?.len() < 2048);
    assert!(authority.open(first.as_str(), "team/one", 399).is_ok());
    Ok(())
}

#[test]
fn snapshot_watermark_rollback_does_not_revoke_later_same_key_token() -> TestResult {
    let mut authority = BatchKeyAuthority::new(100)?;
    let early = authority.seal(claims(100, 10), 100)?;
    let before_later_token = stored(&authority)?;
    let later = authority.seal(claims(200, 600), 200)?;
    let restored: BatchKeyAuthority = serde_json::from_slice(&before_later_token)?;
    assert_eq!(restored.keys[0].max_issued_expiry, 110);
    assert!(restored.open(early.as_str(), "team/one", 200).is_err());
    let verified = restored.open(later.as_str(), "team/one", 200)?;
    restored.check_verified(&verified, "team/one", 799)?;
    let owner = super::super::lease_owner::LeaseOwner::from_batch(&verified);
    restored.check_lease(owner.batch_claims().ok_or("batch owner")?, "team/one", 799)?;
    assert!(restored.open(later.as_str(), "team/one", 800).is_err());
    // Fresh unrelated authority (or a snapshot without this key) cannot decode.
    assert!(
        BatchKeyAuthority::new(100)?
            .open(later.as_str(), "team/one", 200)
            .is_err()
    );
    Ok(())
}

#[test]
fn rejected_issuance_cannot_change_key_watermarks() -> TestResult {
    let mut authority = BatchKeyAuthority::new(100)?;
    let _ = authority.seal(claims(200, 100), 200)?;
    let before = stored(&authority)?;
    assert!(matches!(
        authority.seal(claims(199, 100), 199),
        Err(BatchError::ClockRollback)
    ));
    assert!(authority.seal(claims(201, 100), 202).is_err());
    assert!(authority.seal(claims(201, 0), 201).is_err());
    assert!(authority.seal(claims(201, MAX_BATCH_TTL + 1), 201).is_err());
    let mut wrapped = claims(u64::MAX, 1);
    wrapped.expires_at = 0;
    assert!(authority.seal(wrapped, u64::MAX).is_err());
    let mut too_large = claims(201, 100);
    for n in 0..10 {
        too_large
            .metadata
            .insert(format!("large-{n}"), "x".repeat(1024));
    }
    assert!(matches!(
        authority.seal(too_large, 201),
        Err(BatchError::Capacity)
    ));
    assert!(stored(&authority)?.as_slice() == before.as_slice());
    let mut near_limit = BatchKeyAuthority::new(u64::MAX - 1)?;
    let last = near_limit.seal(claims(u64::MAX - 1, 1), u64::MAX - 1)?;
    assert!(
        near_limit
            .open(last.as_str(), "team/one", u64::MAX - 1)
            .is_ok()
    );
    assert!(
        near_limit
            .open(last.as_str(), "team/one", u64::MAX)
            .is_err()
    );
    Ok(())
}

#[test]
fn claims_and_wire_bounds_are_checked_before_unbounded_allocation() -> TestResult {
    let mut authority = BatchKeyAuthority::new(100)?;
    let mut exact = claims(100, MAX_BATCH_TTL);
    exact.metadata.clear();
    // Fill within each individual field bound, then exactly hit the serialized
    // claim limit. ASCII contents make the byte accounting deterministic.
    for n in 0..7 {
        exact.metadata.insert(format!("fill-{n}"), "x".repeat(1024));
    }
    let base_length = encode_claims(&exact)?.len();
    let remaining = MAX_BATCH_CLAIMS_BYTES
        .checked_sub(base_length + "\"tail\":\"\",".len())
        .ok_or("fixture budget")?;
    assert!(remaining <= 1024);
    exact.metadata.insert("tail".into(), "y".repeat(remaining));
    assert_eq!(encode_claims(&exact)?.len(), MAX_BATCH_CLAIMS_BYTES);
    let token = authority.seal(exact.clone(), 100)?;
    assert!(token.as_str().len() < MAX_BATCH_TOKEN_BYTES);
    assert!(authority.open(token.as_str(), "team/one", 101).is_ok());
    exact.metadata.get_mut("tail").ok_or("tail")?.push('z');
    assert!(matches!(
        authority.seal(exact, 100),
        Err(BatchError::Capacity)
    ));
    assert!(matches!(
        authority.open(&"x".repeat(MAX_BATCH_TOKEN_BYTES + 1), "team/one", 100),
        Err(BatchError::Capacity)
    ));
    let oversized = reframe(&vec![0; MAX_ENVELOPE_BYTES + 1]);
    assert!(oversized.len() < MAX_BATCH_TOKEN_BYTES);
    assert!(authority.open(&oversized, "team/one", 100).is_err());
    Ok(())
}

#[test]
fn authenticated_noncanonical_unknown_or_unsafe_claims_are_rejected() -> TestResult {
    let authority = BatchKeyAuthority::new(100)?;
    let canonical = encode_claims(&claims(100, 300))?;
    let mut spaced = canonical.to_vec();
    spaced.push(b' ');
    assert!(
        authority
            .open(&encrypt_plaintext(&authority, &spaced)?, "team/one", 100)
            .is_err()
    );
    let mut value: serde_json::Value = serde_json::from_slice(&canonical)?;
    value["unknown"] = json!(true);
    assert!(
        authority
            .open(
                &encrypt_plaintext(&authority, &serde_json::to_vec(&value)?)?,
                "team/one",
                100
            )
            .is_err()
    );
    let mut duplicate_set = String::from_utf8(canonical.to_vec())?;
    duplicate_set = duplicate_set.replace(
        "[\"default\",\"reader\"]",
        "[\"default\",\"default\",\"reader\"]",
    );
    assert!(
        authority
            .open(
                &encrypt_plaintext(&authority, duplicate_set.as_bytes())?,
                "team/one",
                100
            )
            .is_err()
    );
    for field in [
        "namespace",
        "parent",
        "entity",
        "policy",
        "cidr",
        "display",
        "path",
    ] {
        let mut candidate = claims(100, 300);
        match field {
            "namespace" => candidate.namespace = "../wrong".into(),
            "parent" => candidate.parent = Some("hvs.raw-parent-secret".into()),
            "entity" => candidate.entity_id = Some("../entity".into()),
            "policy" => {
                candidate.policies.insert("root".into());
            }
            "cidr" => candidate.bound_cidrs = vec!["127.0.0.1/32".into()],
            "display" => candidate.display_name = "unsafe\nname".into(),
            "path" => candidate.path = "x".repeat(2049),
            _ => return Err("unknown fixture case".into()),
        }
        assert!(
            authority
                .open(
                    &encrypt_plaintext(&authority, &encode_claims(&candidate)?)?,
                    "team/one",
                    100
                )
                .is_err()
        );
    }
    Ok(())
}

#[test]
fn durable_authority_rejects_key_substitution_unknown_fields_and_unbounded_slots() -> TestResult {
    let authority = BatchKeyAuthority::new(100)?;
    let original: serde_json::Value = serde_json::from_slice(&stored(&authority)?)?;
    for mutation in [
        "unknown",
        "version",
        "zero_authority",
        "missing_active",
        "wrong_secret",
        "duplicate",
        "too_many",
        "empty",
        "clock",
        "expiry",
    ] {
        let mut value = original.clone();
        match mutation {
            "unknown" => value["tokens"] = json!({}),
            "version" => value["version"] = json!(2),
            "zero_authority" => value["authority_id"] = json!(vec![0; AUTHORITY_BYTES]),
            "missing_active" => value["active_key"] = json!(vec![1; KEY_ID_BYTES]),
            "wrong_secret" => value["keys"][0]["secret"] = json!(URL_SAFE_NO_PAD.encode([9; 32])),
            "duplicate" => {
                value["keys"] = json!([value["keys"][0].clone(), value["keys"][0].clone()])
            }
            "too_many" => value["keys"] = json!(vec![value["keys"][0].clone(); MAX_BATCH_KEYS + 1]),
            "empty" => value["keys"] = json!([]),
            "clock" => value["keys"][0]["last_issued_at"] = json!(99),
            "expiry" => value["keys"][0]["max_issued_expiry"] = json!(100 + MAX_BATCH_TTL + 1),
            _ => return Err("unknown fixture case".into()),
        }
        assert!(
            serde_json::from_value::<BatchKeyAuthority>(value).is_err(),
            "{mutation}"
        );
    }
    Ok(())
}

#[test]
fn orphan_empty_policy_claims_and_retained_nonactive_keys_reopen() -> TestResult {
    let mut authority = BatchKeyAuthority::new(100)?;
    let mut orphan = claims(100, 300);
    orphan.namespace.clear();
    orphan.parent = None;
    orphan.entity_id = None;
    orphan.policies.clear();
    orphan.metadata.clear();
    orphan.bound_cidrs.clear();
    let token = authority.seal(orphan, 100)?;
    // Exercise the persisted ring decoder, not an exposed rotation API. Old
    // retained keys must remain usable even when a different key is active.
    for _ in 1..MAX_BATCH_KEYS {
        let mut additional = BatchKeyAuthority::new(100)?;
        authority.keys.push(additional.keys.pop().ok_or("new key")?);
    }
    authority.active_key = authority.keys.last().ok_or("active key")?.id;
    let reopened: BatchKeyAuthority = serde_json::from_slice(&stored(&authority)?)?;
    assert_eq!(reopened.keys.len(), MAX_BATCH_KEYS);
    let verified = reopened.open(token.as_str(), "", 200)?;
    assert!(verified.parent().is_none());
    assert!(verified.entity_id().is_none());
    assert!(verified.policies().is_empty());
    assert!(verified.metadata().is_empty());
    assert!(verified.bound_cidrs().is_empty());
    reopened.check_verified(&verified, "", 200)?;
    Ok(())
}

#[test]
fn batch_metadata_uses_full_claim_byte_bound_instead_of_arbitrary_field_limits() -> TestResult {
    let mut authority = BatchKeyAuthority::new(100)?;
    let mut value = claims(100, 300);
    value.metadata = (0..65).map(|i| (format!("key-{i}"), "v".into())).collect();
    value.metadata.insert("".into(), "".into());
    value.metadata.insert("k".repeat(129), "v".repeat(1025));
    value
        .metadata
        .insert("control\nkey".into(), "line\n\tvalue".into());
    let expected = value.metadata.clone();
    let raw = authority.seal(value.clone(), 100)?;
    let verified = authority.open(raw.as_str(), "team/one", 100)?;
    assert!(verified.metadata() == &expected);
    let before = stored(&authority)?;
    value
        .metadata
        .insert("large".into(), "x".repeat(MAX_BATCH_CLAIMS_BYTES));
    assert!(matches!(
        authority.seal(value, 100),
        Err(BatchError::Capacity)
    ));
    assert!(before.as_slice() == stored(&authority)?.as_slice());
    Ok(())
}
