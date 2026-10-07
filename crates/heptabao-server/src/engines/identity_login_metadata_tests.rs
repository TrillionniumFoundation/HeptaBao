use super::*;

type TestResult = std::result::Result<(), Box<dyn std::error::Error>>;

fn fixture() -> Result<(IdentityState, String, String)> {
    let mut state = IdentityState::default();
    let entity = state.bind_login("auth_jwt", "subject", 100)?.entity_id;
    let alias = state
        .alias_keys
        .get(&alias_key("auth_jwt", "subject"))
        .ok_or_else(|| bad("test alias"))?
        .clone();
    Ok((state, entity, alias))
}
fn metadata(role: &str) -> BTreeMap<String, String> {
    BTreeMap::from([("role".into(), role.into())])
}

#[test]
fn legacy_alias_metadata_remains_custom_and_absent_backend_bytes_roundtrip() -> TestResult {
    let (mut state, _, id) = fixture()?;
    state.aliases.get_mut(&id).ok_or("alias")?.custom_metadata = Some(metadata("user-maintained"));
    let bytes = serde_json::to_vec(&state)?;
    let mut value: Value = serde_json::from_slice(&bytes)?;
    assert!(value["aliases"][&id].get("login_metadata").is_none());
    let reopened: IdentityState = serde_json::from_slice(&bytes)?;
    reopened.validate_aliases()?;
    assert_eq!(serde_json::to_vec(&reopened)?, bytes);
    let old = value["aliases"][&id]
        .as_object_mut()
        .ok_or("alias object")?;
    let custom = old.remove("custom_metadata").ok_or("custom")?;
    old.insert("metadata".into(), custom);
    let legacy: IdentityState = serde_json::from_value(value)?;
    legacy.validate_aliases()?;
    let alias = legacy.aliases.get(&id).ok_or("alias")?;
    assert_eq!(alias.custom_metadata, Some(metadata("user-maintained")));
    assert!(alias.login_metadata.is_empty());
    assert_eq!(alias_data(alias)["metadata"], json!({}));
    assert!(!legacy.has_login_metadata());
    Ok(())
}

#[test]
fn provider_refresh_and_admin_custom_edit_preserve_separate_alias_metadata() -> TestResult {
    let (mut state, entity, id) = fixture()?;
    handle(
        &mut state,
        "POST",
        &format!("identity/entity-alias/id/{id}"),
        &json!({"canonical_id":entity,"name":"subject","mount_accessor":"auth_jwt",
                "custom_metadata":{"role":"custom-role","team":"operators"}}),
        101,
    )?;
    state.update_login_metadata("auth_jwt", "subject", &metadata("first"), 102)?;
    state.update_login_metadata("auth_jwt", "subject", &metadata("second"), 103)?;
    assert!(state.has_login_metadata());
    let before = serde_json::to_vec(&state)?;
    state.update_login_metadata("auth_jwt", "subject", &metadata("second"), 104)?;
    assert_eq!(
        serde_json::to_vec(&state)?,
        before,
        "same backend metadata must not churn timestamp"
    );
    let data = &handle(
        &mut state,
        "GET",
        &format!("identity/entity-alias/id/{id}"),
        &json!({}),
        104,
    )?
    .body;
    assert_eq!(data["data"]["metadata"], json!({"role":"second"}));
    assert_eq!(
        data["data"]["custom_metadata"],
        json!({"role":"custom-role","team":"operators"})
    );
    handle(
        &mut state,
        "POST",
        &format!("identity/entity-alias/id/{id}"),
        &json!({"canonical_id":entity,"name":"subject","mount_accessor":"auth_jwt",
                "custom_metadata":{"note":"changed"}}),
        105,
    )?;
    let before = serde_json::to_vec(&state)?;
    assert!(
        handle(
            &mut state,
            "POST",
            &format!("identity/entity-alias/id/{id}"),
            &json!({"canonical_id":entity,"name":"subject","mount_accessor":"auth_jwt",
                "metadata":{"role":"forged"}}),
            106
        )
        .is_err()
    );
    assert_eq!(serde_json::to_vec(&state)?, before);
    let reopened: IdentityState = serde_json::from_slice(&before)?;
    reopened.validate_aliases()?;
    let alias = reopened.aliases.get(&id).ok_or("alias")?;
    assert_eq!(alias.login_metadata, metadata("second"));
    assert_eq!(
        alias.custom_metadata,
        Some(BTreeMap::from([("note".into(), "changed".into())]))
    );
    Ok(())
}

#[test]
fn backend_metadata_rejects_disabled_missing_and_malformed_bindings_without_change() -> TestResult {
    let (mut state, entity, id) = fixture()?;
    state.update_login_metadata("auth_jwt", "subject", &metadata("first"), 100)?;
    state.entities.get_mut(&entity).ok_or("entity")?.disabled = true;
    let before = serde_json::to_vec(&state)?;
    assert_eq!(
        state
            .update_login_metadata("auth_jwt", "subject", &metadata("later"), 101)
            .err()
            .ok_or("expected disabled")?
            .status,
        403
    );
    assert_eq!(serde_json::to_vec(&state)?, before);
    state.entities.get_mut(&entity).ok_or("entity")?.disabled = false;
    for fields in [
        metadata(&"x".repeat(crate::login_metadata::MAX_BYTES)),
        metadata(&"\n".repeat(crate::login_metadata::MAX_BYTES / 2)),
    ] {
        let before = serde_json::to_vec(&state)?;
        assert!(
            state
                .update_login_metadata("auth_jwt", "subject", &fields, 101)
                .is_err()
        );
        assert_eq!(serde_json::to_vec(&state)?, before);
        let mut corrupted: Value = serde_json::from_slice(&before)?;
        corrupted["aliases"][&id]["login_metadata"] = json!(fields);
        let corrupted: IdentityState = serde_json::from_value(corrupted)?;
        assert!(
            corrupted.validate_aliases().is_err(),
            "persisted metadata also needs bounds"
        );
    }
    let before = serde_json::to_vec(&state)?;
    assert!(
        state
            .update_login_metadata("other_accessor", "subject", &metadata("later"), 101)
            .is_err()
    );
    assert_eq!(serde_json::to_vec(&state)?, before);
    state.aliases.get_mut(&id).ok_or("alias")?.name = "changed".into();
    let before = serde_json::to_vec(&state)?;
    assert!(
        state
            .update_login_metadata("auth_jwt", "subject", &metadata("later"), 101)
            .is_err()
    );
    assert_eq!(serde_json::to_vec(&state)?, before);
    Ok(())
}

#[test]
fn backend_metadata_is_namespace_scoped_and_independent_of_current_auth_mounts() -> TestResult {
    use super::super::EngineState;
    let mut engines = EngineState::default();
    engines.bind_login_identity("", "auth_same", "subject", 100)?;
    engines.bind_login_identity("other", "auth_same", "subject", 100)?;
    assert!(!engines.has_login_alias_metadata_state());
    engines.update_login_alias_metadata(
        "other",
        "auth_same",
        "subject",
        &metadata("other-role"),
        101,
    )?;
    assert!(engines.has_login_alias_metadata_state());
    let bytes = serde_json::to_vec(&engines)?;
    let mut reopened: EngineState = serde_json::from_slice(&bytes)?;
    reopened.validate_identity_alias_state()?;
    assert!(reopened.has_login_alias_metadata_state());
    // No auth registry is present or consulted: retained aliases alone require the reader gate.
    assert!(
        reopened
            .update_login_alias_metadata("absent", "auth_same", "subject", &metadata("bad"), 102)
            .is_err()
    );
    assert_eq!(serde_json::to_vec(&reopened)?, bytes);
    reopened.update_login_alias_metadata(
        "",
        "auth_same",
        "subject",
        &metadata("root-role"),
        102,
    )?;
    let value = serde_json::to_value(&reopened)?;
    let root_alias = value["namespaces"][""]["identity"]["aliases"]
        .as_object()
        .ok_or("root aliases")?
        .values()
        .next()
        .ok_or("root alias")?;
    let other_alias = value["namespaces"]["other"]["identity"]["aliases"]
        .as_object()
        .ok_or("other aliases")?
        .values()
        .next()
        .ok_or("other alias")?;
    assert_eq!(root_alias["login_metadata"], json!({"role":"root-role"}));
    assert_eq!(other_alias["login_metadata"], json!({"role":"other-role"}));
    Ok(())
}

#[test]
fn backend_metadata_extended_values_are_bounded_and_independently_format_detectable() -> TestResult
{
    let (mut state, entity, id) = fixture()?;
    assert!(!state.has_extended_login_metadata());
    let mut fields: BTreeMap<String, String> =
        (0..65).map(|i| (format!("key-{i}"), "v".into())).collect();
    fields.insert("".into(), "".into());
    fields.insert("k".repeat(129), "v".repeat(1025));
    fields.insert("unicode".into(), "名字\n\t".into());
    state.update_login_metadata("auth_jwt", "subject", &fields, 101)?;
    assert!(state.has_extended_login_metadata());
    assert!(state.aliases.get(&id).ok_or("alias")?.login_metadata == fields);
    let wire = serde_json::to_vec(&state)?;
    let reopened: IdentityState = serde_json::from_slice(&wire)?;
    reopened.validate_aliases()?;
    assert!(reopened.has_extended_login_metadata());
    assert!(serde_json::to_vec(&reopened)? == wire);
    // Administrator custom metadata retains its own stricter validation.
    assert!(
        handle(
            &mut state,
            "POST",
            &format!("identity/entity-alias/id/{id}"),
            &json!({"canonical_id":entity,"name":"subject","mount_accessor":"auth_jwt","custom_metadata":fields}),
            102
        )
        .is_err()
    );
    Ok(())
}

#[test]
fn fresh_backend_metadata_rules_do_not_restrict_existing_empty_alias_updates() -> TestResult {
    let invalid = [
        BTreeMap::from([("".into(), "v".into())]),
        BTreeMap::from([("vault-private".into(), "v".into())]),
        BTreeMap::from([("not.allowed".into(), "v".into())]),
        BTreeMap::from([("名字".into(), "v".into())]),
        BTreeMap::from([("k".repeat(129), "v".into())]),
        BTreeMap::from([("key".into(), "é".repeat(257))]),
        (0..65).map(|i| (format!("k{i}"), "v".into())).collect(),
    ];
    for metadata in invalid {
        let fresh = IdentityState::default();
        let before = serde_json::to_vec(&fresh)?;
        assert_eq!(
            fresh
                .validate_login_metadata_for_alias("auth_a", "subject", &metadata)
                .err()
                .ok_or("fresh metadata accepted")?
                .status,
            500
        );
        assert!(
            serde_json::to_vec(&fresh)? == before,
            "fresh rejection changed Identity"
        );
        let mut existing = IdentityState::default();
        existing.bind_login("auth_a", "subject", 100)?;
        let id = existing
            .alias_keys
            .get(&alias_key("auth_a", "subject"))
            .ok_or("alias")?
            .clone();
        // Represents an old alias created with no backend metadata. It must
        // count as existing despite the skipped/absent durable metadata field.
        let bytes = serde_json::to_vec(&existing)?;
        let value: Value = serde_json::from_slice(&bytes)?;
        assert!(value["aliases"][&id].get("login_metadata").is_none());
        let mut existing: IdentityState = serde_json::from_slice(&bytes)?;
        existing
            .aliases
            .get_mut(&id)
            .ok_or("alias")?
            .custom_metadata = Some(self::metadata("admin"));
        existing.validate_login_metadata_for_alias("auth_a", "subject", &metadata)?;
        existing.update_login_metadata("auth_a", "subject", &metadata, 101)?;
        assert_eq!(
            existing.aliases.get(&id).ok_or("alias")?.login_metadata,
            metadata
        );
        assert_eq!(
            existing.aliases.get(&id).ok_or("alias")?.custom_metadata,
            Some(self::metadata("admin"))
        );
        // Existence is keyed by both accessor and name, never by metadata size.
        assert_eq!(
            existing
                .validate_login_metadata_for_alias("auth_b", "subject", &metadata)
                .err()
                .ok_or("other mount treated as existing")?
                .status,
            500
        );
    }
    let mut boundary: BTreeMap<String, String> =
        (0..63).map(|i| (format!("k{i}"), "v".into())).collect();
    boundary.insert("k".repeat(128), "é".repeat(256));
    let fresh = IdentityState::default();
    fresh.validate_login_metadata_for_alias("auth_a", "subject", &boundary)?;
    fresh.validate_login_metadata_for_alias(
        "auth_a",
        "subject",
        &BTreeMap::from([
            ("AZaz09=/+_-".into(), "\0\n\t\r".into()),
            ("Vault-allowed".into(), "".into()),
        ]),
    )?;
    Ok(())
}

#[test]
fn fresh_metadata_check_rejects_inconsistent_alias_indexes_without_mutation() -> TestResult {
    let (mut state, _, id) = fixture()?;
    state.aliases.remove(&id);
    let before = serde_json::to_vec(&state)?;
    assert_eq!(
        state
            .validate_login_metadata_for_alias("auth_jwt", "subject", &metadata("safe"))
            .err()
            .ok_or("dangling index accepted")?
            .status,
        503
    );
    assert!(
        serde_json::to_vec(&state)? == before,
        "index rejection changed Identity"
    );
    let (mut state, _, _) = fixture()?;
    state.alias_keys.clear();
    assert_eq!(
        state
            .validate_login_metadata_for_alias("auth_jwt", "subject", &metadata("safe"))
            .err()
            .ok_or("unindexed alias accepted")?
            .status,
        503
    );
    Ok(())
}
