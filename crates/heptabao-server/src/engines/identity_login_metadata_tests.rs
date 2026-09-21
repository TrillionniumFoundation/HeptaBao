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
    state.aliases.get_mut(&id).ok_or("alias")?.custom_metadata = metadata("user-maintained");
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
    assert_eq!(alias.custom_metadata, metadata("user-maintained"));
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
        BTreeMap::from([("note".into(), "changed".into())])
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
        BTreeMap::from([("".into(), "bad".into())]),
        metadata("bad\nvalue"),
        metadata(&"x".repeat(MAX_METADATA_VALUE_BYTES + 1)),
        (0..=MAX_METADATA_ENTRIES)
            .map(|i| (format!("k{i}"), "v".into()))
            .collect(),
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
