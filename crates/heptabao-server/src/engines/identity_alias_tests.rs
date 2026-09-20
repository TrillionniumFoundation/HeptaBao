//! Opaque provider names keep exact index bytes across API writes and reopen.
use super::*;

fn id(response: &EngineResponse) -> Result<String> {
    response.body["data"]["id"]
        .as_str()
        .map(str::to_owned)
        .ok_or_else(|| bad("missing test id"))
}
fn reopen(state: &IdentityState) -> Result<IdentityState> {
    let encoded = serde_json::to_vec(state).map_err(|_| bad("test encoding failed"))?;
    let reopened: IdentityState =
        serde_json::from_slice(&encoded).map_err(|_| bad("test decoding failed"))?;
    reopened.validate_aliases()?;
    assert_eq!(
        serde_json::to_vec(&reopened).map_err(|_| bad("test encoding failed"))?,
        encoded
    );
    Ok(reopened)
}

#[test]
fn opaque_entity_alias_create_update_lookup_login_and_reopen() -> Result<()> {
    let mut state = IdentityState::default();
    let entity = id(&handle(
        &mut state,
        "POST",
        "identity/entity",
        &json!({"name":"person"}),
        100,
    )?)?;
    let name = "研发 / Case Person:组织";
    let alias = id(&handle(
        &mut state,
        "POST",
        "identity/entity-alias",
        &json!({"name":name,"canonical_id":entity,"mount_accessor":"auth_ldap"}),
        101,
    )?)?;
    assert_eq!(state.bind_login("auth_ldap", name, 102)?.entity_id, entity);
    let lookup = handle(
        &mut state,
        "POST",
        "identity/lookup/entity",
        &json!({"alias_name":name,"alias_mount_accessor":"auth_ldap"}),
        103,
    )?;
    assert_eq!(lookup.body["data"]["id"], entity);
    assert!(state.has_opaque_aliases());
    let mut state = reopen(&state)?;
    assert_eq!(state.bind_login("auth_ldap", name, 104)?.entity_id, entity);
    state.verify_external_identity(&entity, "auth_ldap", name)?;
    let renamed = "  Person / New 姓名  ";
    handle(
        &mut state,
        "POST",
        &format!("identity/entity-alias/id/{alias}"),
        &json!({"name":renamed,"canonical_id":entity,"mount_accessor":"auth_ldap"}),
        105,
    )?;
    assert!(!state.alias_keys.contains_key(&alias_key("auth_ldap", name)));
    assert_eq!(
        state.alias_keys.get(&alias_key("auth_ldap", renamed)),
        Some(&alias)
    );
    assert!(
        state
            .verify_external_identity(&entity, "auth_ldap", name)
            .is_err()
    );
    let mut state = reopen(&state)?;
    assert_eq!(
        state.bind_login("auth_ldap", renamed, 106)?.entity_id,
        entity
    );
    let other = state.bind_login("auth_other", renamed, 107)?.entity_id;
    assert_ne!(other, entity, "opaque names remain mount-scoped");
    Ok(())
}

#[test]
fn opaque_group_alias_preserves_provider_evidence_and_rename_retracts_it() -> Result<()> {
    let mut state = IdentityState::default();
    let entity = state.bind_login("auth_ldap", "Case Person", 100)?.entity_id;
    let group = id(&handle(
        &mut state,
        "POST",
        "identity/group",
        &json!({"name":"engineering","type":"external","policies":["directory"]}),
        100,
    )?)?;
    let name = "研发 / Engineering Team";
    let alias = id(&handle(
        &mut state,
        "POST",
        "identity/group-alias",
        &json!({"name":name,"canonical_id":group,"mount_accessor":"auth_ldap"}),
        100,
    )?)?;
    let groups = BTreeSet::from([name.to_owned()]);
    assert!(
        state
            .refresh_external_groups(&entity, "auth_ldap", &groups, 101)?
            .policies
            .contains("directory")
    );
    let mut state = reopen(&state)?;
    assert!(state.project(&entity)?.policies.contains("directory"));
    let lookup = handle(
        &mut state,
        "POST",
        "identity/lookup/group",
        &json!({"alias_name":name,"alias_mount_accessor":"auth_ldap"}),
        102,
    )?;
    assert_eq!(lookup.body["data"]["id"], group);
    handle(
        &mut state,
        "POST",
        &format!("identity/group-alias/id/{alias}"),
        &json!({"name":"New Engineering Team","canonical_id":group,"mount_accessor":"auth_ldap"}),
        103,
    )?;
    assert!(
        !state
            .group_alias_keys
            .contains_key(&alias_key("auth_ldap", name))
    );
    assert!(state.project(&entity)?.policies.is_empty());
    let mut state = reopen(&state)?;
    let groups = BTreeSet::from(["New Engineering Team".to_owned()]);
    assert!(
        state
            .refresh_external_groups(&entity, "auth_ldap", &groups, 104)?
            .policies
            .contains("directory")
    );
    // LDAP observations keep their existing 256-byte-per-group authority bound.
    assert!(
        state
            .refresh_external_groups(
                &entity,
                "auth_ldap",
                &BTreeSet::from(["x".repeat(257)]),
                105
            )
            .is_err()
    );
    Ok(())
}

#[test]
fn opaque_alias_bounds_do_not_relax_internal_names_or_index_integrity() -> Result<()> {
    let mut state = IdentityState::default();
    let maximum = "名".repeat(341) + "x";
    assert_eq!(maximum.len(), 1024);
    let entity = state.bind_login("auth_ldap", &maximum, 100)?.entity_id;
    state.validate_aliases()?;
    let group = id(&handle(
        &mut state,
        "POST",
        "identity/group",
        &json!({"name":"group","type":"external"}),
        100,
    )?)?;
    handle(
        &mut state,
        "POST",
        "identity/group-alias",
        &json!({"name":maximum,"canonical_id":group,"mount_accessor":"auth_ldap"}),
        100,
    )?;
    state = reopen(&state)?;
    for invalid in [
        String::new(),
        "a\0b".into(),
        "line\nbreak".into(),
        "x".repeat(1025),
    ] {
        let before = serde_json::to_vec(&state).map_err(|_| bad("test encode"))?;
        assert!(state.bind_login("auth_ldap", &invalid, 101).is_err());
        assert!(
            handle(
                &mut state,
                "POST",
                "identity/entity-alias",
                &json!({"name":invalid,"canonical_id":entity,"mount_accessor":"auth_other"}),
                101
            )
            .is_err()
        );
        assert!(
            handle(
                &mut state,
                "POST",
                "identity/lookup/entity",
                &json!({"alias_name":invalid,"alias_mount_accessor":"auth_ldap"}),
                101
            )
            .is_err()
        );
        assert_eq!(
            serde_json::to_vec(&state).map_err(|_| bad("test encode"))?,
            before
        );
    }
    for path in ["identity/entity", "identity/group"] {
        assert!(
            handle(
                &mut state,
                "POST",
                path,
                &json!({"name":"Internal Name"}),
                102
            )
            .is_err()
        );
    }
    assert!(state.bind_login("auth bad", "Case Person", 102).is_err());
    let mut missing_index = state.clone();
    missing_index.alias_keys.clear();
    assert!(missing_index.validate_aliases().is_err());
    let mut extra_index = state.clone();
    extra_index
        .alias_keys
        .insert("auth_ldap\0wrong".into(), "missing".into());
    assert!(extra_index.validate_aliases().is_err());
    let mut replaced_index = state.clone();
    let key = alias_key("auth_ldap", &maximum);
    replaced_index.alias_keys.insert(key, "missing".into());
    assert!(replaced_index.validate_aliases().is_err());
    let mut ordinary = IdentityState::default();
    ordinary.bind_login("auth_ldap", "alice@example.test", 100)?;
    assert!(!ordinary.has_opaque_aliases());
    assert!(!reopen(&ordinary)?.has_opaque_aliases());
    IdentityState::default().validate_aliases()?;
    Ok(())
}
