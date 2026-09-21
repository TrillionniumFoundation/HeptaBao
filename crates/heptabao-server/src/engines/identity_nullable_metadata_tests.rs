use super::*;

// Historical format fixtures created via current login APIs must restore the
// old administrative {} representation before testing their earlier gate.
// Keep all identities, indexes, nonempty maps and backend metadata unchanged.
impl super::super::EngineState {
    pub(crate) fn restore_pre47_identity_metadata_for_test(&mut self) {
        for namespace in self.namespaces.values_mut() {
            for entity in namespace.identity.entities.values_mut() {
                entity.metadata.get_or_insert_with(BTreeMap::new);
            }
            for group in namespace.identity.groups.values_mut() {
                group.metadata.get_or_insert_with(BTreeMap::new);
            }
            for alias in namespace.identity.aliases.values_mut() {
                alias.custom_metadata.get_or_insert_with(BTreeMap::new);
            }
        }
        assert!(!self.has_nullable_identity_metadata_state());
    }
}

type TestResult = std::result::Result<(), Box<dyn std::error::Error>>;

const OLD_ENTITY: &[u8] = br#"{"id":"e-old","name":"old","disabled":false,"metadata":{},"policies":[],"aliases":[],"group_ids":[],"merged_entity_ids":[],"created_at":1,"updated_at":1}"#;
const OLD_GROUP: &[u8] = br#"{"id":"g-old","name":"old","kind":"internal","metadata":{},"policies":[],"member_entity_ids":[],"member_group_ids":[],"created_at":1,"updated_at":1}"#;
const OLD_ALIAS: &[u8] = br#"{"id":"a-old","canonical_id":"e-old","name":"old","mount_accessor":"auth_old","custom_metadata":{},"created_at":1,"updated_at":1}"#;

fn alias_fixture() -> Result<(IdentityState, String, String)> {
    let mut state = IdentityState::default();
    let entity = state.bind_login("auth_test", "subject", 100)?.entity_id;
    let id = state
        .alias_keys
        .get(&alias_key("auth_test", "subject"))
        .ok_or_else(|| bad("missing alias"))?
        .clone();
    Ok((state, entity, id))
}

#[test]
fn historical_empty_object_bytes_and_legacy_alias_name_are_preserved() -> TestResult {
    let entity: Entity = serde_json::from_slice(OLD_ENTITY)?;
    let group: Group = serde_json::from_slice(OLD_GROUP)?;
    let alias: Alias = serde_json::from_slice(OLD_ALIAS)?;
    assert_eq!(serde_json::to_vec(&entity)?, OLD_ENTITY);
    assert_eq!(serde_json::to_vec(&group)?, OLD_GROUP);
    assert_eq!(serde_json::to_vec(&alias)?, OLD_ALIAS);
    assert_eq!(entity.metadata, Some(BTreeMap::new()));
    assert_eq!(group.metadata, Some(BTreeMap::new()));
    assert_eq!(alias.custom_metadata, Some(BTreeMap::new()));
    let historical = std::str::from_utf8(OLD_ALIAS)?.replace("custom_metadata", "metadata");
    let alias: Alias = serde_json::from_str(&historical)?;
    assert_eq!(alias.custom_metadata, Some(BTreeMap::new()));
    assert!(alias.login_metadata.is_empty());
    let missing = std::str::from_utf8(OLD_ALIAS)?.replace("\"custom_metadata\":{},", "");
    let alias: Alias = serde_json::from_str(&missing)?;
    assert_eq!(
        alias.custom_metadata,
        Some(BTreeMap::new()),
        "preserve the old missing-field default"
    );
    Ok(())
}

#[test]
fn login_creates_native_null_admin_metadata_without_changing_backend_map() -> TestResult {
    let (state, entity, id) = alias_fixture()?;
    assert!(state.entities[&entity].metadata.is_none());
    assert!(state.aliases[&id].custom_metadata.is_none());
    assert_eq!(
        entity_data(&state, &state.entities[&entity])["metadata"],
        Value::Null
    );
    assert_eq!(
        alias_data(&state.aliases[&id])["custom_metadata"],
        Value::Null
    );
    assert_eq!(alias_data(&state.aliases[&id])["metadata"], json!({}));
    assert!(state.has_nullable_metadata());
    let bytes = serde_json::to_vec(&state)?;
    let reopened: IdentityState = serde_json::from_slice(&bytes)?;
    reopened.validate_aliases()?;
    assert_eq!(serde_json::to_vec(&reopened)?, bytes);
    assert!(reopened.has_nullable_metadata());
    let mut engines = super::super::EngineState::default();
    assert!(!engines.has_nullable_identity_metadata_state());
    engines.bind_login_identity("other", "auth_test", "subject", 100)?;
    assert!(engines.has_nullable_identity_metadata_state());
    Ok(())
}

#[test]
fn entity_and_group_updates_distinguish_omitted_null_and_empty_object() -> TestResult {
    for kind in ["entity", "group"] {
        let mut state = IdentityState::default();
        let created = handle(
            &mut state,
            "POST",
            &format!("identity/{kind}"),
            &json!({"name":"item"}),
            100,
        )?;
        let id = created.body["data"]["id"].as_str().ok_or("missing id")?;
        let path = format!("identity/{kind}/id/{id}");
        let initial = handle(&mut state, "GET", &path, &json!({}), 100)?;
        assert_eq!(initial.body["data"]["metadata"], Value::Null);
        for (index, metadata) in [
            json!({}),
            Value::Null,
            json!({"admin":"value"}),
            json!({}),
            json!({"admin":"value"}),
            Value::Null,
        ]
        .into_iter()
        .enumerate()
        {
            handle(
                &mut state,
                "POST",
                &path,
                &json!({"metadata":metadata}),
                101 + index as u64,
            )?;
            let current = handle(&mut state, "GET", &path, &json!({}), 110)?;
            assert_eq!(current.body["data"]["metadata"], metadata, "{kind}");
            handle(&mut state, "POST", &path, &json!({"name":"item"}), 111)?;
            let current = handle(&mut state, "GET", &path, &json!({}), 112)?;
            assert_eq!(
                current.body["data"]["metadata"], metadata,
                "omitted preserves {kind}"
            );
        }
    }
    Ok(())
}

#[test]
fn alias_equal_empty_updates_are_noops_but_nonempty_clears_preserve_shape() -> TestResult {
    let (mut state, entity, id) = alias_fixture()?;
    let path = format!("identity/entity-alias/id/{id}");
    let base = json!({"canonical_id":entity,"name":"subject","mount_accessor":"auth_test"});
    for metadata in [json!({}), Value::Null] {
        let mut body = base.clone();
        body["custom_metadata"] = metadata;
        let before = serde_json::to_vec(&state)?;
        let response = handle(&mut state, "POST", &path, &body, 101)?;
        assert_eq!(response.status, 204);
        assert!(!response.mutated);
        assert_eq!(serde_json::to_vec(&state)?, before);
    }
    for clear in [json!({}), Value::Null] {
        let mut body = base.clone();
        body["custom_metadata"] = json!({"owner":"admin"});
        handle(&mut state, "POST", &path, &body, 102)?;
        let before = serde_json::to_vec(&state)?;
        assert_eq!(handle(&mut state, "POST", &path, &base, 103)?.status, 204);
        assert_eq!(
            serde_json::to_vec(&state)?,
            before,
            "omitted retains nonempty custom metadata"
        );
        body["custom_metadata"] = clear.clone();
        handle(&mut state, "POST", &path, &body, 104)?;
        assert_eq!(alias_data(&state.aliases[&id])["custom_metadata"], clear);
        let bytes = serde_json::to_vec(&state)?;
        let reopened: IdentityState = serde_json::from_slice(&bytes)?;
        assert_eq!(
            serde_json::to_vec(&reopened)?,
            bytes,
            "candidate durable shape is retained; not a claim about native protobuf cold normalization"
        );
        body["custom_metadata"] = if clear.is_null() {
            json!({})
        } else {
            Value::Null
        };
        assert_eq!(handle(&mut state, "POST", &path, &body, 105)?.status, 204);
        assert_eq!(
            serde_json::to_vec(&state)?,
            bytes,
            "nil and empty compare equal without changing representation"
        );
    }
    Ok(())
}

#[test]
fn canonical_only_alias_move_retains_nil_while_name_change_can_set_empty() -> TestResult {
    let (mut state, _, id) = alias_fixture()?;
    let created = handle(
        &mut state,
        "POST",
        "identity/entity",
        &json!({"name":"target"}),
        101,
    )?;
    let entity = created.body["data"]["id"].as_str().ok_or("missing id")?;
    let path = format!("identity/entity-alias/id/{id}");
    let mut body = json!({"canonical_id":entity,"name":"subject","mount_accessor":"auth_test","custom_metadata":{}});
    handle(&mut state, "POST", &path, &body, 102)?;
    assert_eq!(
        alias_data(&state.aliases[&id])["custom_metadata"],
        Value::Null
    );
    body["name"] = json!("renamed");
    handle(&mut state, "POST", &path, &body, 103)?;
    assert_eq!(
        alias_data(&state.aliases[&id])["custom_metadata"],
        json!({})
    );
    state.validate_aliases()?;
    Ok(())
}

#[test]
fn nullable_predicate_detects_each_owner_independently_and_invalid_updates_are_atomic() -> TestResult
{
    let mut state = IdentityState::default();
    state
        .entities
        .insert("e-old".into(), serde_json::from_slice(OLD_ENTITY)?);
    state
        .groups
        .insert("g-old".into(), serde_json::from_slice(OLD_GROUP)?);
    state
        .aliases
        .insert("a-old".into(), serde_json::from_slice(OLD_ALIAS)?);
    assert!(!state.has_nullable_metadata());
    state.entities.get_mut("e-old").ok_or("entity")?.metadata = None;
    assert!(state.has_nullable_metadata());
    state.entities.get_mut("e-old").ok_or("entity")?.metadata = Some(BTreeMap::new());
    state.groups.get_mut("g-old").ok_or("group")?.metadata = None;
    assert!(state.has_nullable_metadata());
    state.groups.get_mut("g-old").ok_or("group")?.metadata = Some(BTreeMap::new());
    state
        .aliases
        .get_mut("a-old")
        .ok_or("alias")?
        .custom_metadata = None;
    assert!(state.has_nullable_metadata());
    for value in [
        json!([]),
        json!(false),
        json!({"bad":1}),
        json!({"":"bad"}),
        json!({"bad":"\n"}),
    ] {
        let before = serde_json::to_vec(&state)?;
        assert!(
            handle(
                &mut state,
                "POST",
                "identity/entity/id/e-old",
                &json!({"metadata":value}),
                102
            )
            .is_err()
        );
        assert_eq!(serde_json::to_vec(&state)?, before);
    }
    Ok(())
}
