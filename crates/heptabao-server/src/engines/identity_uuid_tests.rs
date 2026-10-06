use super::*;

fn native_uuid(id: &str) -> bool {
    let bytes = id.as_bytes();
    bytes.len() == 36
        && bytes[14] == b'4'
        && matches!(bytes[19], b'8' | b'9' | b'a' | b'b')
        && bytes.iter().enumerate().all(|(index, byte)| {
            if matches!(index, 8 | 13 | 18 | 23) {
                *byte == b'-'
            } else {
                byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase()
            }
        })
}

#[test]
fn identity_new_entity_alias_group_and_group_alias_use_native_uuid() -> Result<()> {
    let mut state = IdentityState::default();
    let entity = handle(
        &mut state,
        "POST",
        "identity/entity",
        &json!({"name":"native-uuid-entity"}),
        100,
    )?;
    let entity_id = entity.body["data"]["id"].as_str().ok_or_else(not_found)?;
    let alias = handle(
        &mut state,
        "POST",
        "identity/entity-alias",
        &json!({"name":"native-uuid-alias","canonical_id":entity_id,"mount_accessor":"auth_test"}),
        100,
    )?;
    let group = handle(
        &mut state,
        "POST",
        "identity/group",
        &json!({"name":"native-uuid-group","type":"external"}),
        100,
    )?;
    let group_id = group.body["data"]["id"].as_str().ok_or_else(not_found)?;
    let group_alias = handle(
        &mut state,
        "POST",
        "identity/group-alias",
        &json!({"name":"native-uuid-group-alias","canonical_id":group_id,"mount_accessor":"auth_test"}),
        100,
    )?;
    let ids = [&entity, &alias, &group, &group_alias]
        .into_iter()
        .map(|response| response.body["data"]["id"].as_str().ok_or_else(not_found))
        .collect::<Result<Vec<_>>>()?;
    assert!(ids.iter().all(|id| native_uuid(id)));
    assert_eq!(ids.iter().copied().collect::<BTreeSet<_>>().len(), 4);
    assert_eq!(state.next_id, 4);
    let encoded = serde_json::to_vec(&state).map_err(|_| bad("serialize identity"))?;
    let mut reopened: IdentityState =
        serde_json::from_slice(&encoded).map_err(|_| bad("reopen identity"))?;
    for (kind, id) in ["entity", "entity-alias", "group", "group-alias"]
        .into_iter()
        .zip(ids)
    {
        let response = handle(
            &mut reopened,
            "GET",
            &format!("identity/{kind}/id/{id}"),
            &json!({}),
            101,
        )?;
        assert_eq!(response.body["data"]["id"], id);
    }
    Ok(())
}

#[test]
fn identity_legacy_entity_and_alias_bindings_survive_reopen_and_new_uuid_allocation() -> Result<()>
{
    let mut state = IdentityState::default();
    let binding = state.bind_login("auth_test", "legacy", 100)?;
    let alias_id = state
        .alias_keys
        .get(&alias_key("auth_test", "legacy"))
        .ok_or_else(not_found)?
        .clone();
    let legacy = "e-00000000000000000000000000000001";
    let mut entity = state
        .entities
        .remove(&binding.entity_id)
        .ok_or_else(not_found)?;
    entity.id = legacy.to_owned();
    state
        .entity_names
        .insert(entity.name.clone(), legacy.to_owned());
    state.entities.insert(legacy.to_owned(), entity);
    state
        .aliases
        .get_mut(&alias_id)
        .ok_or_else(not_found)?
        .canonical_id = legacy.to_owned();
    let encoded = serde_json::to_vec(&state).map_err(|_| bad("serialize identity"))?;
    let mut reopened: IdentityState =
        serde_json::from_slice(&encoded).map_err(|_| bad("reopen identity"))?;
    assert_eq!(
        reopened.bind_login("auth_test", "legacy", 101)?.entity_id,
        legacy
    );
    assert_eq!(
        reopened.alias_keys.get(&alias_key("auth_test", "legacy")),
        Some(&alias_id)
    );
    let fresh = reopened.bind_login("auth_test", "fresh", 101)?.entity_id;
    assert!(native_uuid(&fresh));
    assert_ne!(fresh, legacy);
    assert_eq!(
        reopened.bind_login("auth_test", "legacy", 102)?.entity_id,
        legacy
    );
    assert_eq!(
        reopened.bind_login("auth_test", "fresh", 102)?.entity_id,
        fresh
    );
    assert_eq!(reopened.next_id, 4);
    Ok(())
}

#[test]
fn identity_uuid_allocation_rejects_rolled_back_frontier_without_mutation() -> Result<()> {
    let mut state = IdentityState::default();
    state.bind_login("auth_test", "existing", 100)?;
    state.next_id = 0;
    let before = serde_json::to_vec(&state).map_err(|_| bad("serialize identity"))?;
    assert!(state.bind_login("auth_test", "next", 101).is_err());
    assert_eq!(
        serde_json::to_vec(&state).map_err(|_| bad("serialize identity"))?,
        before
    );
    Ok(())
}
