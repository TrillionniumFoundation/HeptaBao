use super::*;
use crate::engines::EngineState;

fn id(response: EngineResponse) -> Result<String> {
    response.body["data"]["id"]
        .as_str()
        .map(str::to_owned)
        .ok_or_else(not_found)
}

fn external(state: &mut IdentityState, name: &str, accessor: &str) -> Result<(String, String)> {
    let group = id(upsert_group(
        state,
        None,
        &json!({"name":name,"type":"external","policies":[name]}),
        100,
    )?)?;
    let alias = id(upsert_group_alias(
        state,
        None,
        &json!({"canonical_id":group,"mount_accessor":accessor,"name":"engineering"}),
        100,
    )?)?;
    Ok((group, alias))
}

fn names() -> BTreeSet<String> {
    BTreeSet::from(["engineering".into()])
}

fn encoded(state: &IdentityState) -> Result<Vec<u8>> {
    serde_json::to_vec(state).map_err(|_| bad("serialization failed"))
}

#[test]
fn external_observation_updates_both_indexes_and_preserves_other_mount_and_live_ancestors()
-> Result<()> {
    let mut state = IdentityState::default();
    let entity = state.bind_login("auth_one", "alice", 100)?.entity_id;
    upsert_alias(
        &mut state,
        None,
        &json!({"canonical_id":entity,"name":"alice","mount_accessor":"auth_two"}),
        100,
    )?;
    let (first, _) = external(&mut state, "first-policy", "auth_one")?;
    let (second, _) = external(&mut state, "second-policy", "auth_two")?;
    let parent = id(upsert_group(
        &mut state,
        None,
        &json!({"name":"parent","policies":["parent-policy"],"member_group_ids":[first]}),
        100,
    )?)?;
    assert!(state.project(&entity)?.policies.is_empty());
    state.refresh_external_groups(&entity, "auth_one", &names(), 101)?;
    let projection = state.refresh_external_groups(&entity, "auth_two", &names(), 102)?;
    assert_eq!(
        projection.policies,
        BTreeSet::from([
            "first-policy".into(),
            "second-policy".into(),
            "parent-policy".into()
        ])
    );
    assert!(state.groups[&first].member_entity_ids.contains(&entity));
    assert!(state.entities[&entity].group_ids.contains(&first));
    // Group policy changes apply immediately, without a new directory request.
    upsert_group(
        &mut state,
        Some(&parent),
        &json!({"policies":["new-parent-policy"]}),
        103,
    )?;
    assert!(
        state
            .project(&entity)?
            .policies
            .contains("new-parent-policy")
    );
    assert!(!state.project(&entity)?.policies.contains("parent-policy"));
    let restored: IdentityState =
        serde_json::from_slice(&encoded(&state)?).map_err(|_| bad("decode"))?;
    assert_eq!(
        restored.project(&entity)?.policies,
        state.project(&entity)?.policies
    );
    let projection = state.refresh_external_groups(&entity, "auth_one", &BTreeSet::new(), 104)?;
    assert_eq!(
        projection.policies,
        BTreeSet::from(["second-policy".into()])
    );
    assert!(!state.groups[&first].member_entity_ids.contains(&entity));
    assert!(!state.entities[&entity].group_ids.contains(&first));
    assert!(state.groups[&second].member_entity_ids.contains(&entity));
    state.revoke_external_groups("auth_two", 105)?;
    assert!(state.project(&entity)?.policies.is_empty());
    assert!(!state.groups[&second].member_entity_ids.contains(&entity));
    assert!(!state.entities[&entity].group_ids.contains(&second));
    assert!(!state.has_external_groups());
    Ok(())
}

#[test]
fn manual_external_members_never_authorize_and_provider_refresh_reconciles_legacy_indexes()
-> Result<()> {
    let mut state = IdentityState::default();
    let entity = state.bind_login("auth_one", "alice", 100)?.entity_id;
    let (group, _) = external(&mut state, "restricted", "auth_one")?;
    let before = encoded(&state)?;
    assert!(
        upsert_group(
            &mut state,
            Some(&group),
            &json!({"member_entity_ids":[entity]}),
            101
        )
        .is_err()
    );
    assert_eq!(encoded(&state)?, before);
    // Simulate the pre-schema-17 persisted shape, which allowed arbitrary members.
    state
        .groups
        .get_mut(&group)
        .ok_or_else(not_found)?
        .member_entity_ids
        .insert(entity.clone());
    state
        .entities
        .get_mut(&entity)
        .ok_or_else(not_found)?
        .group_ids
        .insert(group.clone());
    assert!(state.project(&entity)?.policies.is_empty());
    assert!(!state.has_external_groups());
    state.refresh_external_groups(&entity, "auth_one", &BTreeSet::new(), 102)?;
    assert!(!state.groups[&group].member_entity_ids.contains(&entity));
    assert!(!state.entities[&entity].group_ids.contains(&group));
    state.refresh_external_groups(&entity, "auth_one", &names(), 103)?;
    assert!(state.project(&entity)?.policies.contains("restricted"));
    Ok(())
}

#[test]
fn alias_rebinding_deletion_and_aba_cannot_reuse_external_evidence() -> Result<()> {
    for mutation in [
        "group-rebind",
        "group-delete",
        "entity-rebind",
        "entity-delete",
        "group-record-delete",
    ] {
        let mut state = IdentityState::default();
        let entity = state.bind_login("auth_one", "alice", 100)?.entity_id;
        let other = state.bind_login("auth_two", "bob", 100)?.entity_id;
        let entity_alias = state.entities[&entity]
            .aliases
            .iter()
            .next()
            .ok_or_else(not_found)?
            .clone();
        let (group, group_alias) = external(&mut state, "grant", "auth_one")?;
        let other_group = id(upsert_group(
            &mut state,
            None,
            &json!({"name":"other","type":"external","policies":["other-policy"]}),
            100,
        )?)?;
        state.refresh_external_groups(&entity, "auth_one", &names(), 101)?;
        match mutation {
            "group-rebind" => {
                upsert_group_alias(
                    &mut state,
                    Some(&group_alias),
                    &json!({"canonical_id":other_group,"mount_accessor":"auth_one","name":"engineering"}),
                    102,
                )?;
                upsert_group_alias(
                    &mut state,
                    Some(&group_alias),
                    &json!({"canonical_id":group,"mount_accessor":"auth_one","name":"engineering"}),
                    103,
                )?;
            }
            "group-delete" => {
                handle_group_alias_id(&mut state, "DELETE", &group_alias, &json!({}), 102)?;
            }
            "entity-rebind" => {
                upsert_alias(
                    &mut state,
                    Some(&entity_alias),
                    &json!({"canonical_id":other,"mount_accessor":"auth_one","name":"alice"}),
                    102,
                )?;
                upsert_alias(
                    &mut state,
                    Some(&entity_alias),
                    &json!({"canonical_id":entity,"mount_accessor":"auth_one","name":"alice"}),
                    103,
                )?;
            }
            "entity-delete" => {
                handle_alias_id(&mut state, "DELETE", &entity_alias, &json!({}), 102)?;
            }
            "group-record-delete" => {
                handle_group_id(&mut state, "DELETE", &group, &json!({}), 102)?;
            }
            _ => return Err(bad("unknown mutation")),
        }
        assert!(state.project(&entity)?.policies.is_empty(), "{mutation}");
        assert!(state.project(&other)?.policies.is_empty(), "{mutation}");
        assert!(
            !state.entities[&entity].group_ids.contains(&group),
            "{mutation}"
        );
    }
    Ok(())
}

#[test]
fn external_refresh_failures_are_atomic_and_disabled_or_deleted_entities_fail_closed() -> Result<()>
{
    for mutation in [
        "disabled",
        "missing-alias-index",
        "missing-group-index",
        "root-policy",
        "cycle",
        "oversized-observation",
    ] {
        let mut state = IdentityState::default();
        let entity = state.bind_login("auth_one", "alice", 100)?.entity_id;
        let (group, _) = external(&mut state, "grant", "auth_one")?;
        let mut observed = names();
        match mutation {
            "disabled" => {
                state
                    .entities
                    .get_mut(&entity)
                    .ok_or_else(not_found)?
                    .disabled = true;
            }
            "missing-alias-index" => state.alias_keys.clear(),
            "missing-group-index" => state.group_alias_keys.clear(),
            "root-policy" => {
                state
                    .groups
                    .get_mut(&group)
                    .ok_or_else(not_found)?
                    .policies
                    .insert("root".into());
            }
            "cycle" => {
                let parent = id(upsert_group(
                    &mut state,
                    None,
                    &json!({"name":"parent","member_group_ids":[group]}),
                    100,
                )?)?;
                state
                    .groups
                    .get_mut(&parent)
                    .ok_or_else(not_found)?
                    .member_group_ids
                    .insert(parent.clone());
            }
            "oversized-observation" => {
                observed.insert("x".repeat(257));
            }
            _ => return Err(bad("unknown mutation")),
        }
        let before = encoded(&state)?;
        assert!(
            state
                .refresh_external_groups(&entity, "auth_one", &observed, 101)
                .is_err(),
            "{mutation}"
        );
        assert_eq!(encoded(&state)?, before, "{mutation}");
    }
    let mut state = IdentityState::default();
    let entity = state.bind_login("auth_one", "alice", 100)?.entity_id;
    let (group, _) = external(&mut state, "grant", "auth_one")?;
    state.refresh_external_groups(&entity, "auth_one", &names(), 101)?;
    handle_entity_id(&mut state, "DELETE", &entity, &json!({}), 102)?;
    assert!(state.project(&entity).is_err());
    assert!(
        state
            .refresh_external_groups(&entity, "auth_one", &names(), 103)
            .is_err()
    );
    assert!(!state.groups[&group].member_entity_ids.contains(&entity));
    assert!(!state.has_external_groups());
    Ok(())
}

#[test]
fn external_membership_is_namespace_scoped_and_merge_requires_fresh_provider_observation()
-> Result<()> {
    let mut engine = EngineState::default();
    let root_entity = engine
        .bind_login_identity("", "auth_one", "alice", 100)?
        .entity_id;
    let other_entity = engine
        .bind_login_identity("other", "auth_one", "alice", 100)?
        .entity_id;
    for namespace in ["", "other"] {
        external(
            &mut engine
                .namespaces
                .get_mut(namespace)
                .ok_or_else(not_found)?
                .identity,
            "grant",
            "auth_one",
        )?;
    }
    engine.refresh_external_group_membership("", &root_entity, "auth_one", &names(), 101)?;
    assert!(
        engine
            .identity_projection("", &root_entity)?
            .policies
            .contains("grant")
    );
    assert!(
        engine
            .identity_projection("other", &other_entity)?
            .policies
            .is_empty()
    );
    assert!(
        engine
            .refresh_external_group_membership("absent", &root_entity, "auth_one", &names(), 101)
            .is_err()
    );
    engine.revoke_external_group_membership("other", "auth_one", 102)?;
    assert!(
        engine
            .identity_projection("", &root_entity)?
            .policies
            .contains("grant")
    );
    let state = &mut engine
        .namespaces
        .get_mut("")
        .ok_or_else(not_found)?
        .identity;
    let destination = state.bind_login("auth_two", "bob", 100)?.entity_id;
    handle_entity_merge(
        state,
        "POST",
        &json!({"from_entity_ids":[root_entity],"to_entity_id":destination}),
        103,
    )?;
    assert!(state.project(&root_entity)?.policies.is_empty());
    assert!(state.project(&destination)?.policies.is_empty());
    state.refresh_external_groups(&root_entity, "auth_one", &names(), 104)?;
    assert!(state.project(&destination)?.policies.contains("grant"));
    state.verify_external_identity(&root_entity, "auth_one", "alice")?;
    Ok(())
}

#[test]
fn provider_username_must_still_match_the_current_alias_before_refresh() -> Result<()> {
    let mut engine = EngineState::default();
    let entity = engine
        .bind_login_identity("", "auth_one", "alice", 100)?
        .entity_id;
    engine.verify_external_group_identity("", &entity, "auth_one", "alice")?;
    let state = &mut engine
        .namespaces
        .get_mut("")
        .ok_or_else(not_found)?
        .identity;
    let alias = state.entities[&entity]
        .aliases
        .iter()
        .next()
        .ok_or_else(not_found)?
        .clone();
    upsert_alias(
        state,
        Some(&alias),
        &json!({"canonical_id":entity,"name":"renamed","mount_accessor":"auth_one"}),
        101,
    )?;
    assert!(
        engine
            .verify_external_group_identity("", &entity, "auth_one", "alice")
            .is_err()
    );
    assert!(
        engine
            .verify_external_group_identity("", &entity, "auth_two", "renamed")
            .is_err()
    );
    assert!(
        engine
            .verify_external_group_identity("other", &entity, "auth_one", "renamed")
            .is_err()
    );
    engine.verify_external_group_identity("", &entity, "auth_one", "renamed")?;
    Ok(())
}

#[test]
fn multiple_mounts_may_attest_the_same_group_without_clearing_each_other() -> Result<()> {
    let mut state = IdentityState::default();
    let entity = state.bind_login("auth_one", "alice", 100)?.entity_id;
    upsert_alias(
        &mut state,
        None,
        &json!({"canonical_id":entity,"name":"alice","mount_accessor":"auth_two"}),
        100,
    )?;
    let (group, _) = external(&mut state, "shared-policy", "auth_one")?;
    upsert_group_alias(
        &mut state,
        None,
        &json!({"canonical_id":group,"mount_accessor":"auth_two","name":"engineering"}),
        100,
    )?;
    state.refresh_external_groups(&entity, "auth_one", &names(), 101)?;
    state.refresh_external_groups(&entity, "auth_two", &names(), 102)?;
    state.refresh_external_groups(&entity, "auth_one", &BTreeSet::new(), 103)?;
    assert!(state.project(&entity)?.policies.contains("shared-policy"));
    assert!(state.groups[&group].member_entity_ids.contains(&entity));
    assert!(state.entities[&entity].group_ids.contains(&group));
    state.revoke_external_groups("auth_two", 104)?;
    assert!(state.project(&entity)?.policies.is_empty());
    assert!(!state.groups[&group].member_entity_ids.contains(&entity));
    assert!(!state.entities[&entity].group_ids.contains(&group));
    Ok(())
}

#[test]
fn full_external_group_rejects_addition_without_losing_existing_member() -> Result<()> {
    let mut state = IdentityState::default();
    let (group, _) = external(&mut state, "grant", "auth_one")?;
    let mut members = Vec::new();
    for index in 0..=MAX_MEMBERS {
        members.push(
            state
                .bind_login("auth_one", &format!("user-{index}"), 100)?
                .entity_id,
        );
    }
    for member in &members[..MAX_MEMBERS] {
        state.refresh_external_groups(member, "auth_one", &names(), 101)?;
    }
    let before = encoded(&state)?;
    assert!(
        state
            .refresh_external_groups(&members[MAX_MEMBERS], "auth_one", &names(), 102)
            .is_err()
    );
    assert_eq!(encoded(&state)?, before);
    assert_eq!(state.groups[&group].member_entity_ids.len(), MAX_MEMBERS);
    assert!(state.project(&members[0])?.policies.contains("grant"));
    Ok(())
}
