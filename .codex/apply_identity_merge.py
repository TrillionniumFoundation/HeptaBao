from pathlib import Path

path = Path('crates/heptabao-server/src/engines/identity.rs')
text = path.read_text()

def once(old: str, new: str) -> None:
    global text
    count = text.count(old)
    if count != 1:
        raise SystemExit(f'expected exactly one match, found {count}: {old[:80]!r}')
    text = text.replace(old, new, 1)

once(
'''    aliases: BTreeSet<String>,
    group_ids: BTreeSet<String>,
    created_at: u64,
''',
'''    aliases: BTreeSet<String>,
    group_ids: BTreeSet<String>,
    #[serde(default)]
    merged_entity_ids: BTreeSet<String>,
    created_at: u64,
''')

once(
'''        "entity" => handle_entity_create(state, method, body, now),
        "entity/id" => handle_entity_list(state, method),
''',
'''        "entity" => handle_entity_create(state, method, body, now),
        "entity/merge" => handle_entity_merge(state, method, body, now),
        "entity/id" => handle_entity_list(state, method),
''')

once(
'''    let group_ids = state
        .entities
        .get(&id)
        .map_or_else(BTreeSet::new, |entity| entity.group_ids.clone());
    if let Some(old) = state.entities.get(&id)
''',
'''    let group_ids = state
        .entities
        .get(&id)
        .map_or_else(BTreeSet::new, |entity| entity.group_ids.clone());
    let merged_entity_ids = state
        .entities
        .get(&id)
        .map_or_else(BTreeSet::new, |entity| entity.merged_entity_ids.clone());
    if let Some(old) = state.entities.get(&id)
''')

once(
'''        aliases,
        group_ids,
        created_at,
''',
'''        aliases,
        group_ids,
        merged_entity_ids,
        created_at,
''')

merge_fn = r'''
fn handle_entity_merge(
    state: &mut IdentityState,
    method: &str,
    body: &Value,
    now: u64,
) -> Result<EngineResponse> {
    require_write(method)?;
    reject_unknown(
        body,
        &[
            "from_entity_ids",
            "to_entity_id",
            "force",
            "conflicting_alias_ids_to_keep",
        ],
    )?;
    let destination_id = body
        .get("to_entity_id")
        .and_then(Value::as_str)
        .ok_or_else(|| bad("to_entity_id is required"))?;
    valid_identifier(destination_id, "destination entity id")?;
    if !state.entities.contains_key(destination_id) {
        return Err(not_found());
    }
    let sources = required_set(body, "from_entity_ids", MAX_MEMBERS, "entity id")?;
    if sources.is_empty() {
        return Err(bad("from_entity_ids must not be empty"));
    }
    if sources.contains(destination_id) {
        return Err(bad("destination entity cannot be merged into itself"));
    }
    for source_id in &sources {
        if !state.entities.contains_key(source_id) {
            return Err(bad("source entity does not exist"));
        }
    }
    let keep = optional_set(
        body,
        "conflicting_alias_ids_to_keep",
        MAX_MEMBERS,
        "alias id",
    )?;
    if let Some(force) = body.get("force")
        && !force.is_boolean()
    {
        return Err(bad("force must be a boolean"));
    }

    let mut candidate = state.clone();
    let mut destination = candidate
        .entities
        .get(destination_id)
        .cloned()
        .ok_or_else(not_found)?;
    let mut destination_by_mount = destination
        .aliases
        .iter()
        .filter_map(|alias_id| candidate.aliases.get(alias_id))
        .map(|alias| (alias.mount_accessor.clone(), alias.id.clone()))
        .collect::<BTreeMap<_, _>>();
    let mut consumed_keep = BTreeSet::new();

    for source_id in &sources {
        let source = candidate
            .entities
            .get(source_id)
            .cloned()
            .ok_or_else(|| bad("source entity does not exist"))?;
        for alias_id in &source.aliases {
            let alias = candidate
                .aliases
                .get(alias_id)
                .cloned()
                .ok_or_else(|| error(500, "identity alias index is inconsistent"))?;
            if let Some(destination_alias_id) =
                destination_by_mount.get(&alias.mount_accessor).cloned()
            {
                if sources.len() != 1 {
                    return Err(bad(
                        "alias conflicts require merging exactly one source entity at a time",
                    ));
                }
                let source_kept = keep.contains(alias_id);
                let destination_kept = keep.contains(&destination_alias_id);
                if source_kept == destination_kept {
                    return Err(bad(
                        "exactly one conflicting alias id to keep is required for each mount conflict",
                    ));
                }
                let (kept_id, removed_id) = if source_kept {
                    (alias_id.clone(), destination_alias_id.clone())
                } else {
                    (destination_alias_id.clone(), alias_id.clone())
                };
                consumed_keep.insert(kept_id.clone());
                if let Some(removed) = candidate.aliases.remove(&removed_id) {
                    candidate
                        .alias_keys
                        .remove(&alias_key(&removed.mount_accessor, &removed.name));
                    destination.aliases.remove(&removed_id);
                }
                if source_kept {
                    if let Some(kept_alias) = candidate.aliases.get_mut(&kept_id) {
                        kept_alias.canonical_id = destination_id.to_owned();
                        kept_alias.updated_at = now;
                    }
                    destination.aliases.insert(kept_id.clone());
                    destination_by_mount.insert(alias.mount_accessor.clone(), kept_id);
                }
            } else {
                let moved = candidate
                    .aliases
                    .get_mut(alias_id)
                    .ok_or_else(|| error(500, "identity alias index is inconsistent"))?;
                moved.canonical_id = destination_id.to_owned();
                moved.updated_at = now;
                destination.aliases.insert(alias_id.clone());
                destination_by_mount.insert(moved.mount_accessor.clone(), alias_id.clone());
            }
        }
        destination.group_ids.extend(source.group_ids.iter().cloned());
        destination.merged_entity_ids.insert(source_id.clone());
        destination
            .merged_entity_ids
            .extend(source.merged_entity_ids.iter().cloned());
    }
    if keep != consumed_keep {
        return Err(bad(
            "conflicting_alias_ids_to_keep contains an alias that is not selected by a conflict",
        ));
    }

    for source_id in &sources {
        let source = candidate
            .entities
            .remove(source_id)
            .ok_or_else(|| error(500, "source entity disappeared during merge"))?;
        candidate.entity_names.remove(&source.name);
        for group_id in &source.group_ids {
            let group = candidate
                .groups
                .get_mut(group_id)
                .ok_or_else(|| error(500, "identity group index is inconsistent"))?;
            group.member_entity_ids.remove(source_id);
            group.member_entity_ids.insert(destination_id.to_owned());
            group.updated_at = now;
        }
    }
    destination.updated_at = now;
    candidate
        .entities
        .insert(destination_id.to_owned(), destination);
    *state = candidate;
    Ok(empty(true))
}
'''
once(
'''    state.entities.insert(id.clone(), entity);
    Ok(ok(json!({"id":id}), true))
}

fn handle_entity_list''',
'''    state.entities.insert(id.clone(), entity);
    Ok(ok(json!({"id":id}), true))
}
''' + merge_fn + '''
fn handle_entity_list''')

once(
'''        "merged_entity_ids":Value::Null,
''',
'''        "merged_entity_ids":if entity.merged_entity_ids.is_empty() { Value::Null } else { json!(entity.merged_entity_ids) },
''')

required_set = r'''
fn required_set(
    body: &Value,
    field: &str,
    max: usize,
    label: &str,
) -> Result<BTreeSet<String>> {
    if body.get(field).is_none() {
        return Err(bad(&format!("{field} is required")));
    }
    optional_set(body, field, max, label)
}
'''
once(
'''fn optional_set(body: &Value, field: &str, max: usize, label: &str) -> Result<BTreeSet<String>> {''',
required_set + '''
fn optional_set(body: &Value, field: &str, max: usize, label: &str) -> Result<BTreeSet<String>> {''')

merge_test = r'''
    #[test]
    fn entity_merge_moves_aliases_groups_and_records_lineage() -> Result<()> {
        let mut state = IdentityState::default();
        let destination = handle(
            &mut state,
            "POST",
            "identity/entity",
            &json!({"name":"destination"}),
            1,
        )?;
        let destination_id = destination.body["data"]["id"]
            .as_str()
            .ok_or_else(not_found)?
            .to_owned();
        let source = handle(
            &mut state,
            "POST",
            "identity/entity",
            &json!({"name":"source"}),
            2,
        )?;
        let source_id = source.body["data"]["id"]
            .as_str()
            .ok_or_else(not_found)?
            .to_owned();
        let alias = handle(
            &mut state,
            "POST",
            "identity/entity-alias",
            &json!({"canonical_id":source_id,"name":"source-login","mount_accessor":"auth_userpass"}),
            3,
        )?;
        let alias_id = alias.body["data"]["id"]
            .as_str()
            .ok_or_else(not_found)?
            .to_owned();
        let group = handle(
            &mut state,
            "POST",
            "identity/group",
            &json!({"name":"operators","member_entity_ids":[source_id]}),
            4,
        )?;
        let group_id = group.body["data"]["id"]
            .as_str()
            .ok_or_else(not_found)?
            .to_owned();
        let merged = handle(
            &mut state,
            "POST",
            "identity/entity/merge",
            &json!({"to_entity_id":destination_id,"from_entity_ids":[source_id]}),
            5,
        )?;
        assert_eq!(merged.status, 204);
        let destination = state.entities.get(&destination_id).ok_or_else(not_found)?;
        assert!(destination.aliases.contains(&alias_id));
        assert!(destination.group_ids.contains(&group_id));
        assert!(destination.merged_entity_ids.contains(&source_id));
        assert_eq!(
            state
                .aliases
                .get(&alias_id)
                .map(|alias| alias.canonical_id.as_str()),
            Some(destination_id.as_str())
        );
        assert!(
            state
                .groups
                .get(&group_id)
                .is_some_and(|group| group.member_entity_ids.contains(&destination_id))
        );
        assert!(!state.entities.contains_key(&source_id));
        Ok(())
    }
'''
once(
'''    #[test]
    fn nested_group_cycles_are_rejected_without_committing_candidate() -> Result<()> {''',
merge_test + '''
    #[test]
    fn nested_group_cycles_are_rejected_without_committing_candidate() -> Result<()> {''')

path.write_text(text)
