use super::{EngineResponse, Result, bad, empty, error, ok, reject_unknown, timestamp};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};
use std::collections::{BTreeMap, BTreeSet};

const MAX_NAME_BYTES: usize = 128;
const MAX_METADATA_ENTRIES: usize = 64;
const MAX_METADATA_KEY_BYTES: usize = 128;
const MAX_METADATA_VALUE_BYTES: usize = 1024;
const MAX_POLICIES: usize = 64;
const MAX_MEMBERS: usize = 256;
const MAX_GROUP_DEPTH: usize = 32;

#[derive(Clone, Serialize, Deserialize, Default)]
pub(super) struct IdentityState {
    #[serde(default)]
    next_id: u64,
    #[serde(default)]
    entities: BTreeMap<String, Entity>,
    #[serde(default)]
    entity_names: BTreeMap<String, String>,
    #[serde(default)]
    aliases: BTreeMap<String, Alias>,
    #[serde(default)]
    alias_keys: BTreeMap<String, String>,
    #[serde(default)]
    groups: BTreeMap<String, Group>,
    #[serde(default)]
    group_names: BTreeMap<String, String>,
    #[serde(default)]
    group_aliases: BTreeMap<String, GroupAlias>,
    #[serde(default)]
    group_alias_keys: BTreeMap<String, String>,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Entity {
    id: String,
    name: String,
    disabled: bool,
    metadata: BTreeMap<String, String>,
    policies: BTreeSet<String>,
    aliases: BTreeSet<String>,
    group_ids: BTreeSet<String>,
    #[serde(default)]
    merged_entity_ids: BTreeSet<String>,
    created_at: u64,
    updated_at: u64,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Alias {
    id: String,
    canonical_id: String,
    name: String,
    mount_accessor: String,
    #[serde(default, alias = "metadata")]
    custom_metadata: BTreeMap<String, String>,
    created_at: u64,
    updated_at: u64,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Group {
    id: String,
    name: String,
    kind: String,
    metadata: BTreeMap<String, String>,
    policies: BTreeSet<String>,
    member_entity_ids: BTreeSet<String>,
    member_group_ids: BTreeSet<String>,
    created_at: u64,
    updated_at: u64,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct GroupAlias {
    id: String,
    canonical_id: String,
    name: String,
    mount_accessor: String,
    created_at: u64,
    updated_at: u64,
}

pub(super) fn owns(path: &str) -> bool {
    path == "identity" || path.starts_with("identity/")
}

pub(super) fn handle(
    state: &mut IdentityState,
    method: &str,
    path: &str,
    body: &Value,
    now: u64,
) -> Result<EngineResponse> {
    let relative = path
        .trim_start_matches('/')
        .strip_prefix("identity")
        .unwrap_or("");
    let relative = relative.trim_start_matches('/').trim_end_matches('/');
    match relative {
        "entity" => handle_entity_create(state, method, body, now),
        "entity/merge" => handle_entity_merge(state, method, body, now),
        "entity/id" => handle_entity_list(state, method),
        "entity/name" => handle_entity_name_list(state, method),
        "entity-alias" => handle_alias_create(state, method, body, now),
        "entity-alias/id" => handle_alias_list(state, method),
        "group" => handle_group_create(state, method, body, now),
        "group/id" => handle_group_list(state, method),
        "group/name" => handle_group_name_list(state, method),
        "group-alias" => handle_group_alias_create(state, method, body, now),
        "group-alias/id" => handle_group_alias_list(state, method),
        "lookup/entity" => handle_entity_lookup(state, method, body),
        "lookup/group" => handle_group_lookup(state, method, body),
        _ => {
            if let Some(id) = relative.strip_prefix("entity/id/") {
                handle_entity_id(state, method, id, body, now)
            } else if let Some(name) = relative.strip_prefix("entity/name/") {
                handle_entity_name(state, method, name, body, now)
            } else if let Some(id) = relative.strip_prefix("entity-alias/id/") {
                handle_alias_id(state, method, id, body, now)
            } else if let Some(id) = relative.strip_prefix("group/id/") {
                handle_group_id(state, method, id, body, now)
            } else if let Some(name) = relative.strip_prefix("group/name/") {
                handle_group_name(state, method, name, body, now)
            } else if let Some(id) = relative.strip_prefix("group-alias/id/") {
                handle_group_alias_id(state, method, id, body, now)
            } else {
                Err(error(404, "identity path is not implemented"))
            }
        }
    }
}

fn handle_entity_create(
    state: &mut IdentityState,
    method: &str,
    body: &Value,
    now: u64,
) -> Result<EngineResponse> {
    require_write(method)?;
    reject_unknown(body, &["id", "name", "metadata", "policies", "disabled"])?;
    if let Some(id) = optional_string(body, "id")? {
        return upsert_entity(state, Some(id), body, now);
    }
    upsert_entity(state, None, body, now)
}

fn handle_entity_id(
    state: &mut IdentityState,
    method: &str,
    id: &str,
    body: &Value,
    now: u64,
) -> Result<EngineResponse> {
    valid_identifier(id, "entity id")?;
    match method {
        "GET" | "HEAD" => state
            .entities
            .get(id)
            .map(|entity| ok(entity_data(state, entity), false))
            .ok_or_else(not_found),
        "DELETE" => {
            let Some(entity) = state.entities.remove(id) else {
                return Ok(empty(false));
            };
            state.entity_names.remove(&entity.name);
            for alias_id in entity.aliases {
                if let Some(alias) = state.aliases.remove(&alias_id) {
                    state
                        .alias_keys
                        .remove(&alias_key(&alias.mount_accessor, &alias.name));
                }
            }
            for group_id in entity.group_ids {
                if let Some(group) = state.groups.get_mut(&group_id) {
                    group.member_entity_ids.remove(id);
                    group.updated_at = now;
                }
            }
            Ok(empty(true))
        }
        "POST" | "PUT" | "PATCH" => {
            reject_unknown(body, &["name", "metadata", "policies", "disabled"])?;
            upsert_entity(state, Some(id), body, now)
        }
        _ => Err(method_not_allowed()),
    }
}

fn handle_entity_name(
    state: &mut IdentityState,
    method: &str,
    name: &str,
    body: &Value,
    now: u64,
) -> Result<EngineResponse> {
    valid_name(name, "entity name")?;
    let id = state.entity_names.get(name).cloned();
    match (method, id) {
        ("GET" | "HEAD", Some(id)) => handle_entity_id(state, method, &id, body, now),
        ("DELETE", Some(id)) => handle_entity_id(state, method, &id, body, now),
        ("POST" | "PUT" | "PATCH", Some(id)) => {
            let mut object = body
                .as_object()
                .cloned()
                .ok_or_else(|| bad("request body must be an object"))?;
            if let Some(supplied) = object.get("name").and_then(Value::as_str)
                && supplied != name
            {
                return Err(bad("entity name path and body disagree"));
            }
            object.insert("name".into(), Value::String(name.into()));
            upsert_entity(state, Some(&id), &Value::Object(object), now)
        }
        ("POST" | "PUT" | "PATCH", None) => {
            let mut object = body
                .as_object()
                .cloned()
                .ok_or_else(|| bad("request body must be an object"))?;
            object.insert("name".into(), Value::String(name.into()));
            upsert_entity(state, None, &Value::Object(object), now)
        }
        ("GET" | "HEAD", None) => Err(not_found()),
        ("DELETE", None) => Ok(empty(false)),
        _ => Err(method_not_allowed()),
    }
}

fn upsert_entity(
    state: &mut IdentityState,
    id: Option<&str>,
    body: &Value,
    now: u64,
) -> Result<EngineResponse> {
    let name = body
        .get("name")
        .and_then(Value::as_str)
        .ok_or_else(|| bad("entity name is required"))?;
    valid_name(name, "entity name")?;
    let metadata = optional_metadata(body, "metadata")?;
    let policies = optional_set(body, "policies", MAX_POLICIES, "policy")?;
    let disabled = body.get("disabled").map_or(Ok(false), |value| {
        value
            .as_bool()
            .ok_or_else(|| bad("disabled must be a boolean"))
    })?;

    let id = match id {
        Some(id) => {
            valid_identifier(id, "entity id")?;
            id.to_owned()
        }
        None => state.allocate_id('e')?,
    };
    if let Some(other) = state.entity_names.get(name)
        && other != &id
    {
        return Err(error(409, "entity name already exists"));
    }
    let created_at = state
        .entities
        .get(&id)
        .map_or(now, |entity| entity.created_at);
    let aliases = state
        .entities
        .get(&id)
        .map_or_else(BTreeSet::new, |entity| entity.aliases.clone());
    let group_ids = state
        .entities
        .get(&id)
        .map_or_else(BTreeSet::new, |entity| entity.group_ids.clone());
    let merged_entity_ids = state
        .entities
        .get(&id)
        .map_or_else(BTreeSet::new, |entity| entity.merged_entity_ids.clone());
    if let Some(old) = state.entities.get(&id)
        && old.name != name
    {
        state.entity_names.remove(&old.name);
    }
    let entity = Entity {
        id: id.clone(),
        name: name.to_owned(),
        disabled,
        metadata,
        policies,
        aliases,
        group_ids,
        merged_entity_ids,
        created_at,
        updated_at: now,
    };
    state.entity_names.insert(name.into(), id.clone());
    state.entities.insert(id.clone(), entity);
    Ok(ok(json!({"id":id}), true))
}

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
        destination
            .group_ids
            .extend(source.group_ids.iter().cloned());
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

fn handle_entity_list(state: &IdentityState, method: &str) -> Result<EngineResponse> {
    require_list(method)?;
    let keys = state.entities.keys().cloned().collect::<Vec<_>>();
    let key_info = state
        .entities
        .iter()
        .map(|(id, entity)| (id.clone(), json!({"name":entity.name})))
        .collect::<Map<_, _>>();
    Ok(ok(json!({"keys":keys,"key_info":key_info}), false))
}

fn handle_entity_name_list(state: &IdentityState, method: &str) -> Result<EngineResponse> {
    require_list(method)?;
    Ok(ok(
        json!({"keys":state.entity_names.keys().cloned().collect::<Vec<_>>() }),
        false,
    ))
}

fn entity_data(state: &IdentityState, entity: &Entity) -> Value {
    let aliases = entity
        .aliases
        .iter()
        .filter_map(|id| state.aliases.get(id))
        .map(alias_data)
        .collect::<Vec<_>>();
    let direct_group_ids = entity.group_ids.clone();
    let inherited_group_ids = inherited_groups(state, &direct_group_ids);
    let mut group_ids = direct_group_ids.clone();
    group_ids.extend(inherited_group_ids.iter().cloned());
    json!({
        "id":entity.id,
        "name":entity.name,
        "disabled":entity.disabled,
        "metadata":entity.metadata,
        "policies":entity.policies,
        "aliases":aliases,
        "direct_group_ids":direct_group_ids,
        "inherited_group_ids":inherited_group_ids,
        "group_ids":group_ids,
        "creation_time":timestamp(entity.created_at),
        "last_update_time":timestamp(entity.updated_at),
        "merged_entity_ids":if entity.merged_entity_ids.is_empty() { Value::Null } else { json!(entity.merged_entity_ids) },
    })
}

fn inherited_groups(state: &IdentityState, direct: &BTreeSet<String>) -> BTreeSet<String> {
    let mut all = BTreeSet::new();
    let mut frontier = direct.clone();
    for _ in 0..MAX_GROUP_DEPTH {
        let mut next = BTreeSet::new();
        for group in state.groups.values() {
            if group
                .member_group_ids
                .iter()
                .any(|child| frontier.contains(child))
                && !direct.contains(&group.id)
                && all.insert(group.id.clone())
            {
                next.insert(group.id.clone());
            }
        }
        if next.is_empty() {
            break;
        }
        frontier = next;
    }
    all
}

fn handle_alias_create(
    state: &mut IdentityState,
    method: &str,
    body: &Value,
    now: u64,
) -> Result<EngineResponse> {
    require_write(method)?;
    reject_unknown(
        body,
        &[
            "id",
            "canonical_id",
            "name",
            "mount_accessor",
            "custom_metadata",
        ],
    )?;
    let id = optional_string(body, "id")?;
    upsert_alias(state, id, body, now)
}

fn handle_alias_id(
    state: &mut IdentityState,
    method: &str,
    id: &str,
    body: &Value,
    now: u64,
) -> Result<EngineResponse> {
    valid_identifier(id, "alias id")?;
    match method {
        "GET" | "HEAD" => state
            .aliases
            .get(id)
            .map(|alias| ok(alias_data(alias), false))
            .ok_or_else(not_found),
        "DELETE" => {
            let Some(alias) = state.aliases.remove(id) else {
                return Ok(empty(false));
            };
            state
                .alias_keys
                .remove(&alias_key(&alias.mount_accessor, &alias.name));
            if let Some(entity) = state.entities.get_mut(&alias.canonical_id) {
                entity.aliases.remove(id);
                entity.updated_at = now;
            }
            Ok(empty(true))
        }
        "POST" | "PUT" | "PATCH" => {
            reject_unknown(
                body,
                &["canonical_id", "name", "mount_accessor", "custom_metadata"],
            )?;
            upsert_alias(state, Some(id), body, now)
        }
        _ => Err(method_not_allowed()),
    }
}

fn upsert_alias(
    state: &mut IdentityState,
    id: Option<&str>,
    body: &Value,
    now: u64,
) -> Result<EngineResponse> {
    let canonical_id = body
        .get("canonical_id")
        .and_then(Value::as_str)
        .ok_or_else(|| bad("canonical_id is required"))?;
    valid_identifier(canonical_id, "canonical entity id")?;
    if !state.entities.contains_key(canonical_id) {
        return Err(bad("canonical entity does not exist"));
    }
    let name = body
        .get("name")
        .and_then(Value::as_str)
        .ok_or_else(|| bad("alias name is required"))?;
    valid_name(name, "alias name")?;
    let mount_accessor = body
        .get("mount_accessor")
        .and_then(Value::as_str)
        .ok_or_else(|| bad("mount_accessor is required"))?;
    valid_name(mount_accessor, "mount accessor")?;
    let custom_metadata = optional_metadata(body, "custom_metadata")?;
    let id = match id {
        Some(id) => {
            valid_identifier(id, "alias id")?;
            id.to_owned()
        }
        None => state.allocate_id('a')?,
    };
    let key = alias_key(mount_accessor, name);
    if let Some(other) = state.alias_keys.get(&key)
        && other != &id
    {
        return Err(error(409, "alias already exists for this mount"));
    }
    if state.aliases.values().any(|alias| {
        alias.id != id
            && alias.canonical_id == canonical_id
            && alias.mount_accessor == mount_accessor
    }) {
        return Err(error(409, "entity already has an alias for this mount"));
    }
    if let Some(old) = state.aliases.get(&id) {
        state
            .alias_keys
            .remove(&alias_key(&old.mount_accessor, &old.name));
        if let Some(entity) = state.entities.get_mut(&old.canonical_id) {
            entity.aliases.remove(&id);
            entity.updated_at = now;
        }
    }
    let created_at = state.aliases.get(&id).map_or(now, |alias| alias.created_at);
    let alias = Alias {
        id: id.clone(),
        canonical_id: canonical_id.into(),
        name: name.into(),
        mount_accessor: mount_accessor.into(),
        custom_metadata,
        created_at,
        updated_at: now,
    };
    state.alias_keys.insert(key, id.clone());
    state.aliases.insert(id.clone(), alias);
    if let Some(entity) = state.entities.get_mut(canonical_id) {
        entity.aliases.insert(id.clone());
        entity.updated_at = now;
    }
    Ok(ok(json!({"id":id,"canonical_id":canonical_id}), true))
}

fn handle_alias_list(state: &IdentityState, method: &str) -> Result<EngineResponse> {
    require_list(method)?;
    Ok(ok(
        json!({"keys":state.aliases.keys().cloned().collect::<Vec<_>>() }),
        false,
    ))
}

fn alias_data(alias: &Alias) -> Value {
    json!({
        "id":alias.id,
        "canonical_id":alias.canonical_id,
        "name":alias.name,
        "mount_accessor":alias.mount_accessor,
        "custom_metadata":alias.custom_metadata,
        "metadata":{},
        "creation_time":timestamp(alias.created_at),
        "last_update_time":timestamp(alias.updated_at),
        "local":false,
    })
}

fn handle_entity_lookup(
    state: &IdentityState,
    method: &str,
    body: &Value,
) -> Result<EngineResponse> {
    require_write(method)?;
    reject_unknown(
        body,
        &[
            "id",
            "name",
            "alias_id",
            "alias_name",
            "alias_mount_accessor",
        ],
    )?;
    let mut matches = Vec::new();
    if let Some(id) = optional_string(body, "id")? {
        matches.push(id.to_owned());
    }
    if let Some(name) = optional_string(body, "name")? {
        matches.push(
            state
                .entity_names
                .get(name)
                .cloned()
                .ok_or_else(not_found)?,
        );
    }
    if let Some(id) = optional_string(body, "alias_id")? {
        matches.push(
            state
                .aliases
                .get(id)
                .map(|alias| alias.canonical_id.clone())
                .ok_or_else(not_found)?,
        );
    }
    if let Some(alias_name) = optional_string(body, "alias_name")? {
        let accessor = body
            .get("alias_mount_accessor")
            .and_then(Value::as_str)
            .ok_or_else(|| bad("alias_mount_accessor is required with alias_name"))?;
        let alias_id = state
            .alias_keys
            .get(&alias_key(accessor, alias_name))
            .ok_or_else(not_found)?;
        matches.push(
            state
                .aliases
                .get(alias_id)
                .map(|alias| alias.canonical_id.clone())
                .ok_or_else(not_found)?,
        );
    }
    if matches.len() != 1 {
        return Err(bad("exactly one identity selector is required"));
    }
    let entity = state.entities.get(&matches[0]).ok_or_else(not_found)?;
    Ok(ok(entity_data(state, entity), false))
}

fn handle_group_lookup(
    state: &IdentityState,
    method: &str,
    body: &Value,
) -> Result<EngineResponse> {
    require_write(method)?;
    reject_unknown(
        body,
        &[
            "id",
            "name",
            "alias_id",
            "alias_name",
            "alias_mount_accessor",
        ],
    )?;
    let mut matches = Vec::new();
    if let Some(id) = optional_string(body, "id")? {
        matches.push(id.to_owned());
    }
    if let Some(name) = optional_string(body, "name")? {
        matches.push(state.group_names.get(name).cloned().ok_or_else(not_found)?);
    }
    if let Some(id) = optional_string(body, "alias_id")? {
        matches.push(
            state
                .group_aliases
                .get(id)
                .map(|alias| alias.canonical_id.clone())
                .ok_or_else(not_found)?,
        );
    }
    if let Some(alias_name) = optional_string(body, "alias_name")? {
        let accessor = body
            .get("alias_mount_accessor")
            .and_then(Value::as_str)
            .ok_or_else(|| bad("alias_mount_accessor is required with alias_name"))?;
        let alias_id = state
            .group_alias_keys
            .get(&alias_key(accessor, alias_name))
            .ok_or_else(not_found)?;
        matches.push(
            state
                .group_aliases
                .get(alias_id)
                .map(|alias| alias.canonical_id.clone())
                .ok_or_else(not_found)?,
        );
    }
    if matches.len() != 1 {
        return Err(bad("exactly one identity selector is required"));
    }
    let group = state.groups.get(&matches[0]).ok_or_else(not_found)?;
    Ok(ok(group_data(state, group), false))
}

fn handle_group_create(
    state: &mut IdentityState,
    method: &str,
    body: &Value,
    now: u64,
) -> Result<EngineResponse> {
    require_write(method)?;
    reject_unknown(
        body,
        &[
            "id",
            "name",
            "type",
            "metadata",
            "policies",
            "member_entity_ids",
            "member_group_ids",
        ],
    )?;
    let id = optional_string(body, "id")?;
    upsert_group(state, id, body, now)
}

fn handle_group_id(
    state: &mut IdentityState,
    method: &str,
    id: &str,
    body: &Value,
    now: u64,
) -> Result<EngineResponse> {
    valid_identifier(id, "group id")?;
    match method {
        "GET" | "HEAD" => state
            .groups
            .get(id)
            .map(|group| ok(group_data(state, group), false))
            .ok_or_else(not_found),
        "DELETE" => {
            let Some(group) = state.groups.remove(id) else {
                return Ok(empty(false));
            };
            state.group_names.remove(&group.name);
            for entity_id in group.member_entity_ids {
                if let Some(entity) = state.entities.get_mut(&entity_id) {
                    entity.group_ids.remove(id);
                    entity.updated_at = now;
                }
            }
            for other in state.groups.values_mut() {
                other.member_group_ids.remove(id);
            }
            let aliases = state
                .group_aliases
                .iter()
                .filter_map(|(alias_id, alias)| {
                    (alias.canonical_id == id).then_some(alias_id.clone())
                })
                .collect::<Vec<_>>();
            for alias_id in aliases {
                if let Some(alias) = state.group_aliases.remove(&alias_id) {
                    state
                        .group_alias_keys
                        .remove(&alias_key(&alias.mount_accessor, &alias.name));
                }
            }
            Ok(empty(true))
        }
        "POST" | "PUT" | "PATCH" => {
            reject_unknown(
                body,
                &[
                    "name",
                    "type",
                    "metadata",
                    "policies",
                    "member_entity_ids",
                    "member_group_ids",
                ],
            )?;
            upsert_group(state, Some(id), body, now)
        }
        _ => Err(method_not_allowed()),
    }
}

fn handle_group_name(
    state: &mut IdentityState,
    method: &str,
    name: &str,
    body: &Value,
    now: u64,
) -> Result<EngineResponse> {
    valid_name(name, "group name")?;
    let id = state.group_names.get(name).cloned();
    match (method, id) {
        ("GET" | "HEAD", Some(id)) => handle_group_id(state, method, &id, body, now),
        ("DELETE", Some(id)) => handle_group_id(state, method, &id, body, now),
        ("POST" | "PUT" | "PATCH", Some(id)) => {
            let mut object = body
                .as_object()
                .cloned()
                .ok_or_else(|| bad("request body must be an object"))?;
            object.insert("name".into(), Value::String(name.into()));
            upsert_group(state, Some(&id), &Value::Object(object), now)
        }
        ("POST" | "PUT" | "PATCH", None) => {
            let mut object = body
                .as_object()
                .cloned()
                .ok_or_else(|| bad("request body must be an object"))?;
            object.insert("name".into(), Value::String(name.into()));
            upsert_group(state, None, &Value::Object(object), now)
        }
        ("GET" | "HEAD", None) => Err(not_found()),
        ("DELETE", None) => Ok(empty(false)),
        _ => Err(method_not_allowed()),
    }
}

fn upsert_group(
    state: &mut IdentityState,
    id: Option<&str>,
    body: &Value,
    now: u64,
) -> Result<EngineResponse> {
    let name = body
        .get("name")
        .and_then(Value::as_str)
        .ok_or_else(|| bad("group name is required"))?;
    valid_name(name, "group name")?;
    let kind = body
        .get("type")
        .and_then(Value::as_str)
        .unwrap_or("internal");
    if !matches!(kind, "internal" | "external") {
        return Err(bad("group type must be internal or external"));
    }
    let policies = optional_set(body, "policies", MAX_POLICIES, "policy")?;
    let members = optional_set(body, "member_entity_ids", MAX_MEMBERS, "entity id")?;
    let child_groups = optional_set(body, "member_group_ids", MAX_MEMBERS, "group id")?;
    let metadata = optional_metadata(body, "metadata")?;
    for entity_id in &members {
        if !state.entities.contains_key(entity_id) {
            return Err(bad("group references an unknown entity"));
        }
    }
    for child in &child_groups {
        if !state.groups.contains_key(child) {
            return Err(bad("group references an unknown member group"));
        }
    }
    let id = match id {
        Some(id) => {
            valid_identifier(id, "group id")?;
            id.to_owned()
        }
        None => state.allocate_id('g')?,
    };
    if child_groups.contains(&id) {
        return Err(bad("group cannot contain itself"));
    }
    if let Some(other) = state.group_names.get(name)
        && other != &id
    {
        return Err(error(409, "group name already exists"));
    }
    let previous = state.groups.get(&id).cloned();
    let created_at = previous.as_ref().map_or(now, |group| group.created_at);
    let candidate = Group {
        id: id.clone(),
        name: name.into(),
        kind: kind.into(),
        metadata,
        policies,
        member_entity_ids: members.clone(),
        member_group_ids: child_groups,
        created_at,
        updated_at: now,
    };
    state.groups.insert(id.clone(), candidate);
    if group_cycle(state, &id)? {
        if let Some(previous) = previous.clone() {
            state.groups.insert(id.clone(), previous);
        } else {
            state.groups.remove(&id);
        }
        return Err(bad("nested group membership would create a cycle"));
    }
    if let Some(previous) = previous {
        state.group_names.remove(&previous.name);
        for entity_id in previous.member_entity_ids {
            if let Some(entity) = state.entities.get_mut(&entity_id) {
                entity.group_ids.remove(&id);
            }
        }
    }
    state.group_names.insert(name.into(), id.clone());
    for entity_id in members {
        if let Some(entity) = state.entities.get_mut(&entity_id) {
            entity.group_ids.insert(id.clone());
            entity.updated_at = now;
        }
    }
    Ok(ok(json!({"id":id}), true))
}

fn handle_group_list(state: &IdentityState, method: &str) -> Result<EngineResponse> {
    require_list(method)?;
    let keys = state.groups.keys().cloned().collect::<Vec<_>>();
    let key_info = state
        .groups
        .iter()
        .map(|(id, group)| (id.clone(), json!({"name":group.name,"type":group.kind})))
        .collect::<Map<_, _>>();
    Ok(ok(json!({"keys":keys,"key_info":key_info}), false))
}

fn handle_group_name_list(state: &IdentityState, method: &str) -> Result<EngineResponse> {
    require_list(method)?;
    Ok(ok(
        json!({"keys":state.group_names.keys().cloned().collect::<Vec<_>>() }),
        false,
    ))
}

fn group_data(state: &IdentityState, group: &Group) -> Value {
    let parent_group_ids = state
        .groups
        .values()
        .filter_map(|parent| {
            parent
                .member_group_ids
                .contains(&group.id)
                .then_some(parent.id.clone())
        })
        .collect::<Vec<_>>();
    json!({
        "id":group.id,
        "name":group.name,
        "type":group.kind,
        "metadata":group.metadata,
        "policies":group.policies,
        "member_entity_ids":group.member_entity_ids,
        "member_group_ids":group.member_group_ids,
        "parent_group_ids":parent_group_ids,
        "creation_time":timestamp(group.created_at),
        "last_update_time":timestamp(group.updated_at),
    })
}

fn handle_group_alias_create(
    state: &mut IdentityState,
    method: &str,
    body: &Value,
    now: u64,
) -> Result<EngineResponse> {
    require_write(method)?;
    reject_unknown(body, &["id", "canonical_id", "name", "mount_accessor"])?;
    let id = optional_string(body, "id")?;
    upsert_group_alias(state, id, body, now)
}

fn handle_group_alias_id(
    state: &mut IdentityState,
    method: &str,
    id: &str,
    body: &Value,
    now: u64,
) -> Result<EngineResponse> {
    valid_identifier(id, "group alias id")?;
    match method {
        "GET" | "HEAD" => state
            .group_aliases
            .get(id)
            .map(|alias| ok(group_alias_data(alias), false))
            .ok_or_else(not_found),
        "DELETE" => {
            let Some(alias) = state.group_aliases.remove(id) else {
                return Ok(empty(false));
            };
            state
                .group_alias_keys
                .remove(&alias_key(&alias.mount_accessor, &alias.name));
            Ok(empty(true))
        }
        "POST" | "PUT" | "PATCH" => {
            reject_unknown(body, &["canonical_id", "name", "mount_accessor"])?;
            upsert_group_alias(state, Some(id), body, now)
        }
        _ => Err(method_not_allowed()),
    }
}

fn upsert_group_alias(
    state: &mut IdentityState,
    id: Option<&str>,
    body: &Value,
    now: u64,
) -> Result<EngineResponse> {
    let canonical_id = body
        .get("canonical_id")
        .and_then(Value::as_str)
        .ok_or_else(|| bad("canonical_id is required"))?;
    let group = state
        .groups
        .get(canonical_id)
        .ok_or_else(|| bad("canonical group does not exist"))?;
    if group.kind != "external" {
        return Err(bad("group aliases require an external group"));
    }
    let name = body
        .get("name")
        .and_then(Value::as_str)
        .ok_or_else(|| bad("group alias name is required"))?;
    let mount_accessor = body
        .get("mount_accessor")
        .and_then(Value::as_str)
        .ok_or_else(|| bad("mount_accessor is required"))?;
    valid_name(name, "group alias name")?;
    valid_name(mount_accessor, "mount accessor")?;
    let id = match id {
        Some(id) => {
            valid_identifier(id, "group alias id")?;
            id.to_owned()
        }
        None => state.allocate_id('x')?,
    };
    let key = alias_key(mount_accessor, name);
    if let Some(other) = state.group_alias_keys.get(&key)
        && other != &id
    {
        return Err(error(409, "group alias already exists for this mount"));
    }
    if let Some(old) = state.group_aliases.get(&id) {
        state
            .group_alias_keys
            .remove(&alias_key(&old.mount_accessor, &old.name));
    }
    let created_at = state
        .group_aliases
        .get(&id)
        .map_or(now, |alias| alias.created_at);
    let alias = GroupAlias {
        id: id.clone(),
        canonical_id: canonical_id.into(),
        name: name.into(),
        mount_accessor: mount_accessor.into(),
        created_at,
        updated_at: now,
    };
    state.group_alias_keys.insert(key, id.clone());
    state.group_aliases.insert(id.clone(), alias);
    Ok(ok(json!({"id":id,"canonical_id":canonical_id}), true))
}

fn handle_group_alias_list(state: &IdentityState, method: &str) -> Result<EngineResponse> {
    require_list(method)?;
    Ok(ok(
        json!({"keys":state.group_aliases.keys().cloned().collect::<Vec<_>>() }),
        false,
    ))
}

fn group_alias_data(alias: &GroupAlias) -> Value {
    json!({
        "id":alias.id,
        "canonical_id":alias.canonical_id,
        "name":alias.name,
        "mount_accessor":alias.mount_accessor,
        "creation_time":timestamp(alias.created_at),
        "last_update_time":timestamp(alias.updated_at),
    })
}

fn group_cycle(state: &IdentityState, start: &str) -> Result<bool> {
    fn visit(
        state: &IdentityState,
        current: &str,
        active: &mut BTreeSet<String>,
        visited: &mut BTreeSet<String>,
        depth: usize,
    ) -> Result<bool> {
        if depth > MAX_GROUP_DEPTH {
            return Err(bad("nested group depth exceeds the supported bound"));
        }
        if active.contains(current) {
            return Ok(true);
        }
        if !visited.insert(current.to_owned()) {
            return Ok(false);
        }
        active.insert(current.to_owned());
        if let Some(group) = state.groups.get(current) {
            for child in &group.member_group_ids {
                if visit(state, child, active, visited, depth + 1)? {
                    return Ok(true);
                }
            }
        }
        active.remove(current);
        Ok(false)
    }

    visit(state, start, &mut BTreeSet::new(), &mut BTreeSet::new(), 0)
}

fn optional_metadata(body: &Value, field: &str) -> Result<BTreeMap<String, String>> {
    let Some(value) = body.get(field) else {
        return Ok(BTreeMap::new());
    };
    let object = value
        .as_object()
        .ok_or_else(|| bad("identity metadata must be an object of strings"))?;
    if object.len() > MAX_METADATA_ENTRIES {
        return Err(bad("identity metadata exceeds the supported entry bound"));
    }
    object
        .iter()
        .map(|(key, value)| {
            if key.is_empty() || key.len() > MAX_METADATA_KEY_BYTES {
                return Err(bad("identity metadata key is invalid"));
            }
            let value = value
                .as_str()
                .ok_or_else(|| bad("identity metadata values must be strings"))?;
            if value.len() > MAX_METADATA_VALUE_BYTES || value.chars().any(char::is_control) {
                return Err(bad("identity metadata value is invalid"));
            }
            Ok((key.clone(), value.into()))
        })
        .collect()
}

fn required_set(body: &Value, field: &str, max: usize, label: &str) -> Result<BTreeSet<String>> {
    if body.get(field).is_none() {
        return Err(bad(&format!("{field} is required")));
    }
    optional_set(body, field, max, label)
}

fn optional_set(body: &Value, field: &str, max: usize, label: &str) -> Result<BTreeSet<String>> {
    let Some(value) = body.get(field) else {
        return Ok(BTreeSet::new());
    };
    let values = value
        .as_array()
        .ok_or_else(|| bad("identity list field must be an array of strings"))?;
    if values.len() > max {
        return Err(bad("identity list exceeds the supported bound"));
    }
    values
        .iter()
        .map(|value| {
            let value = value
                .as_str()
                .ok_or_else(|| bad("identity list entries must be strings"))?;
            valid_name(value, label)?;
            Ok(value.to_owned())
        })
        .collect()
}

fn optional_string<'a>(body: &'a Value, field: &str) -> Result<Option<&'a str>> {
    body.get(field)
        .map(|value| {
            value
                .as_str()
                .ok_or_else(|| bad("identity selector must be a string"))
        })
        .transpose()
}

fn valid_identifier(value: &str, label: &str) -> Result<()> {
    valid_name(value, label)
}

fn valid_name(value: &str, label: &str) -> Result<()> {
    if value.is_empty()
        || value.len() > MAX_NAME_BYTES
        || value.starts_with('.')
        || value.ends_with('.')
        || value.bytes().any(|byte| {
            !(byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':' | b'@'))
        })
    {
        return Err(bad(&format!("{label} is invalid")));
    }
    Ok(())
}

fn alias_key(mount_accessor: &str, name: &str) -> String {
    format!("{mount_accessor}\0{name}")
}

fn require_write(method: &str) -> Result<()> {
    if matches!(method, "POST" | "PUT" | "PATCH") {
        Ok(())
    } else {
        Err(method_not_allowed())
    }
}

fn require_list(method: &str) -> Result<()> {
    if matches!(method, "LIST" | "GET") {
        Ok(())
    } else {
        Err(method_not_allowed())
    }
}

fn method_not_allowed() -> super::EngineError {
    error(405, "method is not supported by the identity endpoint")
}

fn not_found() -> super::EngineError {
    error(404, "identity record was not found")
}

impl IdentityState {
    fn allocate_id(&mut self, prefix: char) -> Result<String> {
        self.next_id = self
            .next_id
            .checked_add(1)
            .ok_or_else(|| error(507, "identity identifier space exhausted"))?;
        Ok(format!("{prefix}-{:032x}", self.next_id))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn entity_alias_group_lifecycle_is_deterministic() -> Result<()> {
        let mut state = IdentityState::default();
        let entity = handle(
            &mut state,
            "POST",
            "identity/entity",
            &json!({"name":"alice","policies":["reader"]}),
            10,
        )?;
        let entity_id = entity.body["data"]["id"]
            .as_str()
            .ok_or_else(|| error(500, "missing entity id"))?
            .to_owned();
        let alias = handle(
            &mut state,
            "POST",
            "identity/entity-alias",
            &json!({"canonical_id":entity_id,"name":"alice@example.invalid","mount_accessor":"auth_jwt","custom_metadata":{"qa":"synthetic"}}),
            11,
        )?;
        assert!(alias.mutated);
        let lookup = handle(
            &mut state,
            "POST",
            "identity/lookup/entity",
            &json!({"alias_name":"alice@example.invalid","alias_mount_accessor":"auth_jwt"}),
            12,
        )?;
        assert_eq!(lookup.body["data"]["name"], "alice");
        let by_name = handle(
            &mut state,
            "POST",
            "identity/lookup/entity",
            &json!({"name":"alice"}),
            12,
        )?;
        assert_eq!(by_name.body["data"]["id"], entity_id);
        let group = handle(
            &mut state,
            "POST",
            "identity/group",
            &json!({"name":"engineering","policies":["engineering-read"],"member_entity_ids":[entity_id]}),
            13,
        )?;
        let group_id = group.body["data"]["id"]
            .as_str()
            .ok_or_else(|| error(500, "missing group id"))?;
        let read = handle(
            &mut state,
            "GET",
            &format!("identity/group/id/{group_id}"),
            &json!({}),
            14,
        )?;
        assert_eq!(read.body["data"]["name"], "engineering");
        assert_eq!(
            read.body["data"]["member_entity_ids"]
                .as_array()
                .map(Vec::len),
            Some(1)
        );
        Ok(())
    }

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

    #[test]
    fn nested_group_cycles_are_rejected_without_committing_candidate() -> Result<()> {
        let mut state = IdentityState::default();
        let first = handle(
            &mut state,
            "POST",
            "identity/group",
            &json!({"name":"first"}),
            1,
        )?;
        let first_id = first.body["data"]["id"]
            .as_str()
            .ok_or_else(not_found)?
            .to_owned();
        let second = handle(
            &mut state,
            "POST",
            "identity/group",
            &json!({"name":"second","member_group_ids":[first_id]}),
            2,
        )?;
        let second_id = second.body["data"]["id"]
            .as_str()
            .ok_or_else(not_found)?
            .to_owned();
        let before = serde_json::to_vec(&state).map_err(|_| error(500, "serialization failed"))?;
        let result = handle(
            &mut state,
            "POST",
            &format!("identity/group/id/{first_id}"),
            &json!({"name":"first","member_group_ids":[second_id]}),
            3,
        );
        assert!(result.is_err());
        let after = serde_json::to_vec(&state).map_err(|_| error(500, "serialization failed"))?;
        assert_eq!(before, after);
        Ok(())
    }
}
