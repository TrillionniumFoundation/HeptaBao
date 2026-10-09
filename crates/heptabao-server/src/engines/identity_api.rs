//! Public Alias/Persona compatibility uses the existing namespace-owned graphs.
//! Administrative Alias metadata never becomes provider login metadata.
use super::*;

const MAX_API_RECORDS: usize = 4096;

pub(in crate::engines) fn owns(path: &str) -> bool {
    let path = path.trim_start_matches('/').trim_end_matches('/');
    [
        "identity/entity-alias",
        "identity/alias",
        "identity/persona",
    ]
    .iter()
    .any(|root| {
        path == *root
            || path
                .strip_prefix(root)
                .is_some_and(|rest| rest == "/id" || rest.starts_with("/id/"))
    })
}

pub(in crate::engines) fn alias_write_accessor(
    state: &IdentityState,
    path: &str,
    body: &Value,
) -> Result<Option<String>> {
    let path = path.trim_start_matches('/').trim_end_matches('/');
    let Some(rest) = path
        .strip_prefix("identity/entity-alias")
        .or_else(|| path.strip_prefix("identity/alias"))
    else {
        return Ok(None);
    };
    if let Some(value) = body.get("mount_accessor") {
        return value
            .as_str()
            .map(|s| Some(s.to_owned()))
            .ok_or_else(|| bad("invalid mount accessor"));
    }
    let id = rest
        .strip_prefix("/id/")
        .or_else(|| body.get("id").and_then(Value::as_str));
    Ok(id
        .and_then(|id| state.aliases.get(id))
        .map(|alias| alias.mount_accessor.clone()))
}

pub(in crate::engines) fn handle(
    state: &mut IdentityState,
    method: &str,
    path: &str,
    body: &Value,
    now: u64,
    namespace_id: &str,
) -> Result<EngineResponse> {
    let path = path.trim_start_matches('/').trim_end_matches('/');
    let (root, rest) = [
        "identity/entity-alias",
        "identity/alias",
        "identity/persona",
    ]
    .iter()
    .find_map(|root| path.strip_prefix(root).map(|rest| (*root, rest)))
    .ok_or_else(not_found)?;
    if !matches!(rest, "" | "/id") && !rest.starts_with("/id/") {
        return Err(not_found());
    }
    let id = rest.strip_prefix("/id/");
    if root == "identity/persona" && matches!(method, "POST" | "PUT" | "PATCH") {
        if rest == "/id" {
            return Err(method_not_allowed());
        }
        return write_persona(state, id, body, now);
    }
    if rest == "/id" {
        require_list(method)?;
        if root == "identity/persona" && state.aliases.is_empty() {
            return Err(not_found());
        }
        let key_info: BTreeMap<String, Value> = state
            .aliases
            .iter()
            .map(|(id, alias)| {
                let data = api_alias_data(alias, namespace_id);
                let fields = [
                    "canonical_id",
                    "custom_metadata",
                    "local",
                    "metadata",
                    "mount_accessor",
                    "mount_path",
                    "mount_type",
                    "name",
                ];
                let info: Map<String, Value> = fields
                    .into_iter()
                    .map(|field| (field.into(), data[field].clone()))
                    .collect();
                (id.clone(), Value::Object(info))
            })
            .collect();
        return Ok(ok(
            json!({"keys":state.aliases.keys().collect::<Vec<_>>(), "key_info":key_info}),
            false,
        ));
    }
    if let Some(id) = id {
        valid_identifier(id, "alias id")?;
        if matches!(method, "GET" | "HEAD") {
            return state
                .aliases
                .get(id)
                .map(|alias| ok(api_alias_data(alias, namespace_id), false))
                .ok_or_else(not_found);
        }
        if method == "DELETE" {
            return handle_alias_id(state, method, id, body, now);
        }
    }
    require_write(method)?;
    write_alias(state, id, body, now, root == "identity/alias")
}

fn write_alias(
    state: &mut IdentityState,
    path_id: Option<&str>,
    body: &Value,
    now: u64,
    legacy: bool,
) -> Result<EngineResponse> {
    reject_unknown(
        body,
        &[
            "id",
            "canonical_id",
            "entity_id",
            "name",
            "mount_accessor",
            "metadata",
            "custom_metadata",
        ],
    )?;
    let body_id = optional_string(body, "id")?;
    if path_id
        .zip(body_id)
        .is_some_and(|(path, body)| path != body)
    {
        return Err(bad("identity path and body id disagree"));
    }
    let requested_id = path_id.or(body_id);
    let previous = requested_id.and_then(|id| state.aliases.get(id)).cloned();
    if requested_id.is_some() && previous.is_none() {
        return Err(not_found());
    }
    let mut object = body
        .as_object()
        .cloned()
        .ok_or_else(|| bad("request body must be an object"))?;
    // The public schema recognizes metadata, but only a provider observation
    // can populate login_metadata. The strict internal handle remains unchanged.
    object.remove("metadata");
    object.remove("entity_id");
    object.remove("id");
    if legacy {
        object.remove("custom_metadata");
    }
    for field in ["name", "mount_accessor"] {
        if !object.contains_key(field)
            && let Some(old) = &previous
        {
            let value = if field == "name" {
                &old.name
            } else {
                &old.mount_accessor
            };
            object.insert(field.into(), json!(value));
        }
    }
    let name = object
        .get("name")
        .and_then(Value::as_str)
        .ok_or_else(|| bad("alias name is required"))?;
    valid_alias_name(name, "alias name")?;
    let accessor = object
        .get("mount_accessor")
        .and_then(Value::as_str)
        .ok_or_else(|| bad("mount_accessor is required"))?;
    valid_name(accessor, "mount accessor")?;
    if let Some(value) = body.get("canonical_id").or_else(|| body.get("entity_id")) {
        object.insert("canonical_id".into(), value.clone());
    } else if let Some(old) = &previous {
        object.insert("canonical_id".into(), json!(old.canonical_id));
    } else {
        if state.entities.len() >= MAX_API_RECORDS || state.aliases.len() >= MAX_API_RECORDS {
            return Err(error(507, "identity capacity exceeded"));
        }
        let entity_id = create_implicit_entity(state, now)?;
        object.insert("canonical_id".into(), json!(entity_id));
    }
    if previous.is_none() {
        if state.aliases.len() >= MAX_API_RECORDS {
            return Err(error(507, "identity capacity exceeded"));
        }
        object.entry("custom_metadata").or_insert_with(|| json!({}));
    } else if legacy
        && previous.as_ref().is_some_and(|old| {
            object["name"].as_str() != Some(old.name.as_str())
                || object["mount_accessor"].as_str() != Some(old.mount_accessor.as_str())
        })
    {
        // Legacy has no custom metadata field. A real rename/accessor change
        // stores the native nil representation; ignored-only writes are no-ops.
        object.insert("custom_metadata".into(), Value::Null);
    }
    upsert_alias(state, requested_id, &Value::Object(object), now)
}

fn create_implicit_entity(state: &mut IdentityState, now: u64) -> Result<String> {
    if state.entities.len() >= MAX_API_RECORDS {
        return Err(error(507, "identity capacity exceeded"));
    }
    let id = state.allocate_id('e')?;
    let suffix = state.uuid_namespace.as_deref().unwrap_or("root");
    let name = format!("entity_{}.{}", &id[..8], suffix);
    valid_name(&name, "entity name")?;
    if state.entity_names.contains_key(&name) {
        return Err(error(409, "generated identity name is already in use"));
    }
    state.entity_names.insert(name.clone(), id.clone());
    state.entities.insert(
        id.clone(),
        Entity {
            id: id.clone(),
            name,
            disabled: false,
            metadata: None,
            policies: BTreeSet::new(),
            aliases: BTreeSet::new(),
            group_ids: BTreeSet::new(),
            merged_entity_ids: BTreeSet::new(),
            created_at: now,
            updated_at: now,
        },
    );
    Ok(id)
}

fn write_persona(
    state: &mut IdentityState,
    path_id: Option<&str>,
    body: &Value,
    now: u64,
) -> Result<EngineResponse> {
    reject_unknown(
        body,
        &[
            "id",
            "name",
            "metadata",
            "entity_id",
            "mount_accessor",
            "canonical_id",
            "custom_metadata",
        ],
    )?;
    let body_id = optional_string(body, "id")?;
    if path_id
        .zip(body_id)
        .is_some_and(|(path, body)| path != body)
    {
        return Err(bad("identity path and body id disagree"));
    }
    let id = path_id.or(body_id);
    if let Some(id) = id {
        valid_identifier(id, "entity id")?;
        if !state.entities.contains_key(id) {
            return Err(bad("entity not found from id"));
        }
    }
    let mut object = body
        .as_object()
        .cloned()
        .ok_or_else(|| bad("request body must be an object"))?;
    for ignored in [
        "id",
        "entity_id",
        "mount_accessor",
        "canonical_id",
        "custom_metadata",
    ] {
        object.remove(ignored);
    }
    if let Some(id) = id {
        upsert_entity(state, Some(id), &Value::Object(object), now)?;
        return Ok(empty(true));
    }
    if !object.contains_key("name") {
        let id = create_implicit_entity(state, now)?;
        if !object.is_empty() {
            upsert_entity(state, Some(&id), &Value::Object(object), now)?;
        }
        let entity = state.entities.get(&id).ok_or_else(not_found)?;
        return Ok(ok(json!({"id":id,"name":entity.name,"aliases":null}), true));
    }
    if state.entities.len() >= MAX_API_RECORDS {
        return Err(error(507, "identity capacity exceeded"));
    }
    let response = upsert_entity(state, None, &Value::Object(object), now)?;
    let id = response.body["data"]["id"]
        .as_str()
        .ok_or_else(|| error(503, "entity response is unavailable"))?;
    let entity = state.entities.get(id).ok_or_else(not_found)?;
    Ok(ok(json!({"id":id,"name":entity.name,"aliases":null}), true))
}

fn api_alias_data(alias: &Alias, namespace_id: &str) -> Value {
    let mut data = alias_data(alias);
    data["metadata"] = if alias.login_metadata.is_empty() {
        Value::Null
    } else {
        json!(alias.login_metadata)
    };
    data["merged_from_canonical_ids"] = Value::Null;
    data["mount_path"] = json!("");
    data["mount_type"] = json!("");
    data["namespace_id"] = json!(namespace_id);
    data
}
