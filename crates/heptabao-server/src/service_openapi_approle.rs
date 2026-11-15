use serde_json::{Map, Value, json};
use std::collections::BTreeSet;

// These operations are implemented by the current AppRole dispatcher.
// Attribute endpoints absent from that dispatcher remain absent from discovery.
const ROUTES: &[(&str, &[&str])] = &[
    ("/login", &["post"]),
    ("/role", &["get"]),
    ("/role/{role_name}", &["get", "post", "delete"]),
    ("/role/{role_name}/role-id", &["get", "post"]),
    ("/role/{role_name}/secret-id", &["get", "post"]),
    ("/role/{role_name}/custom-secret-id", &["post"]),
    ("/role/{role_name}/secret-id/lookup", &["post"]),
    ("/role/{role_name}/secret-id/destroy", &["post"]),
    ("/role/{role_name}/secret-id-accessor/lookup", &["post"]),
    ("/role/{role_name}/secret-id-accessor/destroy", &["post"]),
    (
        "/role/{role_name}/bound-cidr-list",
        &["get", "post", "delete"],
    ),
    (
        "/role/{role_name}/secret-id-bound-cidrs",
        &["get", "post", "delete"],
    ),
    (
        "/role/{role_name}/token-bound-cidrs",
        &["get", "post", "delete"],
    ),
    ("/tidy/secret-id", &["post"]),
];

const ROLE_WRITE_FIELDS: &[&str] = &[
    "token_type",
    "token_bound_cidrs",
    "secret_id_bound_cidrs",
    "bound_cidr_list",
    "bind_secret_id",
    "policies",
    "token_policies",
    "token_ttl",
    "token_max_ttl",
    "token_period",
    "token_explicit_max_ttl",
    "token_num_uses",
    "secret_id_ttl",
    "secret_id_num_uses",
];
const SECRET_ID_WRITE_FIELDS: &[&str] = &[
    "cidr_list",
    "metadata",
    "num_uses",
    "token_bound_cidrs",
    "ttl",
];
const ROLE_READ_FIELDS: &[&str] = &[
    "secret_id_bound_cidrs",
    "token_bound_cidrs",
    "token_type",
    "bind_secret_id",
    "token_policies",
    "token_ttl",
    "token_max_ttl",
    "token_period",
    "token_explicit_max_ttl",
    "token_num_uses",
    "secret_id_ttl",
    "secret_id_num_uses",
];

fn references(value: &Value, names: &mut BTreeSet<String>) -> Result<(), ()> {
    match value {
        Value::Object(object) => {
            for (key, value) in object {
                if key == "$ref" {
                    let reference = value.as_str().ok_or(())?;
                    let name = reference.strip_prefix("#/components/schemas/").ok_or(())?;
                    names.insert(name.into());
                } else {
                    references(value, names)?;
                }
            }
        }
        Value::Array(items) => {
            for item in items {
                references(item, names)?;
            }
        }
        _ => {}
    }
    Ok(())
}

pub(super) fn add(
    paths: &mut Map<String, Value>,
    schemas: &mut Map<String, Value>,
    mount: &str,
    generic: bool,
) -> Result<(), ()> {
    // This is the original public document returned by a real OpenBao 2.7.0
    // AppRole HELP request. Its existing qualified references are preserved.
    let document: Value =
        serde_json::from_str(include_str!("help_templates/approle-openapi-270.json"))
            .map_err(|_| ())?;
    let backend_paths = document["paths"].as_object().ok_or(())?;
    let backend_schemas = document["components"]["schemas"].as_object().ok_or(())?;
    let prefix = super::openapi_mount_path(mount, generic, true);
    let actual_mount = mount
        .trim_end_matches('/')
        .strip_prefix("auth/")
        .ok_or(())?;
    let mut needed = BTreeSet::new();
    for &(suffix, methods) in ROUTES {
        let mut item = backend_paths
            .get(suffix)
            .and_then(Value::as_object)
            .ok_or(())?
            .clone();
        item.retain(|key, _| {
            !matches!(
                key.as_str(),
                "get" | "post" | "delete" | "put" | "patch" | "head" | "options"
            ) || methods.contains(&key.as_str())
        });
        if generic {
            let parameters = item
                .entry("parameters")
                .or_insert_with(|| json!([]))
                .as_array_mut()
                .ok_or(())?;
            parameters.push(json!({
                "name": format!("{}_mount_path", actual_mount.replace('-', "_")),
                "description": "Path that the backend was mounted at",
                "in": "path",
                "schema": {"type":"string", "default":actual_mount},
                "required":true
            }));
        }
        let value = Value::Object(item);
        references(&value, &mut needed)?;
        paths.insert(format!("/{prefix}{suffix}"), value);
    }
    let mut processed = BTreeSet::new();
    while let Some(name) = needed
        .iter()
        .find(|name| !processed.contains(*name))
        .cloned()
    {
        let mut schema = backend_schemas.get(&name).ok_or(())?.clone();
        // Publish the request fields accepted and response fields emitted by
        // the current role handler. This does not implement the other fields.
        let supported = match name.as_str() {
            "AppRoleWriteRoleRequest" => Some(ROLE_WRITE_FIELDS),
            "AppRoleReadRoleResponse" => Some(ROLE_READ_FIELDS),
            "AppRoleWriteSecretIdRequest" => Some(SECRET_ID_WRITE_FIELDS),
            _ => None,
        };
        if let Some(fields) = supported {
            schema
                .get_mut("properties")
                .and_then(Value::as_object_mut)
                .ok_or(())?
                .retain(|key, _| fields.contains(&key.as_str()));
        }
        references(&schema, &mut needed)?;
        if schemas.get(&name).is_some_and(|old| old != &schema) {
            return Err(());
        }
        schemas.insert(name.clone(), schema);
        processed.insert(name);
    }
    Ok(())
}
