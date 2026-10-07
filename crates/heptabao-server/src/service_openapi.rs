use super::{Response, Value};
use serde_json::{Map, json};
use std::collections::BTreeMap;

#[path = "service_openapi_approle.rs"]
mod approle;

struct Route {
    path: &'static str,
    methods: &'static [&'static str],
    description: &'static str,
    sudo: bool,
    unauthenticated: bool,
}

const FIXED_ROUTES: &[Route] = &[
    Route {
        path: "/sys/mounts/{path}/tune",
        methods: &["get", "post"],
        description: "Read or tune a secret-engine mount.",
        sudo: false,
        unauthenticated: false,
    },
    Route {
        path: "/sys/auth/{path}/tune",
        methods: &["get", "post"],
        description: "Read or tune an authentication mount.",
        sudo: true,
        unauthenticated: false,
    },
    Route {
        path: "/sys/health",
        methods: &["get"],
        description: "Bounded server health status.",
        sudo: false,
        unauthenticated: true,
    },
    Route {
        path: "/sys/init",
        methods: &["get", "post"],
        description: "Initialization status and one-time initialization.",
        sudo: false,
        unauthenticated: true,
    },
    Route {
        path: "/sys/unseal",
        methods: &["post"],
        description: "Submit one unseal share.",
        sudo: false,
        unauthenticated: true,
    },
    Route {
        path: "/sys/seal-status",
        methods: &["get"],
        description: "Current seal status.",
        sudo: false,
        unauthenticated: true,
    },
    Route {
        path: "/sys/leader",
        methods: &["get"],
        description: "Current HA leader view.",
        sudo: false,
        unauthenticated: true,
    },
    Route {
        path: "/sys/auth",
        methods: &["get"],
        description: "List authentication mounts.",
        sudo: false,
        unauthenticated: false,
    },
    Route {
        path: "/sys/auth/{path}",
        methods: &["get", "post", "delete"],
        description: "Read, enable, tune or disable an authentication mount.",
        sudo: true,
        unauthenticated: false,
    },
    Route {
        path: "/sys/mounts",
        methods: &["get"],
        description: "List secret-engine mounts.",
        sudo: false,
        unauthenticated: false,
    },
    Route {
        path: "/sys/mounts/{path}",
        methods: &["get", "post", "delete"],
        description: "Read, enable or disable a secret-engine mount.",
        sudo: false,
        unauthenticated: false,
    },
    Route {
        path: "/sys/remount",
        methods: &["post"],
        description: "Move an authentication or secret-engine mount.",
        sudo: true,
        unauthenticated: false,
    },
    Route {
        path: "/sys/remount/status/{migration_id}",
        methods: &["get"],
        description: "Check the status of a mount move operation.",
        sudo: false,
        unauthenticated: false,
    },
    Route {
        path: "/sys/plugins/catalog/secret",
        methods: &["get"],
        description: "List deployment-admitted read-only secret plugins.",
        sudo: true,
        unauthenticated: false,
    },
    Route {
        path: "/sys/plugins/catalog/secret/{name}",
        methods: &["get"],
        description: "Inspect one deployment-admitted read-only secret plugin.",
        sudo: true,
        unauthenticated: false,
    },
    Route {
        path: "/sys/policies/acl",
        methods: &["get"],
        description: "List ACL policies.",
        sudo: false,
        unauthenticated: false,
    },
    Route {
        path: "/sys/policies/acl/{name}",
        methods: &["get", "post", "delete"],
        description: "Read or mutate one ACL policy.",
        sudo: false,
        unauthenticated: false,
    },
    Route {
        path: "/sys/capabilities-self",
        methods: &["post"],
        description: "Evaluate capabilities for the calling token.",
        sudo: false,
        unauthenticated: false,
    },
    Route {
        path: "/sys/leases/lookup",
        methods: &["post"],
        description: "Look up a durable lease.",
        sudo: false,
        unauthenticated: false,
    },
    Route {
        path: "/sys/leases/renew",
        methods: &["post"],
        description: "Renew a durable lease.",
        sudo: false,
        unauthenticated: false,
    },
    Route {
        path: "/sys/leases/revoke",
        methods: &["post"],
        description: "Revoke a durable lease.",
        sudo: false,
        unauthenticated: false,
    },
    Route {
        path: "/sys/wrapping/lookup",
        methods: &["get", "post"],
        description: "Inspect response-wrapping metadata.",
        sudo: false,
        unauthenticated: true,
    },
    Route {
        path: "/sys/wrapping/unwrap",
        methods: &["post"],
        description: "Consume a response-wrapping token.",
        sudo: false,
        unauthenticated: false,
    },
    Route {
        path: "/auth/token/create",
        methods: &["post"],
        description: "Create a service token.",
        sudo: false,
        unauthenticated: false,
    },
    Route {
        path: "/auth/token/lookup-self",
        methods: &["get", "post"],
        description: "Read the calling token.",
        sudo: false,
        unauthenticated: false,
    },
    Route {
        path: "/auth/token/revoke",
        methods: &["post"],
        description: "Revoke a token and its descendants according to token semantics.",
        sudo: false,
        unauthenticated: false,
    },
    Route {
        path: "/identity/entity",
        methods: &["post"],
        description: "Create an identity entity.",
        sudo: false,
        unauthenticated: false,
    },
    Route {
        path: "/identity/entity/id",
        methods: &["get"],
        description: "List identity entity IDs.",
        sudo: false,
        unauthenticated: false,
    },
    Route {
        path: "/identity/entity/id/{id}",
        methods: &["get", "post", "delete"],
        description: "Read or mutate an identity entity.",
        sudo: false,
        unauthenticated: false,
    },
    Route {
        path: "/identity/entity-alias",
        methods: &["post"],
        description: "Create an identity alias bound to an auth accessor.",
        sudo: false,
        unauthenticated: false,
    },
    Route {
        path: "/identity/group",
        methods: &["post"],
        description: "Create an identity group.",
        sudo: false,
        unauthenticated: false,
    },
    Route {
        path: "/identity/group/id",
        methods: &["get"],
        description: "List identity group IDs.",
        sudo: false,
        unauthenticated: false,
    },
    Route {
        path: "/identity/group/id/{id}",
        methods: &["get", "post", "delete"],
        description: "Read or mutate an identity group.",
        sudo: false,
        unauthenticated: false,
    },
    Route {
        path: "/sys/internal/specs/openapi",
        methods: &["get", "post"],
        description: "Generate the bounded OpenAPI document for implemented HeptaBao routes.",
        sudo: false,
        unauthenticated: true,
    },
];

fn path_parameters(path: &str) -> Vec<Value> {
    let mut result = Vec::new();
    let mut remaining = path;
    while let Some(open) = remaining.find('{') {
        let after = &remaining[open + 1..];
        let Some(close) = after.find('}') else {
            break;
        };
        let name = &after[..close];
        result.push(json!({
            "name": name,
            "in": "path",
            "required": true,
            "schema": {"type":"string"}
        }));
        remaining = &after[close + 1..];
    }
    result
}

fn add_route_parts(
    paths: &mut Map<String, Value>,
    path: &str,
    methods: &[&str],
    description: &str,
    sudo: bool,
    unauthenticated: bool,
) {
    let mut item = Map::new();
    let parameters = path_parameters(path);
    if !parameters.is_empty() {
        item.insert("parameters".into(), Value::Array(parameters));
    }
    item.insert("description".into(), Value::String(description.into()));
    // ca305 framework.OASPathItem stores these flags on the path item.
    if sudo {
        item.insert("x-vault-sudo".into(), Value::Bool(true));
    }
    if unauthenticated {
        item.insert("x-vault-unauthenticated".into(), Value::Bool(true));
    }
    for method in methods {
        let mut operation = Map::new();
        operation.insert("summary".into(), Value::String(description.into()));
        operation.insert("tags".into(), json!(["heptabao"]));
        operation.insert(
            "responses".into(),
            json!({
                "200":{"description":"OK"},
                "400":{"description":"Invalid request"},
                "403":{"description":"Permission denied"},
                "404":{"description":"Not found"}
            }),
        );
        if unauthenticated {
            operation.insert("security".into(), Value::Array(Vec::new()));
        }
        item.insert((*method).into(), Value::Object(operation));
    }
    paths.insert(path.into(), Value::Object(item));
}

fn add_route(paths: &mut Map<String, Value>, route: &Route) {
    add_route_parts(
        paths,
        route.path,
        route.methods,
        route.description,
        route.sudo,
        route.unauthenticated,
    );
}

fn add_list_query(paths: &mut Map<String, Value>, path: &str, scan: bool, read: bool) {
    if let Some(operation) = paths
        .get_mut(path)
        .and_then(|item| item.get_mut("get"))
        .and_then(Value::as_object_mut)
    {
        let mut parameters = Vec::new();
        for name in if scan {
            &["list", "scan"][..]
        } else {
            &["list"][..]
        } {
            let description = if read {
                if *name == "scan" {
                    "Return a recursive list if `true`"
                } else {
                    "Return a list if `true`"
                }
            } else if scan {
                if *name == "scan" {
                    "Must be set to `true` or else `list` must be set to `true`"
                } else {
                    "Must be set to `true` or else `scan` must be set to `true`"
                }
            } else {
                "Must be set to `true`"
            };
            let mut parameter = json!({"name":name,"in":"query","description":description,"schema":{"type":"string"}});
            if !read {
                parameter["required"] = Value::Bool(true);
                parameter["schema"]["enum"] = json!(["true"]);
            }
            parameters.push(parameter);
        }
        operation.insert("parameters".into(), Value::Array(parameters));
    }
}

fn add_implemented_control_and_identity_routes(paths: &mut Map<String, Value>) {
    // Canonical OAS methods from actual dispatch; no new execution authority.
    for (path, methods) in [
        ("/sys/capabilities", &["post"][..]),
        ("/sys/capabilities-accessor", &["post"][..]),
        ("/sys/namespaces", &["get"][..]),
        (
            "/sys/namespaces/{path}",
            &["get", "post", "patch", "delete"][..],
        ),
        ("/sys/policy", &["get"][..]),
        ("/sys/policy/{name}", &["get", "post", "delete"][..]),
        ("/sys/wrapping/wrap", &["post"][..]),
        ("/sys/wrapping/rewrap", &["post"][..]),
        ("/sys/seal", &["post"][..]),
        ("/sys/step-down", &["post"][..]),
        ("/identity/entity/merge", &["post"][..]),
        ("/identity/entity/name", &["get"][..]),
        (
            "/identity/entity/name/{name}",
            &["get", "post", "delete"][..],
        ),
        ("/identity/entity-alias/id", &["get"][..]),
        (
            "/identity/entity-alias/id/{id}",
            &["get", "post", "delete"][..],
        ),
        ("/identity/group/name", &["get"][..]),
        (
            "/identity/group/name/{name}",
            &["get", "post", "delete"][..],
        ),
        ("/identity/group-alias", &["post"][..]),
        ("/identity/group-alias/id", &["get"][..]),
        (
            "/identity/group-alias/id/{id}",
            &["get", "post", "delete"][..],
        ),
        ("/identity/lookup/entity", &["post"][..]),
        ("/identity/lookup/group", &["post"][..]),
    ] {
        add_route_parts(
            paths,
            path,
            methods,
            "Implemented control or identity operation.",
            false,
            false,
        );
    }
    add_list_query(paths, "/identity/entity/name", false, false);
    add_list_query(paths, "/identity/entity-alias/id", false, false);
    add_list_query(paths, "/identity/group/name", false, false);
    add_list_query(paths, "/identity/group-alias/id", false, false);
    add_list_query(paths, "/sys/policy", false, true);
    if let Some(item) = paths
        .get_mut("/sys/namespaces")
        .and_then(Value::as_object_mut)
        && let Some(get) = item.get_mut("get").and_then(Value::as_object_mut)
    {
        get.insert("parameters".into(), json!([
            {"name":"list", "in":"query", "required":true, "description":"Must be set to `true` or else `scan` must be set to `true`", "schema":{"type":"string", "enum":["true"]}},
            {"name":"scan", "in":"query", "required":true, "description":"Must be set to `true` or else `list` must be set to `true`", "schema":{"type":"string", "enum":["true"]}}
        ]));
    }
}

fn add_token_routes(paths: &mut Map<String, Value>) {
    for (suffix, methods, description, sudo) in [
        ("accessors", &["get"][..], "List token accessors.", true),
        (
            "create-orphan",
            &["post"][..],
            "Create an orphan service token.",
            false,
        ),
        (
            "create/{role_name}",
            &["post"][..],
            "Create a token from one stored token role.",
            false,
        ),
        (
            "lookup",
            &["get", "post"][..],
            "Read a selected token.",
            false,
        ),
        (
            "lookup-accessor",
            &["post"][..],
            "Read a token through its accessor.",
            false,
        ),
        ("renew", &["post"][..], "Renew a selected token.", false),
        (
            "renew-accessor",
            &["post"][..],
            "Renew a token through its accessor.",
            false,
        ),
        (
            "renew-self",
            &["post"][..],
            "Renew the calling token.",
            false,
        ),
        (
            "revoke-accessor",
            &["post"][..],
            "Revoke a token through its accessor.",
            false,
        ),
        (
            "revoke-orphan",
            &["post"][..],
            "Revoke a token while preserving its orphaned children.",
            false,
        ),
        (
            "revoke-self",
            &["post"][..],
            "Revoke the calling service token.",
            false,
        ),
        ("roles", &["get"][..], "List token roles.", false),
        (
            "roles/{role_name}",
            &["get", "post", "delete"][..],
            "Read, configure or remove a token role.",
            false,
        ),
        ("tidy", &["post"][..], "Retire stale token records.", false),
    ] {
        add_route_parts(
            paths,
            &format!("/auth/token/{suffix}"),
            methods,
            description,
            sudo,
            false,
        );
    }
    for path in [
        "/auth/token/accessors",
        "/auth/token/roles",
        "/identity/entity/id",
        "/identity/group/id",
        "/sys/policies/acl",
    ] {
        add_list_query(paths, path, false, false);
    }
    if let Some(route) = paths
        .get_mut("/auth/token/roles/{role_name}")
        .and_then(Value::as_object_mut)
    {
        route.insert("x-vault-createSupported".into(), Value::Bool(true));
    }
}

fn openapi_mount_path(mount: &str, generic: bool, auth: bool) -> String {
    let actual = mount.trim_end_matches('/');
    if !generic {
        return actual.to_owned();
    }
    let relative = if auth {
        actual.strip_prefix("auth/").unwrap_or(actual)
    } else {
        actual
    };
    let name = relative.replace('-', "_");
    let parameter = format!("{{{name}_mount_path}}");
    if auth {
        format!("auth/{parameter}")
    } else {
        parameter
    }
}

fn add_mount_route(
    paths: &mut Map<String, Value>,
    path: String,
    methods: &[&str],
    description: &str,
    mount: &str,
    generic: bool,
    auth: bool,
) {
    // Test the backend-relative suffix; a mount named login/... is ordinary.
    let prefix = format!("/{}/", openapi_mount_path(mount, generic, auth));
    let relative = path.strip_prefix(&prefix).unwrap_or("");
    let anonymous = auth && (relative == "login" || relative.starts_with("login/"));
    add_route_parts(paths, &path, methods, description, false, anonymous);
    if generic {
        let actual = mount.trim_end_matches('/');
        let relative = if auth {
            actual.strip_prefix("auth/").unwrap_or(actual)
        } else {
            actual
        };
        let name = format!("{}_mount_path", relative.replace('-', "_"));
        if let Some(item) = paths.get_mut(&path).and_then(Value::as_object_mut) {
            let parameters = item
                .entry("parameters")
                .or_insert_with(|| Value::Array(Vec::new()));
            if let Some(parameters) = parameters.as_array_mut() {
                // Preserve backend path parameters and append the actual mount
                // parameter, as OpenBao ca305 logical_system.go4408..4446 does.
                parameters.retain(|parameter| {
                    parameter.get("name").and_then(Value::as_str) != Some(name.as_str())
                });
                parameters.push(json!({
                    "name": name,
                    "description": "Path that the backend was mounted at",
                    "in": "path",
                    "schema": {"type": "string", "default": relative},
                    "required": true
                }));
            }
        }
    }
}

fn qualify_kv_openapi(value: &mut Value) {
    match value {
        Value::Object(object) => {
            for (key, value) in object {
                match (key.as_str(), value) {
                    ("$ref", Value::String(reference))
                        if reference.starts_with("#/components/schemas/") =>
                    {
                        *reference = format!(
                            "#/components/schemas/Kv{}",
                            &reference["#/components/schemas/".len()..]
                        );
                    }
                    ("operationId", Value::String(operation)) => {
                        *operation = format!("kv-{operation}");
                    }
                    (_, nested) => qualify_kv_openapi(nested),
                }
            }
        }
        Value::Array(items) => {
            for item in items {
                qualify_kv_openapi(item);
            }
        }
        _ => {}
    }
}

fn add_kv_help_document(
    paths: &mut Map<String, Value>,
    schemas: &mut Map<String, Value>,
    mount: &str,
    generic: bool,
    version_two: bool,
) -> Result<(), ()> {
    // Use the same pinned 2.7.0 backend help document as actual HELP requests.
    // Its empty catch-all path item declares no unsupported operation.
    let template = if version_two {
        include_str!("help_templates/kv2-root.json")
    } else {
        include_str!("help_templates/kv1-root.json")
    };
    let mut help: Value = serde_json::from_str(template).map_err(|_| ())?;
    let document = help.get_mut("openapi").ok_or(())?;
    qualify_kv_openapi(document);
    let backend_paths = document.get("paths").and_then(Value::as_object).ok_or(())?;
    let prefix = openapi_mount_path(mount, generic, false);
    for (suffix, item) in backend_paths {
        let path = format!("/{prefix}{suffix}");
        let mut item = item.clone();
        if generic {
            let parameter_name = format!(
                "{}_mount_path",
                mount.trim_end_matches('/').replace('-', "_")
            );
            let object = item.as_object_mut().ok_or(())?;
            let parameters = object
                .entry("parameters")
                .or_insert_with(|| Value::Array(Vec::new()))
                .as_array_mut()
                .ok_or(())?;
            parameters.push(json!({
                "name": parameter_name,
                "description": "Path that the backend was mounted at",
                "in": "path",
                "schema": {"type": "string", "default": mount.trim_end_matches('/')},
                "required": true
            }));
        }
        paths.insert(path, item);
    }
    let backend_schemas = document
        .get("components")
        .and_then(|components| components.get("schemas"))
        .and_then(Value::as_object)
        .ok_or(())?;
    for (name, schema) in backend_schemas {
        let name = format!("Kv{name}");
        if let Some(previous) = schemas.get(&name)
            && previous != schema
        {
            return Err(());
        }
        schemas.insert(name, schema.clone());
    }
    Ok(())
}

fn add_actual_mount_routes(
    paths: &mut Map<String, Value>,
    schemas: &mut Map<String, Value>,
    generic: bool,
    auth_mounts: &BTreeMap<String, Value>,
    secret_mounts: &BTreeMap<String, Value>,
) -> Result<(), ()> {
    for (mount, descriptor) in secret_mounts {
        let kind = descriptor.get("type").and_then(Value::as_str);
        match kind {
            Some("kv") => {
                add_kv_help_document(
                    paths,
                    schemas,
                    mount,
                    generic,
                    descriptor["options"]["version"] == "2",
                )?;
            }
            Some("transit") => {
                let prefix = openapi_mount_path(mount, generic, false);
                for (suffix, methods, description) in [
                    (
                        "keys/{name}",
                        &["get", "post", "delete"][..],
                        "Read, create or delete a Transit key.",
                    ),
                    (
                        "encrypt/{name}",
                        &["post"][..],
                        "Encrypt bounded plaintext with a Transit key.",
                    ),
                    (
                        "decrypt/{name}",
                        &["post"][..],
                        "Decrypt bounded Transit ciphertext.",
                    ),
                ] {
                    add_mount_route(
                        paths,
                        format!("/{prefix}/{suffix}"),
                        methods,
                        description,
                        mount,
                        generic,
                        false,
                    );
                }
            }
            _ => {}
        }
    }
    for (mount, descriptor) in auth_mounts {
        let kind = descriptor.get("type").and_then(Value::as_str);
        match kind {
            Some("userpass") => {
                let prefix = openapi_mount_path(mount, generic, true);
                add_mount_route(
                    paths,
                    format!("/{prefix}/users/{{username}}"),
                    &["get", "post", "delete"],
                    "Manage a userpass principal.",
                    mount,
                    generic,
                    true,
                );
                add_mount_route(
                    paths,
                    format!("/{prefix}/login/{{username}}"),
                    &["post"],
                    "Authenticate a userpass principal.",
                    mount,
                    generic,
                    true,
                );
                for (suffix, methods, description) in [
                    ("users", &["get"][..], "List userpass principals."),
                    (
                        "users/{username}/password",
                        &["post"][..],
                        "Change one userpass password.",
                    ),
                    (
                        "users/{username}/policies",
                        &["post"][..],
                        "Change one userpass policy set.",
                    ),
                ] {
                    add_mount_route(
                        paths,
                        format!("/{prefix}/{suffix}"),
                        methods,
                        description,
                        mount,
                        generic,
                        true,
                    );
                }
                add_list_query(paths, &format!("/{prefix}/users"), false, false);
            }
            Some("approle") => {
                approle::add(paths, schemas, mount, generic)?;
            }
            _ => {}
        }
    }
    Ok(())
}

pub(super) fn handle_anonymous(
    method: &str,
    body: &Value,
    auth_mounts: &BTreeMap<String, Value>,
    secret_mounts: &BTreeMap<String, Value>,
) -> Response {
    handle_with_visibility(method, body, false, true, auth_mounts, secret_mounts)
}

pub(super) fn handle(
    method: &str,
    body: &Value,
    root_visibility: bool,
    auth_mounts: &BTreeMap<String, Value>,
    secret_mounts: &BTreeMap<String, Value>,
) -> Response {
    handle_with_visibility(
        method,
        body,
        root_visibility,
        false,
        auth_mounts,
        secret_mounts,
    )
}

fn handle_with_visibility(
    method: &str,
    body: &Value,
    root_visibility: bool,
    anonymous_visibility: bool,
    auth_mounts: &BTreeMap<String, Value>,
    secret_mounts: &BTreeMap<String, Value>,
) -> Response {
    if !matches!(method, "GET" | "POST") {
        return Response::error(405, "OpenAPI document requires GET or POST");
    }
    let Some(object) = body.as_object() else {
        return Response::error(400, "OpenAPI parameters must be a JSON object");
    };
    if object.keys().any(|key| key != "generic_mount_paths") {
        return Response::error(400, "unsupported OpenAPI parameter");
    }
    let generic = match object.get("generic_mount_paths") {
        None | Some(Value::Null) => false,
        Some(Value::Bool(value)) => *value,
        Some(Value::String(value)) => match value.as_str() {
            "1" | "t" | "T" | "TRUE" | "true" | "True" => true,
            "" | "0" | "f" | "F" | "FALSE" | "false" | "False" => false,
            _ => return Response::error(400, "generic_mount_paths must be a boolean"),
        },
        // The native HTTP decoder uses json.Number. Weak bool conversion
        // therefore parses its lexical integer 0/1 rather than numeric truth.
        Some(Value::Number(value)) => match value.to_string().as_str() {
            "0" => false,
            "1" => true,
            _ => return Response::error(400, "generic_mount_paths must be a boolean"),
        },
        Some(_) => {
            return Response::error(400, "generic_mount_paths must be a boolean");
        }
    };

    // Default anonymous discovery remains empty. Only actual mounts explicitly
    // configured for unauthenticated listing can enter this projection.
    if anonymous_visibility && auth_mounts.is_empty() && secret_mounts.is_empty() {
        return Response::ok(json!({
            "openapi": "3.0.2",
            "info": {
                "title": "HeptaBao API",
                "description": "HTTP API for HeptaBao.",
                "version": "0.1.0",
                "license": {"name": "Apache License 2.0"}
            },
            "paths": {},
            "components": {"schemas": {}}
        }));
    }

    let mut paths = Map::new();
    for route in FIXED_ROUTES {
        add_route(&mut paths, route);
    }
    add_implemented_control_and_identity_routes(&mut paths);
    add_token_routes(&mut paths);
    if !root_visibility {
        paths.retain(|path, _| {
            let path = path.trim_start_matches('/');
            auth_mounts
                .keys()
                .chain(secret_mounts.keys())
                .any(|mount| path == mount.trim_end_matches('/') || path.starts_with(mount))
        });
    }
    let mut schemas = Map::new();
    if add_actual_mount_routes(
        &mut paths,
        &mut schemas,
        generic,
        auth_mounts,
        secret_mounts,
    )
    .is_err()
    {
        return Response::error(503, "OpenAPI backend help template rejected");
    }

    Response::ok(json!({
        "openapi": "3.0.2",
        "info": {
            "title": "HeptaBao API",
            "description": "HTTP API for the currently implemented HeptaBao runtime. All API routes are prefixed with /v1/. This document is intentionally bounded and does not advertise unsupported OpenBao surfaces.",
            "version": "0.1.0",
            "license": {
                "name": "Apache License 2.0"
            }
        },
        "security": [{"VaultToken": []}],
        "paths": paths,
        "components": {
            "schemas": schemas,
            "securitySchemes": {
                "VaultToken": {
                    "type": "apiKey",
                    "in": "header",
                    "name": "X-Vault-Token"
                }
            }
        },
        "x-heptabao-bounded": true,
        "x-heptabao-policy-filtering": "current_mount_acl_or_unauth_listing",
        "x-heptabao-generic-mount-paths": generic
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    fn handle(method: &str, body: &Value, root_visibility: bool) -> Response {
        let auth_mounts = BTreeMap::from([
            ("auth/userpass/".into(), json!({"type":"userpass"})),
            ("auth/approle/".into(), json!({"type":"approle"})),
        ]);
        let secret_mounts = BTreeMap::from([
            (
                "secret/".into(),
                json!({"type":"kv","options":{"version":"2"}}),
            ),
            ("transit/".into(), json!({"type":"transit"})),
        ]);
        super::handle(method, body, root_visibility, &auth_mounts, &secret_mounts)
    }

    #[test]
    fn generated_document_is_deterministic_and_does_not_advertise_unimplemented_auth()
    -> Result<(), Box<dyn std::error::Error>> {
        let first = handle("POST", &json!({"generic_mount_paths":true}), true);
        let second = handle("POST", &json!({"generic_mount_paths":true}), true);
        assert_eq!(first.status, 200);
        assert_eq!(second.status, 200);
        assert_eq!(first.body, second.body);
        let paths = first.body["paths"]
            .as_object()
            .ok_or("missing OpenAPI paths")?;
        assert!(paths.contains_key("/sys/health"));
        assert!(paths.contains_key("/{secret_mount_path}/data/{path}"));
        assert!(paths.contains_key("/auth/{userpass_mount_path}/login/{username}"));
        assert!(paths.contains_key("/auth/{approle_mount_path}/role/{role_name}/custom-secret-id"));
        assert!(paths.contains_key("/sys/plugins/catalog/secret"));
        assert!(paths.contains_key("/sys/plugins/catalog/secret/{name}"));
        assert!(!paths.keys().any(|path| {
            path.contains("cert_mount_path")
                || path.contains("radius")
                || path.contains("kerberos")
                || path.contains("rabbitmq")
                || path.contains("openldap")
        }));
        Ok(())
    }

    #[test]
    fn openapi_generic_mounts_preserve_distinct_actual_names_and_parameter_defaults()
    -> Result<(), Box<dyn std::error::Error>> {
        let auth_mounts = BTreeMap::from([
            ("auth/team-a/accounts/".into(), json!({"type":"userpass"})),
            ("auth/team-b/accounts/".into(), json!({"type":"userpass"})),
        ]);
        let secret_mounts = BTreeMap::from([
            (
                "applications/config-v2/".into(),
                json!({"type":"kv","options":{"version":"2"}}),
            ),
            (
                "applications/plain-v1/".into(),
                json!({"type":"kv","options":{"version":"1"}}),
            ),
        ]);
        let document = super::handle(
            "POST",
            &json!({"generic_mount_paths":true}),
            true,
            &auth_mounts,
            &secret_mounts,
        );
        assert_eq!(document.status, 200);
        let paths = document.body["paths"].as_object().ok_or("missing paths")?;
        for (path, name, actual) in [
            (
                "/auth/{team_a/accounts_mount_path}/login/{username}",
                "team_a/accounts_mount_path",
                "team-a/accounts",
            ),
            (
                "/auth/{team_b/accounts_mount_path}/login/{username}",
                "team_b/accounts_mount_path",
                "team-b/accounts",
            ),
            (
                "/{applications/config_v2_mount_path}/data/{path}",
                "applications/config_v2_mount_path",
                "applications/config-v2",
            ),
            (
                "/{applications/plain_v1_mount_path}/{path}",
                "applications/plain_v1_mount_path",
                "applications/plain-v1",
            ),
        ] {
            let route = paths.get(path).ok_or("mounted route omitted")?;
            let parameters = route["parameters"].as_array().ok_or("missing parameters")?;
            assert_eq!(parameters.len(), 2);
            let backend_parameter = if path.ends_with("/{username}") {
                "username"
            } else {
                "path"
            };
            assert_eq!(parameters[0]["name"], backend_parameter);
            assert_eq!(parameters[0]["in"], "path");
            assert_eq!(parameters[0]["required"], true);
            assert_eq!(
                parameters[1],
                json!({
                    "name":name, "description":"Path that the backend was mounted at",
                    "in":"path", "schema":{"type":"string","default":actual}, "required":true
                })
            );
        }
        assert!(!paths.contains_key("/auth/{userpass_mount_path}/login/{username}"));
        assert!(!paths.contains_key("/{kv_mount_path}/data/{path}"));
        Ok(())
    }

    #[test]
    fn invalid_parameters_and_methods_fail_closed() {
        assert_eq!(handle("DELETE", &json!({}), true).status, 405);
        assert_eq!(
            handle("POST", &json!({"generic_mount_paths":"yes"}), true).status,
            400
        );
        assert_eq!(handle("POST", &json!({"unknown":true}), true).status, 400);
    }

    #[test]
    fn generic_mount_paths_weak_boolean_matches_actual_native_fields()
    -> Result<(), Box<dyn std::error::Error>> {
        for (value, expected) in [
            (Value::Null, false),
            (json!(true), true),
            (json!(false), false),
            (json!("true"), true),
            (json!("True"), true),
            (json!("t"), true),
            (json!("1"), true),
            (json!("false"), false),
            (json!("0"), false),
            (json!(""), false),
            (json!(0), false),
            (json!(1), true),
        ] {
            let response = handle("POST", &json!({"generic_mount_paths":value}), true);
            assert_eq!(response.status, 200);
            assert_eq!(response.body["x-heptabao-generic-mount-paths"], expected);
        }
        for value in [
            json!("yes"),
            json!("2"),
            json!(2),
            json!(-1),
            json!(0.5),
            json!([]),
            json!({}),
        ] {
            assert_eq!(
                handle("POST", &json!({"generic_mount_paths":value}), true).status,
                400
            );
        }
        Ok(())
    }

    #[test]
    fn non_root_document_contains_only_actual_projected_mounts()
    -> Result<(), Box<dyn std::error::Error>> {
        let response = handle("GET", &json!({}), false);
        assert_eq!(response.status, 200);
        assert_eq!(
            response.body["x-heptabao-policy-filtering"],
            "current_mount_acl_or_unauth_listing"
        );
        let paths = response.body["paths"]
            .as_object()
            .ok_or("missing OpenAPI paths")?;
        assert!(!paths.contains_key("/sys/health"));
        assert!(!paths.contains_key("/sys/internal/specs/openapi"));
        assert!(paths.contains_key("/secret/data/{path}"));
        assert!(paths.contains_key("/auth/userpass/login/{username}"));
        assert!(!paths.contains_key("/auth/token/create"));
        assert!(!paths.contains_key("/identity/entity"));
        Ok(())
    }

    fn kv2_primary_fixture() -> Result<Value, Box<dyn std::error::Error>> {
        Ok(serde_json::from_str(include_str!(
            "testdata/openapi-kv2-270-independent-documents.json"
        ))?)
    }

    #[test]
    fn openapi_kv2_routes_and_schemas_match_actual_primary270_complete_document()
    -> Result<(), Box<dyn std::error::Error>> {
        let reference = kv2_primary_fixture()?;
        let mounts = BTreeMap::from([(
            "diag-visible/".into(),
            json!({"type":"kv","options":{"version":"2"}}),
        )]);
        let response = handle_anonymous("GET", &json!({}), &BTreeMap::new(), &mounts);
        assert_eq!(response.status, 200);
        assert_eq!(response.body["paths"], reference["plain_paths"]);
        assert_eq!(response.body["components"]["schemas"], reference["schemas"]);
        assert_eq!(response.body["paths"]["/diag-visible/^.*$"], json!({}));
        Ok(())
    }

    #[test]
    fn openapi_kv2_generic_mount_and_refs_match_actual_primary270_document()
    -> Result<(), Box<dyn std::error::Error>> {
        let reference = kv2_primary_fixture()?;
        let mounts = BTreeMap::from([(
            "diag-visible/".into(),
            json!({"type":"kv","options":{"version":"2"}}),
        )]);
        let response = handle_anonymous(
            "GET",
            &json!({"generic_mount_paths":true}),
            &BTreeMap::new(),
            &mounts,
        );
        assert_eq!(response.status, 200);
        assert_eq!(response.body["paths"], reference["generic_paths"]);
        assert_eq!(response.body["components"]["schemas"], reference["schemas"]);
        Ok(())
    }

    #[test]
    fn openapi_kv2_two_actual_mounts_share_schemas_and_do_not_retain_old_paths()
    -> Result<(), Box<dyn std::error::Error>> {
        let reference = kv2_primary_fixture()?;
        let mounts = BTreeMap::from([
            (
                "new-a/".into(),
                json!({"type":"kv","options":{"version":"2"}}),
            ),
            (
                "new-b/".into(),
                json!({"type":"kv","options":{"version":"2"}}),
            ),
        ]);
        let response = handle_anonymous("GET", &json!({}), &BTreeMap::new(), &mounts);
        assert_eq!(response.status, 200);
        assert_eq!(response.body["components"]["schemas"], reference["schemas"]);
        let paths = response.body["paths"].as_object().ok_or("paths")?;
        let expected = reference["plain_paths"]
            .as_object()
            .ok_or("reference paths")?;
        assert_eq!(paths.len(), expected.len() * 2);
        for mount in ["new-a", "new-b"] {
            for (path, item) in expected {
                let suffix = path.strip_prefix("/diag-visible").ok_or("original mount")?;
                assert_eq!(paths.get(&format!("/{mount}{suffix}")), Some(item));
            }
        }
        assert!(paths.keys().all(|path| !path.contains("diag-visible")));
        Ok(())
    }

    fn approle_primary_fixture() -> Result<Value, Box<dyn std::error::Error>> {
        Ok(serde_json::from_str(include_str!(
            "testdata/openapi-approle-270-independent-selected.json"
        ))?)
    }

    #[test]
    fn openapi_approle_existing_credential_routes_match_independent_primary_metadata()
    -> Result<(), Box<dyn std::error::Error>> {
        let reference = approle_primary_fixture()?;
        let mounts = BTreeMap::from([("auth/diag-approle/".into(), json!({"type":"approle"}))]);
        let response = handle_anonymous("GET", &json!({}), &mounts, &BTreeMap::new());
        assert_eq!(response.status, 200);
        let paths = response.body["paths"].as_object().ok_or("paths")?;
        for (path, expected) in reference["paths"].as_object().ok_or("reference paths")? {
            assert_eq!(paths.get(path), Some(expected));
        }
        for (name, expected) in reference["schemas"]
            .as_object()
            .ok_or("reference schemas")?
        {
            assert_eq!(
                response.body["components"]["schemas"].get(name),
                Some(expected)
            );
        }
        let accessor_destroy = paths
            .get("/auth/diag-approle/role/{role_name}/secret-id-accessor/destroy")
            .ok_or("destroy")?;
        assert!(accessor_destroy.get("post").is_some());
        assert!(accessor_destroy.get("delete").is_none());
        assert!(
            paths
                .get("/auth/diag-approle/role/{role_name}/secret-id")
                .and_then(|item| item.get("get"))
                .is_some()
        );
        assert!(
            paths
                .get("/auth/diag-approle/tidy/secret-id")
                .and_then(|item| item.get("post"))
                .is_some()
        );
        Ok(())
    }

    #[test]
    fn openapi_approle_generic_current_mount_preserves_backend_role_parameter()
    -> Result<(), Box<dyn std::error::Error>> {
        let reference = approle_primary_fixture()?;
        let mounts = BTreeMap::from([("auth/new-role/".into(), json!({"type":"approle"}))]);
        let response = handle_anonymous(
            "GET",
            &json!({"generic_mount_paths":true}),
            &mounts,
            &BTreeMap::new(),
        );
        assert_eq!(response.status, 200);
        let paths = response.body["paths"].as_object().ok_or("paths")?;
        assert!(paths.keys().all(|path| !path.contains("diag-approle")));
        let item = paths
            .get("/auth/{new_role_mount_path}/role/{role_name}/role-id")
            .ok_or("role-id")?;
        let parameters = item["parameters"].as_array().ok_or("parameters")?;
        assert_eq!(parameters.len(), 2);
        assert_eq!(
            parameters[0],
            reference["paths"]["/auth/diag-approle/role/{role_name}/role-id"]["parameters"][0]
        );
        assert_eq!(
            parameters[1],
            json!({
                "name":"new_role_mount_path", "description":"Path that the backend was mounted at",
                "in":"path", "schema":{"type":"string","default":"new-role"}, "required":true
            })
        );
        Ok(())
    }

    #[test]
    fn openapi_approle_does_not_advertise_unimplemented_attributes_or_unknown_role_fields()
    -> Result<(), Box<dyn std::error::Error>> {
        let mounts = BTreeMap::from([("auth/diag-approle/".into(), json!({"type":"approle"}))]);
        let response = handle_anonymous("GET", &json!({}), &mounts, &BTreeMap::new());
        assert_eq!(response.status, 200);
        let paths = response.body["paths"].as_object().ok_or("paths")?;
        assert!(!paths.contains_key("/auth/diag-approle/role/{role_name}/local-secret-ids"));
        assert!(!paths.contains_key("/auth/diag-approle/role/{role_name}/token-ttl"));
        let schemas = response.body["components"]["schemas"]
            .as_object()
            .ok_or("schemas")?;
        assert!(!schemas.contains_key("AppRoleReadLocalSecretIdsResponse"));
        assert!(!schemas.contains_key("AppRoleWriteTokenTtlRequest"));
        let write = schemas["AppRoleWriteRoleRequest"]["properties"]
            .as_object()
            .ok_or("write properties")?;
        for name in [
            "local_secret_ids",
            "role_id",
            "period",
            "token_no_default_policy",
            "token_strictly_bind_ip",
        ] {
            assert!(!write.contains_key(name));
        }
        assert!(write.contains_key("token_ttl") && write.contains_key("secret_id_bound_cidrs"));
        let read = schemas["AppRoleReadRoleResponse"]["properties"]
            .as_object()
            .ok_or("read properties")?;
        assert!(!read.contains_key("local_secret_ids") && !read.contains_key("policies"));
        let issue = schemas["AppRoleWriteSecretIdRequest"]["properties"]
            .as_object()
            .ok_or("issue properties")?;
        assert!(!issue.contains_key("after") && !issue.contains_key("limit"));
        assert!(issue.contains_key("ttl") && issue.contains_key("metadata"));
        Ok(())
    }
}
