use super::{Response, Value};
use serde_json::{Map, json};
use std::collections::BTreeMap;

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
        unauthenticated: false,
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
        unauthenticated: false,
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

fn add_actual_mount_routes(
    paths: &mut Map<String, Value>,
    generic: bool,
    auth_mounts: &BTreeMap<String, Value>,
    secret_mounts: &BTreeMap<String, Value>,
) {
    for (mount, descriptor) in secret_mounts {
        let kind = descriptor.get("type").and_then(Value::as_str);
        match kind {
            Some("kv") => {
                let prefix = openapi_mount_path(mount, generic, false);
                if descriptor["options"]["version"] == "2" {
                    add_mount_route(
                        paths,
                        format!("/{prefix}/data/{{path}}"),
                        &["get", "post", "patch", "delete"],
                        "Read, write or soft-delete a KV v2 value.",
                        mount,
                        generic,
                        false,
                    );
                    add_mount_route(
                        paths,
                        format!("/{prefix}/metadata/{{path}}"),
                        &["get", "post", "patch", "delete"],
                        "Read, tune or destroy KV v2 metadata.",
                        mount,
                        generic,
                        false,
                    );
                    add_list_query(paths, &format!("/{prefix}/metadata/{{path}}"), true, true);
                    for (suffix, methods, description) in [
                        (
                            "config",
                            &["get", "post"][..],
                            "Read or configure KV v2 settings.",
                        ),
                        (
                            "delete/{path}",
                            &["post"][..],
                            "Soft-delete selected KV v2 versions.",
                        ),
                        (
                            "undelete/{path}",
                            &["post"][..],
                            "Restore selected KV v2 versions.",
                        ),
                        (
                            "destroy/{path}",
                            &["post"][..],
                            "Permanently destroy selected KV v2 versions.",
                        ),
                        (
                            "subkeys/{path}",
                            &["get"][..],
                            "Read a KV v2 structure without stored values.",
                        ),
                        (
                            "detailed-metadata/{path}",
                            &["get"][..],
                            "List detailed KV v2 key metadata.",
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
                    add_list_query(
                        paths,
                        &format!("/{prefix}/detailed-metadata/{{path}}"),
                        true,
                        false,
                    );
                } else {
                    add_mount_route(
                        paths,
                        format!("/{prefix}/{{path}}"),
                        &["get", "post", "delete"],
                        "Read, write or delete a KV v1 value.",
                        mount,
                        generic,
                        false,
                    );
                }
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
                let prefix = openapi_mount_path(mount, generic, true);
                for (suffix, methods, description) in [
                    (
                        "role/{role_name}",
                        &["get", "post", "delete"][..],
                        "Manage an AppRole role.",
                    ),
                    (
                        "role/{role_name}/custom-secret-id",
                        &["post"][..],
                        "Issue a bounded operator-supplied AppRole SecretID.",
                    ),
                    (
                        "login",
                        &["post"][..],
                        "Authenticate with AppRole credentials.",
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
            }
            _ => {}
        }
    }
}

pub(super) fn handle(
    method: &str,
    body: &Value,
    root_visibility: bool,
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
        None => false,
        Some(Value::Bool(value)) => *value,
        Some(_) => {
            return Response::error(400, "generic_mount_paths must be a boolean");
        }
    };

    let mut paths = Map::new();
    for route in FIXED_ROUTES {
        if root_visibility || route.unauthenticated || route.path == "/sys/internal/specs/openapi" {
            add_route(&mut paths, route);
        }
    }

    if !root_visibility {
        return Response::ok(json!({
            "openapi": "3.0.2",
            "info": {
                "title": "HeptaBao API",
                "description": "Fail-closed OpenAPI view for a non-root caller. HeptaBao currently emits only unauthenticated routes plus the spec endpoint instead of over-advertising policy-visible paths it cannot yet derive exactly.",
                "version": "0.1.0",
                "license": {"name": "Apache License 2.0"}
            },
            "security": [{"VaultToken": []}],
            "paths": paths,
            "components": {
                "securitySchemes": {
                    "VaultToken": {
                        "type": "apiKey",
                        "in": "header",
                        "name": "X-Vault-Token"
                    }
                }
            },
            "x-heptabao-bounded": true,
            "x-heptabao-policy-filtering": "fail_closed_non_root_subset",
            "x-heptabao-generic-mount-paths": generic
        }));
    }

    add_token_routes(&mut paths);
    add_actual_mount_routes(&mut paths, generic, auth_mounts, secret_mounts);

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
            "securitySchemes": {
                "VaultToken": {
                    "type": "apiKey",
                    "in": "header",
                    "name": "X-Vault-Token"
                }
            }
        },
        "x-heptabao-bounded": true,
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
            handle("POST", &json!({"generic_mount_paths":"true"}), true).status,
            400
        );
        assert_eq!(handle("POST", &json!({"unknown":true}), true).status, 400);
    }

    #[test]
    fn non_root_document_fails_closed_instead_of_over_advertising()
    -> Result<(), Box<dyn std::error::Error>> {
        let response = handle("GET", &json!({}), false);
        assert_eq!(response.status, 200);
        assert_eq!(
            response.body["x-heptabao-policy-filtering"],
            "fail_closed_non_root_subset"
        );
        let paths = response.body["paths"]
            .as_object()
            .ok_or("missing OpenAPI paths")?;
        assert!(paths.contains_key("/sys/health"));
        assert!(paths.contains_key("/sys/internal/specs/openapi"));
        assert!(!paths.contains_key("/auth/token/create"));
        assert!(!paths.contains_key("/identity/entity"));
        Ok(())
    }
}
