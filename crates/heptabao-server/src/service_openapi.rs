use super::{Response, Value};
use serde_json::{Map, json};

struct Route {
    path: &'static str,
    methods: &'static [&'static str],
    description: &'static str,
    sudo: bool,
    unauthenticated: bool,
}

const FIXED_ROUTES: &[Route] = &[
    Route {
        path: "/sys/health",
        methods: &["get"],
        description: "Bounded server health status.",
        sudo: false,
        unauthenticated: true,
    },
    Route {
        path: "/sys/init",
        methods: &["get", "post", "put"],
        description: "Initialization status and one-time initialization.",
        sudo: false,
        unauthenticated: true,
    },
    Route {
        path: "/sys/unseal",
        methods: &["post", "put"],
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
        methods: &["get", "post", "put", "delete"],
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
        methods: &["post", "put", "delete"],
        description: "Enable or disable a secret-engine mount.",
        sudo: true,
        unauthenticated: false,
    },
    Route {
        path: "/sys/remount",
        methods: &["post", "put"],
        description: "Move an authentication or secret-engine mount.",
        sudo: true,
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
        methods: &["get", "post", "put", "delete"],
        description: "Read or mutate one ACL policy.",
        sudo: false,
        unauthenticated: false,
    },
    Route {
        path: "/sys/capabilities-self",
        methods: &["post", "put"],
        description: "Evaluate capabilities for the calling token.",
        sudo: false,
        unauthenticated: false,
    },
    Route {
        path: "/sys/leases/lookup",
        methods: &["post", "put"],
        description: "Look up a durable lease.",
        sudo: false,
        unauthenticated: false,
    },
    Route {
        path: "/sys/leases/renew",
        methods: &["post", "put"],
        description: "Renew a durable lease.",
        sudo: false,
        unauthenticated: false,
    },
    Route {
        path: "/sys/leases/revoke",
        methods: &["post", "put"],
        description: "Revoke a durable lease.",
        sudo: false,
        unauthenticated: false,
    },
    Route {
        path: "/sys/wrapping/lookup",
        methods: &["post", "put"],
        description: "Inspect response-wrapping metadata.",
        sudo: false,
        unauthenticated: false,
    },
    Route {
        path: "/sys/wrapping/unwrap",
        methods: &["post", "put"],
        description: "Consume a response-wrapping token.",
        sudo: false,
        unauthenticated: false,
    },
    Route {
        path: "/auth/token/create",
        methods: &["post", "put"],
        description: "Create a service token.",
        sudo: false,
        unauthenticated: false,
    },
    Route {
        path: "/auth/token/lookup-self",
        methods: &["get"],
        description: "Read the calling token.",
        sudo: false,
        unauthenticated: false,
    },
    Route {
        path: "/auth/token/revoke",
        methods: &["post", "put"],
        description: "Revoke a token and its descendants according to token semantics.",
        sudo: false,
        unauthenticated: false,
    },
    Route {
        path: "/identity/entity",
        methods: &["post", "put"],
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
        methods: &["get", "post", "put", "patch", "delete"],
        description: "Read or mutate an identity entity.",
        sudo: false,
        unauthenticated: false,
    },
    Route {
        path: "/identity/entity-alias",
        methods: &["post", "put"],
        description: "Create an identity alias bound to an auth accessor.",
        sudo: false,
        unauthenticated: false,
    },
    Route {
        path: "/identity/group",
        methods: &["post", "put"],
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
        methods: &["get", "post", "put", "patch", "delete"],
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
        if sudo {
            operation.insert("x-vault-sudo".into(), Value::Bool(true));
        }
        if unauthenticated {
            operation.insert("x-vault-unauthenticated".into(), Value::Bool(true));
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

fn add_mount_route(
    paths: &mut Map<String, Value>,
    path: String,
    methods: &[&str],
    description: &str,
) {
    add_route_parts(paths, &path, methods, description, false, false);
}

pub(super) fn handle(method: &str, body: &Value, root_visibility: bool) -> Response {
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

    let kv = if generic { "{kv_mount_path}" } else { "secret" };
    add_mount_route(
        &mut paths,
        format!("/{kv}/data/{{path}}"),
        &["get", "post", "delete"],
        "Read, write or soft-delete a KV v2 value.",
    );
    add_mount_route(
        &mut paths,
        format!("/{kv}/metadata/{{path}}"),
        &["get", "post", "delete"],
        "Read, tune or destroy KV v2 metadata.",
    );
    let transit = if generic {
        "{transit_mount_path}"
    } else {
        "transit"
    };
    add_mount_route(
        &mut paths,
        format!("/{transit}/keys/{{name}}"),
        &["get", "post", "delete"],
        "Read, create or delete a Transit key.",
    );
    add_mount_route(
        &mut paths,
        format!("/{transit}/encrypt/{{name}}"),
        &["post", "put"],
        "Encrypt bounded plaintext with a Transit key.",
    );
    add_mount_route(
        &mut paths,
        format!("/{transit}/decrypt/{{name}}"),
        &["post", "put"],
        "Decrypt bounded Transit ciphertext.",
    );
    let userpass = if generic {
        "{userpass_mount_path}"
    } else {
        "userpass"
    };
    add_mount_route(
        &mut paths,
        format!("/auth/{userpass}/users/{{username}}"),
        &["get", "post", "put", "delete"],
        "Manage a userpass principal.",
    );
    add_mount_route(
        &mut paths,
        format!("/auth/{userpass}/login/{{username}}"),
        &["post", "put"],
        "Authenticate a userpass principal.",
    );
    let approle = if generic {
        "{approle_mount_path}"
    } else {
        "approle"
    };
    add_mount_route(
        &mut paths,
        format!("/auth/{approle}/role/{{role_name}}"),
        &["get", "post", "put", "delete"],
        "Manage an AppRole role.",
    );
    add_mount_route(
        &mut paths,
        format!("/auth/{approle}/role/{{role_name}}/custom-secret-id"),
        &["post", "put"],
        "Issue a bounded operator-supplied AppRole SecretID.",
    );
    add_mount_route(
        &mut paths,
        format!("/auth/{approle}/login"),
        &["post", "put"],
        "Authenticate with AppRole credentials.",
    );

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
        assert!(paths.contains_key("/{kv_mount_path}/data/{path}"));
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
