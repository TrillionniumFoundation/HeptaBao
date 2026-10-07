//! Actual committed/reopened discovery metadata never grants backend access.
use super::tests::{Root, bootstrap_unmounted, call};
use super::*;

fn actor(
    service: &mut Service,
    root: &str,
    name: &str,
    policy: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    assert_eq!(
        call(
            service,
            "PUT",
            &format!("sys/policies/acl/{name}"),
            root,
            json!({"policy":policy})
        )
        .status,
        204
    );
    let response = call(
        service,
        "POST",
        "auth/token/create",
        root,
        json!({"policies":[name],"no_default_policy":true}),
    );
    assert_eq!(response.status, 200);
    Ok(response.body["auth"]["client_token"]
        .as_str()
        .ok_or("actual token")?
        .to_owned())
}

fn spec(service: &mut Service, token: &str) -> Response {
    call(
        service,
        "GET",
        "sys/internal/specs/openapi",
        token,
        json!({}),
    )
}

#[test]
fn listing111_real_enable_reopen_clear_and_sticky_publication_floor()
-> Result<(), Box<dyn std::error::Error>> {
    let root = Root::new();
    let mut service = root.service()?;
    let (key, admin) = bootstrap_unmounted(&mut service)?;
    let ordinary = service.state.as_ref().ok_or("ordinary state")?.clone();
    assert_eq!(ordinary.schema, CURRENT_STATE_SCHEMA);
    assert!(!ordinary.has_mount_listing_visibility_state());
    assert_eq!(
        call(
            &mut service,
            "POST",
            "sys/mounts/published",
            &admin,
            json!({"type":"kv","options":{"version":"2"},
            "config":{"listing_visibility":"unauth"}})
        )
        .status,
        204
    );
    let current = service.state.as_ref().ok_or("enabled state")?;
    assert_eq!(current.schema, MOUNT_LISTING_VISIBILITY_STATE_SCHEMA);
    assert_eq!(
        current.writer_schema(),
        MOUNT_LISTING_VISIBILITY_STATE_SCHEMA
    );
    assert!(current.has_mount_listing_visibility_state());
    assert!(current.validate_format().is_ok());
    let mut downgrade = current.clone();
    downgrade.schema = PKI_RSA8192_STATE_SCHEMA;
    assert!(downgrade.validate_format().is_err());
    assert!(
        downgrade
            .validate_publication_schema(Some(current))
            .is_err()
    );
    assert_eq!(
        Service::validate_snapshot_protected_floor(current, &ordinary)
            .err()
            .ok_or("old incoming must be rejected")?
            .status,
        400
    );
    for unsupported in [107, 109, 110] {
        assert!(!supported_reader_schema(unsupported));
    }
    assert!(
        spec(&mut service, "").body["paths"]
            .get("/published/data/{path}")
            .is_some()
    );
    drop(service);
    let mut service = root.service()?;
    assert_eq!(
        call(&mut service, "PUT", "sys/unseal", "", json!({"key":key})).status,
        200
    );
    assert_eq!(
        service.state.as_ref().ok_or("reopened state")?.schema,
        MOUNT_LISTING_VISIBILITY_STATE_SCHEMA
    );
    assert!(
        spec(&mut service, "").body["paths"]
            .get("/published/data/{path}")
            .is_some()
    );
    assert_eq!(
        call(
            &mut service,
            "POST",
            "sys/mounts/published/tune",
            &admin,
            json!({"listing_visibility":null})
        )
        .status,
        204
    );
    let current = service.state.as_ref().ok_or("cleared state")?;
    assert!(!current.has_mount_listing_visibility_state());
    assert_eq!(current.schema, MOUNT_LISTING_VISIBILITY_STATE_SCHEMA);
    assert_eq!(
        current.writer_schema(),
        MOUNT_LISTING_VISIBILITY_STATE_SCHEMA
    );
    assert!(current.validate_format().is_ok());
    let mut downgrade = current.clone();
    downgrade.schema = PKI_RSA8192_STATE_SCHEMA;
    assert!(downgrade.validate_format().is_ok());
    assert!(
        downgrade
            .validate_publication_schema(Some(current))
            .is_err()
    );
    assert_eq!(
        Service::validate_snapshot_protected_floor(current, &downgrade)
            .err()
            .ok_or("sticky floor")?
            .status,
        400
    );
    assert!(
        spec(&mut service, "").body["paths"]
            .as_object()
            .ok_or("anonymous paths")?
            .is_empty()
    );
    assert_eq!(
        call(
            &mut service,
            "DELETE",
            "sys/mounts/published",
            &admin,
            json!({})
        )
        .status,
        204
    );
    assert_eq!(
        service
            .state
            .as_ref()
            .ok_or("retired state")?
            .writer_schema(),
        MOUNT_LISTING_VISIBILITY_STATE_SCHEMA
    );
    Ok(())
}

#[test]
fn listing111_actual_unauth_metadata_cannot_supply_data_or_live_actor_authority()
-> Result<(), Box<dyn std::error::Error>> {
    let root = Root::new();
    let mut service = root.service()?;
    let (_, admin) = bootstrap_unmounted(&mut service)?;
    assert_eq!(
        call(
            &mut service,
            "POST",
            "sys/mounts/public",
            &admin,
            json!({"type":"kv","options":{"version":"2"},
            "config":{"listing_visibility":"unauth"}})
        )
        .status,
        204
    );
    assert_eq!(
        call(
            &mut service,
            "POST",
            "sys/mounts/private",
            &admin,
            json!({"type":"kv","options":{"version":"2"}})
        )
        .status,
        204
    );
    assert_eq!(
        call(
            &mut service,
            "POST",
            "public/data/item",
            &admin,
            json!({"data":{"value":"synthetic public metadata control"}})
        )
        .status,
        200
    );
    let listing = call(&mut service, "GET", "sys/internal/ui/mounts", "", json!({}));
    assert_eq!(listing.status, 200);
    let mounts = listing.body["data"]["secret"]
        .as_object()
        .ok_or("public metadata")?;
    assert_eq!(mounts.len(), 1);
    let descriptor = mounts
        .get("public/")
        .and_then(Value::as_object)
        .ok_or("public descriptor")?;
    assert_eq!(
        descriptor.keys().map(String::as_str).collect::<Vec<_>>(),
        vec!["description", "options", "type"]
    );
    let document = spec(&mut service, "");
    assert_eq!(document.status, 200);
    assert!(document.body["paths"].get("/public/data/{path}").is_some());
    assert!(document.body["paths"].get("/private/data/{path}").is_none());
    assert!(document.body["paths"].get("/sys/health").is_none());
    assert_eq!(
        call(&mut service, "GET", "public/data/item", "", json!({})).status,
        403
    );
    let unrelated = actor(
        &mut service,
        &admin,
        "discovery-unrelated",
        r#"path "unrelated/*" { capabilities=["read"] }"#,
    )?;
    assert!(
        spec(&mut service, &unrelated).body["paths"]
            .get("/public/data/{path}")
            .is_some()
    );
    assert_eq!(
        call(
            &mut service,
            "GET",
            "public/data/item",
            &unrelated,
            json!({})
        )
        .status,
        403
    );
    assert_eq!(
        call(
            &mut service,
            "POST",
            "sys/mounts/public/tune",
            &unrelated,
            json!({"listing_visibility":"hidden"})
        )
        .status,
        403
    );
    assert_eq!(spec(&mut service, "invalid-fixture-token").status, 403);
    assert_eq!(
        call(
            &mut service,
            "POST",
            "auth/token/revoke",
            &admin,
            json!({"token":unrelated})
        )
        .status,
        204
    );
    assert_eq!(spec(&mut service, &unrelated).status, 403);
    Ok(())
}

#[test]
fn listing111_hidden_mount_still_uses_actual_acl_for_valid_token_projection()
-> Result<(), Box<dyn std::error::Error>> {
    let root = Root::new();
    let mut service = root.service()?;
    let (_, admin) = bootstrap_unmounted(&mut service)?;
    assert_eq!(
        call(
            &mut service,
            "POST",
            "sys/mounts/hidden",
            &admin,
            json!({"type":"kv","options":{"version":"2"},
            "config":{"listing_visibility":"hidden"}})
        )
        .status,
        204
    );
    let reader = actor(
        &mut service,
        &admin,
        "discovery-specific",
        r#"path "hidden/data/allowed" { capabilities=["read"] }"#,
    )?;
    let unrelated = actor(
        &mut service,
        &admin,
        "discovery-other",
        r#"path "elsewhere/*" { capabilities=["read"] }"#,
    )?;
    assert!(
        spec(&mut service, "").body["paths"]
            .as_object()
            .ok_or("anon paths")?
            .is_empty()
    );
    assert!(
        spec(&mut service, &unrelated).body["paths"]
            .as_object()
            .ok_or("unrelated paths")?
            .is_empty()
    );
    let document = spec(&mut service, &reader);
    assert_eq!(document.status, 200);
    assert!(document.body["paths"].get("/hidden/data/{path}").is_some());
    assert!(document.body["paths"].get("/sys/mounts").is_none());
    assert!(document.body["paths"].get("/auth/token/create").is_none());
    assert_eq!(
        call(
            &mut service,
            "POST",
            "hidden/data/denied",
            &reader,
            json!({"data":{"value":"no grant"}})
        )
        .status,
        403
    );
    Ok(())
}

#[test]
fn listing111_auth_enable_tune_and_invalid_fields_preserve_committed_state()
-> Result<(), Box<dyn std::error::Error>> {
    let root = Root::new();
    let mut service = root.service()?;
    let (_, admin) = bootstrap_unmounted(&mut service)?;
    assert_eq!(
        call(
            &mut service,
            "POST",
            "sys/auth/public-user",
            &admin,
            json!({"type":"userpass","config":{"listing_visibility":"unauth"}})
        )
        .status,
        204
    );
    assert!(
        spec(&mut service, "").body["paths"]
            .get("/auth/public-user/login/{username}")
            .is_some()
    );
    for invalid in [
        json!("default"),
        json!("UNA UTH"),
        json!(true),
        json!(1),
        json!([]),
        json!({}),
    ] {
        assert_eq!(
            call(
                &mut service,
                "POST",
                "sys/auth/public-user/tune",
                &admin,
                json!({"listing_visibility":invalid})
            )
            .status,
            400
        );
        assert!(
            spec(&mut service, "").body["paths"]
                .get("/auth/public-user/login/{username}")
                .is_some()
        );
    }
    assert_eq!(
        call(
            &mut service,
            "POST",
            "sys/auth/public-user/tune",
            &admin,
            json!({"listing_visibility":"hidden"})
        )
        .status,
        204
    );
    let tune = call(
        &mut service,
        "GET",
        "sys/auth/public-user/tune",
        &admin,
        json!({}),
    );
    assert_eq!(tune.status, 200);
    assert_eq!(tune.body["data"]["listing_visibility"], "hidden");
    assert!(
        spec(&mut service, "").body["paths"]
            .as_object()
            .ok_or("hidden auth anon")?
            .is_empty()
    );
    assert_eq!(
        call(
            &mut service,
            "POST",
            "sys/auth/public-user/tune",
            &admin,
            json!({"listing_visibility":""})
        )
        .status,
        204
    );
    let current = service.state.as_ref().ok_or("cleared auth state")?;
    assert_eq!(current.schema, MOUNT_LISTING_VISIBILITY_STATE_SCHEMA);
    assert!(!current.has_mount_listing_visibility_state());
    Ok(())
}

#[test]
fn listing111_actual_child_namespace_metadata_isolated_from_root_catalog()
-> Result<(), Box<dyn std::error::Error>> {
    let root = Root::new();
    let mut service = root.service()?;
    let (_, admin) = bootstrap_unmounted(&mut service)?;
    assert_eq!(
        call(
            &mut service,
            "POST",
            "sys/namespaces/team",
            &admin,
            json!({})
        )
        .status,
        200
    );
    assert_eq!(service.handle_at("POST", "sys/mounts/child-public", "team", &admin,
        json!({"type":"kv","options":{"version":"2"},"config":{"listing_visibility":"unauth"}}),100).status,204);
    let current = service.state.as_ref().ok_or("actual child state")?;
    assert!(current.has_mount_listing_visibility_state());
    assert_eq!(current.schema, MOUNT_LISTING_VISIBILITY_STATE_SCHEMA);
    assert!(current.validate_format().is_ok());
    assert!(
        spec(&mut service, "").body["paths"]
            .as_object()
            .ok_or("root anon")?
            .is_empty()
    );
    let child = service.handle_at(
        "GET",
        "sys/internal/specs/openapi",
        "team",
        "",
        json!({}),
        100,
    );
    assert_eq!(child.status, 200);
    assert!(
        child.body["paths"]
            .get("/child-public/data/{path}")
            .is_some()
    );
    assert_eq!(
        service
            .handle_at("GET", "child-public/data/item", "team", "", json!({}), 100)
            .status,
        403
    );
    Ok(())
}
