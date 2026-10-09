//! UI metadata follows real authenticated request admission and never becomes
//! permission to read a secret or enter another namespace.
use super::tests::{Root, bootstrap, call};
use super::*;

fn token(
    service: &mut Service,
    admin: &str,
    namespace: &str,
    body: Value,
) -> Result<String, Box<dyn std::error::Error>> {
    let response = service.handle_at("POST", "auth/token/create", namespace, admin, body, 100);
    assert_eq!(response.status, 200);
    Ok(response.body["auth"]["client_token"]
        .as_str()
        .ok_or("token")?
        .to_owned())
}

#[test]
fn ui_resultant_acl_projects_current_rules_without_widening_data_access()
-> Result<(), Box<dyn std::error::Error>> {
    let root = Root::new();
    let mut service = root.service()?;
    let (_, admin) = bootstrap(&mut service)?;
    for (name, policy) in [
        (
            "ui-allow",
            r#"path "sys/internal/ui/resultant-acl" { capabilities=["read"] }
path "secret/data/item" { capabilities=["read"] }
path "secret/*" { capabilities=["read","list"] }"#,
        ),
        ("ui-deny", r#"path "secret/*" { capabilities=["deny"] }"#),
    ] {
        assert_eq!(
            call(
                &mut service,
                "PUT",
                &format!("sys/policies/acl/{name}"),
                &admin,
                json!({"policy":policy})
            )
            .status,
            204
        );
    }
    assert_eq!(
        call(
            &mut service,
            "POST",
            "secret/data/item",
            &admin,
            json!({"data":{"value":"synthetic"}})
        )
        .status,
        200
    );
    let bearer = token(
        &mut service,
        &admin,
        "",
        json!({"policies":["ui-allow","ui-deny"],"no_default_policy":true,"ttl":300}),
    )?;
    let acl = call(
        &mut service,
        "GET",
        "sys/internal/ui/resultant-acl",
        &bearer,
        json!({}),
    );
    assert_eq!(acl.status, 200);
    assert_eq!(acl.body["data"]["root"], false);
    assert_eq!(
        acl.body["data"]["exact_paths"]["secret/data/item"]["capabilities"],
        json!(["read"])
    );
    assert_eq!(
        acl.body["data"]["glob_paths"]["secret/"]["capabilities"],
        json!(["deny"])
    );
    assert_eq!(
        call(&mut service, "GET", "secret/data/item", &bearer, json!({})).status,
        200
    );
    assert_eq!(
        call(&mut service, "GET", "secret/data/other", &bearer, json!({})).status,
        403
    );
    assert_eq!(
        call(
            &mut service,
            "POST",
            "secret/data/item",
            &bearer,
            json!({"data":{"value":"changed"}})
        )
        .status,
        403
    );
    // A subsequent policy mutation appears in the next projection; UI state
    // cannot preserve an obsolete permission.
    assert_eq!(
        call(
            &mut service,
            "PUT",
            "sys/policies/acl/ui-allow",
            &admin,
            json!({"policy":r#"path "sys/internal/ui/resultant-acl" { capabilities=["read"] }"#})
        )
        .status,
        204
    );
    let acl = call(
        &mut service,
        "GET",
        "sys/internal/ui/resultant-acl",
        &bearer,
        json!({}),
    );
    assert_eq!(acl.status, 200);
    assert!(
        acl.body["data"]["exact_paths"]
            .get("secret/data/item")
            .is_none()
    );
    assert_eq!(
        call(&mut service, "GET", "secret/data/item", &bearer, json!({})).status,
        403
    );
    Ok(())
}

#[test]
fn ui_resultant_acl_keeps_default_policy_finite_use_and_revocation()
-> Result<(), Box<dyn std::error::Error>> {
    let root = Root::new();
    let mut service = root.service()?;
    let (_, admin) = bootstrap(&mut service)?;
    let bearer = token(
        &mut service,
        &admin,
        "",
        json!({"policies":["default"],"num_uses":1,"ttl":300}),
    )?;
    let acl = call(
        &mut service,
        "GET",
        "sys/internal/ui/resultant-acl",
        &bearer,
        json!({}),
    );
    assert_eq!(acl.status, 200);
    assert_eq!(acl.body["data"]["root"], false);
    assert_eq!(
        acl.body["data"]["exact_paths"]["auth/token/lookup-self"]["capabilities"],
        json!(["read"])
    );
    assert_eq!(
        call(
            &mut service,
            "GET",
            "sys/internal/ui/resultant-acl",
            &bearer,
            json!({})
        )
        .status,
        403
    );
    let revoked = token(
        &mut service,
        &admin,
        "",
        json!({"policies":["default"],"ttl":300}),
    )?;
    assert_eq!(
        call(
            &mut service,
            "POST",
            "auth/token/revoke",
            &admin,
            json!({"token":revoked})
        )
        .status,
        204
    );
    assert_eq!(
        call(
            &mut service,
            "GET",
            "sys/internal/ui/resultant-acl",
            &revoked,
            json!({})
        )
        .status,
        403
    );
    for path in [
        "sys/internal/ui/resultant-acl",
        "sys/internal/ui/namespaces",
    ] {
        assert_eq!(call(&mut service, "GET", path, "", json!({})).status, 403);
        assert_eq!(
            call(&mut service, "POST", path, &admin, json!({})).status,
            405
        );
        assert_eq!(
            call(
                &mut service,
                "GET",
                path,
                &admin,
                json!({"unexpected":true})
            )
            .status,
            400
        );
    }
    let root_acl = call(
        &mut service,
        "GET",
        "sys/internal/ui/resultant-acl",
        &admin,
        json!({}),
    );
    assert_eq!(root_acl.status, 200);
    assert_eq!(root_acl.body["data"]["root"], true);
    Ok(())
}

#[test]
fn ui_namespace_discovery_preserves_registry_permission_and_actor_scope()
-> Result<(), Box<dyn std::error::Error>> {
    let root = Root::new();
    let mut service = root.service()?;
    let (_, admin) = bootstrap(&mut service)?;
    for path in ["team", "other"] {
        assert_eq!(
            call(
                &mut service,
                "POST",
                &format!("sys/namespaces/{path}"),
                &admin,
                json!({})
            )
            .status,
            200
        );
    }
    assert_eq!(
        service
            .handle_at(
                "POST",
                "sys/namespaces/child",
                "team",
                &admin,
                json!({}),
                100,
            )
            .status,
        200
    );
    let all = call(
        &mut service,
        "GET",
        "sys/internal/ui/namespaces",
        &admin,
        json!({}),
    );
    assert_eq!(all.status, 200);
    assert_eq!(all.body["data"]["keys"], json!(["other/", "team/"]));
    let scoped = service.handle_at(
        "GET",
        "sys/internal/ui/namespaces",
        "team",
        &admin,
        json!({}),
        100,
    );
    assert_eq!(scoped.status, 200);
    assert_eq!(scoped.body["data"]["keys"], json!(["child/"]));
    assert_eq!(
        service
            .handle_at(
                "PUT",
                "sys/policies/acl/ui-list",
                "team",
                &admin,
                json!({"policy":r#"path "sys/namespaces" { capabilities=["list"] }"#}),
                100
            )
            .status,
        204
    );
    let scoped_token = token(
        &mut service,
        &admin,
        "team",
        json!({"policies":["ui-list"],"no_default_policy":true,"ttl":300}),
    )?;
    let scoped = service.handle_at(
        "GET",
        "sys/internal/ui/namespaces",
        "team",
        &scoped_token,
        json!({}),
        100,
    );
    assert_eq!(scoped.status, 200);
    assert_eq!(scoped.body["data"], json!({}));
    // UI namespace access and registry metadata LIST are distinct controls.
    let registry = service.handle_at(
        "LIST",
        "sys/namespaces",
        "team",
        &scoped_token,
        json!({}),
        100,
    );
    assert_eq!(registry.status, 200);
    assert_eq!(registry.body["data"]["keys"], json!(["child/"]));
    assert_eq!(
        service
            .handle_at(
                "GET",
                "sys/internal/ui/namespaces",
                "other",
                &scoped_token,
                json!({}),
                100
            )
            .status,
        403
    );
    assert_eq!(
        service
            .handle_at(
                "GET",
                "sys/internal/ui/namespaces",
                "team/child",
                &scoped_token,
                json!({}),
                100
            )
            .status,
        403
    );
    let ordinary = token(
        &mut service,
        &admin,
        "team",
        json!({"policies":["default"],"ttl":300}),
    )?;
    let discovered = service.handle_at(
        "GET",
        "sys/internal/ui/namespaces",
        "team",
        &ordinary,
        json!({}),
        100,
    );
    assert_eq!(discovered.status, 200);
    assert_eq!(discovered.body["data"], json!({}));
    // Removing LIST changes the real registry API, never the empty picker.
    assert_eq!(
        service
            .handle_at(
                "PUT",
                "sys/policies/acl/ui-list",
                "team",
                &admin,
                json!({"policy":r#"path "sys/namespaces" { capabilities=["deny"] }"#}),
                100,
            )
            .status,
        204
    );
    assert_eq!(
        service
            .handle_at(
                "LIST",
                "sys/namespaces",
                "team",
                &scoped_token,
                json!({}),
                100
            )
            .status,
        403
    );
    let withdrawn = service.handle_at(
        "GET",
        "sys/internal/ui/namespaces",
        "team",
        &scoped_token,
        json!({}),
        100,
    );
    assert_eq!(withdrawn.status, 200);
    assert_eq!(withdrawn.body["data"], json!({}));
    let revoked = token(
        &mut service,
        &admin,
        "team",
        json!({"policies":["default"],"ttl":300}),
    )?;
    assert_eq!(
        service
            .handle_at(
                "POST",
                "auth/token/revoke",
                "team",
                &admin,
                json!({"token":revoked}),
                100,
            )
            .status,
        204
    );
    assert_eq!(
        service
            .handle_at(
                "GET",
                "sys/internal/ui/namespaces",
                "team",
                &revoked,
                json!({}),
                100
            )
            .status,
        403
    );
    let expiring = token(
        &mut service,
        &admin,
        "team",
        json!({"policies":["default"],"ttl":1}),
    )?;
    let live = service.handle_at(
        "GET",
        "sys/internal/ui/namespaces",
        "team",
        &expiring,
        json!({}),
        100,
    );
    assert_eq!(live.status, 200);
    assert_eq!(live.body["data"], json!({}));
    assert_eq!(
        service
            .handle_at(
                "GET",
                "sys/internal/ui/namespaces",
                "team",
                &expiring,
                json!({}),
                102
            )
            .status,
        403
    );
    // Begin a real native deletion with an actual nonempty KV owner. Do not
    // manufacture taint or run cleanup to make the registry assertion pass.
    assert_eq!(
        call(
            &mut service,
            "POST",
            "sys/namespaces/retire-ui",
            &admin,
            json!({})
        )
        .status,
        200
    );
    assert_eq!(
        service
            .handle_at(
                "POST",
                "sys/mounts/payload",
                "retire-ui",
                &admin,
                json!({"type":"kv","options":{"version":"1"}}),
                100,
            )
            .status,
        204
    );
    assert_eq!(
        service
            .handle_at(
                "POST",
                "payload/item",
                "retire-ui",
                &admin,
                json!({"payload":"synthetic-retiring-owner"}),
                100,
            )
            .status,
        204
    );
    let execution = service.begin_request_before(
        ServiceRequest {
            method: "DELETE",
            path: "sys/namespaces/retire-ui",
            namespace: "",
            token: &admin,
            body: json!({}),
            wrap_ttl_seconds: None,
            origin_peer: None,
            client_certificates: None,
        },
        std::time::Instant::now() + std::time::Duration::from_secs(15),
        false,
    );
    let deleting = service.finish_synchronous_request(execution);
    assert_eq!(deleting.status, 200);
    assert_eq!(deleting.body["data"]["status"], "in-progress");
    let state = service.state.as_ref().ok_or("native namespace taint")?;
    assert!(state.namespace_exists("retire-ui"));
    assert!(state.namespace_is_tainted("retire-ui"));
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_secs();
    let root_picker = service.handle_at(
        "GET",
        "sys/internal/ui/namespaces",
        "",
        &admin,
        json!({}),
        now,
    );
    assert_eq!(root_picker.status, 200);
    assert_eq!(root_picker.body["data"]["keys"], json!(["other/", "team/"]));
    let root_registry = service.handle_at("LIST", "sys/namespaces", "", &admin, json!({}), now);
    assert_eq!(root_registry.status, 200);
    assert!(
        root_registry.body["data"]["keys"]
            .as_array()
            .ok_or("root registry keys")?
            .contains(&json!("retire-ui/"))
    );
    Ok(())
}

#[test]
fn ui_segment_navigation_uses_actual_acl_specificity_and_preserves_api_denials()
-> Result<(), Box<dyn std::error::Error>> {
    let root = Root::new();
    let mut service = root.service()?;
    let (_, admin) = bootstrap(&mut service)?;
    let entity = call(
        &mut service,
        "POST",
        "identity/entity",
        &admin,
        json!({"name":"synthetic-ui-segment"}),
    );
    assert_eq!(entity.status, 200);
    let entity_id = entity.body["data"]["id"].as_str().ok_or("entity id")?;
    let policy = r#"path "sys/internal/ui/resultant-acl" { capabilities=["read"] }
path "identity/+/id" { capabilities=["list"] }
path "identity/group/id" { capabilities=["deny"] }"#;
    assert_eq!(
        call(
            &mut service,
            "PUT",
            "sys/policies/acl/ui-segments",
            &admin,
            json!({"policy":policy}),
        )
        .status,
        204
    );
    let bearer = token(
        &mut service,
        &admin,
        "",
        json!({"policies":["ui-segments"],"no_default_policy":true,"ttl":300}),
    )?;
    let acl = call(
        &mut service,
        "GET",
        "sys/internal/ui/resultant-acl",
        &bearer,
        json!({}),
    );
    assert_eq!(acl.status, 200);
    // The official UI asks for "list" at this exact navigation prefix.
    assert_eq!(
        acl.body["data"]["exact_paths"]["identity/entity/id"]["capabilities"],
        json!(["list"])
    );
    assert_eq!(
        acl.body["data"]["exact_paths"]["identity/group/id"]["capabilities"],
        json!(["deny"])
    );
    assert_eq!(
        acl.body["data"]["glob_paths"]["identity/+/id"]["capabilities"],
        json!(["list"])
    );
    let listed = call(
        &mut service,
        "LIST",
        "identity/entity/id",
        &bearer,
        json!({}),
    );
    assert_eq!(listed.status, 200);
    assert_eq!(listed.body["data"]["keys"], json!([entity_id]));
    assert_eq!(
        call(
            &mut service,
            "LIST",
            "identity/group/id",
            &bearer,
            json!({})
        )
        .status,
        403
    );
    assert_eq!(
        call(
            &mut service,
            "GET",
            &format!("identity/entity/id/{entity_id}"),
            &bearer,
            json!({}),
        )
        .status,
        403
    );
    assert_eq!(
        call(
            &mut service,
            "POST",
            "identity/entity",
            &bearer,
            json!({"name":"synthetic-denied"}),
        )
        .status,
        403
    );
    // A narrower live rule wins over the segment wildcard in both discovery
    // and real requests, even for an already-issued token.
    assert_eq!(
        call(
            &mut service,
            "PUT",
            "sys/policies/acl/ui-segments",
            &admin,
            json!({"policy":format!(
                r#"{policy}
            path "identity/entity/id" {{ capabilities=["deny"] }}"#
            )}),
        )
        .status,
        204
    );
    let acl = call(
        &mut service,
        "GET",
        "sys/internal/ui/resultant-acl",
        &bearer,
        json!({}),
    );
    assert_eq!(acl.status, 200);
    assert_eq!(
        acl.body["data"]["exact_paths"]["identity/entity/id"]["capabilities"],
        json!(["deny"])
    );
    assert_eq!(
        call(
            &mut service,
            "LIST",
            "identity/entity/id",
            &bearer,
            json!({})
        )
        .status,
        403
    );
    Ok(())
}
