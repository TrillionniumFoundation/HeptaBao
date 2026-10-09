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
        json!({"policies":[],"num_uses":1,"ttl":300}),
    )?;
    let acl = call(
        &mut service,
        "GET",
        "sys/internal/ui/resultant-acl",
        &bearer,
        json!({}),
    );
    assert_eq!(acl.status, 200);
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
    let revoked = token(&mut service, &admin, "", json!({"policies":[],"ttl":300}))?;
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
    for path in ["team", "team/child", "other"] {
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
    let all = call(
        &mut service,
        "GET",
        "sys/internal/ui/namespaces",
        &admin,
        json!({}),
    );
    assert_eq!(all.status, 200);
    assert_eq!(
        all.body["data"]["keys"],
        json!(["other/", "team/", "team/child/"])
    );
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
    assert_eq!(scoped.body["data"]["keys"], json!(["child/"]));
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
        json!({"policies":[],"ttl":300}),
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
    assert_eq!(discovered.body["data"]["keys"], json!([]));
    Ok(())
}
