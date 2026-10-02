//! Mount metadata never supplies a capability for the subsequent data request.
use super::tests::{Root, bootstrap, call};
use super::*;

fn issue(
    service: &mut Service,
    root: &str,
    policy: &str,
    uses: u64,
) -> Result<String, Box<dyn std::error::Error>> {
    let response = call(
        service,
        "POST",
        "auth/token/create",
        root,
        json!({"policies":[policy],"no_default_policy":true,"num_uses":uses,"ttl":300}),
    );
    assert_eq!(response.status, 200);
    Ok(response.body["auth"]["client_token"]
        .as_str()
        .ok_or("token")?
        .to_owned())
}

#[test]
fn mount_discovery_preserves_data_acl_and_regular_finite_use_admission()
-> Result<(), Box<dyn std::error::Error>> {
    let root = Root::new();
    let mut service = root.service()?;
    let (_, admin) = bootstrap(&mut service)?;
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
    for (name, policy) in [
        (
            "mount-exact",
            r#"path "secret/data/item" { capabilities=["read"] }"#,
        ),
        ("mount-deny", r#"path "secret/*" { capabilities=["deny"] }"#),
        (
            "mount-ui",
            r#"path "sys/internal/ui/mounts/*" { capabilities=["read"] }"#,
        ),
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
    let exact = issue(&mut service, &admin, "mount-exact", 2)?;
    let discovered = call(
        &mut service,
        "GET",
        "sys/internal/ui/mounts/secret/other",
        &exact,
        json!({}),
    );
    assert_eq!(discovered.status, 200);
    assert_eq!(discovered.body["data"]["path"], "secret/");
    assert_eq!(
        call(&mut service, "GET", "secret/data/item", &exact, json!({})).status,
        200
    );
    assert_eq!(
        call(
            &mut service,
            "GET",
            "sys/internal/ui/mounts/secret",
            &exact,
            json!({})
        )
        .status,
        200
    );
    assert_eq!(
        call(&mut service, "GET", "secret/data/item", &exact, json!({})).status,
        200
    );
    assert_eq!(
        call(
            &mut service,
            "GET",
            "sys/internal/ui/mounts/secret",
            &exact,
            json!({})
        )
        .status,
        403
    );
    let denied = issue(&mut service, &admin, "mount-deny", 0)?;
    assert_eq!(
        call(
            &mut service,
            "GET",
            "sys/internal/ui/mounts/secret",
            &denied,
            json!({})
        )
        .status,
        200
    );
    for method in ["GET", "POST", "DELETE"] {
        assert_eq!(
            call(
                &mut service,
                method,
                "secret/data/item",
                &denied,
                json!({"data":{"value":"changed"}})
            )
            .status,
            403
        );
    }
    let ui = issue(&mut service, &admin, "mount-ui", 0)?;
    assert_eq!(
        call(
            &mut service,
            "GET",
            "sys/internal/ui/mounts/secret",
            &ui,
            json!({})
        )
        .status,
        403
    );
    assert_eq!(
        call(&mut service, "GET", "secret/data/item", &ui, json!({})).status,
        403
    );
    assert_eq!(
        call(&mut service, "GET", "secret/data/item", &admin, json!({})).body["data"]["data"]["value"],
        "synthetic"
    );
    Ok(())
}

#[test]
fn mount_discovery_uses_only_the_selected_namespace_registry_across_restart()
-> Result<(), Box<dyn std::error::Error>> {
    let root = Root::new();
    let mut service = root.service()?;
    let (key, admin) = bootstrap(&mut service)?;
    assert_eq!(
        call(
            &mut service,
            "POST",
            "sys/mounts/root-only",
            &admin,
            json!({"type":"kv"})
        )
        .status,
        204
    );
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
    assert_eq!(
        service
            .handle_at(
                "POST",
                "sys/mounts/team-only",
                "team",
                &admin,
                json!({"type":"kv","options":{"version":"2"}}),
                100
            )
            .status,
        204
    );
    for reopened in [false, true] {
        if reopened {
            drop(service);
            service = root.service()?;
            assert_eq!(
                call(&mut service, "POST", "sys/unseal", "", json!({"key":key})).status,
                200
            );
        }
        assert_eq!(
            call(
                &mut service,
                "GET",
                "sys/internal/ui/mounts/team-only",
                &admin,
                json!({})
            )
            .status,
            403
        );
        let team = service.handle_at(
            "GET",
            "sys/internal/ui/mounts/team-only/data/item",
            "team",
            &admin,
            json!({}),
            100,
        );
        assert_eq!(team.status, 200);
        assert_eq!(team.body["data"]["path"], "team-only/");
        let catalog = service.handle_at(
            "GET",
            "sys/internal/ui/mounts",
            "team",
            &admin,
            json!({}),
            100,
        );
        assert!(catalog.body["data"]["secret"].get("team-only/").is_some());
        assert!(catalog.body["data"]["secret"].get("root-only/").is_none());
    }
    Ok(())
}

#[test]
fn mount_discovery_rejects_wrapping_tokens_writes_and_unknown_mounts()
-> Result<(), Box<dyn std::error::Error>> {
    let root = Root::new();
    let mut service = root.service()?;
    let (_, admin) = bootstrap(&mut service)?;
    for actor in ["", "synthetic-invalid"] {
        let denied = call(
            &mut service,
            "GET",
            "sys/internal/ui/mounts/secret",
            actor,
            json!({}),
        );
        assert_eq!(denied.status, 403);
        assert!(denied.body.get("data").is_none());
    }
    let anonymous = call(&mut service, "GET", "sys/internal/ui/mounts", "", json!({}));
    assert_eq!(anonymous.status, 200);
    assert_eq!(anonymous.body["data"], json!({"auth":{},"secret":{}}));
    let mut request = ServiceRequest::new("GET", "auth/token/lookup-self", "", &admin, json!({}));
    request.wrap_ttl_seconds = Some(60);
    let wrapped = service.handle_request_at(request, 100);
    assert_eq!(wrapped.status, 200);
    let token = wrapped.body["wrap_info"]["token"]
        .as_str()
        .ok_or("wrapper")?;
    let denied = call(
        &mut service,
        "GET",
        "sys/internal/ui/mounts/secret",
        token,
        json!({}),
    );
    assert!(denied.status >= 400);
    assert!(denied.body.get("data").is_none());
    let digest = service.current_state_digest().map_err(|_| "digest")?;
    for method in ["POST", "PUT", "PATCH", "DELETE", "LIST", "HEAD"] {
        assert_eq!(
            call(
                &mut service,
                method,
                "sys/internal/ui/mounts/secret",
                &admin,
                json!({"type":"kv"})
            )
            .status,
            405
        );
    }
    assert_eq!(
        call(
            &mut service,
            "GET",
            "sys/internal/ui/mounts/absent",
            &admin,
            json!({})
        )
        .status,
        403
    );
    assert_eq!(
        service.current_state_digest().map_err(|_| "digest")?,
        digest
    );
    Ok(())
}

#[test]
fn mount_metadata_capability_cannot_authorize_data_even_for_the_root_actor()
-> Result<(), Box<dyn std::error::Error>> {
    let root = Root::new();
    let mut service = root.service()?;
    let (_, admin) = bootstrap(&mut service)?;
    let state = service.state.as_ref().ok_or("state")?;
    let metadata = state
        .auth
        .authenticate_mount_metadata_from(&admin, 100, None)
        .map_err(|_| "metadata authentication")?;
    assert!(!metadata.consumed_use());
    assert!(
        state
            .auth
            .ui_mount_visible(&metadata, "", "secret/", 100)
            .map_err(|_| "metadata visibility")?
    );
    for capability in ["read", "create", "update", "delete", "list", "sudo"] {
        assert!(
            state
                .auth
                .authorize_request(&metadata, "", "secret/data/item", capability, 100)
                .is_err()
        );
    }
    Ok(())
}
