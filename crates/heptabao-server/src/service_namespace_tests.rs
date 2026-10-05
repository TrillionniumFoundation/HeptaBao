use super::super::tests::{Root, bootstrap, call};
use super::*;
use serde_json::json;

#[test]
fn namespace_tree_metadata_restart_and_incarnation_are_durable()
-> Result<(), Box<dyn std::error::Error>> {
    let root = Root::new();
    let mut service = root.service()?;
    let (key, token) = bootstrap(&mut service)?;

    assert_eq!(
        call(
            &mut service,
            "POST",
            "sys/namespaces/team",
            &token,
            json!({"custom_metadata":{"owner":"platform","tier":"dev"}})
        )
        .status,
        200
    );
    let team = call(
        &mut service,
        "GET",
        "sys/namespaces/team",
        &token,
        json!({}),
    );
    assert_eq!(team.status, 200);
    assert_eq!(team.body["data"]["path"], "team/");
    assert_eq!(team.body["data"]["custom_metadata"]["owner"], "platform");
    let first_id = team.body["data"]["id"]
        .as_str()
        .ok_or("missing namespace id")?
        .to_owned();

    let list = call(&mut service, "LIST", "sys/namespaces", &token, json!({}));
    assert_eq!(list.status, 200);
    assert_eq!(list.body["data"]["keys"], json!(["team/"]));
    assert_eq!(list.body["data"]["key_info"]["team/"]["id"], first_id);

    assert_eq!(
        service
            .handle_at(
                "POST",
                "sys/namespaces/child",
                "team",
                &token,
                json!({"custom_metadata":{"owner":"application"}}),
                100
            )
            .status,
        200
    );
    let child = service.handle_at(
        "GET",
        "sys/namespaces/child",
        "team",
        &token,
        json!({}),
        100,
    );
    assert_eq!(child.status, 200);
    assert_eq!(child.body["data"]["path"], "team/child/");
    assert_eq!(
        service
            .handle_at(
                "PATCH",
                "sys/namespaces/child",
                "team",
                &token,
                json!({"custom_metadata":{"owner":"payments","obsolete":"remove-me"}}),
                100
            )
            .status,
        200
    );
    assert_eq!(
        service
            .handle_at(
                "PATCH",
                "sys/namespaces/child",
                "team",
                &token,
                json!({"custom_metadata":{"obsolete":null}}),
                100
            )
            .status,
        200
    );
    let scan = call(&mut service, "SCAN", "sys/namespaces", &token, json!({}));
    assert_eq!(scan.status, 200);
    assert_eq!(scan.body["data"]["keys"], json!(["team/", "team/child/"]));
    assert_eq!(
        call(
            &mut service,
            "DELETE",
            "sys/namespaces/team",
            &token,
            json!({})
        )
        .status,
        409
    );

    drop(service);
    let mut service = root.service()?;
    assert_eq!(
        call(&mut service, "PUT", "sys/unseal", "", json!({"key":key})).status,
        200
    );
    let reopened = call(
        &mut service,
        "GET",
        "sys/namespaces/team",
        &token,
        json!({}),
    );
    assert_eq!(reopened.status, 200);
    assert_eq!(reopened.body["data"]["id"], first_id);
    let child = service.handle_at(
        "GET",
        "sys/namespaces/child",
        "team",
        &token,
        json!({}),
        100,
    );
    assert_eq!(child.body["data"]["custom_metadata"]["owner"], "payments");
    assert!(
        child.body["data"]["custom_metadata"]
            .get("obsolete")
            .is_none()
    );

    assert_eq!(
        service
            .handle_at(
                "DELETE",
                "sys/namespaces/child",
                "team",
                &token,
                json!({}),
                100
            )
            .status,
        200
    );
    assert_eq!(
        call(
            &mut service,
            "DELETE",
            "sys/namespaces/team",
            &token,
            json!({})
        )
        .status,
        200
    );
    assert_eq!(
        call(
            &mut service,
            "POST",
            "sys/namespaces/team",
            &token,
            json!({})
        )
        .status,
        200
    );
    let recreated = call(
        &mut service,
        "GET",
        "sys/namespaces/team",
        &token,
        json!({}),
    );
    assert_ne!(recreated.body["data"]["id"], first_id);
    Ok(())
}

#[test]
fn namespace_catalog_seal_state_and_nonempty_delete() -> Result<(), Box<dyn std::error::Error>> {
    let root = Root::new();
    let mut service = root.service()?;
    let (_, token) = bootstrap(&mut service)?;
    assert_eq!(
        call(
            &mut service,
            "POST",
            "sys/namespaces/sealed",
            &token,
            json!({"seal":"invalid"})
        )
        .status,
        500
    );
    assert_eq!(
        call(
            &mut service,
            "POST",
            "sys/namespaces/sealed",
            &token,
            json!({"seal":true})
        )
        .status,
        500
    );
    // A boolean is not a Shamir profile. The pinned official KMS parser
    // accepts this actual configuration and returns a sealed independent owner.
    assert_eq!(
        call(
            &mut service,
            "POST",
            "sys/namespaces/sealed",
            &token,
            json!({"seal":"seal \"shamir\" { shares = 3 threshold = 2 }"})
        )
        .status,
        200
    );
    let sealed = call(
        &mut service,
        "GET",
        "sys/namespaces/sealed/seal-status",
        &token,
        json!({}),
    );
    assert_eq!(sealed.status, 200);
    assert_eq!(sealed.body["data"]["sealed"], true);
    assert_eq!(
        call(
            &mut service,
            "POST",
            "sys/namespaces/team",
            &token,
            json!({})
        )
        .status,
        200
    );
    super::super::tests::provision_fixture_mounts(&mut service, "team", &token);
    assert_eq!(
        service
            .handle_at(
                "POST",
                "secret/data/item",
                "team",
                &token,
                json!({"data":{"value":"secret"}}),
                100
            )
            .status,
        200
    );
    assert_eq!(
        call(
            &mut service,
            "DELETE",
            "sys/namespaces/team",
            &token,
            json!({})
        )
        .status,
        409
    );
    let state = service.state.as_ref().ok_or("missing state")?;
    assert_eq!(
        state.schema, 81,
        "independent namespace ciphertext requires its explicit reader floor"
    );
    let mut downgraded = state.clone();
    downgraded.auth.remove_name_modes_for_legacy_format_test();
    downgraded.schema = 8;
    downgraded.auth.omit_lease_metadata_for_legacy_fixture();
    assert!(downgraded.validate_format().is_err());
    Ok(())
}

#[test]
fn ordinary_namespace_ciphertext_unload_cannot_grant_an_independent_key()
-> Result<(), Box<dyn std::error::Error>> {
    let root = Root::new();
    let mut service = root.service()?;
    let (_, token) = bootstrap(&mut service)?;
    let network_call = |service: &mut Service,
                        method: &str,
                        path: &str,
                        namespace: &str,
                        body: Value|
     -> Response {
        match service.begin_request(ServiceRequest {
            method,
            path,
            namespace,
            token: &token,
            body,
            wrap_ttl_seconds: None,
            origin_peer: None,
            client_certificates: None,
        }) {
            RequestExecution::Complete(response) => response,
            RequestExecution::External(_) => Response::error(500, "unexpected external effect"),
        }
    };
    assert_eq!(
        call(
            &mut service,
            "POST",
            "sys/namespaces/team",
            &token,
            json!({}),
        )
        .status,
        200
    );
    assert_eq!(
        network_call(
            &mut service,
            "POST",
            "sys/namespaces/team/seal",
            "",
            json!({}),
        )
        .status,
        204
    );
    assert_eq!(
        network_call(&mut service, "GET", "secret/data/item", "team", json!({}),).status,
        404
    );
    let status = network_call(
        &mut service,
        "GET",
        "sys/namespaces/team/seal-status",
        "",
        json!({}),
    );
    // Official R28 plain namespace: seal 204, status/unseal both 400 because
    // no independent owner was configured. Real ordinary assets unload under
    // their inherited root key; no independent Shamir authority is invented.
    assert_eq!(status.status, 400);
    assert_eq!(
        network_call(
            &mut service,
            "POST",
            "sys/namespaces/team/unseal",
            "",
            json!({}),
        )
        .status,
        500
    );
    assert_eq!(
        network_call(&mut service, "GET", "secret/data/item", "team", json!({}),).status,
        404
    );
    Ok(())
}

#[test]
fn unknown_namespace_is_not_an_implicit_scope_or_write_target()
-> Result<(), Box<dyn std::error::Error>> {
    let root = Root::new();
    let mut service = root.service()?;
    let (_, token) = bootstrap(&mut service)?;
    let generation = service
        .durable
        .as_ref()
        .ok_or("missing durable store")?
        .generation();
    let network_call = |service: &mut Service,
                        method: &str,
                        path: &str,
                        namespace: &str,
                        token: &str,
                        body: Value|
     -> Response {
        match service.begin_request(ServiceRequest {
            method,
            path,
            namespace,
            token,
            body,
            wrap_ttl_seconds: None,
            origin_peer: None,
            client_certificates: None,
        }) {
            RequestExecution::Complete(response) => response,
            RequestExecution::External(_) => Response::error(
                500,
                "namespace fixture unexpectedly staged an external effect",
            ),
        }
    };

    for (method, path) in [
        ("GET", "sys/health"),
        ("GET", "sys/seal-status"),
        ("GET", "secret/data/ghost-item"),
        ("POST", "secret/data/ghost-item"),
        ("POST", "auth/token/create"),
    ] {
        assert_eq!(
            network_call(&mut service, method, path, "ghost", &token, json!({})).status,
            404,
            "unknown namespace must fail before {method} {path}"
        );
    }
    assert_eq!(
        service
            .durable
            .as_ref()
            .ok_or("missing durable store")?
            .generation(),
        generation,
        "unknown namespace requests must not publish owner state"
    );

    assert_eq!(
        call(
            &mut service,
            "POST",
            "sys/namespaces/ghost",
            &token,
            json!({}),
        )
        .status,
        200
    );
    assert_eq!(
        call(
            &mut service,
            "DELETE",
            "sys/namespaces/ghost",
            &token,
            json!({}),
        )
        .status,
        200
    );
    assert_eq!(
        network_call(
            &mut service,
            "POST",
            "secret/data/ghost-item",
            "ghost",
            &token,
            json!({"data":{"v":"must-not-resurrect"}}),
        )
        .status,
        404,
        "deleted namespace must not reappear through an owner map"
    );
    assert!(
        !service
            .state
            .as_ref()
            .ok_or("missing state")?
            .namespace_exists("ghost")
    );
    Ok(())
}

#[test]
fn health_get_and_head_preserve_namespace_and_recovery_fences()
-> Result<(), Box<dyn std::error::Error>> {
    let health = |service: &mut Service, method: &str, namespace: &str| {
        service.handle_at_mode(RequestDispatch {
            method,
            path: "sys/health",
            namespace,
            token: "",
            body: json!({}),
            now: 100,
            allow_forward: false,
            enforce_namespace: true,
            wrap_ttl_seconds: None,
            origin_peer: None,
            client_certificates: None,
        })
    };
    let root = Root::new();
    let mut service = root.service()?;
    let (_, token) = bootstrap(&mut service)?;
    assert_eq!(
        call(
            &mut service,
            "POST",
            "sys/namespaces/team",
            &token,
            json!({})
        )
        .status,
        200
    );
    for method in ["GET", "HEAD"] {
        let before = service.state_digest;
        let generation = service.durable.as_ref().ok_or("durable")?.generation();
        let unknown = health(&mut service, method, "absent");
        assert_eq!(unknown.status, 404);
        let valid = health(&mut service, method, "team");
        assert_eq!(valid.status, 200);
        assert_eq!(service.state_digest, before);
        assert_eq!(
            service.durable.as_ref().ok_or("durable")?.generation(),
            generation
        );
        service.recovery_required = true;
        let fenced = health(&mut service, method, "team");
        assert_eq!(fenced.status, 503);
        assert!(service.recovery_required);
        assert_eq!(service.state_digest, before);
        assert_eq!(
            service.durable.as_ref().ok_or("durable")?.generation(),
            generation
        );
        // Restore only the test-injected flag before the next independent case.
        service.recovery_required = false;
    }
    Ok(())
}

#[test]
fn malformed_health_queries_never_change_application_state()
-> Result<(), Box<dyn std::error::Error>> {
    let root = Root::new();
    let mut service = root.service()?;
    bootstrap(&mut service)?;
    let before = service.state_digest;
    let generation = service.durable.as_ref().ok_or("durable")?.generation();
    for method in ["GET", "HEAD"] {
        for body in [
            json!({"standbyok":"true"}),
            json!({"perfstandbyok":1}),
            json!({"activecode":99}),
        ] {
            assert_eq!(
                service
                    .handle_request_at(ServiceRequest::new(method, "sys/health", "", "", body), 100)
                    .status,
                400
            );
        }
    }
    assert_eq!(service.state_digest, before);
    assert_eq!(
        service.durable.as_ref().ok_or("durable")?.generation(),
        generation
    );
    Ok(())
}

#[test]
fn native_namespace_wire_projection_preserves_durable_identity()
-> Result<(), Box<dyn std::error::Error>> {
    let root = Root::new();
    let mut service = root.service()?;
    let (key, token) = bootstrap(&mut service)?;
    let created = call(
        &mut service,
        "POST",
        "sys/namespaces/native",
        &token,
        json!({"custom_metadata":{"owner":"first"}}),
    );
    assert_eq!(created.status, 200);
    let data = created.body["data"].clone();
    assert_eq!(data["path"], "native/");
    assert_eq!(data["locked"], false);
    assert_eq!(data["tainted"], false);
    assert_eq!(data["uuid"].as_str().ok_or("uuid")?.len(), 36);
    // The pre-existing v1 persisted ID remains unchanged, not rewritten to
    // imitate the variable-length opaque identifier of another implementation.
    assert_eq!(data["id"].as_str().ok_or("id")?.len(), 5);
    let before = serde_json::to_vec(&service.state.as_ref().ok_or("state")?.namespaces)?;
    let generation = service.durable.as_ref().ok_or("durable")?.generation();
    let read = call(
        &mut service,
        "GET",
        "sys/namespaces/native",
        &token,
        json!({}),
    );
    assert_eq!(read.body["data"], data);
    assert_eq!(
        service.durable.as_ref().ok_or("durable")?.generation(),
        generation
    );
    assert_eq!(
        serde_json::to_vec(&service.state.as_ref().ok_or("state")?.namespaces)?,
        before
    );
    let saved: Value = serde_json::from_slice(&before)?;
    assert!(saved["entries"]["native"].get("uuid").is_none());
    drop(service);
    let mut service = root.service()?;
    assert_eq!(
        call(&mut service, "POST", "sys/unseal", "", json!({"key":key})).status,
        200
    );
    let reopened = call(
        &mut service,
        "GET",
        "sys/namespaces/native",
        &token,
        json!({}),
    );
    assert_eq!(reopened.body["data"], data);
    let patched = call(
        &mut service,
        "PATCH",
        "sys/namespaces/native",
        &token,
        json!({"custom_metadata":{"owner":"second"}}),
    );
    assert_eq!(patched.status, 200);
    assert_eq!(patched.body["data"]["id"], data["id"]);
    assert_eq!(patched.body["data"]["uuid"], data["uuid"]);
    assert_eq!(patched.body["data"]["custom_metadata"]["owner"], "second");
    let removed = call(
        &mut service,
        "DELETE",
        "sys/namespaces/native",
        &token,
        json!({}),
    );
    assert_eq!(removed.status, 200);
    assert_eq!(removed.body, json!({"data":{"status":"in-progress"}}));
    // Lose the deletion acknowledgement, then recover the same committed absence.
    drop(service);
    let mut service = root.service()?;
    assert_eq!(
        call(&mut service, "POST", "sys/unseal", "", json!({"key":key})).status,
        200
    );
    assert_eq!(
        call(
            &mut service,
            "GET",
            "sys/namespaces/native",
            &token,
            json!({})
        )
        .status,
        404
    );
    let generation = service.durable.as_ref().ok_or("durable")?.generation();
    let repeated = call(
        &mut service,
        "DELETE",
        "sys/namespaces/native",
        &token,
        json!({}),
    );
    assert_eq!(repeated.status, 200);
    assert_eq!(repeated.body, json!({"data":null}));
    assert_eq!(
        service.durable.as_ref().ok_or("durable")?.generation(),
        generation
    );
    let recreated = call(
        &mut service,
        "POST",
        "sys/namespaces/native",
        &token,
        json!({}),
    );
    assert_eq!(recreated.status, 200);
    assert_ne!(recreated.body["data"]["id"], data["id"]);
    assert_ne!(recreated.body["data"]["uuid"], data["uuid"]);
    Ok(())
}

#[test]
fn native_namespace_rejections_do_not_publish_or_rebind_owner_state()
-> Result<(), Box<dyn std::error::Error>> {
    let root = Root::new();
    let mut service = root.service()?;
    let (_, token) = bootstrap(&mut service)?;
    assert_eq!(
        call(
            &mut service,
            "POST",
            "sys/namespaces/team",
            &token,
            json!({})
        )
        .status,
        200
    );
    let before = service.state_digest;
    let generation = service.durable.as_ref().ok_or("durable")?.generation();
    for method in ["GET", "POST", "PATCH", "DELETE"] {
        assert_eq!(
            call(
                &mut service,
                method,
                "sys/namespaces/team/child",
                &token,
                json!({})
            )
            .status,
            400
        );
    }
    for reserved in ["root", "sys", "audit", "auth", "cubbyhole", "identity"] {
        assert_eq!(
            call(
                &mut service,
                "POST",
                &format!("sys/namespaces/{reserved}"),
                &token,
                json!({})
            )
            .status,
            400
        );
    }
    assert_eq!(
        call(
            &mut service,
            "DELETE",
            "sys/namespaces/team",
            "invalid",
            json!({})
        )
        .status,
        403
    );
    assert_eq!(
        call(
            &mut service,
            "PATCH",
            "sys/namespaces/team",
            &token,
            json!({"custom_metadata":{"good":"must-not-commit","invalid":1}})
        )
        .status,
        400
    );
    assert_eq!(service.state_digest, before);
    assert_eq!(
        service.durable.as_ref().ok_or("durable")?.generation(),
        generation
    );
    Ok(())
}

#[test]
fn custody_floors_survive_hidden_child_retirement_and_recreation_without_routing_authority()
-> Result<(), Box<dyn std::error::Error>> {
    use crate::namespace_custody::{Descriptor, Progress, Submission};
    let cluster = "namespace-floor-cluster";
    let mut registry = NamespaceRegistry::default();
    registry
        .create(cluster, "outer", BTreeMap::new(), false)
        .map_err(|_| "outer")?;
    registry
        .create(cluster, "outer/inner", BTreeMap::new(), false)
        .map_err(|_| "inner")?;
    let outer_binding = registry
        .custody_binding(cluster, "outer")
        .map_err(|_| "outer binding")?;
    let outer = Descriptor::create(outer_binding, 1, 1, b"{}")?;
    registry
        .install_custody_owner(cluster, "outer", outer.descriptor)
        .map_err(|_| "outer descriptor")?;
    let inner_binding = registry
        .custody_binding(cluster, "outer/inner")
        .map_err(|_| "inner binding")?;
    let inner = Descriptor::create(inner_binding.clone(), 1, 1, b"{}")?;
    registry
        .install_custody_owner(cluster, "outer/inner", inner.descriptor.clone())
        .map_err(|_| "inner descriptor")?;
    let old_catalog = registry
        .clone()
        .detach_catalog("outer")
        .map_err(|_| "old catalog")?;
    let mut progress = Progress::new(inner_binding.clone(), &inner.descriptor)?;
    let key = match progress.submit(&inner.descriptor, &inner.shares[0])? {
        Submission::Unlocked { key, .. } => key,
        Submission::Pending => return Err("threshold".into()),
    };
    let advanced = inner
        .descriptor
        .advance_seal_frontier(&inner_binding, &key)?;
    registry
        .install_custody_owner(cluster, "outer/inner", advanced)
        .map_err(|_| "advanced child")?;
    let visible = registry.clone();
    let catalog = registry
        .detach_catalog("outer")
        .map_err(|_| "closed catalog")?;
    registry
        .validate(cluster)
        .map_err(|_| "hidden floor validation")?;
    registry
        .validate_custody_successor(&visible)
        .map_err(|_| "retained hidden floor")?;
    let public = registry.list(cluster, "", true);
    assert!(
        !registry.contains("outer/inner") && public.body["data"]["keys"] == json!(["outer/"]),
        "a hidden child floor cannot make a route or a public catalog entry"
    );
    let mut missing = registry.clone();
    missing.custody_frontiers.remove("outer/inner");
    assert!(
        missing.validate_custody_successor(&registry).is_err(),
        "a publication cannot remove the hidden child's durable floor"
    );
    let mut stale_restore = registry.clone();
    stale_restore
        .attach_catalog("outer", old_catalog)
        .map_err(|_| "stale catalog candidate")?;
    assert!(
        stale_restore.validate(cluster).is_err(),
        "restore checks the actual child descriptor against the retained manual frontier"
    );
    registry
        .attach_catalog("outer", catalog)
        .map_err(|_| "current child restore")?;
    registry.validate(cluster).map_err(|_| "current floor")?;
    let previous = registry.clone();
    registry
        .remove("outer/inner")
        .map_err(|_| "typed child retirement")?;
    registry.validate(cluster).map_err(|_| "retirement floor")?;
    registry
        .validate_custody_successor(&previous)
        .map_err(|_| "retirement successor")?;
    let retired = registry.clone();
    registry
        .create(cluster, "outer/inner", BTreeMap::new(), false)
        .map_err(|_| "fresh child recreation")?;
    let next_binding = registry
        .custody_binding(cluster, "outer/inner")
        .map_err(|_| "fresh actual binding")?;
    assert!(
        next_binding != inner_binding,
        "recreation has a new actual identity and incarnation"
    );
    let next = Descriptor::create(next_binding, 1, 1, b"{}")?;
    registry
        .install_custody_owner(cluster, "outer/inner", next.descriptor)
        .map_err(|_| "fresh floor")?;
    registry
        .validate(cluster)
        .map_err(|_| "fresh owner floor validation")?;
    registry
        .validate_custody_successor(&retired)
        .map_err(|_| "fresh successor")?;
    assert!(
        registry
            .install_custody_owner(cluster, "outer/inner", inner.descriptor)
            .is_err(),
        "the old child's descriptor cannot attach to the new actual incarnation"
    );
    let recreated = registry.clone();
    registry
        .remove("outer/inner")
        .map_err(|_| "second incarnation retirement")?;
    registry
        .validate(cluster)
        .map_err(|_| "second retirement validation")?;
    registry
        .validate_custody_successor(&recreated)
        .map_err(|_| "second retirement successor")?;
    assert!(
        retired.validate_custody_successor(&registry).is_err(),
        "older retired floor cannot replace a newer incarnation"
    );
    Ok(())
}

#[test]
fn inherited_descriptor_floor_rejects_stale_hidden_owner_and_kind_changes()
-> Result<(), Box<dyn std::error::Error>> {
    use crate::namespace_custody::{Descriptor, InheritedDescriptor};
    let root = Root::new();
    let mut service = root.service()?;
    let (_, token) = bootstrap(&mut service)?;
    assert!(
        call(
            &mut service,
            "POST",
            "sys/namespaces/parent",
            &token,
            json!({})
        )
        .status
            == 200,
        "actual ordinary parent"
    );
    assert!(
        service
            .handle_at(
                "POST",
                "sys/namespaces/child",
                "parent",
                &token,
                json!({}),
                100
            )
            .status
            == 200,
        "actual ordinary child"
    );
    let state = service.state.as_ref().ok_or("actual state")?;
    let cluster = &state.cluster_id;
    let root_key = service.barrier_key.as_ref().ok_or("actual root key")?;
    let actual = "parent/child";
    let mut registry = state.namespaces.clone();
    let binding = registry
        .custody_binding(cluster, actual)
        .map_err(|_| "actual child binding")?;
    let (first, key) = InheritedDescriptor::create_root(binding.clone(), root_key, b"{}")?;
    registry
        .install_inherited_owner(cluster, actual, first.clone())
        .map_err(|_| "first inherited floor")?;
    let second = first.advance_seal_frontier(&binding, &key)?;
    registry
        .install_inherited_owner(cluster, actual, second.clone())
        .map_err(|_| "next inherited floor")?;
    assert!(
        registry
            .install_inherited_owner(cluster, actual, first.clone())
            .is_err(),
        "same incarnation cannot restore a stale frontier"
    );
    let independent = Descriptor::create(binding.clone(), 1, 1, b"{}")?;
    assert!(
        registry
            .install_custody_owner(cluster, actual, independent.descriptor)
            .is_err(),
        "live inherited owner cannot change custody kind"
    );
    let parent = registry
        .detach_catalog("parent")
        .map_err(|_| "actual parent detach")?;
    assert!(
        !registry.contains(actual) && registry.custody_frontiers.contains_key(actual),
        "hidden catalog cannot erase the exact private child floor"
    );
    let public = registry.list(cluster, "", true);
    assert!(
        public.body["data"]["keys"] == json!(["parent/"]),
        "private floor grants no public catalog entry"
    );
    let mut stale = serde_json::to_value(&parent)?;
    stale["entries"][actual]["inherited"] = serde_json::to_value(&first)?;
    let stale = serde_json::from_value(stale)?;
    let mut rejected = registry.clone();
    rejected
        .attach_catalog("parent", stale)
        .map_err(|_| "stale candidate catalog attach")?;
    assert!(
        rejected.validate(cluster).is_err(),
        "restored hidden descriptor must match the retained root floor"
    );
    registry
        .attach_catalog("parent", parent)
        .map_err(|_| "exact current catalog")?;
    registry
        .validate(cluster)
        .map_err(|_| "current exact floor")?;
    let mut false_flag = registry.clone();
    false_flag
        .set_sealed(actual, true)
        .map_err(|_| "candidate flag")?;
    assert!(
        false_flag.validate(cluster).is_err(),
        "inherited ciphertext cannot be replaced by a boolean seal grant"
    );
    Ok(())
}

#[test]
fn inherited_retirement_requires_a_new_actual_incarnation_before_recreation()
-> Result<(), Box<dyn std::error::Error>> {
    use crate::namespace_custody::{Descriptor, InheritedDescriptor};
    let root = Root::new();
    let mut service = root.service()?;
    let (_, token) = bootstrap(&mut service)?;
    assert!(
        call(
            &mut service,
            "POST",
            "sys/namespaces/recreate",
            &token,
            json!({})
        )
        .status
            == 200,
        "actual ordinary owner"
    );
    let state = service.state.as_ref().ok_or("state")?;
    let cluster = &state.cluster_id;
    let root_key = service.barrier_key.as_ref().ok_or("actual root key")?;
    let mut registry = state.namespaces.clone();
    let first_binding = registry
        .custody_binding(cluster, "recreate")
        .map_err(|_| "first binding")?;
    let (first, _) = InheritedDescriptor::create_root(first_binding.clone(), root_key, b"{}")?;
    registry
        .install_inherited_owner(cluster, "recreate", first.clone())
        .map_err(|_| "first actual inherited owner")?;
    registry.remove("recreate").map_err(|_| "retirement")?;
    registry.validate(cluster).map_err(|_| "retired floor")?;
    assert!(
        registry.custody_frontiers["recreate"].is_retired() && !registry.contains("recreate"),
        "retirement persists without routing authority"
    );
    registry
        .insert_legacy(cluster, "recreate")
        .map_err(|_| "fresh catalog incarnation")?;
    assert!(
        registry
            .install_inherited_owner(cluster, "recreate", first)
            .is_err(),
        "retired key owner cannot authorize a recreated namespace"
    );
    let next_binding = registry
        .custody_binding(cluster, "recreate")
        .map_err(|_| "new binding")?;
    assert!(
        next_binding != first_binding,
        "genuine recreation changes binding and incarnation"
    );
    let (next, _) = InheritedDescriptor::create_root(next_binding.clone(), root_key, b"{}")?;
    registry
        .install_inherited_owner(cluster, "recreate", next)
        .map_err(|_| "new actual inherited owner")?;
    registry
        .validate(cluster)
        .map_err(|_| "new incarnation floor")?;
    let mut independent = state.namespaces.clone();
    let created = Descriptor::create(first_binding.clone(), 1, 1, b"{}")?;
    independent
        .install_custody_owner(cluster, "recreate", created.descriptor)
        .map_err(|_| "actual independent owner")?;
    let (wrong_kind, _) = InheritedDescriptor::create_root(first_binding, root_key, b"{}")?;
    assert!(
        independent
            .install_inherited_owner(cluster, "recreate", wrong_kind)
            .is_err(),
        "live independent owner cannot change to inherited custody"
    );
    Ok(())
}

#[test]
fn namespace_local_kv_and_token_delete_retires_actual_owner_and_survives_reopen()
-> Result<(), Box<dyn std::error::Error>> {
    let root = Root::new();
    let mut service = root.service()?;
    let (key, root_token) = bootstrap(&mut service)?;
    for namespace in ["local-delete", "local-sibling"] {
        assert_eq!(
            call(
                &mut service,
                "POST",
                &format!("sys/namespaces/{namespace}"),
                &root_token,
                json!({})
            )
            .status,
            200
        );
        assert_eq!(
            service
                .handle_at(
                    "POST",
                    "sys/mounts/kv",
                    namespace,
                    &root_token,
                    json!({"type":"kv", "options":{"version":"1"}}),
                    100
                )
                .status,
            204
        );
        assert_eq!(
            service
                .handle_at(
                    "PUT",
                    "kv/item",
                    namespace,
                    &root_token,
                    json!({"value":namespace}),
                    100
                )
                .status,
            204
        );
        assert_eq!(
            service
                .handle_at("GET", "kv/item", namespace, &root_token, json!({}), 100)
                .status,
            200
        );
    }
    let mint = service.handle_at(
        "POST",
        "auth/token/create",
        "local-delete",
        &root_token,
        json!({"policies":["default"]}),
        100,
    );
    assert_eq!(mint.status, 200);
    let child = mint.body["auth"]["client_token"]
        .as_str()
        .ok_or("child token")?
        .to_owned();
    let accessor = mint.body["auth"]["accessor"]
        .as_str()
        .ok_or("child accessor")?
        .to_owned();
    assert_eq!(
        service
            .handle_at(
                "GET",
                "auth/token/lookup-self",
                "local-delete",
                &child,
                json!({}),
                100
            )
            .status,
        200
    );
    // Match the genuine SDK flow: revoke an issued child, retain a real mount
    // and KV record, then request deletion. A second live local token proves
    // closure removes its actual encrypted token owner as well.
    assert_eq!(
        service
            .handle_at(
                "POST",
                "auth/token/revoke-accessor",
                "local-delete",
                &root_token,
                json!({"accessor":accessor}),
                100
            )
            .status,
        204
    );
    let mint = service.handle_at(
        "POST",
        "auth/token/create",
        "local-delete",
        &root_token,
        json!({"policies":["default"]}),
        100,
    );
    assert_eq!(mint.status, 200);
    let live = mint.body["auth"]["client_token"]
        .as_str()
        .ok_or("live token")?
        .to_owned();
    let stale = service.state.clone().ok_or("state")?;
    let binding = stale
        .namespaces
        .custody_binding(&stale.cluster_id, "local-delete")
        .map_err(|_| "binding")?;
    let floor = serde_json::to_value(&stale.auth)?["public_origin_floor"].clone();
    let clock = serde_json::to_value(&stale.engines)?["kubernetes_artifact_clock"].clone();
    let deleted = call(
        &mut service,
        "DELETE",
        "sys/namespaces/local-delete",
        &root_token,
        json!({}),
    );
    assert_eq!(deleted.status, 200);
    assert_eq!(deleted.body["data"]["status"], "in-progress");
    assert!(
        stale.namespace_leases.validate().is_err(),
        "retained references cannot keep the retired key live"
    );
    let retired = service.state.as_ref().ok_or("state")?;
    assert!(!retired.namespaces.contains("local-delete"));
    assert!(
        retired.auth.namespace_is_empty("local-delete")
            && retired.engines.namespace_is_empty("local-delete")
    );
    assert_eq!(
        serde_json::to_value(&retired.auth)?["public_origin_floor"],
        floor
    );
    assert_eq!(
        serde_json::to_value(&retired.engines)?["kubernetes_artifact_clock"],
        clock
    );
    assert!(
        retired
            .namespaces
            .retired_custody
            .get("local-delete")
            .is_some_and(
                |tombstone| retired.namespaces.custody_frontiers["local-delete"]
                    .matches_retirement(tombstone)
            )
    );
    retired
        .engines
        .visit_namespace_record_owner_bindings(|owner| {
            assert_ne!(owner, &binding);
            Ok(())
        })?;
    assert_eq!(
        service
            .handle_at(
                "GET",
                "kv/item",
                "local-sibling",
                &root_token,
                json!({}),
                100
            )
            .body["data"]["value"],
        "local-sibling"
    );
    drop(service);
    let mut service = root.service()?;
    assert_eq!(
        call(&mut service, "PUT", "sys/unseal", "", json!({"key":key})).status,
        200
    );
    assert_eq!(
        call(
            &mut service,
            "GET",
            "sys/namespaces/local-delete",
            &root_token,
            json!({})
        )
        .status,
        404
    );
    assert_eq!(
        call(
            &mut service,
            "POST",
            "sys/namespaces/local-delete",
            &root_token,
            json!({})
        )
        .status,
        200
    );
    assert_ne!(
        service
            .state
            .as_ref()
            .ok_or("state")?
            .namespaces
            .custody_binding(
                &service.state.as_ref().ok_or("state")?.cluster_id,
                "local-delete"
            )
            .map_err(|_| "recreated binding")?,
        binding
    );
    assert!(
        service
            .handle_at(
                "GET",
                "auth/token/lookup-self",
                "local-delete",
                &live,
                json!({}),
                100
            )
            .status
            >= 400
    );
    assert_eq!(
        service
            .handle_at(
                "POST",
                "sys/mounts/kv",
                "local-delete",
                &root_token,
                json!({"type":"kv", "options":{"version":"1"}}),
                100
            )
            .status,
        204
    );
    assert_eq!(
        service
            .handle_at(
                "GET",
                "kv/item",
                "local-delete",
                &root_token,
                json!({}),
                100
            )
            .status,
        404
    );
    assert_eq!(
        service
            .handle_at(
                "GET",
                "kv/item",
                "local-sibling",
                &root_token,
                json!({}),
                100
            )
            .body["data"]["value"],
        "local-sibling"
    );
    Ok(())
}

#[test]
fn namespace_local_delete_does_not_discard_provider_mounts_or_unloaded_custody()
-> Result<(), Box<dyn std::error::Error>> {
    let root = Root::new();
    let mut service = root.service()?;
    let (_, root_token) = bootstrap(&mut service)?;
    assert_eq!(
        call(
            &mut service,
            "POST",
            "sys/namespaces/provider-delete",
            &root_token,
            json!({})
        )
        .status,
        200
    );
    assert_eq!(
        service
            .handle_at(
                "POST",
                "sys/mounts/database",
                "provider-delete",
                &root_token,
                json!({"type":"database"}),
                100
            )
            .status,
        204
    );
    let before = service.state.clone().ok_or("state")?;
    assert_eq!(
        call(
            &mut service,
            "DELETE",
            "sys/namespaces/provider-delete",
            &root_token,
            json!({})
        )
        .status,
        409
    );
    assert_eq!(
        serde_json::to_value(&service.state.as_ref().ok_or("state")?.engines)?,
        serde_json::to_value(&before.engines)?
    );
    assert!(
        service
            .state
            .as_ref()
            .ok_or("state")?
            .namespaces
            .contains("provider-delete")
    );
    assert_eq!(
        call(
            &mut service,
            "POST",
            "sys/namespaces/unloaded-delete",
            &root_token,
            json!({})
        )
        .status,
        200
    );
    assert_eq!(
        service
            .handle_at(
                "POST",
                "sys/mounts/kv",
                "unloaded-delete",
                &root_token,
                json!({"type":"kv", "options":{"version":"1"}}),
                100
            )
            .status,
        204
    );
    assert_eq!(
        call(
            &mut service,
            "POST",
            "sys/namespaces/unloaded-delete/seal",
            &root_token,
            json!({})
        )
        .status,
        204
    );
    assert_eq!(
        call(
            &mut service,
            "DELETE",
            "sys/namespaces/unloaded-delete",
            &root_token,
            json!({})
        )
        .status,
        503
    );
    assert!(
        service
            .state
            .as_ref()
            .ok_or("state")?
            .namespaces
            .contains("unloaded-delete")
    );
    Ok(())
}

#[test]
fn namespace_delete_does_not_resurrect_orphan_batch_after_path_recreation()
-> Result<(), Box<dyn std::error::Error>> {
    for populated in [false, true] {
        let root = Root::new();
        let mut service = root.service()?;
        let (_, root_token) = bootstrap(&mut service)?;
        assert_eq!(
            call(
                &mut service,
                "POST",
                "sys/namespaces/batch-retire",
                &root_token,
                json!({})
            )
            .status,
            200
        );
        if populated {
            assert_eq!(
                service
                    .handle_at(
                        "POST",
                        "sys/mounts/kv",
                        "batch-retire",
                        &root_token,
                        json!({"type":"kv", "options":{"version":"1"}}),
                        100
                    )
                    .status,
                204
            );
            assert_eq!(
                service
                    .handle_at(
                        "PUT",
                        "kv/item",
                        "batch-retire",
                        &root_token,
                        json!({"secret":"local"}),
                        100
                    )
                    .status,
                204
            );
        }
        let minted = service.handle_at(
            "POST",
            "auth/token/create-orphan",
            "batch-retire",
            &root_token,
            json!({"type":"batch", "policies":["default"], "ttl":"1h"}),
            100,
        );
        assert_eq!(minted.status, 200);
        let bearer = minted.body["auth"]["client_token"]
            .as_str()
            .ok_or("batch token")?
            .to_owned();
        let lookup = service.handle_at(
            "GET",
            "auth/token/lookup-self",
            "batch-retire",
            &bearer,
            json!({}),
            100,
        );
        assert_eq!(lookup.status, 200);
        assert_eq!(lookup.body["data"]["orphan"], true);
        let before = service.state.clone().ok_or("state")?;
        let binding = before
            .namespaces
            .custody_binding(&before.cluster_id, "batch-retire")
            .map_err(|_| "binding")?;
        let batch_key_before = crate::crypto::digest(
            &crate::secret_serde::to_vec(&before.auth, crate::MAX_APPLICATION_STATE_BYTES)
                .map_err(|_| "auth owner")?,
        );
        assert_eq!(
            call(
                &mut service,
                "DELETE",
                "sys/namespaces/batch-retire",
                &root_token,
                json!({})
            )
            .status,
            409
        );
        let after = service.state.as_ref().ok_or("state")?;
        assert_eq!(
            after
                .namespaces
                .custody_binding(&after.cluster_id, "batch-retire")
                .map_err(|_| "retained binding")?,
            binding
        );
        assert_eq!(
            crate::crypto::digest(
                &crate::secret_serde::to_vec(&after.auth, crate::MAX_APPLICATION_STATE_BYTES)
                    .map_err(|_| "retained auth")?
            ),
            batch_key_before
        );
        // A standard create after the rejected DELETE is the existing owner,
        // rather than an incarnation to which the old stateless token can revive.
        assert_eq!(
            call(
                &mut service,
                "POST",
                "sys/namespaces/batch-retire",
                &root_token,
                json!({})
            )
            .status,
            200
        );
        let after = service.state.as_ref().ok_or("state")?;
        assert_eq!(
            after
                .namespaces
                .custody_binding(&after.cluster_id, "batch-retire")
                .map_err(|_| "same owner")?,
            binding
        );
        assert_eq!(
            service
                .handle_at(
                    "GET",
                    "auth/token/lookup-self",
                    "batch-retire",
                    &bearer,
                    json!({}),
                    100
                )
                .status,
            200
        );
    }
    Ok(())
}
