use super::*;
use crate::configuration::NativeStorageProfile;
use crate::service::tests::Root;
use sha2::Digest;
use std::io::{self, Read};
use std::time::{Duration, Instant};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

// Empty LIST/SCAN and the relative scoped-token observations below are bound
// to official 2.7.1 Darwin/arm64 receipt 624000630338617f61556de72afffeb8745a79355d95e746251c4378bf86b08f.

fn call(
    service: &mut Service,
    method: &str,
    path: &str,
    namespace: &str,
    token: &str,
    body: Value,
) -> Response {
    let _deadline = crate::request_deadline::RequestDeadlineScope::enter(
        Instant::now() + Duration::from_secs(15),
    );
    service.handle(method, path, namespace, token, body)
}

fn formal() -> TestResult<(Root, Service, Zeroizing<String>, Zeroizing<String>)> {
    let files = Root::new();
    let mut service = files.service()?;
    service.configure_native_v6_storage(NativeStorageProfile::File)?;
    let nonce = Zeroizing::new(hex(&crypto::random::<32>()?));
    let mut initialized = call(
        &mut service,
        "POST",
        "sys/init",
        "",
        "",
        json!({"secret_shares": 1, "secret_threshold": 1, "recovery_nonce": nonce.as_str()}),
    );
    assert_eq!(initialized.status, 200);
    let key = Zeroizing::new(
        initialized.body["keys"][0]
            .as_str()
            .ok_or("share")?
            .to_owned(),
    );
    let admin = Zeroizing::new(
        initialized.body["root_token"]
            .as_str()
            .ok_or("token")?
            .to_owned(),
    );
    erase_json(&mut initialized.body);
    assert_eq!(
        call(
            &mut service,
            "POST",
            "sys/unseal",
            "",
            "",
            json!({"key": key.as_str()})
        )
        .status,
        200
    );
    assert_eq!(
        call(&mut service, "POST", "sys/init/ack", "", &admin, json!({})).status,
        204
    );
    assert_eq!(
        call(
            &mut service,
            "POST",
            "sys/storage/native-v6/activate",
            "",
            &admin,
            json!({})
        )
        .status,
        204
    );
    Ok((files, service, key, admin))
}

fn create(service: &mut Service, namespace: &str, name: &str, admin: &str) -> Response {
    let response = call(
        service,
        "POST",
        &format!("sys/namespaces/{name}"),
        namespace,
        admin,
        json!({"custom_metadata": {"owner": "native-tree-test", "keep": "present"}}),
    );
    assert_eq!(response.status, 200, "{}", response.body["errors"]);
    response
}

fn snapshot(
    service: &mut Service,
    admin: &str,
    input: Option<&[u8]>,
) -> TestResult<(Response, Option<Zeroizing<Vec<u8>>>)> {
    let deadline = Instant::now() + Duration::from_secs(15);
    let _scope = crate::request_deadline::RequestDeadlineScope::enter(deadline);
    let method = if input.is_some() { "POST" } else { "GET" };
    match service.begin_native_snapshot_before(
        ServiceRequest::new(method, "sys/storage/raft/snapshot", "", admin, json!({})),
        deadline,
    ) {
        NativeSnapshotAdmission::Execute(RequestExecution::External(mut pending)) => {
            let mut reader = io::Cursor::new(input.unwrap_or_default());
            let (observation, file) = pending.execute_snapshot_transfer(&mut reader);
            let response = service.finish_external_request(*pending, observation);
            assert!(service.native_request_binding.is_none());
            let archive = if let Some(mut file) = file {
                file.rewind_checked()?;
                let mut bytes = Zeroizing::new(Vec::new());
                file.read_to_end(&mut bytes)?;
                Some(bytes)
            } else {
                None
            };
            assert!(Instant::now() < deadline);
            Ok((response, archive))
        }
        NativeSnapshotAdmission::Execute(RequestExecution::Complete(response)) => {
            Ok((response, None))
        }
        NativeSnapshotAdmission::Redirect(_) => Err("formal File snapshot redirected".into()),
    }
}

#[test]
fn formal_native_namespace_tree_metadata_and_scoped_kv2_survive_cold_reopen() -> TestResult {
    let (files, mut service, key, admin) = formal()?;
    create(&mut service, "", "team", &admin);
    create(&mut service, "", "sibling", &admin);
    let child = create(&mut service, "team", "child", &admin);
    create(&mut service, "team/child", "grand", &admin);
    let patched = call(
        &mut service,
        "PATCH",
        "sys/namespaces/child",
        "team",
        &admin,
        json!({"custom_metadata": {"owner": "changed", "keep": null}}),
    );
    assert_eq!(patched.status, 200, "{}", patched.body["errors"]);
    assert_eq!(patched.body["data"]["id"], child.body["data"]["id"]);
    assert_eq!(
        patched.body["data"]["custom_metadata"],
        json!({"owner": "changed"})
    );
    for namespace in ["team/child", "sibling"] {
        let mounted = call(
            &mut service,
            "POST",
            "sys/mounts/vault",
            namespace,
            &admin,
            json!({"type": "kv", "options": {"version": "2"}}),
        );
        assert_eq!(mounted.status, 204, "{}", mounted.body["errors"]);
        let written = call(
            &mut service,
            "POST",
            "vault/data/same-key",
            namespace,
            &admin,
            json!({"data": {"scope": namespace}}),
        );
        assert_eq!(written.status, 200, "{}", written.body["errors"]);
    }
    let state = service.state.as_ref().ok_or("state")?;
    assert_eq!(state.schema, NATIVE_PLAIN_NAMESPACE_TREE_STATE_SCHEMA);
    assert_eq!(state.namespaces.native_flat_retirement_format, Some(2));
    assert!(state.validate_native_flat_retirement_state(None).is_ok());
    let catalog = owner_store::serialize_owner(&state.namespaces)?;
    let refused = call(
        &mut service,
        "DELETE",
        "sys/namespaces/sibling",
        "",
        &admin,
        json!({}),
    );
    assert_eq!(refused.status, 409, "{}", refused.body["errors"]);
    assert_eq!(
        catalog,
        owner_store::serialize_owner(&service.state.as_ref().ok_or("unchanged state")?.namespaces)?
    );
    drop(service);

    let mut cold = files.service()?;
    cold.configure_native_v6_storage(NativeStorageProfile::File)?;
    assert_eq!(
        call(
            &mut cold,
            "POST",
            "sys/unseal",
            "",
            "",
            json!({"key": key.as_str()})
        )
        .status,
        200
    );
    assert!(cold.native_root.is_some() && cold.record_root.is_none());
    assert_eq!(
        catalog,
        owner_store::serialize_owner(&cold.state.as_ref().ok_or("cold state")?.namespaces)?
    );
    for (namespace, expected) in [
        ("", json!(["sibling/", "team/"])),
        ("team", json!(["child/"])),
        ("team/child", json!(["grand/"])),
    ] {
        let listed = call(
            &mut cold,
            "LIST",
            "sys/namespaces",
            namespace,
            &admin,
            json!({}),
        );
        assert_eq!(listed.status, 200, "{}", listed.body["errors"]);
        assert_eq!(listed.body["data"]["keys"], expected);
    }
    for namespace in ["team/child", "sibling"] {
        let read = call(
            &mut cold,
            "GET",
            "vault/data/same-key",
            namespace,
            &admin,
            json!({}),
        );
        assert_eq!(read.status, 200, "{}", read.body["errors"]);
        assert_eq!(read.body["data"]["data"]["scope"], namespace);
    }
    assert_eq!(
        call(
            &mut cold,
            "GET",
            "sys/namespaces/sibling",
            "team",
            &admin,
            json!({})
        )
        .status,
        404
    );
    let metadata = call(
        &mut cold,
        "GET",
        "sys/namespaces/child",
        "team",
        &admin,
        json!({}),
    );
    assert_eq!(metadata.status, 200);
    assert_eq!(metadata.body["data"], patched.body["data"]);
    assert!(!cold.recovery_required);
    Ok(())
}

#[test]
fn formal_native_namespace_tree_retirement_frontiers_and_floor_survive_empty_cold_state()
-> TestResult {
    let (files, mut service, key, admin) = formal()?;
    let parent = create(&mut service, "", "team", &admin);
    let flat = service.state.as_ref().ok_or("flat state")?.clone();
    let child = create(&mut service, "team", "child", &admin);
    let before = owner_store::serialize_owner(&service.state.as_ref().ok_or("state")?.namespaces)?;
    assert_eq!(
        call(
            &mut service,
            "DELETE",
            "sys/namespaces/team",
            "",
            &admin,
            json!({})
        )
        .status,
        400
    );
    assert_eq!(
        before,
        owner_store::serialize_owner(&service.state.as_ref().ok_or("unchanged state")?.namespaces)?
    );
    let removed = call(
        &mut service,
        "DELETE",
        "sys/namespaces/child",
        "team",
        &admin,
        json!({}),
    );
    assert_eq!(removed.status, 200, "{}", removed.body["errors"]);
    assert_eq!(removed.body["data"]["status"], "in-progress");
    let repeated = call(
        &mut service,
        "DELETE",
        "sys/namespaces/child",
        "team",
        &admin,
        json!({}),
    );
    assert_eq!(repeated.status, 200);
    assert!(repeated.body["data"].is_null());
    assert_eq!(
        call(
            &mut service,
            "DELETE",
            "sys/namespaces/team",
            "",
            &admin,
            json!({})
        )
        .status,
        200
    );
    let retired = service.state.as_ref().ok_or("retired state")?.clone();
    assert!(retired.namespaces.entries.is_empty());
    assert_eq!(retired.namespaces.native_flat_retirement_format, Some(2));
    assert_eq!(retired.namespaces.next_incarnation.get("team"), Some(&2));
    assert_eq!(
        retired.namespaces.next_incarnation.get("team/child"),
        Some(&2)
    );
    assert_eq!(retired.schema, NATIVE_PLAIN_NAMESPACE_TREE_STATE_SCHEMA);
    assert!(Service::validate_snapshot_protected_floor(&retired, &flat).is_err());
    let bytes = owner_store::serialize_owner(&retired.namespaces)?;
    drop(service);

    let mut cold = files.service()?;
    cold.configure_native_v6_storage(NativeStorageProfile::File)?;
    assert_eq!(
        call(
            &mut cold,
            "POST",
            "sys/unseal",
            "",
            "",
            json!({"key": key.as_str()})
        )
        .status,
        200
    );
    assert_eq!(
        bytes,
        owner_store::serialize_owner(&cold.state.as_ref().ok_or("cold retired")?.namespaces)?
    );
    let next_parent = create(&mut cold, "", "team", &admin);
    let next_child = create(&mut cold, "team", "child", &admin);
    assert_ne!(next_parent.body["data"]["id"], parent.body["data"]["id"]);
    assert_ne!(next_child.body["data"]["id"], child.body["data"]["id"]);
    let recreated = cold.state.as_ref().ok_or("recreated")?;
    assert_eq!(recreated.namespaces.incarnation("team"), Some(2));
    assert_eq!(recreated.namespaces.incarnation("team/child"), Some(2));
    assert_eq!(recreated.namespaces.next_incarnation.get("team"), Some(&3));
    assert_eq!(
        recreated.namespaces.next_incarnation.get("team/child"),
        Some(&3)
    );
    assert!(
        recreated
            .validate_native_flat_retirement_state(Some(&retired))
            .is_ok()
    );
    assert!(recreated.validate_namespace_batch_state().is_ok());
    assert!(!cold.recovery_required);
    Ok(())
}

#[test]
fn formal_native_namespace_tree_rejects_missing_marker_ancestors_and_paired_history() -> TestResult
{
    let (_files, mut service, _key, admin) = formal()?;
    create(&mut service, "", "team", &admin);
    create(&mut service, "team", "child", &admin);
    create(&mut service, "team/child", "grand", &admin);
    let current = service.state.as_ref().ok_or("current state")?.clone();
    let registry = current
        .namespaces
        .batch_lifecycle
        .as_ref()
        .ok_or("actual ledger")?;
    let all_paths = current.namespaces.entries.keys().cloned().collect();
    assert!(registry.native_v6_plain_incarnation_profile(&all_paths));
    assert!(!registry.native_v6_plain_incarnation_profile(&BTreeSet::from(["team".to_owned()])));
    assert!(!registry.native_v6_flat_incarnation_profile());
    let scope = native_plain::PlainNamespaceScope::capture(&current, "team/child/grand")
        .map_err(|_| "actual plain tree scope")?;
    assert!(scope.check(&current).is_ok());
    for marker in [None, Some(1), Some(3)] {
        let mut changed = current.clone();
        changed.namespaces.native_flat_retirement_format = marker;
        assert!(changed.validate_format().is_err());
        assert!(changed.validate_publication_schema(Some(&current)).is_err());
    }
    let mut lower = current.clone();
    lower.schema = NATIVE_PLAIN_NAMESPACE_TREE_STATE_SCHEMA - 1;
    assert!(lower.validate_format().is_err());
    assert!(lower.validate_publication_schema(Some(&current)).is_err());
    let mut missing_ledger = current.clone();
    missing_ledger.namespaces.batch_lifecycle = None;
    assert!(missing_ledger.validate_format().is_err());
    for ancestor in ["team", "team/child"] {
        let mut absent = current.clone();
        absent.namespaces.entries.remove(ancestor);
        assert!(scope.check(&absent).is_err());
        let mut changed = current.clone();
        changed
            .namespaces
            .entries
            .get_mut(ancestor)
            .ok_or("ancestor")?
            .id
            .push('x');
        assert!(scope.check(&changed).is_err());
    }
    let mut history = current.clone();
    history
        .namespaces
        .next_incarnation
        .insert("retired/deep".to_owned(), 2);
    assert!(history.validate_format().is_err());
    let mut sealed = current.clone();
    sealed
        .namespaces
        .entries
        .get_mut("team")
        .ok_or("parent")?
        .sealed = true;
    assert!(scope.check(&sealed).is_err());
    // All malformed candidates above are detached rejection checks. The real
    // published ledger remains complete and no alternate actor is introduced.
    assert!(
        service
            .state
            .as_ref()
            .ok_or("live")?
            .validate_format()
            .is_ok()
    );
    assert!(!service.recovery_required);
    Ok(())
}

#[test]
fn formal_native_namespace_tree_scoped_catalog_acl_and_empty_contract() -> TestResult {
    let (_files, mut service, _key, admin) = formal()?;
    create(&mut service, "", "team", &admin);
    create(&mut service, "", "sibling", &admin);
    create(&mut service, "team", "visible", &admin);
    for (method, status, body) in [
        ("LIST", 404, json!({"errors": []})),
        ("SCAN", 200, json!({"data": {}})),
    ] {
        let response = call(
            &mut service,
            method,
            "sys/namespaces",
            "team/visible",
            &admin,
            json!({}),
        );
        assert_eq!(response.status, status, "{}", response.body["errors"]);
        assert_eq!(response.body, body);
        assert_eq!(
            call(
                &mut service,
                method,
                "sys/namespaces",
                "team/missing",
                &admin,
                json!({})
            )
            .status,
            404
        );
    }
    let policy = r#"path "sys/namespaces" { capabilities = ["list"] }
path "sys/namespaces/visible" { capabilities = ["read"] }
path "auth/token/lookup-self" { capabilities = ["read"] }"#;
    assert_eq!(
        call(
            &mut service,
            "PUT",
            "sys/policies/acl/tree-reader",
            "team",
            &admin,
            json!({"policy": policy})
        )
        .status,
        204
    );
    let mut issued = call(
        &mut service,
        "POST",
        "auth/token/create",
        "team",
        &admin,
        json!({"policies": ["tree-reader"], "no_default_policy": true, "ttl": "10m"}),
    );
    assert_eq!(issued.status, 200, "{}", issued.body["errors"]);
    let token = Zeroizing::new(
        issued.body["auth"]["client_token"]
            .as_str()
            .ok_or("child token")?
            .to_owned(),
    );
    erase_json(&mut issued.body);
    assert!(token.as_str() != admin.as_str());
    let mut identity = call(
        &mut service,
        "GET",
        "auth/token/lookup-self",
        "team",
        &token,
        json!({}),
    );
    assert_eq!(identity.status, 200);
    assert!(identity.body["data"]["id"].as_str() == Some(token.as_str()));
    assert_eq!(identity.body["data"]["policies"], json!(["tree-reader"]));
    erase_json(&mut identity.body);
    let listed = call(
        &mut service,
        "LIST",
        "sys/namespaces",
        "team",
        &token,
        json!({}),
    );
    assert_eq!(listed.status, 200);
    assert_eq!(listed.body["data"]["keys"], json!(["visible/"]));
    let own = call(
        &mut service,
        "GET",
        "sys/namespaces/visible",
        "team",
        &token,
        json!({}),
    );
    assert_eq!(own.status, 200);
    assert_eq!(own.body["data"]["path"], "team/visible/");
    let catalog = owner_store::serialize_owner(&service.state.as_ref().ok_or("state")?.namespaces)?;
    for (namespace, path) in [
        ("team", "sys/namespaces/sibling"),
        ("sibling", "sys/namespaces/visible"),
        ("", "sys/namespaces/visible"),
    ] {
        let denied = call(&mut service, "GET", path, namespace, &token, json!({}));
        assert_eq!(denied.status, 403, "{}", denied.body["errors"]);
        assert!(denied.body.get("data").is_none());
    }
    assert_eq!(
        call(
            &mut service,
            "POST",
            "auth/token/revoke",
            "team",
            &admin,
            json!({"token": token.as_str()})
        )
        .status,
        204
    );
    assert_eq!(
        call(
            &mut service,
            "GET",
            "sys/namespaces/visible",
            "team",
            &token,
            json!({})
        )
        .status,
        403
    );
    assert_eq!(
        catalog,
        owner_store::serialize_owner(
            &service
                .state
                .as_ref()
                .ok_or("unchanged catalog")?
                .namespaces
        )?
    );
    assert!(!service.recovery_required);
    Ok(())
}

#[test]
fn formal_native_namespace_tree_actual_snapshot_restore_and_cold_keep_paired_frontiers()
-> TestResult {
    let (files, mut service, key, admin) = formal()?;
    create(&mut service, "", "team", &admin);
    let (response, flat) = snapshot(&mut service, &admin, None)?;
    assert_eq!(response.status, 200, "{}", response.body["errors"]);
    let flat = flat.ok_or("actual pre-tree archive")?;

    let child = create(&mut service, "team", "child", &admin);
    create(&mut service, "team", "retired", &admin);
    assert_eq!(
        call(
            &mut service,
            "DELETE",
            "sys/namespaces/retired",
            "team",
            &admin,
            json!({})
        )
        .status,
        200
    );
    assert_eq!(
        call(
            &mut service,
            "POST",
            "sys/mounts/secret",
            "team/child",
            &admin,
            json!({"type":"kv", "options":{"version":"2"}})
        )
        .status,
        204
    );
    assert_eq!(
        call(
            &mut service,
            "POST",
            "secret/data/item",
            "team/child",
            &admin,
            json!({"options":{"cas":0}, "data":{"value":"archived-child-value"}})
        )
        .status,
        200
    );

    let expected = service.state.as_ref().ok_or("actual tree state")?;
    assert_eq!(expected.schema, NATIVE_PLAIN_NAMESPACE_TREE_STATE_SCHEMA);
    assert_eq!(expected.namespaces.native_flat_retirement_format, Some(2));
    assert_eq!(
        expected.namespaces.next_incarnation.get("team/retired"),
        Some(&2)
    );
    assert!(expected.validate_namespace_batch_state().is_ok());
    let catalog = owner_store::serialize_owner(&expected.namespaces)?;
    let ledger = expected
        .namespaces
        .batch_lifecycle
        .clone()
        .ok_or("actual namespace ledger")?;
    assert!(expected.auth.namespace_batch_registry() == Some(&ledger));
    let (response, archive) = snapshot(&mut service, &admin, None)?;
    assert_eq!(response.status, 200, "{}", response.body["errors"]);
    let archive = archive.ok_or("actual tree archive")?;
    assert!(archive.starts_with(&[0x1f, 0x8b]));
    let archive_hash = sha2::Sha256::digest(archive.as_slice());

    // These are real public-route changes. No retirement frontier is lowered
    // or advanced to make an otherwise prohibited snapshot look admissible.
    assert_eq!(
        call(
            &mut service,
            "PATCH",
            "sys/namespaces/child",
            "team",
            &admin,
            json!({"custom_metadata":{"owner":"after-archive"}})
        )
        .status,
        200
    );
    assert_eq!(
        call(
            &mut service,
            "POST",
            "secret/data/item",
            "team/child",
            &admin,
            json!({"options":{"cas":1}, "data":{"value":"after-archive"}})
        )
        .status,
        200
    );
    assert_eq!(
        call(
            &mut service,
            "POST",
            "secret/data/only-after",
            "team/child",
            &admin,
            json!({"options":{"cas":0}, "data":{"value":"not-in-archive"}})
        )
        .status,
        200
    );
    assert_ne!(
        catalog,
        owner_store::serialize_owner(&service.state.as_ref().ok_or("modified tree")?.namespaces)?
    );
    let modified_catalog =
        owner_store::serialize_owner(&service.state.as_ref().ok_or("modified tree")?.namespaces)?;
    let (rejected, output) = snapshot(&mut service, &admin, Some(&flat))?;
    assert_eq!(
        rejected.status, 400,
        "old actual flat archive must retain the tree floor"
    );
    assert!(output.is_none());
    assert_eq!(
        modified_catalog,
        owner_store::serialize_owner(
            &service
                .state
                .as_ref()
                .ok_or("post-rejection tree")?
                .namespaces
        )?
    );
    assert_eq!(
        call(
            &mut service,
            "GET",
            "secret/data/item",
            "team/child",
            &admin,
            json!({})
        )
        .body["data"]["data"]["value"],
        "after-archive"
    );

    let (restored, output) = snapshot(&mut service, &admin, Some(&archive))?;
    assert_eq!(restored.status, 200, "{}", restored.body["errors"]);
    assert!(output.is_none());
    assert_eq!(sha2::Sha256::digest(archive.as_slice()), archive_hash);
    for cold in [false, true] {
        if cold {
            drop(service);
            service = files.service()?;
            service.configure_native_v6_storage(NativeStorageProfile::File)?;
            assert_eq!(
                call(
                    &mut service,
                    "POST",
                    "sys/unseal",
                    "",
                    "",
                    json!({"key":key.as_str()})
                )
                .status,
                200
            );
        }
        let current = service.state.as_ref().ok_or("restored tree")?;
        assert_eq!(current.schema, NATIVE_PLAIN_NAMESPACE_TREE_STATE_SCHEMA);
        assert_eq!(current.namespaces.native_flat_retirement_format, Some(2));
        assert_eq!(catalog, owner_store::serialize_owner(&current.namespaces)?);
        assert!(current.namespaces.batch_lifecycle.as_ref() == Some(&ledger));
        assert!(current.auth.namespace_batch_registry() == Some(&ledger));
        assert_eq!(
            current.namespaces.next_incarnation.get("team/retired"),
            Some(&2)
        );
        assert!(current.validate_namespace_batch_state().is_ok());
        assert!(current.validate_native_flat_retirement_state(None).is_ok());
        let directory = call(
            &mut service,
            "LIST",
            "sys/namespaces",
            "team",
            &admin,
            json!({}),
        );
        assert_eq!(directory.status, 200);
        assert_eq!(directory.body["data"]["keys"], json!(["child/"]));
        assert_eq!(
            call(
                &mut service,
                "GET",
                "sys/namespaces/child",
                "team",
                &admin,
                json!({})
            )
            .body["data"],
            child.body["data"]
        );
        assert_eq!(
            call(
                &mut service,
                "GET",
                "sys/namespaces/retired",
                "team",
                &admin,
                json!({})
            )
            .status,
            404
        );
        let value = call(
            &mut service,
            "GET",
            "secret/data/item",
            "team/child",
            &admin,
            json!({}),
        );
        assert_eq!(value.status, 200);
        assert_eq!(value.body["data"]["metadata"]["version"], 1);
        assert_eq!(
            value.body["data"]["data"],
            json!({"value":"archived-child-value"})
        );
        assert_eq!(
            call(
                &mut service,
                "GET",
                "secret/data/only-after",
                "team/child",
                &admin,
                json!({})
            )
            .status,
            404
        );
        assert!(!service.recovery_required);
    }
    Ok(())
}

// Integration-only addition for service_native_namespace_tree_tests.rs after
// both reviewed owners are merged. Not compiled or qualified on the 846-only
// namespace branch; it requires KV_MOUNT_CONFIGURATION_STATE_SCHEMA (146).
#[test]
fn formal_native_namespace_tree_and_kv_configuration_joint_snapshot_floor() -> TestResult {
    let (files, mut service, key, admin) = formal()?;
    create(&mut service, "", "team", &admin);
    create(&mut service, "team", "child", &admin);
    assert_eq!(
        call(
            &mut service,
            "POST",
            "sys/mounts/secret",
            "team/child",
            &admin,
            json!({"type":"kv", "options":{"version":"2"}})
        )
        .status,
        204
    );
    assert_eq!(
        call(
            &mut service,
            "POST",
            "secret/data/item",
            "team/child",
            &admin,
            json!({"options":{"cas":0}, "data":{"value":"both-formats"}})
        )
        .status,
        200
    );
    assert_eq!(
        service.state.as_ref().ok_or("tree state")?.schema,
        NATIVE_PLAIN_NAMESPACE_TREE_STATE_SCHEMA
    );
    let (response, tree_archive) = snapshot(&mut service, &admin, None)?;
    assert_eq!(response.status, 200);
    let tree_archive = tree_archive.ok_or("actual 145 archive")?;

    assert_eq!(
        call(
            &mut service,
            "POST",
            "sys/mounts/configured",
            "",
            &admin,
            json!({"type":"kv", "options":{"version":"2"},
            "config":{"default_lease_ttl":"30s", "max_lease_ttl":"60s", "force_no_cache":true}})
        )
        .status,
        204
    );
    assert_eq!(
        call(
            &mut service,
            "POST",
            "sys/mounts/legacy",
            "team/child",
            &admin,
            json!({"type":"kv", "options":{"version":"1"},
            "config":{"default_lease_ttl":"15s", "max_lease_ttl":"25s"}})
        )
        .status,
        204
    );
    assert_eq!(
        call(
            &mut service,
            "POST",
            "legacy/item",
            "team/child",
            &admin,
            json!({"value":"child-v1-archived"})
        )
        .status,
        204
    );
    let joint = service.state.as_ref().ok_or("joint state")?;
    assert_eq!(joint.schema, KV_MOUNT_CONFIGURATION_STATE_SCHEMA);
    assert_eq!(joint.namespaces.native_flat_retirement_format, Some(2));
    let catalog = owner_store::serialize_owner(&joint.namespaces)?;
    let ledger = joint
        .namespaces
        .batch_lifecycle
        .clone()
        .ok_or("joint ledger")?;
    let (rejected, output) = snapshot(&mut service, &admin, Some(&tree_archive))?;
    assert_eq!(
        rejected.status, 400,
        "145 alone cannot retire the configured 146 owner"
    );
    assert!(output.is_none());
    let (response, archive) = snapshot(&mut service, &admin, None)?;
    assert_eq!(response.status, 200);
    let archive = archive.ok_or("actual joint archive")?;
    assert_eq!(
        call(
            &mut service,
            "POST",
            "sys/mounts/configured/tune",
            "",
            &admin,
            json!({"default_lease_ttl":"50s"})
        )
        .status,
        204
    );
    assert_eq!(
        call(
            &mut service,
            "POST",
            "secret/data/item",
            "team/child",
            &admin,
            json!({"options":{"cas":1}, "data":{"value":"after-joint-archive"}})
        )
        .status,
        200
    );
    assert_eq!(
        call(
            &mut service,
            "POST",
            "sys/mounts/legacy/tune",
            "team/child",
            &admin,
            json!({"default_lease_ttl":"16s"})
        )
        .status,
        204
    );
    assert_eq!(
        call(
            &mut service,
            "POST",
            "legacy/item",
            "team/child",
            &admin,
            json!({"value":"child-v1-after-archive"})
        )
        .status,
        204
    );

    let (restored, output) = snapshot(&mut service, &admin, Some(&archive))?;
    assert_eq!(restored.status, 200, "{}", restored.body["errors"]);
    assert!(output.is_none());
    drop(service);
    let mut service = files.service()?;
    service.configure_native_v6_storage(NativeStorageProfile::File)?;
    assert_eq!(
        call(
            &mut service,
            "POST",
            "sys/unseal",
            "",
            "",
            json!({"key":key.as_str()})
        )
        .status,
        200
    );
    let cold = service.state.as_ref().ok_or("cold joint state")?;
    assert_eq!(cold.schema, KV_MOUNT_CONFIGURATION_STATE_SCHEMA);
    assert_eq!(cold.namespaces.native_flat_retirement_format, Some(2));
    assert_eq!(catalog, owner_store::serialize_owner(&cold.namespaces)?);
    assert!(cold.namespaces.batch_lifecycle.as_ref() == Some(&ledger));
    assert!(cold.auth.namespace_batch_registry() == Some(&ledger));
    assert!(cold.validate_native_flat_retirement_state(None).is_ok());
    let tune = call(
        &mut service,
        "GET",
        "sys/mounts/configured/tune",
        "",
        &admin,
        json!({}),
    );
    assert_eq!(tune.status, 200);
    assert_eq!(tune.body["data"]["default_lease_ttl"], 30);
    assert_eq!(tune.body["data"]["max_lease_ttl"], 60);
    assert_eq!(tune.body["data"]["force_no_cache"], true);
    let value = call(
        &mut service,
        "GET",
        "secret/data/item",
        "team/child",
        &admin,
        json!({}),
    );
    assert_eq!(value.status, 200);
    assert_eq!(value.body["data"]["data"], json!({"value":"both-formats"}));
    assert_eq!(value.body["data"]["metadata"]["version"], 1);
    let legacy_tune = call(
        &mut service,
        "GET",
        "sys/mounts/legacy/tune",
        "team/child",
        &admin,
        json!({}),
    );
    assert_eq!(legacy_tune.status, 200);
    assert_eq!(legacy_tune.body["data"]["default_lease_ttl"], 15);
    assert_eq!(legacy_tune.body["data"]["max_lease_ttl"], 25);
    let legacy = call(
        &mut service,
        "GET",
        "legacy/item",
        "team/child",
        &admin,
        json!({}),
    );
    assert_eq!(legacy.status, 200);
    assert_eq!(legacy.body["data"], json!({"value":"child-v1-archived"}));
    assert_eq!(legacy.body["lease_duration"], 15);
    assert_eq!(legacy.body["renewable"], false);
    assert!(!service.recovery_required);
    Ok(())
}
