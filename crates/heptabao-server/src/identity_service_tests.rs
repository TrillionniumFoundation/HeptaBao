//! Public Service-boundary identity tests, including encrypted restart and
//! admission failure. Every credential and secret in this file is synthetic.
use super::super::*;
use std::sync::atomic::{AtomicU64, Ordering};

static NEXT: AtomicU64 = AtomicU64::new(0);
type TestResult = Result<(), Box<dyn std::error::Error>>;
struct Fixture {
    path: PathBuf,
}
impl Fixture {
    fn new() -> Result<Self, Box<dyn std::error::Error>> {
        let path = std::env::temp_dir().join(format!(
            "heptabao-identity-live-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        private_directory(&path)?;
        Ok(Self { path })
    }
    fn service(&self) -> Result<Service, Box<dyn std::error::Error>> {
        Ok(Service::new(
            self.path.join("data"),
            &self.path.join("audit.jsonl"),
        )?)
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}
fn call(s: &mut Service, ns: &str, token: &str, method: &str, path: &str, body: Value) -> Response {
    s.handle_at(method, path, ns, token, body, 100)
}
fn text(value: &Value, pointer: &str) -> Result<String, Box<dyn std::error::Error>> {
    Ok(value
        .pointer(pointer)
        .and_then(Value::as_str)
        .ok_or("missing response field")?
        .to_owned())
}
fn bootstrap(s: &mut Service) -> Result<(String, String), Box<dyn std::error::Error>> {
    let init = call(
        s,
        "",
        "",
        "POST",
        "sys/init",
        json!({"secret_shares":1,"secret_threshold":1}),
    );
    assert_eq!(init.status, 200);
    let admin = text(&init.body, "/root_token")?;
    let key = text(&init.body, "/keys_base64/0")?;
    assert_eq!(
        call(s, "", "", "POST", "sys/unseal", json!({"key":key})).status,
        200
    );
    Ok((admin, key))
}
fn policy(s: &mut Service, ns: &str, admin: &str, name: &str, rules: &str) {
    assert_eq!(
        call(
            s,
            ns,
            admin,
            "PUT",
            &format!("sys/policies/acl/{name}"),
            json!({"policy":rules})
        )
        .status,
        204
    );
}
fn role(
    s: &mut Service,
    ns: &str,
    admin: &str,
    mount: &str,
) -> Result<Value, Box<dyn std::error::Error>> {
    let base = format!("auth/{mount}/role/synthetic");
    assert_eq!(
        call(
            s,
            ns,
            admin,
            "POST",
            &base,
            json!({"token_policies":["default"],"secret_id_num_uses":0})
        )
        .status,
        204
    );
    // The same alias name in different namespaces/incarnations must not collide.
    assert_eq!(
        call(
            s,
            ns,
            admin,
            "POST",
            &format!("{base}/role-id"),
            json!({"role_id":"synthetic-shared-role"})
        )
        .status,
        204
    );
    let secret = call(
        s,
        ns,
        admin,
        "POST",
        &format!("{base}/secret-id"),
        json!({}),
    );
    assert_eq!(secret.status, 200);
    Ok(json!({"role_id":"synthetic-shared-role","secret_id":text(&secret.body,"/data/secret_id")?}))
}
fn login(s: &mut Service, ns: &str, mount: &str, credentials: &Value) -> Response {
    call(
        s,
        ns,
        "",
        "POST",
        &format!("auth/{mount}/login"),
        credentials.clone(),
    )
}
fn update_entity(s: &mut Service, ns: &str, admin: &str, id: &str, body: Value) {
    assert_eq!(
        call(
            s,
            ns,
            admin,
            "POST",
            &format!("identity/entity/id/{id}"),
            body
        )
        .status,
        204
    );
}
fn read_fixture(s: &mut Service, ns: &str, admin: &str) {
    policy(
        s,
        ns,
        admin,
        "reader",
        "path \"secret/data/item\" { capabilities = [\"read\"] }",
    );
    assert_eq!(
        call(
            s,
            ns,
            admin,
            "POST",
            "secret/data/item",
            json!({"data":{"value":"synthetic-only"}})
        )
        .status,
        200
    );
}
fn read_status(s: &mut Service, ns: &str, token: &str) -> u16 {
    call(s, ns, token, "GET", "secret/data/item", json!({})).status
}

#[test]
fn identity_live_entity_policy_changes_apply_to_existing_tokens_after_restart() -> TestResult {
    let f = Fixture::new()?;
    let mut s = f.service()?;
    let (admin, key) = bootstrap(&mut s)?;
    read_fixture(&mut s, "", &admin);
    let credentials = role(&mut s, "", &admin, "approle")?;
    let first = login(&mut s, "", "approle", &credentials);
    assert_eq!(first.status, 200);
    let token = text(&first.body, "/auth/client_token")?;
    let id = text(&first.body, "/auth/entity_id")?;
    assert!(!id.is_empty());
    assert_eq!(read_status(&mut s, "", &token), 403);
    update_entity(&mut s, "", &admin, &id, json!({"policies":["reader"]}));
    assert_eq!(read_status(&mut s, "", &token), 200);
    let second = login(&mut s, "", "approle", &credentials);
    assert_eq!(second.status, 200);
    assert_eq!(second.body["auth"]["entity_id"], id);
    assert_eq!(second.body["auth"]["identity_policies"], json!(["reader"]));
    assert_eq!(second.body["auth"]["token_policies"], json!(["default"]));
    update_entity(&mut s, "", &admin, &id, json!({"policies":[]}));
    drop(s);
    let mut s = f.service()?;
    assert_eq!(
        call(&mut s, "", "", "POST", "sys/unseal", json!({"key":key})).status,
        200
    );
    assert_eq!(read_status(&mut s, "", &token), 403);
    Ok(())
}

#[test]
fn identity_live_disabled_entity_denies_login_and_use_without_revoking_token() -> TestResult {
    let f = Fixture::new()?;
    let mut s = f.service()?;
    let (admin, key) = bootstrap(&mut s)?;
    read_fixture(&mut s, "", &admin);
    let credentials = role(&mut s, "", &admin, "approle")?;
    let first = login(&mut s, "", "approle", &credentials);
    let token = text(&first.body, "/auth/client_token")?;
    let id = text(&first.body, "/auth/entity_id")?;
    update_entity(
        &mut s,
        "",
        &admin,
        &id,
        json!({"policies":["reader"],"metadata":{"fixture":"preserved"}}),
    );
    update_entity(&mut s, "", &admin, &id, json!({"disabled":true}));
    assert_eq!(read_status(&mut s, "", &token), 403);
    assert_eq!(login(&mut s, "", "approle", &credentials).status, 403);
    let entity = call(
        &mut s,
        "",
        &admin,
        "GET",
        &format!("identity/entity/id/{id}"),
        json!({}),
    );
    assert_eq!(entity.body["data"]["policies"], json!(["reader"]));
    assert_eq!(entity.body["data"]["metadata"]["fixture"], "preserved");
    assert_eq!(
        call(
            &mut s,
            "",
            &admin,
            "POST",
            "auth/token/lookup",
            json!({"token":token})
        )
        .status,
        200
    );
    drop(s);
    let mut s = f.service()?;
    assert_eq!(
        call(&mut s, "", "", "POST", "sys/unseal", json!({"key":key})).status,
        200
    );
    assert_eq!(read_status(&mut s, "", &token), 403);
    update_entity(&mut s, "", &admin, &id, json!({"disabled":false}));
    assert_eq!(read_status(&mut s, "", &token), 200);
    Ok(())
}

#[test]
fn identity_live_nested_internal_group_policy_and_membership_removal_take_effect() -> TestResult {
    let f = Fixture::new()?;
    let mut s = f.service()?;
    let (admin, _) = bootstrap(&mut s)?;
    read_fixture(&mut s, "", &admin);
    let credentials = role(&mut s, "", &admin, "approle")?;
    let first = login(&mut s, "", "approle", &credentials);
    let token = text(&first.body, "/auth/client_token")?;
    let id = text(&first.body, "/auth/entity_id")?;
    let child = call(
        &mut s,
        "",
        &admin,
        "POST",
        "identity/group",
        json!({"name":"child","member_entity_ids":[id]}),
    );
    let child_id = text(&child.body, "/data/id")?;
    let parent = call(
        &mut s,
        "",
        &admin,
        "POST",
        "identity/group",
        json!({"name":"parent","policies":["reader"],"member_group_ids":[child_id]}),
    );
    let parent_id = text(&parent.body, "/data/id")?;
    assert_eq!(read_status(&mut s, "", &token), 200);
    assert_eq!(
        call(
            &mut s,
            "",
            &admin,
            "POST",
            &format!("identity/group/id/{parent_id}"),
            json!({"policies":[]})
        )
        .status,
        204
    );
    assert_eq!(read_status(&mut s, "", &token), 403);
    assert_eq!(
        call(
            &mut s,
            "",
            &admin,
            "POST",
            &format!("identity/group/id/{parent_id}"),
            json!({"policies":["reader"]})
        )
        .status,
        204
    );
    assert_eq!(read_status(&mut s, "", &token), 200);
    assert_eq!(
        call(
            &mut s,
            "",
            &admin,
            "POST",
            &format!("identity/group/id/{child_id}"),
            json!({"member_entity_ids":[]})
        )
        .status,
        204
    );
    assert_eq!(read_status(&mut s, "", &token), 403);
    Ok(())
}

#[test]
fn identity_live_children_inherit_identity_but_cannot_convert_it_into_token_policies() -> TestResult
{
    let f = Fixture::new()?;
    let mut s = f.service()?;
    let (admin, _) = bootstrap(&mut s)?;
    read_fixture(&mut s, "", &admin);
    policy(
        &mut s,
        "",
        &admin,
        "creator",
        "path \"auth/token/create\" { capabilities = [\"update\"] }",
    );
    let credentials = role(&mut s, "", &admin, "approle")?;
    assert_eq!(
        call(
            &mut s,
            "",
            &admin,
            "POST",
            "auth/approle/role/synthetic",
            json!({"token_policies":["creator"]})
        )
        .status,
        204
    );
    let first = login(&mut s, "", "approle", &credentials);
    let parent = text(&first.body, "/auth/client_token")?;
    let id = text(&first.body, "/auth/entity_id")?;
    update_entity(&mut s, "", &admin, &id, json!({"policies":["reader"]}));
    assert_eq!(
        call(
            &mut s,
            "",
            &parent,
            "POST",
            "auth/token/create",
            json!({"policies":["reader"]})
        )
        .status,
        403
    );
    let child = call(&mut s, "", &parent, "POST", "auth/token/create", json!({}));
    assert_eq!(child.status, 200);
    assert_eq!(child.body["auth"]["entity_id"], id);
    let token = text(&child.body, "/auth/client_token")?;
    assert_eq!(read_status(&mut s, "", &token), 200);
    update_entity(&mut s, "", &admin, &id, json!({"policies":[]}));
    assert_eq!(read_status(&mut s, "", &token), 403);
    Ok(())
}

#[test]
fn identity_live_merge_lineage_applies_to_tokens_but_deleted_names_do_not_rebind() -> TestResult {
    let f = Fixture::new()?;
    let mut s = f.service()?;
    let (admin, _) = bootstrap(&mut s)?;
    read_fixture(&mut s, "", &admin);
    let credentials = role(&mut s, "", &admin, "approle")?;
    let first = login(&mut s, "", "approle", &credentials);
    let token = text(&first.body, "/auth/client_token")?;
    let source = text(&first.body, "/auth/entity_id")?;
    let dest = call(
        &mut s,
        "",
        &admin,
        "POST",
        "identity/entity",
        json!({"name":"destination","policies":["reader"]}),
    );
    let dest_id = text(&dest.body, "/data/id")?;
    let merge = call(
        &mut s,
        "",
        &admin,
        "POST",
        "identity/entity/merge",
        json!({"from_entity_ids":[source],"to_entity_id":dest_id}),
    );
    assert_eq!(merge.status, 204);
    assert_eq!(read_status(&mut s, "", &token), 200);
    let lookup = call(
        &mut s,
        "",
        &token,
        "GET",
        "auth/token/lookup-self",
        json!({}),
    );
    assert_eq!(lookup.body["data"]["entity_id"], dest_id);
    assert_eq!(
        call(
            &mut s,
            "",
            &admin,
            "DELETE",
            &format!("identity/entity/id/{dest_id}"),
            json!({})
        )
        .status,
        204
    );
    assert_eq!(read_status(&mut s, "", &token), 403);
    assert_eq!(
        call(
            &mut s,
            "",
            &admin,
            "POST",
            "identity/entity",
            json!({"name":"destination","policies":["reader"]})
        )
        .status,
        200
    );
    assert_eq!(read_status(&mut s, "", &token), 403);
    assert_eq!(
        call(
            &mut s,
            "",
            &admin,
            "POST",
            &format!("identity/entity/id/{dest_id}"),
            json!({"name":"resurrected","policies":["reader"]})
        )
        .status,
        404
    );
    assert_eq!(
        call(
            &mut s,
            "",
            &admin,
            "POST",
            "identity/entity",
            json!({"id":source,"name":"resurrected-source","policies":["reader"]})
        )
        .status,
        404
    );
    assert_eq!(read_status(&mut s, "", &token), 403);
    Ok(())
}

#[test]
fn identity_live_mount_incarnations_and_namespaces_do_not_share_alias_authority() -> TestResult {
    let f = Fixture::new()?;
    let mut s = f.service()?;
    let (admin, _) = bootstrap(&mut s)?;
    read_fixture(&mut s, "", &admin);
    read_fixture(&mut s, "tenant", &admin);
    let a = role(&mut s, "", &admin, "approle")?;
    let b = role(&mut s, "tenant", &admin, "approle")?;
    let first = login(&mut s, "", "approle", &a);
    let tenant = login(&mut s, "tenant", "approle", &b);
    let token = text(&first.body, "/auth/client_token")?;
    let tenant_token = text(&tenant.body, "/auth/client_token")?;
    let id = text(&first.body, "/auth/entity_id")?;
    update_entity(&mut s, "", &admin, &id, json!({"policies":["reader"]}));
    assert_eq!(read_status(&mut s, "", &token), 200);
    assert_eq!(read_status(&mut s, "tenant", &tenant_token), 403);
    let old = call(&mut s, "", &admin, "GET", "sys/auth/approle", json!({}));
    let old_accessor = text(&old.body, "/data/accessor")?;
    assert_eq!(
        call(&mut s, "", &admin, "DELETE", "sys/auth/approle", json!({})).status,
        204
    );
    assert_eq!(
        call(
            &mut s,
            "",
            &admin,
            "POST",
            "sys/auth/approle",
            json!({"type":"approle"})
        )
        .status,
        204
    );
    let next = call(&mut s, "", &admin, "GET", "sys/auth/approle", json!({}));
    assert_ne!(text(&next.body, "/data/accessor")?, old_accessor);
    let c = role(&mut s, "", &admin, "approle")?;
    let fresh = login(&mut s, "", "approle", &c);
    assert_ne!(fresh.body["auth"]["entity_id"], id);
    assert_eq!(
        read_status(&mut s, "", &text(&fresh.body, "/auth/client_token")?),
        403
    );
    assert_eq!(read_status(&mut s, "", &token), 403);
    assert_eq!(
        call(
            &mut s,
            "",
            &admin,
            "POST",
            "identity/entity-alias",
            json!({"name":"reused","mount_accessor":old_accessor,"canonical_id":id})
        )
        .status,
        400
    );
    Ok(())
}

#[test]
fn identity_live_failed_login_commit_publishes_neither_token_nor_entity() -> TestResult {
    let f = Fixture::new()?;
    let mut s = f.service()?;
    let (admin, _) = bootstrap(&mut s)?;
    let credentials = role(&mut s, "", &admin, "approle")?;
    let before = serde_json::to_vec(s.state.as_ref().ok_or("sealed")?)?;
    s.state_capacity = before.len();
    let failed = login(&mut s, "", "approle", &credentials);
    assert_eq!(failed.status, 507);
    assert!(failed.body.get("auth").is_none());
    assert_eq!(
        serde_json::to_vec(s.state.as_ref().ok_or("sealed")?)?,
        before
    );
    s.state_capacity = MAX_STATE_BYTES;
    let retry = login(&mut s, "", "approle", &credentials);
    assert_eq!(retry.status, 200);
    assert!(!text(&retry.body, "/auth/entity_id")?.is_empty());
    Ok(())
}

#[test]
fn identity_schema_preserves_legacy_canonical_bytes_and_rejects_downgrade() -> TestResult {
    let (mut auth, _) = AuthState::bootstrap(100)?;
    auth.remove_name_modes_for_legacy_format_test();
    auth.omit_lease_metadata_for_legacy_fixture();
    let state = State {
        schema: 1,
        cluster_id: "legacy-synthetic".into(),
        replay_epoch: 0,
        namespaces: namespaces::NamespaceRegistry::default().into(),
        auth: auth.into(),
        engines: EngineState::default().into(),
        database: database::DatabaseState::default().into(),
        raft_admin: raft_admin::RaftAdminState::default().into(),
    };
    let bytes = serde_json::to_vec(&state)?;
    let restored: State = serde_json::from_slice(&bytes)?;
    assert!(restored.validate_format().is_ok());
    assert_eq!(bytes, serde_json::to_vec(&restored)?);
    let mut value = serde_json::to_value(&state)?;
    for token in value["auth"]["tokens"]
        .as_object()
        .ok_or("tokens")?
        .values()
    {
        assert!(token.get("entity_id").is_none());
    }
    for schema in [0, CURRENT_STATE_SCHEMA + 1, u32::MAX] {
        value["schema"] = json!(schema);
        assert!(
            serde_json::from_value::<State>(value.clone())?
                .validate_format()
                .is_err()
        );
    }
    value["schema"] = json!(1);
    value["auth"]["tokens"]
        .as_object_mut()
        .ok_or("tokens")?
        .values_mut()
        .next()
        .ok_or("token")?["entity_id"] = json!("e-bound");
    assert!(
        serde_json::from_value::<State>(value.clone())?
            .validate_format()
            .is_err()
    );
    value["schema"] = json!(CURRENT_STATE_SCHEMA);
    assert!(
        serde_json::from_value::<State>(value)?
            .validate_format()
            .is_ok()
    );
    let mut mounts = serde_json::to_value(&state)?;
    mounts["auth"]["auth_mounts"] =
        json!({"": {"approle": {"kind": "approle", "description": "", "accessor": "auth-new"}}});
    assert!(
        serde_json::from_value::<State>(mounts)?
            .validate_format()
            .is_err()
    );
    Ok(())
}

#[test]
fn identity_schema_fences_persisted_radius_state_for_old_readers() -> TestResult {
    let (mut auth, raw) = AuthState::bootstrap(100)?;
    let root = auth.authenticate(&raw, 100)?;
    let configured = auth.handle(
        Some(&root),
        "",
        "POST",
        "sys/auth/radius",
        &json!({"type":"radius"}),
        100,
    )?;
    assert_eq!(configured.ok_or("missing mount response")?.status, 204);
    let configured = auth.handle(
        Some(&root),
        "",
        "POST",
        "auth/radius/config",
        &json!({"url":"radius://radius.example.test:1812","token_policies":["default"]}),
        100,
    )?;
    assert_eq!(configured.ok_or("missing config response")?.status, 204);
    let mut state = State {
        schema: CURRENT_STATE_SCHEMA,
        cluster_id: "radius-schema-test".into(),
        replay_epoch: 0,
        namespaces: namespaces::NamespaceRegistry::default().into(),
        auth: auth.into(),
        engines: EngineState::default().into(),
        database: database::DatabaseState::default().into(),
        raft_admin: raft_admin::RaftAdminState::default().into(),
    };
    assert!(state.validate_format().is_ok());
    // Schema 12 admits the bounded RADIUS state; schema 11 is the last
    // reader that must reject it. Keep this historical boundary explicit as
    // the current schema advances with new external-provider fences.
    state.schema = 11;
    state.auth.remove_name_modes_for_legacy_format_test();
    state.auth.omit_lease_metadata_for_legacy_fixture();
    assert!(state.validate_format().is_err());
    Ok(())
}

#[test]
fn identity_schema_promotes_before_a_mutating_response_and_survives_reopen() -> TestResult {
    let f = Fixture::new()?;
    let mut s = f.service()?;
    let (admin, key) = bootstrap(&mut s)?;
    assert_eq!(
        s.state.as_ref().ok_or("state")?.schema,
        CURRENT_STATE_SCHEMA
    );
    // Materialize an exact schema-1 fixture to model the previously supported
    // on-disk format; no runtime API permits downgrading this discriminator.
    let mut legacy = s.state.clone().ok_or("state")?;
    legacy.schema = 1;
    legacy.auth.remove_name_modes_for_legacy_format_test();
    legacy.auth.omit_lease_metadata_for_legacy_fixture();
    assert!(legacy.validate_format().is_ok());
    s.commit_state(&legacy).map_err(|_| "fixture persistence")?;
    s.state = Some(legacy);
    drop(s);
    let mut s = f.service()?;
    assert_eq!(
        call(&mut s, "", "", "POST", "sys/unseal", json!({"key":key})).status,
        200
    );
    assert_eq!(s.state.as_ref().ok_or("state")?.schema, 1);
    assert_eq!(
        call(
            &mut s,
            "",
            &admin,
            "GET",
            "auth/token/lookup-self",
            json!({})
        )
        .status,
        200
    );
    assert_eq!(s.state.as_ref().ok_or("state")?.schema, 1);
    assert_eq!(
        call(
            &mut s,
            "",
            &admin,
            "POST",
            "secret/data/schema",
            json!({"data":{"v":"synthetic"}})
        )
        .status,
        200
    );
    assert_eq!(
        s.state.as_ref().ok_or("state")?.schema,
        CURRENT_STATE_SCHEMA
    );
    let durable = s.durable.as_ref().ok_or("store")?;
    let (persisted, _, _) =
        Service::load_state_from_durable(durable).map_err(|_| "persisted state")?;
    assert_eq!(persisted.schema, CURRENT_STATE_SCHEMA);
    drop(s);
    let mut s = f.service()?;
    assert_eq!(
        call(&mut s, "", "", "POST", "sys/unseal", json!({"key":key})).status,
        200
    );
    assert_eq!(
        s.state.as_ref().ok_or("state")?.schema,
        CURRENT_STATE_SCHEMA
    );
    Ok(())
}

#[test]
fn identity_schema_finite_use_upgrade_is_durable_even_when_acl_denies() -> TestResult {
    let f = Fixture::new()?;
    let mut s = f.service()?;
    let (admin, key) = bootstrap(&mut s)?;
    // Issue through AuthState before any Service mutation publishes a v5 root.
    // Persisting this historical fixture must not attempt to downgrade an
    // already-published record root or discard any KV1 data.
    let mut legacy = s.state.clone().ok_or("state")?;
    assert!(legacy.engines.record_root().is_none());
    assert!(!legacy.engines.has_record_kv1());
    let actor = legacy.auth.authenticate(&admin, 100)?;
    let issued = legacy
        .auth
        .handle(
            Some(&actor),
            "",
            "POST",
            "auth/token/create",
            &json!({"policies":["default"],"num_uses":1}),
            100,
        )?
        .ok_or("missing token creation response")?;
    assert_eq!(issued.status, 200);
    let token = text(&issued.body, "/auth/client_token")?;
    // Model a token actually issued by the schema-1 API, before the explicit
    // token-API issuer marker existed; do not relabel new content as legacy.
    let mut encoded_auth = serde_json::to_value(&legacy.auth)?;
    for token in encoded_auth["tokens"]
        .as_object_mut()
        .ok_or("missing tokens")?
        .values_mut()
    {
        token
            .as_object_mut()
            .ok_or("invalid token")?
            .remove("auth_provenance");
    }
    legacy.auth = serde_json::from_value::<AuthState>(encoded_auth)?.into();
    legacy.schema = 1;
    legacy.auth.remove_name_modes_for_legacy_format_test();
    legacy.auth.omit_lease_metadata_for_legacy_fixture();
    assert!(legacy.validate_format().is_ok());
    s.commit_state(&legacy).map_err(|_| "fixture persistence")?;
    s.state = Some(legacy);
    assert_eq!(
        call(
            &mut s,
            "",
            &token,
            "GET",
            "secret/data/forbidden",
            json!({})
        )
        .status,
        403
    );
    assert_eq!(
        s.state.as_ref().ok_or("state")?.schema,
        CURRENT_STATE_SCHEMA
    );
    drop(s);
    let mut s = f.service()?;
    assert_eq!(
        call(&mut s, "", "", "POST", "sys/unseal", json!({"key":key})).status,
        200
    );
    assert_eq!(
        s.state.as_ref().ok_or("state")?.schema,
        CURRENT_STATE_SCHEMA
    );
    assert_eq!(
        call(
            &mut s,
            "",
            &token,
            "GET",
            "auth/token/lookup-self",
            json!({})
        )
        .status,
        403
    );
    Ok(())
}

#[test]
fn metadata_cas_schema_rejects_downgrade_from_version_or_requirement() -> TestResult {
    for (path, body) in [
        ("secret/config", json!({"metadata_cas_required":true})),
        (
            "secret/metadata/item",
            json!({"custom_metadata":{"owner":"synthetic"}}),
        ),
        (
            "secret/metadata/item",
            json!({"metadata_cas_required":true}),
        ),
    ] {
        let (mut auth, _) = AuthState::bootstrap(100)?;
        auth.remove_name_modes_for_legacy_format_test();
        auth.omit_lease_metadata_for_legacy_fixture();
        let mut engines = EngineState::default();
        engines
            .handle("", "POST", path, &body, 100)?
            .ok_or("missing engine response")?;
        let mut state = State {
            schema: 15,
            cluster_id: "metadata-cas-schema".into(),
            replay_epoch: 0,
            namespaces: namespaces::NamespaceRegistry::default().into(),
            auth: auth.into(),
            engines: engines.into(),
            database: database::DatabaseState::default().into(),
            raft_admin: raft_admin::RaftAdminState::default().into(),
        };
        assert!(state.validate_format().is_ok());
        state.schema = 14;
        state.auth.remove_name_modes_for_legacy_format_test();
        state.auth.omit_lease_metadata_for_legacy_fixture();
        assert!(state.validate_format().is_err());
    }
    Ok(())
}

fn batch_userpass_login(s: &mut Service, wrap: Option<u64>) -> Response {
    s.handle_at_mode(RequestDispatch {
        method: "POST",
        path: "auth/userpass/login/alice",
        namespace: "",
        token: "",
        body: json!({"password":"batch fixture password"}),
        now: 100,
        allow_forward: false,
        enforce_namespace: true,
        wrap_ttl_seconds: wrap,
        origin_peer: None,
        client_certificates: None,
    })
}
fn create_batch_user(s: &mut Service, admin: &str) {
    assert_eq!(
        call(
            s,
            "",
            admin,
            "POST",
            "auth/userpass/users/alice",
            json!({"password":"batch fixture password","token_type":"batch","token_ttl":300})
        )
        .status,
        204
    );
}

#[test]
fn batch_login_identity_wrapping_and_reopen_publish_one_transaction_without_service_backing()
-> TestResult {
    let f = Fixture::new()?;
    let mut s = f.service()?;
    let (admin, key) = bootstrap(&mut s)?;
    create_batch_user(&mut s, &admin);
    // Unseal schedules GC. V4->V5 publication leaves its first collection due.
    // Physical generations include GC; this counter counts published roots and
    // resets only when GC completes, so two AuthState publications would yield 2.
    assert!(s.record_writes_since_gc >= 64);
    let before = s.durable.as_ref().ok_or("durable")?.generation();
    let wrapped = batch_userpass_login(&mut s, Some(60));
    assert_eq!(wrapped.status, 200);
    assert_eq!(s.record_writes_since_gc, 1);
    assert!(s.durable.as_ref().ok_or("durable")?.generation() > before);
    assert!(wrapped.body.get("auth").is_none_or(Value::is_null));
    let wrapper = text(&wrapped.body, "/wrap_info/token")?;
    let unwrapped = call(
        &mut s,
        "",
        &wrapper,
        "POST",
        "sys/wrapping/unwrap",
        json!({}),
    );
    assert_eq!(unwrapped.status, 200);
    let raw = text(&unwrapped.body, "/auth/client_token")?;
    assert!(raw.starts_with("hvb."));
    let entity = text(&unwrapped.body, "/auth/entity_id")?;
    assert!(!entity.is_empty());
    assert_eq!(
        unwrapped.body["auth"]["metadata"],
        json!({"username":"alice"})
    );
    assert_ne!(
        call(
            &mut s,
            "",
            &wrapper,
            "POST",
            "sys/wrapping/unwrap",
            json!({})
        )
        .status,
        200
    );
    let lookup = call(&mut s, "", &raw, "GET", "auth/token/lookup-self", json!({}));
    assert_eq!(lookup.status, 200);
    assert_eq!(lookup.body["data"]["entity_id"], entity);
    // Batch grants have no backing row. A consumed wrapper may remain as a tombstone.
    let serialized =
        zeroize::Zeroizing::new(serde_json::to_vec(&s.state.as_ref().ok_or("state")?.auth)?);
    let auth: Value = serde_json::from_slice(&serialized)?;
    assert!(
        auth["tokens"]
            .as_object()
            .ok_or("tokens")?
            .values()
            .all(|t| t["root"] == true || t["display_name"] == "response-wrapping")
    );
    drop(s);
    let mut s = f.service()?;
    assert_eq!(
        call(&mut s, "", "", "POST", "sys/unseal", json!({"key":key})).status,
        200
    );
    assert_eq!(
        call(&mut s, "", &raw, "GET", "auth/token/lookup-self", json!({})).status,
        200
    );
    update_entity(&mut s, "", &admin, &entity, json!({"disabled":true}));
    let digest = s.current_state_digest().map_err(|_| "digest")?;
    assert_eq!(batch_userpass_login(&mut s, None).status, 403);
    assert_eq!(s.current_state_digest().map_err(|_| "digest")?, digest);
    assert_eq!(
        call(&mut s, "", &raw, "GET", "auth/token/lookup-self", json!({})).status,
        403
    );
    Ok(())
}

#[test]
fn batch_login_wrapping_capacity_failure_discards_identity_and_key_watermark_together() -> TestResult
{
    let f = Fixture::new()?;
    let mut s = f.service()?;
    let (admin, _) = bootstrap(&mut s)?;
    create_batch_user(&mut s, &admin);
    let mut candidate = s.state.as_ref().ok_or("state")?.clone();
    for _ in 0..256 {
        candidate
            .auth
            .wrap_response("", "fixture", 60, &json!({"data":{"ok":true}}), 100)?;
    }
    s.commit_state(&candidate).map_err(|_| "fixture commit")?;
    s.state = Some(candidate);
    let before = s.current_state_digest().map_err(|_| "digest")?;
    let generation = s.durable.as_ref().ok_or("durable")?.generation();
    let response = batch_userpass_login(&mut s, Some(60));
    assert_eq!(response.status, 503);
    assert!(response.body.get("auth").is_none_or(Value::is_null));
    assert!(response.body.get("wrap_info").is_none_or(Value::is_null));
    assert_eq!(s.current_state_digest().map_err(|_| "digest")?, before);
    assert_eq!(
        s.durable.as_ref().ok_or("durable")?.generation(),
        generation
    );
    Ok(())
}

#[test]
fn failed_new_batch_wrapper_does_not_publish_a_clock_only_state() -> TestResult {
    let f = Fixture::new()?;
    let mut s = f.service()?;
    let (admin, _) = bootstrap(&mut s)?;
    let before = s.current_state_digest().map_err(|_| "digest")?;
    let generation = s.durable.as_ref().ok_or("durable")?.generation();
    let response = s.handle_at_mode(RequestDispatch {
        method: "POST",
        path: "auth/token/create",
        namespace: "",
        token: &admin,
        body: json!({"type":"batch","policies":["root"]}),
        now: 100,
        allow_forward: false,
        enforce_namespace: true,
        wrap_ttl_seconds: Some(60),
        origin_peer: None,
        client_certificates: None,
    });
    assert_eq!(response.status, 400);
    assert!(response.body.get("auth").is_none_or(Value::is_null));
    assert!(response.body.get("wrap_info").is_none_or(Value::is_null));
    assert_eq!(s.current_state_digest().map_err(|_| "digest")?, before);
    assert_eq!(
        s.durable.as_ref().ok_or("durable")?.generation(),
        generation
    );
    Ok(())
}

#[test]
fn existing_wrapper_expiry_observation_remains_durable_across_clock_rollback() -> TestResult {
    let f = Fixture::new()?;
    let mut s = f.service()?;
    let (admin, key) = bootstrap(&mut s)?;
    create_batch_user(&mut s, &admin);
    let wrapped = batch_userpass_login(&mut s, Some(1));
    assert_eq!(wrapped.status, 200);
    let wrapper = text(&wrapped.body, "/wrap_info/token")?;
    assert_eq!(
        s.handle_at("POST", "sys/wrapping/unwrap", "", &wrapper, json!({}), 102)
            .status,
        400
    );
    // The rejected access at 102 must fence the old wrapper even when the
    // following request (or a restarted process) observes the earlier time.
    assert_eq!(
        s.handle_at("POST", "sys/wrapping/unwrap", "", &wrapper, json!({}), 100)
            .status,
        400
    );
    drop(s);
    let mut s = f.service()?;
    assert_eq!(
        call(&mut s, "", "", "POST", "sys/unseal", json!({"key":key})).status,
        200
    );
    assert_eq!(
        s.handle_at("POST", "sys/wrapping/unwrap", "", &wrapper, json!({}), 100)
            .status,
        400
    );
    Ok(())
}
