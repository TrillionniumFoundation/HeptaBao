//! Normal Service requests, sparse live projection and independent schema fences.
use super::*;

struct TemplateFixture {
    root: Fixture,
    service: Service,
    admin: String,
    key: String,
    token: String,
    entity: String,
}

impl TemplateFixture {
    fn new(batch: bool) -> Result<Self, Box<dyn std::error::Error>> {
        let root = Fixture::new()?;
        let mut service = root.service()?;
        let (admin, key) = bootstrap(&mut service)?;
        assert_eq!(
            call(
                &mut service,
                "",
                &admin,
                "POST",
                "sys/mounts/idtest",
                json!({"type":"kv","options":{"version":"1"}})
            )
            .status,
            204
        );
        let credentials = role(&mut service, "", &admin, "approle")?;
        if batch {
            assert_eq!(
                call(
                    &mut service,
                    "",
                    &admin,
                    "POST",
                    "auth/approle/role/synthetic",
                    json!({"token_type":"batch"})
                )
                .status,
                204
            );
        }
        let issued = login(&mut service, "", "approle", &credentials);
        assert_eq!(issued.status, 200);
        let token = text(&issued.body, "/auth/client_token")?;
        let entity = text(&issued.body, "/auth/entity_id")?;
        Ok(Self {
            root,
            service,
            admin,
            key,
            token,
            entity,
        })
    }
    fn grant(&mut self, source: &str) {
        policy(&mut self.service, "", &self.admin, "template", source);
        update_entity(
            &mut self.service,
            "",
            &self.admin,
            &self.entity,
            json!({"name":"alice", "metadata":{"team":"blue"}, "policies":["template"]}),
        );
    }
    fn seed(&mut self, path: &str) {
        assert_eq!(
            call(
                &mut self.service,
                "",
                &self.admin,
                "POST",
                path,
                json!({"synthetic":"original"})
            )
            .status,
            204
        );
    }
    fn read(&mut self, path: &str) -> u16 {
        call(&mut self.service, "", &self.token, "GET", path, json!({})).status
    }
    fn restart(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        // Move the existing service out before opening the same guarded root.
        let temporary = Fixture::new()?;
        let old = std::mem::replace(&mut self.service, temporary.service()?);
        drop(old);
        let mut reopened = self.root.service()?;
        assert_eq!(
            call(
                &mut reopened,
                "",
                "",
                "POST",
                "sys/unseal",
                json!({"key":self.key})
            )
            .status,
            200
        );
        self.service = reopened;
        Ok(())
    }
}

#[test]
fn acl_identity_templates_apply_live_entity_fields_to_service_and_batch_tokens() -> TestResult {
    for batch in [false, true] {
        let mut f = TemplateFixture::new(batch)?;
        f.grant(
            r#"
path "idtest/id/{{identity.entity.id}}/*" { capabilities = ["read"] }
path "idtest/name/{{ identity.entity.name }}/*" { capabilities = ["read"] }
path "idtest/team/{{identity.entity.metadata.team}}/*" { capabilities = ["read"] }
"#,
        );
        let own = format!("idtest/id/{}/item", f.entity);
        for path in [
            &own,
            "idtest/id/other/item",
            "idtest/name/alice/item",
            "idtest/name/renamed/item",
            "idtest/team/blue/item",
            "idtest/team/red/item",
        ] {
            f.seed(path);
        }
        assert_eq!(f.read(&own), 200);
        assert_eq!(f.read("idtest/id/other/item"), 403);
        assert_eq!(f.read("idtest/name/alice/item"), 200);
        assert_eq!(f.read("idtest/team/blue/item"), 200);
        let caps = call(
            &mut f.service,
            "",
            &f.admin,
            "POST",
            "sys/capabilities",
            json!({"token":f.token,"paths":[own,"idtest/id/other/item"]}),
        );
        assert_eq!(caps.status, 200);
        assert_eq!(caps.body["data"][&own], json!(["read"]));
        assert_eq!(caps.body["data"]["idtest/id/other/item"], json!(["deny"]));
        update_entity(
            &mut f.service,
            "",
            &f.admin,
            &f.entity,
            json!({"name":"renamed","metadata":{"team":"red"}}),
        );
        assert_eq!(f.read("idtest/name/alice/item"), 403);
        assert_eq!(f.read("idtest/team/blue/item"), 403);
        assert_eq!(f.read("idtest/name/renamed/item"), 200);
        assert_eq!(f.read("idtest/team/red/item"), 200);
        f.restart()?;
        assert_eq!(f.read(&own), 200);
        assert_eq!(f.read("idtest/team/blue/item"), 403);
        assert_eq!(f.read("idtest/team/red/item"), 200);
        update_entity(
            &mut f.service,
            "",
            &f.admin,
            &f.entity,
            json!({"disabled":true}),
        );
        assert_eq!(f.read(&own), 403);
    }
    Ok(())
}

#[test]
fn acl_identity_template_parameters_and_static_rules_share_rendered_specificity() -> TestResult {
    let mut f = TemplateFixture::new(false)?;
    f.grant(
        r#"
path "idtest/*" { capabilities = ["create", "read", "update"] }
path "idtest/{{identity.entity.id}}/item" {
  capabilities = ["create", "read", "update"]
  required_parameters = ["foo"]
  allowed_parameters = { "foo" = ["good"] }
}
"#,
    );
    let path = format!("idtest/{}/item", f.entity);
    assert_eq!(
        call(
            &mut f.service,
            "",
            &f.token,
            "POST",
            &path,
            json!({"foo":"good"})
        )
        .status,
        204
    );
    for body in [
        json!({}),
        json!({"foo":"bad"}),
        json!({"foo":"good","unapproved":"value"}),
    ] {
        assert_eq!(
            call(&mut f.service, "", &f.token, "POST", &path, body).status,
            403
        );
        assert_eq!(
            call(&mut f.service, "", &f.admin, "GET", &path, json!({})).body["data"],
            json!({"foo":"good"})
        );
    }
    policy(
        &mut f.service,
        "",
        &f.admin,
        "literal",
        &format!("path \"{path}\" {{ capabilities = [\"delete\"] }}"),
    );
    update_entity(
        &mut f.service,
        "",
        &f.admin,
        &f.entity,
        json!({"policies":["literal","template"]}),
    );
    assert_eq!(
        call(
            &mut f.service,
            "",
            &f.token,
            "POST",
            &path,
            json!({"foo":"bad"})
        )
        .status,
        403
    );
    assert_eq!(
        call(&mut f.service, "", &f.token, "DELETE", &path, json!({})).status,
        204
    );
    assert_eq!(
        call(&mut f.service, "", &f.admin, "GET", &path, json!({})).status,
        404
    );
    Ok(())
}

#[test]
fn acl_identity_templates_reject_metadata_wildcards_and_missing_identity_without_effects()
-> TestResult {
    let mut f = TemplateFixture::new(false)?;
    f.grant(r#"path "idtest/{{identity.entity.metadata.team}}/*" { capabilities = ["create","read","update"] }"#);
    f.seed("idtest/blue/item");
    f.seed("idtest/peer/item");
    let orphan = call(
        &mut f.service,
        "",
        &f.admin,
        "POST",
        "auth/token/create",
        json!({"policies":["template"],"no_default_policy":true,"ttl":"10m"}),
    );
    assert_eq!(orphan.status, 200);
    let orphan = text(&orphan.body, "/auth/client_token")?;
    assert_eq!(
        call(
            &mut f.service,
            "",
            &orphan,
            "GET",
            "idtest/blue/item",
            json!({})
        )
        .status,
        403
    );
    for value in [
        "*",
        "+",
        "blue*",
        "../peer",
        "%2e%2e",
        "{{identity.entity.id}}",
    ] {
        let expected_status = if value.contains(['*', '+']) { 400 } else { 403 };
        update_entity(
            &mut f.service,
            "",
            &f.admin,
            &f.entity,
            json!({"metadata":{"team":value}}),
        );
        assert_eq!(f.read("idtest/peer/item"), expected_status);
        assert_eq!(
            call(
                &mut f.service,
                "",
                &f.token,
                "POST",
                "idtest/peer/item",
                json!({"synthetic":"forbidden"})
            )
            .status,
            expected_status
        );
        assert_eq!(
            call(
                &mut f.service,
                "",
                &f.admin,
                "GET",
                "idtest/peer/item",
                json!({})
            )
            .body["data"],
            json!({"synthetic":"original"})
        );
    }
    update_entity(
        &mut f.service,
        "",
        &f.admin,
        &f.entity,
        json!({"metadata":{}}),
    );
    assert_eq!(f.read("idtest/blue/item"), 403);
    Ok(())
}

#[test]
fn acl_identity_group_templates_use_verified_direct_and_inherited_membership() -> TestResult {
    let mut f = TemplateFixture::new(false)?;
    let child = call(
        &mut f.service,
        "",
        &f.admin,
        "POST",
        "identity/group",
        json!({"name":"team","type":"internal","member_entity_ids":[f.entity],"metadata":{"zone":"blue"}}),
    );
    assert_eq!(child.status, 200);
    let child = text(&child.body, "/data/id")?;
    let parent = call(
        &mut f.service,
        "",
        &f.admin,
        "POST",
        "identity/group",
        json!({"name":"division","type":"internal","member_group_ids":[child]}),
    );
    assert_eq!(parent.status, 200);
    let peer = call(
        &mut f.service,
        "",
        &f.admin,
        "POST",
        "identity/group",
        json!({"name":"peer","type":"internal","metadata":{"zone":"peer"}}),
    );
    assert_eq!(peer.status, 200);
    f.grant(&format!(
        r#"
path "idtest/group/{{{{identity.groups.ids.{child}.id}}}}/*" {{ capabilities = ["read"] }}
path "idtest/team/{{{{identity.groups.names.team.metadata.zone}}}}/*" {{ capabilities = ["read"] }}
path "idtest/parent/{{{{identity.groups.names.division.name}}}}/*" {{ capabilities = ["read"] }}
path "idtest/peer/{{{{identity.groups.names.peer.metadata.zone}}}}/*" {{ capabilities = ["read"] }}
"#
    ));
    let own = format!("idtest/group/{child}/item");
    for path in [
        &own,
        "idtest/team/blue/item",
        "idtest/parent/division/item",
        "idtest/peer/peer/item",
    ] {
        f.seed(path);
    }
    for path in [&own, "idtest/team/blue/item", "idtest/parent/division/item"] {
        assert_eq!(f.read(path), 200);
    }
    assert_eq!(f.read("idtest/peer/peer/item"), 403);
    assert_eq!(
        call(
            &mut f.service,
            "",
            &f.admin,
            "POST",
            &format!("identity/group/id/{child}"),
            json!({"member_entity_ids":[]})
        )
        .status,
        204
    );
    for path in [&own, "idtest/team/blue/item", "idtest/parent/division/item"] {
        assert_eq!(f.read(path), 403);
    }
    f.restart()?;
    assert_eq!(f.read("idtest/parent/division/item"), 403);
    Ok(())
}

#[test]
fn acl_identity_alias_templates_use_live_accessor_and_distinct_metadata_owners() -> TestResult {
    let mut f = TemplateFixture::new(false)?;
    let entity = call(
        &mut f.service,
        "",
        &f.admin,
        "GET",
        &format!("identity/entity/id/{}", f.entity),
        json!({}),
    );
    let alias = text(&entity.body, "/data/aliases/0/id")?;
    let accessor = text(&entity.body, "/data/aliases/0/mount_accessor")?;
    let alias_name = text(&entity.body, "/data/aliases/0/name")?;
    assert_eq!(call(&mut f.service,"",&f.admin,"POST",&format!("identity/entity-alias/id/{alias}"),
        json!({"canonical_id":f.entity,"mount_accessor":accessor,"name":alias_name,"custom_metadata":{"tenant":"blue"}})).status,200);
    f.grant(&format!(r#"
path "idtest/id/{{{{identity.entity.aliases.{accessor}.id}}}}/*" {{ capabilities = ["read"] }}
path "idtest/name/{{{{identity.entity.aliases.{accessor}.name}}}}/*" {{ capabilities = ["read"] }}
path "idtest/native/{{{{identity.entity.aliases.{accessor}.metadata.role_name}}}}/*" {{ capabilities = ["read"] }}
path "idtest/custom/{{{{identity.entity.aliases.{accessor}.custom_metadata.tenant}}}}/*" {{ capabilities = ["read"] }}
"#));
    let own = format!("idtest/id/{alias}/item");
    let named = format!("idtest/name/{alias_name}/item");
    for path in [
        &own,
        &named,
        "idtest/native/synthetic/item",
        "idtest/custom/blue/item",
        "idtest/custom/red/item",
    ] {
        f.seed(path);
    }
    for path in [
        &own,
        &named,
        "idtest/native/synthetic/item",
        "idtest/custom/blue/item",
    ] {
        assert_eq!(f.read(path), 200);
    }
    assert_eq!(call(&mut f.service,"",&f.admin,"POST",&format!("identity/entity-alias/id/{alias}"),
        json!({"canonical_id":f.entity,"mount_accessor":accessor,"name":alias_name,"custom_metadata":{"tenant":"red"}})).status,200);
    assert_eq!(f.read("idtest/custom/blue/item"), 403);
    assert_eq!(f.read("idtest/custom/red/item"), 200);
    f.restart()?;
    assert_eq!(f.read("idtest/custom/blue/item"), 403);
    assert_eq!(f.read("idtest/custom/red/item"), 200);
    assert_eq!(
        call(
            &mut f.service,
            "",
            &f.admin,
            "DELETE",
            &format!("identity/entity-alias/id/{alias}"),
            json!({})
        )
        .status,
        204
    );
    assert_eq!(f.read(&own), 403);
    assert_eq!(f.read("idtest/native/synthetic/item"), 403);
    Ok(())
}

#[test]
fn acl_identity_template_schema60_is_independent_and_no_template_schema59_is_byte_stable()
-> TestResult {
    let mut f = TemplateFixture::new(false)?;
    let mut legacy = f.service.state.clone().ok_or("state")?;
    legacy.schema = 59;
    legacy.validate_format().map_err(|_| "schema59 rejected")?;
    let original = serde_json::to_vec(&legacy)?;
    let decoded: State = serde_json::from_slice(&original)?;
    // Raw JSON deliberately has no authenticated KV1 record-root binding.
    // Do not weaken that guard: the normal reopen below must reconstruct it.
    assert!(decoded.validate_format().is_err());
    assert_eq!(serde_json::to_vec(&decoded)?, original);
    f.service
        .commit_state(&legacy)
        .map_err(|_| "legacy publish")?;
    f.service.state = Some(legacy);
    f.restart()?;
    assert_eq!(f.service.state.as_ref().ok_or("state")?.schema, 59);
    f.grant(r#"path "idtest/{{identity.entity.id}}/*" { capabilities = ["read"] }"#);
    let state = f.service.state.as_ref().ok_or("state")?;
    assert_eq!(state.schema, CURRENT_STATE_SCHEMA);
    let mut disguised = state.clone();
    disguised.schema = 59;
    let denied = disguised
        .validate_format()
        .err()
        .ok_or("missing template fence")?;
    assert_eq!(denied.status, 503);
    assert_eq!(
        denied.body["errors"][0],
        "ACL Identity templates require schema 60"
    );
    f.restart()?;
    assert_eq!(
        f.service.state.as_ref().ok_or("state")?.schema,
        CURRENT_STATE_SCHEMA
    );
    Ok(())
}

#[test]
fn acl_identity_template_rebinding_clears_old_projection_before_late_completion() -> TestResult {
    let mut f = TemplateFixture::new(false)?;
    f.grant(r#"path "idtest/{{identity.entity.metadata.team}}/*" { capabilities = ["read"] }"#);
    let mut before = f.service.state.clone().ok_or("state")?;
    let mut actor = before.auth.authenticate(&f.token, 100)?;
    Service::bind_identity_principal(&before, &mut actor, "").map_err(|_| "initial projection")?;
    before
        .auth
        .authorize_request(&actor, "", "idtest/blue/item", "read", 100)?;
    update_entity(
        &mut f.service,
        "",
        &f.admin,
        &f.entity,
        json!({"metadata":{"team":"red"}}),
    );
    let after = f.service.state.as_ref().ok_or("state")?;
    Service::bind_identity_principal(after, &mut actor, "").map_err(|_| "refreshed projection")?;
    assert!(
        after
            .auth
            .authorize_request(&actor, "", "idtest/blue/item", "read", 100)
            .is_err()
    );
    after
        .auth
        .authorize_request(&actor, "", "idtest/red/item", "read", 100)?;
    Ok(())
}

#[test]
fn acl_identity_forbidden_substitution_cannot_drop_deny_under_a_broad_grant() -> TestResult {
    for batch in [false, true] {
        let mut f = TemplateFixture::new(batch)?;
        f.grant(
            r#"
path "idtest/*" { capabilities = ["read", "create", "update"] }
path "idtest/{{identity.entity.metadata.team}}/*" { capabilities = ["deny"] }
"#,
        );
        f.seed("idtest/blue/item");
        f.seed("idtest/peer/item");
        assert_eq!(f.read("idtest/blue/item"), 403);
        assert_eq!(f.read("idtest/peer/item"), 200);
        for value in ["*", "+", "peer*", "a+b"] {
            update_entity(
                &mut f.service,
                "",
                &f.admin,
                &f.entity,
                json!({"metadata":{"team":value}}),
            );
            assert_eq!(
                f.read("idtest/peer/item"),
                400,
                "invalid substitution must fail the full ACL evaluation, not erase deny: batch={batch}"
            );
            let before = f
                .service
                .current_state_digest()
                .map_err(|_| "state digest")?;
            assert_eq!(
                call(
                    &mut f.service,
                    "",
                    &f.token,
                    "POST",
                    "idtest/peer/item",
                    json!({"synthetic":"forbidden"})
                )
                .status,
                400
            );
            assert_eq!(
                f.service
                    .current_state_digest()
                    .map_err(|_| "state digest")?,
                before
            );
            assert_eq!(
                call(
                    &mut f.service,
                    "",
                    &f.admin,
                    "GET",
                    "idtest/peer/item",
                    json!({})
                )
                .body["data"],
                json!({"synthetic":"original"})
            );
            assert_eq!(
                call(
                    &mut f.service,
                    "",
                    &f.admin,
                    "POST",
                    "sys/capabilities",
                    json!({"token":f.token,"path":"idtest/peer/item"})
                )
                .status,
                403
            );
        }
        f.restart()?;
        assert_eq!(f.read("idtest/peer/item"), 400);
        update_entity(
            &mut f.service,
            "",
            &f.admin,
            &f.entity,
            json!({"metadata":{"team":"blue"}}),
        );
        assert_eq!(
            f.read("idtest/peer/item"),
            200,
            "independent root can repair malformed metadata"
        );
        assert_eq!(f.read("idtest/blue/item"), 403);
    }
    Ok(())
}
