//! Source controls for policy admission and encrypted owner compatibility.
use super::*;
type TestResult = Result<(), Box<dyn std::error::Error>>;

fn policy(ttl: &str, capabilities: &str) -> String {
    format!(
        r#"path "secret/data/+" {{
      capabilities = ["create", "update", "read"]
      control_group = {{
        ttl = "{ttl}"
        factor "review" {{
          controlled_capabilities = [{capabilities}]
          identity {{ group_names = ["cg-team"] approvals = 2 self_authorization = false }}
        }}
      }}
    }}"#
    )
}
fn owner(namespace: &str) -> DeferredRequest {
    let namespace_id = if namespace.is_empty() {
        "root"
    } else {
        "test-namespace"
    };
    DeferredRequest {
        cluster_id: "synthetic-cluster".into(),
        namespace: namespace.into(),
        namespace_id: namespace_id.into(),
        namespace_incarnation: if namespace.is_empty() { 0 } else { 1 },
        resource_binding: ResourceBinding::System,
        actor_digest: hash("hvs.synthetic-requester"),
        actor_accessor: "a.synthetic-requester".into(),
        actor_entity_id: "synthetic-entity".into(),
        actor_entity: json!({"ID":"synthetic-entity","name":"synthetic","namespace_id":namespace_id,"aliases":[]}),
        request_accessor: String::new(),
        credential: None,
        method: "POST".into(),
        path: "secret/data/key".into(),
        capability: "update".into(),
        requires_sudo: false,
        body: json!({"data":{"value":"synthetic-secret"}}),
        transport_method: "POST".into(),
        transport_path: "secret/data/key".into(),
        transport_namespace: namespace.into(),
        transport_body: json!({"data":{"value":"synthetic-secret"}}),
        wrap_ttl_seconds: None,
        origin_peer: None,
        client_certificates: None,
        created_at: 100,
        expires_at: 160,
        creation_time: crate::engines::timestamp(100),
        factors: vec![ResolvedFactor {
            name: "requester:review".into(),
            group_ids: BTreeSet::from(["synthetic-group".into()]),
            approvals: 2,
            self_authorization: false,
        }],
        authorizations: BTreeMap::new(),
    }
}
#[test]
fn cg270_policy_grammar_is_bounded_and_keeps_capability_subset_and_self_defaults() -> TestResult {
    let parsed = parse_policy(&Value::String(policy("60s", "\"update\"")))?;
    let control = parsed
        .control_groups
        .get("secret/data/+")
        .ok_or("control missing")?;
    assert_eq!(control.len(), 1);
    assert_eq!(control[0].rule_index, 0);
    let control = &control[0].control;
    assert_eq!(control.ttl, 60);
    assert_eq!(control.factors.len(), 1);
    assert!(!control.factors[0].self_authorization);
    assert_eq!(control.factors[0].approvals, 2);
    let json_policy = json!({"path":{"secret/data/+":{"capabilities":["create","update","read"],
        "control_group":{"ttl":"60s","factor":{"review":{"controlled_capabilities":["update"],
        "identity":{"group_names":["cg-team"],"approvals":2,"self_authorization":false}}}}}}});
    assert!(parse_policy(&json_policy)?.control_groups == parsed.control_groups);
    for invalid in [
        policy("0s", "\"update\""),
        policy("60s", "\"delete\""),
        policy("60s", "\"update\"").replace("approvals = 2", "approvals = 0"),
        policy("60s", "\"update\"")
            .replace("self_authorization = false", "self_auth_allowed = false"),
        policy("60s", "\"update\"").replace(
            "group_names = [\"cg-team\"]",
            "group_names = [\"cg-team\", \"cg-team\"]",
        ),
        policy("60s", "\"update\"").replace(
            "factor \"review\"",
            "factor \"review\" {} factor \"review\"",
        ),
    ] {
        assert!(parse_policy(&Value::String(invalid)).is_err());
    }
    let no_subset =
        policy("60s", "\"update\"").replace("controlled_capabilities = [\"update\"]", "");
    assert!(
        parse_policy(&Value::String(no_subset))?.control_groups["secret/data/+"][0]
            .control
            .factors[0]
            .controlled_capabilities
            .is_none()
    );
    let sudo = policy("60s", "\"update\"")
        .replace(
            "[\"create\", \"update\", \"read\"]",
            "[\"create\", \"update\", \"read\", \"sudo\"]",
        )
        .replace(
            "controlled_capabilities = [\"update\"]",
            "controlled_capabilities = [\"sudo\"]",
        );
    let parsed = parse_policy(&Value::String(sudo.clone()))?;
    assert_eq!(
        parsed.control_groups["secret/data/+"][0].control.factors[0].controlled_capabilities,
        Some(BTreeSet::from(["sudo".to_owned()]))
    );
    assert!(parse_policy(&Value::String(sudo.replace(", \"sudo\"", ""))).is_err());
    // Complete pinned non-Go OpenBao2.7 documentation example.
    let documented = r#"path "kv/*" {
    capabilities = ["create","update","delete","list","sudo"]
    control_group = {
        factor "admin" {
            controlled_capabilities = ["delete","list","sudo"]
            identity {
                group_names = ["admin"]
                approvals = 1
            }
        }
    }
}
path "kv/*" {
    capabilities = ["create"]
    control_group = {
        factor "superuser" {
            identity {
                group_names = ["superuser"]
                approvals = 2
            }
        }
    }
}
"#;
    let documented = parse_policy(&Value::String(documented.into()))?;
    assert_eq!(documented.rules.len(), 2);
    assert_eq!(documented.control_groups["kv/*"].len(), 2);
    assert_eq!(documented.control_groups["kv/*"][0].rule_index, 0);
    assert_eq!(documented.control_groups["kv/*"][1].rule_index, 1);
    assert_eq!(
        documented.control_groups["kv/*"][0].control.factors[0].name,
        "admin"
    );
    assert_eq!(
        documented.control_groups["kv/*"][1].control.factors[0].name,
        "superuser"
    );
    assert_eq!(
        documented.control_groups["kv/*"][0].control.factors[0].controlled_capabilities,
        Some(BTreeSet::from([
            "delete".into(),
            "list".into(),
            "sudo".into()
        ]))
    );
    assert!(
        documented.control_groups["kv/*"][1].control.factors[0]
            .controlled_capabilities
            .is_none()
    );
    let second_owned = r#"path "kv/*" { capabilities = ["read"] }
      path "kv/*" { capabilities = ["create"]
        control_group = { factor "same" { controlled_capabilities = ["create"]
          identity { group_names = ["admin"] approvals = 1 } } } }"#;
    let accepted = parse_policy(&Value::String(second_owned.into()))?;
    assert_eq!(accepted.control_groups["kv/*"][0].rule_index, 1);
    assert!(
        parse_policy(&Value::String(
            second_owned
                .replace(r#"capabilities = ["read"]"#, r#"capabilities = ["create"]"#)
                .replace(
                    r#"capabilities = ["create"]
        control_group"#,
                    r#"capabilities = ["read"]
        control_group"#
                )
        ))
        .is_err()
    );
    Ok(())
}
#[test]
fn cg270_effective_rule_uses_exact_acl_specificity_and_filters_create_without_root_bypass()
-> TestResult {
    let (mut state, root) = AuthState::bootstrap(100)?;
    let mut token = state
        .tokens
        .get(&hash(&root))
        .ok_or("root missing")?
        .clone();
    token.root = false;
    token.policies = BTreeSet::from(["controlled".into(), "override".into()]);
    let digest = hash("hvs.synthetic-actor");
    state.tokens.insert(digest.clone(), token.clone());
    let mut actor = AuthState::request_principal(
        digest,
        token,
        100,
        None,
        PrincipalAdmission::Operation {
            finite_use_consumed: false,
        },
    );
    actor.bind_identity_policies(BTreeSet::new());
    state.policies.entry("".into()).or_default().insert(
        "controlled".into(),
        parse_policy(&Value::String(policy("60s", "\"update\"")))?,
    );
    state.policies.get_mut("").ok_or("policies")?.insert(
        "override".into(),
        parse_policy(&Value::String(
            "path \"secret/data/exact\" { capabilities = [\"update\"] }".into(),
        ))?,
    );
    assert!(
        state
            .control_group_policy(
                &actor,
                "",
                "secret/data/key",
                "update",
                AuthorityTime::Coarse(100)
            )?
            .is_some()
    );
    assert!(
        state
            .control_group_policy(
                &actor,
                "",
                "secret/data/key",
                "create",
                AuthorityTime::Coarse(100)
            )?
            .is_none()
    );
    assert!(
        state
            .control_group_policy(
                &actor,
                "",
                "secret/data/exact",
                "update",
                AuthorityTime::Coarse(100)
            )?
            .is_none()
    );
    let repeated = r#"path "secret/data/+" { capabilities = ["update"]
      control_group = { ttl = "60s" factor "same" {
        controlled_capabilities = ["update"]
        identity { group_names = ["cg-team"] approvals = 1 } } } }
      path "secret/data/+" { capabilities = ["read"]
      control_group = { ttl = "10s" factor "same" {
        controlled_capabilities = ["read"]
        identity { group_names = ["cg-team"] approvals = 2 } } } }"#;
    state.policies.get_mut("").ok_or("policies")?.insert(
        "controlled".into(),
        parse_policy(&Value::String(repeated.into()))?,
    );
    let update = state
        .control_group_policy(
            &actor,
            "",
            "secret/data/key",
            "update",
            AuthorityTime::Coarse(100),
        )?
        .ok_or("update control")?;
    assert_eq!(update.ttl, 60);
    assert_eq!(update.factors.len(), 1);
    assert_eq!(update.factors[0].name, "controlled:0:same");
    let read = state
        .control_group_policy(
            &actor,
            "",
            "secret/data/key",
            "read",
            AuthorityTime::Coarse(100),
        )?
        .ok_or("read control")?;
    assert_eq!(read.ttl, 10);
    assert_eq!(read.factors.len(), 1);
    assert_eq!(read.factors[0].name, "controlled:1:same");
    // The omitted subset controls every operation at the merged selected path.
    let unfiltered = repeated.replace(r#"controlled_capabilities = ["read"]"#, "");
    state.policies.get_mut("").ok_or("policies")?.insert(
        "controlled".into(),
        parse_policy(&Value::String(unfiltered))?,
    );
    let merged = state
        .control_group_policy(
            &actor,
            "",
            "secret/data/key",
            "update",
            AuthorityTime::Coarse(100),
        )?
        .ok_or("merged control")?;
    assert_eq!(merged.ttl, 10);
    assert_eq!(merged.factors.len(), 2);
    assert_eq!(merged.factors[0].name, "controlled:0:same");
    assert_eq!(merged.factors[1].name, "controlled:1:same");
    let root_actor = state.authenticate(&root, 100)?;
    assert!(
        state
            .control_group_policy(
                &root_actor,
                "",
                "secret/data/key",
                "update",
                AuthorityTime::Coarse(100)
            )?
            .is_none()
    );
    Ok(())
}
#[test]
fn cg270_strict_deferred_owner_rejects_forged_entity_and_unknown_persistent_shape() -> TestResult {
    let (mut state, _) = AuthState::bootstrap(100)?;
    let old = Zeroizing::new(serde_json::to_vec(&state)?);
    assert!(
        !old.windows(b"control_groups".len())
            .any(|w| w == b"control_groups")
    );
    let response = state.issue_control_group(owner(""))?;
    let raw = response.body["wrap_info"]["token"]
        .as_str()
        .ok_or("wrapper")?;
    assert!(state.control_group_target(raw, "", 100)?.is_some());
    state.validate_control_group_state()?;
    let encoded = Zeroizing::new(serde_json::to_vec(&state)?);
    let restored: AuthState = serde_json::from_slice(&encoded)?;
    restored.validate_control_group_state()?;
    let mut value: Value = serde_json::from_slice(&encoded)?;
    value["control_groups"]["unknown"] = json!(true);
    assert!(serde_json::from_value::<AuthState>(value).is_err());
    let mut invalid = owner("");
    invalid.actor_entity["ID"] = json!("different-entity");
    assert!(invalid.validate().is_err());
    invalid = owner("");
    invalid.actor_digest = "f".repeat(64);
    assert!(invalid.validate().is_err());
    invalid = owner("");
    invalid.namespace_incarnation = 1;
    assert!(invalid.validate().is_err());
    Ok(())
}
#[test]
fn cg270_namespace_partition_keeps_deferred_payload_private_and_expiry_floor_sticky() -> TestResult
{
    let (mut state, _) = AuthState::bootstrap(100)?;
    let mut pending = owner("team");
    pending.body = json!({"data":{"value":"private-namespace-only"}});
    pending.transport_body = pending.body.clone();
    let response = state.issue_control_group(pending)?;
    let raw = response.body["wrap_info"]["token"]
        .as_str()
        .ok_or("wrapper")?
        .to_owned();
    let assets = state.detach_namespace("team")?;
    assets.validate("team")?;
    let root_encoded = Zeroizing::new(serde_json::to_vec(&state)?);
    assert!(
        !root_encoded
            .windows(b"private-namespace-only".len())
            .any(|w| w == b"private-namespace-only")
    );
    assert!(state.has_control_group_state());
    let parcel = Zeroizing::new(serde_json::to_vec(&assets)?);
    assert!(
        parcel
            .windows(b"private-namespace-only".len())
            .any(|w| w == b"private-namespace-only")
    );
    let restored = serde_json::from_slice(&parcel)?;
    state.attach_namespace("team", restored)?;
    state.validate_control_group_state()?;
    assert!(state.control_group_target(&raw, "team", 159)?.is_some());
    assert!(state.advance_control_group_clock(160));
    assert!(state.control_group_target(&raw, "team", 160).is_err());
    assert!(state.has_control_group_state());
    let encoded = Zeroizing::new(serde_json::to_vec(&state)?);
    let mut restored: AuthState = serde_json::from_slice(&encoded)?;
    assert!(!restored.advance_control_group_clock(159));
    assert!(restored.control_group_target(&raw, "team", 159).is_err());
    restored.validate_control_group_state()?;
    Ok(())
}
