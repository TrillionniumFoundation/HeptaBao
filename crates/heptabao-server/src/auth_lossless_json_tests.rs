//! Persisted policy parameters and stored ordinary reply body controls.
use super::*;
type TestResult = Result<(), Box<dyn std::error::Error>>;

#[test]
fn auth_lossless_parameter_rules_reopen_without_user_map_coercion() -> TestResult {
    let value = heptabao_domain::json::decode(br#"{"big":184467440737095516160001,"decimal":0.12345678901234567890123456789,"fake":{"$serde_json::private::Number":"7"}}"#)?;
    let rule = Rule {
        path: "secret/data/item".into(),
        capabilities: BTreeSet::from(["update".into()]),
        allowed_parameters: BTreeMap::from([("payload".into(), vec![value.clone()])]),
        denied_parameters: BTreeMap::from([("blocked".into(), vec![value.clone()])]),
        required_parameters: BTreeSet::new(),
        min_wrapping_ttl: 0,
        max_wrapping_ttl: 0,
    };
    let raw = serde_json::to_vec(&rule)?;
    let decoded: Rule = serde_json::from_slice(&raw)?;
    assert_eq!(decoded.allowed_parameters, rule.allowed_parameters);
    assert_eq!(decoded.denied_parameters, rule.denied_parameters);
    assert_eq!(serde_json::to_vec(&decoded)?, raw);
    let trusted: Rule = serde_json::from_value(serde_json::to_value(&rule)?)?;
    assert_eq!(trusted.allowed_parameters, rule.allowed_parameters);
    let mut bad = heptabao_domain::json::decode(&raw)?;
    bad["allowed_parameters"] = json!({"payload":false});
    assert!(serde_json::from_slice::<Rule>(&serde_json::to_vec(&bad)?).is_err());
    Ok(())
}

#[test]
fn auth_lossless_ordinary_stored_reply_reopen_keeps_map_and_full_wire_equality() -> TestResult {
    let (mut auth, root) = AuthState::bootstrap(100)?;
    let logical = heptabao_domain::json::decode(br#"{"data":{"actual":123,"fake":{"$serde_json::private::Number":"7"},"raw":{"$serde_json::private::RawValue":"[1]"}}}"#)?;
    let _ingress = IngressReplyScope::listener(&[0x81; 16]);
    let wrapped = auth.wrap_logical_response("", "sys/wrapping/wrap", 60, &logical, 100)?;
    let wrapper = wrapped.body["wrap_info"]["token"]
        .as_str()
        .ok_or("wrapper")?
        .to_owned();
    let mut reopened: AuthState = serde_json::from_slice(&serde_json::to_vec(&auth)?)?;
    let admin = reopened.authenticate(&root, 100)?;
    let response = reopened.wrapping_route(
        Some(&admin),
        "",
        "POST",
        "sys/wrapping/unwrap",
        &json!({"token":wrapper}),
        100,
    )?;
    assert_eq!(response.status, 200);
    assert_eq!(response.body["data"], logical["data"]);
    let raw = response
        .unwrapped_json
        .as_ref()
        .ok_or("trusted reply")?
        .raw_bytes(&response.body)?
        .ok_or("stored ordinary bytes")?;
    let decoded = heptabao_domain::json::decode(raw)?;
    assert!(decoded["data"]["fake"].is_object());
    assert!(decoded["data"]["raw"].is_object());
    assert_eq!(decoded["data"], logical["data"]);
    let mut changed = response.body.clone();
    changed["data"]["fake"] = json!(7);
    assert!(
        response
            .unwrapped_json
            .as_ref()
            .ok_or("trusted reply")?
            .raw_bytes(&changed)
            .is_err()
    );
    Ok(())
}

#[test]
fn auth_lossless_cubbyhole_owner_reopen_preserves_user_maps_and_format_predicate() -> TestResult {
    let (mut auth, root) = AuthState::bootstrap(100)?;
    assert!(!auth.has_lossless_json_state());
    let admin = auth.authenticate(&root, 100)?;
    let body = heptabao_domain::json::decode(
        br#"{"big":184467440737095516160001,"fake":{"$serde_json::private::Number":"7"}}"#,
    )?;
    assert_eq!(
        auth.handle(Some(&admin), "", "POST", "cubbyhole/lossless", &body, 100)?
            .ok_or("cubbyhole route")?
            .status,
        204
    );
    assert!(auth.has_lossless_json_state());
    let bytes = serde_json::to_vec(&auth)?;
    let mut reopened: AuthState = serde_json::from_slice(&bytes)?;
    assert!(reopened.has_lossless_json_state());
    assert_eq!(serde_json::to_vec(&reopened)?, bytes);
    let admin = reopened.authenticate(&root, 100)?;
    let response = reopened
        .handle(
            Some(&admin),
            "",
            "GET",
            "cubbyhole/lossless",
            &json!({}),
            100,
        )?
        .ok_or("read route")?;
    assert_eq!(response.status, 200);
    assert_eq!(response.body["data"], body);
    Ok(())
}
