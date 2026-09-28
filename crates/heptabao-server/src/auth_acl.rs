//! Deterministic specificity ordering for the supported OpenBao ACL dialect.
//! Select one highest-priority matching pattern, then union only identical
//! patterns across policies. Deny wins inside that selected union.

use serde_json::Value;
use std::{
    cmp::Ordering,
    collections::{BTreeMap, BTreeSet},
};

pub(super) const DEFAULT_RULES: &[(&str, &[&str])] = &[
    ("auth/token/lookup-self", &["read"]),
    ("sys/capabilities-self", &["update"]),
    ("auth/token/renew-self", &["update"]),
    ("auth/token/revoke-self", &["update"]),
    ("sys/wrapping/wrap", &["update"]),
    ("sys/wrapping/unwrap", &["update"]),
    ("sys/wrapping/lookup", &["update", "read"]),
    (
        "cubbyhole/*",
        &["create", "read", "update", "delete", "list"],
    ),
];

fn priority(left: &str, right: &str) -> Ordering {
    let first_wildcard = |path: &str| path.find(['+', '*']).unwrap_or(path.len());
    first_wildcard(left)
        .cmp(&first_wildcard(right))
        .then_with(|| right.ends_with('*').cmp(&left.ends_with('*')))
        .then_with(|| {
            right
                .split('/')
                .filter(|part| *part == "+")
                .count()
                .cmp(&left.split('/').filter(|part| *part == "+").count())
        })
        .then_with(|| left.len().cmp(&right.len()))
        .then_with(|| left.cmp(right))
}

pub(super) type ParameterMap = BTreeMap<String, Vec<Value>>;

#[derive(Default)]
pub(super) struct Decision {
    pattern: Option<String>,
    allowed: bool,
    denied: bool,
    allowed_parameters: ParameterMap,
    denied_parameters: ParameterMap,
    required_parameters: BTreeSet<String>,
}

impl Decision {
    pub(super) fn consider<'b>(
        &mut self,
        pattern: &str,
        capabilities: impl Iterator<Item = &'b str>,
        request_path: &str,
        requested: &str,
    ) {
        if !super::path_matches(pattern, request_path) {
            return;
        }
        match self.pattern.as_deref().map(|old| priority(pattern, old)) {
            Some(Ordering::Less) => return,
            Some(Ordering::Equal) => {}
            None | Some(Ordering::Greater) => {
                self.pattern = Some(pattern.to_owned());
                self.allowed = false;
                self.denied = false;
            }
        }
        for capability in capabilities {
            self.allowed |= capability == requested;
            self.denied |= capability == "deny";
        }
    }

    pub(super) fn consider_parameters(
        &mut self,
        pattern: &str,
        allowed: &ParameterMap,
        denied: &ParameterMap,
        required: &BTreeSet<String>,
        request_path: &str,
    ) {
        if !super::path_matches(pattern, request_path) {
            return;
        }
        match self.pattern.as_deref().map(|old| priority(pattern, old)) {
            Some(Ordering::Less) => return,
            Some(Ordering::Equal) => {}
            None | Some(Ordering::Greater) => {
                self.pattern = Some(pattern.to_owned());
                self.allowed_parameters.clear();
                self.denied_parameters.clear();
                self.required_parameters.clear();
            }
        }
        merge_parameter_map(&mut self.allowed_parameters, allowed);
        merge_parameter_map(&mut self.denied_parameters, denied);
        self.required_parameters.extend(required.iter().cloned());
    }

    pub(super) fn parameters_allowed(&self, body: &Value) -> bool {
        let Some(_) = self.pattern else {
            return true;
        };
        let empty = serde_json::Map::new();
        let data = body.as_object().unwrap_or(&empty);
        if self
            .required_parameters
            .iter()
            .any(|parameter| !data.contains_key(parameter))
        {
            return false;
        }
        if data.is_empty() {
            return true;
        }
        if self.denied_parameters.contains_key("*") {
            return false;
        }
        for (parameter, value) in data {
            if self
                .denied_parameters
                .get(&parameter.to_ascii_lowercase())
                .is_some_and(|values| parameter_value_matches(value, values))
            {
                return false;
            }
        }
        if self.allowed_parameters.is_empty() {
            return true;
        }
        let allowed_all = self.allowed_parameters.contains_key("*");
        if allowed_all && self.allowed_parameters.len() == 1 {
            return true;
        }
        data.iter().all(|(parameter, value)| {
            self.allowed_parameters
                .get(&parameter.to_ascii_lowercase())
                .map_or(allowed_all, |values| parameter_value_matches(value, values))
        })
    }

    pub(super) fn allowed(&self) -> bool {
        self.allowed && !self.denied
    }
}

fn merge_parameter_map(target: &mut ParameterMap, source: &ParameterMap) {
    for (key, values) in source {
        match target.get_mut(key) {
            None => {
                target.insert(key.clone(), values.clone());
            }
            Some(current) if current.is_empty() || values.is_empty() => current.clear(),
            Some(current) => current.extend(values.iter().cloned()),
        }
    }
}

fn parameter_value_matches(value: &Value, allowed: &[Value]) -> bool {
    allowed.is_empty()
        || allowed.iter().any(|candidate| match (candidate, value) {
            (Value::String(pattern), Value::String(value)) => {
                globbed_string_matches(pattern, value)
            }
            _ => parameter_deep_equal(candidate, value),
        })
}

// OpenBao's HTTP request decoder and HCL policy decoder use distinct numeric
// dynamic types, so numeric values never DeepEqual at the public API boundary.
// Preserve that observed behavior while retaining exact bool/null/map/array
// comparisons. Nested strings are exact; globbing applies only to a top-level
// string value, as in OpenBao's valueInSlice.
fn parameter_deep_equal(left: &Value, right: &Value) -> bool {
    match (left, right) {
        (Value::Number(_), _) | (_, Value::Number(_)) => false,
        (Value::Array(left), Value::Array(right)) => {
            left.len() == right.len()
                && left
                    .iter()
                    .zip(right)
                    .all(|(left, right)| parameter_deep_equal(left, right))
        }
        (Value::Object(left), Value::Object(right)) => {
            left.len() == right.len()
                && left.iter().all(|(key, left)| {
                    right
                        .get(key)
                        .is_some_and(|right| parameter_deep_equal(left, right))
                })
        }
        _ => left == right,
    }
}

fn globbed_string_matches(pattern: &str, value: &str) -> bool {
    if pattern.len() < 2 {
        return pattern == value;
    }
    let leading = pattern.starts_with('*');
    let trailing = pattern.ends_with('*');
    match (leading, trailing) {
        (true, true) => value.contains(&pattern[1..pattern.len() - 1]),
        (true, false) => value.ends_with(&pattern[1..]),
        (false, true) => value.starts_with(&pattern[..pattern.len() - 1]),
        (false, false) => pattern == value,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn acl_identity_template_policy_is_admitted_without_granting_literal_authority() {
        let policy = super::super::parse_policy(&json!(
            r#"path "secret/{{identity.entity.id}}/*" { capabilities = ["read"] }"#
        ));
        assert!(
            policy.is_ok(),
            "identity paths must be accepted for live expansion"
        );
        assert!(!super::super::path_matches(
            "secret/{{identity.entity.id}}/*",
            "secret/other/value"
        ));
    }

    #[test]
    fn acl_specificity_applies_all_five_tie_breaks() {
        for (higher, lower) in [
            ("secret/team/*", "secret/+/item"),
            ("secret/+/item", "secret/+/item*"),
            ("secret/*", "secret/+/+/item/*"),
            ("secret/+/item", "secret/+/x"),
            ("secret/+/z", "secret/+/a"),
            ("secret/item", "secret/*"),
        ] {
            assert_eq!(priority(higher, lower), Ordering::Greater);
            assert_eq!(priority(lower, higher), Ordering::Less);
        }
    }

    #[test]
    fn acl_narrow_rule_does_not_inherit_broad_capabilities() {
        for reverse in [false, true] {
            let mut rules = vec![
                ("secret/*", vec!["read", "delete"]),
                ("secret/item", vec!["read"]),
            ];
            if reverse {
                rules.reverse();
            }
            let mut decision = Decision::default();
            for (path, caps) in rules {
                decision.consider(path, caps.into_iter(), "secret/item", "delete");
            }
            assert!(!decision.allowed());
        }
    }

    #[test]
    fn acl_same_pattern_union_and_deny_are_order_independent() {
        let mut decision = Decision::default();
        decision.consider("secret/item", ["read"].into_iter(), "secret/item", "delete");
        decision.consider(
            "secret/item",
            ["delete"].into_iter(),
            "secret/item",
            "delete",
        );
        assert!(decision.allowed());
        decision.consider("secret/item", ["deny"].into_iter(), "secret/item", "delete");
        assert!(!decision.allowed());
        decision.consider(
            "secret/item",
            ["sudo", "delete"].into_iter(),
            "secret/item",
            "delete",
        );
        assert!(!decision.allowed());
    }

    #[test]
    fn acl_parameter_constraints_merge_and_match_openbao_value_rules() {
        let mut decision = Decision::default();
        decision.consider_parameters(
            "secret/item",
            &ParameterMap::from([
                ("foo".into(), vec![Value::String("good*".into())]),
                ("bar".into(), vec![json!(1), json!(2)]),
                ("flag".into(), vec![json!(false)]),
                ("map".into(), vec![json!({"good":"one"})]),
            ]),
            &ParameterMap::from([("blocked".into(), Vec::new())]),
            &BTreeSet::from(["foo".into()]),
            "secret/item",
        );
        assert!(decision.parameters_allowed(&json!({"foo":"good-value"})));
        assert!(
            decision.parameters_allowed(&json!({"foo":"good", "flag":false, "map":{"good":"one"}}))
        );
        assert!(!decision.parameters_allowed(&json!({"foo":"good", "bar":1})));
        for body in [
            json!({"bar":1}),
            json!({"foo":"bad"}),
            json!({"foo":"good", "unknown":1}),
            json!({"foo":"good", "blocked":null}),
            json!({"foo":"good", "bar":3}),
            json!({"foo":"good", "flag":true}),
        ] {
            assert!(!decision.parameters_allowed(&body), "{body}");
        }
        decision.consider_parameters(
            "secret/item",
            &ParameterMap::from([("extra".into(), Vec::new())]),
            &ParameterMap::new(),
            &BTreeSet::from(["extra".into()]),
            "secret/item",
        );
        assert!(decision.parameters_allowed(&json!({"foo":"good", "extra":"anything"})));
        assert!(!decision.parameters_allowed(&json!({"foo":"good"})));
    }

    #[test]
    fn acl_parameter_wildcard_and_specific_value_precedence_match_openbao() {
        let mut decision = Decision::default();
        decision.consider_parameters(
            "secret/*",
            &ParameterMap::from([("*".into(), Vec::new()), ("bar".into(), vec![json!(false)])]),
            &ParameterMap::new(),
            &BTreeSet::new(),
            "secret/item",
        );
        assert!(decision.parameters_allowed(&json!({"anything":true, "bar":false})));
        assert!(!decision.parameters_allowed(&json!({"anything":true, "bar":true})));
        let mut allow_all = Decision::default();
        allow_all.consider_parameters(
            "secret/*",
            &ParameterMap::from([("*".into(), vec![json!(false)])]),
            &ParameterMap::new(),
            &BTreeSet::new(),
            "secret/item",
        );
        assert!(allow_all.parameters_allowed(&json!({"anything":true})));
    }

    #[test]
    fn acl_only_selected_pattern_can_grant_or_deny() {
        let mut decision = Decision::default();
        decision.consider("secret/*", ["deny"].into_iter(), "secret/item", "read");
        decision.consider("secret/item", ["read"].into_iter(), "secret/item", "read");
        assert!(decision.allowed());
        decision.consider("secret/other", ["deny"].into_iter(), "secret/item", "read");
        assert!(decision.allowed());
        decision.consider("secret/*", ["deny"].into_iter(), "secret/item", "read");
        assert!(decision.allowed());
    }
}
