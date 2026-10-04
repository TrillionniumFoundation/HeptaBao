//! Token API policy resolution; login and mapping policy semantics are separate.
//!
//! Pinned OpenBao 2.7.0 token_store.go resolveTokenPolicies and policyutil.go.
use super::{AuthError, Token, bad};
use serde_json::Value;
use std::collections::BTreeSet;
#[path = "auth_token_go_print.rs"]
mod go_print;

// Claims use the already resolved Token API policy set. Preserve the API's
// Unicode and punctuation grammar without changing native login policy names.
pub(super) fn valid_api_policy_name(value: &str) -> bool {
    !value.is_empty() && value.trim() == value && simple_lowercase(value) == value
}

pub(super) fn resolve(
    body: &Value,
    parent: &Token,
    namespace: &str,
    is_sudo: bool,
    role: Option<&super::token_roles::Role>,
) -> Result<BTreeSet<String>, AuthError> {
    let input = string_slice(body.get("policies"))?;
    let no_default = weak_boolean(body.get("no_default_policy"), "no_default_policy")?;
    let omitted_or_empty = input.is_empty();
    let mut requested: BTreeSet<String> = input
        .iter()
        .map(|policy| simple_lowercase(policy.trim()))
        .filter(|policy| !policy.is_empty())
        .collect();
    // Normalizing a root-containing set does not grant root authority: the
    // actual parent-root and namespace checks below still apply.
    if requested.contains("root") {
        requested = BTreeSet::from(["root".into()]);
    }
    let add_default = if let Some(role) = role.filter(|role| role.restricted()) {
        requested = role.resolve_policies(&input, parent, no_default)?;
        if namespace != parent.namespace && requested.contains("root") {
            return Err(bad(
                "root tokens may not be created from a parent namespace",
            ));
        }
        false
    } else if namespace != parent.namespace {
        if !is_sudo {
            return Err(bad(
                "root or sudo privileges required to directly generate a token in a child namespace",
            ));
        }
        if requested.contains("root") {
            return Err(bad(
                "root tokens may not be created from a parent namespace",
            ));
        }
        !no_default
    } else if omitted_or_empty {
        // An empty request inherits exactly the parent policies. In particular,
        // a parent without default does not acquire it through this operation.
        requested.clone_from(&parent.policies);
        false
    } else if !is_sudo {
        // Validate before removing default: requesting a policy not held by the
        // parent remains forbidden even when no_default_policy would remove it.
        if !requested.is_subset(&parent.policies) {
            return Err(bad("child policies must be subset of parent"));
        }
        !no_default && parent.policies.contains("default")
    } else {
        !no_default
    };
    if add_default && !requested.contains("root") {
        requested.insert("default".into());
    }
    if no_default {
        requested.remove("default");
    }
    if requested.contains("root") && !parent.root {
        return Err(bad(
            "root tokens may not be created without parent token being root",
        ));
    }
    // Exact 2.7.0 policy.NonAssignablePolicies table. This check follows
    // normalization and default removal; root-containing sets normalize first.
    if requested.contains("response-wrapping") {
        return Err(bad("cannot assign policy \"response-wrapping\""));
    }
    Ok(requested)
}

// These are Token API field conversions. Keep login/mapping helpers separate.
// TypeStringSlice uses WeakDecode: scalar numbers are strings, bools become
// 1/0, null array entries retain an empty slot, and an empty map is an empty
// slice. That last distinction matters to policy inheritance.
pub(super) fn string_slice(value: Option<&Value>) -> Result<Vec<String>, AuthError> {
    match value {
        None | Some(Value::Null) => Ok(Vec::new()),
        Some(Value::String(value)) if value.is_empty() => Ok(Vec::new()),
        Some(Value::Object(value)) if value.is_empty() => Ok(Vec::new()),
        Some(Value::Array(values)) => {
            let mut result = Vec::with_capacity(values.len());
            let mut failures = Vec::new();
            for (index, value) in values.iter().enumerate() {
                match weak_string(value) {
                    Some(value) => result.push(value),
                    None => failures.push(format!(
                        "'[{index}]' expected type 'string', got unconvertible type '{}'",
                        go_kind(value)
                    )),
                }
            }
            if failures.is_empty() {
                Ok(result)
            } else {
                Err(bad(&format!(
                    "Field validation failed: error converting input for field \"policies\": decoding failed due to the following error(s):\n\n{}",
                    failures.join("\n")
                )))
            }
        }
        Some(value) => weak_string(value).map(|value| vec![value]).ok_or_else(|| {
            bad(&format!(
                "Field validation failed: error converting input for field \"policies\": decoding failed due to the following error(s):\n\n'[0]' expected type 'string', got unconvertible type '{}'",
                go_kind(value)
            ))
        }),
    }
}

pub(super) fn weak_string(value: &Value) -> Option<String> {
    match value {
        Value::Null => Some(String::new()),
        Value::String(value) => Some(value.clone()),
        Value::Number(value) => Some(value.to_string()),
        Value::Bool(value) => Some(if *value { "1" } else { "0" }.into()),
        Value::Array(_) | Value::Object(_) => None,
    }
}

pub(super) fn weak_boolean(value: Option<&Value>, field: &str) -> Result<bool, AuthError> {
    let value = match value {
        None | Some(Value::Null) => return Ok(false),
        Some(Value::Bool(value)) => return Ok(*value),
        Some(Value::String(value)) => value.clone(),
        Some(Value::Number(value)) => value.to_string(),
        Some(value) => {
            return Err(bad(&format!(
                "Field validation failed: error converting input for field \"{field}\": '' expected type 'bool', got unconvertible type '{}'",
                go_kind(value)
            )));
        }
    };
    match value.as_str() {
        "1" | "t" | "T" | "true" | "TRUE" | "True" => Ok(true),
        "" | "0" | "f" | "F" | "false" | "FALSE" | "False" => Ok(false),
        _ => Err(bad(&format!(
            "Field validation failed: error converting input for field \"{field}\": '' cannot parse value as 'bool': strconv.ParseBool: invalid syntax"
        ))),
    }
}

pub(super) fn quote_policy(value: &str) -> String {
    // Go fmt %q uses printable Unicode and Go string escapes, rather than
    // inventing a different name after the policy-existence lookup.
    let mut quoted = String::from("\"");
    for character in value.chars() {
        match character {
            '\\' => quoted.push_str("\\\\"),
            '\"' => quoted.push_str("\\\""),
            '\x07' => quoted.push_str("\\a"),
            '\x08' => quoted.push_str("\\b"),
            '\x0c' => quoted.push_str("\\f"),
            '\n' => quoted.push_str("\\n"),
            '\r' => quoted.push_str("\\r"),
            '\t' => quoted.push_str("\\t"),
            '\x0b' => quoted.push_str("\\v"),
            character if (character as u32) < 0x20 || character == '\x7f' => {
                quoted.push_str(&format!("\\x{:02x}", character as u32));
            }
            character if !go_print::is_print(character) => {
                let point = character as u32;
                if point < 0x10000 {
                    quoted.push_str(&format!("\\u{point:04x}"));
                } else {
                    quoted.push_str(&format!("\\U{point:08x}"));
                }
            }
            character => quoted.push(character),
        }
    }
    quoted.push('\"');
    quoted
}

fn go_kind(value: &Value) -> &'static str {
    match value {
        Value::Array(_) => "[]interface {}",
        Value::Object(_) => "map[string]interface {}",
        _ => "unsupported",
    }
}

pub(super) fn simple_lowercase(value: &str) -> String {
    // Go strings.ToLower applies one Unicode simple mapping per rune. Rust's
    // full lowercase expands U+0130 to i + combining dot; its first mapping is
    // the simple i used by the pinned reference. No context-specific casing.
    value
        .chars()
        .map(|character| character.to_lowercase().next().unwrap_or(character))
        .collect()
}

#[cfg(test)]
#[path = "auth_token_policies_tests.rs"]
mod tests;
