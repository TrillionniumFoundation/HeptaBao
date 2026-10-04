//! Token API policy resolution; login and mapping policy semantics are separate.
//!
//! Pinned OpenBao 2.7.0 token_store.go resolveTokenPolicies and policyutil.go.
use super::{AuthError, Token, bad, boolean};
use serde_json::Value;
use std::collections::BTreeSet;

pub(super) fn resolve(
    body: &Value,
    parent: &Token,
    namespace: &str,
    is_sudo: bool,
) -> Result<BTreeSet<String>, AuthError> {
    let input: Vec<&str> = match body.get("policies") {
        None | Some(Value::Null) => Vec::new(),
        Some(Value::String(value)) if value.is_empty() => Vec::new(),
        // Token creation uses TypeStringSlice, not the comma-delimited role
        // fields. A comma-containing string is one literal policy name.
        Some(Value::String(value)) => vec![value],
        Some(Value::Array(values)) => values
            .iter()
            .map(|value| {
                value
                    .as_str()
                    .ok_or_else(|| bad("policies must contain strings"))
            })
            .collect::<Result<_, _>>()?,
        _ => return Err(bad("policies must be an array or string")),
    };
    let no_default = boolean(body, "no_default_policy", false)?;
    let omitted_or_empty = input.is_empty();
    let mut requested: BTreeSet<String> = input
        .into_iter()
        .map(|policy| simple_lowercase(policy.trim()))
        .filter(|policy| !policy.is_empty())
        .collect();
    // Normalizing a root-containing set does not grant root authority: the
    // actual parent-root and namespace checks below still apply.
    if requested.contains("root") {
        requested = BTreeSet::from(["root".into()]);
    }
    let add_default = if namespace != parent.namespace {
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

fn simple_lowercase(value: &str) -> String {
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
