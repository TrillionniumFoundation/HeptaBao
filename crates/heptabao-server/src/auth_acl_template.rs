//! Bounded Identity substitutions for ACL paths, never a general expression engine.
//! Values are a request-local projection of the current namespace's authoritative
//! Identity records. They cannot be serialized into a token or reused as a grant.
use super::{AuthError, bad, denied, validate_path};
use std::{borrow::Cow, collections::BTreeMap};
use zeroize::Zeroize;

const MAX_PATH_BYTES: usize = 2048;
const MAX_DIRECTIVES: usize = 64;
const MAX_SELECTOR_BYTES: usize = 512;
pub(super) const MAX_EFFECTIVE_SELECTORS: usize = 4096;

#[derive(Default)]
pub(crate) struct IdentityTemplateValues {
    values: BTreeMap<String, String>,
}

impl IdentityTemplateValues {
    pub(crate) fn insert(&mut self, selector: &str, value: &str) {
        self.values.insert(selector.to_owned(), value.to_owned());
    }
}

impl Drop for IdentityTemplateValues {
    fn drop(&mut self) {
        for (mut key, mut value) in std::mem::take(&mut self.values) {
            key.zeroize();
            value.zeroize();
        }
    }
}

#[derive(Clone, Copy)]
pub(crate) enum TemplateField<'a> {
    Id,
    Name,
    Metadata(&'a str),
    CustomMetadata(&'a str),
}

#[derive(Clone, Copy)]
pub(crate) enum IdentitySelector<'a> {
    Entity(TemplateField<'a>),
    Alias {
        accessor: &'a str,
        field: TemplateField<'a>,
    },
    Group {
        by_name: bool,
        selector: &'a str,
        field: TemplateField<'a>,
    },
}

fn field(value: &str, alias: bool) -> Option<TemplateField<'_>> {
    match value {
        "id" => Some(TemplateField::Id),
        "name" => Some(TemplateField::Name),
        _ => {
            let (key, custom) = if let Some(key) = value.strip_prefix("metadata.") {
                (key, false)
            } else if alias {
                (value.strip_prefix("custom_metadata.")?, true)
            } else {
                return None;
            };
            if key.is_empty() || key.len() > 128 || key.chars().any(char::is_control) {
                return None;
            }
            Some(if custom {
                TemplateField::CustomMetadata(key)
            } else {
                TemplateField::Metadata(key)
            })
        }
    }
}

pub(crate) fn parse_selector(value: &str) -> Option<IdentitySelector<'_>> {
    if value.is_empty() || value.len() > MAX_SELECTOR_BYTES || value.contains(['{', '}']) {
        return None;
    }
    if let Some(value) = value.strip_prefix("identity.entity.") {
        if let Some(value) = value.strip_prefix("aliases.") {
            let (accessor, value) = value.split_once('.')?;
            if !super::valid_name(accessor) {
                return None;
            }
            return Some(IdentitySelector::Alias {
                accessor,
                field: field(value, true)?,
            });
        }
        return Some(IdentitySelector::Entity(field(value, false)?));
    }
    let value = value.strip_prefix("identity.groups.")?;
    let (kind, value) = value.split_once('.')?;
    let by_name = match kind {
        "names" => true,
        "ids" => false,
        _ => return None,
    };
    let (selector, value) = value.split_once('.')?;
    if !super::valid_name(selector) {
        return None;
    }
    Some(IdentitySelector::Group {
        by_name,
        selector,
        field: field(value, false)?,
    })
}

#[derive(Clone, Copy)]
enum Part<'a> {
    Literal(&'a str),
    Directive(&'a str),
}

fn parts(path: &str) -> Result<Vec<Part<'_>>, AuthError> {
    if path.is_empty() || path.len() > MAX_PATH_BYTES {
        return Err(bad("ACL template path exceeds its bound"));
    }
    let mut result = Vec::new();
    let mut remaining = path;
    let mut directives = 0;
    while let Some(open) = remaining.find("{{") {
        let literal = &remaining[..open];
        if literal.contains("}}") {
            return Err(bad("unbalanced ACL template"));
        }
        result.push(Part::Literal(literal));
        let suffix = &remaining[open + 2..];
        let close = suffix
            .find("}}")
            .ok_or_else(|| bad("unbalanced ACL template"))?;
        let selector = suffix[..close].trim();
        if parse_selector(selector).is_none() {
            return Err(bad("unsupported or malformed Identity ACL selector"));
        }
        directives += 1;
        if directives > MAX_DIRECTIVES {
            return Err(bad("too many ACL template substitutions"));
        }
        result.push(Part::Directive(selector));
        remaining = &suffix[close + 2..];
    }
    if remaining.contains("}}") {
        return Err(bad("unbalanced ACL template"));
    }
    result.push(Part::Literal(remaining));
    Ok(result)
}

pub(super) fn validate_policy_path(path: &str) -> Result<(), AuthError> {
    let mut skeleton = String::with_capacity(path.len());
    for part in parts(path)? {
        match part {
            Part::Literal(value) => skeleton.push_str(value),
            Part::Directive(_) => skeleton.push('x'),
        }
    }
    validate_path(&skeleton, true)
}

pub(super) fn selectors(path: &str) -> Result<Vec<&str>, AuthError> {
    Ok(parts(path)?
        .into_iter()
        .filter_map(|part| match part {
            Part::Directive(selector) => Some(selector),
            Part::Literal(_) => None,
        })
        .collect())
}

pub(super) fn render<'a>(
    path: &'a str,
    values: &IdentityTemplateValues,
) -> Result<Option<Cow<'a, str>>, AuthError> {
    if !path.contains("{{") && !path.contains("}}") {
        return Ok(Some(Cow::Borrowed(path)));
    }
    let mut rendered = String::with_capacity(path.len());
    for part in parts(path).map_err(|_| denied())? {
        let value = match part {
            Part::Literal(value) => value,
            Part::Directive(selector) => {
                let Some(value) = values.values.get(selector) else {
                    // Missing Identity is common, including on root repair
                    // tokens and default-policy paths. This is not a present
                    // but forbidden substitution and may omit just the rule.
                    return Ok(None);
                };
                // GHSA-hr5j-3j78-4vh2: silently omitting a failed template can
                // delete a deny while retaining a broad grant. An invalid
                // present substitution fails the entire ACL evaluation,
                // even when this particular rule would not match the path.
                if value.contains(['*', '+']) {
                    // The pinned 2.7.0 oracle classifies an invalid present
                    // binding as bad input, not a normal policy denial. Still
                    // abort the entire evaluation; never echo Identity data.
                    return Err(bad(
                        "ACL Identity substitution contains a forbidden wildcard",
                    ));
                }
                value.as_str()
            }
        };
        if rendered.len().checked_add(value.len()).ok_or_else(denied)? > MAX_PATH_BYTES {
            return Err(denied());
        }
        rendered.push_str(value);
    }
    if rendered.contains("}}") || validate_path(&rendered, true).is_err() {
        return Err(denied());
    }
    Ok(Some(Cow::Owned(rendered)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identity_selectors_cover_entity_alias_and_member_group_scalar_fields() {
        for selector in [
            "identity.entity.id",
            "identity.entity.name",
            "identity.entity.metadata.team.name",
            "identity.entity.aliases.auth_userpass_1.id",
            "identity.entity.aliases.auth_userpass_1.name",
            "identity.entity.aliases.auth_userpass_1.metadata.role",
            "identity.entity.aliases.auth_userpass_1.custom_metadata.department",
            "identity.groups.ids.group-1.id",
            "identity.groups.ids.group-1.name",
            "identity.groups.names.ops.metadata.team",
            "identity.groups.names.ops.name",
        ] {
            assert!(parse_selector(selector).is_some(), "{selector}");
            assert!(validate_policy_path(&format!("secret/{{{{ {selector} }}}}/*")).is_ok());
        }
    }

    #[test]
    fn identity_template_parser_rejects_unbalanced_unknown_and_unbounded_input() {
        for path in [
            "secret/{{identity.entity.id}",
            "secret/identity.entity.id}}",
            "secret/{{{{identity.entity.id}}",
            "secret/{{identity.entity.id}}}}",
            "secret/{{}}",
            "secret/{{time.now}}",
            "secret/{{identity.entity.groups.ids}}",
            "secret/{{identity.entity.metadata}}",
            "secret/{{identity.entity.aliases.bad}}",
            "secret/{{identity.groups.names.ops.custom_metadata.team}}",
            "secret/${identity.entity.id}",
            "secret//{{identity.entity.id}}",
            "secret/../{{identity.entity.id}}",
        ] {
            assert!(validate_policy_path(path).is_err(), "{path}");
        }
        assert!(
            validate_policy_path(&"{{identity.entity.id}}".repeat(MAX_DIRECTIVES + 1)).is_err()
        );
        assert!(validate_policy_path(&"a".repeat(MAX_PATH_BYTES + 1)).is_err());
    }

    #[test]
    fn identity_substitutions_never_introduce_wildcards_or_path_escapes() {
        let selector = "identity.entity.metadata.team";
        for value in [
            "*",
            "+",
            "a*",
            "a+b",
            "../escape",
            "a//b",
            "%2f",
            "a\\b",
            "a\nb",
            "{{identity.entity.id}}",
            "x}}",
        ] {
            let mut values = IdentityTemplateValues::default();
            values.insert(selector, value);
            assert!(
                render("secret/{{identity.entity.metadata.team}}/item", &values).is_err(),
                "{value:?}"
            );
        }
        let mut values = IdentityTemplateValues::default();
        values.insert(selector, "engineering/team");
        assert_eq!(
            render("secret/{{identity.entity.metadata.team}}/*", &values)
                .as_ref()
                .ok()
                .and_then(|value| value.as_deref()),
            Some("secret/engineering/team/*")
        );
    }

    #[test]
    fn openbao270_forbidden_wildcard_binding_is_a_redacted_bad_request() {
        for value in ["*", "+", "synthetic-private-team*", "synthetic+private"] {
            let mut values = IdentityTemplateValues::default();
            values.insert("identity.entity.metadata.team", value);
            assert!(
                render("secret/{{identity.entity.metadata.team}}/item", &values).is_err_and(
                    |error| error.status == 400
                        && error.message
                            == "ACL Identity substitution contains a forbidden wildcard"
                )
            );
        }
    }

    #[test]
    fn missing_template_value_omits_only_that_rule_and_rendering_is_single_pass() {
        let mut values = IdentityTemplateValues::default();
        assert!(
            render("secret/{{identity.entity.id}}/*", &values).is_ok_and(|value| value.is_none())
        );
        assert_eq!(
            render("secret/plain/*", &values)
                .as_ref()
                .ok()
                .and_then(|value| value.as_deref()),
            Some("secret/plain/*")
        );
        values.insert("identity.entity.id", "e-1");
        assert_eq!(
            render("secret/prefix-{{ identity.entity.id }}-suffix/*", &values)
                .as_ref()
                .ok()
                .and_then(|value| value.as_deref()),
            Some("secret/prefix-e-1-suffix/*")
        );
        values.insert("identity.entity.metadata.empty", "");
        assert_eq!(
            render("secret/a{{identity.entity.metadata.empty}}b", &values)
                .as_ref()
                .ok()
                .and_then(|value| value.as_deref()),
            Some("secret/ab")
        );
        values.insert(
            "identity.entity.metadata.empty",
            &"x".repeat(MAX_PATH_BYTES),
        );
        assert!(render("secret/{{identity.entity.metadata.empty}}", &values).is_err());
    }
}
