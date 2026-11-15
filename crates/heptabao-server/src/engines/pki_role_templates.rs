//! PKI Identity substitutions use scalar values from the current verified
//! entity/alias/group facade. They never parse user request metadata as identity.
use super::*;
use crate::auth::{IdentityTemplateValues, parse_identity_selector};

const MAX_PATTERN_BYTES: usize = 2048;
const MAX_PATTERN_DIRECTIVES: usize = 64;

enum Part<'a> {
    Literal(&'a str),
    Selector(&'a str),
}

fn parts(pattern: &str) -> Option<Vec<Part<'_>>> {
    if pattern.len() > MAX_PATTERN_BYTES {
        return None;
    }
    let mut parts = Vec::new();
    let mut rest = pattern;
    let mut directives = 0;
    while let Some(begin) = rest.find("{{") {
        let literal = &rest[..begin];
        if literal.contains("}}") {
            return None;
        }
        parts.push(Part::Literal(literal));
        let directive = &rest[begin + 2..];
        let end = directive.find("}}")?;
        let selector = directive[..end].trim();
        parse_identity_selector(selector)?;
        directives += 1;
        if directives > MAX_PATTERN_DIRECTIVES {
            return None;
        }
        parts.push(Part::Selector(selector));
        rest = &directive[end + 2..];
    }
    if rest.contains("}}") {
        return None;
    }
    parts.push(Part::Literal(rest));
    Some(parts)
}

fn selectors(pattern: &str, out: &mut BTreeSet<String>) {
    if let Some(parts) = parts(pattern) {
        for part in parts {
            if let Part::Selector(selector) = part {
                out.insert(selector.to_owned());
            }
        }
    }
}

fn render(
    pattern: &str,
    values: Option<&IdentityTemplateValues>,
    allow_globs: bool,
) -> Option<String> {
    let mut rendered = String::new();
    for part in parts(pattern)? {
        let value = match part {
            Part::Literal(value) => value,
            Part::Selector(selector) => {
                let value = values?.value(selector)?;
                if !allow_globs && value.contains('*') {
                    return None;
                }
                value
            }
        };
        if rendered.len().checked_add(value.len())? > MAX_PATTERN_BYTES {
            return None;
        }
        rendered.push_str(value);
    }
    Some(rendered)
}

impl Role {
    pub(super) fn identity_selectors(&self) -> BTreeSet<String> {
        let mut out = BTreeSet::new();
        let Some(policy) = &self.role_name_policy else {
            return out;
        };
        if policy.allowed_domains_template {
            for domain in &self.allowed_domains {
                selectors(domain, &mut out);
            }
        }
        if policy.allowed_uri_sans_template {
            for uri in &policy.allowed_uri_sans {
                selectors(uri, &mut out);
            }
        }
        out
    }

    pub(super) fn resolve_identity_templates(&mut self, values: Option<&IdentityTemplateValues>) {
        let Some(policy) = &mut self.role_name_policy else {
            return;
        };
        if policy.allowed_domains_template {
            self.allowed_domains = self
                .allowed_domains
                .iter()
                .filter_map(|pattern| {
                    render(pattern, values, policy.allow_globs_in_identity_templates)
                })
                .collect();
        }
        if policy.allowed_uri_sans_template {
            policy.allowed_uri_sans = policy
                .allowed_uri_sans
                .iter()
                .filter_map(|pattern| {
                    render(pattern, values, policy.allow_globs_in_identity_templates)
                })
                .collect();
        }
    }
}

impl Pki {
    pub(in crate::engines) fn identity_selectors(&self, path: &str) -> BTreeSet<String> {
        let name = path
            .strip_prefix("issue/")
            .or_else(|| path.strip_prefix("sign/"))
            .or_else(|| Self::issuer_issue_route(path).map(|(_, name)| name))
            .or_else(|| Self::issuer_sign_route(path).map(|(_, name)| name));
        name.and_then(|name| self.roles.get(name))
            .map_or_else(BTreeSet::new, Role::identity_selectors)
    }
}
