//! Request-local SSH certificate data. This is neither an ACL grant nor durable state.
use super::*;
use crate::auth::{IdentitySelector, IdentityTemplateValues, Principal, TemplateField};
use std::time::{SystemTime, UNIX_EPOCH};

const MAX_TEMPLATE_BYTES: usize = 1024 * 1024;
const MAX_DIRECTIVES: usize = 4096;

/// Only Service's actual authenticated principal selects the authoritative identity.
pub(super) struct RequestIdentity {
    values: Option<IdentityTemplateValues>,
}
impl RequestIdentity {
    pub(super) fn absent() -> Self {
        Self { values: None }
    }
    pub(super) fn has_entity(&self) -> bool {
        self.values.is_some()
    }

    pub(super) fn render(&self, source: &str, allow_commas: bool) -> Result<String> {
        if !self.has_entity() || !matched_template(source) {
            return Ok(source.to_owned());
        }
        let mut result = String::new();
        for part in parts(source)? {
            let value = match part {
                Part::Literal(value) => value.to_owned(),
                Part::Selector(selector) => {
                    let value = if let Some(time) = selector.strip_prefix("time.") {
                        render_time(time)?
                    } else {
                        let parsed = parse_selector(selector)
                            .ok_or_else(|| bad("unsupported SSH identity template selector"))?;
                        let value = self
                            .values
                            .as_ref()
                            .and_then(|values| values.value(selector))
                            .ok_or_else(|| bad("SSH identity template value is unavailable"))?;
                        let metadata = matches!(
                            parsed,
                            IdentitySelector::Entity(TemplateField::Metadata(_))
                                | IdentitySelector::Alias {
                                    field: TemplateField::Metadata(_)
                                        | TemplateField::CustomMetadata(_),
                                    ..
                                }
                                | IdentitySelector::Group {
                                    field: TemplateField::Metadata(_),
                                    ..
                                }
                        );
                        if value.is_empty() && !metadata {
                            return Err(bad("SSH identity template value is unavailable"));
                        }
                        value.to_owned()
                    };
                    if !allow_commas && value.contains(',') {
                        return Err(bad(
                            "SSH identity template substitution contains a forbidden comma",
                        ));
                    }
                    value
                }
            };
            if result
                .len()
                .checked_add(value.len())
                .filter(|n| *n <= MAX_TEMPLATE_BYTES)
                .is_none()
            {
                return Err(bad("SSH identity template result exceeds its bound"));
            }
            result.push_str(&value);
        }
        Ok(result)
    }
}

impl EngineState {
    pub(super) fn ssh_request_identity(
        &self,
        namespace: &str,
        principal: &Principal,
        sources: &[String],
    ) -> Result<RequestIdentity> {
        let Some(id) = principal.entity_id() else {
            return Ok(RequestIdentity::absent());
        };
        let projection = self.identity_projection(namespace, id)?;
        if projection.disabled {
            return Err(error(403, "identity unavailable"));
        }
        let mut selectors = BTreeSet::new();
        for source in sources {
            // Parsing errors belong to the actual rendered field's error path.
            // Only bounded recognizable selectors are copied from current records.
            for suffix in source.split("{{").skip(1) {
                let Some((selector, _)) = suffix.split_once("}}") else {
                    continue;
                };
                let selector = selector.trim();
                if parse_selector(selector).is_some() {
                    selectors.insert(selector.to_owned());
                    if selectors.len() > MAX_DIRECTIVES {
                        return Err(bad("SSH identity selectors exceed their bound"));
                    }
                }
            }
        }
        // Primary EntityInfo retains same-namespace aliases after mount removal.
        // This is a data-only copy; no ACL live-accessor gate is changed.
        let values = self
            .namespaces
            .get(namespace)
            .ok_or_else(|| error(403, "identity unavailable"))?
            .identity
            .ssh_template_values(&projection, &selectors)?;
        Ok(RequestIdentity {
            values: Some(values),
        })
    }
}

// Primary SSH selectors are data keys, not ACL path components.
pub(super) fn parse_selector(value: &str) -> Option<IdentitySelector<'_>> {
    if value.is_empty() || value.len() > MAX_TEMPLATE_BYTES {
        return None;
    }
    fn field(value: &str, alias: bool) -> Option<TemplateField<'_>> {
        match value {
            "id" => Some(TemplateField::Id),
            "name" => Some(TemplateField::Name),
            _ => {
                if let Some(key) = value.strip_prefix("metadata.") {
                    Some(TemplateField::Metadata(key))
                } else if alias {
                    value
                        .strip_prefix("custom_metadata.")
                        .map(TemplateField::CustomMetadata)
                } else {
                    None
                }
            }
        }
    }
    if let Some(value) = value.strip_prefix("identity.entity.") {
        if let Some(value) = value.strip_prefix("aliases.") {
            let (accessor, value) = value.split_once('.')?;
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
    Some(IdentitySelector::Group {
        by_name,
        selector,
        field: field(value, false)?,
    })
}

pub(super) fn matched_template(source: &str) -> bool {
    // The earliest opening on each line dominates every later opening:
    // a closing pair after one Unicode scalar is exactly Go's {{.+?}} match.
    // Do not scan every suffix of a one-MiB unmatched opening string.
    source.split('\n').any(|line| {
        let Some((_, suffix)) = line.split_once("{{") else {
            return false;
        };
        let Some(first) = suffix.chars().next() else {
            return false;
        };
        suffix[first.len_utf8()..].contains("}}")
    })
}
enum Part<'a> {
    Literal(&'a str),
    Selector(&'a str),
}
fn parts(source: &str) -> Result<Vec<Part<'_>>> {
    if source.len() > MAX_TEMPLATE_BYTES {
        return Err(bad("SSH template exceeds its bound"));
    }
    let mut result = Vec::new();
    let mut pieces = source.split("{{");
    let first = pieces.next().unwrap_or("");
    if first.contains("}}") {
        return Err(bad("unbalanced SSH identity template"));
    }
    result.push(Part::Literal(first));
    let mut count = 0usize;
    for piece in pieces {
        let mut suffix = piece.split("}}");
        let selector = suffix.next().unwrap_or("");
        let literal = suffix
            .next()
            .ok_or_else(|| bad("unbalanced SSH identity template"))?;
        if suffix.next().is_some() {
            return Err(bad("unbalanced SSH identity template"));
        }
        count += 1;
        if count > MAX_DIRECTIVES {
            return Err(bad("too many SSH identity template directives"));
        }
        result.push(Part::Selector(selector.trim()));
        result.push(Part::Literal(literal));
    }
    Ok(result)
}
fn render_time(selector: &str) -> Result<String> {
    let mut fields = selector.splitn(3, '.');
    if fields.next() != Some("now") {
        return Err(bad("invalid SSH time selector"));
    }
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| error(503, "system time unavailable"))?
        .as_nanos();
    let now = i128::try_from(nanos).map_err(|_| bad("SSH time overflow"))?;
    let result = match fields.next() {
        None => now,
        Some(operation) => {
            let value = fields
                .next()
                .ok_or_else(|| bad("missing SSH time operand"))?;
            let delta = i128::from(
                crate::auth::ssh_identity_template_duration(value)
                    .map_err(|_| bad("invalid SSH time duration"))?,
            );
            match operation {
                "plus" => now.checked_add(delta),
                "minus" => now.checked_sub(delta),
                _ => return Err(bad("invalid SSH time operator")),
            }
            .ok_or_else(|| bad("SSH time overflow"))?
        }
    };
    let seconds = result.div_euclid(1_000_000_000);
    Ok(i64::try_from(seconds)
        .map_err(|_| bad("SSH time overflow"))?
        .to_string())
}

#[cfg(test)]
#[path = "engine_ssh_templates_tests.rs"]
mod tests;
