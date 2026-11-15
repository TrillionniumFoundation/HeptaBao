//! Sparse ACL value projection. Only requested selectors are copied, and group
//! selection uses the same verified membership expansion as policy projection.
use super::*;
use crate::auth::{
    IdentitySelector, IdentityTemplateValues, TemplateField, parse_identity_selector,
};

fn metadata_value<'a>(
    metadata: &'a Option<BTreeMap<String, String>>,
    key: &str,
) -> Option<&'a str> {
    metadata.as_ref()?.get(key).map(String::as_str)
}

impl IdentityState {
    pub(crate) fn acl_template_values(
        &self,
        projection: &super::super::IdentityProjection,
        selectors: &BTreeSet<String>,
        live_accessor: impl Fn(&str) -> bool,
    ) -> Result<IdentityTemplateValues> {
        let entity = self
            .entities
            .get(&projection.entity_id)
            .ok_or_else(|| error(403, "identity unavailable"))?;
        if projection.disabled || entity.disabled {
            return Err(error(403, "identity unavailable"));
        }
        let mut values = IdentityTemplateValues::default();
        for selector in selectors {
            let Some(parsed) = parse_identity_selector(selector) else {
                return Err(error(503, "invalid persisted ACL Identity selector"));
            };
            let value = match parsed {
                IdentitySelector::Entity(field) => match field {
                    TemplateField::Id => Some(entity.id.as_str()),
                    TemplateField::Name => Some(entity.name.as_str()),
                    TemplateField::Metadata(key) => metadata_value(&entity.metadata, key),
                    TemplateField::CustomMetadata(_) => None,
                },
                IdentitySelector::Alias { accessor, field } => {
                    if !live_accessor(accessor) {
                        continue;
                    }
                    let mut matches = entity
                        .aliases
                        .iter()
                        .filter_map(|id| self.aliases.get(id))
                        .filter(|alias| alias.mount_accessor == accessor);
                    let Some(alias) = matches.next() else {
                        continue;
                    };
                    if matches.next().is_some()
                        || alias.canonical_id != entity.id
                        || self.alias_keys.get(&alias_key(accessor, &alias.name)) != Some(&alias.id)
                    {
                        return Err(error(503, "inconsistent ACL Identity alias binding"));
                    }
                    match field {
                        TemplateField::Id => Some(alias.id.as_str()),
                        TemplateField::Name => Some(alias.name.as_str()),
                        TemplateField::Metadata(key) => {
                            alias.login_metadata.get(key).map(String::as_str)
                        }
                        TemplateField::CustomMetadata(key) => {
                            metadata_value(&alias.custom_metadata, key)
                        }
                    }
                }
                IdentitySelector::Group {
                    by_name,
                    selector,
                    field,
                } => {
                    let id = if by_name {
                        let Some(id) = self.group_names.get(selector) else {
                            continue;
                        };
                        id.as_str()
                    } else {
                        selector
                    };
                    if !projection.group_ids.contains(id) {
                        continue;
                    }
                    let group = self
                        .groups
                        .get(id)
                        .ok_or_else(|| error(503, "ACL Identity group unavailable"))?;
                    if group.id != id || by_name && group.name != selector {
                        return Err(error(503, "inconsistent ACL Identity group binding"));
                    }
                    match field {
                        TemplateField::Id => Some(group.id.as_str()),
                        TemplateField::Name => Some(group.name.as_str()),
                        TemplateField::Metadata(key) => metadata_value(&group.metadata, key),
                        TemplateField::CustomMetadata(_) => None,
                    }
                }
            };
            if let Some(value) = value {
                values.insert(selector, value);
            }
        }
        Ok(values)
    }
}
