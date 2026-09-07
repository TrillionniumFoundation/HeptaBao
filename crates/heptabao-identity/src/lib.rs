#![forbid(unsafe_code)]
#![deny(missing_debug_implementations)]

//! Entity, alias and group resolution with deterministic policy expansion.

use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::fmt;

use heptabao_domain::Id;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Entity {
    id: Id,
    aliases: BTreeSet<Id>,
    direct_policies: BTreeSet<Id>,
    groups: BTreeSet<Id>,
    disabled: bool,
}

impl Entity {
    pub fn id(&self) -> &Id {
        &self.id
    }

    pub fn aliases(&self) -> &BTreeSet<Id> {
        &self.aliases
    }

    pub fn disabled(&self) -> bool {
        self.disabled
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Group {
    id: Id,
    policies: BTreeSet<Id>,
    members: BTreeSet<Id>,
}

impl Group {
    pub fn id(&self) -> &Id {
        &self.id
    }

    pub fn members(&self) -> &BTreeSet<Id> {
        &self.members
    }
}

#[derive(Debug, Default)]
pub struct IdentityStore {
    entities: BTreeMap<Id, Entity>,
    aliases: BTreeMap<Id, Id>,
    groups: BTreeMap<Id, Group>,
}

impl IdentityStore {
    pub fn create_entity(&mut self, id: Id) -> Result<(), IdentityError> {
        if self.entities.contains_key(&id) {
            return Err(IdentityError::DuplicateEntity);
        }
        self.entities.insert(
            id.clone(),
            Entity {
                id,
                aliases: BTreeSet::new(),
                direct_policies: BTreeSet::new(),
                groups: BTreeSet::new(),
                disabled: false,
            },
        );
        Ok(())
    }

    pub fn create_group(&mut self, id: Id, policies: BTreeSet<Id>) -> Result<(), IdentityError> {
        if self.groups.contains_key(&id) {
            return Err(IdentityError::DuplicateGroup);
        }
        self.groups.insert(
            id.clone(),
            Group {
                id,
                policies,
                members: BTreeSet::new(),
            },
        );
        Ok(())
    }

    pub fn add_alias(&mut self, entity_id: &Id, alias: Id) -> Result<(), IdentityError> {
        if self.aliases.contains_key(&alias) {
            return Err(IdentityError::DuplicateAlias);
        }
        let entity = self
            .entities
            .get_mut(entity_id)
            .ok_or(IdentityError::MissingEntity)?;
        entity.aliases.insert(alias.clone());
        self.aliases.insert(alias, entity_id.clone());
        Ok(())
    }

    pub fn attach_policy(&mut self, entity_id: &Id, policy_id: Id) -> Result<(), IdentityError> {
        let entity = self
            .entities
            .get_mut(entity_id)
            .ok_or(IdentityError::MissingEntity)?;
        entity.direct_policies.insert(policy_id);
        Ok(())
    }

    pub fn add_entity_to_group(
        &mut self,
        entity_id: &Id,
        group_id: &Id,
    ) -> Result<(), IdentityError> {
        if !self.entities.contains_key(entity_id) {
            return Err(IdentityError::MissingEntity);
        }
        if !self.groups.contains_key(group_id) {
            return Err(IdentityError::MissingGroup);
        }
        if let Some(group) = self.groups.get_mut(group_id) {
            group.members.insert(entity_id.clone());
        }
        if let Some(entity) = self.entities.get_mut(entity_id) {
            entity.groups.insert(group_id.clone());
        }
        Ok(())
    }

    pub fn set_disabled(&mut self, entity_id: &Id, disabled: bool) -> Result<(), IdentityError> {
        let entity = self
            .entities
            .get_mut(entity_id)
            .ok_or(IdentityError::MissingEntity)?;
        entity.disabled = disabled;
        Ok(())
    }

    pub fn resolve_alias(&self, alias: &Id) -> Result<&Entity, IdentityError> {
        let entity_id = self.aliases.get(alias).ok_or(IdentityError::MissingAlias)?;
        self.entities
            .get(entity_id)
            .ok_or(IdentityError::MissingEntity)
    }

    pub fn entity(&self, entity_id: &Id) -> Result<&Entity, IdentityError> {
        self.entities
            .get(entity_id)
            .ok_or(IdentityError::MissingEntity)
    }

    pub fn effective_policy_ids(&self, entity_id: &Id) -> Result<BTreeSet<Id>, IdentityError> {
        let entity = self.entity(entity_id)?;
        if entity.disabled {
            return Err(IdentityError::EntityDisabled);
        }
        let mut policies = entity.direct_policies.clone();
        for group_id in &entity.groups {
            let group = self
                .groups
                .get(group_id)
                .ok_or(IdentityError::MissingGroup)?;
            policies.extend(group.policies.iter().cloned());
        }
        Ok(policies)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IdentityError {
    DuplicateEntity,
    DuplicateAlias,
    DuplicateGroup,
    MissingEntity,
    MissingAlias,
    MissingGroup,
    EntityDisabled,
}

impl fmt::Display for IdentityError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::DuplicateEntity => "entity already exists",
            Self::DuplicateAlias => "alias already exists",
            Self::DuplicateGroup => "group already exists",
            Self::MissingEntity => "entity does not exist",
            Self::MissingAlias => "alias does not exist",
            Self::MissingGroup => "group does not exist",
            Self::EntityDisabled => "entity is disabled",
        })
    }
}

impl Error for IdentityError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn aliases_groups_and_direct_policies_expand_deterministically() -> Result<(), Box<dyn Error>> {
        let entity = Id::parse("alice")?;
        let alias = Id::parse("oidc_alice")?;
        let group = Id::parse("engineering")?;
        let direct = Id::parse("self_service")?;
        let inherited = Id::parse("engineering_read")?;
        let mut group_policies = BTreeSet::new();
        group_policies.insert(inherited.clone());

        let mut store = IdentityStore::default();
        store.create_entity(entity.clone())?;
        store.add_alias(&entity, alias.clone())?;
        store.attach_policy(&entity, direct.clone())?;
        store.create_group(group.clone(), group_policies)?;
        store.add_entity_to_group(&entity, &group)?;

        assert_eq!(entity, store.resolve_alias(&alias)?.id().clone());
        let effective = store.effective_policy_ids(&entity)?;
        assert!(effective.contains(&direct));
        assert!(effective.contains(&inherited));
        Ok(())
    }

    #[test]
    fn disabled_entities_fail_closed() -> Result<(), Box<dyn Error>> {
        let entity = Id::parse("disabled_user")?;
        let mut store = IdentityStore::default();
        store.create_entity(entity.clone())?;
        store.set_disabled(&entity, true)?;
        assert_eq!(
            Err(IdentityError::EntityDisabled),
            store.effective_policy_ids(&entity)
        );
        Ok(())
    }
}
