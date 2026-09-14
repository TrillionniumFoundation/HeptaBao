//! Login binding and bounded live policy projection from authoritative records.
use super::super::IdentityProjection;
use super::*;

const MAX_IDENTITY_RECORDS: usize = 4096;
const MAX_EFFECTIVE_POLICIES: usize = 256;

impl IdentityState {
    pub(crate) fn bind_login(
        &mut self,
        accessor: &str,
        name: &str,
        now: u64,
    ) -> Result<IdentityProjection> {
        valid_identifier(accessor, "mount accessor")?;
        valid_name(name, "login alias")?;
        let key = alias_key(accessor, name);
        if let Some(alias_id) = self.alias_keys.get(&key) {
            let alias = self
                .aliases
                .get(alias_id)
                .ok_or_else(|| error(503, "inconsistent identity alias"))?;
            if alias.mount_accessor != accessor || alias.name != name {
                return Err(error(503, "inconsistent identity alias binding"));
            }
            return self.project(&alias.canonical_id);
        }
        if self
            .aliases
            .values()
            .any(|alias| alias.mount_accessor == accessor && alias.name == name)
        {
            return Err(error(503, "identity alias index is missing"));
        }
        if self.entities.len() >= MAX_IDENTITY_RECORDS || self.aliases.len() >= MAX_IDENTITY_RECORDS
        {
            return Err(error(507, "identity capacity exceeded"));
        }
        // Stage allocation, indexes and records together. A failed name check
        // or projection cannot leave an orphan entity or consume an identifier.
        let mut candidate = self.clone();
        let entity_id = candidate.allocate_id('e')?;
        let alias_id = candidate.allocate_id('a')?;
        let entity_name = format!("entity-{entity_id}");
        if candidate.entity_names.contains_key(&entity_name) {
            return Err(error(409, "generated identity name is already in use"));
        }
        candidate
            .entity_names
            .insert(entity_name.clone(), entity_id.clone());
        candidate.entities.insert(
            entity_id.clone(),
            Entity {
                id: entity_id.clone(),
                name: entity_name,
                disabled: false,
                metadata: BTreeMap::new(),
                policies: BTreeSet::new(),
                aliases: BTreeSet::from([alias_id.clone()]),
                group_ids: BTreeSet::new(),
                merged_entity_ids: BTreeSet::new(),
                created_at: now,
                updated_at: now,
            },
        );
        candidate.aliases.insert(
            alias_id.clone(),
            Alias {
                id: alias_id.clone(),
                canonical_id: entity_id.clone(),
                name: name.to_owned(),
                mount_accessor: accessor.to_owned(),
                custom_metadata: BTreeMap::new(),
                created_at: now,
                updated_at: now,
            },
        );
        candidate.alias_keys.insert(key, alias_id);
        let projection = candidate.project(&entity_id)?;
        *self = candidate;
        Ok(projection)
    }

    pub(crate) fn project(&self, id: &str) -> Result<IdentityProjection> {
        valid_identifier(id, "entity id")?;
        let entity = if let Some(entity) = self.entities.get(id) {
            entity
        } else {
            // Existing tokens follow explicit merge lineage, never a reused name.
            let mut successors = self
                .entities
                .values()
                .filter(|entity| entity.merged_entity_ids.contains(id));
            let entity = successors
                .next()
                .ok_or_else(|| error(403, "identity unavailable"))?;
            if successors.next().is_some() {
                return Err(error(503, "ambiguous identity merge lineage"));
            }
            entity
        };
        if self.groups.len() > MAX_IDENTITY_RECORDS {
            return Err(error(507, "identity group capacity exceeded"));
        }
        // Derive membership from authoritative group records, not the entity's
        // reverse-index convenience field. External-group login sync is separate.
        let mut parents: BTreeMap<&str, BTreeSet<&str>> = BTreeMap::new();
        let mut direct = Vec::new();
        for (id, group) in &self.groups {
            if group.kind != "internal" {
                continue;
            }
            if group.member_entity_ids.contains(&entity.id) {
                direct.push(id.as_str());
            }
            for child in &group.member_group_ids {
                if self
                    .groups
                    .get(child)
                    .is_some_and(|group| group.kind == "internal")
                {
                    parents.entry(child).or_default().insert(id);
                }
            }
        }
        let mut expansion = Expansion {
            state: self,
            parents,
            visiting: BTreeSet::new(),
            visited: BTreeSet::new(),
            policies: entity.policies.clone(),
        };
        for group in direct {
            expansion.visit(group, 0)?;
        }
        if expansion.policies.len() > MAX_EFFECTIVE_POLICIES || expansion.policies.contains("root")
        {
            return Err(error(403, "identity policy set is not admissible"));
        }
        Ok(IdentityProjection {
            entity_id: entity.id.clone(),
            policies: expansion.policies,
            disabled: entity.disabled,
        })
    }
}

struct Expansion<'a> {
    state: &'a IdentityState,
    parents: BTreeMap<&'a str, BTreeSet<&'a str>>,
    visiting: BTreeSet<&'a str>,
    visited: BTreeSet<&'a str>,
    policies: BTreeSet<String>,
}
impl<'a> Expansion<'a> {
    fn visit(&mut self, id: &'a str, depth: usize) -> Result<()> {
        if depth > MAX_GROUP_DEPTH || self.visiting.contains(id) {
            return Err(error(503, "identity group cycle or depth limit"));
        }
        if self.visited.contains(id) {
            return Ok(());
        }
        if self.visited.len() + self.visiting.len() >= MAX_MEMBERS {
            return Err(error(507, "identity group expansion exceeds bound"));
        }
        let group = self
            .state
            .groups
            .get(id)
            .ok_or_else(|| error(503, "identity group missing"))?;
        self.policies.extend(group.policies.iter().cloned());
        if self.policies.len() > MAX_EFFECTIVE_POLICIES || self.policies.contains("root") {
            return Err(error(403, "identity policy set is not admissible"));
        }
        self.visiting.insert(id);
        if let Some(parents) = self.parents.get(id).cloned() {
            for parent in parents {
                self.visit(parent, depth + 1)?;
            }
        }
        self.visiting.remove(id);
        self.visited.insert(id);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identity_missing_alias_index_and_counter_reuse_fail_closed() -> Result<()> {
        let mut state = IdentityState::default();
        let id = state.bind_login("auth_test", "a", 100)?.entity_id;
        state.alias_keys.clear();
        let before = serde_json::to_value(&state).map_err(|_| bad("serialize"))?;
        assert!(state.bind_login("auth_test", "a", 101).is_err());
        assert_eq!(
            serde_json::to_value(&state).map_err(|_| bad("serialize"))?,
            before
        );
        state.next_id = 0;
        assert!(state.allocate_id('e').is_err());
        assert_eq!(state.next_id, 0);
        // Explicit merge lineage remains reserved even after the source record
        // no longer exists; rollback of an allocator cannot recycle its ID.
        let mut fresh = IdentityState::default();
        let destination = fresh.bind_login("auth_test", "destination", 100)?.entity_id;
        fresh
            .entities
            .get_mut(&destination)
            .ok_or_else(not_found)?
            .merged_entity_ids
            .insert("e-00000000000000000000000000000003".into());
        assert!(fresh.allocate_id('e').is_err());
        assert_eq!(fresh.next_id, 2);
        assert!(state.entities.contains_key(&id));
        Ok(())
    }

    #[test]
    fn identity_projection_rejects_cycle_root_policy_and_missing_entity() -> Result<()> {
        let mut state = IdentityState::default();
        let entity = state
            .bind_login("auth_test", "synthetic-role", 100)?
            .entity_id;
        let group = upsert_group(
            &mut state,
            None,
            &json!({"name":"g","member_entity_ids":[entity]}),
            100,
        )?;
        let id = group.body["data"]["id"]
            .as_str()
            .ok_or_else(|| bad("missing group"))?
            .to_owned();
        state
            .groups
            .get_mut(&id)
            .ok_or_else(not_found)?
            .member_group_ids
            .insert(id.clone());
        assert!(state.project(&entity).is_err());
        state
            .groups
            .get_mut(&id)
            .ok_or_else(not_found)?
            .member_group_ids
            .clear();
        state
            .groups
            .get_mut(&id)
            .ok_or_else(not_found)?
            .policies
            .insert("root".into());
        assert!(state.project(&entity).is_err());
        assert!(state.project("e-missing").is_err());
        Ok(())
    }

    #[test]
    fn identity_projection_refuses_ambiguous_merge_lineage() -> Result<()> {
        let mut state = IdentityState::default();
        let a = state.bind_login("auth_test", "a", 100)?.entity_id;
        let b = state.bind_login("auth_test", "b", 100)?.entity_id;
        state
            .entities
            .get_mut(&a)
            .ok_or_else(not_found)?
            .merged_entity_ids
            .insert("e-former".into());
        state
            .entities
            .get_mut(&b)
            .ok_or_else(not_found)?
            .merged_entity_ids
            .insert("e-former".into());
        assert!(state.project("e-former").is_err());
        Ok(())
    }

    #[test]
    fn identity_partial_updates_reject_unknown_fields_and_preserve_state() -> Result<()> {
        let mut state = IdentityState::default();
        let entity = state.bind_login("auth_test", "a", 100)?.entity_id;
        let before = serde_json::to_value(&state).map_err(|_| bad("serialize"))?;
        assert!(
            upsert_entity(
                &mut state,
                Some(&entity),
                &json!({"disabled":true,"typo":true}),
                101
            )
            .is_err()
        );
        assert_eq!(
            serde_json::to_value(&state).map_err(|_| bad("serialize"))?,
            before
        );
        assert!(
            upsert_entity(
                &mut state,
                Some(&entity),
                &json!({"id":"different","disabled":true}),
                101
            )
            .is_err()
        );
        assert_eq!(
            serde_json::to_value(&state).map_err(|_| bad("serialize"))?,
            before
        );
        Ok(())
    }
}
