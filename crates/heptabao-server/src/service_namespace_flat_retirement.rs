//! Plain flat namespace retirement is an actual incarnation transition.
//! Its sticky marker is data, never a key, Actor, publication or route grant.
//! The private namespace operation owner alone performs the deterministic
//! catalog/Auth/engine delta; readers independently retain the full ledger.
use super::*;

fn invalid() -> Response {
    Response::error(503, "native flat namespace retirement custody is invalid")
}

impl NamespaceRegistry {
    pub(in crate::service) fn has_native_flat_retirement_state(&self) -> bool {
        self.native_flat_retirement_format.is_some()
    }

    /// Keep the previous fresh profile exact when no new marker exists. The
    /// new profile admits only fully visible flat incarnation history. An
    /// independently sealed/retired owner or hidden child is never normalized.
    #[cfg(feature = "native-v6-storage")]
    pub(super) fn native_flat_catalog_paths(&self) -> Result<BTreeSet<String>, Response> {
        if self.has_native_plain_tree_state() {
            self.validate_native_plain_tree_shape()?;
            return Ok(self.entries.keys().cloned().collect());
        }
        if self.deletions.is_some()
            || !self.retired_custody.is_empty()
            || !self.custody_frontiers.is_empty()
            || !self.closed_auth_routes.is_empty()
            || !self.workflows.is_empty()
            || self.entries.iter().any(|(path, entry)| {
                path.is_empty()
                    || path.contains('/')
                    || entry.incarnation == 0
                    || entry.custody.is_some()
                    || entry.inherited.is_some()
                    || entry.sealed
            })
        {
            return Err(invalid());
        }
        match self.native_flat_retirement_format {
            None => {
                if !self.next_incarnation.is_empty()
                    || self.entries.values().any(|entry| entry.incarnation != 1)
                    || self
                        .batch_lifecycle
                        .as_ref()
                        .is_some_and(|registry| !registry.native_v6_flat_catalog_profile())
                {
                    return Err(invalid());
                }
            }
            Some(1) => self.validate_native_flat_retirement_shape()?,
            Some(_) => return Err(invalid()),
        }
        Ok(self.entries.keys().cloned().collect())
    }

    fn validate_native_flat_retirement_shape(&self) -> Result<(), Response> {
        if self.native_flat_retirement_format != Some(1)
            || self.next_incarnation.is_empty()
            || self.deletions.is_some()
            || !self.retired_custody.is_empty()
            || !self.custody_frontiers.is_empty()
            || !self.closed_auth_routes.is_empty()
            || !self.workflows.is_empty()
            || self
                .next_incarnation
                .iter()
                .any(|(path, next)| !valid_segment(path) || *next < 2)
            || self.entries.iter().any(|(path, entry)| {
                !valid_segment(path)
                    || entry.custody.is_some()
                    || entry.inherited.is_some()
                    || entry.sealed
                    || if entry.incarnation == 1 {
                        self.next_incarnation.contains_key(path)
                    } else {
                        entry.incarnation == 0
                            || self
                                .next_incarnation
                                .get(path)
                                .is_none_or(|next| *next <= entry.incarnation)
                    }
            })
        {
            return Err(invalid());
        }
        let actual = self.batch_lifecycle.as_ref().ok_or_else(invalid)?;
        if !actual.native_v6_flat_incarnation_profile() {
            return Err(invalid());
        }
        Ok(())
    }
}

impl State {
    /// Called for cold readers, publication and before any snapshot writer
    /// normalization. Both the actual catalog and paired Auth ledger remain
    /// exact; prior retirement frontiers can never disappear or decrease.
    pub(in crate::service) fn validate_native_flat_retirement_state(
        &self,
        previous: Option<&Self>,
    ) -> Result<(), Response> {
        let present = self.namespaces.has_native_flat_retirement_state();
        let tree = self.namespaces.has_native_plain_tree_state();
        if (present && self.schema < NATIVE_FLAT_NAMESPACE_RETIREMENT_STATE_SCHEMA)
            || (self.schema == NATIVE_FLAT_NAMESPACE_RETIREMENT_STATE_SCHEMA && !present)
            || (tree && self.schema < NATIVE_PLAIN_NAMESPACE_TREE_STATE_SCHEMA)
            || (self.schema == NATIVE_PLAIN_NAMESPACE_TREE_STATE_SCHEMA && !tree)
            || previous.is_some_and(|old| {
                old.namespaces.has_native_flat_retirement_state() && !present
                    || old.schema >= NATIVE_FLAT_NAMESPACE_RETIREMENT_STATE_SCHEMA
                        && self.schema < NATIVE_FLAT_NAMESPACE_RETIREMENT_STATE_SCHEMA
                    || old.namespaces.has_native_plain_tree_state() && !tree
                    || old.schema >= NATIVE_PLAIN_NAMESPACE_TREE_STATE_SCHEMA
                        && self.schema < NATIVE_PLAIN_NAMESPACE_TREE_STATE_SCHEMA
            })
        {
            return Err(invalid());
        }
        if !present {
            return Ok(());
        }
        if self.namespace_protected.is_some() || !self.namespace_leases.is_empty() {
            return Err(invalid());
        }
        self.namespaces.validate(&self.cluster_id)?;
        if tree {
            self.namespaces.validate_native_plain_tree_shape()?;
        } else {
            self.namespaces.validate_native_flat_retirement_shape()?;
        }
        self.validate_namespace_batch_state()?;
        let actual = self
            .namespaces
            .batch_lifecycle
            .as_ref()
            .ok_or_else(invalid)?;
        let expected = crate::auth::batch_namespace::Registry::adopt_visible(
            &self.cluster_id,
            self.namespaces
                .entries
                .iter()
                .map(|(path, entry)| (path.clone(), entry.incarnation))
                .collect(),
            self.namespaces.next_incarnation.clone(),
        )
        .map_err(|_| invalid())?;
        if actual != &expected {
            return Err(invalid());
        }
        if let Some(old) = previous {
            if old.cluster_id != self.cluster_id
                || old
                    .namespaces
                    .next_incarnation
                    .iter()
                    .any(|(path, frontier)| {
                        self.namespaces
                            .next_incarnation
                            .get(path)
                            .is_none_or(|next| next < frontier)
                    })
            {
                return Err(invalid());
            }
            if let Some(prior) = old.namespaces.batch_lifecycle.as_ref() {
                actual.validate_successor(prior).map_err(|_| invalid())?;
            }
        }
        Ok(())
    }
}

#[cfg(all(test, feature = "native-v6-storage"))]
#[path = "service_native_flat_retirement_tests.rs"]
mod tests;
