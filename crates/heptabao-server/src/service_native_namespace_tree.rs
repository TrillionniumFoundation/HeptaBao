//! Schema 145 retains a complete ordinary namespace tree and its actual
//! incarnation ledger. The format marker is a reader capability, not an
//! authentication, publication or independent-custody capability.
use super::*;

fn invalid() -> Response {
    Response::error(503, "native namespace tree custody is invalid")
}

fn canonical_key(path: &str) -> bool {
    canonical_path(path).is_ok_and(|canonical| canonical == path)
}

impl NamespaceRegistry {
    pub(in crate::service) fn has_native_plain_tree_state(&self) -> bool {
        self.native_flat_retirement_format == Some(2)
    }

    /// Format 2 never treats a partial catalog as the complete tree. Active
    /// ancestors must be visible; retired descendants remain in the frontier
    /// even after their last active ancestor has been removed.
    pub(super) fn validate_native_plain_tree_shape(&self) -> Result<(), Response> {
        if !self.has_native_plain_tree_state()
            || self.batch_lifecycle.is_none()
            || self.deletions.is_some()
            || !self.retired_custody.is_empty()
            || !self.custody_frontiers.is_empty()
            || !self.closed_auth_routes.is_empty()
            || !self.workflows.is_empty()
            || self
                .next_incarnation
                .iter()
                .any(|(path, next)| !canonical_key(path) || *next < 2)
            || self.entries.iter().any(|(path, entry)| {
                !canonical_key(path)
                    || entry.incarnation == 0
                    || entry.custody.is_some()
                    || entry.inherited.is_some()
                    || entry.sealed
                    || if entry.incarnation == 1 {
                        self.next_incarnation.contains_key(path)
                    } else {
                        self.next_incarnation
                            .get(path)
                            .is_none_or(|next| *next <= entry.incarnation)
                    }
            })
        {
            return Err(invalid());
        }
        for path in self.entries.keys() {
            let mut parent = parent_path(path);
            while !parent.is_empty() {
                if !self.entries.contains_key(parent) {
                    return Err(invalid());
                }
                parent = parent_path(parent);
            }
        }
        // State validation independently requires equality with adopt_visible
        // and with Auth's paired ledger. No hidden owner is normalized here.
        Ok(())
    }
}

#[cfg(all(test, feature = "native-v6-storage"))]
#[path = "service_native_namespace_tree_tests.rs"]
mod tests;
