#![forbid(unsafe_code)]
#![deny(missing_debug_implementations)]

//! Durable migration writer authority and fail-closed reconciliation.
//!
//! Migration transitions are intentionally exposed only by
//! [`DurableMigrationJournal`]. A process-local phase model cannot fence an
//! OpenBao source, persist an intent, or prove a target write, so this crate
//! does not provide one as a usable API.

// The durable filesystem profile is Linux-only. In non-Linux test builds the
// production API is still compiled and the unsupported-platform path is tested,
// while Linux-only test helpers are intentionally unreferenced.
#[cfg_attr(all(test, not(target_os = "linux")), allow(dead_code))]
mod durable;
pub use durable::*;

/// Compatibility marker for callers that used the removed in-memory model.
///
/// This type is deliberately unconstructable. Keeping a deprecated symbol
/// for one release gives downstream code a diagnostic migration path without
/// leaving a model API that can claim writer authority without the durable
/// journal. Use [`DurableMigrationJournal`] instead.
#[doc(hidden)]
#[deprecated(
    since = "0.1.0",
    note = "the process-local migration model cannot authorize migration; use DurableMigrationJournal"
)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MigrationState {
    _private: (),
}

/// Error returned by the removed process-local migration compatibility marker.
#[doc(hidden)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[deprecated(
    since = "0.1.0",
    note = "use MigrationJournalError from DurableMigrationJournal"
)]
pub enum MigrationError {
    DurableJournalRequired,
}

#[allow(deprecated)]
impl std::fmt::Display for MigrationError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(
            "durable migration journal is required; process-local migration state is unavailable",
        )
    }
}

#[allow(deprecated)]
impl std::error::Error for MigrationError {}

#[allow(deprecated)]
impl MigrationState {
    /// Always fails: migration authority must be established durably.
    #[deprecated(
        since = "0.1.0",
        note = "the process-local migration model was removed; use DurableMigrationJournal"
    )]
    pub fn new(
        _migration_id: heptabao_domain::Id,
        _source_id: heptabao_domain::Id,
        _target_id: heptabao_domain::Id,
    ) -> Result<Self, MigrationError> {
        Err(MigrationError::DurableJournalRequired)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[allow(deprecated)]
    #[test]
    fn process_local_model_is_unavailable_and_requires_durable_journal()
    -> Result<(), Box<dyn std::error::Error>> {
        let migration = heptabao_domain::Id::parse("migration-one")?;
        let source = heptabao_domain::Id::parse("openbao-source")?;
        let target = heptabao_domain::Id::parse("heptabao-target")?;
        assert!(matches!(
            MigrationState::new(migration, source, target),
            Err(MigrationError::DurableJournalRequired)
        ));
        Ok(())
    }
}
