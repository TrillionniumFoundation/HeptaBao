//! Pure V6 root comparison; operation ownership and refusal mapping stay with each caller.
use super::{EngineError, Result};
use crate::state_record_root_v6::{OwnerDomain, RecordStateRootV6};

pub(super) fn only_owners_changed(
    prior: &RecordStateRootV6,
    next: &RecordStateRootV6,
    roles: &[OwnerDomain],
    rejected: fn() -> EngineError,
) -> Result<()> {
    prior.validate().map_err(|_| rejected())?;
    next.validate().map_err(|_| rejected())?;
    if next.state_schema < prior.state_schema
        || next.reader_floor.minimum_state_schema < prior.reader_floor.minimum_state_schema
    {
        return Err(rejected());
    }
    let mut normalized = next.clone();
    normalized.state_schema = prior.state_schema;
    normalized.reader_floor.minimum_state_schema = prior.reader_floor.minimum_state_schema;
    for (old, new) in prior.owners.iter().zip(&mut normalized.owners) {
        if old.domain == new.domain && roles.contains(&old.domain) {
            *new = old.clone();
        }
    }
    (prior.encode().map_err(|_| rejected())?.as_slice()
        == normalized.encode().map_err(|_| rejected())?.as_slice())
    .then_some(())
    .ok_or_else(rejected)
}
