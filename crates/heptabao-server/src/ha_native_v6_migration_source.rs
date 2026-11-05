//! Historical V5 provenance owned by the same actual native quorum selection.
//! No ordinary V5 read cursor or application witness is minted here.
use super::*;
use crate::ha_state::runtime_reference;
use crate::state_record_root::{RecordStateRoot, StateIdentity};

/// Only the real HaProcess decoder can construct this owner. Its borrow keeps
/// the original native selection, store instance and deadline alive throughout
/// local predecessor recovery; neither serialized roots nor callers mint it.
pub(crate) struct NativeV6MigrationSource<'a> {
    selected: &'a CommittedNativeV6Read,
    root: RecordStateRoot,
    bytes: Zeroizing<Vec<u8>>,
}

impl NativeV6MigrationSource<'_> {
    pub(crate) fn root(&self) -> &RecordStateRoot {
        &self.root
    }
    pub(crate) fn bytes(&self) -> &[u8] {
        &self.bytes
    }
    pub(crate) fn check(&self, process: &HaProcess) -> Result<(), String> {
        process.verify_native_v6_committed_read(self.selected)
    }
}

impl HaProcess {
    pub(crate) fn native_v6_retained_migration_source<'a>(
        &self,
        selected: &'a CommittedNativeV6Read,
    ) -> Result<NativeV6MigrationSource<'a>, String> {
        self.verify_native_v6_committed_read(selected)?;
        let node = self.node.as_ref().ok_or("HA process is shut down")?;
        let published = self.block_on_observed(node.native_v6_retained_migration_source(&selected.selected))
            .map_err(|error| error.to_string())?;
        let envelope = published.envelope();
        let CommittedStateDescriptor::RecordsV5(decoded) = self
            .codec
            .open_committed_descriptor(
                envelope.operation_id(),
                envelope.digest(),
                envelope.sealed(),
            )
            .map_err(|error| error.to_string())?
        else {
            return Err("native migration predecessor kind mismatch".into());
        };
        if decoded.base != published.base()
            || decoded
                .root
                .references()
                .map(runtime_reference)
                .collect::<Vec<_>>()
                != published.direct_refs()
            || decoded.root.cluster_id != self.cluster_id
            || decoded.root.replay_epoch != selected.published().native_origin_epoch()
            || decoded
                .root
                .identity()
                .map_err(|_| "native predecessor identity invalid")?
                != StateIdentity::RecordsV5(selected.published().migration_source().0)
            || envelope.digest() != selected.published().migration_source().0
            || decoded
                .root
                .encode()
                .map_err(|_| "native predecessor encoding invalid")?
                .as_slice()
                != decoded.bytes.as_slice()
        {
            return Err("native migration predecessor does not match committed provenance".into());
        }
        self.verify_native_v6_committed_read(selected)?;
        Ok(NativeV6MigrationSource {
            selected,
            root: decoded.root,
            bytes: decoded.bytes,
        })
    }
}
