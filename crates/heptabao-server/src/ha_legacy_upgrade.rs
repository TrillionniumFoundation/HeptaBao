//! Explicit historical publication; normal publication never uses this fallback.
use super::*;
use crate::service::legacy_upgrade_wire::Candidate;
pub(crate) enum LegacyCommitError {
    BeforeProposal,
    ProposalUncertain,
}
impl HaProcess {
    pub(crate) fn commit_legacy_upgrade_whole(
        &self,
        operation_id: &str,
        candidate: &Candidate,
        binding: OwnerPublicationBinding,
    ) -> Result<CommitReceipt, LegacyCommitError> {
        candidate
            .live()
            .map_err(|_| LegacyCommitError::BeforeProposal)?;
        let bytes = candidate.bytes();
        if !self.emit_legacy_peer_v1
            || candidate.cluster_id() != self.cluster_id
            || bytes.is_empty()
            || bytes.len() > crate::service::legacy_upgrade_wire::OLD_STATE_LIMIT
        {
            return Err(LegacyCommitError::BeforeProposal);
        }
        validate_owner_binding(operation_id, bytes, binding)
            .map_err(|_| LegacyCommitError::BeforeProposal)?;
        let node = self
            .node
            .as_ref()
            .ok_or(LegacyCommitError::BeforeProposal)?;
        if self.runtime.block_on(node.current_leader()) != Some(node.id()) {
            return Err(LegacyCommitError::BeforeProposal);
        }
        self.block_on_read(node.ensure_linearizable())
            .map_err(|_| LegacyCommitError::BeforeProposal)?;
        if self
            .runtime
            .block_on(node.record_root_at_generation())
            .map_err(|_| LegacyCommitError::BeforeProposal)?
            .1
            .is_some()
        {
            return Err(LegacyCommitError::BeforeProposal);
        }
        let previous = self
            .runtime
            .block_on(node.latest_envelope())
            .map_err(|_| LegacyCommitError::BeforeProposal)?
            .ok_or(LegacyCommitError::BeforeProposal)?;
        let CommittedStateDescriptor::Legacy(opened) = self
            .codec
            .open_committed_descriptor(
                previous.operation_id(),
                previous.digest(),
                previous.sealed(),
            )
            .map_err(|_| LegacyCommitError::BeforeProposal)?
        else {
            return Err(LegacyCommitError::BeforeProposal);
        };
        if previous.digest() != candidate.base_digest()
            || sha256(&opened) != candidate.base_digest()
        {
            return Err(LegacyCommitError::BeforeProposal);
        }
        let proposal = self
            .codec
            .seal(operation_id.to_owned(), candidate.base_digest(), bytes)
            .map_err(|_| LegacyCommitError::BeforeProposal)?;
        let envelope = ReplicatedEnvelope::new(
            proposal.operation_id().to_owned(),
            proposal.digest(),
            proposal.sealed().to_vec(),
        )
        .map_err(|_| LegacyCommitError::BeforeProposal)?;
        candidate
            .live()
            .map_err(|_| LegacyCommitError::BeforeProposal)?;
        let serial = self
            .runtime
            .block_on(node.next_production_client_serial())
            .map_err(|_| LegacyCommitError::BeforeProposal)?;
        let receipt = self
            .runtime
            .block_on(node.replicate(serial, &envelope))
            .map_err(|_| LegacyCommitError::ProposalUncertain)?;
        #[cfg(test)]
        let receipt = {
            let mut receipt = receipt;
            LEGACY_BAD_RECEIPT.with(|bad| {
                if bad.replace(false) {
                    receipt.envelope_digest[0] ^= 1;
                }
            });
            receipt
        };
        if receipt.leader_id != node.id() || receipt.envelope_digest != proposal.digest() {
            return Err(LegacyCommitError::ProposalUncertain);
        }
        Ok(receipt)
    }
}

#[cfg(test)]
impl HaProcess {
    pub(crate) fn seed_legacy_upgrade_fixture(&self, bytes: &[u8]) -> Result<(), String> {
        let node = self.node.as_ref().ok_or("node")?;
        if self
            .runtime
            .block_on(node.latest_envelope())
            .map_err(|e| e.to_string())?
            .is_some()
            || self
                .runtime
                .block_on(node.record_root_at_generation())
                .map_err(|e| e.to_string())?
                .1
                .is_some()
        {
            return Err("fixture requires actual empty application".into());
        }
        let proposal = self
            .codec
            .seal("legacy-seed-fixture", [0; 32], bytes)
            .map_err(|e| e.to_string())?;
        let envelope = ReplicatedEnvelope::new(
            proposal.operation_id().to_owned(),
            proposal.digest(),
            proposal.sealed().to_vec(),
        )
        .map_err(|e| e.to_string())?;
        let serial = self
            .runtime
            .block_on(node.next_production_client_serial())
            .map_err(|e| e.to_string())?;
        self.runtime
            .block_on(node.replicate(serial, &envelope))
            .map_err(|e| e.to_string())?;
        Ok(())
    }
}

#[cfg(test)]
thread_local! { static LEGACY_BAD_RECEIPT: std::cell::Cell<bool> = const {std::cell::Cell::new(false)}; }
#[cfg(test)]
impl HaProcess {
    pub(crate) fn reject_next_legacy_receipt_for_test() {
        LEGACY_BAD_RECEIPT.with(|bad| bad.set(true));
    }
}
