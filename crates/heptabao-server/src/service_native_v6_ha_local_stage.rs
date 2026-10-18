//! Rewrap a received, fully typed V6 object into this node's actual barrier.
//!
//! This child owns no locator journal, cursor, root publication or response ACK.
//! Its only input object is a temporary borrow minted by the complete Service
//! closure reader. The reader's original Actor/deadline survives every local
//! crypto/filesystem gate; the target gate adds custody and never replaces it.
use super::*;
use crate::service::native_v6_ha_objects::VerifiedNativeV6Object;

pub(in crate::service) fn stage_verified_received(
    durable: &mut DurableService<AeadBarrier>,
    session: &ImmutableSourceSession,
    object: &VerifiedNativeV6Object<'_>,
    target_gate: &mut impl FnMut() -> Result<(), ServiceError>,
) -> Result<Secret, ServiceError> {
    let mut before = || {
        object
            .check_original()
            .map_err(|_| ServiceError::BarrierFailure)?;
        target_gate()?;
        object
            .check_original()
            .map_err(|_| ServiceError::BarrierFailure)
    };
    before()?;
    let reference = object.reference();
    let plaintext = object.plaintext();
    if session.replay_epoch() != object.root().replay_epoch
        || session.store_id() != store_id(object.root_bytes())?
        || plaintext.len() != reference.encoded_bytes as usize
    {
        return Err(ServiceError::PublicationConditionConflict);
    }
    // The target must already select a root in this same actual cluster. A
    // physical session for an unrelated resource/store cannot substitute for
    // the target Service's selected root. Its exact generation, replay epoch
    // and owner-instance are rechecked by every DurableService operation.
    let selected = durable
        .get("system", "state")?
        .ok_or(ServiceError::CorruptState)?;
    before()?;
    if store_id(selected.expose())? != session.store_id() {
        return Err(ServiceError::PublicationConditionConflict);
    }
    let locator = BlobLocator::new(session.store_id(), *reference.id.bytes())
        .map_err(|_| ServiceError::CorruptState)?;
    let aad = context(object.domain(), reference);
    let resource = v6_records::native_resource(object.domain(), reference);
    let mut registered = None;
    if let Some(stored) = durable.get("system", &resource)? {
        before()?;
        if stored.expose().starts_with(MAGIC) {
            let slot =
                Slot::decode(stored.expose(), reference).map_err(|_| ServiceError::CorruptState)?;
            // This concrete owner is AeadBarrier's HBA1: four-byte magic,
            // twelve-byte nonce and sixteen-byte tag. A changed locator length
            // cannot be legitimized by repairing a missing physical file.
            if slot.locator != locator
                || slot.plaintext_bytes != plaintext.len()
                || Some(slot.ciphertext_bytes) != plaintext.len().checked_add(32)
            {
                return Err(ServiceError::CorruptState);
            }
            registered = Some(stored);
        } else if stored.expose() != plaintext {
            return Err(ServiceError::RequestBindingConflict);
        }
        // Existing format-1 inline records gain no new authority. Rewrap uses
        // the fresh verified plaintext and still leaves the journal untouched.
    }
    before()?;
    // The real durable owner seals with its local barrier, checks every write,
    // fsync/link/directory boundary, and reopens the selected file through AEAD
    // with exact plaintext equality. A same-address orphan from an interrupted
    // earlier attempt is therefore reusable only after fresh authentication.
    // A registered but missing file is repaired with the same no-replace write;
    // an existing corrupt file is authenticated and rejected, never overwritten.
    let pin = durable.stage_immutable_object_before_publish(
        session,
        locator,
        &aad,
        plaintext,
        &mut before,
    )?;
    before()?;
    let result = Slot {
        locator,
        ciphertext_bytes: pin.ciphertext_len(),
        plaintext_bytes: plaintext.len(),
    }
    .encode()?;
    before()?;
    if registered.is_some_and(|stored| stored.expose() != result.expose()) {
        return Err(ServiceError::RequestBindingConflict);
    }
    Ok(result)
}

#[cfg(test)]
#[path = "service_native_v6_ha_local_stage_tests.rs"]
pub(in crate::service) mod tests;
