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
    stage_received(durable, session, object, None, target_gate)
}

fn stage_received(
    durable: &mut DurableService<AeadBarrier>,
    session: &ImmutableSourceSession,
    object: &VerifiedNativeV6Object<'_>,
    epoch_scope: Option<&crate::service::native_v6_ha_install::EpochInstallScope<'_>>,
    target_gate: &mut impl FnMut() -> Result<(), ServiceError>,
) -> Result<Secret, ServiceError> {
    let mut before = || {
        object
            .check_original()
            .map_err(|_| ServiceError::BarrierFailure)?;
        target_gate()?;
        if let Some(scope) = epoch_scope {
            scope.check_received(session, object)?;
        }
        object
            .check_original()
            .map_err(|_| ServiceError::BarrierFailure)
    };
    before()?;
    let reference = object.reference();
    let plaintext = object.plaintext();
    if (epoch_scope.is_none() && session.replay_epoch() != object.root().replay_epoch)
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
    // HBA1 has an exact 32-byte overhead; a generic Barrier's length bound is
    // not an exact ciphertext length. Existing physical leaves are synced on
    // their actual descriptor and directory, then opened with this local
    // barrier and compared to the fresh typed borrow. Only initial absence
    // takes the ordinary seal/no-replace write path. A changed or corrupt leaf
    // cannot be repaired by overwriting it, even when a locator is registered.
    let exact_ciphertext_bytes = plaintext
        .len()
        .checked_add(32)
        .ok_or(ServiceError::RequestCapacityExhausted)?;
    let pin = durable.stage_immutable_object_reusing_existing_before_publish(
        session,
        locator,
        exact_ciphertext_bytes,
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

/// Stage one bounded group from exactly one current typed visitor. Existing
/// leaves retain the original independent actual-fd reuse path; only absent
/// leaves share the physical barrier. Locator/root publication stays outside.
pub(in crate::service) fn stage_verified_received_batch(
    durable: &mut DurableService<AeadBarrier>,
    session: &ImmutableSourceSession,
    objects: &[VerifiedNativeV6Object<'_>],
    epoch_scope: Option<&crate::service::native_v6_ha_install::EpochInstallScope<'_>>,
    target_gate: &mut impl FnMut() -> Result<(), ServiceError>,
) -> Result<Vec<Secret>, ServiceError> {
    if objects.is_empty() || objects.len() > heptabao_filesystem_guard::MAX_IMMUTABLE_BATCH_OBJECTS
    {
        return Err(ServiceError::RequestCapacityExhausted);
    }
    #[cfg(test)]
    let prepare_timing = crate::ha::NativeV6TimingSpan::start("local_stage_batch", "prepare", None);
    let first = &objects[0];
    for object in objects {
        object
            .check_original()
            .map_err(|_| ServiceError::BarrierFailure)?;
        if !object.shares_visitor_with(first) {
            return Err(ServiceError::PublicationConditionConflict);
        }
    }
    // The immutable shared root and exactly identical original gate are proven
    // above. This one common gate retains both real Actor checks and target
    // custody at every original crypto/physical boundary for every member.
    let mut before = || {
        first
            .check_original()
            .map_err(|_| ServiceError::BarrierFailure)?;
        target_gate()?;
        if let Some(scope) = epoch_scope {
            scope.check_received(session, first)?;
        }
        first
            .check_original()
            .map_err(|_| ServiceError::BarrierFailure)
    };
    // Timing observes the unchanged callback, once per original invocation.
    // No source check, target check, epoch check or deadline is replaced.
    #[cfg(test)]
    let mut before = || {
        crate::ha::observe_native_v6_timing("local_stage_batch", "original_gate", None, &mut before)
    };
    before()?;
    if (epoch_scope.is_none() && session.replay_epoch() != first.root().replay_epoch)
        || session.store_id() != store_id(first.root_bytes())?
    {
        return Err(ServiceError::PublicationConditionConflict);
    }
    let selected = durable
        .get("system", "state")?
        .ok_or(ServiceError::CorruptState)?;
    before()?;
    if store_id(selected.expose())? != session.store_id() {
        return Err(ServiceError::PublicationConditionConflict);
    }

    let mut prepared = Vec::with_capacity(objects.len());
    for object in objects {
        before()?;
        let reference = object.reference();
        let plaintext = object.plaintext();
        if plaintext.len() != reference.encoded_bytes as usize {
            return Err(ServiceError::PublicationConditionConflict);
        }
        let locator = BlobLocator::new(session.store_id(), *reference.id.bytes())
            .map_err(|_| ServiceError::CorruptState)?;
        let aad = context(object.domain(), reference);
        let resource = v6_records::native_resource(object.domain(), reference);
        let exact_len = plaintext
            .len()
            .checked_add(32)
            .ok_or(ServiceError::RequestCapacityExhausted)?;
        let mut registered = None;
        if let Some(stored) = durable.get("system", &resource)? {
            before()?;
            if stored.expose().starts_with(MAGIC) {
                let slot = Slot::decode(stored.expose(), reference)
                    .map_err(|_| ServiceError::CorruptState)?;
                if slot.locator != locator
                    || slot.plaintext_bytes != plaintext.len()
                    || slot.ciphertext_bytes != exact_len
                {
                    return Err(ServiceError::CorruptState);
                }
                registered = Some(stored);
            } else if stored.expose() != plaintext {
                return Err(ServiceError::RequestBindingConflict);
            }
        }
        before()?;
        prepared.push((locator, exact_len, aad, registered));
    }
    let inputs: Vec<_> = prepared
        .iter()
        .zip(objects)
        .map(|((locator, exact_len, aad, _), object)| {
            (*locator, *exact_len, aad.as_slice(), object.plaintext())
        })
        .collect();
    #[cfg(test)]
    if let Some(timing) = prepare_timing {
        timing.finish(true);
    }
    #[cfg(test)]
    let durable_timing =
        crate::ha::NativeV6TimingSpan::start("local_stage_batch", "durable_reuse_or_stage", None);
    let pins = durable.stage_immutable_objects_reusing_existing_before_publish(
        session,
        &inputs,
        &mut before,
    )?;
    #[cfg(test)]
    if let Some(timing) = durable_timing {
        timing.finish(true);
    }
    before()?;
    if pins.len() != objects.len() {
        return Err(ServiceError::CorruptState);
    }
    let mut markers = Vec::with_capacity(objects.len());
    for ((pin, (locator, exact_len, _, registered)), object) in
        pins.into_iter().zip(prepared).zip(objects)
    {
        before()?;
        if pin.locator() != locator || pin.ciphertext_len() != exact_len {
            return Err(ServiceError::CorruptState);
        }
        let marker = Slot {
            locator,
            ciphertext_bytes: pin.ciphertext_len(),
            plaintext_bytes: object.plaintext().len(),
        }
        .encode()?;
        before()?;
        if registered.is_some_and(|stored| stored.expose() != marker.expose()) {
            return Err(ServiceError::RequestBindingConflict);
        }
        markers.push(marker);
    }
    before()?;
    Ok(markers)
}

#[cfg(test)]
#[path = "service_native_v6_ha_local_stage_tests.rs"]
pub(in crate::service) mod tests;
