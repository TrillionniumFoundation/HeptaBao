//! Bounded local import staging through the existing physical batch barrier.
//! Registered leaves retain the ordinary fresh authenticated read path.
//! This helper publishes no locator, cursor or root.
use super::*;

pub(in crate::service) fn stage_batch(
    durable: &mut DurableService<AeadBarrier>,
    session: &ImmutableSourceSession,
    objects: &[(&ObjectDomain, &StagedObject)],
    before: &mut impl FnMut() -> Result<(), ServiceError>,
) -> Result<Vec<Secret>, ServiceError> {
    before()?;
    if objects.is_empty() || objects.len() > heptabao_filesystem_guard::MAX_IMMUTABLE_BATCH_OBJECTS
    {
        return Err(ServiceError::RequestCapacityExhausted);
    }
    let mut markers = (0..objects.len())
        .map(|_| None)
        .collect::<Vec<Option<Secret>>>();
    let mut pending = Vec::new();
    let mut total_bytes = 0usize;
    for (index, (domain, object)) in objects.iter().enumerate() {
        before()?;
        let reference = object.reference();
        if object.bytes().len() != reference.encoded_bytes as usize {
            return Err(ServiceError::CorruptState);
        }
        let locator = BlobLocator::new(session.store_id(), *reference.id.bytes())
            .map_err(|_| ServiceError::CorruptState)?;
        let exact_len = object
            .bytes()
            .len()
            .checked_add(32)
            .ok_or(ServiceError::RequestCapacityExhausted)?;
        total_bytes = total_bytes
            .checked_add(exact_len)
            .filter(|n| *n <= ImmutableSourceSession::MAX_BATCH_CIPHERTEXT_BYTES)
            .ok_or(ServiceError::RequestCapacityExhausted)?;
        let resource = v6_records::native_resource(domain, reference);
        if let Some(stored) = durable.get("system", &resource)? {
            before()?;
            if stored.expose().starts_with(MAGIC) {
                // The ordinary adapter checks the exact slot, current source,
                // actual pin and fresh local AEAD plaintext equality.
                markers[index] = Some(stage(durable, session, domain, object, before)?);
                continue;
            }
            if stored.expose() != object.bytes() {
                return Err(ServiceError::RequestBindingConflict);
            }
        }
        pending.push((index, locator, exact_len, context(domain, reference)));
    }
    before()?;
    if !pending.is_empty() {
        let inputs = pending
            .iter()
            .map(|(index, locator, length, aad)| {
                (*locator, *length, aad.as_slice(), objects[*index].1.bytes())
            })
            .collect::<Vec<_>>();
        // This owner is AeadBarrier/HBA1 with exactly 32 bytes of overhead.
        // The existing API checks every member, keeps the original gate at all
        // physical boundaries, fsyncs the real descriptors and directory, and
        // authenticates every readback before returning any pin. An orphan is
        // reusable only through that same byte-for-byte authenticated proof.
        let pins = durable
            .stage_immutable_objects_reusing_existing_before_publish(session, &inputs, before)?;
        before()?;
        if pins.len() != pending.len() {
            return Err(ServiceError::CorruptState);
        }
        for (pin, (index, locator, exact_len, _)) in pins.into_iter().zip(pending) {
            before()?;
            if pin.locator() != locator || pin.ciphertext_len() != exact_len {
                return Err(ServiceError::CorruptState);
            }
            markers[index] = Some(
                Slot {
                    locator,
                    ciphertext_bytes: exact_len,
                    plaintext_bytes: objects[index].1.bytes().len(),
                }
                .encode()?,
            );
            #[cfg(test)]
            note_staging_outcome(false);
        }
    }
    before()?;
    markers
        .into_iter()
        .map(|marker| marker.ok_or(ServiceError::CorruptState))
        .collect()
}
