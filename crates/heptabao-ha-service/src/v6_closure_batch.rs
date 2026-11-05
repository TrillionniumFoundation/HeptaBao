//! Legacy frames retain their three-leaf contract. Explicit packed-stage
//! frames carry at most twelve independently authenticated leaves within the
//! SAME original ciphertext-frame byte limit.
//! Pure-reference Ensure frames have a separate small bound: they carry no
//! ciphertext. The leaf and fsync boundaries and final whole-closure fsync
//! gate remain mandatory for every reference.
use super::*;

pub(super) const OBJECTS: usize = 3;
pub(super) const MAX_PAYLOAD: usize = 1 + OBJECTS * (36 + wire::MAX_CIPHERTEXT);
pub(super) const MAX_ACK: usize = 1 + OBJECTS * 36;
// This is a distinct wire kind, not an expansion of legacy StageBatch.
// A new leaf retains temporary, published and Darwin watch descriptors.
// Twelve keeps this path to 36 object descriptors per receiver; the
// lower storage layer's 32-object cap is not a process-wide FD budget.
// This revises the never-deployed experimental kind 8 from its eight-leaf
// candidate. Peers must run the same revision; there is no mutation fallback.
pub(super) const PACKED_OBJECTS: usize = 12;
pub(super) const MAX_PACKED_ACK: usize = 1 + PACKED_OBJECTS * 36;
const _: () = assert!(PACKED_OBJECTS <= LocalV6BlobStage::MAX_CHECKED_BATCH_OBJECTS);
pub(super) const ENSURE_OBJECTS: usize = 64;
pub(super) const MAX_ENSURE_PAYLOAD: usize = 1 + ENSURE_OBJECTS * 36;

pub(super) fn expected(references: &[RecordObjectRef]) -> Result<Vec<u8>, HaError> {
    reference_payload(references, OBJECTS)
}

pub(super) fn packed_expected(references: &[RecordObjectRef]) -> Result<Vec<u8>, HaError> {
    packed_payload_length(references)?;
    reference_payload(references, PACKED_OBJECTS)
}

// Check the complete reference set and exact encoded byte budget before
// any source read or receiver publication. A small count is not a byte cap.
fn packed_payload_length(references: &[RecordObjectRef]) -> Result<usize, HaError> {
    let _ = reference_payload(references, PACKED_OBJECTS)?;
    references.iter().try_fold(1usize, |bytes, reference| {
        bytes
            .checked_add(36)
            .and_then(|value| value.checked_add(reference.encoded_bytes as usize))
            .filter(|value| *value <= MAX_PAYLOAD)
            .ok_or(HaError::InvalidFrame)
    })
}

/// Partition only one authenticated Ensure subset. References and their
/// order are preserved; there is no I/O, retry, or new operation clock.
/// First minimize batch-wide barriers, then the current storage implementation's
/// four-worker pre/post-sync waves. Equal costs take the longest first batch.
/// This chooses a bounded work shape; it does not predict a deadline result.
pub(super) fn packed_batches(
    references: &[RecordObjectRef],
) -> Result<Vec<&[RecordObjectRef]>, HaError> {
    if references.is_empty() {
        return Ok(Vec::new());
    }
    let _ = ensure_expected(references)?;
    // ensure_expected validated the complete ordered set and its <=64 bound
    // before any array indexing. At most 65 states and 64*12 intervals exist.
    let count = references.len();
    let mut best: [Option<(usize, usize, usize)>; ENSURE_OBJECTS + 1] = [None; ENSURE_OBJECTS + 1];
    best[count] = Some((0, 0, count));
    for start in (0..count).rev() {
        let mut bytes = 1usize;
        for (offset, reference) in references[start..].iter().take(PACKED_OBJECTS).enumerate() {
            let stop = start + offset + 1;
            bytes = bytes
                .checked_add(36)
                .and_then(|value| value.checked_add(reference.encoded_bytes as usize))
                .ok_or(HaError::InvalidFrame)?;
            if bytes > MAX_PAYLOAD {
                break;
            }
            let suffix = best[stop].ok_or(HaError::InvalidFrame)?;
            let cost = (1 + suffix.0, (stop - start).div_ceil(4) + suffix.1);
            if best[start].is_none_or(|prior| {
                cost < (prior.0, prior.1) || (cost == (prior.0, prior.1) && stop > prior.2)
            }) {
                best[start] = Some((cost.0, cost.1, stop));
            }
        }
    }
    let mut batches = Vec::new();
    let mut start = 0usize;
    while start < count {
        let stop = best[start].ok_or(HaError::InvalidFrame)?.2;
        if stop <= start || stop > count {
            return Err(HaError::InvalidFrame);
        }
        batches.push(&references[start..stop]);
        start = stop;
    }
    Ok(batches)
}

pub(super) fn ensure_expected(references: &[RecordObjectRef]) -> Result<Vec<u8>, HaError> {
    reference_payload(references, ENSURE_OBJECTS)
}

fn reference_payload(references: &[RecordObjectRef], maximum: usize) -> Result<Vec<u8>, HaError> {
    if references.is_empty() || references.len() > maximum {
        return Err(HaError::InvalidFrame);
    }
    let mut bytes = vec![u8::try_from(references.len()).map_err(|_| HaError::InvalidFrame)?];
    let mut prior = None;
    for reference in references {
        if prior.is_some_and(|id| id >= reference.id) {
            return Err(HaError::InvalidFrame);
        }
        prior = Some(reference.id);
        bytes.extend_from_slice(&wire::reference_payload(reference)?);
    }
    Ok(bytes)
}

pub(super) fn payload(
    source: &LocalV6BlobStage,
    references: &[RecordObjectRef],
    transfer: bool,
    deadline: Instant,
) -> Result<Vec<u8>, HaError> {
    payload_bounded(source, references, transfer, OBJECTS, deadline)
}

pub(super) fn packed_payload(
    source: &LocalV6BlobStage,
    references: &[RecordObjectRef],
    deadline: Instant,
) -> Result<Vec<u8>, HaError> {
    packed_payload_length(references)?;
    payload_bounded(source, references, true, PACKED_OBJECTS, deadline)
}

fn payload_bounded(
    source: &LocalV6BlobStage,
    references: &[RecordObjectRef],
    transfer: bool,
    maximum: usize,
    deadline: Instant,
) -> Result<Vec<u8>, HaError> {
    let _ = reference_payload(references, maximum)?;
    check_deadline(deadline)?;
    let mut bytes = Vec::with_capacity(if transfer { MAX_PAYLOAD } else { MAX_ACK });
    bytes.push(references.len() as u8);
    for reference in references {
        bytes.extend_from_slice(&wire::reference_payload(reference)?);
        if transfer {
            let ciphertext = source.read_local(reference).map_err(|_| unknown())?;
            check_deadline(deadline)?;
            bytes.extend_from_slice(&ciphertext);
        }
    }
    check_deadline(deadline)?;
    if bytes.len() > MAX_PAYLOAD {
        return Err(HaError::InvalidFrame);
    }
    Ok(bytes)
}

fn parse(
    bytes: &[u8],
    transfer: bool,
    maximum: usize,
) -> Result<Vec<(RecordObjectRef, &[u8])>, HaError> {
    let count = usize::from(*bytes.first().ok_or(HaError::InvalidFrame)?);
    if count == 0 || count > maximum || bytes.len() > MAX_PAYLOAD {
        return Err(HaError::InvalidFrame);
    }
    let mut at = 1usize;
    let mut parsed = Vec::with_capacity(count);
    let mut prior = None;
    for _ in 0..count {
        let end = at.checked_add(36).ok_or(HaError::InvalidFrame)?;
        let reference = wire::parse_reference(bytes.get(at..end).ok_or(HaError::InvalidFrame)?)?;
        if prior.is_some_and(|id| id >= reference.id) {
            return Err(HaError::InvalidFrame);
        }
        prior = Some(reference.id);
        at = end;
        let end = at
            .checked_add(if transfer {
                reference.encoded_bytes as usize
            } else {
                0
            })
            .ok_or(HaError::InvalidFrame)?;
        let ciphertext = bytes.get(at..end).ok_or(HaError::InvalidFrame)?;
        at = end;
        parsed.push((reference, ciphertext));
    }
    if at != bytes.len() {
        return Err(HaError::InvalidFrame);
    }
    Ok(parsed)
}

// Keep pure-reference parsing separate from ciphertext/reconciliation parsing.
// Raising this bound never expands the legacy StageBatch contract, and
// even a malicious count cannot allocate more than 64 references.
fn parse_ensure(bytes: &[u8]) -> Result<Vec<RecordObjectRef>, HaError> {
    let count = usize::from(*bytes.first().ok_or(HaError::InvalidFrame)?);
    if count == 0
        || count > ENSURE_OBJECTS
        || bytes.len() > MAX_ENSURE_PAYLOAD
        || bytes.len() != 1 + count * 36
    {
        return Err(HaError::InvalidFrame);
    }
    let mut references = Vec::with_capacity(count);
    let mut prior = None;
    for bytes in bytes[1..].as_chunks::<36>().0 {
        let reference = wire::parse_reference(bytes)?;
        if prior.is_some_and(|id| id >= reference.id) {
            return Err(HaError::InvalidFrame);
        }
        prior = Some(reference.id);
        references.push(reference);
    }
    Ok(references)
}

/// An empty subset is explicit success for already present leaves. The
/// bounded payload otherwise carries each exact missing reference in order.
fn missing_payload(references: &[RecordObjectRef]) -> Result<Vec<u8>, HaError> {
    if references.is_empty() {
        Ok(vec![0])
    } else {
        ensure_expected(references)
    }
}

pub(super) fn parse_missing(
    payload: &[u8],
    requested: &[u8],
) -> Result<Vec<RecordObjectRef>, HaError> {
    let requested = parse_ensure(requested)?;
    if payload == [0] {
        return Ok(Vec::new());
    }
    let missing = parse_ensure(payload)?;
    if missing.len() > requested.len()
        || missing
            .iter()
            .any(|reference| !requested.contains(reference))
    {
        return Err(HaError::InvalidFrame);
    }
    Ok(missing)
}

impl NativeV6ClosureReceiver {
    pub(super) fn receive_ensure_batch(
        &self,
        state: &mut IncomingClosure,
        admission: &NativeV6ClosureAdmission,
        deadline: Instant,
        payload: &[u8],
    ) -> Result<Vec<u8>, HaError> {
        let parsed = parse_ensure(payload)?;
        let mut missing = Vec::with_capacity(parsed.len());
        let mut pending = Vec::with_capacity(LocalV6BlobStage::MAX_CHECKED_BATCH_OBJECTS);
        let mut pending_bytes = 0usize;
        for reference in parsed {
            // Flush before reading another ciphertext, so even the retained
            // buffers are bounded by 32 actual objects and four MiB. The wire
            // Ensure bound remains 64 references, with no ciphertext payload.
            let expected_bytes =
                usize::try_from(reference.encoded_bytes).map_err(|_| HaError::InvalidFrame)?;
            if expected_bytes > LocalV6BlobStage::MAX_CHECKED_BATCH_CIPHERTEXT_BYTES {
                return Err(HaError::InvalidFrame);
            }
            if !pending.is_empty()
                && (pending.len() == LocalV6BlobStage::MAX_CHECKED_BATCH_OBJECTS
                    || pending_bytes.checked_add(expected_bytes).is_none_or(|sum| {
                        sum > LocalV6BlobStage::MAX_CHECKED_BATCH_CIPHERTEXT_BYTES
                    }))
            {
                self.synchronize_ensured_existing_batch(state, admission, deadline, &pending)?;
                pending.clear();
                pending_bytes = 0;
            }
            let index = state.selected(&reference)?;
            self.verify(admission, deadline)?;
            let mut gate = || {
                self.verify(admission, deadline)
                    .map_err(|_| LocalV6BlobError::CorruptOrChanged)
            };
            let existing = self
                .observe_receive_result(
                    "ensure_read_existing",
                    deadline,
                    self.storage
                        .read_local_if_present_checked(&reference, &mut gate),
                )
                .map_err(|_| unknown())?;
            let Some(ciphertext) = existing else {
                // Only the initial guarded open may report missing. It grants
                // no fsync bit. If a prior exact page was repeated, an observed
                // absence also invalidates that transfer cache's old bit.
                self.verify(admission, deadline)?;
                if state.fsynced[index] {
                    state.fsynced_count = state.fsynced_count.checked_sub(1).ok_or_else(unknown)?;
                    state.fsynced[index] = false;
                }
                missing.push(reference);
                continue;
            };
            if ciphertext.len() != expected_bytes {
                return Err(unknown());
            }
            pending_bytes = pending_bytes
                .checked_add(ciphertext.len())
                .filter(|sum| *sum <= LocalV6BlobStage::MAX_CHECKED_BATCH_CIPHERTEXT_BYTES)
                .ok_or_else(unknown)?;
            self.verify(admission, deadline)?;
            // A read is not a fsync bit. Only the helper below can set bits,
            // after the entire physical batch has returned real receipts.
            pending.push((index, reference, ciphertext));
        }
        self.synchronize_ensured_existing_batch(state, admission, deadline, &pending)?;
        self.verify(admission, deadline)?;
        missing_payload(&missing)
    }

    fn synchronize_ensured_existing_batch(
        &self,
        state: &mut IncomingClosure,
        admission: &NativeV6ClosureAdmission,
        deadline: Instant,
        pending: &[(usize, RecordObjectRef, Vec<u8>)],
    ) -> Result<(), HaError> {
        if pending.is_empty() {
            return Ok(());
        }
        let objects: Vec<_> = pending
            .iter()
            .map(|(_, reference, ciphertext)| (reference, ciphertext.as_slice()))
            .collect();
        let mut gate = || {
            self.verify(admission, deadline)
                .map_err(|_| LocalV6BlobError::CorruptOrChanged)
        };
        let receipts = self
            .observe_receive_result(
                "ensure_sync_existing_batch",
                deadline,
                self.storage
                    .sync_existing_replicas_batch_checked(&objects, &mut gate),
            )
            .map_err(|_| unknown())?;
        if receipts.len() != pending.len() {
            return Err(unknown());
        }
        for ((index, reference, _), receipt) in pending.iter().zip(receipts) {
            if receipt.reference() != reference {
                return Err(unknown());
            }
            // Keep the original per-reference post-sync admission. A later
            // failure returns no Ensure response and cannot mint a Finalize ACK.
            self.verify(admission, deadline)?;
            if !state.fsynced[*index] {
                state.fsynced[*index] = true;
                state.fsynced_count += 1;
            }
        }
        Ok(())
    }

    pub(super) fn receive_batch(
        &self,
        state: &mut IncomingClosure,
        admission: &NativeV6ClosureAdmission,
        deadline: Instant,
        payload: &[u8],
        transfer: bool,
    ) -> Result<Vec<u8>, HaError> {
        self.receive_batch_bounded(state, admission, deadline, payload, transfer, OBJECTS)
    }

    pub(super) fn receive_packed_stage(
        &self,
        state: &mut IncomingClosure,
        admission: &NativeV6ClosureAdmission,
        deadline: Instant,
        payload: &[u8],
    ) -> Result<Vec<u8>, HaError> {
        self.receive_batch_bounded(state, admission, deadline, payload, true, PACKED_OBJECTS)
    }

    fn receive_batch_bounded(
        &self,
        state: &mut IncomingClosure,
        admission: &NativeV6ClosureAdmission,
        deadline: Instant,
        payload: &[u8],
        transfer: bool,
        maximum: usize,
    ) -> Result<Vec<u8>, HaError> {
        #[cfg(any(test, feature = "private-forward-stage-diagnostic"))]
        let prepare_timing = diagnostic::Span::start(diagnostic::Phase::ReceiverBatchPrepare);
        let parsed = parse(payload, transfer, maximum)?;
        let mut pending = Vec::with_capacity(parsed.len());
        for (reference, ciphertext) in parsed {
            let index = state.selected(&reference)?;
            self.verify(admission, deadline)?;
            let ciphertext = if transfer {
                ciphertext.to_vec()
            } else {
                let mut gate = || {
                    self.verify(admission, deadline)
                        .map_err(|_| LocalV6BlobError::CorruptOrChanged)
                };
                self.storage
                    .read_local_checked(&reference, &mut gate)
                    .map_err(|_| unknown())?
            };
            // Bind every complete ciphertext to the exact ordered manifest
            // reference before ANY member can enter physical publication.
            // Preserve the original checked-replica entry, reference-binding
            // and checked-stage entry admissions independently for each leaf.
            self.verify(admission, deadline)?;
            wire::validate_reference(&reference)?;
            if u64::try_from(ciphertext.len()).ok() != Some(reference.payload_bytes) {
                return Err(unknown());
            }
            let checked =
                heptabao_raft_runtime::SealedRecordObject::new_native_v6_ciphertext_chunk(
                    ciphertext.clone(),
                )
                .map_err(|_| unknown())?;
            if checked.reference() != &reference {
                return Err(unknown());
            }
            self.verify(admission, deadline)?;
            self.verify(admission, deadline)?;
            pending.push((index, reference, ciphertext));
        }
        #[cfg(any(test, feature = "private-forward-stage-diagnostic"))]
        if let Some(timing) = prepare_timing {
            timing.finish(true);
        }
        let mut gate = || {
            observe_closure_phase!(ReceiverStorageGate, self.verify(admission, deadline))
                .map_err(|_| LocalV6BlobError::CorruptOrChanged)
        };
        // Both kinds retain the original 768 KiB-class frame bound. The new
        // packed kind shares only the existing bounded real file/directory
        // barriers; every per-file sync, mutation witness, held-inode readback
        // and final callback-free check remains inside this same storage call.
        let receipts = observe_closure_phase!(
            ReceiverStorage,
            if transfer {
                let ciphertexts: Vec<_> = pending
                    .iter()
                    .map(|(_, _, ciphertext)| ciphertext.as_slice())
                    .collect();
                self.storage
                    .stage_local_batch_checked(&ciphertexts, &mut gate)
            } else {
                let objects: Vec<_> = pending
                    .iter()
                    .map(|(_, reference, ciphertext)| (reference, ciphertext.as_slice()))
                    .collect();
                self.storage
                    .sync_existing_replicas_batch_checked(&objects, &mut gate)
            }
        )
        .map_err(|_| unknown())?;
        #[cfg(any(test, feature = "private-forward-stage-diagnostic"))]
        let post_timing = diagnostic::Span::start(diagnostic::Phase::ReceiverBatchPost);
        if receipts.len() != pending.len() {
            return Err(unknown());
        }
        let mut acknowledged = Vec::with_capacity(pending.len());
        for ((index, reference, _), receipt) in pending.iter().zip(receipts) {
            if receipt.reference() != reference {
                return Err(unknown());
            }
            self.verify(admission, deadline)?;
            if !state.fsynced[*index] {
                state.fsynced[*index] = true;
                state.fsynced_count += 1;
            }
            acknowledged.push(reference.clone());
        }
        let result = reference_payload(&acknowledged, maximum);
        #[cfg(any(test, feature = "private-forward-stage-diagnostic"))]
        if let Some(timing) = post_timing {
            timing.finish(result.is_ok());
        }
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use heptabao_raft_runtime::SealedRecordObject;

    #[test]
    fn bounded_batch_rejects_fourth_leaf_truncation_trailing_and_duplicate_refs()
    -> Result<(), HaError> {
        let mut objects = Vec::new();
        for value in 1u8..=4 {
            objects.push(
                SealedRecordObject::new_native_v6_ciphertext_chunk(vec![value; 256 * 1024])
                    .map_err(|_| HaError::InvalidFrame)?,
            );
        }
        objects.sort_by_key(|object| object.reference().id);
        let references: Vec<_> = objects
            .iter()
            .map(|object| object.reference().clone())
            .collect();
        assert!(expected(&references).is_err());
        let mut encoded = vec![3u8];
        for object in &objects[..3] {
            encoded.extend_from_slice(&wire::reference_payload(object.reference())?);
            encoded.extend_from_slice(object.sealed());
        }
        assert_eq!(encoded.len(), MAX_PAYLOAD);
        assert_eq!(parse(&encoded, true, OBJECTS)?.len(), 3);
        assert!(parse(&encoded[..encoded.len() - 1], true, OBJECTS).is_err());
        encoded.push(0);
        assert!(parse(&encoded, true, OBJECTS).is_err());
        encoded.pop();
        encoded[0] = 4;
        assert!(parse(&encoded, true, OBJECTS).is_err());
        let duplicate = vec![references[0].clone(), references[0].clone()];
        assert!(expected(&duplicate).is_err());
        let mut duplicate_wire = vec![2u8];
        duplicate_wire.extend_from_slice(&wire::reference_payload(&references[0])?);
        duplicate_wire.extend_from_slice(&wire::reference_payload(&references[0])?);
        assert!(parse(&duplicate_wire, false, OBJECTS).is_err());
        Ok(())
    }

    #[test]
    fn ensure_reference_bound_and_missing_subset_do_not_expand_ciphertext_batches()
    -> Result<(), HaError> {
        let mut references = Vec::new();
        for value in 1u8..=65 {
            references.push(
                SealedRecordObject::new_native_v6_ciphertext_chunk(vec![value; 32])
                    .map_err(|_| HaError::InvalidFrame)?
                    .reference()
                    .clone(),
            );
        }
        references.sort_unstable_by_key(|reference| reference.id);
        let selected = &references[..ENSURE_OBJECTS];
        let requested = ensure_expected(selected)?;
        assert_eq!(requested.len(), MAX_ENSURE_PAYLOAD);
        assert_eq!(parse_ensure(&requested)?, selected);
        assert_eq!(parse_missing(&requested, &requested)?, selected);
        assert!(parse_missing(&[0], &requested)?.is_empty());
        let subset = vec![
            selected[0].clone(),
            selected[31].clone(),
            selected[63].clone(),
        ];
        assert_eq!(
            parse_missing(&ensure_expected(&subset)?, &requested)?,
            subset
        );

        assert!(ensure_expected(&references).is_err());
        assert!(expected(selected).is_err());
        assert!(parse(&requested, false, OBJECTS).is_err());
        assert!(parse(&requested, true, OBJECTS).is_err());
        assert!(parse_ensure(&[]).is_err());
        assert!(parse_ensure(&[0]).is_err());
        assert!(parse_ensure(&requested[..requested.len() - 1]).is_err());
        let mut invalid = requested.clone();
        invalid.push(0);
        assert!(parse_ensure(&invalid).is_err());
        invalid = requested.clone();
        invalid[0] = 65;
        invalid.extend_from_slice(&wire::reference_payload(&references[64])?);
        assert!(parse_ensure(&invalid).is_err());
        let foreign = ensure_expected(&references[64..])?;
        assert!(parse_missing(&foreign, &requested).is_err());
        let mut changed_length = selected[0].clone();
        changed_length.encoded_bytes += 1;
        changed_length.payload_bytes += 1;
        assert!(parse_missing(&ensure_expected(&[changed_length])?, &requested).is_err());
        let mut duplicate = vec![2];
        duplicate.extend_from_slice(&wire::reference_payload(&selected[0])?);
        duplicate.extend_from_slice(&wire::reference_payload(&selected[0])?);
        assert!(parse_missing(&duplicate, &requested).is_err());
        let mut reversed = vec![2];
        reversed.extend_from_slice(&wire::reference_payload(&selected[1])?);
        reversed.extend_from_slice(&wire::reference_payload(&selected[0])?);
        assert!(parse_missing(&reversed, &requested).is_err());
        let mut trailing_empty = vec![0];
        trailing_empty.extend_from_slice(&wire::reference_payload(&selected[0])?);
        assert!(parse_missing(&trailing_empty, &requested).is_err());
        assert!(parse_missing(&[0], &[0]).is_err());
        Ok(())
    }
}

#[cfg(test)]
#[path = "v6_closure_packed_batch_tests.rs"]
mod packed_tests;
