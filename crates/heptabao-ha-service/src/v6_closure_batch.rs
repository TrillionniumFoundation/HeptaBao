//! At most three independently authenticated ciphertext leaves per TLS frame.
//! Pure-reference Ensure frames have a separate small bound: they carry no
//! ciphertext. The leaf and fsync boundaries and final whole-closure fsync
//! gate remain mandatory for every reference.
use super::*;

pub(super) const OBJECTS: usize = 3;
pub(super) const MAX_PAYLOAD: usize = 1 + OBJECTS * (36 + wire::MAX_CIPHERTEXT);
pub(super) const MAX_ACK: usize = 1 + OBJECTS * 36;
pub(super) const ENSURE_OBJECTS: usize = 64;
pub(super) const MAX_ENSURE_PAYLOAD: usize = 1 + ENSURE_OBJECTS * 36;

pub(super) fn expected(references: &[RecordObjectRef]) -> Result<Vec<u8>, HaError> {
    reference_payload(references, OBJECTS)
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
    let _ = expected(references)?;
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

fn parse(bytes: &[u8], transfer: bool) -> Result<Vec<(RecordObjectRef, &[u8])>, HaError> {
    let count = usize::from(*bytes.first().ok_or(HaError::InvalidFrame)?);
    if count == 0 || count > OBJECTS || bytes.len() > MAX_PAYLOAD {
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
// Raising this bound never admits a fourth ciphertext leaf or a larger Stage
// ACK, and even a malicious count cannot allocate more than 64 references.
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
    for bytes in bytes[1..].chunks_exact(36) {
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
        for reference in parsed {
            let index = state.selected(&reference)?;
            self.verify(admission, deadline)?;
            let mut gate = || {
                self.verify(admission, deadline)
                    .map_err(|_| LocalV6BlobError::CorruptOrChanged)
            };
            let existing = self
                .storage
                .read_local_if_present_checked(&reference, &mut gate)
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
            // Preserve the original actual existing-file path: exact
            // ciphertext/ref verification, held descriptor and directory
            // identity, both real fsync barriers and terminal admission.
            self.storage
                .stage_received_replica_checked(&reference, &ciphertext, &mut gate)
                .map_err(|_| unknown())?;
            self.verify(admission, deadline)?;
            if !state.fsynced[index] {
                state.fsynced[index] = true;
                state.fsynced_count += 1;
            }
        }
        self.verify(admission, deadline)?;
        missing_payload(&missing)
    }

    pub(super) fn receive_batch(
        &self,
        state: &mut IncomingClosure,
        admission: &NativeV6ClosureAdmission,
        deadline: Instant,
        payload: &[u8],
        transfer: bool,
    ) -> Result<Vec<u8>, HaError> {
        let parsed = parse(payload, transfer)?;
        let mut acknowledged = Vec::with_capacity(parsed.len());
        for (reference, ciphertext) in parsed {
            let index = state.selected(&reference)?;
            self.verify(admission, deadline)?;
            let existing;
            let ciphertext = if transfer {
                ciphertext
            } else {
                existing = self.storage.read_local(&reference).map_err(|_| unknown())?;
                &existing
            };
            let mut gate = || {
                self.verify(admission, deadline)
                    .map_err(|_| LocalV6BlobError::CorruptOrChanged)
            };
            self.storage
                .stage_received_replica_checked(&reference, ciphertext, &mut gate)
                .map_err(|_| unknown())?;
            self.verify(admission, deadline)?;
            if !state.fsynced[index] {
                state.fsynced[index] = true;
                state.fsynced_count += 1;
            }
            acknowledged.push(reference);
        }
        expected(&acknowledged)
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
        assert_eq!(parse(&encoded, true)?.len(), 3);
        assert!(parse(&encoded[..encoded.len() - 1], true).is_err());
        encoded.push(0);
        assert!(parse(&encoded, true).is_err());
        encoded.pop();
        encoded[0] = 4;
        assert!(parse(&encoded, true).is_err());
        let duplicate = vec![references[0].clone(), references[0].clone()];
        assert!(expected(&duplicate).is_err());
        let mut duplicate_wire = vec![2u8];
        duplicate_wire.extend_from_slice(&wire::reference_payload(&references[0])?);
        duplicate_wire.extend_from_slice(&wire::reference_payload(&references[0])?);
        assert!(parse(&duplicate_wire, false).is_err());
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
        assert_eq!(parse_missing(&ensure_expected(&subset)?, &requested)?, subset);

        assert!(ensure_expected(&references).is_err());
        assert!(expected(selected).is_err());
        assert!(parse(&requested, false).is_err());
        assert!(parse(&requested, true).is_err());
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
