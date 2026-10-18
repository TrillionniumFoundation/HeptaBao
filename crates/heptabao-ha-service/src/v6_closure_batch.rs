//! At most three independently authenticated ciphertext leaves per TLS frame.
//! The leaf and fsync boundaries are unchanged; batching only amortizes TLS and
//! fresh admission. The final whole-closure fsync gate remains mandatory.
use super::*;

pub(super) const OBJECTS: usize = 3;
pub(super) const MAX_PAYLOAD: usize = 1 + OBJECTS * (36 + wire::MAX_CIPHERTEXT);
pub(super) const MAX_ACK: usize = 1 + OBJECTS * 36;

pub(super) fn expected(references: &[RecordObjectRef]) -> Result<Vec<u8>, HaError> {
    if references.is_empty() || references.len() > OBJECTS {
        return Err(HaError::InvalidFrame);
    }
    let mut bytes = vec![references.len() as u8];
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

impl NativeV6ClosureReceiver {
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
}
