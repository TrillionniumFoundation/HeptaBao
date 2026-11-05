//! The explicit kind's count and byte limits are independent. Legacy parsing
//! keeps its old bound, including when a packed body would otherwise be valid.
use super::*;
use heptabao_raft_runtime::{RecordObjectKind, SealedRecordObject};

fn objects(count: u8, bytes: usize) -> Result<Vec<SealedRecordObject>, HaError> {
    let mut result = (1..=count)
        .map(|value| {
            SealedRecordObject::new_native_v6_ciphertext_chunk(vec![value; bytes])
                .map_err(|_| HaError::InvalidFrame)
        })
        .collect::<Result<Vec<_>, _>>()?;
    result.sort_by_key(|object| object.reference().id);
    Ok(result)
}

fn encode_objects(objects: &[SealedRecordObject]) -> Result<Vec<u8>, HaError> {
    let mut bytes = vec![u8::try_from(objects.len()).map_err(|_| HaError::InvalidFrame)?];
    for object in objects {
        bytes.extend_from_slice(&wire::reference_payload(object.reference())?);
        bytes.extend_from_slice(object.sealed());
    }
    Ok(bytes)
}

#[test]
fn packed_stage_count_bound_does_not_expand_legacy_or_allow_thirteenth_leaf() -> Result<(), HaError>
{
    let objects = objects(13, 25)?;
    let references: Vec<_> = objects
        .iter()
        .map(|object| object.reference().clone())
        .collect();
    let encoded = encode_objects(&objects[..12])?;
    assert_eq!(encoded.len(), 1 + 12 * (36 + 25));
    assert_eq!(parse(&encoded, true, PACKED_OBJECTS)?.len(), 12);
    assert_eq!(packed_expected(&references[..12])?.len(), MAX_PACKED_ACK);
    assert!(parse(&encoded, true, OBJECTS).is_err());
    assert!(expected(&references[..12]).is_err());
    assert!(parse(&encode_objects(&objects)?, true, PACKED_OBJECTS).is_err());
    assert!(packed_expected(&references).is_err());
    assert!(parse(&[0], true, PACKED_OBJECTS).is_err());
    assert!(parse(&encoded[..encoded.len() - 1], true, PACKED_OBJECTS).is_err());
    let mut invalid = encoded.clone();
    invalid.push(0);
    assert!(parse(&invalid, true, PACKED_OBJECTS).is_err());
    let mut duplicate = vec![2];
    for _ in 0..2 {
        duplicate.extend_from_slice(&wire::reference_payload(objects[0].reference())?);
        duplicate.extend_from_slice(objects[0].sealed());
    }
    assert!(parse(&duplicate, true, PACKED_OBJECTS).is_err());
    let mut reversed = vec![2];
    for object in objects[..2].iter().rev() {
        reversed.extend_from_slice(&wire::reference_payload(object.reference())?);
        reversed.extend_from_slice(object.sealed());
    }
    assert!(parse(&reversed, true, PACKED_OBJECTS).is_err());
    Ok(())
}

#[test]
fn packed_stage_retains_original_exact_ciphertext_frame_byte_bound() -> Result<(), HaError> {
    let objects = objects(4, wire::MAX_CIPHERTEXT)?;
    let references: Vec<_> = objects
        .iter()
        .map(|object| object.reference().clone())
        .collect();
    let encoded = encode_objects(&objects[..3])?;
    assert_eq!(encoded.len(), MAX_PAYLOAD);
    assert_eq!(parse(&encoded, true, PACKED_OBJECTS)?.len(), 3);
    assert!(packed_expected(&references[..3]).is_ok());
    // Four is below the new count limit but above the unchanged wire budget.
    let oversized = encode_objects(&objects)?;
    assert!(oversized.len() > MAX_PAYLOAD);
    assert!(parse(&oversized, true, PACKED_OBJECTS).is_err());
    assert!(packed_expected(&references).is_err());
    let batches = packed_batches(&references)?;
    assert_eq!(
        batches.iter().map(|batch| batch.len()).collect::<Vec<_>>(),
        vec![3, 1]
    );
    assert_eq!(batches.concat(), references);
    Ok(())
}

#[test]
fn packed_partition_preserves_exact_subset_and_both_bounds_without_io() -> Result<(), HaError> {
    let objects = objects(65, 25)?;
    let references: Vec<_> = objects
        .iter()
        .map(|object| object.reference().clone())
        .collect();
    assert!(packed_batches(&[])?.is_empty());
    let batches = packed_batches(&references[..64])?;
    assert_eq!(batches.len(), 6);
    assert_eq!(
        batches.iter().map(|batch| batch.len()).collect::<Vec<_>>(),
        vec![12, 12, 12, 12, 12, 4]
    );
    assert_eq!(batches.concat(), references[..64]);
    assert_eq!(
        packed_batches(&references[..13])?
            .iter()
            .map(|batch| batch.len())
            .collect::<Vec<_>>(),
        vec![12, 1]
    );
    // Only one authenticated Ensure response may be partitioned at a time.
    assert!(packed_batches(&references).is_err());
    let mut duplicate = references[..13].to_vec();
    duplicate[12] = duplicate[11].clone();
    assert!(packed_batches(&duplicate).is_err());
    let mut reversed = references[..13].to_vec();
    reversed.reverse();
    assert!(packed_batches(&reversed).is_err());
    let mut invalid_tail = references[..64].to_vec();
    invalid_tail[63].record_count = 1;
    assert!(packed_batches(&invalid_tail).is_err());
    invalid_tail[63].record_count = 0;
    invalid_tail[63].encoded_bytes = u32::MAX;
    invalid_tail[63].payload_bytes = u64::from(u32::MAX);
    assert!(packed_batches(&invalid_tail).is_err());
    Ok(())
}

// These are valid ordered reference shapes for a pure partition operation.
// No ciphertext is claimed to have been read or authenticated by this helper.
fn sized_references(sizes: &[usize]) -> Result<Vec<RecordObjectRef>, HaError> {
    sizes
        .iter()
        .enumerate()
        .map(|(index, bytes)| {
            let reference = RecordObjectRef {
                id: [u8::try_from(index + 1).map_err(|_| HaError::InvalidFrame)?; 32],
                kind: RecordObjectKind::NativeV6CiphertextChunk,
                encoded_bytes: u32::try_from(*bytes).map_err(|_| HaError::InvalidFrame)?,
                record_count: 0,
                payload_bytes: u64::try_from(*bytes).map_err(|_| HaError::InvalidFrame)?,
            };
            wire::validate_reference(&reference)?;
            Ok(reference)
        })
        .collect()
}

#[test]
fn packed_partition_minimizes_barriers_then_four_worker_waves_with_stable_ties()
-> Result<(), HaError> {
    let references = sized_references(&[
        25,
        25,
        25,
        wire::MAX_CIPHERTEXT,
        wire::MAX_CIPHERTEXT,
        wire::MAX_CIPHERTEXT,
    ])?;
    // Greedy [5,1] has the same two batch barriers but needs three worker
    // waves. [4,2] needs two waves and preserves every reference's order.
    let batches = packed_batches(&references)?;
    assert_eq!(
        batches.iter().map(|batch| batch.len()).collect::<Vec<_>>(),
        vec![4, 2]
    );
    assert_eq!(batches.concat(), references);
    assert_eq!(
        batches
            .iter()
            .map(|batch| batch.len().div_ceil(4))
            .sum::<usize>(),
        2
    );
    // One nine-leaf frame is preferred to two frames with equal wave cost.
    let nine = sized_references(&[25; 9])?;
    assert_eq!(
        packed_batches(&nine)?
            .iter()
            .map(|batch| batch.len())
            .collect::<Vec<_>>(),
        vec![9]
    );
    // Both [12,1] and several shorter first cuts have two barriers/four
    // waves. The stable tie rule takes the longest valid first segment.
    let thirteen = sized_references(&[25; 13])?;
    assert_eq!(
        packed_batches(&thirteen)?
            .iter()
            .map(|batch| batch.len())
            .collect::<Vec<_>>(),
        vec![12, 1]
    );
    Ok(())
}

#[test]
fn packed_partition_matches_exhaustive_small_ordered_partitions() -> Result<(), HaError> {
    // This oracle enumerates every cut-mask, rather than reproducing the
    // production suffix dynamic program. Small/large mixtures exercise the
    // exact frame-byte limit and partially filled four-worker batches.
    for count in 1..=8usize {
        for sizes_mask in 0..(1usize << count) {
            let sizes: Vec<_> = (0..count)
                .map(|index| {
                    if sizes_mask & (1 << index) == 0 {
                        25
                    } else {
                        wire::MAX_CIPHERTEXT
                    }
                })
                .collect();
            let references = sized_references(&sizes)?;
            let mut expected: Option<(usize, usize, Vec<usize>)> = None;
            for cut_mask in 0..(1usize << (count - 1)) {
                let mut stops: Vec<_> = (1..count)
                    .filter(|stop| cut_mask & (1 << (*stop - 1)) != 0)
                    .collect();
                stops.push(count);
                let mut start = 0usize;
                let mut waves = 0usize;
                let mut valid = true;
                for stop in &stops {
                    let batch = &references[start..*stop];
                    let bytes = 1 + batch
                        .iter()
                        .map(|reference| 36 + reference.encoded_bytes as usize)
                        .sum::<usize>();
                    if batch.len() > PACKED_OBJECTS || bytes > MAX_PAYLOAD {
                        valid = false;
                        break;
                    }
                    waves += batch.len().div_ceil(4);
                    start = *stop;
                }
                if !valid {
                    continue;
                }
                let cost = (stops.len(), waves);
                if expected.as_ref().is_none_or(|prior| {
                    cost < (prior.0, prior.1) || (cost == (prior.0, prior.1) && stops > prior.2)
                }) {
                    expected = Some((cost.0, cost.1, stops));
                }
            }
            let batches = packed_batches(&references)?;
            let mut stop = 0usize;
            let actual_stops: Vec<_> = batches
                .iter()
                .map(|batch| {
                    stop += batch.len();
                    stop
                })
                .collect();
            let expected = expected.ok_or(HaError::InvalidFrame)?;
            assert_eq!(
                (
                    batches.len(),
                    batches
                        .iter()
                        .map(|batch| batch.len().div_ceil(4))
                        .sum::<usize>()
                ),
                (expected.0, expected.1)
            );
            assert_eq!(actual_stops, expected.2);
            assert_eq!(batches.concat(), references);
        }
    }
    Ok(())
}

#[test]
fn packed_partition_keeps_442_leaf_order_and_bounded_work_projection() -> Result<(), HaError> {
    // The unchanged real pipeline fixture's exact ciphertext population and
    // native digest ordering, without its Raft/TLS/storage side effects. This
    // checks partition work, not elapsed time or successful physical repair.
    let mut references = Vec::with_capacity(442);
    let mut ciphertext_bytes = 0usize;
    for index in 0..442usize {
        let bytes = match index {
            0..=135 => 256 * 1024,
            136..=440 => 1_790,
            441 => 1_918,
            _ => return Err(HaError::InvalidFrame),
        };
        let mut ciphertext = vec![(index % 251 + 1) as u8; bytes];
        ciphertext[..8].copy_from_slice(&(index as u64).to_be_bytes());
        let object = SealedRecordObject::new_native_v6_ciphertext_chunk(ciphertext)
            .map_err(|_| HaError::InvalidFrame)?;
        references.push(object.reference().clone());
        ciphertext_bytes += bytes;
    }
    references.sort_by_key(|reference| reference.id);
    assert_eq!(ciphertext_bytes, 36_199_452);
    let mut batch_count = 0usize;
    let mut waves = 0usize;
    for page in references.chunks(ENSURE_OBJECTS) {
        let batches = packed_batches(page)?;
        assert_eq!(batches.concat().as_slice(), page);
        for batch in batches {
            assert!((1..=12).contains(&batch.len()));
            assert!(packed_payload_length(batch)? <= MAX_PAYLOAD);
            batch_count += 1;
            waves += batch.len().div_ceil(4);
        }
    }
    assert_eq!((batch_count, waves), (67, 124));
    Ok(())
}
