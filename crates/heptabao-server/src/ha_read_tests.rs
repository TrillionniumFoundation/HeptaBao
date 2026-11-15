use super::*;
use std::cell::Cell;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

struct Fixture {
    codec: ClusterStateCodec,
    envelope: ReplicatedEnvelope,
    chunks: BTreeMap<(u16, u8), ReplicatedEnvelope>,
    references: Vec<ReplicatedChunkRef>,
    bytes: Vec<u8>,
    generation: u64,
}

impl Fixture {
    fn new(bytes: &[u8], owner: [u8; 32]) -> TestResult<Self> {
        let codec = ClusterStateCodec::new("verified-read-test", [7; 32])?;
        let mut chunks = BTreeMap::new();
        let mut references = Vec::new();
        for (index, bytes) in bytes.chunks(REPLICATED_STATE_CHUNK_BYTES).enumerate() {
            let index = u16::try_from(index)?;
            let proposal = codec.seal_chunk(format!("test-chunk-{index}"), index, 0, bytes)?;
            references.push(ReplicatedChunkRef {
                index,
                slot: 0,
                bytes: u32::try_from(bytes.len())?,
                digest: proposal.digest(),
            });
            chunks.insert(
                (index, 0),
                ReplicatedEnvelope::new(
                    proposal.operation_id(),
                    proposal.digest(),
                    proposal.sealed().to_vec(),
                )?,
            );
        }
        let proposal = codec.seal_manifest_with_owner_binding(
            "test-manifest",
            [1; 32],
            bytes,
            references.clone(),
            owner,
            0x1f,
        )?;
        let envelope = ReplicatedEnvelope::new(
            proposal.operation_id(),
            proposal.digest(),
            proposal.sealed().to_vec(),
        )?;
        Ok(Self {
            codec,
            envelope,
            chunks,
            references,
            bytes: bytes.to_vec(),
            generation: 19,
        })
    }

    fn read(
        &self,
        known: Option<&ValidatedReadCursor>,
        reads: &Cell<usize>,
        indexes: &Cell<usize>,
    ) -> Result<CommittedStateRead, String> {
        read_committed_application(
            &self.codec,
            known,
            || {
                indexes.set(indexes.get() + 1);
                Ok(())
            },
            || Ok((self.generation, Some(self.envelope.clone()))),
            |index, slot| {
                reads.set(reads.get() + 1);
                Ok(self.chunks.get(&(index, slot)).cloned())
            },
            || self.generation,
        )
    }

    fn materialize(&self) -> TestResult<CommittedApplicationState> {
        match self.read(None, &Cell::new(0), &Cell::new(0))? {
            CommittedStateRead::Materialized(state) => Ok(state),
            _ => Err("cold read did not materialize".into()),
        }
    }
}

// Service tests receive genuine evidence from the same full authentication
// path as production, never a constructor for the opaque cursor fields.
pub(crate) fn fully_verified_fixture(
    bytes: &[u8],
    owner: [u8; 32],
) -> TestResult<CommittedApplicationState> {
    Fixture::new(bytes, owner)?.materialize()
}

#[test]
fn stable_generation_authenticates_manifest_and_skips_all_chunk_loads() -> TestResult {
    let fixture = Fixture::new(&vec![b'x'; REPLICATED_STATE_CHUNK_BYTES * 2 + 17], [2; 32])?;
    let reads = Cell::new(0);
    let indexes = Cell::new(0);
    let first = fixture.materialize()?;
    assert_eq!(first.bytes.as_slice(), fixture.bytes);
    let cursor = first
        .read_cursor
        .as_ref()
        .ok_or("full read must issue cursor")?;
    assert!(matches!(
        fixture.read(Some(cursor), &reads, &indexes)?,
        CommittedStateRead::Unchanged
    ));
    assert_eq!(reads.get(), 0);
    assert_eq!(indexes.get(), 1);
    Ok(())
}

#[test]
fn warm_cursor_never_bypasses_read_index_after_authority_loss() -> TestResult {
    let fixture = Fixture::new(b"state", [2; 32])?;
    let first = fixture.materialize()?;
    let latest_calls = Cell::new(0);
    let chunk_calls = Cell::new(0);
    let result = read_committed_application(
        &fixture.codec,
        first.read_cursor.as_ref(),
        || Err("not current leader".into()),
        || {
            latest_calls.set(latest_calls.get() + 1);
            Ok((fixture.generation, Some(fixture.envelope.clone())))
        },
        |_, _| {
            chunk_calls.set(chunk_calls.get() + 1);
            Ok(None)
        },
        || fixture.generation,
    );
    assert!(matches!(result, Err(error) if error == "not current leader"));
    assert_eq!(latest_calls.get(), 0);
    assert_eq!(chunk_calls.get(), 0);
    Ok(())
}

#[test]
fn changed_chunk_under_same_manifest_invalidates_cursor_and_fails_authentication() -> TestResult {
    let mut fixture = Fixture::new(b"state", [2; 32])?;
    let first = fixture.materialize()?;
    let chunk = fixture.chunks.get(&(0, 0)).ok_or("chunk missing")?;
    let mut corrupted = chunk.sealed().to_vec();
    *corrupted.last_mut().ok_or("empty sealed chunk")? ^= 1;
    fixture.chunks.insert(
        (0, 0),
        ReplicatedEnvelope::new(chunk.operation_id(), chunk.digest(), corrupted)?,
    );
    fixture.generation += 1;
    let reads = Cell::new(0);
    assert!(
        fixture
            .read(first.read_cursor.as_ref(), &reads, &Cell::new(0))
            .is_err()
    );
    assert_eq!(reads.get(), 1);
    Ok(())
}

#[test]
fn same_logical_digest_with_different_authenticated_owner_metadata_requires_full_read() -> TestResult
{
    let mut fixture = Fixture::new(b"state", [2; 32])?;
    let first = fixture.materialize()?;
    let proposal = fixture.codec.seal_manifest_with_owner_binding(
        "test-manifest",
        [1; 32],
        &fixture.bytes,
        fixture.references.clone(),
        [3; 32],
        0x01,
    )?;
    fixture.envelope = ReplicatedEnvelope::new(
        proposal.operation_id(),
        proposal.digest(),
        proposal.sealed().to_vec(),
    )?;
    assert_eq!(fixture.envelope.digest(), first.digest);
    // Even a same-generation injected value cannot reuse evidence for a
    // different envelope. A real applied replacement also advances generation.
    let reads = Cell::new(0);
    match fixture.read(first.read_cursor.as_ref(), &reads, &Cell::new(0))? {
        CommittedStateRead::Materialized(state) => {
            assert_eq!(state.owner_manifest_digest, Some([3; 32]))
        }
        _ => return Err("different owner metadata reused old cursor".into()),
    }
    assert_eq!(reads.get(), 1);
    Ok(())
}

#[test]
fn tampered_manifest_cannot_reuse_a_matching_logical_digest() -> TestResult {
    let mut fixture = Fixture::new(b"state", [2; 32])?;
    let first = fixture.materialize()?;
    let mut sealed = fixture.envelope.sealed().to_vec();
    *sealed.last_mut().ok_or("empty manifest")? ^= 1;
    fixture.envelope =
        ReplicatedEnvelope::new(fixture.envelope.operation_id(), first.digest, sealed)?;
    let reads = Cell::new(0);
    assert!(
        fixture
            .read(first.read_cursor.as_ref(), &reads, &Cell::new(0))
            .is_err()
    );
    assert_eq!(reads.get(), 0);
    Ok(())
}

#[test]
fn generation_change_during_full_read_does_not_issue_evidence() -> TestResult {
    let fixture = Fixture::new(b"state", [2; 32])?;
    match read_committed_application(
        &fixture.codec,
        None,
        || Ok(()),
        || Ok((fixture.generation, Some(fixture.envelope.clone()))),
        |index, slot| Ok(fixture.chunks.get(&(index, slot)).cloned()),
        || fixture.generation + 1,
    )? {
        CommittedStateRead::Materialized(state) => assert!(state.read_cursor.is_none()),
        _ => return Err("cold read did not materialize".into()),
    }
    Ok(())
}

#[test]
fn missing_chunks_and_legacy_formats_cannot_issue_reusable_evidence() -> TestResult {
    let mut fixture = Fixture::new(b"state", [2; 32])?;
    let first = fixture.materialize()?;
    fixture.chunks.clear();
    fixture.generation += 1;
    assert!(
        fixture
            .read(first.read_cursor.as_ref(), &Cell::new(0), &Cell::new(0))
            .is_err()
    );
    let legacy = fixture.codec.seal("legacy", [1; 32], b"state")?;
    fixture.envelope = ReplicatedEnvelope::new(
        legacy.operation_id(),
        legacy.digest(),
        legacy.sealed().to_vec(),
    )?;
    let read = fixture.materialize()?;
    assert!(read.legacy_whole_state);
    assert!(read.read_cursor.is_none());
    Ok(())
}
