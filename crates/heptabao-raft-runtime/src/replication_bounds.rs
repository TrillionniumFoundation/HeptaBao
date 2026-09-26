//! Byte bounds shared by production proposal admission and replication reads.
//! A count bound alone can strand a new leader replaying large sealed records.
use crate::{ApplicationRequest, TypeConfig};
use openraft::EntryPayload;
use openraft::alias::{EntryOf, LogIdOf, VoteOf};
use openraft::raft::AppendEntriesRequest;
use serde::Serialize;
use std::io;

pub(crate) const MAX_REMOTE_RPC_BYTES: usize = 768 * 1024;

fn largest_log_id() -> LogIdOf<TypeConfig> {
    openraft::LogId {
        leader_id: openraft::impls::leader_id_adv::LeaderId {
            term: u64::MAX,
            node_id: u64::MAX,
        },
        index: u64::MAX,
    }
}

/// All metadata fields are fixed enums/bools or unsigned u64 values. Max-width
/// integers, Some log IDs and the longer false vote flag bound every wire header.
fn largest_header() -> AppendEntriesRequest<TypeConfig> {
    AppendEntriesRequest {
        vote: VoteOf::<TypeConfig>::new(u64::MAX, u64::MAX),
        prev_log_id: Some(largest_log_id()),
        entries: Vec::new(),
        leader_commit: Some(largest_log_id()),
    }
}

fn encoded_size(value: &impl Serialize) -> io::Result<usize> {
    struct Counter(usize);
    impl io::Write for Counter {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            self.0 = self
                .0
                .checked_add(bytes.len())
                .filter(|n| *n <= MAX_REMOTE_RPC_BYTES)
                .ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        "Raft proposal exceeds remote wire budget",
                    )
                })?;
            Ok(bytes.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
    let mut counter = Counter(0);
    serde_json::to_writer(&mut counter, value).map_err(io::Error::other)?;
    Ok(counter.0)
}

pub(crate) fn entry_payload_budget() -> io::Result<usize> {
    MAX_REMOTE_RPC_BYTES
        .checked_sub(encoded_size(&largest_header())?)
        .ok_or_else(|| io::Error::other("Raft metadata exceeds wire budget"))
}

pub(crate) fn validate_proposal(request: &ApplicationRequest) -> io::Result<()> {
    let entry = EntryOf::<TypeConfig> {
        log_id: largest_log_id(),
        payload: EntryPayload::Normal(request.clone()),
    };
    if encoded_size(&entry)? > entry_payload_budget()? {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "single Raft entry exceeds remote wire budget",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn metadata_budget_bounds_real_headers_and_single_proposals() -> io::Result<()> {
        let maximum = encoded_size(&largest_header())?;
        for term in [0, 9, u64::MAX] {
            for committed in [false, true] {
                let vote = if committed {
                    VoteOf::<TypeConfig>::new_committed(term, u64::MAX)
                } else {
                    VoteOf::<TypeConfig>::new(term, u64::MAX)
                };
                for previous in [None, Some(largest_log_id())] {
                    let request = AppendEntriesRequest::<TypeConfig> {
                        vote,
                        prev_log_id: previous,
                        entries: Vec::new(),
                        leader_commit: previous,
                    };
                    assert!(encoded_size(&request)? <= maximum);
                }
            }
        }
        let legal: ApplicationRequest = openraft_memstore::ClientRequest {
            client: "synthetic".into(),
            serial: 1,
            status: "a".repeat(256 * 1024),
        }
        .into();
        validate_proposal(&legal)?;
        let oversized: ApplicationRequest = openraft_memstore::ClientRequest {
            client: "synthetic".into(),
            serial: 1,
            status: "a".repeat(MAX_REMOTE_RPC_BYTES),
        }
        .into();
        assert!(validate_proposal(&oversized).is_err());
        Ok(())
    }
}
