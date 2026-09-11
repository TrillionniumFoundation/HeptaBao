use openraft::errors::RaftError;
use openraft::raft::SnapshotResponse;
use openraft::type_config::alias::{SnapshotMetaOf, VoteOf};
use openraft_memstore::TypeConfig;
use serde::{Deserialize, Serialize};

pub(super) const MAX_REMOTE_RPC_BYTES: usize = 768 * 1024;
pub(super) const SNAPSHOT_CHUNK_BYTES: usize = 128 * 1024;
pub(super) const MAX_REMOTE_SNAPSHOT_BYTES: usize = 128 * 1024 * 1024;
pub(super) const MAX_INCOMING_SNAPSHOTS: usize = 4;

#[derive(Serialize, Deserialize)]
pub(super) struct SnapshotChunkWire {
    pub transfer_id: String,
    pub ordinal: u32,
    pub total_chunks: u32,
    pub vote: Option<VoteOf<TypeConfig>>,
    pub meta: Option<SnapshotMetaOf<TypeConfig>>,
    pub total_bytes: u64,
    pub whole_crc32: u32,
    pub chunk_crc32: u32,
    pub chunk: Vec<u8>,
}

#[derive(Serialize, Deserialize)]
pub(super) struct SnapshotChunkAck {
    pub transfer_id: String,
    pub next_ordinal: u32,
    pub complete: bool,
    pub result: Option<Result<SnapshotResponse<TypeConfig>, RaftError<TypeConfig>>>,
}

pub(super) struct IncomingSnapshot {
    pub total_chunks: u32,
    pub next_ordinal: u32,
    pub vote: VoteOf<TypeConfig>,
    pub meta: SnapshotMetaOf<TypeConfig>,
    pub total_bytes: usize,
    pub whole_crc32: u32,
    pub data: Vec<u8>,
}

pub(super) fn snapshot_transfer_id(meta: &[u8], vote: &[u8], data_len: usize) -> String {
    format!("{:08x}{:08x}-{}", crc32(meta), crc32(vote), data_len)
}

pub(super) fn crc32(bytes: &[u8]) -> u32 {
    let mut crc = 0xffff_ffff_u32;
    for byte in bytes {
        crc ^= u32::from(*byte);
        for _ in 0..8 {
            let mask = 0_u32.wrapping_sub(crc & 1);
            crc = (crc >> 1) ^ (0xedb8_8320 & mask);
        }
    }
    !crc
}
