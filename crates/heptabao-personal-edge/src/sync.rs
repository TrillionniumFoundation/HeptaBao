//! A private, single-owner opaque snapshot store, suitable for an authenticated
//! transport adapter. It does not itself expose an HTTP listener or authorize
//! remote devices. A stable operation ID and exact expected ciphertext head
//! prevent offline lost updates and duplicate publication after a lost ACK.
//! All historical ciphertexts and receipts are retained until the explicit
//! bound; reaching it rejects new writes instead of silently discarding data.

use base64::{
    Engine as _,
    engine::general_purpose::{STANDARD, STANDARD_NO_PAD},
};
use heptabao_filesystem_guard::{ExclusiveDirectory, FileAccess};
use ring::digest::{SHA256, digest};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    fs,
    io::{Read, Write},
    path::Path,
};

const MAX_CIPHERTEXT: usize = 4 * 1024 * 1024;
const MAX_STATE: u64 = 2 * 1024 * 1024;
const MAX_PUBLICATIONS: usize = 4096;
const MAX_TOTAL_CIPHERTEXT: usize = 64 * 1024 * 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SyncError {
    InvalidInput,
    PrivateRootRequired,
    StorageUnavailable,
    CorruptState,
    Conflict,
    OperationConflict,
    Capacity,
    NotFound,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Receipt {
    pub generation: u64,
    pub head_id: String,
    pub ciphertext_sha256: String,
    pub operation_id: String,
    request_sha256: String,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct State {
    schema: u32,
    vault_id: String,
    head: Option<Receipt>,
    receipts: BTreeMap<String, Receipt>,
}

pub struct CiphertextStore {
    directory: ExclusiveDirectory,
    state: State,
    fenced: bool,
    retained_bytes: usize,
    blob_sizes: BTreeMap<String, usize>,
}

pub fn sha256(bytes: &[u8]) -> String {
    digest(&SHA256, bytes)
        .as_ref()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

fn valid_id(id: &str) -> bool {
    (16..=96).contains(&id.len())
        && id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

fn valid_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

impl CiphertextStore {
    pub fn open(root: &Path, vault_id: &str) -> Result<Self, SyncError> {
        let vault_bytes = STANDARD_NO_PAD
            .decode(vault_id)
            .map_err(|_| SyncError::InvalidInput)?;
        if vault_bytes.len() != 16 || STANDARD_NO_PAD.encode(&vault_bytes) != vault_id {
            return Err(SyncError::InvalidInput);
        }
        let metadata = fs::symlink_metadata(root).map_err(|_| SyncError::PrivateRootRequired)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            if metadata.mode() & 0o077 != 0 || metadata.uid() != rustix::process::getuid().as_raw()
            {
                return Err(SyncError::PrivateRootRequired);
            }
        }
        if !metadata.is_dir() || metadata.file_type().is_symlink() {
            return Err(SyncError::PrivateRootRequired);
        }
        let directory =
            ExclusiveDirectory::open(root).map_err(|_| SyncError::StorageUnavailable)?;
        let (retained_bytes, blob_sizes) = inventory(&directory)?;
        let state = if directory
            .entry_exists("state.json")
            .map_err(|_| SyncError::StorageUnavailable)?
        {
            let bytes = read_private(&directory, "state.json", MAX_STATE)?;
            let state: State =
                serde_json::from_slice(&bytes).map_err(|_| SyncError::CorruptState)?;
            if state.schema != 1
                || state.vault_id != vault_id
                || state.receipts.len() > MAX_PUBLICATIONS
            {
                return Err(SyncError::CorruptState);
            }
            match &state.head {
                Some(head)
                    if head.generation as usize == state.receipts.len()
                        && state.receipts.get(&head.operation_id) == Some(head) => {}
                None if state.receipts.is_empty() => {}
                _ => return Err(SyncError::CorruptState),
            }
            let mut generations = std::collections::BTreeSet::new();
            let mut checked_blobs = std::collections::BTreeSet::new();
            for (id, receipt) in &state.receipts {
                if id != &receipt.operation_id
                    || !valid_id(id)
                    || !valid_digest(&receipt.ciphertext_sha256)
                    || !valid_digest(&receipt.request_sha256)
                    || receipt.head_id != head_id(vault_id, receipt)
                    || receipt.generation == 0
                    || receipt.generation as usize > state.receipts.len()
                    || !generations.insert(receipt.generation)
                {
                    return Err(SyncError::CorruptState);
                }
                if checked_blobs.insert(&receipt.ciphertext_sha256) {
                    let body = read_private(
                        &directory,
                        &blob_name(&receipt.ciphertext_sha256),
                        MAX_CIPHERTEXT as u64,
                    )?;
                    if sha256(&body) != receipt.ciphertext_sha256 {
                        return Err(SyncError::CorruptState);
                    }
                }
            }
            state
        } else {
            State {
                schema: 1,
                vault_id: vault_id.into(),
                head: None,
                receipts: BTreeMap::new(),
            }
        };
        // Reopen is also the reconciliation path after rename succeeded but a
        // directory-fsync response was lost. Establish durability before any
        // historical receipt can be returned as committed.
        directory
            .sync_all()
            .map_err(|_| SyncError::StorageUnavailable)?;
        Ok(Self {
            directory,
            state,
            fenced: false,
            retained_bytes,
            blob_sizes,
        })
    }

    pub fn head(&self) -> Result<Option<&Receipt>, SyncError> {
        if self.fenced {
            return Err(SyncError::StorageUnavailable);
        }
        Ok(self.state.head.as_ref())
    }

    pub fn receipt(&self, operation_id: &str) -> Result<Receipt, SyncError> {
        if self.fenced {
            return Err(SyncError::StorageUnavailable);
        }
        self.state
            .receipts
            .get(operation_id)
            .cloned()
            .ok_or(SyncError::NotFound)
    }

    pub fn fetch(&self, digest: &str) -> Result<Vec<u8>, SyncError> {
        if self.fenced {
            return Err(SyncError::StorageUnavailable);
        }
        if !valid_digest(digest)
            || !self
                .state
                .receipts
                .values()
                .any(|r| r.ciphertext_sha256 == digest)
        {
            return Err(SyncError::NotFound);
        }
        let bytes = read_private(&self.directory, &blob_name(digest), MAX_CIPHERTEXT as u64)?;
        if sha256(&bytes) != digest {
            return Err(SyncError::CorruptState);
        }
        Ok(bytes)
    }

    /// The transport must supply the device's previously observed exact head.
    /// `None` means create-only, never overwrite-anything.
    pub fn publish(
        &mut self,
        operation_id: &str,
        expected_head: Option<&str>,
        ciphertext: &[u8],
    ) -> Result<Receipt, SyncError> {
        if self.fenced {
            return Err(SyncError::StorageUnavailable);
        }
        if !valid_id(operation_id)
            || ciphertext.is_empty()
            || ciphertext.len() > MAX_CIPHERTEXT
            || expected_head.is_some_and(|h| !valid_digest(h))
        {
            return Err(SyncError::InvalidInput);
        }
        let ciphertext_sha256 = sha256(ciphertext);
        let request = serde_json::to_vec(&(
            "heptabao-personal-sync-v1",
            &self.state.vault_id,
            operation_id,
            expected_head,
            &ciphertext_sha256,
        ))
        .map_err(|_| SyncError::InvalidInput)?;
        let request_sha256 = sha256(&request);
        if let Some(old) = self.state.receipts.get(operation_id) {
            return if old.request_sha256 == request_sha256 {
                Ok(old.clone())
            } else {
                Err(SyncError::OperationConflict)
            };
        }
        if self.state.head.as_ref().map(|r| r.head_id.as_str()) != expected_head {
            return Err(SyncError::Conflict);
        }
        if self.state.receipts.len() >= MAX_PUBLICATIONS {
            return Err(SyncError::Capacity);
        }
        let mut receipt = Receipt {
            generation: self.state.receipts.len() as u64 + 1,
            head_id: String::new(),
            ciphertext_sha256,
            operation_id: operation_id.into(),
            request_sha256,
        };
        receipt.head_id = head_id(&self.state.vault_id, &receipt);
        let already_retained = self
            .state
            .receipts
            .values()
            .any(|r| r.ciphertext_sha256 == receipt.ciphertext_sha256);
        let blob = blob_name(&receipt.ciphertext_sha256);
        let old_bytes = self.blob_sizes.get(&blob).copied().unwrap_or(0);
        if !self.blob_sizes.contains_key(&blob) && self.blob_sizes.len() >= MAX_PUBLICATIONS {
            return Err(SyncError::Capacity);
        }
        let next_bytes = self
            .retained_bytes
            .checked_sub(old_bytes)
            .and_then(|x| x.checked_add(ciphertext.len()))
            .ok_or(SyncError::Capacity)?;
        if next_bytes > MAX_TOTAL_CIPHERTEXT {
            return Err(SyncError::Capacity);
        }
        self.fenced = true;
        if self
            .directory
            .entry_exists(&blob)
            .map_err(|_| SyncError::StorageUnavailable)?
        {
            let old = read_private(&self.directory, &blob, MAX_CIPHERTEXT as u64)?;
            if old != ciphertext {
                if already_retained {
                    return Err(SyncError::CorruptState);
                }
                // This content-addressed file has no committed reference. A
                // crash before publication may leave it incomplete; repair it
                // only from the exact new caller-provided digest-bound bytes.
                self.directory
                    .remove_file(&blob)
                    .map_err(|_| SyncError::StorageUnavailable)?;
                self.directory
                    .sync_all()
                    .map_err(|_| SyncError::StorageUnavailable)?;
            }
        }
        if !self
            .directory
            .entry_exists(&blob)
            .map_err(|_| SyncError::StorageUnavailable)?
        {
            let mut file = self
                .directory
                .open_file(&blob, FileAccess::CreateNew)
                .map_err(|_| SyncError::StorageUnavailable)?;
            file.write_all(ciphertext)
                .and_then(|()| file.sync_all())
                .map_err(|_| SyncError::StorageUnavailable)?;
            self.directory
                .sync_all()
                .map_err(|_| SyncError::StorageUnavailable)?;
        }
        // The in-memory object may not continue after an uncertain storage error.
        // Durable state, publication and receipt become visible in one rename.
        let mut receipts = self.state.receipts.clone();
        receipts.insert(operation_id.into(), receipt.clone());
        let next = State {
            schema: 1,
            vault_id: self.state.vault_id.clone(),
            head: Some(receipt.clone()),
            receipts,
        };
        let bytes = serde_json::to_vec(&next).map_err(|_| SyncError::StorageUnavailable)?;
        if bytes.len() as u64 > MAX_STATE {
            return Err(SyncError::Capacity);
        }
        if self
            .directory
            .entry_exists("pending.json")
            .map_err(|_| SyncError::StorageUnavailable)?
        {
            // A private stale temporary file is uncommitted. State remains the
            // sole authority; removing it never acknowledges its operation.
            let _ = read_private(&self.directory, "pending.json", MAX_STATE)?;
            self.directory
                .remove_file("pending.json")
                .map_err(|_| SyncError::StorageUnavailable)?;
        }
        let mut file = self
            .directory
            .open_file("pending.json", FileAccess::CreateNew)
            .map_err(|_| SyncError::StorageUnavailable)?;
        file.write_all(&bytes)
            .and_then(|()| file.sync_all())
            .map_err(|_| SyncError::StorageUnavailable)?;
        self.directory
            .rename("pending.json", "state.json")
            .map_err(|_| SyncError::StorageUnavailable)?;
        self.directory
            .sync_all()
            .map_err(|_| SyncError::StorageUnavailable)?;
        self.state = next;
        self.retained_bytes = next_bytes;
        self.blob_sizes.insert(blob, ciphertext.len());
        self.fenced = false;
        Ok(receipt)
    }
}

fn blob_name(hash: &str) -> String {
    format!("ciphertext-{hash}.bin")
}

fn inventory(
    directory: &ExclusiveDirectory,
) -> Result<(usize, BTreeMap<String, usize>), SyncError> {
    let mut total = 0usize;
    let mut blobs = BTreeMap::new();
    for (count, entry) in directory
        .entries()
        .map_err(|_| SyncError::StorageUnavailable)?
        .enumerate()
    {
        if count >= MAX_PUBLICATIONS + 2 {
            return Err(SyncError::Capacity);
        }
        let name = entry
            .map_err(|_| SyncError::StorageUnavailable)?
            .into_string()
            .map_err(|_| SyncError::CorruptState)?;
        let file = directory
            .open_file(&name, FileAccess::Read)
            .map_err(|_| SyncError::StorageUnavailable)?;
        let size = private_size(&file)?;
        if name == "state.json" || name == "pending.json" {
            if size > MAX_STATE {
                return Err(SyncError::Capacity);
            }
            continue;
        }
        let hash = name
            .strip_prefix("ciphertext-")
            .and_then(|s| s.strip_suffix(".bin"))
            .ok_or(SyncError::CorruptState)?;
        if !valid_digest(hash) {
            return Err(SyncError::CorruptState);
        }
        if size > MAX_CIPHERTEXT as u64 {
            return Err(SyncError::Capacity);
        }
        total = total
            .checked_add(size as usize)
            .ok_or(SyncError::Capacity)?;
        if total > MAX_TOTAL_CIPHERTEXT {
            return Err(SyncError::Capacity);
        }
        blobs.insert(name, size as usize);
    }
    // Uncommitted ciphertext consumes the same bounded disk budget. It is
    // retained as recovery evidence, never omitted from the quota calculation.
    Ok((total, blobs))
}

fn private_size(file: &std::fs::File) -> Result<u64, SyncError> {
    let metadata = file.metadata().map_err(|_| SyncError::StorageUnavailable)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if metadata.mode() & 0o077 != 0 || metadata.uid() != rustix::process::getuid().as_raw() {
            return Err(SyncError::PrivateRootRequired);
        }
    }
    Ok(metadata.len())
}

fn head_id(vault_id: &str, receipt: &Receipt) -> String {
    // Fixed-length digest plus delimited bounded identifiers. Generation is
    // included so A -> B -> A is a distinct publication, never an ABA CAS hit.
    sha256(
        format!(
            "heptabao-sync-head-v1\n{vault_id}\n{}\n{}\n{}\n{}",
            receipt.generation,
            receipt.operation_id,
            receipt.ciphertext_sha256,
            receipt.request_sha256
        )
        .as_bytes(),
    )
}

fn read_private(
    directory: &ExclusiveDirectory,
    name: &str,
    max: u64,
) -> Result<Vec<u8>, SyncError> {
    let mut file = directory
        .open_file(name, FileAccess::Read)
        .map_err(|_| SyncError::StorageUnavailable)?;
    if private_size(&file)? > max {
        return Err(SyncError::Capacity);
    }
    let mut bytes = Vec::new();
    (&mut file)
        .take(max + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| SyncError::StorageUnavailable)?;
    if bytes.len() as u64 > max {
        return Err(SyncError::Capacity);
    }
    // This includes reuse of an equal orphan left before the original fsync.
    // Equal bytes are insufficient evidence of stable storage on their own.
    file.sync_all().map_err(|_| SyncError::StorageUnavailable)?;
    Ok(bytes)
}

pub fn decode_ciphertext(value: &str) -> Result<Vec<u8>, SyncError> {
    if value.len() > MAX_CIPHERTEXT.div_ceil(3) * 4 {
        return Err(SyncError::Capacity);
    }
    STANDARD.decode(value).map_err(|_| SyncError::InvalidInput)
}

pub fn encode_ciphertext(value: &[u8]) -> String {
    STANDARD.encode(value)
}
