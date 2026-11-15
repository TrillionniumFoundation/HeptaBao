//! Data-only ciphertext reads under the original complete retained-history
//! guard and exclusive blob owner. No ordinary operation is opened while the
//! store is quiescent. A caller cannot reconstruct this handle from filenames,
//! a decoded root, a manifest digest or an old retirement capsule.
use super::*;
use crate::NativeV6RetainedRoot;
use heptabao_filesystem_guard::PreparedFileRetirement;
use shared_retirement::{Descriptor, read_descriptor};

const MAX_MANIFEST_BYTES: usize = 16 + 131_072 * 40;

/// Borrowed actual guard/owner, held manifest descriptor and exact manifest
/// references. This is retention-only custody, not a live quorum read, Actor,
/// publication receipt, prepare/commit interface or deletion permission.
pub struct NativeV6RetainedClosure<'a> {
    store: &'a LocalV6BlobStage,
    root: NativeV6RetainedRoot<'a>,
    exclusive: &'a NativeV6BlobQuiescence,
    manifest: PreparedFileRetirement,
    descriptor: Descriptor,
    references: Vec<RecordObjectRef>,
}

impl LocalV6BlobStage {
    /// Open only the manifest selected by an opaque entry of the complete
    /// retained-root catalog. Every actual payload read remains independently
    /// selected and authenticated under this same exclusive owner.
    pub fn reopen_retained_root_closure<'a>(
        &'a self,
        root: NativeV6RetainedRoot<'a>,
        exclusive: &'a NativeV6BlobQuiescence,
        gate: &mut impl FnMut() -> Result<(), LocalV6BlobError>,
    ) -> Result<NativeV6RetainedClosure<'a>, LocalV6BlobError> {
        let mut owned_gate = || {
            gate()?;
            root.verify_shared_ownership(self, exclusive)
                .map_err(|_| LocalV6BlobError::CorruptOrChanged)?;
            shared_retirement::ownership(self, root.retention_guard(), exclusive)?;
            gate()
        };
        owned_gate()?;
        let intent = root.intent();
        let name = closure_manifest::manifest_leaf(&intent.closure_manifest_sha256)?;
        let (manifest, descriptor, bytes) =
            read_descriptor(self, &name, MAX_MANIFEST_BYTES, &mut owned_gate)?;
        let references = Self::validate_archived_closure_manifest(&bytes, &intent)?;
        owned_gate()?;
        // The canonical manifest grammar requires strictly increasing ids.
        // Retain that exact list; an arbitrary caller reference is not a read.
        if references.is_empty() || references.windows(2).any(|pair| pair[0].id >= pair[1].id) {
            return Err(LocalV6BlobError::InvalidClosure);
        }
        let result = NativeV6RetainedClosure {
            store: self,
            root,
            exclusive,
            manifest,
            descriptor,
            references,
        };
        result.verify()?;
        gate()?;
        Ok(result)
    }
}

impl<'a> NativeV6RetainedClosure<'a> {
    pub fn root(&self) -> &NativeV6RetainedRoot<'a> {
        &self.root
    }
    pub fn references(&self) -> &[RecordObjectRef] {
        &self.references
    }

    pub fn verify(&self) -> Result<(), LocalV6BlobError> {
        self.root
            .verify_shared_ownership(self.store, self.exclusive)
            .map_err(|_| LocalV6BlobError::CorruptOrChanged)?;
        shared_retirement::ownership(self.store, self.root.retention_guard(), self.exclusive)?;
        self.store
            .directory
            .verify_file_retirement(&self.manifest)?;
        if Descriptor::read(self.manifest.file())? != self.descriptor {
            return Err(LocalV6BlobError::CorruptOrChanged);
        }
        self.root
            .verify_shared_ownership(self.store, self.exclusive)
            .map_err(|_| LocalV6BlobError::CorruptOrChanged)
    }

    pub fn read_local(
        &self,
        reference: &RecordObjectRef,
        gate: &mut impl FnMut() -> Result<(), LocalV6BlobError>,
    ) -> Result<Vec<u8>, LocalV6BlobError> {
        let mut owned_gate = || {
            gate()?;
            self.verify()?;
            gate()
        };
        owned_gate()?;
        let index = self
            .references
            .binary_search_by_key(&reference.id, |entry| entry.id)
            .map_err(|_| LocalV6BlobError::InvalidClosure)?;
        if self.references[index] != *reference
            || reference.kind != RecordObjectKind::NativeV6CiphertextChunk
        {
            return Err(LocalV6BlobError::InvalidClosure);
        }
        let name = LocalV6BlobStage::leaf(reference)?;
        let maximum = usize::try_from(reference.payload_bytes)
            .map_err(|_| LocalV6BlobError::InvalidCiphertext)?;
        let (file, descriptor, bytes) =
            read_descriptor(self.store, &name, maximum, &mut owned_gate)?;
        let sealed = SealedRecordObject::new(reference.clone(), Vec::new(), bytes)
            .map_err(|_| LocalV6BlobError::CorruptOrChanged)?;
        if sealed.reference() != reference {
            return Err(LocalV6BlobError::CorruptOrChanged);
        }
        owned_gate()?;
        self.store.directory.verify_file_retirement(&file)?;
        if Descriptor::read(file.file())? != descriptor {
            return Err(LocalV6BlobError::CorruptOrChanged);
        }
        owned_gate()?;
        Ok(sealed.into_sealed())
    }
}
