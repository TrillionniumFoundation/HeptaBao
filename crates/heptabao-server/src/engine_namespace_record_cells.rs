//! Trusted typed record cells. This synthetic scope cannot be mounted or chosen
//! through a caller's KV payload. Its values are independent namespace AEAD
//! ciphertext; actual private graph roots remain inside the encrypted parcel.
use super::*;
use crate::namespace_custody::Binding;
use crate::namespace_record_graph::Cells;
use crate::state_records::{Kv1Key, RecordError};
use zeroize::Zeroizing;

const MOUNT: &str = "@namespace-custody81/";
const INCARNATION: u64 = 1;

#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Owner {
    binding: Binding,
    scope: String,
}

fn scope(binding: &Binding) -> Result<String> {
    let bytes =
        serde_json::to_vec(binding).map_err(|_| error(503, "namespace record owner is invalid"))?;
    let mut context = b"heptabao-namespace-record-cell-scope-v1\0".to_vec();
    context.extend_from_slice(&bytes);
    Ok(crate::crypto::digest(&context)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect())
}

fn cell_key(scope: &str, name: &str) -> std::result::Result<Kv1Key, RecordError> {
    if name.len() != 64
        || name
            .bytes()
            .any(|byte| !byte.is_ascii_hexdigit() || byte.is_ascii_uppercase())
    {
        return Err(RecordError::Corrupt);
    }
    Kv1Key::new("", MOUNT, INCARNATION, &format!("{scope}/{name}"))
}

pub(super) fn is_cell(key: &Kv1Key) -> bool {
    key.namespace().is_empty() && key.mount() == MOUNT
}

impl EngineState {
    pub(crate) fn has_namespace_record_custody(&self) -> bool {
        !self.namespace_record_owners.is_empty()
    }

    pub(crate) fn publish_namespace_record_cells(
        &mut self,
        binding: &Binding,
        cells: &Cells,
    ) -> Result<()> {
        let owner_scope = scope(binding)?;
        for (name, ciphertext) in cells {
            cell_key(&owner_scope, name).map_err(kv1_records::record_error)?;
            if ciphertext.len() <= 32
                || ciphertext.len() > crate::state_records::BLOCK_BYTES + 25 + 32
                || !ciphertext.starts_with(b"HBA1")
            {
                return Err(error(503, "namespace record ciphertext framing rejected"));
            }
        }
        if self
            .namespace_record_owners
            .get(binding.namespace())
            .is_some_and(|owner| owner.binding != *binding || owner.scope != owner_scope)
        {
            return Err(error(503, "namespace record cell incarnation rejected"));
        }
        let Some(runtime) = self.records.as_mut() else {
            if !cells.is_empty() {
                return Err(error(
                    503,
                    "namespace record cells have no publication root",
                ));
            }
            self.namespace_record_owners.insert(
                binding.namespace().to_owned(),
                Owner {
                    binding: binding.clone(),
                    scope: owner_scope,
                },
            );
            return Ok(());
        };
        let before = runtime.protected.clone();
        let prefix = format!("{owner_scope}/");
        before
            .visit_keys(|key| {
                if is_cell(key) && key.path().starts_with(&prefix) {
                    let name = key
                        .path()
                        .strip_prefix(&prefix)
                        .ok_or(RecordError::Corrupt)?;
                    if !cells.contains_key(name) {
                        runtime
                            .apply(key.clone(), None)
                            .map_err(|_| RecordError::Corrupt)?;
                    }
                }
                Ok(())
            })
            .map_err(kv1_records::record_error)?;
        for (name, ciphertext) in cells {
            runtime
                .apply(
                    cell_key(&owner_scope, name).map_err(kv1_records::record_error)?,
                    Some(ciphertext),
                )
                .map_err(|_| error(503, "namespace record ciphertext publication failed"))?;
        }
        self.namespace_record_owners.insert(
            binding.namespace().to_owned(),
            Owner {
                binding: binding.clone(),
                scope: owner_scope,
            },
        );
        Ok(())
    }

    pub(crate) fn read_namespace_record_cell(
        &self,
        binding: &Binding,
        name: &str,
    ) -> std::result::Result<Zeroizing<Vec<u8>>, RecordError> {
        let owner = self
            .namespace_record_owners
            .get(binding.namespace())
            .ok_or(RecordError::Missing)?;
        if owner.binding != *binding {
            return Err(RecordError::Corrupt);
        }
        let key = cell_key(&owner.scope, name)?;
        let bytes = self
            .records
            .as_ref()
            .ok_or(RecordError::Missing)?
            .protected
            .get(&key)
            .ok_or(RecordError::Missing)?;
        Ok(Zeroizing::new(bytes.to_vec()))
    }

    pub(crate) fn namespace_record_cells(
        &self,
        binding: &Binding,
    ) -> std::result::Result<Cells, RecordError> {
        let owner = self
            .namespace_record_owners
            .get(binding.namespace())
            .ok_or(RecordError::Missing)?;
        if owner.binding != *binding {
            return Err(RecordError::Corrupt);
        }
        let mut cells = Cells::new();
        let Some(runtime) = &self.records else {
            return Ok(cells);
        };
        let prefix = format!("{}/", owner.scope);
        runtime.protected.visit_keys(|key| {
            if is_cell(key)
                && let Some(name) = key.path().strip_prefix(&prefix)
            {
                let bytes = runtime.protected.get(key).ok_or(RecordError::Missing)?;
                self.validate_namespace_record_cell(key, bytes)?;
                if cells
                    .insert(name.to_owned(), Zeroizing::new(bytes.to_vec()))
                    .is_some()
                {
                    return Err(RecordError::Corrupt);
                }
            }
            Ok(())
        })?;
        Ok(cells)
    }

    pub(super) fn validate_namespace_record_cell(
        &self,
        key: &Kv1Key,
        bytes: &[u8],
    ) -> std::result::Result<(), RecordError> {
        let (owner_scope, name) = key.path().split_once('/').ok_or(RecordError::Corrupt)?;
        if key.incarnation() != INCARNATION
            || cell_key(owner_scope, name)? != *key
            || !self
                .namespace_record_owners
                .values()
                .any(|owner| owner.scope == owner_scope)
            || bytes.len() <= 32
            || bytes.len() > crate::state_records::BLOCK_BYTES + 25 + 32
            || !bytes.starts_with(b"HBA1")
        {
            return Err(RecordError::Corrupt);
        }
        Ok(())
    }

    pub(super) fn validate_namespace_record_owners(&self) -> Result<()> {
        if self.namespace_record_owners.len() > 1024 {
            return Err(error(503, "namespace record owner capacity exhausted"));
        }
        for (namespace, owner) in &self.namespace_record_owners {
            if namespace.is_empty()
                || namespace != owner.binding.namespace()
                || owner.scope != scope(&owner.binding)?
            {
                return Err(error(503, "namespace record owner binding rejected"));
            }
        }
        Ok(())
    }
}
