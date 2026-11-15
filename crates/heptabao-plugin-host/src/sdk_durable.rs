//! An SDK Storage view over the existing encrypted DurableService and ledger.
//! Scope and request context are supplied after the server's owner/ACL checks;
//! constructing this view does not perform or grant that authorization.
use std::collections::BTreeSet;
use std::time::Instant;

use heptabao_domain::{CanonicalPath, Id};
use heptabao_durable_service::{
    Barrier, DeleteRequest, DurableBackend, DurableService, MutationOutcome, PutRequest, Secret,
    ServiceError,
};
use ring::digest::{SHA256, digest};
use serde_json::{Value, json};
use zeroize::Zeroizing;

use crate::{
    PluginMutationContext,
    sdk_backend::{SdkBridgeError, SdkStorage, SdkStorageEntry},
};

#[derive(Clone, Eq, PartialEq)]
pub struct SdkStorageScope {
    namespace: String,
    owner_digest: String,
}
impl std::fmt::Debug for SdkStorageScope {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SdkStorageScope([REDACTED])")
    }
}
impl SdkStorageScope {
    pub fn durable_namespace(&self) -> &str {
        &self.namespace
    }
    /// Bind cluster, actual namespace, mount identity and actual incarnation.
    /// The caller retains the responsibility to validate these against Service.
    pub fn new(
        cluster: &Id,
        namespace: &CanonicalPath,
        mount: &Id,
        incarnation: u64,
    ) -> Result<Self, SdkBridgeError> {
        if incarnation == 0 {
            return Err(SdkBridgeError::BeforeEntry);
        }
        let material=serde_json::to_vec(&json!({"format":1,"cluster":cluster.as_str(),"namespace":namespace.as_str(),"mount":mount.as_str(),"incarnation":incarnation})).map_err(|_|SdkBridgeError::BeforeEntry)?;
        let owner_digest = hex(digest(&SHA256, &material).as_ref());
        Ok(Self {
            namespace: format!("sdk-backend-{owner_digest}"),
            owner_digest,
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SdkStorageMutation {
    pub sequence: u64,
    pub operation: &'static str,
    pub outcome: MutationOutcome,
}

pub struct SdkDurableStorage<'a, B: Barrier, P: DurableBackend> {
    durable: &'a mut DurableService<B, P>,
    scope: SdkStorageScope,
    context: PluginMutationContext,
    mutations: Vec<SdkStorageMutation>,
    sequence: u64,
}
impl<B: Barrier, P: DurableBackend> std::fmt::Debug for SdkDurableStorage<'_, B, P> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SdkDurableStorage([REDACTED])")
    }
}
impl<'a, B: Barrier, P: DurableBackend> SdkDurableStorage<'a, B, P> {
    pub fn new(
        durable: &'a mut DurableService<B, P>,
        scope: SdkStorageScope,
        context: PluginMutationContext,
    ) -> Result<Self, SdkBridgeError> {
        durable.verify_live_ownership().map_err(durable_error)?;
        if durable.recovery_required() {
            return Err(SdkBridgeError::Fenced);
        }
        Ok(Self {
            durable,
            scope,
            context,
            mutations: Vec::new(),
            sequence: 0,
        })
    }
    pub fn mutations(&self) -> &[SdkStorageMutation] {
        &self.mutations
    }
    fn gate(&mut self, deadline: Instant) -> Result<(), SdkBridgeError> {
        if self.durable.recovery_required() {
            return Err(SdkBridgeError::Fenced);
        }
        if Instant::now() >= deadline {
            return Err(SdkBridgeError::OutcomeUnknown);
        }
        self.durable.verify_live_ownership().map_err(durable_error)
    }
    fn next_request(&mut self) -> Result<(u64, String), SdkBridgeError> {
        self.sequence = self
            .sequence
            .checked_add(1)
            .ok_or(SdkBridgeError::Storage)?;
        Ok((
            self.sequence,
            format!(
                "sdk:{}:{}",
                self.context.request_id().as_str(),
                self.sequence
            ),
        ))
    }
    fn record(&self, value: &Secret, key: Option<&str>) -> Result<SdkStorageEntry, SdkBridgeError> {
        let value: Value =
            serde_json::from_slice(value.expose()).map_err(|_| SdkBridgeError::Storage)?;
        let name = value
            .get("key")
            .and_then(Value::as_str)
            .ok_or(SdkBridgeError::Storage)?;
        validate_key(name)?;
        if value.get("format").and_then(Value::as_u64) != Some(1)
            || value.get("owner").and_then(Value::as_str) != Some(self.scope.owner_digest.as_str())
            || key.is_some_and(|key| key != name)
        {
            return Err(SdkBridgeError::Storage);
        }
        let raw = value
            .get("value_hex")
            .and_then(Value::as_str)
            .ok_or(SdkBridgeError::Storage)?;
        let bytes = unhex(raw)?;
        Ok(SdkStorageEntry {
            key: name.to_owned(),
            value: bytes,
            seal_wrap: value
                .get("seal_wrap")
                .and_then(Value::as_bool)
                .ok_or(SdkBridgeError::Storage)?,
        })
    }
}
impl<B: Barrier, P: DurableBackend> SdkStorage for SdkDurableStorage<'_, B, P> {
    fn get(
        &mut self,
        key: &str,
        deadline: Instant,
    ) -> Result<Option<SdkStorageEntry>, SdkBridgeError> {
        self.gate(deadline)?;
        validate_key(key)?;
        self.durable
            .get(&self.scope.namespace, &resource(key))
            .map_err(durable_error)?
            .as_ref()
            .map(|v| self.record(v, Some(key)))
            .transpose()
    }
    fn put(&mut self, entry: SdkStorageEntry, deadline: Instant) -> Result<(), SdkBridgeError> {
        self.gate(deadline)?;
        validate_key(&entry.key)?;
        if entry.value.len() > 256 * 1024 {
            return Err(SdkBridgeError::Storage);
        }
        let payload=Zeroizing::new(serde_json::to_vec(&json!({"format":1,"owner":self.scope.owner_digest,"key":entry.key,"value_hex":hex(&entry.value),"seal_wrap":entry.seal_wrap})).map_err(|_|SdkBridgeError::Storage)?);
        let (sequence, request_id) = self.next_request()?;
        let request = PutRequest::new(
            self.context.principal().as_str(),
            &self.scope.namespace,
            request_id,
            resource(&entry.key),
            *self.context.authorization_digest(),
            Secret::new(payload.to_vec()).map_err(|_| SdkBridgeError::Storage)?,
        )
        .map_err(|_| SdkBridgeError::Storage)?;
        let outcome = self.durable.put(request).map_err(durable_error)?;
        self.mutations.push(SdkStorageMutation {
            sequence,
            operation: "put",
            outcome,
        });
        if Instant::now() >= deadline {
            return Err(SdkBridgeError::OutcomeUnknown);
        }
        Ok(())
    }
    fn delete(&mut self, key: &str, deadline: Instant) -> Result<(), SdkBridgeError> {
        self.gate(deadline)?;
        validate_key(key)?;
        let (sequence, request_id) = self.next_request()?;
        let request = DeleteRequest::new(
            self.context.principal().as_str(),
            &self.scope.namespace,
            request_id,
            resource(key),
            *self.context.authorization_digest(),
        )
        .map_err(|_| SdkBridgeError::Storage)?;
        let outcome = self.durable.delete(request).map_err(durable_error)?;
        self.mutations.push(SdkStorageMutation {
            sequence,
            operation: "delete",
            outcome,
        });
        if Instant::now() >= deadline {
            return Err(SdkBridgeError::OutcomeUnknown);
        }
        Ok(())
    }
    fn list_page(
        &mut self,
        prefix: &str,
        after: &str,
        limit: i64,
        deadline: Instant,
    ) -> Result<Vec<String>, SdkBridgeError> {
        self.gate(deadline)?;
        if prefix.len() > 4096
            || prefix.contains('\0')
            || after.len() > 4096
            || after.contains('\0')
        {
            return Err(SdkBridgeError::Storage);
        }
        let mut keys = BTreeSet::new();
        let entries = self
            .durable
            .list(&self.scope.namespace, "entries")
            .map_err(durable_error)?;
        if entries.len() > 10000 {
            return Err(SdkBridgeError::Storage);
        }
        for hash in entries {
            self.gate(deadline)?;
            if hash.len() != 64
                || !hash
                    .bytes()
                    .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
            {
                return Err(SdkBridgeError::Storage);
            }
            let value = self
                .durable
                .get(&self.scope.namespace, &format!("entries/{hash}"))
                .map_err(durable_error)?
                .ok_or(SdkBridgeError::Storage)?;
            let entry = self.record(&value, None)?;
            if resource(&entry.key) != format!("entries/{hash}") {
                return Err(SdkBridgeError::Storage);
            }
            if let Some(suffix) = entry.key.strip_prefix(prefix) {
                let child = suffix
                    .find('/')
                    .map_or_else(|| suffix.to_owned(), |i| suffix[..=i].to_owned());
                if after.is_empty() || child.as_str() > after {
                    keys.insert(child);
                }
            }
        }
        let limit = if limit <= 0 {
            usize::MAX
        } else {
            usize::try_from(limit).map_err(|_| SdkBridgeError::Storage)?
        };
        Ok(keys.into_iter().take(limit).collect())
    }
}
fn durable_error(error: ServiceError) -> SdkBridgeError {
    match error {
        ServiceError::OutcomeUnknown { .. } => SdkBridgeError::OutcomeUnknown,
        ServiceError::RecoveryRequired => SdkBridgeError::Fenced,
        _ => SdkBridgeError::Storage,
    }
}
fn validate_key(key: &str) -> Result<(), SdkBridgeError> {
    if key.is_empty() || key.len() > 4096 || key.contains('\0') {
        Err(SdkBridgeError::Storage)
    } else {
        Ok(())
    }
}
fn resource(key: &str) -> String {
    format!("entries/{}", hex(digest(&SHA256, key.as_bytes()).as_ref()))
}
fn hex(value: &[u8]) -> String {
    value.iter().map(|v| format!("{v:02x}")).collect()
}
fn unhex(value: &str) -> Result<Zeroizing<Vec<u8>>, SdkBridgeError> {
    if value.len() > 512 * 1024 || !value.len().is_multiple_of(2) {
        return Err(SdkBridgeError::Storage);
    }
    value
        .as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| {
            std::str::from_utf8(pair)
                .ok()
                .and_then(|s| u8::from_str_radix(s, 16).ok())
                .ok_or(SdkBridgeError::Storage)
        })
        .collect::<Result<Vec<_>, _>>()
        .map(Zeroizing::new)
}
