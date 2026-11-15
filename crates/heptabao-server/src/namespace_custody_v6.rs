//! Actual namespace-key V6 domains; never a root-key substitute.
use super::*;
use crate::engines::kv2_native_records::NativeScope;
use crate::state_records::{AddressKey, Kv1Key, RecordError};
use crate::v6_record_resources::{CipherDomain, CipherReference};
use std::sync::Arc;
use zeroize::Zeroize;

impl Key {
    pub(crate) fn matches_v6_frontier(
        &self,
        frontier: &crate::v6_native_custody::NamespaceFrontier,
    ) -> bool {
        self.matches_binding(&frontier.binding)
            && self.key_epoch == frontier.key_epoch
            && frontier.seal_frontier != 0
    }
    pub(crate) fn v6_parent_key(
        &self,
        cluster: &str,
        epoch: u64,
        namespace: &str,
    ) -> Result<Arc<AddressKey>, RecordError> {
        self.binding
            .validate_cluster_namespace(cluster, self.binding.namespace())
            .map_err(|_| RecordError::Invalid)?;
        if namespace.len() > 1024 || !self.owns_namespace(namespace) {
            return Err(RecordError::Invalid);
        }
        let context = self
            .record_context(namespace, &[0; 32])
            .map_err(|_| RecordError::Invalid)?;
        let mut material = Zeroizing::new(b"HeptaBao/v6/namespace-native-parent\0".to_vec());
        material.extend_from_slice(&epoch.to_be_bytes());
        material.extend_from_slice(&context);
        let mac = ring::hmac::Key::new(ring::hmac::HMAC_SHA256, self.bytes.as_slice());
        let mut derived: [u8; 32] = ring::hmac::sign(&mac, &material)
            .as_ref()
            .try_into()
            .map_err(|_| RecordError::Corrupt)?;
        let key = AddressKey::from_bytes(derived);
        derived.zeroize();
        Ok(key)
    }
    pub(crate) fn v6_domain(
        &self,
        cluster: &str,
        epoch: u64,
        scope: NativeScope<'_>,
    ) -> Result<CipherDomain, RecordError> {
        Kv1Key::new(scope.namespace, scope.mount, scope.incarnation, "scope")?;
        let parent = self.v6_parent_key(cluster, epoch, scope.namespace)?;
        let binding =
            crate::secret_serde::to_vec(&self.binding, 4096).map_err(|_| RecordError::Invalid)?;
        let mut identity = Zeroizing::new(binding.to_vec());
        identity.extend_from_slice(&self.key_epoch.to_be_bytes());
        let owner = parent.digest(b"state-v6/custody-owner", &identity)?;
        let scope_bytes = crate::secret_serde::to_vec(
            &(scope.namespace, scope.mount, scope.incarnation),
            16 * 1024,
        )
        .map_err(|_| RecordError::Invalid)?;
        Ok(CipherDomain::NamespaceKv2 {
            owner,
            scope: parent.digest(b"state-v6/custody-scope", &scope_bytes)?,
        })
    }
    pub(crate) fn protect_v6_object(
        &self,
        cluster: &str,
        epoch: u64,
        scope: NativeScope<'_>,
        reference: &CipherReference,
        bytes: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, RecordError> {
        if reference.domain != self.v6_domain(cluster, epoch, scope)?
            || bytes.len() != reference.encoded_bytes as usize
        {
            return Err(RecordError::Invalid);
        }
        let context = reference.aad(cluster, epoch)?;
        let barrier = AeadBarrier::new(*self.bytes).map_err(|_| RecordError::Corrupt)?;
        barrier
            .seal(&context, bytes)
            .map(Zeroizing::new)
            .map_err(|_| RecordError::Corrupt)
    }
    pub(crate) fn open_v6_object(
        &self,
        cluster: &str,
        epoch: u64,
        scope: NativeScope<'_>,
        reference: &CipherReference,
        bytes: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, RecordError> {
        if reference.domain != self.v6_domain(cluster, epoch, scope)?
            || bytes.len() != reference.encoded_bytes as usize + 32
        {
            return Err(RecordError::Corrupt);
        }
        let context = reference.aad(cluster, epoch)?;
        let barrier = AeadBarrier::new(*self.bytes).map_err(|_| RecordError::Corrupt)?;
        barrier
            .open(&context, bytes)
            .map(Zeroizing::new)
            .map_err(|_| RecordError::Corrupt)
    }
}
