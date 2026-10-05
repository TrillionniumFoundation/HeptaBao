//! Shareless custody for an ordinary namespace. These primitives authenticate
//! an actual parent/child owner and derive a private key; they grant no caller
//! principal and do not themselves unload or restore Service resources.
use super::{
    Binding, CUSTODY_SCHEMA, Error, Frontier, Key, MAX_ENCODING, Tombstone, VERSION,
    validate_assets,
};
use crate::crypto::AeadBarrier;
use base64::{Engine, engine::general_purpose::STANDARD};
use heptabao_durable_service::Barrier;
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

/// Actual custody from which the ordinary owner inherits. Root means the real
/// cluster barrier; Namespace means the actual enclosing authenticated key.
#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum InheritedParent {
    Root { cluster_id: String },
    Namespace { binding: Binding, key_epoch: u64 },
}

impl InheritedParent {
    fn root(actual: &Binding) -> Self {
        Self::Root {
            cluster_id: actual.cluster_id.clone(),
        }
    }

    fn namespace(parent: &Key) -> Self {
        Self::Namespace {
            binding: parent.binding.clone(),
            key_epoch: parent.key_epoch,
        }
    }

    fn validate(&self, actual: &Binding) -> Result<(), Error> {
        actual.validate()?;
        match self {
            Self::Root { cluster_id } if cluster_id == &actual.cluster_id => Ok(()),
            Self::Namespace { binding, key_epoch } => {
                binding.validate()?;
                if *key_epoch == 0
                    || binding.cluster_id != actual.cluster_id
                    || !actual
                        .namespace
                        .strip_prefix(&binding.namespace)
                        .is_some_and(|suffix| suffix.starts_with('/'))
                {
                    return Err(Error::InvalidBinding);
                }
                Ok(())
            }
            _ => Err(Error::InvalidBinding),
        }
    }
}

/// This owner has no independent unseal key, share count or progress. Its
/// ciphertext and all counters are bound to both actual owners. Service must
/// select the real longest parent and verify its durable frontier separately.
#[derive(Clone, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct InheritedDescriptor {
    version: u32,
    schema: u32,
    binding: Binding,
    parent: InheritedParent,
    generation: u64,
    seal_frontier: u64,
    protected_assets: String,
}

impl std::fmt::Debug for InheritedDescriptor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NamespaceInheritedDescriptor")
            .field("binding", &self.binding)
            .field("parent", &self.parent)
            .field("generation", &self.generation)
            .field("seal_frontier", &self.seal_frontier)
            .field("protected_assets", &"[REDACTED]")
            .finish()
    }
}

fn derive(actual: &Binding, parent: &InheritedParent, secret: &[u8]) -> Result<Key, Error> {
    parent.validate(actual)?;
    let mut context = b"heptabao-namespace-inherited-key-v1\0".to_vec();
    let owner = serde_json::to_vec(&(actual, parent)).map_err(|_| Error::InvalidBinding)?;
    context.extend_from_slice(&(owner.len() as u64).to_be_bytes());
    context.extend_from_slice(&owner);
    let mac = ring::hmac::Key::new(ring::hmac::HMAC_SHA256, secret);
    let bytes = ring::hmac::sign(&mac, &context)
        .as_ref()
        .try_into()
        .map_err(|_| Error::InvalidKey)?;
    Ok(Key {
        binding: actual.clone(),
        key_epoch: 1,
        bytes: Zeroizing::new(bytes),
    })
}

impl InheritedDescriptor {
    pub fn create_root(
        actual: Binding,
        root_key: &[u8; 32],
        assets: &[u8],
    ) -> Result<(Self, Key), Error> {
        let parent = InheritedParent::root(&actual);
        let key = derive(&actual, &parent, root_key)?;
        Self::create(actual, parent, key, assets)
    }

    pub fn create_namespace(
        actual: Binding,
        parent_key: &Key,
        assets: &[u8],
    ) -> Result<(Self, Key), Error> {
        let parent = InheritedParent::namespace(parent_key);
        let key = derive(&actual, &parent, parent_key.bytes.as_slice())?;
        Self::create(actual, parent, key, assets)
    }

    fn create(
        actual: Binding,
        parent: InheritedParent,
        key: Key,
        assets: &[u8],
    ) -> Result<(Self, Key), Error> {
        let mut descriptor = Self {
            version: VERSION,
            schema: CUSTODY_SCHEMA,
            binding: actual,
            parent,
            generation: 1,
            seal_frontier: 1,
            protected_assets: String::new(),
        };
        descriptor.encrypt(&key, assets)?;
        descriptor.validate(&key.binding)?;
        Ok((descriptor, key))
    }

    pub fn binding(&self) -> &Binding {
        &self.binding
    }

    pub fn parent(&self) -> &InheritedParent {
        &self.parent
    }

    pub fn generation(&self) -> u64 {
        self.generation
    }

    pub fn seal_frontier(&self) -> u64 {
        self.seal_frontier
    }

    pub(crate) fn frontier(&self) -> Frontier {
        let mut digest = ring::digest::Context::new(&ring::digest::SHA256);
        digest.update(b"heptabao-namespace-inherited-durable-floor-v1\0");
        fn field(digest: &mut ring::digest::Context, bytes: &[u8]) {
            digest.update(&(bytes.len() as u64).to_be_bytes());
            digest.update(bytes);
        }
        fn binding(digest: &mut ring::digest::Context, binding: &Binding) {
            for value in [
                &binding.cluster_id,
                &binding.namespace,
                &binding.namespace_id,
            ] {
                field(digest, value.as_bytes());
            }
            digest.update(&binding.incarnation.to_be_bytes());
        }
        binding(&mut digest, &self.binding);
        match &self.parent {
            InheritedParent::Root { cluster_id } => {
                digest.update(&[0]);
                field(&mut digest, cluster_id.as_bytes());
            }
            InheritedParent::Namespace {
                binding: parent,
                key_epoch,
            } => {
                digest.update(&[1]);
                binding(&mut digest, parent);
                digest.update(&key_epoch.to_be_bytes());
            }
        }
        digest.update(&self.version.to_be_bytes());
        digest.update(&self.schema.to_be_bytes());
        digest.update(&1u64.to_be_bytes());
        digest.update(&self.generation.to_be_bytes());
        digest.update(&self.seal_frontier.to_be_bytes());
        field(&mut digest, self.protected_assets.as_bytes());
        let descriptor_digest = digest
            .finish()
            .as_ref()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect();
        Frontier {
            version: VERSION,
            schema: CUSTODY_SCHEMA,
            binding: self.binding.clone(),
            key_epoch: 1,
            generation: self.generation,
            seal_frontier: self.seal_frontier,
            retired: false,
            descriptor_digest,
        }
    }

    pub fn admits_successor(&self, next: &Self) -> bool {
        self.binding == next.binding
            && self.parent == next.parent
            && next.generation >= self.generation
            && next.seal_frontier >= self.seal_frontier
            && (next.generation != self.generation || self == next)
    }

    pub(crate) fn retirement(&self) -> Tombstone {
        Tombstone {
            version: VERSION,
            schema: CUSTODY_SCHEMA,
            binding: self.binding.clone(),
            key_epoch: 1,
            seal_frontier: self.seal_frontier,
        }
    }

    pub fn validate(&self, actual: &Binding) -> Result<(), Error> {
        self.parent.validate(actual)?;
        if self.version != VERSION
            || self.schema != CUSTODY_SCHEMA
            || self.binding != *actual
            || self.generation == 0
            || self.seal_frontier == 0
            || self.protected_assets.is_empty()
            || self.protected_assets.len() > MAX_ENCODING
        {
            return Err(Error::CorruptDescriptor);
        }
        Ok(())
    }

    fn context(&self) -> Result<Vec<u8>, Error> {
        let owner = serde_json::to_vec(&(&self.binding, &self.parent))
            .map_err(|_| Error::InvalidBinding)?;
        let mut context = b"heptabao-namespace-inherited-assets-v1\0".to_vec();
        context.extend_from_slice(&(owner.len() as u64).to_be_bytes());
        context.extend_from_slice(&owner);
        context.extend_from_slice(&self.version.to_be_bytes());
        context.extend_from_slice(&self.schema.to_be_bytes());
        context.extend_from_slice(&self.generation.to_be_bytes());
        context.extend_from_slice(&self.seal_frontier.to_be_bytes());
        Ok(context)
    }

    fn encrypt(&mut self, key: &Key, assets: &[u8]) -> Result<(), Error> {
        validate_assets(assets)?;
        if !key.matches_binding(&self.binding) || key.key_epoch != 1 {
            return Err(Error::InvalidKey);
        }
        let barrier = AeadBarrier::new(*key.bytes).map_err(|_| Error::InvalidKey)?;
        let protected = Zeroizing::new(
            barrier
                .seal(&self.context()?, assets)
                .map_err(|_| Error::Randomness)?,
        );
        self.protected_assets = STANDARD.encode(protected.as_slice());
        Ok(())
    }

    pub fn open_assets(&self, actual: &Binding, key: &Key) -> Result<Zeroizing<Vec<u8>>, Error> {
        self.validate(actual)?;
        if !key.matches_binding(actual) || key.key_epoch != 1 {
            return Err(Error::InvalidKey);
        }
        let protected = Zeroizing::new(
            STANDARD
                .decode(&self.protected_assets)
                .map_err(|_| Error::CorruptDescriptor)?,
        );
        let barrier = AeadBarrier::new(*key.bytes).map_err(|_| Error::InvalidKey)?;
        let bytes = Zeroizing::new(
            barrier
                .open(&self.context()?, &protected)
                .map_err(|_| Error::InvalidKey)?,
        );
        validate_assets(&bytes)?;
        Ok(bytes)
    }

    pub fn open_root(
        &self,
        actual: &Binding,
        root_key: &[u8; 32],
    ) -> Result<(Key, Zeroizing<Vec<u8>>), Error> {
        self.validate(actual)?;
        if self.parent != InheritedParent::root(actual) {
            return Err(Error::InvalidBinding);
        }
        let key = derive(actual, &self.parent, root_key)?;
        let bytes = self.open_assets(actual, &key)?;
        Ok((key, bytes))
    }

    pub fn open_namespace(
        &self,
        actual: &Binding,
        parent_key: &Key,
    ) -> Result<(Key, Zeroizing<Vec<u8>>), Error> {
        self.validate(actual)?;
        if self.parent != InheritedParent::namespace(parent_key) {
            return Err(Error::InvalidBinding);
        }
        let key = derive(actual, &self.parent, parent_key.bytes.as_slice())?;
        let bytes = self.open_assets(actual, &key)?;
        Ok((key, bytes))
    }

    pub fn replace_assets(
        &self,
        actual: &Binding,
        key: &Key,
        assets: &[u8],
    ) -> Result<Self, Error> {
        // Authenticate the current owner before allowing a replacement.
        // A Key with the right public binding alone is insufficient.
        self.open_assets(actual, key)?;
        let mut next = self.clone();
        next.generation = next
            .generation
            .checked_add(1)
            .ok_or(Error::CorruptDescriptor)?;
        next.encrypt(key, assets)?;
        next.validate(actual)?;
        Ok(next)
    }

    pub fn advance_seal_frontier(&self, actual: &Binding, key: &Key) -> Result<Self, Error> {
        let assets = self.open_assets(actual, key)?;
        let mut next = self.clone();
        next.generation = next
            .generation
            .checked_add(1)
            .ok_or(Error::CorruptDescriptor)?;
        next.seal_frontier = next
            .seal_frontier
            .checked_add(1)
            .ok_or(Error::CorruptDescriptor)?;
        next.encrypt(key, &assets)?;
        next.validate(actual)?;
        Ok(next)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::namespace_custody::{Descriptor, Progress, Submission};
    type TestResult = Result<(), Box<dyn std::error::Error>>;

    fn binding(path: &str, incarnation: u64) -> Result<Binding, Error> {
        Binding::new(
            "public-test-cluster".into(),
            path.into(),
            format!("public-test-owner-{incarnation}"),
            incarnation,
        )
    }

    #[test]
    fn inherited_root_roundtrip_excludes_share_key_and_progress_fields() -> TestResult {
        let root = Zeroizing::new(crate::crypto::random::<32>()?);
        let actual = binding("ordinary", 1)?;
        let (descriptor, key) = InheritedDescriptor::create_root(actual.clone(), &root, b"public")?;
        let bytes = serde_json::to_vec(&descriptor)?;
        let value: serde_json::Value = serde_json::from_slice(&bytes)?;
        for field in [
            "shares",
            "threshold",
            "wrapped_key",
            "progress",
            "key",
            "bytes",
        ] {
            assert!(
                value.get(field).is_none(),
                "shareless owner contains no {field}"
            );
        }
        let stored: InheritedDescriptor = serde_json::from_slice(&bytes)?;
        let (_, opened) = stored.open_root(&actual, &root)?;
        assert!(
            opened.as_slice() == b"public"
                && stored.open_assets(&actual, &key)?.as_slice() == b"public"
        );
        assert!(format!("{stored:?}").contains("[REDACTED]"));
        Ok(())
    }

    #[test]
    fn inherited_root_rejects_wrong_key_actual_owner_and_parent_tampering() -> TestResult {
        let root = Zeroizing::new(crate::crypto::random::<32>()?);
        let other = Zeroizing::new(crate::crypto::random::<32>()?);
        let actual = binding("ordinary", 1)?;
        let (descriptor, _) = InheritedDescriptor::create_root(actual.clone(), &root, b"public")?;
        assert!(descriptor.open_root(&actual, &other).is_err());
        for wrong in [binding("ordinary", 2)?, binding("other", 1)?] {
            assert!(descriptor.open_root(&wrong, &root).is_err());
        }
        let mut wrong = actual.clone();
        wrong.cluster_id = "other-public-cluster".into();
        assert!(descriptor.open_root(&wrong, &root).is_err());
        let mut altered = descriptor.clone();
        altered.parent = InheritedParent::Root {
            cluster_id: "other-public-cluster".into(),
        };
        assert!(altered.open_root(&actual, &root).is_err());
        Ok(())
    }

    #[test]
    fn inherited_namespace_requires_the_actual_strict_ancestor_key() -> TestResult {
        let parent_binding = binding("parent", 1)?;
        let created = Descriptor::create(parent_binding.clone(), 3, 2, b"public-parent")?;
        let mut progress = Progress::new(parent_binding.clone(), &created.descriptor)?;
        progress.submit(&created.descriptor, &created.shares[0])?;
        let Submission::Unlocked { key: parent, .. } =
            progress.submit(&created.descriptor, &created.shares[1])?
        else {
            return Err("actual parent threshold".into());
        };
        let actual = binding("parent/ordinary", 1)?;
        let (descriptor, _) =
            InheritedDescriptor::create_namespace(actual.clone(), &parent, b"public-child")?;
        assert!(descriptor.open_namespace(&actual, &parent)?.1.as_slice() == b"public-child");
        for wrong in [
            binding("parent", 1)?,
            binding("parent-other/child", 1)?,
            binding("elsewhere", 1)?,
        ] {
            assert!(
                InheritedDescriptor::create_namespace(wrong, &parent, b"public-child").is_err()
            );
        }
        let root = Zeroizing::new(crate::crypto::random::<32>()?);
        assert!(descriptor.open_root(&actual, &root).is_err());
        let (_, different_parent) =
            InheritedDescriptor::create_root(parent_binding, &root, b"public")?;
        assert!(
            descriptor
                .open_namespace(&actual, &different_parent)
                .is_err()
        );
        Ok(())
    }

    #[test]
    fn inherited_counters_authenticate_and_replacement_requires_real_current_key() -> TestResult {
        let root = Zeroizing::new(crate::crypto::random::<32>()?);
        let other = Zeroizing::new(crate::crypto::random::<32>()?);
        let actual = binding("ordinary", 1)?;
        let (descriptor, key) = InheritedDescriptor::create_root(actual.clone(), &root, b"first")?;
        let (_, wrong_key) =
            InheritedDescriptor::create_root(actual.clone(), &other, b"unrelated")?;
        assert!(
            descriptor
                .replace_assets(&actual, &wrong_key, b"second")
                .is_err()
        );
        let changed = descriptor.replace_assets(&actual, &key, b"second")?;
        let closed = changed.advance_seal_frontier(&actual, &key)?;
        assert!(closed.generation() == 3 && closed.seal_frontier() == 2);
        assert!(closed.open_root(&actual, &root)?.1.as_slice() == b"second");
        for frontier in [false, true] {
            let mut altered = closed.clone();
            if frontier {
                altered.seal_frontier += 1;
            } else {
                altered.generation += 1;
            }
            assert!(altered.open_root(&actual, &root).is_err());
        }
        Ok(())
    }
}
