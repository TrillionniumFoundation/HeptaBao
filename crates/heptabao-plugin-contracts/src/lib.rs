#![forbid(unsafe_code)]
#![deny(missing_debug_implementations)]

//! Plugin registration, lifecycle and call-outcome contracts.

use std::collections::BTreeMap;
use std::error::Error;
use std::fmt;

use heptabao_domain::{CanonicalPath, Id};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PluginKind {
    Secrets,
    Authentication,
    Database,
    Audit,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PluginStatus {
    Registered,
    Enabled,
    Disabled,
    Revoked,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PluginDescriptor {
    id: Id,
    kind: PluginKind,
    command: CanonicalPath,
    checksum: [u8; 32],
    protocol_version: u16,
    status: PluginStatus,
    generation: u64,
}

impl PluginDescriptor {
    pub fn new(
        id: Id,
        kind: PluginKind,
        command: CanonicalPath,
        checksum: [u8; 32],
        protocol_version: u16,
    ) -> Result<Self, PluginError> {
        if checksum == [0; 32] {
            return Err(PluginError::InvalidChecksum);
        }
        if protocol_version == 0 {
            return Err(PluginError::InvalidProtocolVersion);
        }
        Ok(Self {
            id,
            kind,
            command,
            checksum,
            protocol_version,
            status: PluginStatus::Registered,
            generation: 1,
        })
    }

    pub fn id(&self) -> &Id {
        &self.id
    }

    pub fn status(&self) -> PluginStatus {
        self.status
    }

    pub fn generation(&self) -> u64 {
        self.generation
    }

    pub fn kind(&self) -> PluginKind {
        self.kind
    }

    pub fn command(&self) -> &CanonicalPath {
        &self.command
    }

    pub fn checksum(&self) -> &[u8; 32] {
        &self.checksum
    }

    pub fn protocol_version(&self) -> u16 {
        self.protocol_version
    }

    /// Build a candidate descriptor for a rolling replacement.
    ///
    /// The candidate is deliberately returned in `Registered` state.  A
    /// registry (or another admission controller) must verify the new
    /// executable before enabling it.  Generation is monotonic and therefore
    /// lets callers fence stale in-flight invocations after the swap.
    pub fn replacement(
        &self,
        command: CanonicalPath,
        checksum: [u8; 32],
        protocol_version: u16,
    ) -> Result<Self, PluginError> {
        if checksum == [0; 32] {
            return Err(PluginError::InvalidChecksum);
        }
        if protocol_version == 0 {
            return Err(PluginError::InvalidProtocolVersion);
        }
        let generation = self
            .generation
            .checked_add(1)
            .ok_or(PluginError::GenerationOverflow)?;
        Ok(Self {
            id: self.id.clone(),
            kind: self.kind,
            command,
            checksum,
            protocol_version,
            status: PluginStatus::Registered,
            generation,
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PluginCallOutcome<T> {
    BeforeEntryFailure,
    Completed(T),
    OutcomeUnknownAfterEntry { recovery_reference: Id },
}

#[derive(Debug, Default)]
pub struct PluginRegistry {
    plugins: BTreeMap<Id, PluginDescriptor>,
}

impl PluginRegistry {
    pub fn register(&mut self, plugin: PluginDescriptor) -> Result<(), PluginError> {
        if self.plugins.contains_key(plugin.id()) {
            return Err(PluginError::DuplicatePlugin);
        }
        self.plugins.insert(plugin.id().clone(), plugin);
        Ok(())
    }

    pub fn get(&self, id: &Id) -> Result<&PluginDescriptor, PluginError> {
        self.plugins.get(id).ok_or(PluginError::MissingPlugin)
    }

    pub fn enable(&mut self, id: &Id) -> Result<(), PluginError> {
        let plugin = self.plugins.get_mut(id).ok_or(PluginError::MissingPlugin)?;
        if !matches!(
            plugin.status,
            PluginStatus::Registered | PluginStatus::Disabled
        ) {
            return Err(PluginError::InvalidTransition);
        }
        plugin.status = PluginStatus::Enabled;
        plugin.generation = plugin.generation.saturating_add(1);
        Ok(())
    }

    pub fn disable(&mut self, id: &Id) -> Result<(), PluginError> {
        let plugin = self.plugins.get_mut(id).ok_or(PluginError::MissingPlugin)?;
        if plugin.status != PluginStatus::Enabled {
            return Err(PluginError::InvalidTransition);
        }
        plugin.status = PluginStatus::Disabled;
        plugin.generation = plugin.generation.saturating_add(1);
        Ok(())
    }

    pub fn revoke(&mut self, id: &Id) -> Result<(), PluginError> {
        let plugin = self.plugins.get_mut(id).ok_or(PluginError::MissingPlugin)?;
        if plugin.status == PluginStatus::Revoked {
            return Err(PluginError::InvalidTransition);
        }
        plugin.status = PluginStatus::Revoked;
        plugin.generation = plugin.generation.saturating_add(1);
        Ok(())
    }

    /// Atomically install an admitted replacement while keeping the plugin ID.
    ///
    /// The old descriptor must be enabled and the candidate must have been
    /// produced by `PluginDescriptor::replacement`.  The candidate is enabled
    /// only at the commit point, so a failed external admission leaves the old
    /// descriptor untouched.  This is registry lifecycle support; it does not
    /// itself drain processes, migrate leases or qualify a provider sandbox.
    pub fn upgrade(
        &mut self,
        id: &Id,
        mut replacement: PluginDescriptor,
    ) -> Result<(), PluginError> {
        let current = self.plugins.get(id).ok_or(PluginError::MissingPlugin)?;
        if current.status != PluginStatus::Enabled
            || replacement.id() != id
            || replacement.kind() != current.kind
            || replacement.status() != PluginStatus::Registered
            || replacement.generation() <= current.generation
        {
            return Err(PluginError::InvalidTransition);
        }
        replacement.status = PluginStatus::Enabled;
        self.plugins.insert(id.clone(), replacement);
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PluginError {
    InvalidChecksum,
    InvalidProtocolVersion,
    DuplicatePlugin,
    MissingPlugin,
    InvalidTransition,
    GenerationOverflow,
}

impl fmt::Display for PluginError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidChecksum => "plugin checksum is invalid",
            Self::InvalidProtocolVersion => "plugin protocol version is invalid",
            Self::DuplicatePlugin => "plugin already exists",
            Self::MissingPlugin => "plugin does not exist",
            Self::InvalidTransition => "plugin lifecycle transition is invalid",
            Self::GenerationOverflow => "plugin generation overflowed",
        })
    }
}

impl Error for PluginError {}

#[cfg(test)]
mod tests {
    use super::*;

    fn descriptor() -> Result<PluginDescriptor, Box<dyn Error>> {
        Ok(PluginDescriptor::new(
            Id::parse("database_plugin")?,
            PluginKind::Database,
            CanonicalPath::parse("/opt/heptabao/plugins/database")?,
            [7; 32],
            1,
        )?)
    }

    #[test]
    fn lifecycle_is_monotonic_after_revocation() -> Result<(), Box<dyn Error>> {
        let plugin = descriptor()?;
        let id = plugin.id().clone();
        let mut registry = PluginRegistry::default();
        registry.register(plugin)?;
        registry.enable(&id)?;
        registry.disable(&id)?;
        registry.enable(&id)?;
        registry.revoke(&id)?;
        assert_eq!(PluginStatus::Revoked, registry.get(&id)?.status());
        assert_eq!(Err(PluginError::InvalidTransition), registry.enable(&id));
        Ok(())
    }

    #[test]
    fn invalid_descriptor_is_rejected_before_registration() -> Result<(), Box<dyn Error>> {
        assert_eq!(
            Err(PluginError::InvalidChecksum),
            PluginDescriptor::new(
                Id::parse("bad_plugin")?,
                PluginKind::Secrets,
                CanonicalPath::parse("/plugin")?,
                [0; 32],
                1,
            )
        );
        Ok(())
    }

    #[test]
    fn replacement_is_monotonic_and_upgrade_is_atomic() -> Result<(), Box<dyn Error>> {
        let plugin = descriptor()?;
        let id = plugin.id().clone();
        let mut registry = PluginRegistry::default();
        registry.register(plugin.clone())?;
        registry.enable(&id)?;
        let candidate = registry.get(&id)?.replacement(
            CanonicalPath::parse("/opt/heptabao/plugins/database-v2")?,
            [9; 32],
            2,
        )?;
        assert_eq!(candidate.status(), PluginStatus::Registered);
        assert_eq!(candidate.generation(), registry.get(&id)?.generation() + 1);
        registry.upgrade(&id, candidate)?;
        let active = registry.get(&id)?;
        assert_eq!(active.status(), PluginStatus::Enabled);
        assert_eq!(active.protocol_version(), 2);
        assert_eq!(active.checksum(), &[9; 32]);

        let bad = PluginDescriptor::new(
            id.clone(),
            PluginKind::Secrets,
            CanonicalPath::parse("/opt/heptabao/plugins/wrong-kind")?,
            [8; 32],
            1,
        )?;
        assert_eq!(
            Err(PluginError::InvalidTransition),
            registry.upgrade(&id, bad)
        );
        assert_eq!(PluginStatus::Enabled, registry.get(&id)?.status());
        Ok(())
    }
}
