#![forbid(unsafe_code)]
#![deny(missing_debug_implementations)]

//! Namespace-scoped longest-prefix mount routing.

use std::collections::BTreeMap;
use std::error::Error;
use std::fmt;

use heptabao_domain::{CanonicalPath, Id};

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Backend {
    Kv,
    Plugin(Id),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Mount {
    id: Id,
    namespace_id: Id,
    path: CanonicalPath,
    backend: Backend,
    enabled: bool,
    generation: u64,
}

impl Mount {
    pub fn id(&self) -> &Id {
        &self.id
    }

    pub fn namespace_id(&self) -> &Id {
        &self.namespace_id
    }

    pub fn path(&self) -> &CanonicalPath {
        &self.path
    }

    pub fn backend(&self) -> &Backend {
        &self.backend
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Route {
    pub mount_id: Id,
    pub backend: Backend,
    pub relative_path: String,
    pub mount_generation: u64,
}

#[derive(Debug, Default)]
pub struct MountRouter {
    mounts: BTreeMap<Id, Mount>,
}

impl MountRouter {
    pub fn mount(
        &mut self,
        id: Id,
        namespace_id: Id,
        path: CanonicalPath,
        backend: Backend,
    ) -> Result<Mount, MountError> {
        if self.mounts.contains_key(&id) {
            return Err(MountError::DuplicateMount);
        }
        if self
            .mounts
            .values()
            .any(|mount| mount.namespace_id == namespace_id && mount.path == path)
        {
            return Err(MountError::DuplicatePath);
        }
        let mount = Mount {
            id: id.clone(),
            namespace_id,
            path,
            backend,
            enabled: true,
            generation: 1,
        };
        self.mounts.insert(id, mount.clone());
        Ok(mount)
    }

    pub fn set_enabled(&mut self, id: &Id, enabled: bool) -> Result<(), MountError> {
        let mount = self.mounts.get_mut(id).ok_or(MountError::MissingMount)?;
        if mount.enabled == enabled {
            return Err(MountError::NoStateChange);
        }
        mount.enabled = enabled;
        mount.generation = mount.generation.saturating_add(1);
        Ok(())
    }

    pub fn unmount(&mut self, id: &Id) -> Result<Mount, MountError> {
        self.mounts.remove(id).ok_or(MountError::MissingMount)
    }

    pub fn route(
        &self,
        namespace_id: &Id,
        path: &CanonicalPath,
    ) -> Result<Route, MountError> {
        let mount = self
            .mounts
            .values()
            .filter(|mount| {
                mount.enabled
                    && &mount.namespace_id == namespace_id
                    && path.matches_prefix(&mount.path)
            })
            .max_by_key(|mount| mount.path.as_str().len())
            .ok_or(MountError::NoRoute)?;
        let relative = path
            .relative_to(&mount.path)
            .ok_or(MountError::NoRoute)?
            .to_owned();
        Ok(Route {
            mount_id: mount.id.clone(),
            backend: mount.backend.clone(),
            relative_path: relative,
            mount_generation: mount.generation,
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MountError {
    DuplicateMount,
    DuplicatePath,
    MissingMount,
    NoRoute,
    NoStateChange,
}

impl fmt::Display for MountError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::DuplicateMount => "mount already exists",
            Self::DuplicatePath => "mount path already exists in namespace",
            Self::MissingMount => "mount does not exist",
            Self::NoRoute => "no enabled mount matches the request",
            Self::NoStateChange => "mount state is unchanged",
        })
    }
}

impl Error for MountError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn longest_prefix_wins_within_namespace() -> Result<(), Box<dyn Error>> {
        let namespace = Id::parse("root")?;
        let mut router = MountRouter::default();
        router.mount(
            Id::parse("secret")?,
            namespace.clone(),
            CanonicalPath::parse("/secret")?,
            Backend::Kv,
        )?;
        let plugin = Id::parse("database_plugin")?;
        router.mount(
            Id::parse("database")?,
            namespace.clone(),
            CanonicalPath::parse("/secret/database")?,
            Backend::Plugin(plugin.clone()),
        )?;
        let route = router.route(
            &namespace,
            &CanonicalPath::parse("/secret/database/creds/read")?,
        )?;
        assert_eq!(Backend::Plugin(plugin), route.backend);
        assert_eq!("creds/read", route.relative_path);
        Ok(())
    }

    #[test]
    fn namespace_and_enablement_are_fail_closed() -> Result<(), Box<dyn Error>> {
        let root = Id::parse("root")?;
        let mount_id = Id::parse("secret")?;
        let mut router = MountRouter::default();
        router.mount(
            mount_id.clone(),
            root.clone(),
            CanonicalPath::parse("/secret")?,
            Backend::Kv,
        )?;
        assert_eq!(
            Err(MountError::NoRoute),
            router.route(&Id::parse("other")?, &CanonicalPath::parse("/secret/a")?)
        );
        router.set_enabled(&mount_id, false)?;
        assert_eq!(
            Err(MountError::NoRoute),
            router.route(&root, &CanonicalPath::parse("/secret/a")?)
        );
        Ok(())
    }
}
