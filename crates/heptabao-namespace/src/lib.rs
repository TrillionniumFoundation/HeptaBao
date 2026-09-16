#![forbid(unsafe_code)]
#![deny(missing_debug_implementations)]

//! Hierarchical namespace ownership and path isolation.

use std::collections::BTreeMap;
use std::error::Error;
use std::fmt;

use heptabao_domain::{CanonicalPath, DomainError, Id};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NamespaceState {
    Active,
    Disabled,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Namespace {
    id: Id,
    parent_id: Option<Id>,
    path: CanonicalPath,
    state: NamespaceState,
    generation: u64,
}

impl Namespace {
    pub fn id(&self) -> &Id {
        &self.id
    }

    pub fn parent_id(&self) -> Option<&Id> {
        self.parent_id.as_ref()
    }

    pub fn path(&self) -> &CanonicalPath {
        &self.path
    }

    pub fn state(&self) -> NamespaceState {
        self.state
    }

    pub fn generation(&self) -> u64 {
        self.generation
    }
}

#[derive(Debug, Default)]
pub struct NamespaceStore {
    namespaces: BTreeMap<Id, Namespace>,
    path_index: BTreeMap<CanonicalPath, Id>,
}

impl NamespaceStore {
    pub fn bootstrap_root(&mut self, id: Id) -> Result<(), NamespaceError> {
        if !self.namespaces.is_empty() {
            return Err(NamespaceError::RootAlreadyExists);
        }
        let path = CanonicalPath::root();
        self.path_index.insert(path.clone(), id.clone());
        self.namespaces.insert(
            id.clone(),
            Namespace {
                id,
                parent_id: None,
                path,
                state: NamespaceState::Active,
                generation: 1,
            },
        );
        Ok(())
    }

    pub fn create(&mut self, id: Id, parent_id: &Id) -> Result<Namespace, NamespaceError> {
        if self.namespaces.contains_key(&id) {
            return Err(NamespaceError::DuplicateNamespace);
        }
        let parent = self
            .namespaces
            .get(parent_id)
            .ok_or(NamespaceError::MissingParent)?;
        if parent.state != NamespaceState::Active {
            return Err(NamespaceError::ParentDisabled);
        }
        let path = parent.path.child(&id).map_err(NamespaceError::Domain)?;
        if self.path_index.contains_key(&path) {
            return Err(NamespaceError::DuplicatePath);
        }
        let namespace = Namespace {
            id: id.clone(),
            parent_id: Some(parent_id.clone()),
            path: path.clone(),
            state: NamespaceState::Active,
            generation: 1,
        };
        self.path_index.insert(path, id.clone());
        self.namespaces.insert(id, namespace.clone());
        Ok(namespace)
    }

    pub fn get(&self, id: &Id) -> Result<&Namespace, NamespaceError> {
        self.namespaces
            .get(id)
            .ok_or(NamespaceError::MissingNamespace)
    }

    pub fn disable(&mut self, id: &Id) -> Result<(), NamespaceError> {
        let namespace = self
            .namespaces
            .get_mut(id)
            .ok_or(NamespaceError::MissingNamespace)?;
        if namespace.parent_id.is_none() {
            return Err(NamespaceError::CannotDisableRoot);
        }
        if namespace.state == NamespaceState::Disabled {
            return Err(NamespaceError::AlreadyDisabled);
        }
        namespace.state = NamespaceState::Disabled;
        namespace.generation = namespace.generation.saturating_add(1);
        Ok(())
    }

    pub fn resolve(&self, path: &CanonicalPath) -> Result<&Namespace, NamespaceError> {
        self.namespaces
            .values()
            .filter(|namespace| {
                namespace.state == NamespaceState::Active && path.matches_prefix(&namespace.path)
            })
            .max_by_key(|namespace| namespace.path.as_str().len())
            .ok_or(NamespaceError::MissingNamespace)
    }

    /// Seals a namespace and every descendant in one deterministic transition.
    ///
    /// A sealed subtree cannot be used for strict path resolution or qualification.
    /// The root namespace is intentionally excluded because sealing it would make
    /// the entire control plane unreachable; callers must use the service seal API
    /// for that operation.
    pub fn seal_subtree(&mut self, id: &Id) -> Result<Vec<Id>, NamespaceError> {
        let target = self
            .namespaces
            .get(id)
            .ok_or(NamespaceError::MissingNamespace)?;
        if target.parent_id.is_none() {
            return Err(NamespaceError::CannotDisableRoot);
        }
        if target.state == NamespaceState::Disabled {
            return Err(NamespaceError::AlreadyDisabled);
        }

        let target_path = target.path.clone();
        let mut sealed = Vec::new();
        for namespace in self.namespaces.values_mut() {
            let descendant = namespace.id == *id || namespace.path.matches_prefix(&target_path);
            if descendant && namespace.state == NamespaceState::Active {
                namespace.state = NamespaceState::Disabled;
                namespace.generation = namespace.generation.saturating_add(1);
                sealed.push(namespace.id.clone());
            }
        }
        sealed.sort_by(|left, right| left.as_str().cmp(right.as_str()));
        Ok(sealed)
    }

    /// Resolves a path while enforcing that every namespace in its ancestry is active.
    /// This closes the disabled-subtree fallback that `resolve` deliberately preserves
    /// for legacy callers.
    pub fn resolve_strict(&self, path: &CanonicalPath) -> Result<&Namespace, NamespaceError> {
        let namespace = self
            .namespaces
            .values()
            .filter(|candidate| path.matches_prefix(&candidate.path))
            .max_by_key(|candidate| candidate.path.as_str().len())
            .ok_or(NamespaceError::MissingNamespace)?;
        let mut cursor = Some(namespace.id());
        while let Some(id) = cursor {
            let ancestor = self
                .namespaces
                .get(id)
                .ok_or(NamespaceError::MissingNamespace)?;
            if ancestor.state != NamespaceState::Active {
                return Err(NamespaceError::NamespaceDisabled);
            }
            cursor = ancestor.parent_id.as_ref();
        }
        Ok(namespace)
    }

    pub fn qualify(
        &self,
        namespace_id: &Id,
        resource_path: &CanonicalPath,
    ) -> Result<CanonicalPath, NamespaceError> {
        let namespace = self.get(namespace_id)?;
        if namespace.state != NamespaceState::Active {
            return Err(NamespaceError::NamespaceDisabled);
        }
        if resource_path.as_str() == "/" {
            return Ok(namespace.path.clone());
        }
        let suffix = resource_path
            .as_str()
            .strip_prefix('/')
            .ok_or(NamespaceError::InvalidResourcePath)?;
        CanonicalPath::parse(format!(
            "{}/{}",
            namespace.path.as_str().trim_end_matches('/'),
            suffix
        ))
        .map_err(NamespaceError::Domain)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NamespaceError {
    RootAlreadyExists,
    DuplicateNamespace,
    DuplicatePath,
    MissingNamespace,
    MissingParent,
    ParentDisabled,
    NamespaceDisabled,
    CannotDisableRoot,
    AlreadyDisabled,
    InvalidResourcePath,
    Domain(DomainError),
}

impl fmt::Display for NamespaceError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::RootAlreadyExists => "root namespace already exists",
            Self::DuplicateNamespace => "namespace already exists",
            Self::DuplicatePath => "namespace path already exists",
            Self::MissingNamespace => "namespace does not exist",
            Self::MissingParent => "parent namespace does not exist",
            Self::ParentDisabled => "parent namespace is disabled",
            Self::NamespaceDisabled => "namespace is disabled",
            Self::CannotDisableRoot => "root namespace cannot be disabled",
            Self::AlreadyDisabled => "namespace is already disabled",
            Self::InvalidResourcePath => "resource path is invalid",
            Self::Domain(_) => "namespace path construction failed",
        })
    }
}

impl Error for NamespaceError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hierarchy_and_longest_prefix_resolution_are_deterministic() -> Result<(), Box<dyn Error>> {
        let root = Id::parse("root")?;
        let team = Id::parse("team")?;
        let app = Id::parse("app")?;
        let mut store = NamespaceStore::default();
        store.bootstrap_root(root.clone())?;
        store.create(team.clone(), &root)?;
        store.create(app.clone(), &team)?;
        let resolved = store.resolve(&CanonicalPath::parse("/team/app/secret/config")?)?;
        assert_eq!(&app, resolved.id());
        let qualified = store.qualify(&app, &CanonicalPath::parse("/secret/config")?)?;
        assert_eq!("/team/app/secret/config", qualified.as_str());
        Ok(())
    }

    #[test]
    fn disabled_namespace_fails_closed() -> Result<(), Box<dyn Error>> {
        let root = Id::parse("root")?;
        let child = Id::parse("child")?;
        let mut store = NamespaceStore::default();
        store.bootstrap_root(root.clone())?;
        store.create(child.clone(), &root)?;
        store.disable(&child)?;
        assert_eq!(
            Err(NamespaceError::NamespaceDisabled),
            store.qualify(&child, &CanonicalPath::parse("/secret")?)
        );
        assert_eq!(Err(NamespaceError::CannotDisableRoot), store.disable(&root));
        Ok(())
    }
    #[test]
    fn seal_subtree_disables_descendants_and_strict_resolution_fails_closed()
    -> Result<(), Box<dyn Error>> {
        let root = Id::parse("root")?;
        let team = Id::parse("team")?;
        let app = Id::parse("app")?;
        let sibling = Id::parse("sibling")?;
        let mut store = NamespaceStore::default();
        store.bootstrap_root(root.clone())?;
        store.create(team.clone(), &root)?;
        store.create(app.clone(), &team)?;
        store.create(sibling.clone(), &root)?;

        let sealed = store.seal_subtree(&team)?;
        assert_eq!(vec![app.clone(), team.clone()], sealed);
        assert_eq!(NamespaceState::Disabled, store.get(&team)?.state());
        assert_eq!(NamespaceState::Disabled, store.get(&app)?.state());
        assert_eq!(NamespaceState::Active, store.get(&sibling)?.state());
        assert_eq!(
            Err(NamespaceError::NamespaceDisabled),
            store.resolve_strict(&CanonicalPath::parse("/team/app/secret")?)
        );
        assert_eq!(
            &sibling,
            store
                .resolve_strict(&CanonicalPath::parse("/sibling/secret")?)?
                .id()
        );
        assert_eq!(
            Err(NamespaceError::AlreadyDisabled),
            store.seal_subtree(&team)
        );
        assert_eq!(
            Err(NamespaceError::CannotDisableRoot),
            store.seal_subtree(&root)
        );
        Ok(())
    }
}
