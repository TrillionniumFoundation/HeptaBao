#![forbid(unsafe_code)]
#![deny(missing_debug_implementations)]

//! Versioned in-memory KV engine with compare-and-set and tombstone semantics.

use std::collections::BTreeMap;
use std::error::Error;
use std::fmt;

use heptabao_domain::{CanonicalPath, SecretValue, Tick};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct KvMetadata {
    pub version: u64,
    pub created_at: Tick,
    pub deleted: bool,
    pub destroyed: bool,
}

#[derive(Eq, PartialEq)]
struct VersionRecord {
    metadata: KvMetadata,
    value: Option<SecretValue>,
}

impl fmt::Debug for VersionRecord {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("VersionRecord")
            .field("metadata", &self.metadata)
            .field("value", &self.value.as_ref().map(|value| value.len()))
            .finish()
    }
}

pub struct KvRead<'a> {
    pub metadata: KvMetadata,
    pub value: &'a [u8],
}

impl fmt::Debug for KvRead<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("KvRead")
            .field("metadata", &self.metadata)
            .field("value", &"[REDACTED]")
            .field("length", &self.value.len())
            .finish()
    }
}

#[derive(Debug)]
pub struct KvStore {
    entries: BTreeMap<CanonicalPath, Vec<VersionRecord>>,
    max_versions: usize,
}

impl KvStore {
    pub fn new(max_versions: usize) -> Result<Self, KvError> {
        if max_versions == 0 {
            return Err(KvError::InvalidMaxVersions);
        }
        Ok(Self {
            entries: BTreeMap::new(),
            max_versions,
        })
    }

    pub fn current_version(&self, path: &CanonicalPath) -> u64 {
        self.entries
            .get(path)
            .and_then(|history| history.last())
            .map_or(0, |record| record.metadata.version)
    }

    pub fn write(
        &mut self,
        path: CanonicalPath,
        value: SecretValue,
        now: Tick,
        cas: Option<u64>,
    ) -> Result<KvMetadata, KvError> {
        let history = self.entries.entry(path).or_default();
        let current = history.last().map_or(0, |record| record.metadata.version);
        if let Some(expected) = cas {
            if expected != current {
                return Err(KvError::CasMismatch);
            }
        }
        let version = current.checked_add(1).ok_or(KvError::VersionOverflow)?;
        let metadata = KvMetadata {
            version,
            created_at: now,
            deleted: false,
            destroyed: false,
        };
        history.push(VersionRecord {
            metadata: metadata.clone(),
            value: Some(value),
        });
        while history.len() > self.max_versions {
            history.remove(0);
        }
        Ok(metadata)
    }

    pub fn read(
        &self,
        path: &CanonicalPath,
        version: Option<u64>,
    ) -> Result<KvRead<'_>, KvError> {
        let history = self.entries.get(path).ok_or(KvError::MissingKey)?;
        let record = match version {
            Some(expected) => history
                .iter()
                .find(|record| record.metadata.version == expected)
                .ok_or(KvError::MissingVersion)?,
            None => history.last().ok_or(KvError::MissingVersion)?,
        };
        if record.metadata.destroyed {
            return Err(KvError::Destroyed);
        }
        if record.metadata.deleted {
            return Err(KvError::Deleted);
        }
        let value = record.value.as_ref().ok_or(KvError::Destroyed)?;
        Ok(KvRead {
            metadata: record.metadata.clone(),
            value: value.expose(),
        })
    }

    pub fn delete_latest(&mut self, path: &CanonicalPath) -> Result<KvMetadata, KvError> {
        let history = self.entries.get_mut(path).ok_or(KvError::MissingKey)?;
        let record = history.last_mut().ok_or(KvError::MissingVersion)?;
        if record.metadata.destroyed {
            return Err(KvError::Destroyed);
        }
        if record.metadata.deleted {
            return Err(KvError::Deleted);
        }
        record.metadata.deleted = true;
        Ok(record.metadata.clone())
    }

    pub fn undelete(&mut self, path: &CanonicalPath, version: u64) -> Result<KvMetadata, KvError> {
        let history = self.entries.get_mut(path).ok_or(KvError::MissingKey)?;
        let record = history
            .iter_mut()
            .find(|record| record.metadata.version == version)
            .ok_or(KvError::MissingVersion)?;
        if record.metadata.destroyed {
            return Err(KvError::Destroyed);
        }
        if !record.metadata.deleted {
            return Err(KvError::NotDeleted);
        }
        record.metadata.deleted = false;
        Ok(record.metadata.clone())
    }

    pub fn destroy(
        &mut self,
        path: &CanonicalPath,
        versions: &[u64],
    ) -> Result<usize, KvError> {
        if versions.is_empty() {
            return Err(KvError::MissingVersion);
        }
        let history = self.entries.get_mut(path).ok_or(KvError::MissingKey)?;
        let mut changed = 0;
        for version in versions {
            let record = history
                .iter_mut()
                .find(|record| record.metadata.version == *version)
                .ok_or(KvError::MissingVersion)?;
            if !record.metadata.destroyed {
                record.value = None;
                record.metadata.destroyed = true;
                record.metadata.deleted = true;
                changed += 1;
            }
        }
        Ok(changed)
    }

    pub fn list(&self, prefix: &CanonicalPath) -> Vec<CanonicalPath> {
        self.entries
            .keys()
            .filter(|path| path.matches_prefix(prefix))
            .cloned()
            .collect()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum KvError {
    InvalidMaxVersions,
    MissingKey,
    MissingVersion,
    CasMismatch,
    VersionOverflow,
    Deleted,
    Destroyed,
    NotDeleted,
}

impl fmt::Display for KvError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidMaxVersions => "maximum versions must be positive",
            Self::MissingKey => "secret key does not exist",
            Self::MissingVersion => "secret version does not exist",
            Self::CasMismatch => "compare-and-set version mismatch",
            Self::VersionOverflow => "secret version overflow",
            Self::Deleted => "secret version is deleted",
            Self::Destroyed => "secret version is destroyed",
            Self::NotDeleted => "secret version is not deleted",
        })
    }
}

impl Error for KvError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compare_and_set_and_version_lifecycle_are_enforced() -> Result<(), Box<dyn Error>> {
        let path = CanonicalPath::parse("/app/config")?;
        let mut store = KvStore::new(3)?;
        let first = store.write(
            path.clone(),
            SecretValue::new(b"one".to_vec())?,
            Tick::new(1),
            Some(0),
        )?;
        assert_eq!(1, first.version);
        assert_eq!(
            Err(KvError::CasMismatch),
            store.write(
                path.clone(),
                SecretValue::new(b"two".to_vec())?,
                Tick::new(2),
                Some(0),
            )
        );
        let second = store.write(
            path.clone(),
            SecretValue::new(b"two".to_vec())?,
            Tick::new(2),
            Some(1),
        )?;
        assert_eq!(b"two", store.read(&path, None)?.value);
        store.delete_latest(&path)?;
        assert_eq!(Err(KvError::Deleted), store.read(&path, None));
        store.undelete(&path, second.version)?;
        assert_eq!(b"two", store.read(&path, None)?.value);
        store.destroy(&path, &[first.version])?;
        assert_eq!(Err(KvError::Destroyed), store.read(&path, Some(first.version)));
        Ok(())
    }

    #[test]
    fn retention_prunes_old_versions_and_list_is_prefix_bounded() -> Result<(), Box<dyn Error>> {
        let path = CanonicalPath::parse("/app/config")?;
        let other = CanonicalPath::parse("/application/config")?;
        let mut store = KvStore::new(2)?;
        for version in 0..3 {
            store.write(
                path.clone(),
                SecretValue::new(vec![b'a' + version])?,
                Tick::new(u64::from(version)),
                None,
            )?;
        }
        store.write(
            other.clone(),
            SecretValue::new(b"other".to_vec())?,
            Tick::new(4),
            None,
        )?;
        assert_eq!(Err(KvError::MissingVersion), store.read(&path, Some(1)));
        assert_eq!(vec![path], store.list(&CanonicalPath::parse("/app")?));
        Ok(())
    }
}
