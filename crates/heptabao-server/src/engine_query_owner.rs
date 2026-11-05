//! Immutable query syntax owned by one actual secret mount.
//! This is a routing fact, not a Principal, grant or effect capability.
use super::{Backend, canonical_secret_mount};
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(crate) enum QueryKind {
    Ordinary,
    Kv,
    Pki,
    Transit,
}

impl QueryKind {
    pub(super) fn from_backend(backend: &Backend) -> Self {
        match backend {
            Backend::Kv1(_) | Backend::Kv1Records | Backend::Kv2(_) | Backend::Kv2Native(_) => {
                Self::Kv
            }
            Backend::Pki(_) => Self::Pki,
            Backend::Transit(_) => Self::Transit,
            _ => Self::Ordinary,
        }
    }
}

#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct MountQueryOwner {
    pub(crate) path: String,
    pub(crate) incarnation: u64,
    pub(crate) kind: QueryKind,
}

impl MountQueryOwner {
    /// Keep the registered mount's existing canonical path bound. The stored
    /// trailing slash is in addition to the existing bare-path limit of 1024.
    pub(crate) fn is_valid(&self) -> bool {
        self.incarnation > 0
            && self.path.strip_suffix('/').is_some_and(|bare| {
                canonical_secret_mount(bare)
                    .is_ok_and(|actual| actual == bare && format!("{actual}/") == self.path)
            })
    }

    pub(crate) fn kv_root(&self, method: &str, path: &str) -> Option<String> {
        (matches!(method, "LIST" | "SCAN")
            && !path.ends_with('/')
            && self.kind == QueryKind::Kv
            && self.path.strip_suffix('/') == Some(path))
        .then(|| self.path.clone())
    }

    fn pki_relative<'a>(&self, path: &'a str) -> Option<&'a str> {
        if self.kind != QueryKind::Pki || path.contains('?') || path.starts_with('/') {
            return None;
        }
        path.strip_prefix(self.path.as_str())
    }

    pub(crate) fn pki_ocsp_get(&self, path: &str) -> Option<(String, String)> {
        let suffix = self.pki_relative(path)?.strip_prefix("ocsp/")?;
        Some((format!("{}ocsp", self.path), suffix.to_owned()))
    }

    pub(crate) fn is_ocsp(&self, path: &str) -> bool {
        self.pki_relative(path)
            .is_some_and(|relative| relative == "ocsp")
    }

    pub(crate) fn is_pki_path(&self, path: &str) -> bool {
        self.pki_relative(path)
            .is_some_and(|relative| relative == "ocsp" || relative.starts_with("ocsp/"))
    }

    pub(crate) fn is_kv(&self, path: &str) -> bool {
        self.kind == QueryKind::Kv && path.starts_with(self.path.as_str())
    }

    pub(crate) fn is_transit_export(&self, path: &str) -> bool {
        if self.kind != QueryKind::Transit {
            return false;
        }
        let Some(relative) = path
            .strip_prefix(self.path.as_str())
            .and_then(|relative| relative.strip_prefix("export/"))
        else {
            return false;
        };
        let parts: Vec<_> = relative.split('/').collect();
        matches!(parts.len(), 2 | 3)
            && parts.iter().all(|part| !part.is_empty())
            && matches!(
                parts[0],
                "public-key" | "signing-key" | "encryption-key" | "hmac-key"
            )
    }

    pub(crate) fn is_transit_byok_export(&self, path: &str) -> bool {
        if self.kind != QueryKind::Transit {
            return false;
        }
        let Some(relative) = path
            .strip_prefix(self.path.as_str())
            .and_then(|relative| relative.strip_prefix("byok-export/"))
        else {
            return false;
        };
        let parts: Vec<_> = relative.split('/').collect();
        matches!(parts.len(), 2 | 3) && parts.iter().all(|part| !part.is_empty())
    }
}
