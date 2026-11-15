//! Persisted auth-mount options follow the native TypeKVPairs input contract.
use super::*;

#[derive(Clone, Serialize, Deserialize, Debug, Eq, PartialEq)]
#[serde(
    tag = "input",
    content = "value",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub(super) enum Options {
    Null,
    Map(BTreeMap<String, String>),
}

impl Options {
    pub(super) fn parse(body: &Value) -> Result<Option<Self>, AuthError> {
        let Some(value) = body.get("options") else {
            return Ok(None);
        };
        Ok(match public_origin::key_pairs(value, "options")? {
            None => Some(Self::Null),
            Some(map) if map.is_empty() => None,
            Some(map) => Some(Self::Map(map)),
        })
    }

    pub(super) fn descriptor(&self) -> Value {
        match self {
            Self::Null => Value::Null,
            Self::Map(map) => json!(map),
        }
    }

    pub(super) fn has_version(&self) -> bool {
        matches!(self, Self::Map(map) if map.get("version").is_some_and(|value| !value.is_empty()))
    }

    fn validate(&self) -> Result<(), AuthError> {
        if matches!(self, Self::Map(map) if map.is_empty()) || self.has_version() {
            return Err(err(503, "invalid persisted auth mount options"));
        }
        Ok(())
    }
}

impl AuthState {
    pub(crate) fn has_auth_mount_options_state(&self) -> bool {
        self.auth_mounts
            .values()
            .any(|mounts| mounts.values().any(|mount| mount.options.is_some()))
    }

    pub(crate) fn validate_auth_mount_options_state(&self) -> Result<(), AuthError> {
        for mounts in self.auth_mounts.values() {
            for mount in mounts.values() {
                if let Some(options) = &mount.options {
                    options.validate()?;
                }
            }
        }
        Ok(())
    }
}
