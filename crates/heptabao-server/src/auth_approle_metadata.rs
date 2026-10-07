//! AppRole credential metadata is separate from the live Identity alias map.
//! SID metadata retains the administrator's input; issued metadata is immutable.
use super::*;
use std::borrow::Cow;

pub(super) fn erase(metadata: &mut BTreeMap<String, String>) {
    for (mut key, mut value) in std::mem::take(metadata) {
        key.zeroize();
        value.zeroize();
    }
}

impl Drop for SecretId {
    fn drop(&mut self) {
        if let Some(metadata) = &mut self.metadata {
            erase(metadata);
        }
    }
}

fn invalid() -> AuthError {
    bad("invalid SecretID metadata")
}

fn validate(metadata: &BTreeMap<String, String>) -> Result<(), AuthError> {
    if !crate::login_metadata::within_limit(metadata)
        || metadata
            .iter()
            .any(|(key, value)| !key.is_empty() && value.is_empty())
    {
        return Err(invalid());
    }
    Ok(())
}

#[path = "auth_approle_metadata_parser.rs"]
mod parser;

/// Owns metadata while parsing/admission can still fail. Taking the map is only
/// for transfer into a persistent or independently drop-cleared owner.
#[derive(Default)]
pub(super) struct Metadata(pub(super) BTreeMap<String, String>);
impl Metadata {
    pub(super) fn new(map: BTreeMap<String, String>) -> Self {
        Self(map)
    }
    pub(super) fn take(&mut self) -> BTreeMap<String, String> {
        std::mem::take(&mut self.0)
    }
    pub(super) fn insert(&mut self, key: String, value: String) {
        if let Some((mut old_key, mut old_value)) = self.0.remove_entry(&key) {
            old_key.zeroize();
            old_value.zeroize();
        }
        self.0.insert(key, value);
    }
}
impl Drop for Metadata {
    fn drop(&mut self) {
        erase(&mut self.0);
    }
}

pub(super) fn parse(body: &Value) -> Result<Option<BTreeMap<String, String>>, AuthError> {
    let Some(raw) = body.get("metadata") else {
        return Ok(None);
    };
    let input = match raw {
        Value::Null => "",
        Value::String(value) if value.len() <= crate::login_metadata::MAX_BYTES => value.trim(),
        _ => return Err(invalid()),
    };
    if input.is_empty() {
        return Ok(Some(BTreeMap::new()));
    }
    let encoded = Zeroizing::new(input.replace(['\r', '\n'], ""));
    let engine = base64::engine::general_purpose::GeneralPurpose::new(
        &base64::alphabet::STANDARD,
        base64::engine::general_purpose::GeneralPurposeConfig::new()
            .with_decode_allow_trailing_bits(true),
    );
    // decode_slice can have written plaintext before failing. Its entire output
    // allocation is zeroized on both branches, not wrapped only after success.
    let mut decoded = Zeroizing::new(vec![0; encoded.len() / 4 * 3 + 3]);
    let replacement;
    let input = match engine.decode_slice(encoded.as_bytes(), decoded.as_mut_slice()) {
        Ok(length) => match std::str::from_utf8(&decoded[..length]) {
            Ok(input) => input,
            Err(_) => {
                replacement = parser::replace_invalid_utf8(&decoded[..length])?;
                &replacement
            }
        },
        Err(_) => input,
    };
    let mut metadata = Metadata::default();
    if !parser::json(input, &mut metadata)? {
        parser::csv(input, &mut metadata)?;
    }
    validate(&metadata.0)?;
    Ok(Some(metadata.take()))
}

pub(super) fn token_metadata(token: &Token) -> Option<Cow<'_, BTreeMap<String, String>>> {
    match token.auth_provenance.as_ref()? {
        TokenAuthProvenance::AppRole {
            role_name,
            issued_metadata,
        } => Some(match issued_metadata {
            Some(metadata) => Cow::Borrowed(metadata),
            // Older service tokens only retain this known issuer fact. Never
            // guess which SID they used or migrate their stored provenance.
            None => Cow::Owned(BTreeMap::from([("role_name".into(), role_name.clone())])),
        }),
        _ => None,
    }
}

impl AuthState {
    pub(crate) fn has_approle_metadata(&self) -> bool {
        self.roles
            .values()
            .flat_map(|roles| roles.values())
            .chain(
                self.mounted_roles
                    .values()
                    .flat_map(|mounts| mounts.values())
                    .flat_map(|roles| roles.values()),
            )
            .any(|role| {
                role.secret_ids
                    .values()
                    .any(|secret| secret.metadata.is_some())
            })
            || self.tokens.values().any(|token| {
                matches!(
                    &token.auth_provenance,
                    Some(TokenAuthProvenance::AppRole {
                        issued_metadata: Some(_),
                        ..
                    })
                )
            })
    }

    pub(crate) fn validate_approle_metadata(&self) -> Result<(), AuthError> {
        for (namespace, roles) in &self.roles {
            self.validate_role_metadata(namespace, "approle", roles)?;
        }
        for (namespace, mounts) in &self.mounted_roles {
            for (mount, roles) in mounts {
                self.validate_role_metadata(namespace, mount, roles)?;
            }
        }
        for token in self.tokens.values() {
            if let Some(TokenAuthProvenance::AppRole {
                role_name,
                issued_metadata: Some(metadata),
            }) = &token.auth_provenance
            {
                validate(metadata)?;
                if metadata.get("role_name") != Some(role_name)
                    || !valid_name(role_name)
                    || token.parent.is_some()
                    || token.root
                    || token.auth_mount.as_deref().is_none_or(|mount| {
                        !self.online_mount_enabled(&token.namespace, mount, "approle")
                    })
                {
                    return Err(invalid());
                }
            }
        }
        Ok(())
    }

    fn validate_role_metadata(
        &self,
        namespace: &str,
        mount: &str,
        roles: &BTreeMap<String, Role>,
    ) -> Result<(), AuthError> {
        for metadata in roles
            .values()
            .flat_map(|role| role.secret_ids.values())
            .filter_map(|secret| secret.metadata.as_ref())
        {
            validate(metadata)?;
            if !self.online_mount_enabled(namespace, mount, "approle") {
                return Err(invalid());
            }
        }
        // SID destruction and role reconfiguration do not invalidate a token's
        // immutable metadata. No live SID/role lookup belongs in this validator.
        Ok(())
    }
}
