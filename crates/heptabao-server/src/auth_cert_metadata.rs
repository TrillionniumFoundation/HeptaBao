//! Certificate service-token metadata belongs to the authenticated issuance,
//! not the current role selectors or current Identity alias metadata.
use super::*;

const BASE_KEYS: [&str; 5] = [
    "cert_name",
    "common_name",
    "serial_number",
    "subject_key_id",
    "authority_key_id",
];

pub(super) fn validate(
    metadata: &BTreeMap<String, String>,
    role_name: &str,
) -> Result<(), AuthError> {
    if !valid_name(role_name) || !crate::login_metadata::within_limit(metadata) {
        return Err(bad("invalid certificate token metadata"));
    }
    // The existing opaque-leaf test/legacy profile cannot recover X.509
    // attributes. Preserve its explicitly empty snapshot; never guess a CN.
    if metadata.is_empty() {
        return Ok(());
    }
    if metadata.len() > BASE_KEYS.len() + MAX_CERT_ROLE_MATCH_VALUES
        || metadata.get("cert_name").map(String::as_str) != Some(role_name)
        || BASE_KEYS.iter().any(|key| !metadata.contains_key(*key))
        || metadata.iter().any(|(key, value)| {
            !BASE_KEYS.contains(&key.as_str())
                && (!valid_oid(&key.replace('-', "."))
                    || value.len() > MAX_CERT_EXTENSION_VALUE_BYTES)
        })
    {
        return Err(bad("invalid certificate token metadata"));
    }
    // Empty common_name, serial/key identifiers and extension strings are not
    // rejected by AppRole's nonempty-value rule: this is a separate producer.
    Ok(())
}

pub(super) fn snapshot(token: &Token) -> Option<&BTreeMap<String, String>> {
    match token.auth_provenance.as_ref()? {
        TokenAuthProvenance::Cert {
            issued_metadata, ..
        } => Some(issued_metadata),
        _ => None,
    }
}

pub(super) fn creation_ttl(token: &Token) -> Option<u64> {
    match token.auth_provenance.as_ref()? {
        TokenAuthProvenance::Cert {
            issued_creation_ttl,
            ..
        } => *issued_creation_ttl,
        _ => None,
    }
}

impl AuthState {
    pub(crate) fn has_cert_issued_metadata(&self) -> bool {
        self.tokens.values().any(|token| snapshot(token).is_some())
    }
    pub(crate) fn validate_cert_issued_metadata(&self) -> Result<(), AuthError> {
        for token in self.tokens.values() {
            let Some(metadata) = snapshot(token) else {
                continue;
            };
            let role = token
                .auth_cert_role
                .as_deref()
                .ok_or_else(|| bad("certificate metadata has no issuer"))?;
            validate(metadata, role)?;
            if let Some(ttl) = creation_ttl(token) {
                let issued_expiry = token.created_at.checked_add(ttl);
                if ttl == 0
                    || ttl > MAX_TTL
                    || issued_expiry.is_none()
                    || token
                        .max_expires_at
                        .is_some_and(|cap| issued_expiry.is_some_and(|expiry| expiry > cap))
                {
                    return Err(bad("invalid certificate creation TTL"));
                }
            }
            if token.root
                || token.parent.is_some()
                || token.wrapping.is_some()
                || token.policies.contains("root")
                || token.auth_cert_sha256.as_ref().is_none_or(|digest| {
                    normalized_certificate_sha256(digest).as_deref() != Some(digest.as_str())
                })
                || token
                    .auth_mount
                    .as_deref()
                    .is_none_or(|mount| !self.online_mount_enabled(&token.namespace, mount, "cert"))
            {
                return Err(bad("invalid certificate metadata origin"));
            }
        }
        // Role deletion or selector/extension edits cannot invalidate the
        // saved issuance facts. No current-role read belongs in this validator.
        Ok(())
    }
}
