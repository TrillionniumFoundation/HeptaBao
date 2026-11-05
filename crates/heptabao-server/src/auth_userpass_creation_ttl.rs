//! Captured native Userpass issuance facts, never reconstructed from renewal.
use super::*;

pub(crate) const STATE_SCHEMA: u32 = 132;
#[derive(Clone, Copy, Serialize, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub(super) enum Floor {
    V1,
}

impl Token {
    pub(super) fn has_userpass_creation_ttl(&self) -> bool {
        matches!(
            self.auth_provenance,
            Some(TokenAuthProvenance::Userpass {
                issued_creation_ttl: Some(_),
                ..
            })
        )
    }
    pub(super) fn capture_userpass_creation_ttl(&mut self) -> Result<(), AuthError> {
        let Some(TokenAuthProvenance::Userpass {
            issued_creation_ttl,
            ..
        }) = &mut self.auth_provenance
        else {
            return Ok(());
        };
        let granted = self
            .expires_at
            .and_then(|end| end.checked_sub(self.created_at))
            .filter(|ttl| *ttl > 0 && *ttl <= MAX_TTL)
            .ok_or_else(|| err(503, "invalid native Userpass initial grant"))?;
        if issued_creation_ttl.is_some_and(|old| old != granted) {
            return Err(err(503, "native Userpass initial grant already captured"));
        }
        *issued_creation_ttl = Some(granted);
        self.validate_userpass_creation_ttl()
    }
    pub(super) fn validate_userpass_creation_ttl(&self) -> Result<(), AuthError> {
        let Some(TokenAuthProvenance::Userpass {
            issued_creation_ttl: Some(ttl),
            ..
        }) = &self.auth_provenance
        else {
            return Ok(()); // Genuine historical wire did not capture this fact.
        };
        let end = self
            .created_at
            .checked_add(*ttl)
            .ok_or_else(|| err(503, "invalid native Userpass initial grant"))?;
        if *ttl == 0
            || *ttl > MAX_TTL
            || self.root
            || self.parent.is_some()
            || self.expires_at.is_none()
            || self.wrapping.is_some()
            || self.max_expires_at.is_some_and(|maximum| end > maximum)
        {
            return Err(err(503, "invalid native Userpass initial grant"));
        }
        Ok(())
    }
}
impl AuthState {
    pub(crate) fn has_userpass_issuance_state(&self) -> bool {
        self.userpass_issuance_floor.is_some()
            || self.tokens.values().any(Token::has_userpass_creation_ttl)
    }
    pub(crate) fn validate_userpass_issuance_state(
        &self,
        previous: Option<&Self>,
    ) -> Result<(), AuthError> {
        if self.tokens.values().any(Token::has_userpass_creation_ttl)
            && self.userpass_issuance_floor.is_none()
        {
            return Err(err(503, "native Userpass issuance floor is missing"));
        }
        for token in self.tokens.values() {
            token.validate_userpass_creation_ttl()?;
        }
        if let Some(previous) = previous {
            previous.validate_userpass_issuance_state(None)?;
            if previous.userpass_issuance_floor.is_some() && self.userpass_issuance_floor.is_none()
            {
                return Err(err(503, "native Userpass issuance floor cannot retire"));
            }
            for (id, old) in &previous.tokens {
                let Some(TokenAuthProvenance::Userpass {
                    issued_creation_ttl: Some(grant),
                    ..
                }) = &old.auth_provenance
                else {
                    continue;
                };
                if let Some(current) = self.tokens.get(id)
                    && (current.created_at != old.created_at
                        || !matches!(
                            &current.auth_provenance,
                            Some(TokenAuthProvenance::Userpass { issued_creation_ttl: Some(now), .. }) if now == grant
                        ))
                {
                    return Err(err(503, "native Userpass initial grant changed"));
                }
            }
        }
        Ok(())
    }
}
