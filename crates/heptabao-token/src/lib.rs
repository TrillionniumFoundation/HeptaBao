#![forbid(unsafe_code)]
#![deny(missing_debug_implementations)]

//! Opaque token lifecycle with expiration, renewal and revocation.

use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::fmt;

use heptabao_domain::{DomainError, Id, Tick};

#[derive(Clone, Eq, Ord, PartialEq, PartialOrd)]
pub struct TokenId(Id);

impl TokenId {
    pub fn parse(value: impl Into<String>) -> Result<Self, DomainError> {
        Id::parse(value).map(Self)
    }
}

impl fmt::Debug for TokenId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("TokenId([REDACTED])")
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TokenView {
    pub entity_id: Id,
    pub policy_ids: BTreeSet<Id>,
    pub issued_at: Tick,
    pub expires_at: Tick,
    pub renewable: bool,
    pub generation: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct TokenRecord {
    entity_id: Id,
    policy_ids: BTreeSet<Id>,
    issued_at: Tick,
    expires_at: Tick,
    renewable: bool,
    revoked_at: Option<Tick>,
    generation: u64,
}

impl TokenRecord {
    fn view(&self) -> TokenView {
        TokenView {
            entity_id: self.entity_id.clone(),
            policy_ids: self.policy_ids.clone(),
            issued_at: self.issued_at,
            expires_at: self.expires_at,
            renewable: self.renewable,
            generation: self.generation,
        }
    }
}

#[derive(Debug, Default)]
pub struct TokenStore {
    tokens: BTreeMap<TokenId, TokenRecord>,
}

impl TokenStore {
    pub fn issue(
        &mut self,
        token_id: TokenId,
        entity_id: Id,
        policy_ids: BTreeSet<Id>,
        issued_at: Tick,
        ttl: u64,
        renewable: bool,
    ) -> Result<TokenView, TokenError> {
        if ttl == 0 {
            return Err(TokenError::InvalidTtl);
        }
        if self.tokens.contains_key(&token_id) {
            return Err(TokenError::DuplicateToken);
        }
        let expires_at = issued_at
            .checked_add(ttl)
            .map_err(|_| TokenError::InvalidTtl)?;
        let record = TokenRecord {
            entity_id,
            policy_ids,
            issued_at,
            expires_at,
            renewable,
            revoked_at: None,
            generation: 1,
        };
        let view = record.view();
        self.tokens.insert(token_id, record);
        Ok(view)
    }

    pub fn validate(&self, token_id: &TokenId, now: Tick) -> Result<TokenView, TokenError> {
        let record = self.tokens.get(token_id).ok_or(TokenError::MissingToken)?;
        if record.revoked_at.is_some() {
            return Err(TokenError::Revoked);
        }
        if now >= record.expires_at {
            return Err(TokenError::Expired);
        }
        Ok(record.view())
    }

    pub fn renew(
        &mut self,
        token_id: &TokenId,
        now: Tick,
        ttl: u64,
    ) -> Result<TokenView, TokenError> {
        if ttl == 0 {
            return Err(TokenError::InvalidTtl);
        }
        let record = self
            .tokens
            .get_mut(token_id)
            .ok_or(TokenError::MissingToken)?;
        if record.revoked_at.is_some() {
            return Err(TokenError::Revoked);
        }
        if now >= record.expires_at {
            return Err(TokenError::Expired);
        }
        if !record.renewable {
            return Err(TokenError::NotRenewable);
        }
        record.expires_at = now.checked_add(ttl).map_err(|_| TokenError::InvalidTtl)?;
        record.generation = record.generation.saturating_add(1);
        Ok(record.view())
    }

    pub fn revoke(&mut self, token_id: &TokenId, now: Tick) -> Result<(), TokenError> {
        let record = self
            .tokens
            .get_mut(token_id)
            .ok_or(TokenError::MissingToken)?;
        if record.revoked_at.is_some() {
            return Err(TokenError::Revoked);
        }
        record.revoked_at = Some(now);
        record.generation = record.generation.saturating_add(1);
        Ok(())
    }

    pub fn revoke_entity(&mut self, entity_id: &Id, now: Tick) -> usize {
        let mut count = 0;
        for record in self.tokens.values_mut() {
            if &record.entity_id == entity_id && record.revoked_at.is_none() {
                record.revoked_at = Some(now);
                record.generation = record.generation.saturating_add(1);
                count += 1;
            }
        }
        count
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TokenError {
    InvalidTtl,
    DuplicateToken,
    MissingToken,
    Revoked,
    Expired,
    NotRenewable,
}

impl fmt::Display for TokenError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidTtl => "token TTL is invalid",
            Self::DuplicateToken => "token already exists",
            Self::MissingToken => "token does not exist",
            Self::Revoked => "token is revoked",
            Self::Expired => "token is expired",
            Self::NotRenewable => "token is not renewable",
        })
    }
}

impl Error for TokenError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn token_lifecycle_enforces_expiry_renewal_and_revocation() -> Result<(), Box<dyn Error>> {
        let token_id = TokenId::parse("token_alpha")?;
        let entity = Id::parse("alice")?;
        let mut policies = BTreeSet::new();
        policies.insert(Id::parse("reader")?);
        let mut store = TokenStore::default();
        let issued = store.issue(
            token_id.clone(),
            entity,
            policies,
            Tick::new(10),
            10,
            true,
        )?;
        assert_eq!(Tick::new(20), issued.expires_at);
        let renewed = store.renew(&token_id, Tick::new(15), 20)?;
        assert_eq!(Tick::new(35), renewed.expires_at);
        store.revoke(&token_id, Tick::new(16))?;
        assert_eq!(Err(TokenError::Revoked), store.validate(&token_id, Tick::new(17)));
        Ok(())
    }

    #[test]
    fn token_identifier_debug_is_redacted() -> Result<(), DomainError> {
        let token_id = TokenId::parse("token_secret_value")?;
        assert_eq!("TokenId([REDACTED])", format!("{token_id:?}"));
        Ok(())
    }
}
