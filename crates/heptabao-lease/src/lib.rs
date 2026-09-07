#![forbid(unsafe_code)]
#![deny(missing_debug_implementations)]

//! Lease issue, renewal, expiration and revocation contracts.

use std::collections::BTreeMap;
use std::error::Error;
use std::fmt;

use heptabao_domain::{CanonicalPath, Id, Tick};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LeaseKind {
    Secret,
    Authentication,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LeaseState {
    Active,
    Revoked,
    Expired,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LeaseView {
    pub id: Id,
    pub owner_entity: Id,
    pub scope: CanonicalPath,
    pub kind: LeaseKind,
    pub state: LeaseState,
    pub issued_at: Tick,
    pub expires_at: Tick,
    pub renewable: bool,
    pub generation: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct LeaseRecord {
    id: Id,
    owner_entity: Id,
    scope: CanonicalPath,
    kind: LeaseKind,
    state: LeaseState,
    issued_at: Tick,
    expires_at: Tick,
    renewable: bool,
    generation: u64,
}

impl LeaseRecord {
    fn view(&self) -> LeaseView {
        LeaseView {
            id: self.id.clone(),
            owner_entity: self.owner_entity.clone(),
            scope: self.scope.clone(),
            kind: self.kind,
            state: self.state,
            issued_at: self.issued_at,
            expires_at: self.expires_at,
            renewable: self.renewable,
            generation: self.generation,
        }
    }
}

#[derive(Debug, Default)]
pub struct LeaseStore {
    leases: BTreeMap<Id, LeaseRecord>,
}

impl LeaseStore {
    pub fn issue(
        &mut self,
        id: Id,
        owner_entity: Id,
        scope: CanonicalPath,
        kind: LeaseKind,
        issued_at: Tick,
        ttl: u64,
        renewable: bool,
    ) -> Result<LeaseView, LeaseError> {
        if ttl == 0 {
            return Err(LeaseError::InvalidTtl);
        }
        if self.leases.contains_key(&id) {
            return Err(LeaseError::DuplicateLease);
        }
        let expires_at = issued_at
            .checked_add(ttl)
            .map_err(|_| LeaseError::InvalidTtl)?;
        let record = LeaseRecord {
            id: id.clone(),
            owner_entity,
            scope,
            kind,
            state: LeaseState::Active,
            issued_at,
            expires_at,
            renewable,
            generation: 1,
        };
        let view = record.view();
        self.leases.insert(id, record);
        Ok(view)
    }

    pub fn validate(&mut self, id: &Id, now: Tick) -> Result<LeaseView, LeaseError> {
        let record = self.leases.get_mut(id).ok_or(LeaseError::MissingLease)?;
        if record.state == LeaseState::Active && now >= record.expires_at {
            record.state = LeaseState::Expired;
            record.generation = record.generation.saturating_add(1);
        }
        match record.state {
            LeaseState::Active => Ok(record.view()),
            LeaseState::Revoked => Err(LeaseError::Revoked),
            LeaseState::Expired => Err(LeaseError::Expired),
        }
    }

    pub fn renew(&mut self, id: &Id, now: Tick, ttl: u64) -> Result<LeaseView, LeaseError> {
        if ttl == 0 {
            return Err(LeaseError::InvalidTtl);
        }
        let record = self.leases.get_mut(id).ok_or(LeaseError::MissingLease)?;
        if record.state == LeaseState::Revoked {
            return Err(LeaseError::Revoked);
        }
        if record.state == LeaseState::Expired || now >= record.expires_at {
            record.state = LeaseState::Expired;
            return Err(LeaseError::Expired);
        }
        if !record.renewable {
            return Err(LeaseError::NotRenewable);
        }
        record.expires_at = now.checked_add(ttl).map_err(|_| LeaseError::InvalidTtl)?;
        record.generation = record.generation.saturating_add(1);
        Ok(record.view())
    }

    pub fn revoke(&mut self, id: &Id) -> Result<(), LeaseError> {
        let record = self.leases.get_mut(id).ok_or(LeaseError::MissingLease)?;
        if record.state != LeaseState::Active {
            return Err(match record.state {
                LeaseState::Revoked => LeaseError::Revoked,
                LeaseState::Expired => LeaseError::Expired,
                LeaseState::Active => LeaseError::MissingLease,
            });
        }
        record.state = LeaseState::Revoked;
        record.generation = record.generation.saturating_add(1);
        Ok(())
    }

    pub fn revoke_prefix(&mut self, prefix: &CanonicalPath) -> usize {
        let mut count = 0;
        for record in self.leases.values_mut() {
            if record.state == LeaseState::Active && record.scope.matches_prefix(prefix) {
                record.state = LeaseState::Revoked;
                record.generation = record.generation.saturating_add(1);
                count += 1;
            }
        }
        count
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LeaseError {
    InvalidTtl,
    DuplicateLease,
    MissingLease,
    Revoked,
    Expired,
    NotRenewable,
}

impl fmt::Display for LeaseError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidTtl => "lease TTL is invalid",
            Self::DuplicateLease => "lease already exists",
            Self::MissingLease => "lease does not exist",
            Self::Revoked => "lease is revoked",
            Self::Expired => "lease is expired",
            Self::NotRenewable => "lease is not renewable",
        })
    }
}

impl Error for LeaseError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lease_lifecycle_is_monotonic() -> Result<(), Box<dyn Error>> {
        let lease = Id::parse("lease_one")?;
        let owner = Id::parse("alice")?;
        let scope = CanonicalPath::parse("/secret/app")?;
        let mut store = LeaseStore::default();
        store.issue(
            lease.clone(),
            owner,
            scope,
            LeaseKind::Secret,
            Tick::new(5),
            10,
            true,
        )?;
        assert!(store.validate(&lease, Tick::new(10)).is_ok());
        let renewed = store.renew(&lease, Tick::new(10), 20)?;
        assert_eq!(Tick::new(30), renewed.expires_at);
        store.revoke(&lease)?;
        assert_eq!(
            Err(LeaseError::Revoked),
            store.validate(&lease, Tick::new(11))
        );
        Ok(())
    }

    #[test]
    fn prefix_revocation_respects_path_boundaries() -> Result<(), Box<dyn Error>> {
        let mut store = LeaseStore::default();
        store.issue(
            Id::parse("lease_app")?,
            Id::parse("alice")?,
            CanonicalPath::parse("/secret/app/config")?,
            LeaseKind::Secret,
            Tick::new(0),
            100,
            false,
        )?;
        store.issue(
            Id::parse("lease_application")?,
            Id::parse("bob")?,
            CanonicalPath::parse("/secret/application")?,
            LeaseKind::Secret,
            Tick::new(0),
            100,
            false,
        )?;
        assert_eq!(
            1,
            store.revoke_prefix(&CanonicalPath::parse("/secret/app")?)
        );
        Ok(())
    }
}
