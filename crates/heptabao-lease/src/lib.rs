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
pub struct LeaseIssue {
    pub id: Id,
    pub owner_entity: Id,
    pub scope: CanonicalPath,
    pub kind: LeaseKind,
    pub issued_at: Tick,
    pub ttl: u64,
    pub renewable: bool,
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
    pub fn issue(&mut self, command: LeaseIssue) -> Result<LeaseView, LeaseError> {
        if command.ttl == 0 {
            return Err(LeaseError::InvalidTtl);
        }
        if self.leases.contains_key(&command.id) {
            return Err(LeaseError::DuplicateLease);
        }
        let expires_at = command
            .issued_at
            .checked_add(command.ttl)
            .map_err(|_| LeaseError::InvalidTtl)?;
        let record = LeaseRecord {
            id: command.id.clone(),
            owner_entity: command.owner_entity,
            scope: command.scope,
            kind: command.kind,
            state: LeaseState::Active,
            issued_at: command.issued_at,
            expires_at,
            renewable: command.renewable,
            generation: 1,
        };
        let view = record.view();
        self.leases.insert(command.id, record);
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

    /// Renew a lease while enforcing an absolute lifetime from its issue time.
    ///
    /// The legacy [`Self::renew`] method remains available for the historical
    /// in-memory model, but it has no policy input and must not be used as a
    /// production lease admission path. This bounded form measures
    /// `max_ttl` from `issued_at`, so repeated renewals cannot extend a lease
    /// beyond that deadline. Zero values, arithmetic overflow, expired leases
    /// and non-renewable leases fail closed.
    pub fn renew_bounded(
        &mut self,
        id: &Id,
        now: Tick,
        ttl: u64,
        max_ttl: u64,
    ) -> Result<LeaseView, LeaseError> {
        if ttl == 0 || max_ttl == 0 {
            return Err(LeaseError::InvalidTtl);
        }
        let record = self.leases.get_mut(id).ok_or(LeaseError::MissingLease)?;
        if record.state == LeaseState::Revoked {
            return Err(LeaseError::Revoked);
        }
        if record.state == LeaseState::Expired {
            return Err(LeaseError::Expired);
        }
        if now >= record.expires_at {
            record.state = LeaseState::Expired;
            record.generation = record.generation.saturating_add(1);
            return Err(LeaseError::Expired);
        }
        if !record.renewable {
            return Err(LeaseError::NotRenewable);
        }
        let hard_deadline = record
            .issued_at
            .checked_add(max_ttl)
            .map_err(|_| LeaseError::InvalidTtl)?;
        if now >= hard_deadline {
            record.state = LeaseState::Expired;
            record.generation = record.generation.saturating_add(1);
            return Err(LeaseError::Expired);
        }
        let requested_deadline = now.checked_add(ttl).map_err(|_| LeaseError::InvalidTtl)?;
        record.expires_at = requested_deadline.min(hard_deadline);
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

    fn renewable_lease(issued_at: u64, ttl: u64) -> Result<(LeaseStore, Id), Box<dyn Error>> {
        let id = Id::parse("bounded_lease")?;
        let mut store = LeaseStore::default();
        store.issue(LeaseIssue {
            id: id.clone(),
            owner_entity: Id::parse("alice")?,
            scope: CanonicalPath::parse("/secret/app")?,
            kind: LeaseKind::Secret,
            issued_at: Tick::new(issued_at),
            ttl,
            renewable: true,
        })?;
        Ok((store, id))
    }

    #[test]
    fn bounded_renewal_cannot_extend_absolute_lifetime() -> Result<(), Box<dyn Error>> {
        let (mut store, id) = renewable_lease(5, 10)?;
        let first = store.renew_bounded(&id, Tick::new(10), 5, 20)?;
        assert_eq!(Tick::new(15), first.expires_at);
        let capped = store.renew_bounded(&id, Tick::new(14), 50, 20)?;
        assert_eq!(Tick::new(25), capped.expires_at);
        let again = store.renew_bounded(&id, Tick::new(24), 50, 20)?;
        assert_eq!(Tick::new(25), again.expires_at);
        assert_eq!(4, again.generation);
        assert_eq!(
            Err(LeaseError::Expired),
            store.renew_bounded(&id, Tick::new(25), 50, 20)
        );
        assert_eq!(5, store.leases[&id].generation);
        assert_eq!(
            Err(LeaseError::Expired),
            store.renew_bounded(&id, Tick::new(24), 50, 20)
        );
        assert_eq!(5, store.leases[&id].generation);
        Ok(())
    }

    #[test]
    fn bounded_renewal_invalid_input_is_atomic() -> Result<(), Box<dyn Error>> {
        let (mut store, id) = renewable_lease(5, 10)?;
        let before = store.validate(&id, Tick::new(6))?;
        for (ttl, max_ttl) in [(0, 20), (1, 0), (1, u64::MAX), (u64::MAX, 20)] {
            assert_eq!(
                Err(LeaseError::InvalidTtl),
                store.renew_bounded(&id, Tick::new(6), ttl, max_ttl)
            );
            assert_eq!(before, store.validate(&id, Tick::new(6))?);
        }
        Ok(())
    }

    #[test]
    fn bounded_renewal_rejects_expired_revoked_and_nonrenewable_leases()
    -> Result<(), Box<dyn Error>> {
        let (mut expired, id) = renewable_lease(5, 10)?;
        assert_eq!(
            Err(LeaseError::Expired),
            expired.renew_bounded(&id, Tick::new(15), 10, 20)
        );
        assert_eq!(2, expired.leases[&id].generation);

        // A reduced policy deadline also expires an otherwise-live lease.
        let (mut reduced, id) = renewable_lease(5, 100)?;
        assert_eq!(
            Err(LeaseError::Expired),
            reduced.renew_bounded(&id, Tick::new(25), 10, 20)
        );
        assert_eq!(
            Err(LeaseError::Expired),
            reduced.validate(&id, Tick::new(6))
        );

        let (mut revoked, id) = renewable_lease(5, 10)?;
        revoked.revoke(&id)?;
        assert_eq!(
            Err(LeaseError::Revoked),
            revoked.renew_bounded(&id, Tick::new(6), 10, 20)
        );

        let (mut nonrenewable, id) = renewable_lease(5, 10)?;
        nonrenewable
            .leases
            .get_mut(&id)
            .ok_or("missing test lease")?
            .renewable = false;
        let before = nonrenewable.validate(&id, Tick::new(6))?;
        assert_eq!(
            Err(LeaseError::NotRenewable),
            nonrenewable.renew_bounded(&id, Tick::new(6), 10, 20)
        );
        assert_eq!(before, nonrenewable.validate(&id, Tick::new(6))?);
        assert_eq!(
            Err(LeaseError::MissingLease),
            nonrenewable.renew_bounded(&Id::parse("absent")?, Tick::new(6), 10, 20)
        );
        Ok(())
    }

    #[test]
    fn lease_lifecycle_is_monotonic() -> Result<(), Box<dyn Error>> {
        let lease = Id::parse("lease_one")?;
        let owner = Id::parse("alice")?;
        let scope = CanonicalPath::parse("/secret/app")?;
        let mut store = LeaseStore::default();
        store.issue(LeaseIssue {
            id: lease.clone(),
            owner_entity: owner,
            scope,
            kind: LeaseKind::Secret,
            issued_at: Tick::new(5),
            ttl: 10,
            renewable: true,
        })?;
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
        store.issue(LeaseIssue {
            id: Id::parse("lease_app")?,
            owner_entity: Id::parse("alice")?,
            scope: CanonicalPath::parse("/secret/app/config")?,
            kind: LeaseKind::Secret,
            issued_at: Tick::new(0),
            ttl: 100,
            renewable: false,
        })?;
        store.issue(LeaseIssue {
            id: Id::parse("lease_application")?,
            owner_entity: Id::parse("bob")?,
            scope: CanonicalPath::parse("/secret/application")?,
            kind: LeaseKind::Secret,
            issued_at: Tick::new(0),
            ttl: 100,
            renewable: false,
        })?;
        assert_eq!(
            1,
            store.revoke_prefix(&CanonicalPath::parse("/secret/app")?)
        );
        Ok(())
    }
}
