//! Private Token API clock and lease precision types. No wire timestamp exists.
//! Issuance remains disabled until every explicit admission/finalization path is migrated.
use serde::{Deserialize, Serialize};
use std::time::{Duration, Instant};

const NANOS: u64 = 1_000_000_000;
const MAX_SECONDS: u64 = 253_402_300_799;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum PrecisionError {
    Timestamp,
    Duration,
    Lease,
    Clock,
}
impl std::fmt::Display for PrecisionError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("invalid private token clock or lease precision")
    }
}
impl std::error::Error for PrecisionError {}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(try_from = "TimestampWire", into = "TimestampWire")]
pub(crate) struct Timestamp {
    seconds: u64,
    nanoseconds: u32,
}

#[derive(Clone, Copy, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct TimestampWire {
    seconds: u64,
    nanoseconds: u32,
}
impl TryFrom<TimestampWire> for Timestamp {
    type Error = &'static str;
    fn try_from(value: TimestampWire) -> Result<Self, Self::Error> {
        Self::checked(value.seconds, value.nanoseconds).map_err(|_| "invalid precise timestamp")
    }
}
impl From<Timestamp> for TimestampWire {
    fn from(value: Timestamp) -> Self {
        Self {
            seconds: value.seconds,
            nanoseconds: value.nanoseconds,
        }
    }
}

impl Timestamp {
    pub(crate) fn checked(seconds: u64, nanoseconds: u32) -> Result<Self, PrecisionError> {
        if seconds > MAX_SECONDS || u64::from(nanoseconds) >= NANOS {
            return Err(PrecisionError::Timestamp);
        }
        Ok(Self {
            seconds,
            nanoseconds,
        })
    }
    pub(crate) fn from_wall(value: Duration) -> Result<Self, PrecisionError> {
        Self::checked(value.as_secs(), value.subsec_nanos())
    }
    pub(crate) fn whole(seconds: u64) -> Result<Self, PrecisionError> {
        Self::checked(seconds, 0)
    }
    pub(crate) fn seconds(self) -> u64 {
        self.seconds
    }
    pub(crate) fn ceil_seconds(self) -> Result<u64, PrecisionError> {
        self.seconds
            .checked_add(u64::from(self.nanoseconds != 0))
            .filter(|seconds| *seconds <= MAX_SECONDS)
            .ok_or(PrecisionError::Timestamp)
    }
    pub(crate) fn duration_since_epoch(self) -> Duration {
        Duration::new(self.seconds, self.nanoseconds)
    }
    pub(crate) fn rfc3339(self) -> String {
        let whole = crate::engines::timestamp(self.seconds);
        if self.nanoseconds == 0 {
            return whole;
        }
        let fraction = format!("{:09}", self.nanoseconds);
        format!(
            "{}.{}Z",
            whole.trim_end_matches('Z'),
            fraction.trim_end_matches('0')
        )
    }
    /// Public local-zone rendering never changes the private epoch authority.
    pub(crate) fn local_rfc3339(self) -> Result<String, super::AuthError> {
        super::public_origin::CreationStamp::local_epoch(self.seconds, self.nanoseconds)?.render()
    }
    pub(crate) fn truncate_seconds(self) -> Self {
        Self {
            seconds: self.seconds,
            nanoseconds: 0,
        }
    }
    pub(crate) fn round_seconds(self) -> Result<Self, PrecisionError> {
        Self::whole(
            self.seconds
                .checked_add(u64::from(self.nanoseconds >= 500_000_000))
                .ok_or(PrecisionError::Timestamp)?,
        )
    }
    pub(crate) fn checked_add(self, span: DurationNanos) -> Result<Self, PrecisionError> {
        let nanos = u64::from(self.nanoseconds) + span.0 % NANOS;
        let seconds = self
            .seconds
            .checked_add(span.0 / NANOS)
            .and_then(|seconds| seconds.checked_add(nanos / NANOS))
            .ok_or(PrecisionError::Timestamp)?;
        Self::checked(seconds, (nanos % NANOS) as u32)
    }
    pub(crate) fn elapsed(self, earlier: Self) -> Result<DurationNanos, PrecisionError> {
        if self < earlier {
            return Err(PrecisionError::Clock);
        }
        let difference = self.as_i128_nanos() - earlier.as_i128_nanos();
        DurationNanos::checked(u64::try_from(difference).map_err(|_| PrecisionError::Duration)?)
    }
    fn as_i128_nanos(self) -> i128 {
        i128::from(self.seconds) * i128::from(NANOS) + i128::from(self.nanoseconds)
    }
    pub(crate) fn lookup_remaining_seconds(self, now: Self) -> Result<i64, PrecisionError> {
        // The reference rounds now before subtracting, then truncates toward zero.
        let difference = self.as_i128_nanos() - now.round_seconds()?.as_i128_nanos();
        i64::try_from(difference / i128::from(NANOS)).map_err(|_| PrecisionError::Duration)
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(try_from = "u64", into = "u64")]
pub(crate) struct DurationNanos(u64);
impl TryFrom<u64> for DurationNanos {
    type Error = &'static str;
    fn try_from(value: u64) -> Result<Self, Self::Error> {
        Self::checked(value).map_err(|_| "invalid precise lease duration")
    }
}
impl From<DurationNanos> for u64 {
    fn from(value: DurationNanos) -> Self {
        value.0
    }
}
impl DurationNanos {
    pub(crate) fn checked(value: u64) -> Result<Self, PrecisionError> {
        (value <= i64::MAX as u64)
            .then_some(Self(value))
            .ok_or(PrecisionError::Duration)
    }
    pub(crate) fn from_seconds(value: u64) -> Result<Self, PrecisionError> {
        Self::checked(value.checked_mul(NANOS).ok_or(PrecisionError::Duration)?)
    }
    pub(crate) fn nanoseconds(self) -> u64 {
        self.0
    }
    pub(crate) fn is_zero(self) -> bool {
        self.0 == 0
    }
    pub(crate) fn public_seconds(self) -> u64 {
        self.0 / NANOS
    }
    pub(crate) fn ceil_seconds(self) -> u64 {
        self.0 / NANOS + u64::from(!self.0.is_multiple_of(NANOS))
    }
}

/// The expiry anchor is sampled before the lease registration timestamp.
/// Token CreationTime remains whole seconds; issue/last-renewal are separate
/// public registration clocks and never reconstruct expiration authority.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ServicePrecision {
    pub(crate) issued_at: Timestamp,
    pub(crate) grant_started_at: Timestamp,
    pub(crate) expires_at: Option<Timestamp>,
    pub(crate) last_renewed_at: Option<Timestamp>,
    pub(crate) previous_grant: DurationNanos,
    pub(crate) creation_grant: DurationNanos,
    pub(crate) requested_period: DurationNanos,
    pub(crate) requested_explicit_max: DurationNanos,
}
impl ServicePrecision {
    pub(crate) fn validate(
        &self,
        creation_seconds: u64,
        coarse_expiry: Option<u64>,
        coarse_grant: Option<u64>,
    ) -> Result<(), PrecisionError> {
        if self.issued_at.truncate_seconds() < Timestamp::whole(creation_seconds)?
            || self.grant_started_at < Timestamp::whole(creation_seconds)?
            || match self.last_renewed_at {
                Some(last) => {
                    self.grant_started_at < self.issued_at || last < self.grant_started_at
                }
                None => self.grant_started_at > self.issued_at,
            }
            || self.creation_grant.is_zero() != self.previous_grant.is_zero()
        {
            return Err(PrecisionError::Lease);
        }
        let anchor = self.grant_started_at;
        match self.expires_at {
            Some(deadline)
                if !self.previous_grant.is_zero()
                    && deadline == anchor.checked_add(self.previous_grant)?
                    && coarse_expiry == Some(deadline.ceil_seconds()?)
                    && coarse_grant == Some(self.previous_grant.ceil_seconds()) =>
            {
                Ok(())
            }
            None if self.previous_grant.is_zero()
                && self.creation_grant.is_zero()
                && self.requested_period.is_zero()
                && self.requested_explicit_max.is_zero()
                && self.last_renewed_at.is_none()
                && self.grant_started_at == self.issued_at
                && coarse_expiry.is_none()
                && coarse_grant.is_none() =>
            {
                Ok(())
            }
            _ => Err(PrecisionError::Lease),
        }
    }
}

/// Batch issue time is deliberately whole-second CreationTime; changing this
/// anchor would extend stateless authority relative to the pinned reference.
#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct BatchPrecision {
    pub(crate) granted_ttl: DurationNanos,
    pub(crate) expires_at: Timestamp,
}
impl BatchPrecision {
    pub(crate) fn validate(
        &self,
        issued_seconds: u64,
        coarse_expiry: u64,
    ) -> Result<(), PrecisionError> {
        if self.granted_ttl.is_zero()
            || self.granted_ttl > DurationNanos::from_seconds(super::batch::MAX_BATCH_TTL)?
            || self.expires_at != Timestamp::whole(issued_seconds)?.checked_add(self.granted_ttl)?
            || self.expires_at.ceil_seconds()? != coarse_expiry
        {
            return Err(PrecisionError::Lease);
        }
        Ok(())
    }
}

/// Constructed only at a trusted Service entry point; no bearer or client body
/// may select wall time. Monotonic elapsed time preserves the ingress fraction.
#[derive(Clone, Copy)]
pub(crate) struct RequestClock {
    wall: Timestamp,
    started: Instant,
    floor: Option<Timestamp>,
}
impl RequestClock {
    pub(crate) fn anchored(wall: Duration, started: Instant) -> Result<Self, PrecisionError> {
        Ok(Self {
            wall: Timestamp::from_wall(wall)?,
            started,
            floor: None,
        })
    }
    pub(crate) fn observed_at(self) -> Result<Timestamp, PrecisionError> {
        let elapsed = self.started.elapsed();
        // The elapsed span is request bounded; reject rather than saturate.
        let observed = self.wall.checked_add(DurationNanos::checked(
            u64::try_from(elapsed.as_nanos()).map_err(|_| PrecisionError::Clock)?,
        )?)?;
        Ok(self.floor.map_or(observed, |floor| observed.max(floor)))
    }
    pub(crate) fn admitted_at(self) -> Timestamp {
        self.floor.map_or(self.wall, |floor| self.wall.max(floor))
    }
    pub(crate) fn started(self) -> Instant {
        self.started
    }
    pub(crate) fn with_seconds_floor(self, seconds: u64) -> Result<Self, PrecisionError> {
        Ok(self.with_timestamp_floor(Timestamp::whole(seconds)?))
    }
    pub(crate) fn with_timestamp_floor(self, floor: Timestamp) -> Self {
        Self {
            floor: Some(self.floor.map_or(floor, |previous| previous.max(floor))),
            ..self
        }
    }
}

/// Coarse entry points remain usable for historical tokens, but cannot confer
/// authority from a rounded projection of a new precise issuer-owned lease.
#[derive(Clone, Copy)]
pub(crate) enum AuthorityTime {
    Coarse(u64),
    Precise(Timestamp),
}
impl AuthorityTime {
    pub(crate) fn seconds(self) -> u64 {
        match self {
            Self::Coarse(seconds) => seconds,
            Self::Precise(at) => at.seconds(),
        }
    }
    pub(crate) fn service_live(
        self,
        precision: Option<&ServicePrecision>,
        expiry: Option<u64>,
    ) -> bool {
        match precision {
            Some(lease) => match self {
                // The service lease manager rejects ExpireTime.Before(now).
                Self::Precise(now) => {
                    now >= lease.issued_at && lease.expires_at.is_none_or(|end| now <= end)
                }
                Self::Coarse(_) => false,
            },
            None => expiry.is_none_or(|end| self.seconds() < end),
        }
    }
    pub(crate) fn batch_live(
        self,
        precision: Option<&BatchPrecision>,
        issued: u64,
        expiry: u64,
    ) -> bool {
        match precision {
            Some(lease) => match self {
                // The authenticated reference batch claim expires after its
                // whole-second CreationTime + exact TTL, without moving anchor.
                Self::Precise(now) => now.seconds() >= issued && now <= lease.expires_at,
                Self::Coarse(_) => false,
            },
            None => self.seconds() >= issued && self.seconds() < expiry,
        }
    }
    pub(crate) fn with_seconds_floor(self, seconds: u64) -> Result<Self, PrecisionError> {
        Ok(match self {
            Self::Coarse(now) => Self::Coarse(now.max(seconds)),
            Self::Precise(now) => Self::Precise(now.max(Timestamp::whole(seconds)?)),
        })
    }
    pub(crate) fn exact(self) -> Option<Timestamp> {
        match self {
            Self::Precise(at) => Some(at),
            Self::Coarse(_) => None,
        }
    }
}

impl super::AuthState {
    pub(crate) fn terminal_token_clock_floor(&self) -> Option<Timestamp> {
        self.token_api_observed_at
    }
    pub(crate) fn has_token_api_precision_state(&self) -> bool {
        self.token_api_precision_state
            || self.token_api_observed_at.is_some()
            || self
                .tokens
                .values()
                .any(|token| token.token_api_precision.is_some())
    }
    pub(crate) fn token_api_observed_time(&self, time: AuthorityTime) -> AuthorityTime {
        match (time, self.token_api_observed_at) {
            (AuthorityTime::Precise(now), Some(floor)) => AuthorityTime::Precise(now.max(floor)),
            _ => time,
        }
    }
    pub(super) fn token_api_request_clock(&self, clock: RequestClock) -> RequestClock {
        self.token_api_observed_at
            .map_or(clock, |floor| clock.with_timestamp_floor(floor))
    }
    pub(crate) fn observe_token_api_time(
        &mut self,
        time: AuthorityTime,
    ) -> Result<bool, super::AuthError> {
        if !self.has_token_api_precision_state() {
            return Ok(false);
        }
        let at = self
            .token_api_observed_time(time)
            .exact()
            .ok_or_else(|| super::err(503, "trusted token clock is required"))?
            .max(
                Timestamp::whole(self.wrapping_clock)
                    .map_err(|_| super::err(503, "trusted token clock is unavailable"))?,
            );
        let changed = self.token_api_observed_at != Some(at);
        self.token_api_observed_at = Some(at);
        Ok(changed)
    }
    pub(crate) fn validate_token_api_clock_floor(
        &self,
        previous: Option<&Self>,
    ) -> Result<(), super::AuthError> {
        if let Some(previous) = previous
            && previous.has_token_api_precision_state()
            && (!self.token_api_precision_state
                || self.token_api_observed_at.is_none()
                || previous.token_api_observed_at.is_none()
                || self.token_api_observed_at < previous.token_api_observed_at)
        {
            return Err(super::err(
                503,
                "Token API precise observation floor cannot decrease",
            ));
        }
        Ok(())
    }
    pub(crate) fn validate_token_api_precision_state(&self) -> Result<(), super::AuthError> {
        if self.token_api_precision_state != self.token_api_observed_at.is_some() {
            return Err(super::bad(
                "invalid private Token API precise observation floor",
            ));
        }
        for token in self.tokens.values() {
            let Some(lease) = &token.token_api_precision else {
                continue;
            };
            if !self.token_api_precision_state
                || self.token_api_observed_at.is_none_or(|floor| {
                    lease.grant_started_at > floor
                        || lease.issued_at > floor
                        || lease.last_renewed_at.is_some_and(|last| last > floor)
                })
                || token.wrapping.is_some()
                || token.auth_cert_role.is_some()
                || token.auth_cert_sha256.is_some()
                || token.period != lease.requested_period.ceil_seconds()
                || (lease.last_renewed_at.is_some() && !token.renewable)
                || !token.root
                    && (lease.creation_grant
                        > DurationNanos::from_seconds(super::MAX_TTL)
                            .map_err(|_| super::bad("invalid precise grant limit"))?
                        || lease.previous_grant
                            > DurationNanos::from_seconds(super::MAX_TTL)
                                .map_err(|_| super::bad("invalid precise grant limit"))?)
            {
                return Err(super::bad(
                    "invalid private Token API precise lease ownership",
                ));
            }
            let Some(super::TokenAuthProvenance::TokenApi {
                issued_creation_ttl: Some(initial),
            }) = token.auth_provenance.as_ref()
            else {
                return Err(super::bad(
                    "invalid private Token API precise issuer provenance",
                ));
            };
            if *initial != lease.creation_grant.public_seconds()
                || lease
                    .validate(
                        token.created_at,
                        token.expires_at,
                        token.token_api_lease_ttl,
                    )
                    .is_err()
            {
                return Err(super::bad(
                    "invalid private Token API precise lease projection",
                ));
            }
            if lease.expires_at.is_none()
                && (!token.root
                    || !token.namespace.is_empty()
                    || token.policies.len() != 1
                    || !token.policies.contains("root")
                    || token.renewable
                    || !token.bound_cidrs.is_empty())
            {
                return Err(super::bad("invalid private non-expiring Token API lease"));
            }
            let expected_max = if lease.requested_explicit_max.is_zero() {
                None
            } else {
                Some(
                    Timestamp::whole(token.created_at)
                        .and_then(|at| at.checked_add(lease.requested_explicit_max))
                        .and_then(Timestamp::ceil_seconds)
                        .map_err(|_| super::bad("invalid private Token API precise maximum"))?,
                )
            };
            if token.max_expires_at != expected_max {
                return Err(super::bad(
                    "invalid private Token API precise maximum projection",
                ));
            }
        }
        Ok(())
    }
}

#[cfg(test)]
#[path = "auth_token_precision_tests.rs"]
mod tests;
