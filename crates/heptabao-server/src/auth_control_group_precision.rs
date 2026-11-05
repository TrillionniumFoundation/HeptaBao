//! Optional schema122 precision. Whole-second118 owners retain their original wire and AAD.
use super::*;

#[derive(Clone, Copy, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Precision {
    pub(crate) issued_at: Timestamp,
    pub(crate) expires_at: Timestamp,
    pub(crate) ttl: DurationNanos,
}
impl Precision {
    pub(crate) fn capture(time: AuthorityTime, ttl: DurationNanos) -> Result<Self, AuthError> {
        let issued_at = time
            .exact()
            .ok_or_else(|| bad("fractional control group TTL requires a precise request clock"))?;
        let expires_at = issued_at
            .checked_add(ttl)
            .map_err(|_| bad("control group TTL overflows precise timestamp"))?;
        Ok(Self {
            issued_at,
            expires_at,
            ttl,
        })
    }
    pub(crate) fn validate(self, created: u64, retained_expiry: u64) -> Result<(), AuthError> {
        if self.ttl.is_zero()
            || self.ttl.nanoseconds() > MAX_TTL * 1_000_000_000
            || self.ttl.nanoseconds().is_multiple_of(1_000_000_000)
            || self.issued_at.seconds() != created
            || self.issued_at.checked_add(self.ttl).ok() != Some(self.expires_at)
            || self.expires_at.ceil_seconds().ok() != Some(retained_expiry)
        {
            return Err(bad("invalid precise control group deadline"));
        }
        Ok(())
    }
    pub(crate) fn live(self, time: AuthorityTime) -> bool {
        match time.exact() {
            Some(now) => now >= self.issued_at && now < self.expires_at,
            None => false,
        }
    }
}
impl DeferredRequest {
    pub(crate) fn live(&self, time: AuthorityTime) -> bool {
        self.precision.map_or_else(
            || time.seconds() >= self.created_at && time.seconds() < self.expires_at,
            |precision| precision.live(time),
        )
    }
    pub(crate) fn duration(&self) -> Result<DurationNanos, AuthError> {
        match self.precision {
            Some(precision) => Ok(precision.ttl),
            None => DurationNanos::from_seconds(self.expires_at - self.created_at)
                .map_err(|_| bad("control group TTL exceeds bounds")),
        }
    }
    pub(crate) fn wire_ttl(&self) -> u64 {
        self.precision
            .map_or(self.expires_at - self.created_at, |precision| {
                precision.ttl.public_seconds()
            })
    }
}
