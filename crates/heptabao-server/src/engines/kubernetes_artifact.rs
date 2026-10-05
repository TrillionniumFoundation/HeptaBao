//! Public artifact metadata is an observation, never provider execution authority.
//! Missing durable contract fields retain the original strict provider-expiry mode.
use super::kubernetes::{LeaseAuthority, MAX_TOKEN_TTL};
use crate::auth::Timestamp;
use serde::{Deserialize, Serialize};

pub(crate) const ISSUANCE_ENABLED: bool = false;
pub(crate) const STATE_SCHEMA: u32 = 87;
const MAX_PUBLIC_TTL: u64 = 32 * 24 * 60 * 60;

#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) enum Producer {
    #[serde(rename = "authenticated-token-request-opaque-artifact-registration-v2")]
    AuthenticatedTokenRequest,
}

/// Captured by Service from the actual role/system defaults before outbound entry.
/// There is no request-body decoder or constructor accepting public JWT fields.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Contract {
    producer: Producer,
    pub(super) requested_ttl: u64,
    pub(super) role_max_ttl: u64,
    pub(super) system_default_ttl: u64,
    pub(super) system_max_ttl: u64,
}

impl Contract {
    pub(super) fn admitted(
        requested_ttl: u64,
        role_max_ttl: u64,
        system_default_ttl: u64,
        system_max_ttl: u64,
    ) -> Result<Self, &'static str> {
        let value = Self {
            producer: Producer::AuthenticatedTokenRequest,
            requested_ttl,
            role_max_ttl,
            system_default_ttl,
            system_max_ttl,
        };
        value.validate()?;
        Ok(value)
    }
    pub(super) fn validate(&self) -> Result<(), &'static str> {
        if self.requested_ttl == 0
            || self.requested_ttl > self.role_max_ttl
            || self.role_max_ttl > MAX_TOKEN_TTL
            || self.system_default_ttl == 0
            || self.system_default_ttl > self.system_max_ttl
            || self.system_max_ttl > MAX_PUBLIC_TTL
        {
            return Err("invalid opaque Kubernetes artifact contract");
        }
        Ok(())
    }
    pub(super) fn public_ttl(&self, lifetime_nanos: i64) -> Result<u64, &'static str> {
        self.validate()?;
        let requested_nanos = i64::try_from(self.requested_ttl)
            .map_err(|_| "artifact TTL overflow")?
            .checked_mul(1_000_000_000)
            .ok_or("artifact TTL overflow")?;
        let lifetime = lifetime_nanos.min(requested_nanos);
        let proposed = if lifetime <= 0 {
            self.system_default_ttl
        } else {
            u64::try_from(lifetime / 1_000_000_000).map_err(|_| "artifact TTL overflow")?
        };
        Ok(proposed.min(self.role_max_ttl).min(self.system_max_ttl))
    }
    pub(super) fn warnings(&self, lifetime_nanos: i64) -> Result<Vec<String>, &'static str> {
        self.validate()?;
        let requested_nanos = i64::try_from(self.requested_ttl)
            .map_err(|_| "artifact TTL overflow")?
            .checked_mul(1_000_000_000)
            .ok_or("artifact TTL overflow")?;
        let mut warnings = Vec::new();
        if lifetime_nanos != requested_nanos {
            let relation = if lifetime_nanos < requested_nanos {
                "less"
            } else {
                "greater"
            };
            let suffix = if lifetime_nanos < requested_nanos {
                "; capping the lease TTL accordingly"
            } else {
                ""
            };
            warnings.push(format!("the created Kubernetes service accout token TTL {} is {relation} than the OpenBao lease TTL {}{suffix}",
                                   duration(lifetime_nanos), duration(requested_nanos)));
        }
        if lifetime_nanos <= 0 {
            let maximum = self.role_max_ttl.min(self.system_max_ttl);
            if self.system_default_ttl > maximum {
                warnings.push(format!("TTL of \"{}\" exceeded the effective max_ttl of \"{}\"; TTL value is capped accordingly",
                                      compact_seconds(self.system_default_ttl), compact_seconds(maximum)));
            }
        }
        Ok(warnings)
    }
}

/// Complete serialized owner bytes are covered by the existing Engine owner/AAD.
/// `received_at` is sampled from the original private request clock at completion,
/// not JWT iat/exp or a new wall epoch. `admission` retains the original grant cap.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct LeaseObservation {
    pub(super) admission: LeaseAuthority,
    pub(super) contract: Contract,
    pub(super) request_digest: String,
    pub(super) config_digest: String,
    pub(super) received_at: Timestamp,
    pub(super) public_expires_at: Timestamp,
    pub(super) lifetime_nanos: i64,
    pub(super) public_ttl: u64,
    pub(super) retired: bool,
}

impl LeaseObservation {
    pub(super) fn registration_expiry(&self) -> Result<Timestamp, &'static str> {
        let public_ttl = self.contract.public_ttl(self.lifetime_nanos)?;
        let expiry = self
            .received_at
            .duration_since_epoch()
            .checked_add(std::time::Duration::from_secs(public_ttl))
            .ok_or("artifact expiry overflow")?;
        let mut end = Timestamp::checked(expiry.as_secs(), expiry.subsec_nanos())
            .map_err(|_| "artifact expiry overflow")?;
        // This type comes from actual authenticated owner resolution, never
        // public claims/type/body or the narrower effective private parent cap.
        if let Some(batch) = self.admission.owner.batch_claims() {
            let intrinsic = batch
                .precision()
                .map_or_else(
                    || Timestamp::whole(batch.expires_at()),
                    |lease| Ok(lease.expires_at),
                )
                .map_err(|_| "batch intrinsic expiry overflow")?;
            end = end.min(intrinsic);
        }
        Ok(end)
    }
    pub(super) fn registered_response_ttl(&self) -> Result<u64, &'static str> {
        // Official Register time.Until(actual public expiry).Round(time.Second).
        let end = self.public_expires_at.duration_since_epoch();
        let now = self.received_at.duration_since_epoch();
        let remaining = end.checked_sub(now).unwrap_or_default();
        remaining
            .as_secs()
            .checked_add(u64::from(remaining.subsec_nanos() >= 500_000_000))
            .ok_or("artifact duration overflow")
    }
    pub(super) fn lookup_ttl(&self, at: Timestamp) -> Result<u64, &'static str> {
        // Official leaseEntry.ttl: expire.Sub(now.Round(1s)).Seconds() -> int64.
        // This differs from registration Round and from floor(now).
        let now = at.duration_since_epoch();
        let rounded = now
            .as_secs()
            .checked_add(u64::from(now.subsec_nanos() >= 500_000_000))
            .ok_or("artifact clock overflow")?;
        Ok(self
            .public_expires_at
            .duration_since_epoch()
            .checked_sub(std::time::Duration::from_secs(rounded))
            .unwrap_or_default()
            .as_secs())
    }
    pub(super) fn validate(&self, public_expires_at: u64) -> Result<(), &'static str> {
        self.contract.validate()?;
        if self.received_at.seconds() < self.admission.issued_at
            || self.public_expires_at != self.registration_expiry()?
            || self.public_ttl != self.registered_response_ttl()?
            || self
                .public_expires_at
                .ceil_seconds()
                .map_err(|_| "artifact expiry overflow")?
                != public_expires_at
            || ![&self.request_digest, &self.config_digest]
                .into_iter()
                .all(|value| {
                    value.len() == 64
                        && value
                            .bytes()
                            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
                })
        {
            return Err("invalid opaque Kubernetes artifact lease observation");
        }
        Ok(())
    }
}

fn compact_seconds(value: u64) -> String {
    if value.is_multiple_of(3600) {
        format!("{}h", value / 3600)
    } else if value.is_multiple_of(60) {
        format!("{}m", value / 60)
    } else {
        format!("{value}s")
    }
}

fn duration(nanos: i64) -> String {
    let negative = if nanos < 0 { "-" } else { "" };
    let value = nanos.unsigned_abs();
    let seconds = value / 1_000_000_000;
    let fraction = value % 1_000_000_000;
    let tail = if fraction == 0 {
        format!("{}s", seconds % 60)
    } else {
        format!("{}.{:09}s", seconds % 60, fraction)
            .trim_end_matches('s')
            .trim_end_matches('0')
            .to_owned()
            + "s"
    };
    if seconds >= 3600 {
        format!("{negative}{}h{}m{tail}", seconds / 3600, seconds / 60 % 60)
    } else if seconds >= 60 {
        format!("{negative}{}m{tail}", seconds / 60)
    } else {
        format!("{negative}{tail}")
    }
}
