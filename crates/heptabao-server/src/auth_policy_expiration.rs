//! OpenBao 2.7.1 policy and path expiration. The original request clock owns
//! evaluation; neither an integer projection nor a new wall-clock sample can
//! renew a grant. Source bytes keep every path, including expired paths.
use super::*;
use chrono::{DateTime, FixedOffset};

pub(crate) const STATE_SCHEMA: u32 = 143;
const GO_ZERO_SECONDS: i64 = -62_135_596_800;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(try_from = "DeadlineWire", into = "DeadlineWire")]
pub(super) struct Deadline {
    seconds: i64,
    nanoseconds: u32,
    offset_seconds: i32,
}

#[derive(Clone, Copy, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct DeadlineWire {
    seconds: i64,
    nanoseconds: u32,
    offset_seconds: i32,
}

impl TryFrom<DeadlineWire> for Deadline {
    type Error = &'static str;
    fn try_from(value: DeadlineWire) -> Result<Self, Self::Error> {
        if value.nanoseconds >= 1_000_000_000
            || value.offset_seconds % 60 != 0
            || value.offset_seconds.unsigned_abs() >= 86_400
        {
            return Err("invalid policy expiration");
        }
        Ok(Self {
            seconds: value.seconds,
            nanoseconds: value.nanoseconds,
            offset_seconds: value.offset_seconds,
        })
    }
}

impl From<Deadline> for DeadlineWire {
    fn from(value: Deadline) -> Self {
        Self {
            seconds: value.seconds,
            nanoseconds: value.nanoseconds,
            offset_seconds: value.offset_seconds,
        }
    }
}

fn invalid() -> AuthError {
    bad("invalid policy expiration time")
}

fn precise(time: AuthorityTime) -> Result<Timestamp, AuthError> {
    time.exact()
        .ok_or_else(|| err(503, "precise policy expiration clock is unavailable"))
}

impl Deadline {
    fn epoch(seconds: i64) -> Self {
        Self {
            seconds,
            nanoseconds: 0,
            offset_seconds: 0,
        }
    }

    fn from_timestamp(at: Timestamp) -> Result<Self, AuthError> {
        let wall = at.duration_since_epoch();
        Ok(Self {
            seconds: i64::try_from(wall.as_secs()).map_err(|_| invalid())?,
            nanoseconds: wall.subsec_nanos(),
            offset_seconds: 0,
        })
    }

    fn instant(self) -> (i64, u32) {
        (self.seconds, self.nanoseconds)
    }

    fn is_go_zero(self) -> bool {
        self.instant() == (GO_ZERO_SECONDS, 0)
    }

    pub(super) fn live(self, time: AuthorityTime) -> Result<bool, AuthError> {
        // GetPolicy and ACL construction use now.After(expiration): equality
        // remains valid, unlike the strict-future check for a policy write.
        Ok(Self::from_timestamp(precise(time)?)?.instant() <= self.instant())
    }

    pub(super) fn render(self) -> Result<String, AuthError> {
        let epoch = DateTime::from_timestamp(self.seconds, self.nanoseconds).ok_or_else(invalid)?;
        let offset = FixedOffset::east_opt(self.offset_seconds).ok_or_else(invalid)?;
        let local = epoch.with_timezone(&offset);
        let year = local.format("%Y").to_string();
        if year.len() != 4 || !year.bytes().all(|byte| byte.is_ascii_digit()) {
            return Err(invalid());
        }
        let mut rendered = local.format("%Y-%m-%dT%H:%M:%S").to_string();
        if self.nanoseconds != 0 {
            rendered.push('.');
            rendered.push_str(format!("{:09}", self.nanoseconds).trim_end_matches('0'));
        }
        if self.offset_seconds == 0 {
            rendered.push('Z');
        } else {
            let minutes = self.offset_seconds.unsigned_abs() / 60;
            rendered.push(if self.offset_seconds < 0 { '-' } else { '+' });
            rendered.push_str(&format!("{:02}:{:02}", minutes / 60, minutes % 60));
        }
        Ok(rendered)
    }

    fn earlier(self, other: Self) -> Self {
        if self.instant() <= other.instant() {
            self
        } else {
            other
        }
    }
}

/// ParseAbsoluteTime's integer epochs include negative values. A historical
/// path may already be expired; parsing it must not reject the whole policy.
pub(super) fn absolute(value: &Value) -> Result<Deadline, AuthError> {
    match value {
        Value::Number(value) => value.as_i64().map(Deadline::epoch).ok_or_else(invalid),
        Value::String(value) => {
            if let Ok(seconds) = token_duration::signed_int(value, false) {
                return Ok(Deadline::epoch(seconds));
            }
            // RFC3339's separator and four-digit year are part of the pinned
            // grammar. Chrono also accepts relaxed spellings, so do not silently
            // broaden this policy boundary to a space or lower-case separator.
            let bytes = value.as_bytes();
            if bytes.len() < 20
                || bytes.get(10) != Some(&b'T')
                || !bytes[..4].iter().all(u8::is_ascii_digit)
                || (!value.ends_with('Z')
                    && !matches!(bytes.get(bytes.len().saturating_sub(6)), Some(b'+' | b'-')))
            {
                return Err(invalid());
            }
            let parsed = DateTime::parse_from_rfc3339(value).map_err(|_| invalid())?;
            Deadline::try_from(DeadlineWire {
                seconds: parsed.timestamp(),
                nanoseconds: parsed.timestamp_subsec_nanos(),
                offset_seconds: parsed.offset().local_minus_utc(),
            })
            .map_err(|_| invalid())
        }
        _ => Err(invalid()),
    }
}

pub(super) fn path(value: Option<&Value>) -> Result<Option<Deadline>, AuthError> {
    match value {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(value)) if value.is_empty() => Ok(None),
        // The pinned HCL decoder converts a NUMBER token to its spelling
        // before assigning ExpirationRaw. Floats still fail ParseAbsoluteTime.
        Some(value @ Value::String(_)) => absolute(value).map(Some),
        Some(Value::Number(value)) => absolute(&Value::String(value.to_string())).map(Some),
        Some(_) => Err(bad("path expiration must be a string or integer epoch")),
    }
}

pub(super) fn expired_at_compile(
    expiration: Option<Deadline>,
    at: Option<Timestamp>,
) -> Result<bool, AuthError> {
    match (expiration, at) {
        (Some(deadline), Some(at)) => Ok(!deadline.live(AuthorityTime::Precise(at))?),
        _ => Ok(false),
    }
}

pub(super) fn prepare(
    existing: Option<&Policy>,
    body: &Value,
    patch: bool,
    time: AuthorityTime,
) -> Result<Option<Deadline>, AuthError> {
    let expiration = body.get("expiration").filter(|value| !value.is_null());
    let ttl = body.get("ttl").filter(|value| !value.is_null());
    if expiration.is_some() && ttl.is_some() {
        return Err(bad(
            "cannot supply both 'expiration' and 'ttl' for policies",
        ));
    }
    let deadline = if let Some(value) = expiration {
        let mut parsed = absolute(value)?;
        // framework.TypeTime normalizes absolute API inputs to UTC.
        parsed.offset_seconds = 0;
        (!parsed.is_go_zero()).then_some(parsed)
    } else if let Some(value) = ttl {
        let spelling = match value {
            Value::String(value) => value.clone(),
            Value::Number(value) => value.to_string(),
            _ => return Err(bad("invalid policy ttl")),
        };
        // framework.TypeDurationSecond converts int(time.Duration.Seconds()).
        // Go first splits whole seconds and the signed nanosecond remainder;
        // casting the whole nanosecond count to float can round differently.
        // A sub-second or zero TTL remains present for the future check below.
        let nanos = token_duration::parse_duration(&spelling).map_err(|message| bad(&message))?;
        let seconds = ((nanos / 1_000_000_000) as f64
            + (nanos % 1_000_000_000) as f64 / 1_000_000_000_f64) as i64;
        if seconds < 0 {
            return Err(bad("policy ttl cannot be negative"));
        }
        let span = token_precision::DurationNanos::from_seconds(seconds as u64)
            .map_err(|_| bad("policy ttl exceeds supported range"))?;
        Some(Deadline::from_timestamp(
            precise(time)?.checked_add(span).map_err(|_| invalid())?,
        )?)
    } else if patch {
        existing.and_then(|policy| policy.expiration)
    } else {
        None
    };
    if let Some(deadline) = deadline {
        if Deadline::from_timestamp(precise(time)?)?.instant() >= deadline.instant() {
            return Err(bad(
                "refusing to update policy as expiration time has already elapsed",
            ));
        }
        deadline.render()?;
    }
    Ok(deadline)
}

impl Rule {
    pub(super) fn live(&self, time: AuthorityTime) -> Result<bool, AuthError> {
        self.expiration
            .map_or(Ok(true), |deadline| deadline.live(time))
    }
}

impl Policy {
    pub(super) fn live(&self, time: AuthorityTime) -> Result<bool, AuthError> {
        if self.expired_default {
            return Ok(false);
        }
        self.expiration
            .map_or(Ok(true), |deadline| deadline.live(time))
    }

    pub(super) fn has_expiration(&self) -> bool {
        self.expired_default
            || self.expiration.is_some()
            || self.path_compiled_at.is_some()
            || self.rules.iter().any(|rule| rule.expiration.is_some())
    }

    pub(super) fn expired_default() -> Self {
        Self {
            namespace_factory: None,
            security: None,
            expiration: None,
            path_compiled_at: None,
            expired_default: true,
            source: String::new(),
            rules: Vec::new(),
            control_groups: BTreeMap::new(),
        }
    }

    pub(super) fn control_group_projection(
        &self,
    ) -> Result<BTreeMap<String, Vec<control_groups::StanzaControl>>, AuthError> {
        control_groups::canonical_policy_projection_observed(
            &self.source,
            &self.rules,
            &self.control_groups,
            self.path_compiled_at,
        )
    }

    pub(super) fn validate_expiration(&self) -> Result<(), AuthError> {
        if self.expired_default {
            if self.security.is_some()
                || self.expiration.is_some()
                || self.path_compiled_at.is_some()
                || !self.source.is_empty()
                || !self.rules.is_empty()
                || !self.control_groups.is_empty()
            {
                return Err(bad("invalid expired default policy owner"));
            }
            return Ok(());
        }
        if let Some(deadline) = self.expiration {
            let metadata = self
                .security
                .as_ref()
                .ok_or_else(|| bad("policy expiration has no writer metadata"))?;
            if deadline.is_go_zero()
                || deadline.offset_seconds != 0
                || deadline.instant() <= Deadline::from_timestamp(metadata.modified)?.instant()
            {
                return Err(bad("invalid policy expiration writer binding"));
            }
            deadline.render()?;
        }
        if let Some(at) = self.path_compiled_at {
            if self
                .security
                .as_ref()
                .is_none_or(|metadata| metadata.modified != at)
            {
                return Err(bad("policy path compilation clock has no writer binding"));
            }
        } else if self.rules.iter().any(|rule| rule.expiration.is_some()) {
            return Err(bad(
                "policy path expiration has no original compilation clock",
            ));
        }
        // A missing compiled expiration must not widen a source path. Reparse
        // only at owner admission, never per request; retain original raw bytes.
        self.control_group_projection()?;
        Ok(())
    }
}

impl AuthState {
    pub(crate) fn has_policy_expiration_state(&self) -> bool {
        self.policies
            .values()
            .flat_map(BTreeMap::values)
            .any(Policy::has_expiration)
    }

    pub(crate) fn validate_policy_expiration_state(&self) -> Result<(), AuthError> {
        for policies in self.policies.values() {
            for (name, policy) in policies {
                if policy.expired_default && name != "default" {
                    return Err(bad("expired default policy has a different owner"));
                }
                policy.validate_expiration()?;
            }
        }
        Ok(())
    }

    /// This bounds a single immutable capabilities observation. Rechecking
    /// credential identity must not assign a later lifetime to the old reply.
    pub(super) fn inspection_policy_deadline(
        &self,
        namespace: &str,
        policies: &BTreeSet<String>,
        identity_policies: &BTreeSet<String>,
        time: AuthorityTime,
    ) -> Result<Option<Deadline>, AuthError> {
        let mut earliest: Option<Deadline> = None;
        for name in policies.iter().chain(identity_policies) {
            let Some(policy) = self
                .policies
                .get(namespace)
                .and_then(|entries| entries.get(name))
            else {
                continue;
            };
            if !policy.live(time)? {
                continue;
            }
            for deadline in policy
                .expiration
                .into_iter()
                .chain(policy.rules.iter().filter_map(|rule| rule.expiration))
            {
                if deadline.live(time)? {
                    earliest = Some(earliest.map_or(deadline, |old| old.earlier(deadline)));
                }
            }
        }
        Ok(earliest)
    }
}

#[cfg(test)]
#[path = "auth_policy_expiration_tests.rs"]
mod tests;
