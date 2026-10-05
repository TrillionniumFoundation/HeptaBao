//! Role time policy from the pinned OpenBao 2.7 certificate producer.
//! Optional durable ownership preserves historical roles and protects reader89.
use super::*;

pub(super) const ROLE_TIME_FIELDS: &[&str] = &[
    "ttl",
    "not_before_duration",
    "not_before",
    "not_before_bound",
    "not_after",
    "not_after_bound",
];

#[derive(Clone, Serialize, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub(super) struct RoleTimePolicy {
    ttl: u64,
    not_before_duration: u64,
    not_before: String,
    not_before_bound: String,
    not_after: String,
    not_after_bound: String,
}

impl Default for RoleTimePolicy {
    fn default() -> Self {
        Self {
            ttl: 0,
            not_before_duration: 30,
            not_before: String::new(),
            not_before_bound: "permit".into(),
            not_after: String::new(),
            not_after_bound: "permit".into(),
        }
    }
}

pub(super) struct ResolvedRoleTime {
    pub(super) not_before: u64,
    pub(super) not_after: u64,
    pub(super) warnings: Vec<String>,
}

fn text_field(body: &Value, name: &str, default: &str) -> Result<String> {
    Ok(match body.get(name) {
        None => default.into(),
        Some(Value::Null) => String::new(),
        Some(Value::String(value)) => value.clone(),
        Some(Value::Number(value)) => value.to_string(),
        Some(Value::Bool(value)) => if *value { "1" } else { "0" }.into(),
        _ => return Err(bad(&format!("invalid PKI {name}"))),
    })
}

fn role_duration(body: &Value, name: &str, default: u64) -> Result<u64> {
    match body.get(name) {
        None => Ok(default),
        Some(Value::Null) => Ok(0),
        Some(Value::Number(value)) => value
            .as_u64()
            .or_else(|| {
                value
                    .as_f64()
                    .filter(|v| v.is_finite() && *v >= 0.0 && *v < i64::MAX as f64)
                    .map(|v| v.trunc() as u64)
            })
            .ok_or_else(|| bad(&format!("invalid PKI {name}"))),
        _ => ttl_field(body, name, default),
    }
}

fn absolute_time(value: &str, name: &str) -> Result<u64> {
    root_fields::rfc3339_seconds(value).map_err(|_| bad(&format!("invalid PKI {name}")))
}

impl RoleTimePolicy {
    pub(super) fn from_body(body: &Value, max_ttl: u64) -> Result<Self> {
        let policy = Self {
            ttl: role_duration(body, "ttl", 0)?,
            not_before_duration: role_duration(body, "not_before_duration", 30)?,
            not_before: text_field(body, "not_before", "")?,
            not_before_bound: text_field(body, "not_before_bound", "permit")?,
            not_after: text_field(body, "not_after", "")?,
            not_after_bound: text_field(body, "not_after_bound", "permit")?,
        };
        policy.validate(max_ttl)?;
        Ok(policy)
    }

    pub(super) fn validate(&self, max_ttl: u64) -> Result<()> {
        if self.ttl > MAX_TTL || self.not_before_duration > MAX_TTL {
            return Err(bad("PKI role time policy exceeds supported bounds"));
        }
        if max_ttl > 0 && self.ttl > max_ttl {
            return Err(bad("\"ttl\" value must be less than \"max_ttl\" value"));
        }
        if !matches!(
            self.not_before_bound.as_str(),
            "permit" | "duration" | "forbid"
        ) {
            return Err(bad(
                "Unknown value for field `not_before_bound`. Possible values are `permit` `duration` or `forbid`",
            ));
        }
        if !matches!(
            self.not_after_bound.as_str(),
            "permit" | "ttl-limited" | "forbid"
        ) {
            absolute_time(&self.not_after_bound, "not_after_bound")?;
        }
        Ok(())
    }

    pub(super) fn descriptor(&self) -> Value {
        json!({"ttl":self.ttl,"not_before_duration":self.not_before_duration,
            "not_before":self.not_before,"not_before_bound":self.not_before_bound,
            "not_after":self.not_after,"not_after_bound":self.not_after_bound})
    }

    pub(super) fn resolve(
        &self,
        request: &Value,
        role_max_ttl: u64,
        mount_default_ttl: u64,
        mount_max_ttl: u64,
        now: u64,
    ) -> Result<ResolvedRoleTime> {
        self.validate(role_max_ttl)?;
        let requested_before = text_field(request, "not_before", "")?;
        let before = if !self.not_before.is_empty() {
            absolute_time(&self.not_before, "not_before")?
        } else if !requested_before.is_empty() {
            if self.not_before_bound == "forbid" {
                return Err(bad(
                    "not_before_bound is set to forbid. not_before cannot be provided.",
                ));
            }
            let before = absolute_time(&requested_before, "not_before")?;
            if self.not_before_bound == "duration"
                && before < now.saturating_sub(self.not_before_duration)
            {
                return Err(bad(&format!(
                    "not_before_bound is set to duration. Cannot satisfy request as it would result in notBefore of {} that is older than the allowed not_before_duration of {}",
                    timestamp(before),
                    go_duration(self.not_before_duration)
                )));
            }
            before
        } else {
            now.saturating_sub(self.not_before_duration)
        };
        let requested_after = text_field(request, "not_after", "")?;
        let after_text = if !self.not_after.is_empty() {
            self.not_after.as_str()
        } else {
            if self.not_after_bound == "forbid" && !requested_after.is_empty() {
                return Err(bad(
                    "not_after_bound is set to forbid. not_after cannot be provided.",
                ));
            }
            requested_after.as_str()
        };
        let request_ttl = role_duration(request, "ttl", 0)?;
        if request_ttl > 0 && !after_text.is_empty() {
            return Err(bad(
                "Either ttl or not_after should be provided. Both should not be provided in the same request.",
            ));
        }
        let mut ttl = if request_ttl > 0 {
            request_ttl
        } else if self.ttl > 0 {
            self.ttl
        } else {
            mount_default_ttl
        };
        let max_ttl = if role_max_ttl > 0 {
            role_max_ttl
        } else {
            mount_max_ttl
        };
        let mut warnings = Vec::new();
        if ttl > max_ttl {
            warnings.push(format!(
                "TTL \"{}\" is longer than permitted maxTTL \"{}\", so maxTTL is being used",
                go_duration(ttl),
                go_duration(max_ttl)
            ));
            ttl = max_ttl;
        }
        let ttl_expiry = now
            .checked_add(ttl)
            .ok_or_else(|| bad("PKI lease TTL overflow"))?;
        let after = if after_text.is_empty() {
            ttl_expiry
        } else {
            absolute_time(after_text, "not_after")?
        };
        if self.not_after_bound == "ttl-limited" && self.not_after.is_empty() && after > ttl_expiry
        {
            return Err(bad(&format!(
                "not_after_bound is set to ttl-limited. Cannot satisfy request as that would result in notAfter of {} that is beyond the TTL of {}",
                timestamp(after),
                go_duration(ttl)
            )));
        }
        Ok(ResolvedRoleTime {
            not_before: before,
            not_after: after,
            warnings,
        })
    }
    pub(super) fn validate_final_not_after(&self, not_after: u64) -> Result<()> {
        if !matches!(
            self.not_after_bound.as_str(),
            "permit" | "ttl-limited" | "forbid"
        ) {
            let bound = absolute_time(&self.not_after_bound, "not_after_bound")?;
            if not_after > bound {
                return Err(bad(&format!(
                    "not_after_bound is set to {}. Cannot statisfy request as that would result in notAfter of {} that is beyond the maximum timestamp of {}",
                    self.not_after_bound,
                    timestamp(not_after),
                    timestamp(bound)
                )));
            }
        }
        Ok(())
    }
}

fn go_duration(seconds: u64) -> String {
    let hours = seconds / 3600;
    let minutes = seconds % 3600 / 60;
    let seconds = seconds % 60;
    if hours > 0 {
        format!("{hours}h{minutes}m{seconds}s")
    } else if minutes > 0 {
        format!("{minutes}m{seconds}s")
    } else {
        format!("{seconds}s")
    }
}

impl Pki {
    pub(in crate::engines) fn has_role_time_state(&self) -> bool {
        self.root
            .iter()
            .any(|root| root.leaf_not_after_behavior.is_some())
            || self.local_issuers.iter().any(|state| {
                state
                    .other
                    .values()
                    .chain(state.orphan_keys.values())
                    .any(|root| root.leaf_not_after_behavior.is_some())
            })
            || self
                .roles
                .values()
                .any(|role| role.role_time_policy.is_some() || role.max_ttl == 0)
            || self
                .issued
                .values()
                .any(|leaf| leaf.role_time_owned || leaf.issuer_not_after_behavior.is_some())
    }
}
