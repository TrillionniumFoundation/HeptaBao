//! Ordinary Token API duration parsing and CalculateTTL are nanosecond exact.
//! They are deliberately not used for issuer publication until schema82's
//! explicit authority and provider/final-delivery graph is complete.
use super::token_precision::{DurationNanos, PrecisionError, Timestamp};
use super::{AuthError, Value, bad, token_duration};

fn weak_string(value: Option<&Value>, field: &str) -> Result<String, AuthError> {
    match value {
        None | Some(Value::Null) => Ok(String::new()),
        Some(Value::String(text)) => Ok(text.clone()),
        Some(Value::Bool(value)) => Ok(u8::from(*value).to_string()),
        // At actual HTTP ingress the private authorized numeric lexeme bridge
        // restores the original string; generic JSON Number is not evidence of
        // noncanonical numeric wire parity.
        Some(Value::Number(value)) => Ok(value.to_string()),
        Some(value) => Err(bad(&format!(
            "Field validation failed: error converting input for field {field:?}: '' expected type 'string', got unconvertible type '{}'",
            if value.is_array() {
                "[]interface {}"
            } else {
                "map[string]interface {}"
            }
        ))),
    }
}
fn positive_duration(text: &str, field: &str) -> Result<DurationNanos, AuthError> {
    let parsed = token_duration::parse_duration(text).map_err(|error| bad(&error))?;
    if parsed < 0 {
        return Err(bad(&format!("{field} must be positive")));
    }
    DurationNanos::checked(parsed as u64).map_err(|_| bad("invalid checked token duration"))
}
#[derive(Clone, Copy)]
pub(super) struct RequestedDurations {
    pub(super) ttl: DurationNanos,
    pub(super) period: DurationNanos,
    pub(super) explicit_max: DurationNanos,
}
impl RequestedDurations {
    pub(super) fn parse(body: &Value) -> Result<Self, AuthError> {
        // Framework validates type conversion before running the token handler.
        // Values are kept separate so ttl="0" takes precedence over lease while
        // ttl="" or null selects the compatibility alias.
        let ttl = weak_string(body.get("ttl"), "ttl")?;
        let lease = weak_string(body.get("lease"), "lease")?;
        let period = weak_string(body.get("period"), "period")?;
        let maximum = weak_string(body.get("explicit_max_ttl"), "explicit_max_ttl")?;
        let explicit_max = positive_duration(&maximum, "explicit_max_ttl")?;
        let period = positive_duration(&period, "period")?;
        let ttl = if ttl.is_empty() {
            positive_duration(&lease, "lease")?
        } else {
            positive_duration(&ttl, "ttl")?
        };
        Ok(Self {
            ttl,
            period,
            explicit_max,
        })
    }
}
pub(super) fn uses(body: &Value) -> Result<u64, AuthError> {
    let field = "num_uses";
    let text = match body.get(field) {
        None | Some(Value::Null) => String::new(),
        Some(Value::Bool(value)) => u8::from(*value).to_string(),
        Some(Value::String(text)) => text.clone(),
        Some(Value::Number(value)) => value.to_string(),
        Some(value) => {
            return Err(bad(&format!(
                "Field validation failed: error converting input for field {field:?}: '' expected type 'int', got unconvertible type '{}'",
                if value.is_array() {
                    "[]interface {}"
                } else {
                    "map[string]interface {}"
                }
            )));
        }
    };
    let parsed=token_duration::signed_int(if text.is_empty(){"0"}else{&text},true).map_err(|error|bad(&format!("Field validation failed: error converting input for field {field:?}: '' cannot parse value as 'int': strconv.ParseInt: {error}")))?;
    u64::try_from(parsed).map_err(|_| bad("number of uses cannot be negative"))
}

/// Renew's framework TypeDurationSecond truncates through float64 Seconds,
/// unlike ordinary creation's TypeString durations. Negative subsecond input
/// becomes zero; nonzero negative seconds are rejected before handler execution.
pub(super) fn renew_increment(body: &Value) -> Result<DurationNanos, AuthError> {
    let field = "increment";
    let text = match body.get(field) {
        None | Some(Value::Null) => {
            return DurationNanos::from_seconds(0).map_err(|_| bad("invalid checked increment"));
        }
        Some(Value::String(value)) => value.clone(),
        Some(Value::Number(value)) => value.to_string(),
        Some(_) => {
            return Err(bad(
                "Field validation failed: error converting input for field \"increment\": could not parse duration from input",
            ));
        }
    };
    let nanos = token_duration::parse_duration(&text).map_err(|error| {
        bad(&format!(
            "Field validation failed: error converting input for field {field:?}: {error}"
        ))
    })?;
    let seconds = (nanos as f64 / 1_000_000_000_f64) as i64;
    let seconds = u64::try_from(seconds).map_err(|_| bad(&format!("Field validation failed: error converting input for field {field:?}: cannot provide negative value '{seconds}'")))?;
    DurationNanos::from_seconds(seconds).map_err(|_| bad("invalid checked increment"))
}

#[derive(Clone, Copy)]
pub(super) struct TTLInputs {
    pub(super) default_ttl: DurationNanos,
    pub(super) mount_max: DurationNanos,
    pub(super) increment: DurationNanos,
    pub(super) backend_ttl: DurationNanos,
    pub(super) period: DurationNanos,
    pub(super) backend_max: DurationNanos,
    pub(super) explicit_max: DurationNanos,
    pub(super) start: Option<Timestamp>,
}
pub(super) struct TTLGrant {
    pub(super) ttl: DurationNanos,
    pub(super) warnings: Vec<String>,
}
#[derive(Debug, Eq, PartialEq)]
pub(super) enum TTLError {
    NonpositiveMax,
    PastMax,
    Checked(PrecisionError),
}
impl From<PrecisionError> for TTLError {
    fn from(value: PrecisionError) -> Self {
        Self::Checked(value)
    }
}
impl std::fmt::Display for TTLError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NonpositiveMax => f.write_str("max TTL must be greater than zero"),
            Self::PastMax => f.write_str("past the max TTL, cannot renew"),
            Self::Checked(value) => std::fmt::Display::fmt(value, f),
        }
    }
}
impl std::error::Error for TTLError {}

pub(super) fn calculate(input: TTLInputs, now: Timestamp) -> Result<TTLGrant, TTLError> {
    let now = now.truncate_seconds();
    let start = input.start.unwrap_or(now).truncate_seconds();
    if start > now {
        return Err(TTLError::Checked(PrecisionError::Clock));
    }
    let mut maximum = input.mount_max;
    for restrict in [input.backend_max, input.explicit_max] {
        if !restrict.is_zero() && restrict < maximum {
            maximum = restrict
        }
    }
    if maximum.is_zero() {
        return Err(TTLError::NonpositiveMax);
    }
    let mut warnings = Vec::new();
    let (mut ttl, maximum_time) = if !input.period.is_zero() {
        let period = if input.period > maximum {
            warnings.push(format!("period of {:?} exceeded the effective max_ttl of {:?}; period value is capped accordingly",human_duration(input.period),human_duration(maximum)));
            maximum
        } else {
            input.period
        };
        (
            period,
            if input.explicit_max.is_zero() {
                None
            } else {
                Some(start.checked_add(input.explicit_max)?)
            },
        )
    } else {
        let ttl = if !input.increment.is_zero() {
            input.increment
        } else if !input.backend_ttl.is_zero() {
            input.backend_ttl
        } else {
            input.default_ttl
        };
        (ttl, Some(start.checked_add(maximum)?))
    };
    if let Some(end) = maximum_time {
        if end <= now {
            return Err(TTLError::PastMax);
        }
        let remaining = end.elapsed(now)?;
        if ttl > remaining {
            warnings.push(format!("TTL of {:?} exceeded the effective max_ttl of {:?}; TTL value is capped accordingly",human_duration(ttl),human_duration(remaining)));
            ttl = remaining;
        }
    }
    Ok(TTLGrant { ttl, warnings })
}
fn decimal(integer: u64, remainder: u64, digits: usize) -> String {
    if remainder == 0 {
        integer.to_string()
    } else {
        let fraction = format!("{remainder:0digits$}");
        format!("{integer}.{}", fraction.trim_end_matches('0'))
    }
}
fn human_duration(value: DurationNanos) -> String {
    let ns = value.nanoseconds();
    if ns == 0 {
        return "0s".into();
    }
    if ns < 1_000 {
        return format!("{ns}ns");
    }
    if ns < 1_000_000 {
        return format!("{}µs", decimal(ns / 1_000, ns % 1_000, 3));
    }
    if ns < 1_000_000_000 {
        return format!("{}ms", decimal(ns / 1_000_000, ns % 1_000_000, 6));
    }
    let seconds = ns / 1_000_000_000;
    let hours = seconds / 3600;
    let minutes = seconds % 3600 / 60;
    let seconds = seconds % 60;
    let fraction = ns % 1_000_000_000;
    let mut text = String::new();
    if hours > 0 {
        text.push_str(&format!("{hours}h"))
    }
    if minutes > 0 {
        text.push_str(&format!("{minutes}m"))
    }
    if seconds > 0 || fraction > 0 {
        text.push_str(&decimal(seconds, fraction, 9));
        text.push('s')
    };
    text
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    type TestResult = Result<(), Box<dyn std::error::Error>>;
    fn span(ns: u64) -> DurationNanos {
        DurationNanos::checked(ns).unwrap()
    }
    fn at(seconds: u64, nanos: u32) -> Timestamp {
        Timestamp::checked(seconds, nanos).unwrap()
    }
    fn inputs() -> TTLInputs {
        TTLInputs {
            default_ttl: span(10_000_000_000),
            mount_max: span(32_000_000_000),
            increment: span(0),
            backend_ttl: span(0),
            period: span(0),
            backend_max: span(0),
            explicit_max: span(0),
            start: None,
        }
    }
    #[test]
    fn ordinary_fractional_durations_reject_negative_subseconds_and_preserve_lease_alias_priority()
    -> TestResult {
        for (field, text, ns) in [
            ("ttl", "500ms", 500_000_000),
            ("ttl", "1.5s", 1_500_000_000),
            ("ttl", "2500ms", 2_500_000_000),
            ("period", ".5s", 500_000_000),
            ("explicit_max_ttl", "1.5s", 1_500_000_000),
        ] {
            let mut body = json!({});
            body[field] = json!(text);
            let requested = RequestedDurations::parse(&body)?;
            let value = match field {
                "period" => requested.period,
                "explicit_max_ttl" => requested.explicit_max,
                _ => requested.ttl,
            };
            assert_eq!(value, span(ns));
            body[field] = json!("-0.5s");
            assert_eq!(
                RequestedDurations::parse(&body)
                    .err()
                    .ok_or("negative duration accepted")?
                    .message,
                format!("{field} must be positive")
            );
        }
        assert_eq!(
            RequestedDurations::parse(&json!({"ttl":0,"lease":"2s"}))?.ttl,
            span(0)
        );
        assert_eq!(
            RequestedDurations::parse(&json!({"ttl":null,"lease":"2s"}))?.ttl,
            span(2_000_000_000)
        );
        assert_eq!(
            RequestedDurations::parse(&json!({"ttl":false,"lease":"2s"}))?.ttl,
            span(0)
        );
        assert_eq!(
            RequestedDurations::parse(&json!({"ttl":true}))?.ttl,
            span(1_000_000_000)
        );
        assert_eq!(
            RequestedDurations::parse(&json!({"ttl":1.5}))
                .err()
                .ok_or("unit missing accepted")?
                .message,
            "time: missing unit in duration \"1.5\""
        );
        assert_eq!(
            RequestedDurations::parse(&json!({"ttl":"1e0"}))
                .err()
                .ok_or("exponent accepted")?
                .message,
            "time: unknown unit \"e\" in duration \"1e0\""
        );
        assert_eq!(
            RequestedDurations::parse(&json!({"ttl":[]}))
                .err()
                .ok_or("array accepted")?
                .message,
            "Field validation failed: error converting input for field \"ttl\": '' expected type 'string', got unconvertible type '[]interface {}'"
        );
        Ok(())
    }
    #[test]
    fn ordinary_num_uses_weak_int_preserves_signed_errors_and_i64_bounds() -> TestResult {
        for (value, expected) in [
            (json!(null), 0),
            (json!(false), 0),
            (json!(true), 1),
            (json!("0x10"), 16),
            (json!("020"), 16),
            (json!(i64::MAX), i64::MAX as u64),
        ] {
            assert_eq!(uses(&json!({"num_uses":value}))?, expected)
        }
        assert_eq!(
            uses(&json!({"num_uses":"-1"}))
                .err()
                .ok_or("negative uses accepted")?
                .message,
            "number of uses cannot be negative"
        );
        assert!(
            uses(&json!({"num_uses":9223372036854775808_u64}))
                .err()
                .ok_or("uses overflow")?
                .message
                .ends_with("strconv.ParseInt: value out of range")
        );
        assert!(
            uses(&json!({"num_uses":1.5}))
                .err()
                .ok_or("fraction uses")?
                .message
                .ends_with("strconv.ParseInt: invalid syntax")
        );
        Ok(())
    }
    #[test]
    fn calculate_ttl_truncates_only_clocks_and_keeps_fractional_grants_and_precise_issue_anchor()
    -> TestResult {
        let input = TTLInputs {
            backend_ttl: span(500_000_000),
            ..inputs()
        };
        let q = calculate(input, at(100, 900_000_000))?;
        assert_eq!(q.ttl, span(500_000_000));
        assert!(q.warnings.is_empty());
        // Expiration.RegisterAuth uses real time plus this exact grant. The
        // metadata CreationTime and CalculateTTL clock remain whole-second.
        assert_eq!(
            at(100, 900_000_000).checked_add(q.ttl)?,
            at(101, 400_000_000)
        );
        let q = calculate(
            TTLInputs {
                backend_ttl: span(10_000_000_000),
                explicit_max: span(1_500_000_000),
                start: Some(at(100, 900_000_000)),
                ..inputs()
            },
            at(101, 300_000_000),
        )?;
        assert_eq!(q.ttl, span(500_000_000));
        assert_eq!(
            q.warnings,
            vec![
                "TTL of \"10s\" exceeded the effective max_ttl of \"500ms\"; TTL value is capped accordingly"
            ]
        );
        assert!(matches!(
            calculate(
                TTLInputs {
                    explicit_max: span(1_500_000_000),
                    start: Some(at(100, 900_000_000)),
                    ..inputs()
                },
                at(102, 0)
            ),
            Err(TTLError::PastMax)
        ));
        Ok(())
    }
    #[test]
    fn period_lifetime_and_each_warning_format_follow_pinned_source() -> TestResult {
        let q = calculate(
            TTLInputs {
                period: span(500_000_000),
                start: Some(at(100, 900_000_000)),
                ..inputs()
            },
            at(1000, 100_000_000),
        )?;
        assert_eq!(q.ttl, span(500_000_000));
        assert!(q.warnings.is_empty());
        let q = calculate(
            TTLInputs {
                period: span(40_000_000_000),
                ..inputs()
            },
            at(100, 0),
        )?;
        assert_eq!(q.ttl, span(32_000_000_000));
        assert_eq!(
            q.warnings,
            vec![
                "period of \"40s\" exceeded the effective max_ttl of \"32s\"; period value is capped accordingly"
            ]
        );
        for (ns, text) in [
            (0, "0s"),
            (1, "1ns"),
            (1001, "1.001µs"),
            (1500000, "1.5ms"),
            (500000000, "500ms"),
            (60000000000, "1m"),
            (3600000000000, "1h"),
            (3600000000001, "1h0.000000001s"),
            (3661000000000, "1h1m1s"),
        ] {
            assert_eq!(human_duration(span(ns)), text)
        }
        assert!(matches!(
            calculate(
                TTLInputs {
                    mount_max: span(0),
                    ..inputs()
                },
                at(100, 0)
            ),
            Err(TTLError::NonpositiveMax)
        ));
        Ok(())
    }
}

#[cfg(test)]
mod increment_tests {
    use super::*;
    use serde_json::json;
    #[test]
    fn framework_renew_increment_is_whole_seconds_without_changing_creation_parser() {
        assert_eq!(
            renew_increment(&json!({"increment":"1.5s"}))
                .unwrap()
                .public_seconds(),
            1
        );
        assert_eq!(
            renew_increment(&json!({"increment":"-0.5s"}))
                .unwrap()
                .public_seconds(),
            0
        );
        assert!(renew_increment(&json!({"increment":"-1s"})).is_err());
        assert!(renew_increment(&json!({"increment":true})).is_err());
        assert_eq!(
            RequestedDurations::parse(&json!({"ttl":"1.5s"}))
                .unwrap()
                .ttl
                .nanoseconds(),
            1_500_000_000
        );
    }
}
