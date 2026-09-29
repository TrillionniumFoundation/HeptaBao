//! OpenBao 2.7 index middleware. An index is a replication prerequisite, never
//! authentication, read authority, a retry permit, or an application-state proof.
use super::*;
use base64::{
    Engine as _, alphabet,
    engine::{GeneralPurpose, GeneralPurposeConfig},
};
use serde::Serialize;
use serde::de::{self, MapAccess, Visitor};
use std::fmt;

const INDEX_PREFIX: &str = "heptabao-raft-v1:";
const MAX_INDEX: usize = 12 * 1024;

#[derive(Default, Serialize)]
pub(crate) struct IndexValue {
    pub(crate) cluster: String,
    pub(crate) value: String,
}

// Match Go's index object decoder without granting authority to input fields.
impl<'de> Deserialize<'de> for IndexValue {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct IndexVisitor;
        impl<'de> Visitor<'de> for IndexVisitor {
            type Value = IndexValue;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("an index object or null")
            }
            fn visit_unit<E: de::Error>(self) -> Result<Self::Value, E> {
                Ok(IndexValue::default())
            }
            fn visit_map<M: MapAccess<'de>>(self, mut map: M) -> Result<Self::Value, M::Error> {
                let mut result = IndexValue::default();
                while let Some(key) = map.next_key::<String>()? {
                    let slot = if key.eq_ignore_ascii_case("cluster") {
                        Some(&mut result.cluster)
                    } else if key.eq_ignore_ascii_case("value") {
                        Some(&mut result.value)
                    } else {
                        None
                    };
                    if let Some(slot) = slot {
                        if let Some(value) = map.next_value::<Option<String>>()? {
                            *slot = value;
                        }
                    } else {
                        map.next_value::<de::IgnoredAny>()?;
                    }
                }
                Ok(result)
            }
        }
        deserializer.deserialize_any(IndexVisitor)
    }
}
impl Drop for IndexValue {
    fn drop(&mut self) {
        self.cluster.zeroize();
        self.value.zeroize();
    }
}

fn codec() -> GeneralPurpose {
    // Go StdEncoding permits non-zero unused trailing bits but requires padding.
    GeneralPurpose::new(
        &alphabet::STANDARD,
        GeneralPurposeConfig::new().with_decode_allow_trailing_bits(true),
    )
}
impl IndexValue {
    pub(crate) fn for_raft(cluster: &str, index: u64) -> Self {
        Self {
            cluster: cluster.to_owned(),
            value: format!("{INDEX_PREFIX}{index}"),
        }
    }
    pub(crate) fn raft_index(&self) -> Option<u64> {
        let value = self.value.strip_prefix(INDEX_PREFIX)?;
        let index = value.parse::<u64>().ok()?;
        (index.to_string() == value).then_some(index)
    }
    pub(crate) fn wire(&self) -> Option<ResponseIndex> {
        let bytes = Zeroizing::new(serde_json::to_vec(self).ok()?);
        let value = codec().encode(bytes.as_slice());
        (value.len() <= MAX_INDEX).then_some(ResponseIndex(value))
    }
}
// Only encoded server-produced metadata can become a response header.
#[derive(Clone)]
pub(crate) struct ResponseIndex(String);
impl ResponseIndex {
    pub(crate) fn as_str(&self) -> &str {
        &self.0
    }
    pub(crate) fn raft_index_for_cluster(&self, cluster: &str) -> Option<u64> {
        let bytes = Zeroizing::new(codec().decode(self.0.as_bytes()).ok()?);
        let value: IndexValue = serde_json::from_slice(&bytes).ok()?;
        (value.cluster == cluster)
            .then(|| value.raft_index())
            .flatten()
    }
}
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(super) enum Fallback {
    #[default]
    Fail,
    Forward,
}
#[derive(Clone, Copy)]
pub(crate) struct Settings {
    wait: Duration,
    fallback: Fallback,
    missing_forward: bool,
}
impl Default for Settings {
    fn default() -> Self {
        Self {
            wait: Duration::from_millis(25),
            fallback: Fallback::Fail,
            missing_forward: false,
        }
    }
}
impl Settings {
    pub(super) fn checked(
        wait: Option<&str>,
        fallback: Option<&str>,
        missing_forward: bool,
    ) -> Result<Self, String> {
        let fallback = match fallback {
            None | Some("" | "fail") => Fallback::Fail,
            Some("forward-active-node") => Fallback::Forward,
            _ => return Err("invalid consistency_fallback_behavior".into()),
        };
        let wait = match wait {
            None => Duration::from_millis(25),
            Some(value) => {
                let (number, multiplier) = if let Some(number) = value.strip_suffix("ms") {
                    (number, 1_u64)
                } else if let Some(number) = value.strip_suffix('s') {
                    (number, 1_000)
                } else if let Some(number) = value.strip_suffix('m') {
                    (number, 60_000)
                } else {
                    return Err("consistency_max_index_wait requires ms, s or m units".into());
                };
                let millis = number
                    .parse::<u64>()
                    .ok()
                    .filter(|_| !number.is_empty() && number.bytes().all(|b| b.is_ascii_digit()))
                    .and_then(|number| number.checked_mul(multiplier))
                    .filter(|millis| *millis <= 60_000)
                    .ok_or("consistency_max_index_wait exceeds the bounded listener budget")?;
                Duration::from_millis(millis.max(25))
            }
        };
        Ok(Self {
            wait,
            fallback,
            missing_forward,
        })
    }
}
#[derive(Default)]
pub(super) struct RawHeaders {
    indices: Vec<Zeroizing<String>>,
    policies: Vec<Zeroizing<String>>,
}
#[derive(Default)]
pub(crate) struct Headers {
    index: Option<IndexValue>,
    present_policy: bool,
    await_state: bool,
    fallback: Option<Fallback>,
}
impl RawHeaders {
    pub(super) fn push(&mut self, name: &str, value: &str) -> Result<bool, ParseError> {
        match name {
            "x-vault-index" => {
                if !self.indices.is_empty() {
                    return Err(bad("expected at most one value for \"X-Vault-Index\""));
                }
                if value.len() > MAX_INDEX {
                    return Err(bad("index header exceeds limit"));
                }
                self.indices.push(Zeroizing::new(value.to_owned()));
            }
            "x-vault-inconsistent" => {
                if self.policies.len() >= 2 {
                    return Err(bad(
                        "expected at most two values for \"X-Vault-Inconsistent\"",
                    ));
                }
                self.policies.push(Zeroizing::new(value.to_owned()));
            }
            _ => return Ok(false),
        }
        Ok(true)
    }
    pub(super) fn finish(self) -> Result<Headers, ParseError> {
        let index = self
            .indices
            .first()
            .filter(|value| !value.is_empty())
            .map(|value| {
                let invalid = || bad("failed to decode \"X-Vault-Index\"");
                let bytes =
                    Zeroizing::new(codec().decode(value.as_bytes()).map_err(|_| invalid())?);
                serde_json::from_slice::<IndexValue>(&bytes).map_err(|_| invalid())
            })
            .transpose()?;
        let values = self.policies.iter().map(|v| v.as_str()).collect::<Vec<_>>();
        let (await_state, fallback) = match values.as_slice() {
            [] => (false, None),
            ["fail"] => (false, Some(Fallback::Fail)),
            ["forward-active-node"] => (false, Some(Fallback::Forward)),
            ["await-state"] => (true, None),
            ["await-state", "fail"] => (true, Some(Fallback::Fail)),
            ["await-state", "forward-active-node"] => (true, Some(Fallback::Forward)),
            ["fail", _] => {
                return Err(bad(
                    "X-Vault-Inconsistent=fail cannot be used with more than one value",
                ));
            }
            ["forward-active-node", _] => {
                return Err(bad(
                    "X-Vault-Inconsistent=forward-active-node cannot be used with more than one value",
                ));
            }
            ["await-state", _] => {
                return Err(bad(
                    "unknown second value for \"X-Vault-Inconsistent\": must either be \"fail\" or \"forward-active-node\"",
                ));
            }
            _ => return Err(bad("unknown value for \"X-Vault-Inconsistent\" header")),
        };
        Ok(Headers {
            index,
            present_policy: !values.is_empty(),
            await_state,
            fallback,
        })
    }
}

pub(crate) struct Observation {
    pub(crate) cluster: String,
    pub(crate) standby: bool,
    pub(crate) committed: Option<u64>,
    pub(crate) applied: Option<u64>,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum Decision {
    Continue,
    Forward,
    Await,
    Reject,
}
impl Headers {
    // Continue still enters the ordinary authorization and materialization path.
    pub(super) fn decide(
        &self,
        observation: Option<&Observation>,
        settings: Settings,
        elapsed: bool,
    ) -> Decision {
        let Some(observation) = observation else {
            return Decision::Continue;
        };
        if !observation.standby {
            return Decision::Continue;
        }
        let Some(index) = self
            .index
            .as_ref()
            .filter(|index| index.cluster == observation.cluster && !index.value.is_empty())
        else {
            return if settings.missing_forward && !self.present_policy {
                Decision::Forward
            } else {
                Decision::Continue
            };
        };
        let seen = index.raft_index().map(|required| {
            observation
                .applied
                .is_some_and(|applied| applied >= required)
                && observation
                    .committed
                    .is_some_and(|committed| committed >= required)
        });
        // Unknown backend values follow upstream's immediate comparison-error
        // path. Normal Service dispatch remains strong; awaiting cannot mark
        // an undecodable backend value as locally applied.
        if seen == Some(true) || (seen.is_none() && !self.await_state) {
            return Decision::Continue;
        }
        if self.await_state && !elapsed {
            return Decision::Await;
        }
        let fallback = self.fallback.unwrap_or(if self.await_state {
            settings.fallback
        } else {
            Fallback::Fail
        });
        if fallback == Fallback::Forward {
            Decision::Forward
        } else {
            Decision::Reject
        }
    }
}

pub(crate) fn admit(
    service: &Arc<Mutex<Service>>,
    headers: &Headers,
    settings: Settings,
    transport_deadline: Instant,
) -> Result<bool, Response> {
    if headers.index.is_none() && !settings.missing_forward {
        return Ok(false);
    }
    let deadline = execution_deadline_with_response_reserve(Instant::now(), transport_deadline);
    let wait_end = (Instant::now() + settings.wait).min(deadline);
    let _scope = RequestDeadlineScope::enter(deadline);
    loop {
        let observation = lock_until(service, deadline)
            .map_err(|_| Response::error(503, "consistency observation deadline exceeded"))?
            .consistency_observation()?;
        match headers.decide(observation.as_ref(), settings, Instant::now() >= wait_end) {
            Decision::Continue => return Ok(false),
            Decision::Forward => return Ok(true),
            Decision::Reject => {
                return Err(Response {
                    consistency_index: None,
                    status: 429,
                    body: json!({"errors": []}),
                });
            }
            Decision::Await => {
                let remaining = wait_end.saturating_duration_since(Instant::now());
                // Both locks are dropped before waiting. This consumes no
                // authentication grant and starts no business/provider effect.
                std::thread::sleep(remaining.min(Duration::from_millis(5)));
            }
        }
    }
}

pub(super) fn forward(
    service: &Arc<Mutex<Service>>,
    mut request: ServiceRequest<'_>,
    transport_deadline: Instant,
) -> Response {
    let deadline = execution_deadline_with_response_reserve(Instant::now(), transport_deadline);
    let _scope = RequestDeadlineScope::enter(deadline);
    match lock_until(service, deadline) {
        Ok(service) => service.forward_consistency_request(request, deadline),
        Err(_) => {
            crate::service::erase_json(&mut request.body);
            Response::error(503, "consistency forwarding deadline exceeded")
        }
    }
}

#[cfg(all(test, target_os = "linux"))]
pub(crate) fn test_headers(index: &str, policies: &[&str]) -> Result<Headers, &'static str> {
    let mut raw = RawHeaders::default();
    raw.push("x-vault-index", index)
        .map_err(|error| error.message)?;
    for policy in policies {
        raw.push("x-vault-inconsistent", policy)
            .map_err(|error| error.message)?;
    }
    raw.finish().map_err(|error| error.message)
}

#[cfg(test)]
mod duration_format_tests {
    use super::*;

    #[test]
    fn consistency270_duration_accepts_fractional_compound_and_small_units() -> Result<(), String> {
        for (input, nanos) in [
            ("25.5ms", 25_500_000),
            ("1s250ms", 1_250_000_000),
            ("0.5m", 30_000_000_000),
            ("0h0m0.125s", 125_000_000),
            ("25000us", 25_000_000),
            ("25001µs", 25_001_000),
            ("25002μs", 25_002_000),
            ("25000001ns", 25_000_001),
            (".025000001s", 25_000_001),
            ("+25ms", 25_000_000),
            ("0", 25_000_000),
            ("0.000000001s", 25_000_000),
            ("1.s", 1_000_000_000),
            ("0.9999999999s", 999_999_999),
            ("59s999ms999us999ns", 59_999_999_999),
            ("1m0s", 60_000_000_000),
        ] {
            let settings = Settings::checked(Some(input), None, false)?;
            assert_eq!(settings.wait, Duration::from_nanos(nanos), "{input}");
        }
        Ok(())
    }

    #[test]
    fn consistency270_duration_rejects_malformed_and_over_budget_values() {
        for input in [
            "",
            "+",
            "-1s",
            "1m1ns",
            "60.000000001s",
            "1d",
            "1e3ms",
            "1 s",
            "1s ",
            " 1s",
            ".s",
            "1..2s",
            "1s-2ms",
            "1ss",
            "NaNs",
            "Infms",
            "184467440737095516160s",
            "1m1m",
            "1.5",
            "1μ",
        ] {
            assert!(
                Settings::checked(Some(input), None, false).is_err(),
                "{input}"
            );
        }
        assert!(Settings::checked(Some(&"0".repeat(129)), None, false).is_err());
    }
}
