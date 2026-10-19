//! Explicit native-only migration profile. The ordinary 16-MiB JSON decoder
//! and legacy import remain unchanged. This proof conveys syntax, not custody.
use super::*;
use crate::state_records::RecordError;
use serde::de::{DeserializeSeed, MapAccess, SeqAccess, Visitor};
use std::fmt;
use std::collections::BTreeSet;
use zeroize::Zeroizing;

pub(crate) const PATH: &str = "sys/migration/openbao/kv2/native-large";
pub(crate) const MEDIA_TYPE: &str = "application/vnd.heptabao.kv2-lossless+json";
pub(crate) const MAX_BUNDLE_BYTES: usize = 64 * 1024 * 1024;
pub(crate) const MAX_RECORD_BYTES: usize = 4 * 1024 * 1024;
const MAX_NODES: usize = 1_048_576;
const MAX_DEPTH: usize = 128;

type CheckResult = std::result::Result<(), RecordError>;

/// Only this strict profile can construct the large input. No raw bytes may
/// select a decoder budget or bypass the Service's pre-body admission.
pub(crate) struct NativeLargeBundle(Zeroizing<Vec<u8>>);
impl NativeLargeBundle {
    pub(crate) fn checked(
        bytes: Zeroizing<Vec<u8>>,
        check: &impl Fn() -> CheckResult,
    ) -> Result<Self> {
        let rejected = || bad("native-large KV2 profile rejected");
        check().map_err(|_| error(503, "native-large KV2 original deadline exceeded"))?;
        if bytes.is_empty() || bytes.len() > MAX_BUNDLE_BYTES {
            return Err(rejected());
        }
        let mut budget = Budget { nodes: 0, check };
        let mut decoder = serde_json::Deserializer::from_slice(&bytes);
        Strict { budget: &mut budget, depth: 0 }
            .deserialize(&mut decoder).map_err(|_| rejected())?;
        decoder.end().map_err(|_| rejected())?;
        check().map_err(|_| error(503, "native-large KV2 original deadline exceeded"))?;
        // The outer closed schema is small metadata with borrowed raw payloads.
        // A single value still uses the ordinary lossless JSON decoder below.
        let input: Import<'_> = serde_json::from_slice(&bytes).map_err(|_| rejected())?;
        if input.schema != IMPORT_SCHEMA || input.entries.len() > MAX_IMPORT_ENTRIES {
            return Err(rejected());
        }
        let mut versions = 0_usize;
        for entry in input.entries.values() {
            check().map_err(|_| error(503, "native-large KV2 original deadline exceeded"))?;
            versions = versions.checked_add(entry.versions.len()).ok_or_else(rejected)?;
            if versions > MAX_IMPORT_VERSIONS
                || entry.versions.len() > MAX_RETAINED_VERSIONS as usize
                || entry.versions.values().any(|version| version.data.get().len() > MAX_RECORD_BYTES)
            {
                return Err(rejected());
            }
        }
        drop(input);
        check().map_err(|_| error(503, "native-large KV2 original deadline exceeded"))?;
        Ok(Self(bytes))
    }
}

impl Kv2 {
    pub(in crate::engines) fn from_native_large_import(
        input: &NativeLargeBundle,
        check: &impl Fn() -> CheckResult,
    ) -> Result<Self> {
        Self::from_validated_lossless_import_json(&input.0, &|| {
            check().map_err(|_| error(503, "native-large KV2 original deadline exceeded"))
        })
    }
}

// A validation-only token walk catches duplicate keys throughout the raw
// bundle without materializing a 64-MiB generic Value or relaxing domain JSON.
// Arbitrary precision numbers are only validated here; each actual payload is
// decoded by the original token-preserving domain decoder during projection.
struct Budget<'a> {
    nodes: usize,
    check: &'a dyn Fn() -> CheckResult,
}
struct Strict<'a, 'b> {
    budget: &'a mut Budget<'b>,
    depth: usize,
}
impl<'de> DeserializeSeed<'de> for Strict<'_, '_> {
    type Value = ();
    fn deserialize<D: serde::Deserializer<'de>>(self, decoder: D) -> std::result::Result<(), D::Error> {
        (self.budget.check)().map_err(serde::de::Error::custom)?;
        if self.depth > MAX_DEPTH || self.budget.nodes >= MAX_NODES {
            return Err(serde::de::Error::custom("native-large JSON structural bound"));
        }
        self.budget.nodes += 1;
        decoder.deserialize_any(self)
    }
}
struct Keys(BTreeSet<String>);
impl Drop for Keys {
    fn drop(&mut self) {
        for mut key in std::mem::take(&mut self.0) { key.zeroize(); }
    }
}
impl<'de> Visitor<'de> for Strict<'_, '_> {
    type Value = ();
    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("bounded native-large JSON token")
    }
    fn visit_bool<E: serde::de::Error>(self, _: bool) -> std::result::Result<(), E> { Ok(()) }
    fn visit_i64<E: serde::de::Error>(self, _: i64) -> std::result::Result<(), E> { Ok(()) }
    fn visit_u64<E: serde::de::Error>(self, _: u64) -> std::result::Result<(), E> { Ok(()) }
    fn visit_f64<E: serde::de::Error>(self, _: f64) -> std::result::Result<(), E> { Ok(()) }
    fn visit_unit<E: serde::de::Error>(self) -> std::result::Result<(), E> { Ok(()) }
    fn visit_none<E: serde::de::Error>(self) -> std::result::Result<(), E> { Ok(()) }
    fn visit_str<E: serde::de::Error>(self, _: &str) -> std::result::Result<(), E> { Ok(()) }
    fn visit_string<E: serde::de::Error>(self, mut text: String) -> std::result::Result<(), E> {
        text.zeroize(); Ok(())
    }
    fn visit_seq<A: SeqAccess<'de>>(self, mut sequence: A) -> std::result::Result<(), A::Error> {
        while sequence.next_element_seed(Strict {
            budget: &mut *self.budget, depth: self.depth + 1,
        })?.is_some() {}
        Ok(())
    }
    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> std::result::Result<(), A::Error> {
        let mut keys = Keys(BTreeSet::new());
        while let Some(key) = map.next_key::<String>()? {
            let key = Zeroizing::new(key);
            if !keys.0.insert(key.to_string()) {
                return Err(serde::de::Error::custom("duplicate native-large JSON key"));
            }
            map.next_value_seed(Strict {
                budget: &mut *self.budget, depth: self.depth + 1,
            })?;
        }
        Ok(())
    }
}

#[cfg(test)]
#[path = "kv_lossless_native_large_tests.rs"]
mod tests;
