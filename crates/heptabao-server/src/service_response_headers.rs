//! Response headers are separate transport metadata, retained through the same
//! affine SDK delivery capsule. Values are wiped when the response is withheld.
use serde_json::Value;
use std::collections::BTreeMap;
use std::io::{self, Write};
use zeroize::{Zeroize, Zeroizing};

#[derive(Default)]
pub(crate) struct Headers(BTreeMap<String, Vec<Zeroizing<String>>>);
impl Drop for Headers {
    fn drop(&mut self) {
        for (mut name, values) in std::mem::take(&mut self.0) {
            name.zeroize();
            drop(values);
        }
    }
}
fn valid_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 256
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b))
}
fn transport_owned(name: &str) -> bool {
    matches!(
        name.to_ascii_lowercase().as_str(),
        "content-length"
            | "transfer-encoding"
            | "connection"
            | "keep-alive"
            | "proxy-connection"
            | "upgrade"
            | "trailer"
            | "te"
            | "host"
            | "x-vault-index"
            | "x-vault-namespace"
    )
}
pub(crate) fn validate_allowlist(names: &[String]) -> bool {
    names.len() <= 64
        && names
            .iter()
            .all(|name| valid_name(name) && !transport_owned(name))
}
fn canonical_name(name: &str) -> String {
    let mut first = true;
    name.bytes()
        .map(|b| {
            let b = if first {
                b.to_ascii_uppercase()
            } else {
                b.to_ascii_lowercase()
            };
            first = b == b'-';
            char::from(b)
        })
        .collect()
}
impl Headers {
    pub(crate) fn from_sdk(value: Option<&Value>, allowed: &[String]) -> Result<Self, ()> {
        Self::from_bounded_map(value, allowed, 32)
    }
    fn from_bounded_map(
        value: Option<&Value>,
        allowed: &[String],
        max_values: usize,
    ) -> Result<Self, ()> {
        if allowed.is_empty() {
            return Ok(Self::default());
        }
        if !validate_allowlist(allowed) {
            return Err(());
        }
        let Some(value) = value.filter(|v| !v.is_null()) else {
            return Ok(Self::default());
        };
        let map = value.as_object().ok_or(())?;
        let mut result = Self::default();
        let mut total = 0usize;
        for (name, values) in map {
            // OpenBao's routing.filteredHeaders performs exact, case-insensitive
            // matching. A literal '*' in the configuration does not enable a glob.
            if !allowed
                .iter()
                .any(|allowed| allowed.eq_ignore_ascii_case(name))
            {
                continue;
            }
            if !valid_name(name) || transport_owned(name) {
                return Err(());
            }
            let values = values.as_array().ok_or(())?;
            if values.len() > max_values {
                return Err(());
            }
            let mut selected = Vec::with_capacity(values.len());
            for value in values {
                let value = value.as_str().ok_or(())?;
                if value.len() > 4096
                    || value
                        .bytes()
                        .any(|b| (b < 32 && !matches!(b, b'\r' | b'\n' | b'\t')) || b == 127)
                {
                    return Err(());
                }
                // Go net/http replaces CR/LF and trims surrounding whitespace.
                let sanitized = Zeroizing::new(
                    value
                        .replace(['\r', '\n'], " ")
                        .trim_matches([' ', '\t'])
                        .to_owned(),
                );
                total = total
                    .checked_add(name.len() + sanitized.len() + 4)
                    .ok_or(())?;
                if total > 32 * 1024 {
                    return Err(());
                }
                selected.push(sanitized);
            }
            let name = canonical_name(name);
            result.0.entry(name).or_default().extend(selected);
        }
        Ok(result)
    }
    pub(crate) fn copy_for_forward(&self) -> Self {
        Self(
            self.0
                .iter()
                .map(|(name, values)| {
                    (
                        name.clone(),
                        values
                            .iter()
                            .map(|value| Zeroizing::new(value.as_str().to_owned()))
                            .collect(),
                    )
                })
                .collect(),
        )
    }
    pub(crate) fn clear(&mut self) {
        *self = Self::default();
    }
    pub(crate) fn write(&self, writer: &mut impl Write) -> io::Result<()> {
        for (name, values) in &self.0 {
            // OpenBao's final JSON and outer listener writers overwrite these
            // two allowed fields after logical response headers were added.
            if matches!(name.as_str(), "Content-Type" | "Strict-Transport-Security") {
                continue;
            }
            for value in values {
                write!(writer, "{name}: {}\r\n", value.as_str())?
            }
        }
        Ok(())
    }
    pub(crate) fn has_date(&self) -> bool {
        self.0.get("Date").is_some_and(|values| !values.is_empty())
    }
    pub(crate) fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

// The negotiated HA response carries already-filtered metadata. Its bounded
// deserializer accepts no framing/control header, and secret string values keep
// the same wiping ownership as a local response. This never supplies an ACL.
impl serde::Serialize for Headers {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeMap;
        let mut map = serializer.serialize_map(Some(self.0.len()))?;
        for (name, values) in &self.0 {
            let borrowed: Vec<&str> = values.iter().map(|value| value.as_str()).collect();
            map.serialize_entry(name, &borrowed)?;
        }
        map.end()
    }
}
struct HeaderValue(Value);
impl Drop for HeaderValue {
    fn drop(&mut self) {
        super::erase_json(&mut self.0);
    }
}
impl<'de> serde::Deserialize<'de> for Headers {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value = HeaderValue(<Value as serde::Deserialize>::deserialize(deserializer)?);
        let map = value.0.as_object().ok_or_else(|| {
            serde::de::Error::custom("HA response headers require bounded object")
        })?;
        let names: Vec<String> = map.keys().cloned().collect();
        // Local case variants may merge into more than 32 canonical values.
        // Each admitted line costs at least five bytes; keep the same 32KiB
        // total bound instead of narrowing an already admitted response.
        Self::from_bounded_map(Some(&value.0), &names, 32 * 1024 / 5)
            .map_err(|()| serde::de::Error::custom("HA response header metadata rejected"))
    }
}
