//! Data-only logical request fields. This scope grants no authentication authority.
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{cell::RefCell, collections::BTreeMap};
use zeroize::Zeroize;
pub(crate) type Headers = BTreeMap<String, Vec<String>>;
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct QueryProfile {
    pub(crate) namespace_id: String,
    pub(crate) incarnation: u64,
    pub(crate) path: String,
    pub(crate) version: u64,
    pub(crate) document: String,
    pub(crate) digest: [u8; 32],
}
#[derive(Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct DataFrame {
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub(crate) headers: Headers,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub(crate) query: BTreeMap<String, Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) profile: Option<QueryProfile>,
}
impl std::fmt::Debug for DataFrame {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("LogicalRequestData([REDACTED])")
    }
}
impl DataFrame {
    pub(crate) fn validate(&self) -> Result<(), &'static str> {
        validate_headers(&self.headers)?;
        if self.query.len() > 64 {
            return Err("workflow query exceeds field bound");
        }
        let mut bytes = 0usize;
        for (key, values) in &self.query {
            if key.is_empty()
                || key.len() > 64
                || key.contains('\0')
                || values.is_empty()
                || values.len() > 64
            {
                return Err("invalid workflow query data");
            }
            bytes = bytes
                .checked_add(key.len())
                .ok_or("workflow query overflows")?;
            for value in values {
                if value.len() > 16 * 1024 || value.contains('\0') {
                    return Err("invalid workflow query value");
                }
                bytes = bytes
                    .checked_add(value.len())
                    .ok_or("workflow query overflows")?;
            }
        }
        if bytes > 64 * 1024 {
            return Err("workflow query exceeds byte bound");
        }
        if let Some(profile) = &self.profile {
            if profile.namespace_id.is_empty()
                || (profile.namespace_id == "root") != (profile.incarnation == 0)
                || profile.version == 0
                || profile.path.is_empty()
                || profile.path.len() > 256
                || profile.document.is_empty()
                || profile.document.len() > 64 * 1024
                || crate::crypto::digest(profile.document.as_bytes()) != profile.digest
            {
                return Err("invalid workflow query definition binding");
            }
        }
        Ok(())
    }
}
pub(crate) fn validate_headers(headers: &Headers) -> Result<(), &'static str> {
    if headers.len() > 64 {
        return Err("logical header count exceeds bound");
    }
    let mut bytes = 0usize;
    for (key, values) in headers {
        if key.len() > 256 || values.len() > 64 {
            return Err("invalid logical header name or values");
        }
        bytes = bytes
            .checked_add(key.len())
            .ok_or("logical headers overflow")?;
        for value in values {
            if value.len() > 16 * 1024 {
                return Err("invalid logical header value");
            }
            bytes = bytes
                .checked_add(value.len())
                .ok_or("logical headers overflow")?;
        }
    }
    if bytes > 64 * 1024 {
        return Err("logical headers exceed byte bound");
    }
    Ok(())
}
pub(crate) fn erase_headers(headers: &mut Headers) {
    for values in headers.values_mut() {
        for value in values {
            value.zeroize();
        }
    }
    headers.clear();
}
impl Drop for DataFrame {
    fn drop(&mut self) {
        erase_headers(&mut self.headers);
        erase_headers(&mut self.query);
        if let Some(profile) = &mut self.profile {
            profile.document.zeroize();
        }
    }
}
struct Bound {
    digest: [u8; 32],
    frame: DataFrame,
}
thread_local! { static DATA: RefCell<Option<Bound>> = const { RefCell::new(None) }; }
// Request metadata is a data-only binding, not a storage or authorization
// grant. Hash the exact canonical JSON stream without retaining a second
// plaintext request copy. The 64 KiB allowance accounts for bounded
// method/path/namespace framing beyond the largest scoped JSON budget;
// ordinary routes are still fenced by their original 2 MiB HTTP entry.
const MAX_LOGICAL_BINDING_BYTES: usize = crate::http::MAX_KV2_JSON_WRITE_BODY + 64 * 1024;

fn binding(
    method: &str,
    path: &str,
    namespace: &str,
    body: &Value,
) -> Result<[u8; 32], &'static str> {
    struct DigestWriter {
        context: ring::digest::Context,
        count: usize,
    }
    impl std::io::Write for DigestWriter {
        fn write(&mut self, input: &[u8]) -> std::io::Result<usize> {
            let Some(next) = self
                .count
                .checked_add(input.len())
                .filter(|length| *length <= MAX_LOGICAL_BINDING_BYTES)
            else {
                return Err(std::io::Error::other(
                    "logical binding byte budget exceeded",
                ));
            };
            self.context.update(input);
            self.count = next;
            Ok(input.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let mut writer = DigestWriter {
        context: ring::digest::Context::new(&ring::digest::SHA256),
        count: 0,
    };
    // serde_json::to_writer uses the same canonical serializer as the old
    // Zeroizing to_vec path, so existing small-request digests are unchanged.
    serde_json::to_writer(
        &mut writer,
        &("logical-data-v1", method, path, namespace, body),
    )
    .map_err(|_| "logical request data binding exceeds bound")?;
    writer
        .context
        .finish()
        .as_ref()
        .try_into()
        .map_err(|_| "logical request digest unavailable")
}

pub(crate) struct Scope {
    previous: Option<Bound>,
    _thread: std::marker::PhantomData<std::rc::Rc<()>>,
}
impl Scope {
    pub(crate) fn enter(
        frame: Option<DataFrame>,
        method: &str,
        path: &str,
        namespace: &str,
        body: &Value,
    ) -> Result<Self, &'static str> {
        let value = frame
            .map(|frame| -> Result<Bound, &'static str> {
                frame.validate()?;
                Ok(Bound {
                    digest: binding(method, path, namespace, body)?,
                    frame,
                })
            })
            .transpose()?;
        let previous = DATA.with(|slot| slot.replace(value));
        Ok(Self {
            previous,
            _thread: std::marker::PhantomData,
        })
    }
}
impl Drop for Scope {
    fn drop(&mut self) {
        DATA.with(|slot| {
            slot.replace(self.previous.take());
        });
    }
}
pub(crate) fn current(
    method: &str,
    path: &str,
    namespace: &str,
    body: &Value,
) -> Result<Option<DataFrame>, &'static str> {
    DATA.with(|slot| {
        let slot = slot.borrow();
        let Some(bound) = slot.as_ref() else {
            return Ok(None);
        };
        if bound.digest != binding(method, path, namespace, body)? {
            return Err("logical request data belongs to another request");
        }
        Ok(Some(bound.frame.clone()))
    })
}

#[cfg(test)]
mod large_binding_tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn streaming_binding_matches_legacy_canonical_bytes() {
        let body = json!({"data":{"string":"abc","signed":-7,"number":1.5}});
        let tuple = ("logical-data-v1", "POST", "secret/data/item", "team", &body);
        let old = crate::secret_serde::to_vec(&tuple, 1024 * 1024)
            .ok()
            .expect("small canonical old digest");
        assert_eq!(
            binding("POST", "secret/data/item", "team", &body).unwrap(),
            crate::crypto::digest(&old),
        );
    }

    #[test]
    fn streaming_binding_accepts_1536k_and_rejects_changed_request_identity() {
        let original = json!({"data":{"payload":"J".repeat(1536 * 1024)}});
        let mut changed = original.clone();
        changed["data"]["payload"] = json!("K".repeat(1536 * 1024));
        let digest = binding("POST", "secret/data/large", "", &original).unwrap();
        assert_ne!(
            digest,
            binding("POST", "secret/data/large", "", &changed).unwrap(),
        );
        let scope = Scope::enter(
            Some(DataFrame::default()),
            "POST",
            "secret/data/large",
            "",
            &original,
        )
        .expect("bounded data-only original scope");
        assert!(
            current("POST", "secret/data/large", "", &original)
                .unwrap()
                .is_some()
        );
        assert!(current("POST", "secret/data/large", "", &changed).is_err());
        drop(scope);
        assert!(
            current("POST", "secret/data/large", "", &original)
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn streaming_binding_rejects_over_budget_before_using_digest() {
        let oversized = json!({"data":{"payload":"X".repeat(MAX_LOGICAL_BINDING_BYTES)}});
        assert!(binding("POST", "secret/data/too-large", "", &oversized).is_err());
    }
}
