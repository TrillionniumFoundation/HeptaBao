//! Presentation-only proof for a signed, non-leased KV1 read response.
//! The admitted registry, never public JSON or a URL, is the local producer.
use super::*;

#[derive(Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct StaticKv1LeaseProjection {
    format: u8,
    namespace_digest: [u8; 32],
    path_digest: [u8; 32],
    logical_digest: [u8; 32],
    seconds: i64,
}

impl StaticKv1LeaseProjection {
    #[allow(clippy::too_many_arguments)]
    pub(super) fn capture(
        engines: &crate::engines::EngineState,
        namespace: &str,
        method: &str,
        path: &str,
        request: &Value,
        logical: &Value,
        status: u16,
    ) -> Result<Option<Self>, AuthError> {
        if status != 200 {
            return Ok(None);
        }
        let Some(seconds) = logical.get("lease_duration").and_then(Value::as_i64)
            .filter(|seconds| *seconds < 0) else {
            return Ok(None);
        };
        if !engines.is_kv1_value_read(namespace, method, path, request)
            || engines.kv1_default_lease_duration_nanos(namespace, path)
                .is_none_or(|value| value >= 0 || value / 1_000_000_000 != seconds)
        {
            return Err(err(503, "signed KV1 lease has no admitted registry owner"));
        }
        validate_namespace(namespace)?;
        validate_path(path, false)?;
        let projection = Self {
            format: 1,
            namespace_digest: crate::crypto::digest(namespace.as_bytes()),
            path_digest: crate::crypto::digest(path.as_bytes()),
            logical_digest: Self::logical_digest(logical)?,
            seconds,
        };
        projection.validate(logical)?;
        Ok(Some(projection))
    }

    pub(crate) fn validate(&self, logical: &Value) -> Result<(), AuthError> {
        if self.format != 1 || self.seconds >= 0
            || self.seconds < i64::MIN / 1_000_000_000
            || logical.get("lease_duration").and_then(Value::as_i64) != Some(self.seconds)
            || logical.get("renewable").and_then(Value::as_bool) != Some(false)
            || !logical.get("lease_id").is_none_or(|value| value.as_str() == Some(""))
            || !logical.get("auth").is_none_or(Value::is_null)
            || !logical.get("wrap_info").is_none_or(Value::is_null)
            || !logical.get("data").is_some_and(Value::is_object)
            || self.logical_digest != Self::logical_digest(logical)?
        {
            return Err(err(503, "signed KV1 static reply differs from its producer"));
        }
        Ok(())
    }

    fn logical_digest(logical: &Value) -> Result<[u8; 32], AuthError> {
        let bytes = crate::secret_serde::to_vec(logical, crate::MAX_APPLICATION_STATE_BYTES)
            .map_err(|_| err(503, "signed KV1 reply exceeds its admitted bound"))?;
        Ok(crate::crypto::digest(&bytes))
    }

    pub(crate) fn matches_scope(&self, namespace: &str, path: &str) -> bool {
        self.namespace_digest == crate::crypto::digest(namespace.as_bytes())
            && self.matches_path(path)
    }

    pub(super) fn matches_path(&self, path: &str) -> bool {
        self.path_digest == crate::crypto::digest(path.as_bytes())
    }

    pub(super) fn matches_namespace(&self, namespace: &str) -> bool {
        self.namespace_digest == crate::crypto::digest(namespace.as_bytes())
    }
}
