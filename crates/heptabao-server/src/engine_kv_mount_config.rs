//! Durable KV mount configuration. Signed nanoseconds retain the reference's
//! configuration precision; they grant no lease, Actor or publication authority.
use super::*;

const NANOS: i64 = 1_000_000_000;

#[derive(Clone, Copy, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Configuration {
    format: u32,
    default_ttl_ns: i64,
    max_ttl_ns: i64,
    force_no_cache: bool,
}

impl Default for Configuration {
    fn default() -> Self {
        Self {
            format: 1,
            default_ttl_ns: 0,
            max_ttl_ns: 0,
            force_no_cache: false,
        }
    }
}

fn supplied_duration(body: &Value, field: &str) -> Result<Option<i64>> {
    let Some(value) = body.get(field) else {
        return Ok(None);
    };
    match value {
        Value::Null => Ok(None),
        Value::String(value) if value.is_empty() => Ok(None),
        Value::String(value) => crate::auth::kv_mount_configuration_duration(value)
            .map(Some)
            .map_err(|_| bad("invalid KV mount lease duration")),
        Value::Number(value) => value
            .as_i64()
            .and_then(|seconds| seconds.checked_mul(NANOS))
            .map(Some)
            .ok_or_else(|| bad("KV mount lease duration requires integer seconds")),
        _ => Err(bad("invalid KV mount lease duration")),
    }
}

impl Configuration {
    fn validate(&self) -> Result<()> {
        if self.format != 1 {
            return Err(error(503, "unsupported KV mount configuration format"));
        }
        // Zero inherits independently. The actual reference permits a zero
        // default with a nonzero maximum, and does not clamp non-leased KV1
        // reads to that maximum. Negative configuration remains signed data.
        if self.default_ttl_ns != 0 && self.max_ttl_ns != 0 && self.default_ttl_ns > self.max_ttl_ns
        {
            return Err(bad("default lease TTL exceeds maximum lease TTL"));
        }
        Ok(())
    }

    pub(super) fn enable(config: Option<&Value>) -> Result<Option<Self>> {
        let Some(config) = config else {
            return Ok(None);
        };
        let fields = config
            .as_object()
            .ok_or_else(|| error(501, "unsupported KV mount configuration"))?;
        if fields.keys().any(|field| {
            !matches!(
                field.as_str(),
                "options" | "default_lease_ttl" | "max_lease_ttl" | "force_no_cache"
            )
        }) || config.get("options").is_some_and(|value| !value.is_null())
        {
            return Err(error(501, "unsupported KV mount configuration option"));
        }
        let configured = Self {
            default_ttl_ns: supplied_duration(config, "default_lease_ttl")?.unwrap_or(0),
            max_ttl_ns: supplied_duration(config, "max_lease_ttl")?.unwrap_or(0),
            force_no_cache: optional_bool(config, "force_no_cache")?.unwrap_or(false),
            ..Self::default()
        };
        configured.validate()?;
        Ok((configured != Self::default()).then_some(configured))
    }

    pub(super) fn tune(prior: Option<&Self>, body: &Value) -> Result<Option<Self>> {
        let mut configured = prior.copied().unwrap_or_default();
        if let Some(value) = supplied_duration(body, "default_lease_ttl")? {
            configured.default_ttl_ns = value;
        }
        if let Some(value) = supplied_duration(body, "max_lease_ttl")? {
            configured.max_ttl_ns = value;
        }
        // OpenBao 2.7.1 accepts but ignores force_no_cache on tune in both
        // directions. Only mount creation chooses that durable flag.
        configured.validate()?;
        // Neutral historical SDK input retains its old representation. Once a
        // real configuration exists, tuning back to zero retains its format.
        Ok((prior.is_some() || configured != Self::default()).then_some(configured))
    }

    pub(super) fn project_descriptor(&self, descriptor: &mut Value) {
        descriptor["config"]["default_lease_ttl"] = json!(self.default_ttl_ns / NANOS);
        descriptor["config"]["max_lease_ttl"] = json!(self.max_ttl_ns / NANOS);
        descriptor["config"]["force_no_cache"] = json!(self.force_no_cache);
    }
}

impl EngineState {
    pub(crate) fn has_kv_mount_configuration(&self) -> bool {
        self.namespaces.values().any(|owner| {
            owner
                .mounts
                .values()
                .any(|mount| mount.kv_configuration.is_some())
        })
    }

    pub(crate) fn validate_kv_mount_configuration(&self) -> Result<()> {
        for owner in self.namespaces.values() {
            for mount in owner.mounts.values() {
                if let Some(configuration) = &mount.kv_configuration {
                    if !matches!(
                        mount.backend,
                        Backend::Kv1(_)
                            | Backend::Kv1Records
                            | Backend::Kv2(_)
                            | Backend::Kv2Native(_)
                    ) {
                        return Err(error(503, "KV configuration has a different backend owner"));
                    }
                    configuration.validate()?;
                }
            }
        }
        Ok(())
    }

    /// Exact registry selection distinguishes inherited zero from a retained
    /// fractional duration that only rounds to zero in its public projection.
    pub(crate) fn kv_mount_tune_duration_nanos(
        &self,
        namespace: &str,
        path: &str,
    ) -> Option<(i64, i64)> {
        let relative = path.strip_prefix("sys/mounts/")?.trim_end_matches('/');
        let name = format!("{}/", relative.strip_suffix("/tune")?);
        let mount = self.namespaces.get(namespace)?.mounts.get(&name)?;
        if !matches!(
            mount.backend,
            Backend::Kv1(_) | Backend::Kv1Records | Backend::Kv2(_) | Backend::Kv2Native(_)
        ) {
            return None;
        }
        let configuration = mount.kv_configuration.unwrap_or_default();
        Some((configuration.default_ttl_ns, configuration.max_ttl_ns))
    }

    /// The caller already proved an actual KV1 value read. Retain its longest
    /// mount identity and use the current admitted metadata snapshot.
    pub(crate) fn kv1_default_lease_duration_nanos(
        &self,
        namespace: &str,
        path: &str,
    ) -> Option<i64> {
        let (_, mount) = self
            .namespaces
            .get(namespace)?
            .mounts
            .iter()
            .filter(|(name, _)| path.starts_with(name.as_str()))
            .max_by_key(|(name, _)| name.len())?;
        matches!(mount.backend, Backend::Kv1(_) | Backend::Kv1Records)
            .then_some(mount.kv_configuration.unwrap_or_default().default_ttl_ns)
    }
}
