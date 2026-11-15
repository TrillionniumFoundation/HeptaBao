//! Prepare KV1 conversion without changing the retained mount or record graph.
use super::*;

pub(super) fn deadline() -> Result<()> {
    if crate::request_deadline::current()
        .is_some_and(|deadline| std::time::Instant::now() >= deadline)
    {
        return Err(error(
            503,
            "KV conversion deadline elapsed before publication",
        ));
    }
    Ok(())
}

pub(super) fn account_value(total: &mut usize, path: &str, bytes: usize) -> Result<()> {
    *total = total
        .checked_add(path.len())
        .and_then(|value| value.checked_add(bytes))
        .filter(|value| *value <= crate::MAX_APPLICATION_STATE_BYTES)
        .ok_or_else(|| error(507, "KV conversion exceeds application state capacity"))?;
    Ok(())
}

impl EngineState {
    pub(super) fn upgrade_kv_mount(
        &self,
        namespace: &str,
        name: &str,
        mount: &MountState,
        now: u64,
    ) -> Result<kv::Kv2> {
        deadline()?;
        let entries = match &mount.backend {
            Backend::Kv1(entries) => {
                let mut total = 0;
                for (path, value) in entries {
                    deadline()?;
                    valid_path(path)?;
                    if !value.is_object() {
                        return Err(error(503, "KV1 conversion source is not an object"));
                    }
                    let bytes =
                        crate::secret_serde::to_vec(value, crate::MAX_APPLICATION_STATE_BYTES)
                            .map_err(|_| {
                                error(507, "KV conversion exceeds application state capacity")
                            })?;
                    account_value(&mut total, path, bytes.len())?;
                }
                entries.clone()
            }
            Backend::Kv1Records => {
                self.record_kv1_conversion_values(namespace, name, mount.incarnation)?
            }
            _ => return Err(bad("KV conversion requires a version 1 mount")),
        };
        let converted = kv::Kv2::from_v1(entries, now);
        // Values plus metadata must fit the existing opaque engine-owner bound.
        // The Service additionally checks every other owner before publication.
        let _bytes = crate::secret_serde::to_vec(&converted, crate::MAX_APPLICATION_STATE_BYTES)
            .map_err(|_| error(507, "KV conversion exceeds application state capacity"))?;
        deadline()?;
        Ok(converted)
    }
}

#[cfg(test)]
#[path = "engine_kv_versioning_tests.rs"]
mod tests;
