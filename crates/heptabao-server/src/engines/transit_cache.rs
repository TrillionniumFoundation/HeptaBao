//! Non-authoritative policy acceleration. Only the installed Service state may
//! publish fingerprints; transaction candidates can consume an equal policy but
//! cannot authorize their own replacement. Runtime entries never enter serde.
use super::*;
use std::{
    collections::VecDeque,
    io::{self, Write},
    sync::{Arc, MutexGuard},
};

#[derive(Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
enum Format { V1 }

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Config {
    format: Format,
    size: u64,
}

#[derive(Clone, PartialEq, Eq)]
struct Owner {
    namespace: String,
    namespace_incarnation: u64,
    mount: String,
    mount_incarnation: u64,
}

#[derive(Default)]
pub(super) struct Runtime {
    owner: Option<Owner>,
    published_generation: Option<u64>,
    active_size: u64,
    basis: BTreeMap<String, [u8; 32]>,
    entries: BTreeMap<String, ([u8; 32], Arc<Key>)>,
    order: VecDeque<String>,
}

struct Fingerprint(Sha256);
impl Write for Fingerprint {
    fn write(&mut self, input: &[u8]) -> io::Result<usize> {
        if crate::request_deadline::current().is_some_and(|deadline| std::time::Instant::now() >= deadline) {
            return Err(io::Error::other("original request deadline expired"));
        }
        self.0.update(input);
        Ok(input.len())
    }
    fn flush(&mut self) -> io::Result<()> { Ok(()) }
}

fn fingerprint(key: &Key) -> Result<[u8; 32]> {
    let mut writer = Fingerprint(Sha256::new());
    serde_json::to_writer(&mut writer, key)
        .map_err(|_| error(503, "transit policy fingerprint unavailable"))?;
    Ok(writer.0.finalize().into())
}

fn size(value: &Value) -> Result<u64> {
    let value = match value {
        Value::Number(value) => value.as_i64(),
        Value::String(value) => value.parse::<i64>().ok(),
        _ => None,
    }.ok_or_else(|| bad("cache size must be an integer"))?;
    if value != 0 && value < 10 { return Err(bad("cache size must be zero or at least 10")); }
    u64::try_from(value).map_err(|_| bad("cache size must be zero or at least 10"))
}

impl Runtime {
    fn touch(&mut self, name: &str) {
        self.order.retain(|value| value != name);
        self.order.push_back(name.to_owned());
    }

    fn trim(&mut self) {
        while self.active_size != 0 && self.entries.len() as u64 > self.active_size {
            let Some(name) = self.order.pop_front() else { break };
            self.entries.remove(&name);
        }
    }

    fn publish(&mut self, owner: Owner, generation: u64, configured: u64,
        basis: BTreeMap<String, [u8; 32]>) {
        if self.owner.as_ref() != Some(&owner) {
            *self = Self { owner: Some(owner), active_size: configured, ..Self::default() };
        }
        self.entries.retain(|name, (hash, _)| basis.get(name) == Some(hash));
        self.order.retain(|name| self.entries.contains_key(name));
        self.basis = basis;
        self.published_generation = Some(generation);
        self.trim();
    }
}

impl Transit {
    fn policy_cache_lock(&self) -> Result<MutexGuard<'_, Runtime>> {
        match crate::request_deadline::current() {
            Some(deadline) => crate::request_deadline::lock_until(&self.policy_cache, deadline)
                .map_err(|_| error(503, "transit policy cache original deadline or owner unavailable")),
            None => self.policy_cache.lock().map_err(|_| error(503, "transit policy cache unavailable")),
        }
    }

    #[cfg(test)]
    pub(in crate::engines) fn policy_cache_observation(&self) -> Result<(u64, usize)> {
        let runtime = self.policy_cache_lock()?;
        Ok((runtime.active_size, runtime.entries.len()))
    }

    #[cfg(test)]
    pub(in crate::engines) fn policy_cache_entry_observation(&self, name: &str)
        -> Result<Option<(u64, std::sync::Weak<dyn std::any::Any + Send + Sync>)>> {
        let runtime = self.policy_cache_lock()?;
        Ok(runtime.entries.get(name).map(|(_, policy)| {
            let version = policy.latest_version;
            let erased: Arc<dyn std::any::Any + Send + Sync> = Arc::clone(policy) as Arc<_>;
            (version, Arc::downgrade(&erased))
        }))
    }


    pub(in crate::engines) fn policy_cache_config_identity(&self) -> Option<u64> {
        self.cache_config.as_ref().map(|config| config.size)
    }

    /// Called only with engines borrowed from the installed accepted State.
    /// Prepare every fingerprint and acquire every distinct mutex before the
    /// first mutation, so a failed owner/deadline cannot partially reload.
    pub(in crate::engines) fn reload_policy_cache_batch(
        namespace: &str, namespace_incarnation: u64, generation: u64,
        engines: &[(&Self, &str, u64)],
    ) -> Result<()> {
        let mut prepared = Vec::with_capacity(engines.len());
        for (index, (engine, mount, mount_incarnation)) in engines.iter().enumerate() {
            if engines[..index].iter().any(|(old, _, _)|
                Arc::ptr_eq(&old.policy_cache, &engine.policy_cache)) {
                return Err(error(503, "transit reload runtime owners are aliased"));
            }
            let mut basis = BTreeMap::new();
            for (name, key) in &engine.keys {
                basis.insert(name.clone(), fingerprint(key)?);
            }
            prepared.push((Owner {
                namespace: namespace.to_owned(), namespace_incarnation,
                mount: (*mount).to_owned(), mount_incarnation: *mount_incarnation,
            }, engine.policy_cache_config_identity().unwrap_or(0), basis));
        }
        let mut locks = Vec::with_capacity(engines.len());
        for (engine, _, _) in engines { locks.push(engine.policy_cache_lock()?); }
        if crate::request_deadline::current().is_some_and(|deadline|
            std::time::Instant::now() >= deadline) {
            return Err(error(503, "transit reload original deadline expired"));
        }
        for (mut runtime, (owner, configured, basis)) in locks.into_iter().zip(prepared) {
            // Dropping the old entries drops their Arc<Key> ownership. KeyVersion
            // already zeroizes its private material when the last owner leaves.
            *runtime = Runtime { owner: Some(owner), published_generation: Some(generation),
                active_size: configured, basis, ..Runtime::default() };
        }
        Ok(())
    }

    pub(in crate::engines) fn has_policy_cache_state(&self) -> bool { self.cache_config.is_some() }

    pub(in crate::engines) fn validate_policy_cache_state(&self, previous: Option<&Self>) -> Result<()> {
        if self.cache_config.as_ref().is_some_and(|config|
            config.format != Format::V1 || config.size > i64::MAX as u64
                || config.size != 0 && config.size < 10)
            || previous.is_some_and(Self::has_policy_cache_state) && self.cache_config.is_none()
        {
            return Err(error(503, "invalid or erased transit cache configuration"));
        }
        Ok(())
    }

    pub(super) fn policy_cache_config(&mut self, method: &str, body: &Value)
        -> Result<EngineResponse> {
        if method == "GET" {
            return Ok(ok(json!({"size":self.cache_config.as_ref().map_or(0, |config| config.size)}), false));
        }
        if !write_method(method) { return Err(unsupported()); }
        reject_unknown(body, &["size"])?;
        let requested = size(body.get("size").ok_or_else(|| bad("cache size is required"))?)?;
        // An explicit zero on an ordinary historical engine keeps the omitted
        // representation. Once configured, zero retains the known reader floor.
        if requested != 0 || self.cache_config.is_some() {
            self.cache_config = Some(Config { format: Format::V1, size: requested });
        }
        Ok(ok(json!({"size":requested}), true))
    }

    /// An absent durable/catalog owner confers no cache authority. Historical
    /// trusted native namespaces still read their installed policies directly.
    /// Erasing the shared runtime also drops any old retained Arc<Key> entries.
    pub(in crate::engines) fn invalidate_unowned_policy_cache(&self) -> Result<()> {
        *self.policy_cache_lock()? = Runtime::default();
        Ok(())
    }

    pub(in crate::engines) fn synchronize_policy_cache(&self, namespace: &str, namespace_incarnation: u64,
        mount: &str, mount_incarnation: u64, generation: u64) -> Result<()> {
        let owner = Owner { namespace: namespace.to_owned(), namespace_incarnation,
            mount: mount.to_owned(), mount_incarnation };
        {
            let runtime = self.policy_cache_lock()?;
            if runtime.owner.as_ref() == Some(&owner) && runtime.published_generation == Some(generation) {
                return Ok(());
            }
        }
        let mut basis = BTreeMap::new();
        for (name, key) in &self.keys {
            basis.insert(name.clone(), fingerprint(key)?);
        }
        let configured = self.cache_config.as_ref().map_or(0, |config| config.size);
        self.policy_cache_lock()?
            .publish(owner, generation, configured, basis);
        Ok(())
    }

    pub(super) fn cached_policy(&self, name: &str) -> Result<Arc<Key>> {
        let key = self.keys.get(name).ok_or_else(not_found)?;
        let hash = fingerprint(key)?;
        let mut runtime = self.policy_cache_lock()?;
        // A COW candidate shares runtime custody but cannot publish a new key,
        // version, permission, or replacement under that shared current owner.
        if runtime.owner.is_none() || runtime.basis.get(name) != Some(&hash) {
            return Ok(Arc::new(key.clone()));
        }
        if let Some((stored_hash, cached)) = runtime.entries.get(name)
            && *stored_hash == hash
        {
            let policy = Arc::clone(cached);
            runtime.touch(name);
            return Ok(policy);
        }
        let policy = Arc::new(key.clone());
        runtime.entries.insert(name.to_owned(), (hash, Arc::clone(&policy)));
        runtime.touch(name);
        runtime.trim();
        Ok(policy)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    type TestResult = std::result::Result<(), &'static str>;
    fn call(t: &mut Transit, method: &str, path: &str, body: Value)
        -> std::result::Result<EngineResponse, &'static str> {
        t.handle("team", "transit/", method, path, &body, 100)
            .map_err(|_| "actual transit cache test route")
    }
    fn snapshot(t: &Transit) -> std::result::Result<Zeroizing<Vec<u8>>, &'static str> {
        crate::secret_serde::to_vec(t, crate::MAX_APPLICATION_STATE_BYTES)
            .map_err(|_| "private transit snapshot")
    }

    #[test]
    fn cache130_lru_real_policy_consumption_eviction_and_pending_configuration_restart() -> TestResult {
        let mut t = Transit::default();
        assert!(call(&mut t, "POST", "config/cache", json!({"size":10}))?.status == 200);
        for number in 0..11 {
            assert!(call(&mut t, "POST", &format!("keys/k{number}"), json!({"exportable":true}))?.status == 200);
        }
        t.synchronize_policy_cache("team", 7, "transit/", 9, 1).map_err(|_| "publish current policies")?;
        let first = t.cached_policy("k0").map_err(|_| "first actual policy")?;
        assert!(Arc::ptr_eq(&first, &t.cached_policy("k0").map_err(|_| "same actual policy")?));
        for number in 1..11 {
            assert!(call(&mut t, "GET", &format!("keys/k{number}"), json!({}))?.status == 200);
        }
        {
            let runtime = t.policy_cache.lock().map_err(|_| "cache lock")?;
            assert!(runtime.active_size == 10 && runtime.entries.len() == 10
                && !runtime.entries.contains_key("k0") && runtime.order.front().is_some_and(|key| key == "k1"));
        }
        assert!(!Arc::ptr_eq(&first, &t.cached_policy("k0").map_err(|_| "evicted actual policy")?));
        assert!(call(&mut t, "GET", "export/encryption-key/k0", json!({}))?.status == 200);
        assert!(call(&mut t, "POST", "config/cache", json!({"size":0}))?.body["data"]["size"] == 0);
        t.synchronize_policy_cache("team", 7, "transit/", 9, 2).map_err(|_| "same runtime activation")?;
        assert!(t.policy_cache.lock().map_err(|_| "cache lock")?.active_size == 10);
        let raw = snapshot(&t)?;
        let restored: Transit = serde_json::from_slice(&raw).map_err(|_| "restore persisted configuration")?;
        restored.synchronize_policy_cache("team", 7, "transit/", 9, 2).map_err(|_| "restart activation")?;
        assert!(restored.policy_cache.lock().map_err(|_| "cache lock")?.active_size == 0);
        for number in 0..11 { restored.cached_policy(&format!("k{number}")).map_err(|_| "unlimited actual policy")?; }
        assert!(restored.policy_cache.lock().map_err(|_| "cache lock")?.entries.len() == 11);
        assert!(snapshot(&restored)? == raw);
        Ok(())
    }

    #[test]
    fn cache130_uncommitted_candidates_rotation_permissions_and_incarnation_cannot_publish_authority() -> TestResult {
        let mut current = Transit::default();
        call(&mut current, "POST", "keys/key", json!({"exportable":true}))?;
        current.synchronize_policy_cache("team", 1, "transit/", 1, 1).map_err(|_| "current publish")?;
        let old = current.cached_policy("key").map_err(|_| "current policy")?;
        let before = snapshot(&current)?;
        let mut rejected = current.clone();
        call(&mut rejected, "POST", "keys/key/soft-delete", json!({}))?;
        let different = rejected.cached_policy("key").map_err(|_| "candidate policy")?;
        assert!(different.deleted && !Arc::ptr_eq(&old, &different));
        assert!(Arc::ptr_eq(&old, &current.cached_policy("key").map_err(|_| "retained current")?));
        assert!(snapshot(&current)? == before);
        assert!(call(&mut rejected, "GET", "export/encryption-key/key", json!({})).is_err());
        assert!(snapshot(&current)? == before);
        call(&mut current, "POST", "keys/key/rotate", json!({}))?;
        current.synchronize_policy_cache("team", 1, "transit/", 1, 2).map_err(|_| "committed rotation")?;
        let next = current.cached_policy("key").map_err(|_| "rotated policy")?;
        assert!(next.latest_version == 2 && old.latest_version == 1 && !Arc::ptr_eq(&old, &next));
        current.synchronize_policy_cache("team", 1, "transit/", 2, 2).map_err(|_| "new actual mount incarnation")?;
        assert!(!Arc::ptr_eq(&next, &current.cached_policy("key").map_err(|_| "recreated mount")?));
        current.synchronize_policy_cache("team", 2, "transit/", 2, 2).map_err(|_| "new namespace incarnation")?;
        assert!(current.policy_cache.lock().map_err(|_| "cache lock")?.owner.as_ref()
            .is_some_and(|owner| owner.namespace_incarnation == 2));
        Ok(())
    }

    #[test]
    fn cache130_missing_installed_owner_retires_cached_material_without_changing_policy() -> TestResult {
        let mut current = Transit::default();
        call(&mut current, "POST", "config/cache", json!({"size":10}))?;
        call(&mut current, "POST", "keys/key", json!({"exportable":true}))?;
        current.synchronize_policy_cache("legacy-team", 7, "transit/", 9, 1)
            .map_err(|_| "previous installed owner")?;
        let policy = current.cached_policy("key").map_err(|_| "retained cached material")?;
        let retained = Arc::downgrade(&policy);
        drop(policy);
        assert!(retained.upgrade().is_some());
        let before = snapshot(&current)?;
        current.invalidate_unowned_policy_cache().map_err(|_| "retire missing actual owner")?;
        assert!(retained.upgrade().is_none(), "no runtime owner keeps the old material alive");
        let first = current.cached_policy("key").map_err(|_| "installed uncached policy")?;
        let second = current.cached_policy("key").map_err(|_| "second uncached policy")?;
        assert!(!Arc::ptr_eq(&first, &second));
        {
            let runtime = current.policy_cache.lock().map_err(|_| "cache lock")?;
            assert!(runtime.owner.is_none() && runtime.published_generation.is_none()
                && runtime.basis.is_empty() && runtime.entries.is_empty() && runtime.order.is_empty());
        }
        assert!(snapshot(&current)? == before, "cache invalidation cannot edit durable policy/configuration");
        Ok(())
    }

    #[test]
    fn cache130_wire_integer_bounds_strict_decoder_and_ordinary_serde_omit_runtime() -> TestResult {
        let mut t = Transit::default();
        let initial = snapshot(&t)?;
        assert!(!initial.windows(b"cache_config".len()).any(|window| window == b"cache_config"));
        assert!(call(&mut t, "GET", "config/cache", json!({}))?.body["data"]["size"] == 0);
        for value in [json!(9),json!(-1),json!(10.5),json!(true),json!(null)] {
            let before = snapshot(&t)?;
            assert!(t.handle("team","transit/","POST","config/cache",&json!({"size":value}),100).is_err_and(|e| e.status == 400));
            assert!(snapshot(&t)? == before);
        }
        assert!(call(&mut t, "POST", "config/cache", json!({"size":"10"}))?.body["data"]["size"] == 10);
        assert!(t.has_policy_cache_state());
        let stored = snapshot(&t)?;
        for invalid in [json!({"format":"V1","size":9}),json!({"format":"V1","size":10,"unknown":1}),json!({"format":"V2","size":10})] {
            let mut forged: Value = serde_json::from_slice(&stored).map_err(|_| "synthetic private test decode")?;
            forged["cache_config"] = invalid;
            match serde_json::from_value::<Transit>(forged) {
                Ok(forged) => assert!(forged.validate_policy_cache_state(Some(&t)).is_err()),
                Err(_) => {}
            }
        }
        let mut erased = t.clone(); erased.cache_config = None;
        assert!(erased.validate_policy_cache_state(Some(&t)).is_err());
        assert!(call(&mut t, "POST", "config/cache", json!({"size":0}))?.body["data"]["size"] == 0 && t.has_policy_cache_state());
        assert!(!snapshot(&t)?.windows(b"policy_cache".len()).any(|window| window == b"policy_cache"));
        call(&mut t, "POST", "keys/key", json!({}))?;
        t.synchronize_policy_cache("team", 1, "transit/", 1, 1).map_err(|_| "actual current policy basis")?;
        let before = snapshot(&t)?;
        let _deadline = crate::request_deadline::RequestDeadlineScope::enter(std::time::Instant::now());
        assert!(t.handle("team","transit/","GET","keys/key",&json!({}),100).is_err_and(|e| e.status == 503));
        assert!(snapshot(&t)? == before && t.policy_cache.lock().map_err(|_| "cache lock")?.entries.is_empty());
        Ok(())
    }
}
