//! Deployment-owned genuine KMS bridge bindings. HTTP input cannot install these.
use super::*;
use heptabao_domain::{CanonicalPath, Id, SecretValue};
use heptabao_plugin_contracts::{PluginDescriptor, PluginKind, PluginRegistry};
use heptabao_plugin_host::kms_bridge::{Invocation, Operation, ProviderResult};
use heptabao_plugin_host::{
    CommandSandboxRunner, PluginHost, PluginHostState, PluginLimits, PluginManifest,
    PluginOperation, SandboxBinding, SecretEnvironment,
};
use serde::Deserialize;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, Mutex};

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PluginExternalKmsConfig {
    pub id: String,
    pub command: String,
    pub command_sha256: String,
    pub sandbox_provider_id: String,
    pub sandbox_command: String,
    pub sandbox_command_sha256: String,
    pub sandbox_profile_id: String,
    pub deployment_file: String,
    pub deployment_sha256: String,
    pub owned_temp: String,
    #[serde(default = "enabled")]
    pub enabled: bool,
    #[serde(default = "request_bytes")]
    pub maximum_request_bytes: usize,
    #[serde(default = "response_bytes")]
    pub maximum_response_bytes: usize,
    #[serde(default = "timeout_ms")]
    pub timeout_ms: u64,
}
fn enabled() -> bool {
    true
}
fn request_bytes() -> usize {
    256 * 1024
}
fn response_bytes() -> usize {
    1024 * 1024
}
fn timeout_ms() -> u64 {
    5000
}
pub(super) struct Binding {
    pins: Vec<OperatorPin>,
    pub(super) host: plugin::SharedKmsPlugin,
    operator_environment: BTreeMap<String, String>,
    timeout_ms: u64,
    enabled: bool,
}
pub(super) type Bindings = BTreeMap<String, Arc<Binding>>;
pub(super) struct Admitted {
    id: String,
    binding: Arc<Binding>,
    generation: u64,
    invocation: Invocation,
}
impl Admitted {
    /// A fresh protocol nonce for another operation on the same original
    /// operator binding and generation. This never performs a new admission.
    pub(super) fn for_operation(
        &self,
        operation: Operation,
        input: &SecretValue,
    ) -> Result<Self, Response> {
        Ok(Self {
            id: self.id.clone(),
            binding: Arc::clone(&self.binding),
            generation: self.generation,
            invocation: Invocation::new(operation, input).map_err(plugin::failure)?,
        })
    }

    pub(super) fn host(&self) -> plugin::SharedKmsPlugin {
        Arc::clone(&self.binding.host)
    }
    pub(super) fn host_ref(&self) -> &plugin::SharedKmsPlugin {
        &self.binding.host
    }
    pub(super) fn current(&self, bindings: &Bindings) -> bool {
        bindings.get(&self.id).is_some_and(|b| {
            Arc::ptr_eq(b, &self.binding) && b.enabled && b.pins.iter().all(OperatorPin::unchanged)
        })
    }
    pub(super) fn host_current(&self, guard: &PluginHost<CommandSandboxRunner>) -> bool {
        guard.state() == PluginHostState::Active
            && guard.manifest().descriptor().generation() == self.generation
            && self.binding.pins.iter().all(OperatorPin::unchanged)
    }
    pub(super) fn execute(&self) -> Result<ProviderResult, Response> {
        let mut guard = self
            .binding
            .host
            .try_lock()
            .map_err(|_| Response::error(503, "genuine KMS provider busy before entry"))?;
        if !self.binding.enabled || !self.host_current(&guard) {
            return Err(Response::error(
                503,
                "genuine KMS provider admission changed",
            ));
        }
        // Observe kernel monotonic time before computing remaining Instant time:
        // this ordering cannot extend the original deadline by observation/spawn delay.
        let observed_monotonic = monotonic_nanos()?;
        let remaining = match crate::request_deadline::current() {
            Some(deadline) => match deadline.checked_duration_since(std::time::Instant::now()) {
                Some(left) => u64::try_from(left.as_millis())
                    .unwrap_or(u64::MAX)
                    .min(self.binding.timeout_ms),
                None => 0,
            },
            None => self.binding.timeout_ms,
        };
        if remaining == 0 {
            return Err(Response::error(
                503,
                "genuine KMS original invocation deadline expired",
            ));
        }
        let deadline_monotonic = observed_monotonic
            .checked_add(
                remaining
                    .checked_mul(1_000_000)
                    .ok_or_else(|| Response::error(503, "genuine KMS deadline overflow"))?,
            )
            .ok_or_else(|| Response::error(503, "genuine KMS deadline overflow"))?;
        let mut environment = SecretEnvironment::new();
        for (name, value) in &self.binding.operator_environment {
            let value = if name == "HEPTABAO_KMS_TIMEOUT_MS" {
                remaining.to_string()
            } else if name == "HEPTABAO_KMS_DEADLINE_MONOTONIC_NS" {
                deadline_monotonic.to_string()
            } else {
                value.clone()
            };
            environment.insert(name, value).map_err(plugin::failure)?;
        }
        self.invocation
            .invoke(&mut guard, &environment)
            .map_err(plugin::failure)
    }
}
fn monotonic_nanos() -> Result<u64, Response> {
    #[cfg(unix)]
    {
        let ts = rustix::time::clock_gettime_dynamic(rustix::time::DynamicClockId::Known(
            rustix::time::ClockId::Monotonic,
        ))
        .map_err(|_| Response::error(503, "genuine KMS monotonic clock unavailable"))?;
        u64::try_from(i128::from(ts.tv_sec) * 1_000_000_000 + i128::from(ts.tv_nsec))
            .map_err(|_| Response::error(503, "genuine KMS monotonic clock unavailable"))
    }
    #[cfg(not(unix))]
    Err(Response::error(
        503,
        "genuine KMS monotonic clock unavailable",
    ))
}

fn digest(s: &str) -> Result<[u8; 32], String> {
    if s.len() != 64
        || !s
            .bytes()
            .all(|b| b.is_ascii_digit() || b'a' <= b && b <= b'f')
    {
        return Err("invalid genuine KMS SHA256".into());
    }
    let mut out = [0u8; 32];
    for (i, b) in out.iter_mut().enumerate() {
        *b = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16)
            .map_err(|_| "invalid genuine KMS SHA256")?;
    }
    Ok(out)
}

#[cfg(unix)]
struct OperatorPin {
    file: std::fs::File,
    path: std::path::PathBuf,
    identity: [i128; 8],
    digest: [u8; 32],
}
#[cfg(unix)]
fn file_identity(m: &std::fs::Metadata) -> [i128; 8] {
    use std::os::unix::fs::MetadataExt;
    [
        m.dev().into(),
        m.ino().into(),
        m.mode().into(),
        m.uid().into(),
        m.nlink().into(),
        m.size().into(),
        i128::from(m.mtime()) * 1_000_000_000 + i128::from(m.mtime_nsec()),
        i128::from(m.ctime()) * 1_000_000_000 + i128::from(m.ctime_nsec()),
    ]
}
#[cfg(unix)]
impl OperatorPin {
    fn open(path: &str, expected: [u8; 32], executable: bool) -> Result<Self, String> {
        use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
        if !std::path::Path::new(path).is_absolute()
            || std::path::Path::new(path).components().any(|c| {
                matches!(
                    c,
                    std::path::Component::ParentDir | std::path::Component::CurDir
                )
            })
        {
            return Err("genuine KMS operator path is not canonical".into());
        }
        let file = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
            .open(path)
            .map_err(|_| "genuine KMS operator pin cannot be opened")?;
        let m = file
            .metadata()
            .map_err(|_| "genuine KMS operator pin unavailable")?;
        // Only this owned/root regular inode may authorize the deployment.
        let uid = rustix::process::geteuid().as_raw();
        if !m.is_file()
            || m.nlink() != 1
            || !(m.uid() == uid || m.uid() == 0)
            || m.mode() & 0o6022 != 0
            || executable && m.mode() & 0o100 == 0
            || m.size() > 512 * 1024 * 1024
        {
            return Err("genuine KMS operator pin ownership is invalid".into());
        }
        let pin = Self {
            file,
            path: path.into(),
            identity: file_identity(&m),
            digest: expected,
        };
        if !pin.unchanged() {
            return Err("genuine KMS operator pin digest or identity changed".into());
        }
        Ok(pin)
    }
    fn unchanged(&self) -> bool {
        use sha2::{Digest, Sha256};
        use std::os::unix::fs::FileExt;
        let before = match self.file.metadata() {
            Ok(m) => m,
            Err(_) => return false,
        };
        if file_identity(&before) != self.identity {
            return false;
        }
        let mut hash = Sha256::new();
        let mut buf = zeroize::Zeroizing::new([0u8; 64 * 1024]);
        let mut offset = 0u64;
        loop {
            let n = match self.file.read_at(&mut *buf, offset) {
                Ok(n) => n,
                Err(_) => return false,
            };
            if n == 0 {
                break;
            }
            hash.update(&buf[..n]);
            offset += n as u64;
            if i128::from(offset) > self.identity[5] {
                return false;
            }
        }
        let actual: [u8; 32] = hash.finalize().into();
        actual == self.digest
            && i128::from(offset) == self.identity[5]
            && self
                .file
                .metadata()
                .is_ok_and(|m| file_identity(&m) == self.identity)
            && std::fs::symlink_metadata(&self.path)
                .is_ok_and(|m| file_identity(&m) == self.identity)
    }
    fn deployment(&self) -> Result<Value, String> {
        use std::os::unix::fs::FileExt;
        if self.identity[5] > 1024 * 1024 {
            return Err("genuine KMS deployment exceeds bound".into());
        }
        let size =
            usize::try_from(self.identity[5]).map_err(|_| "genuine KMS deployment size invalid")?;
        let mut b = zeroize::Zeroizing::new(vec![0u8; size]);
        let mut n = 0;
        while n < size {
            let got = self
                .file
                .read_at(&mut b[n..], n as u64)
                .map_err(|_| "genuine KMS deployment read failed")?;
            if got == 0 {
                return Err("genuine KMS deployment changed".into());
            }
            n += got;
        }
        if !self.unchanged() {
            return Err("genuine KMS deployment changed".into());
        }
        crate::auth::parse_strict_json(&b).map_err(|_| "genuine KMS deployment is invalid".into())
    }
}
#[cfg(not(unix))]
struct OperatorPin;
#[cfg(not(unix))]
impl OperatorPin {
    fn open(_: &str, _: [u8; 32], _: bool) -> Result<Self, String> {
        Err("genuine KMS requires sealed Unix operator files".into())
    }
    fn unchanged(&self) -> bool {
        false
    }
    fn deployment(&self) -> Result<Value, String> {
        Err("genuine KMS requires sealed Unix operator files".into())
    }
}
#[derive(Clone, Copy, PartialEq, Eq)]
enum OperatorImplementation {
    OpaqueKmsV1,
    OpenBaoPkcs11AliasesV1,
}
fn operator_implementation(
    object: &serde_json::Map<String, Value>,
) -> Result<OperatorImplementation, String> {
    match object.get("implementation") {
        None => Ok(OperatorImplementation::OpaqueKmsV1),
        Some(Value::String(s)) if s == "opaque-kms-v1" => Ok(OperatorImplementation::OpaqueKmsV1),
        Some(Value::String(s)) if s == "openbao-pkcs11-aliases-v1" => {
            Ok(OperatorImplementation::OpenBaoPkcs11AliasesV1)
        }
        _ => Err("genuine KMS operator implementation is invalid".into()),
    }
}
fn operator_pins(path: &str, sha: &str, id: &str) -> Result<Vec<OperatorPin>, String> {
    let deployment = OperatorPin::open(path, digest(sha)?, false)?;
    let mut v = deployment.deployment()?;
    let result: Result<Vec<OperatorPin>, String> = (|| {
        let object = v
            .as_object()
            .ok_or("genuine KMS deployment must be an object")?;
        if object.len() != 5 + usize::from(object.contains_key("implementation"))
            || object.keys().any(|k| {
                !matches!(
                    k.as_str(),
                    "provider" | "image" | "image_sha256" | "args" | "libraries" | "implementation"
                )
            })
            || object.get("provider").and_then(Value::as_str) != Some(id)
        {
            return Err("genuine KMS deployment provider binding is invalid".into());
        }
        let image = object
            .get("image")
            .and_then(Value::as_str)
            .ok_or("genuine KMS provider image is invalid")?;
        let image_sha = object
            .get("image_sha256")
            .and_then(Value::as_str)
            .ok_or("genuine KMS provider digest is invalid")?;
        let args = object
            .get("args")
            .and_then(Value::as_array)
            .ok_or("genuine KMS provider arguments are invalid")?;
        if args.len() > 64
            || args.iter().any(|a| {
                !a.as_str()
                    .is_some_and(|s| s.len() <= 4096 && !s.contains('\0'))
            })
        {
            return Err("genuine KMS provider arguments are invalid".into());
        }
        let libs = object
            .get("libraries")
            .and_then(Value::as_array)
            .ok_or("genuine KMS library aliases are invalid")?;
        if libs.len() > 32 {
            return Err("genuine KMS library count exceeds bound".into());
        }
        if operator_implementation(object)? == OperatorImplementation::OpaqueKmsV1
            && !libs.is_empty()
        {
            return Err("genuine KMS library aliases require a sealed implementation".into());
        }
        let mut pins = vec![OperatorPin::open(image, digest(image_sha)?, true)?];
        let mut names = BTreeSet::new();
        for lib in libs {
            let m = lib
                .as_object()
                .ok_or("genuine KMS library alias must be an object")?;
            if m.len() != 3
                || m.keys()
                    .any(|k| !matches!(k.as_str(), "alias" | "path" | "sha256"))
            {
                return Err("genuine KMS library alias is invalid".into());
            }
            let name = m
                .get("alias")
                .and_then(Value::as_str)
                .ok_or("genuine KMS library alias is invalid")?;
            if name.is_empty()
                || name.len() > 128
                || name.contains(['=', ',', '\r', '\n', '\0'])
                || !names.insert(name.to_owned())
            {
                return Err("genuine KMS library alias is invalid".into());
            }
            pins.push(OperatorPin::open(
                m.get("path")
                    .and_then(Value::as_str)
                    .ok_or("genuine KMS library path is invalid")?,
                digest(
                    m.get("sha256")
                        .and_then(Value::as_str)
                        .ok_or("genuine KMS library digest is invalid")?,
                )?,
                false,
            )?);
        }
        Ok(pins)
    })();
    erase_json(&mut v);
    let mut pins = result?;
    pins.insert(0, deployment);
    Ok(pins)
}

fn validate_owned_temp(path: &str) -> Result<(), String> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let p = std::path::Path::new(path);
        if !p.is_absolute()
            || p.components().any(|c| {
                matches!(
                    c,
                    std::path::Component::ParentDir | std::path::Component::CurDir
                )
            })
        {
            return Err("genuine KMS socket directory is not canonical".into());
        }
        let m =
            std::fs::symlink_metadata(p).map_err(|_| "genuine KMS socket directory unavailable")?;
        let uid = rustix::process::geteuid().as_raw();
        if !m.is_dir() || m.mode() & 0o7777 != 0o700 || m.uid() != uid {
            return Err("genuine KMS socket directory must be operator-owned mode0700".into());
        }
        Ok(())
    }
    #[cfg(not(unix))]
    Err("genuine KMS requires an owned Unix socket directory".into())
}

pub(super) fn admit(configs: Vec<PluginExternalKmsConfig>) -> Result<Bindings, String> {
    if configs.len() > 16 {
        return Err("genuine KMS provider count exceeds bound".into());
    }
    let mut out = Bindings::new();
    for c in configs {
        let id = Id::parse(c.id.clone()).map_err(|_| "invalid genuine KMS identifier")?;
        if out.contains_key(id.as_str()) {
            return Err("duplicate genuine KMS identifier".into());
        }
        let deployment = CanonicalPath::parse(c.deployment_file)
            .map_err(|_| "invalid genuine KMS deployment path")?;
        let temp = CanonicalPath::parse(c.owned_temp)
            .map_err(|_| "invalid genuine KMS socket directory")?;
        if temp.as_str().len() > 60 {
            return Err("genuine KMS socket directory exceeds its Unix socket bound".into());
        }
        validate_owned_temp(temp.as_str())?;
        let pins = operator_pins(deployment.as_str(), &c.deployment_sha256, id.as_str())?;
        let descriptor = PluginDescriptor::new(
            id.clone(),
            PluginKind::Kms,
            CanonicalPath::parse(c.command).map_err(|_| "invalid genuine KMS bridge path")?,
            digest(&c.command_sha256)?,
            1,
        )
        .map_err(|_| "invalid genuine KMS bridge descriptor")?;
        let mut registry = PluginRegistry::default();
        registry
            .register(descriptor)
            .map_err(|_| "genuine KMS bridge registration failed")?;
        registry
            .enable(&id)
            .map_err(|_| "genuine KMS bridge enable failed")?;
        let sandbox = SandboxBinding::new(
            Id::parse(c.sandbox_provider_id)
                .map_err(|_| "invalid genuine KMS sandbox identifier")?,
            CanonicalPath::parse(c.sandbox_command)
                .map_err(|_| "invalid genuine KMS sandbox path")?,
            digest(&c.sandbox_command_sha256)?,
            Id::parse(c.sandbox_profile_id).map_err(|_| "invalid genuine KMS sandbox profile")?,
        )
        .map_err(|_| "invalid genuine KMS sandbox binding")?;
        let mut env = SecretEnvironment::new();
        let values = [
            ("HEPTABAO_KMS_DEPLOYMENT", deployment.as_str().to_owned()),
            ("HEPTABAO_KMS_DEPLOYMENT_SHA256", c.deployment_sha256),
            ("HEPTABAO_KMS_PROVIDER", c.id),
            ("HEPTABAO_KMS_TEMP", temp.as_str().to_owned()),
            ("HEPTABAO_KMS_TIMEOUT_MS", c.timeout_ms.to_string()),
            ("HEPTABAO_KMS_DEADLINE_MONOTONIC_NS", "1".to_owned()),
        ];
        for (name, value) in &values {
            env.insert(name, value.clone())
                .map_err(|_| "invalid genuine KMS operator environment")?;
        }
        let manifest = PluginManifest::new(
            registry
                .get(&id)
                .map_err(|_| "genuine KMS descriptor unavailable")?
                .clone(),
            sandbox,
            PluginLimits {
                maximum_request_bytes: c.maximum_request_bytes,
                maximum_response_bytes: c.maximum_response_bytes,
                timeout_ms: c.timeout_ms,
            },
            BTreeSet::from([PluginOperation::Read]),
            values.iter().map(|(name, _)| (*name).to_owned()).collect(),
        )
        .map_err(|_| "invalid genuine KMS manifest")?;
        let host = PluginHost::admit(manifest, CommandSandboxRunner)
            .map_err(|_| "genuine KMS bridge or sandbox admission failed")?;
        out.insert(
            id.to_string(),
            Arc::new(Binding {
                pins,
                host: Arc::new(Mutex::new(host)),
                operator_environment: values.into_iter().map(|(n, v)| (n.to_owned(), v)).collect(),
                timeout_ms: c.timeout_ms,
                enabled: c.enabled,
            }),
        );
    }
    Ok(out)
}
pub(super) fn prepare(
    bindings: &Bindings,
    id: &str,
    operation: Operation,
    input: &SecretValue,
) -> Result<Option<Admitted>, Response> {
    let Some(binding) = bindings.get(id) else {
        return Ok(None);
    };
    if !binding.enabled {
        return Err(Response::error(403, "genuine KMS provider is disabled"));
    }
    let generation = {
        let guard = binding
            .host
            .try_lock()
            .map_err(|_| Response::error(503, "genuine KMS provider admission busy"))?;
        if guard.state() != PluginHostState::Active
            || !binding.pins.iter().all(OperatorPin::unchanged)
        {
            return Err(Response::error(
                503,
                "genuine KMS provider requires reconciliation",
            ));
        }
        guard.manifest().descriptor().generation()
    };
    let invocation = Invocation::new(operation, input).map_err(plugin::failure)?;
    Ok(Some(Admitted {
        id: id.to_owned(),
        binding: Arc::clone(binding),
        generation,
        invocation,
    }))
}

#[cfg(all(test, target_os = "linux"))]
mod sealed_library_policy_tests {
    use super::super::tests::Root;
    use super::*;
    use sha2::{Digest, Sha256};
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;

    type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

    struct Fixture {
        root: Root,
        image: std::path::PathBuf,
        library: std::path::PathBuf,
        next: usize,
    }
    impl Fixture {
        fn new() -> TestResult<Self> {
            let root = Root::new();
            private_directory(&root.path)?;
            let image = root.path.join("operator-image");
            let library = root.path.join("operator-library");
            for (path, mode, bytes) in [
                (&image, 0o700, b"operator image: never invoked".as_slice()),
                (
                    &library,
                    0o600,
                    b"operator library: never loaded".as_slice(),
                ),
            ] {
                let mut f = std::fs::OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .mode(mode)
                    .open(path)?;
                f.write_all(bytes)?;
            }
            Ok(Self {
                root,
                image,
                library,
                next: 0,
            })
        }
        fn deployment(
            &mut self,
            implementation: Option<Value>,
            libraries: bool,
            provider: &str,
        ) -> TestResult<(std::path::PathBuf, String)> {
            let mut value = serde_json::json!({
                "provider": provider,
                "image": self.image.to_str().ok_or("image path")?,
                "image_sha256": hex(&Sha256::digest(std::fs::read(&self.image)?)),
                "args": [],
                "libraries": []
            });
            if libraries {
                value["libraries"] = serde_json::json!([{
                    "alias": "token",
                    "path": self.library.to_str().ok_or("library path")?,
                    "sha256": hex(&Sha256::digest(std::fs::read(&self.library)?))
                }]);
            }
            if let Some(kind) = implementation {
                value["implementation"] = kind;
            }
            let path = self
                .root
                .path
                .join(format!("deployment-{}.json", self.next));
            self.next += 1;
            let bytes = serde_json::to_vec(&value)?;
            let mut f = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&path)?;
            f.write_all(&bytes)?;
            Ok((path, hex(&Sha256::digest(&bytes))))
        }
    }

    #[test]
    fn pkcs11_operator_class_is_explicit_and_not_inferred_from_provider_name() -> TestResult {
        let mut fixture = Fixture::new()?;
        for name in ["transit", "arbitrary-operator-name"] {
            let (path, sha) = fixture.deployment(
                Some(Value::String("openbao-pkcs11-aliases-v1".into())),
                true,
                name,
            )?;
            let pins = operator_pins(path.to_str().ok_or("deployment path")?, &sha, name)?;
            assert_eq!(pins.len(), 3);
            assert!(pins.iter().all(OperatorPin::unchanged));
        }
        Ok(())
    }

    #[test]
    fn pkcs11_operator_unknown_or_unclassified_libraries_fail_admission() -> TestResult {
        let mut fixture = Fixture::new()?;
        let (path, sha) = fixture.deployment(None, false, "transit")?;
        assert_eq!(
            operator_pins(path.to_str().ok_or("deployment path")?, &sha, "transit")?.len(),
            2
        );
        for kind in [
            None,
            Some(Value::String("opaque-kms-v1".into())),
            Some(Value::String("pkcs11".into())),
            Some(Value::String(String::new())),
            Some(Value::Null),
            Some(Value::Bool(true)),
        ] {
            let (path, sha) = fixture.deployment(kind, true, "transit")?;
            assert!(
                operator_pins(path.to_str().ok_or("deployment path")?, &sha, "transit").is_err()
            );
        }
        Ok(())
    }

    #[test]
    fn pkcs11_operator_library_or_classification_change_vetoes_original_held_pins() -> TestResult {
        let mut fixture = Fixture::new()?;
        let (path, sha) = fixture.deployment(
            Some(Value::String("openbao-pkcs11-aliases-v1".into())),
            true,
            "transit",
        )?;
        let pins = operator_pins(path.to_str().ok_or("deployment path")?, &sha, "transit")?;
        assert!(pins.iter().all(OperatorPin::unchanged));
        std::fs::write(&fixture.library, b"replacement library bytes")?;
        assert!(!pins[2].unchanged());
        let mut deployment: Value = serde_json::from_slice(&std::fs::read(&path)?)?;
        deployment["implementation"] = Value::String("opaque-kms-v1".into());
        std::fs::write(&path, serde_json::to_vec(&deployment)?)?;
        assert!(!pins[0].unchanged());
        Ok(())
    }
}
