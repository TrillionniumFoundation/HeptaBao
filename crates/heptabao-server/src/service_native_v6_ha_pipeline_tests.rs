//! Actual Service dispatch -> native publication coordinator -> pinned mTLS
//! closure quorum -> real three-node Raft -> local barrier installation.
//!
//! Unlike the installer primitive fixture, this test never stages a Raft
//! intent, publishes a root, constructs a quorum receipt or copies ciphertext.
//! It exercises the Service HTTP handlers without claiming a public HTTP
//! socket test. Peer forwarding and all Raft/ciphertext traffic use the actual
//! production TLS listeners. Process-owner drop is not a physical SIGKILL test.
#[path = "service_native_v6_ha_snapshot_tests.rs"]
mod snapshot_tests;

#[path = "service_native_v6_ha_snapshot_repair_tests.rs"]
mod snapshot_repair_tests;

#[path = "service_native_v6_ha_historical_restore_tests.rs"]
mod historical_restore_tests;

use super::*;
use crate::ha::{HaPeerConfig, HaProcessConfig};
use crate::request_deadline::{RequestDeadlineScope, lock_until};
use crate::service::tests::{Root, bootstrap};
use crate::v6_native_custody::OriginalDeadline;
use std::collections::BTreeSet;
use std::net::TcpListener;
use std::process::{Command, Stdio};
use std::thread;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;
const REQUEST_BUDGET: Duration = Duration::from_secs(15);

fn scope() -> RequestDeadlineScope {
    RequestDeadlineScope::enter(Instant::now() + REQUEST_BUDGET)
}

fn errors_only(path: &str, response: &Response) {
    if response.status >= 400 {
        let errors = response
            .body
            .get("errors")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(Value::as_str)
            .collect::<Vec<_>>();
        eprintln!(
            "native HA Service pipeline path={path} status={} errors={errors:?}",
            response.status
        );
    }
}

fn expect(response: Response, status: u16, stage: &str) -> TestResult<Response> {
    if response.status != status {
        errors_only(stage, &response);
        return Err(format!(
            "native HA Service pipeline stage={stage}: expected HTTP {status}, observed {}",
            response.status
        )
        .into());
    }
    Ok(response)
}

fn secret_field(response: &mut Response, pointer: &str) -> TestResult<Zeroizing<String>> {
    let value = response
        .body
        .pointer_mut(pointer)
        .ok_or("native pipeline credential field absent")?;
    let Value::String(secret) = value.take() else {
        return Err("native pipeline credential field type".into());
    };
    if secret.is_empty() {
        return Err("native pipeline credential field empty".into());
    }
    Ok(Zeroizing::new(secret))
}

fn copy_cold_directory(source: &Path, target: &Path) -> TestResult {
    private_directory(target)?;
    for entry in fs::read_dir(source)? {
        let entry = entry?;
        let info = fs::symlink_metadata(entry.path())?;
        let destination = target.join(entry.file_name());
        if info.file_type().is_symlink() {
            return Err("cold synthetic V5 source contains a symlink".into());
        }
        if info.is_dir() {
            copy_cold_directory(&entry.path(), &destination)?;
        } else if info.is_file() {
            let mut options = OpenOptions::new();
            options.write(true).create_new(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                options.mode(0o600);
            }
            let mut output = options.open(destination)?;
            io::copy(&mut File::open(entry.path())?, &mut output)?;
            output.sync_all()?;
        } else {
            return Err("cold synthetic V5 source is not a regular file".into());
        }
    }
    File::open(target)?.sync_all()?;
    Ok(())
}

fn openssl(directory: &Path, arguments: &[&str]) -> TestResult {
    if !Command::new("openssl")
        .current_dir(directory)
        .args(arguments)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()?
        .success()
    {
        return Err("native pipeline disposable TLS setup failed".into());
    }
    Ok(())
}

// The exact certificate profile used by the previously executed native mTLS
// fixture. HaProcess itself loads/verifies the resulting TLS client/server
// configuration; this helper does not substitute a transport or listener.
fn certificates(directory: &Path) -> TestResult<BTreeMap<u64, [u8; 32]>> {
    openssl(
        directory,
        &[
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-days",
            "2",
            "-keyout",
            "ca.key",
            "-out",
            "ca.crt",
            "-subj",
            "/CN=NativeServicePipelineCA",
            "-addext",
            "basicConstraints=critical,CA:TRUE",
            "-addext",
            "keyUsage=critical,keyCertSign,cRLSign",
        ],
    )?;
    let mut pins = BTreeMap::new();
    for id in 1..=3 {
        let name = format!("voter-{id}");
        openssl(
            directory,
            &[
                "req",
                "-new",
                "-newkey",
                "rsa:2048",
                "-nodes",
                "-keyout",
                &format!("{name}.key"),
                "-out",
                &format!("{name}.csr"),
                "-subj",
                &format!("/CN={name}"),
            ],
        )?;
        fs::write(
            directory.join(format!("{name}.ext")),
            "basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=clientAuth,serverAuth\nsubjectAltName=DNS:localhost,IP:127.0.0.1\n",
        )?;
        openssl(
            directory,
            &[
                "x509",
                "-req",
                "-in",
                &format!("{name}.csr"),
                "-CA",
                "ca.crt",
                "-CAkey",
                "ca.key",
                "-CAcreateserial",
                "-out",
                &format!("{name}.crt"),
                "-days",
                "2",
                "-sha256",
                "-extfile",
                &format!("{name}.ext"),
            ],
        )?;
        let leaf = rustls_pemfile::certs(&mut io::BufReader::new(File::open(
            directory.join(format!("{name}.crt")),
        )?))
        .next()
        .ok_or("native pipeline TLS leaf absent")??;
        pins.insert(id, crypto::digest(leaf.as_ref()));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        for leaf in ["ca.key", "voter-1.key", "voter-2.key", "voter-3.key"] {
            fs::set_permissions(directory.join(leaf), fs::Permissions::from_mode(0o600))?;
        }
    }
    Ok(pins)
}

fn configurations(
    directory: &Path,
    cluster_id: &str,
    pins: &BTreeMap<u64, [u8; 32]>,
) -> TestResult<Vec<HaProcessConfig>> {
    let listeners = (0..3)
        .map(|_| TcpListener::bind("127.0.0.1:0"))
        .collect::<Result<Vec<_>, _>>()?;
    let addresses = listeners
        .iter()
        .map(TcpListener::local_addr)
        .collect::<Result<Vec<_>, _>>()?;
    let peers = (1..=3)
        .map(|id| {
            (
                id,
                HaPeerConfig {
                    node_name: format!("service-pipeline-{id}"),
                    address: addresses[(id - 1) as usize],
                    api_address: None,
                    cluster_address: None,
                    server_name: "localhost".into(),
                    certificate_sha256: pins[&id]
                        .iter()
                        .map(|byte| format!("{byte:02x}"))
                        .collect(),
                    certificate_sha256_next: None,
                },
            )
        })
        .collect::<BTreeMap<_, _>>();
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut key = options.open(directory.join("replication.key"))?;
    key.write_all(&crypto::random::<32>()?)?;
    key.sync_all()?;
    Ok((1..=3)
        .map(|id| HaProcessConfig {
            node_id: id,
            cluster_id: cluster_id.into(),
            raft_dir: directory.join(format!("raft-{id}")),
            listen: addresses[(id - 1) as usize],
            ca_file: directory.join("ca.crt"),
            cert_file: directory.join(format!("voter-{id}.crt")),
            key_file: directory.join(format!("voter-{id}.key")),
            replication_key_file: directory.join("replication.key"),
            peers: peers.clone(),
            bootstrap: id == 1,
            initial_voters: None,
            peer_timeout_ms: 1500,
            forward_timeout_ms: 8000,
            max_inflight: 32,
            allow_legacy_peer_v1: false,
            emit_legacy_peer_v1: Some(false),
        })
        .collect())
}

pub(super) struct Pipeline {
    files: Root,
    configs: Vec<HaProcessConfig>,
    processes: Vec<Option<Arc<Mutex<HaProcess>>>>,
    services: Vec<Option<Arc<Mutex<Service>>>>,
    key: Zeroizing<String>,
    admin: Zeroizing<String>,
    seed_identity: crate::state_record_root::StateIdentity,
}

impl Pipeline {
    pub(super) fn start() -> TestResult<Self> {
        let mut files = Root::new();
        private_directory(&files.path)?;
        files.path = fs::canonicalize(&files.path)?;
        let seed = files.path.join("seed");
        private_directory(&seed)?;
        let mut service = Service::new(seed.join("data"), &seed.join("audit.jsonl"))?;
        let (key, admin) = {
            let _scope = scope();
            bootstrap(&mut service)?
        };
        let key = Zeroizing::new(key);
        let admin = Zeroizing::new(admin);
        {
            let _scope = scope();
            expect(
                service.handle(
                    "POST",
                    "secret/data/pipeline/history",
                    "",
                    &admin,
                    json!({"options":{"cas":0},"data":{"value":"seed-v5"}}),
                ),
                200,
                "standalone-v5-seed",
            )?;
        }
        let state = service.state.as_ref().ok_or("pipeline V5 state absent")?;
        let cluster_id = state.cluster_id.clone();
        let seed_identity = service
            .current_state_identity()
            .map_err(|_| "pipeline V5 identity absent")?;
        assert!(matches!(
            seed_identity,
            crate::state_record_root::StateIdentity::RecordsV5(_)
        ));
        drop(service);
        for id in 1..=3 {
            let directory = files.path.join(format!("service-{id}"));
            private_directory(&directory)?;
            copy_cold_directory(&seed.join("data"), &directory.join("data"))?;
        }
        let pins = certificates(&files.path)?;
        let configs = configurations(&files.path, &cluster_id, &pins)?;
        let mut pipeline = Self {
            files,
            configs,
            processes: vec![None, None, None],
            services: vec![None, None, None],
            key,
            admin,
            seed_identity,
        };
        // Actual production bootstrap owner starts after the other two real
        // TLS endpoints. No manually initialized router or test-owned log CAS.
        for index in [1, 2, 0] {
            pipeline.start_process(index)?;
        }
        let leader = pipeline.ready_leader()?;
        // Bootstrap configuration owns group construction. It does not
        // override the actual election after membership promotion completes.
        let unseal_order = std::iter::once(leader).chain((0..3).filter(|id| *id != leader));
        for index in unseal_order {
            pipeline.unseal(index)?;
        }
        for index in 0..3 {
            let service = pipeline.services[index]
                .as_ref()
                .ok_or("pipeline Service absent")?;
            let writer = service.lock().map_err(|_| "pipeline Service poisoned")?;
            assert_eq!(
                writer
                    .current_state_identity()
                    .map_err(|_| "initial HA identity")?,
                seed_identity
            );
            assert!(
                writer.native_candidate_profile.is_none(),
                "HA never acquires a single-node profile"
            );
        }
        Ok(pipeline)
    }

    fn directory(&self, index: usize) -> PathBuf {
        self.files.path.join(format!("service-{}", index + 1))
    }

    fn start_process(&mut self, index: usize) -> TestResult {
        if self.processes[index].is_some() || self.services[index].is_some() {
            return Err("pipeline process or Service already owned".into());
        }
        let process = Arc::new(Mutex::new(HaProcess::start_native_v6_candidate(
            self.configs[index].clone(),
        )?));
        assert!(
            process
                .lock()
                .map_err(|_| "pipeline process poisoned")?
                .native_v6_enabled()
        );
        self.processes[index] = Some(process);
        self.open_service(index)
    }

    fn open_service(&mut self, index: usize) -> TestResult {
        if self.services[index].is_some() {
            return Err("pipeline Service already open".into());
        }
        let process = self.processes[index]
            .as_ref()
            .ok_or("pipeline process absent")?;
        let directory = self.directory(index);
        let service = Arc::new(Mutex::new(Service::new_with_ha(
            directory.join("data"),
            &directory.join("audit.jsonl"),
            process.clone(),
        )?));
        // The current process's handler is registered once. The indirection
        // below is not replaced during a request and its weak owner cannot
        // outlive the Service. Reopening a Service uses a new process below.
        let weak = Arc::downgrade(&service);
        process
            .lock()
            .map_err(|_| "pipeline process poisoned")?
            .register_forward_handler(Arc::new(move |mut request| {
                let Some(service) = weak.upgrade() else {
                    return Response::error(503, "native pipeline forwarded owner closed");
                };
                let Some(deadline) = crate::ha_forward_completion::CompletionScope::deadline()
                else {
                    return Response::error(
                        503,
                        "native pipeline original forward deadline absent",
                    );
                };
                let _scope = RequestDeadlineScope::enter(deadline);
                let Ok(mut writer) = lock_until(&service, deadline) else {
                    return Response::error(503, "native pipeline forwarded owner unavailable");
                };
                let execution = writer.begin_request_before(
                    ServiceRequest {
                        method: &request.method,
                        path: &request.path,
                        namespace: &request.namespace,
                        token: &request.token,
                        body: std::mem::take(&mut request.body),
                        wrap_ttl_seconds: request.wrap_ttl_seconds,
                        origin_peer: request.origin_peer,
                        client_certificates: request.client_certificates.take(),
                    },
                    deadline,
                    true,
                );
                let response = writer.finish_synchronous_request(execution);
                writer.seal_forward_completion(&response);
                request.token.zeroize();
                response
            }))?;
        self.services[index] = Some(service);
        Ok(())
    }

    pub(super) fn call(
        &self,
        index: usize,
        method: &str,
        path: &str,
        token: &str,
        body: Value,
    ) -> TestResult<Response> {
        let began = Instant::now();
        let _scope = RequestDeadlineScope::enter(began + REQUEST_BUDGET);
        let service = self.services[index]
            .as_ref()
            .ok_or("pipeline Service absent")?;
        let mut writer = lock_until(service, began + REQUEST_BUDGET)
            .map_err(|_| "pipeline Service lock deadline")?;
        let response = writer.handle(method, path, "", token, body);
        errors_only(path, &response);
        if began.elapsed() >= REQUEST_BUDGET {
            return Err(
                format!("native pipeline original 15-second request exceeded: {path}").into(),
            );
        }
        Ok(response)
    }

    pub(super) fn admin(&self) -> &str {
        &self.admin
    }

    /// Read the actual selected Service graph for sibling security tests.
    /// This returns no mutation, Raft, Actor or completed-response authority.
    pub(super) fn with_service<T>(
        &self,
        index: usize,
        inspect: impl FnOnce(&Service) -> TestResult<T>,
    ) -> TestResult<T> {
        let until = Instant::now() + REQUEST_BUDGET;
        let _scope = RequestDeadlineScope::enter(until);
        let service = self.services[index]
            .as_ref()
            .ok_or("pipeline Service absent")?;
        let writer = lock_until(service, until).map_err(|_| "pipeline Service read deadline")?;
        let result = inspect(&writer)?;
        if Instant::now() >= until {
            return Err("pipeline Service inspection deadline".into());
        }
        Ok(result)
    }

    fn unseal(&self, index: usize) -> TestResult {
        let response = expect(
            self.call(
                index,
                "POST",
                "sys/unseal",
                "",
                json!({"key":self.key.as_str()}),
            )?,
            200,
            "actual-Service-cold-unseal",
        )?;
        assert_eq!(response.body["sealed"], false);
        Ok(())
    }

    pub(super) fn ready_leader(&self) -> TestResult<usize> {
        let until = Instant::now() + Duration::from_secs(8);
        let _scope = RequestDeadlineScope::enter(until);
        let mut selected = None;
        let mut since = Instant::now();
        while Instant::now() < until {
            let mut active = None;
            for (index, process) in self.processes.iter().enumerate() {
                let Some(process) = process else {
                    continue;
                };
                let process = process
                    .lock_for_request()
                    .map_err(|_| "pipeline observation lock")?;
                let role = process.leader_status()?;
                if !role.local_is_leader || role.leader != Some((index + 1) as u64) {
                    continue;
                }
                let membership = match process.membership() {
                    Ok(value) => value,
                    Err(_) => continue,
                };
                let fresh_peers = membership
                    .voters
                    .iter()
                    .filter(|id| **id != role.local_id)
                    .filter(|id| {
                        membership
                            .peer_contact_ms
                            .get(id)
                            .is_some_and(|age| age.is_some_and(|age| age <= 400))
                            && membership.peer_matched.get(id).is_some_and(|matched| {
                                matched.is_some_and(|matched| {
                                    role.committed_index
                                        .is_some_and(|committed| matched >= committed)
                                })
                            })
                    })
                    .count();
                if membership.committed
                    && !membership.joint
                    && membership.term == role.term
                    && membership.voters == BTreeSet::from([1, 2, 3])
                    && fresh_peers >= 1
                    && role.committed_index.is_some_and(|committed| {
                        role.applied_index
                            .is_some_and(|applied| applied >= committed)
                    })
                {
                    if active.replace(index).is_some() {
                        return Err("pipeline observed two current writable leaders".into());
                    }
                }
            }
            if let Some(index) = active {
                if selected == Some(index) && since.elapsed() >= Duration::from_millis(250) {
                    return Ok(index);
                }
                if selected != Some(index) {
                    selected = Some(index);
                    since = Instant::now();
                }
            } else {
                selected = None;
            }
            thread::sleep(Duration::from_millis(20));
        }
        Err("pipeline actual leader/quorum heartbeat readiness deadline".into())
    }

    fn native_selection(&self, index: usize) -> TestResult<(u64, [u8; 32], u64)> {
        let _scope = scope();
        let process = self.processes[index]
            .as_ref()
            .ok_or("pipeline process absent")?
            .lock_for_request()
            .map_err(|_| "pipeline selection lock")?;
        let selected = process
            .native_v6_committed_read(OriginalDeadline::capture()?)?
            .ok_or("pipeline native root was not committed")?;
        process.verify_native_v6_committed_read(&selected)?;
        assert_eq!(selected.enrollment().epoch(), 0);
        assert_eq!(
            selected.published().migration_source().0,
            self.seed_identity.digest()
        );
        Ok((
            selected.published().generation(),
            selected.published().root_digest(),
            selected.published().publication_log_id().index,
        ))
    }

    fn assert_history(&self, index: usize, expected: &[(u64, &str)]) -> TestResult {
        for (version, value) in expected {
            let response = expect(
                self.call(
                    index,
                    "GET",
                    "secret/data/pipeline/history",
                    &self.admin,
                    json!({"version":version}),
                )?,
                200,
                "native-history-read",
            )?;
            assert_eq!(response.body["data"]["metadata"]["version"], *version);
            assert!(response.body["data"]["data"]["value"].as_str() == Some(*value));
        }
        Ok(())
    }

    fn stop_process(&mut self, index: usize) -> TestResult {
        drop(self.services[index].take());
        let process = self.processes[index]
            .take()
            .ok_or("pipeline process already stopped")?;
        let process = Arc::try_unwrap(process)
            .map_err(|_| "pipeline retained another process owner")?
            .into_inner()
            .map_err(|_| "pipeline stopped process poisoned")?;
        drop(process);
        Ok(())
    }
}

impl Drop for Pipeline {
    fn drop(&mut self) {
        // Release all Service references before any actual listener/node
        // owner. Weak forwarding handlers introduce no lifetime cycle.
        for service in &mut self.services {
            drop(service.take());
        }
        for process in &mut self.processes {
            drop(process.take());
        }
    }
}

#[test]
fn native_ha_pipeline_service_activation_kv_auth_mtls_and_cold_leader_rejoin() -> TestResult {
    let mut pipeline = Pipeline::start()?;
    let first = pipeline.ready_leader()?;
    expect(
        pipeline.call(
            first,
            "POST",
            "sys/internal/native-v6/activate",
            &pipeline.admin,
            json!({}),
        )?,
        204,
        "Service-native-activation-coordinator",
    )?;
    let activated = pipeline.native_selection(first)?;
    assert_eq!(activated.0, 1);
    let value = "native-service-through-actual-pinned-tls".repeat(2048);
    expect(
        pipeline.call(
            first,
            "POST",
            "secret/data/pipeline/history",
            &pipeline.admin,
            json!({"options":{"cas":1},"data":{"value":value}}),
        )?,
        200,
        "Service-native-KV-CAS",
    )?;
    let written = pipeline.native_selection(first)?;
    assert_eq!(written.0, activated.0 + 1);
    assert_ne!(written.1, activated.1);
    assert!(written.2 > activated.2);
    for index in 0..3 {
        pipeline.assert_history(index, &[(1, "seed-v5"), (2, &value)])?;
    }
    let conflict = expect(
        pipeline.call(
            first,
            "POST",
            "secret/data/pipeline/history",
            &pipeline.admin,
            json!({"options":{"cas":1},"data":{"value":"must-not-replace"}}),
        )?,
        400,
        "Service-native-CAS-conflict",
    )?;
    assert!(conflict.body.get("auth").is_none());
    assert_eq!(pipeline.native_selection(first)?, written);

    expect(pipeline.call(first, "PUT", "sys/policies/acl/native-pipeline", &pipeline.admin,
        json!({"policy":"path \"secret/data/pipeline/*\" { capabilities = [\"create\",\"read\",\"update\"] }"}))?,
        204, "Service-native-policy-publication")?;
    expect(
        pipeline.call(
            first,
            "POST",
            "sys/auth/pipeline-approle",
            &pipeline.admin,
            json!({"type":"approle"}),
        )?,
        204,
        "Service-native-AppRole-mount",
    )?;
    expect(pipeline.call(first, "POST", "auth/pipeline-approle/role/client", &pipeline.admin,
        json!({"token_policies":["native-pipeline"],"token_ttl":"300s","token_max_ttl":"900s","secret_id_num_uses":1}))?,
        204, "Service-native-AppRole-role")?;
    let mut role = expect(
        pipeline.call(
            first,
            "GET",
            "auth/pipeline-approle/role/client/role-id",
            &pipeline.admin,
            json!({}),
        )?,
        200,
        "Service-native-AppRole-role-ID",
    )?;
    let role_id = secret_field(&mut role, "/data/role_id")?;
    let mut secret = expect(
        pipeline.call(
            first,
            "POST",
            "auth/pipeline-approle/role/client/secret-id",
            &pipeline.admin,
            json!({}),
        )?,
        200,
        "Service-native-AppRole-secret-ID",
    )?;
    let secret_id = secret_field(&mut secret, "/data/secret_id")?;
    let mut login = expect(
        pipeline.call(
            first,
            "POST",
            "auth/pipeline-approle/login",
            "",
            json!({"role_id":role_id.as_str(),"secret_id":secret_id.as_str()}),
        )?,
        200,
        "Service-native-AppRole-login",
    )?;
    let token = secret_field(&mut login, "/auth/client_token")?;
    assert!(
        login.body["auth"]["entity_id"]
            .as_str()
            .is_some_and(|value| !value.is_empty())
    );
    let denied = expect(
        pipeline.call(
            first,
            "POST",
            "auth/pipeline-approle/login",
            "",
            json!({"role_id":role_id.as_str(),"secret_id":secret_id.as_str()}),
        )?,
        400,
        "Service-one-use-SID-replay",
    )?;
    assert!(denied.body.get("auth").is_none());
    let standby = (first + 1) % 3;
    let lookup = expect(
        pipeline.call(standby, "GET", "auth/token/lookup-self", &token, json!({}))?,
        200,
        "Service-native-Auth-actual-TLS-forward",
    )?;
    assert!(lookup.body["data"]["id"].as_str() == Some(token.as_str()));
    expect(
        pipeline.call(
            standby,
            "POST",
            "secret/data/pipeline/credential",
            &token,
            json!({"options":{"cas":0},"data":{"value":"synthetic-AppRole-owned"}}),
        )?,
        200,
        "Service-AppRole-KV-actual-TLS-forward",
    )?;
    for index in 0..3 {
        let read = expect(
            pipeline.call(
                index,
                "GET",
                "secret/data/pipeline/credential",
                &token,
                json!({}),
            )?,
            200,
            "Service-AppRole-read-on-every-voter",
        )?;
        assert_eq!(
            read.body["data"]["data"]["value"],
            "synthetic-AppRole-owned"
        );
    }
    let renewal = expect(
        pipeline.call(
            first,
            "POST",
            "auth/token/renew-self",
            &token,
            json!({"increment":"300s"}),
        )?,
        200,
        "Service-native-Auth-renewal",
    )?;
    assert!(renewal.body["auth"]["client_token"].as_str() == Some(token.as_str()));
    let before_stop = pipeline.native_selection(first)?;

    pipeline.stop_process(first)?;
    let next = pipeline.ready_leader()?;
    assert_ne!(next, first);
    assert_eq!(pipeline.native_selection(next)?, before_stop);
    pipeline.assert_history(next, &[(1, "seed-v5"), (2, &value)])?;
    let lookup = expect(
        pipeline.call(next, "GET", "auth/token/lookup-self", &token, json!({}))?,
        200,
        "new-leader-native-Auth-current-ReadIndex",
    )?;
    assert!(lookup.body["data"]["id"].as_str() == Some(token.as_str()));
    expect(
        pipeline.call(
            next,
            "POST",
            "secret/data/pipeline/history",
            &token,
            json!({"options":{"cas":2},"data":{"value":"after-real-leader-stop"}}),
        )?,
        200,
        "Service-native-write-with-original-leader-offline",
    )?;
    let after_failover = pipeline.native_selection(next)?;
    assert_eq!(after_failover.0, before_stop.0 + 1);
    assert_ne!(after_failover.1, before_stop.1);
    assert!(after_failover.2 > before_stop.2);
    // The old leader had no listener, Service or process owner during the
    // unique new-leader write. Reopening its existing directories now must
    // select the new committed root, fetch any missing ciphertext through
    // actual pinned peers and install it under the local barrier.
    pipeline.start_process(first)?;
    pipeline.unseal(first)?;
    let current = pipeline.ready_leader()?;
    assert_eq!(pipeline.native_selection(first)?, after_failover);
    for index in 0..3 {
        pipeline.assert_history(
            index,
            &[(1, "seed-v5"), (2, &value), (3, "after-real-leader-stop")],
        )?;
    }
    expect(
        pipeline.call(current, "POST", "auth/token/revoke-self", &token, json!({}))?,
        204,
        "Service-native-revocation",
    )?;
    for index in 0..3 {
        let revoked = expect(
            pipeline.call(
                index,
                "GET",
                "secret/data/pipeline/credential",
                &token,
                json!({}),
            )?,
            403,
            "Service-revoked-principal-on-every-voter",
        )?;
        assert!(revoked.body.get("data").is_none() && revoked.body.get("auth").is_none());
    }
    Ok(())
}
