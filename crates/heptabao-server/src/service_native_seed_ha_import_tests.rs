#![allow(clippy::expect_used, clippy::unwrap_used)]
//! Real private three-voter TLS/Raft fixtures. These are in-process ownership
//! and original-deadline tests; they do not claim physical SIGKILL or HTTP SLA.
use super::*;
use crate::service::tests::{Root, bootstrap};
use std::collections::BTreeMap;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::net::TcpListener;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::PathBuf;
use std::process::{Command, Stdio};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

fn private_dir(path: &Path) -> TestResult {
    fs::create_dir(path)?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    Ok(())
}
fn write_private(path: &Path, bytes: &[u8]) -> TestResult {
    let mut file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o600)
        .open(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}
fn cold_copy(source: &Path, target: &Path) -> TestResult {
    private_dir(target)?;
    for entry in fs::read_dir(source)? {
        let entry = entry?;
        let metadata = fs::symlink_metadata(entry.path())?;
        let destination = target.join(entry.file_name());
        if metadata.file_type().is_symlink() {
            return Err("synthetic seed symlink".into());
        }
        if metadata.is_dir() {
            cold_copy(&entry.path(), &destination)?;
        } else if metadata.is_file() {
            write_private(&destination, &fs::read(entry.path())?)?;
        } else {
            return Err("synthetic seed nonregular leaf".into());
        }
    }
    File::open(target)?.sync_all()?;
    Ok(())
}
fn openssl(path: &Path, args: &[&str]) -> TestResult {
    if !Command::new("openssl")
        .current_dir(path)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()?
        .success()
    {
        return Err("synthetic HA TLS certificate setup failed".into());
    }
    Ok(())
}
fn certificates(path: &Path) -> TestResult<BTreeMap<u64, String>> {
    openssl(
        path,
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
            "/CN=HaMaintenanceImportCA",
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
            path,
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
        write_private(&path.join(format!("{name}.ext")),
            b"basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=clientAuth,serverAuth\nsubjectAltName=DNS:localhost,IP:127.0.0.1\n")?;
        openssl(
            path,
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
            path.join(format!("{name}.crt")),
        )?))
        .next()
        .ok_or("synthetic leaf missing")??;
        pins.insert(id, hex(Sha256::digest(leaf.as_ref()).as_ref()));
    }
    for name in [
        "ca.key",
        "ca.crt",
        "voter-1.key",
        "voter-1.crt",
        "voter-2.key",
        "voter-2.crt",
        "voter-3.key",
        "voter-3.crt",
    ] {
        fs::set_permissions(path.join(name), fs::Permissions::from_mode(0o600))?;
    }
    Ok(pins)
}
fn bundle() -> serde_json::Value {
    let mut entries = serde_json::Map::new();
    for n in 0..8 {
        entries.insert(format!("item-{n:03}"), json!({
            "created_time":"1970-01-01T00:01:30.000000113Z",
            "updated_time":"1970-01-01T00:01:35.000000113Z",
            "current_version":3,"oldest_version":0,"current_metadata_version":2,
            "max_versions":3,"cas_required":true,"metadata_cas_required":true,
            "delete_version_after":"0s","custom_metadata":{"owner":"ha-maintenance-fixture"},
            "versions":{
                "1":{"created_time":"1970-01-01T00:01:30.000000113Z","deletion_time":"","destroyed":true,"data":null},
                "2":{"created_time":"1970-01-01T00:01:33.000000113Z","deletion_time":"1970-01-01T00:01:36.000000113Z","destroyed":false,"data":{"old":n}},
                "3":{"created_time":"1970-01-01T00:01:35.000000113Z","deletion_time":"","destroyed":false,"data":{"ordinal":n,"payload":"maintenance-secret-sentinel".repeat(50)}}
            }
        }));
    }
    json!({"schema":"openbao270-kv2-lossless-v1",
        "config":{"max_versions":3,"cas_required":false,"metadata_cas_required":true,"delete_version_after":"0s"},
        "entries":entries})
}

#[derive(Clone)]
struct Inputs {
    server: PathBuf,
    ha: PathBuf,
    shares: PathBuf,
    token: PathBuf,
    bundle: PathBuf,
    digest: String,
}
impl Inputs {
    fn options(&self) -> HaKv2Import<'_> {
        HaKv2Import {
            server_config_path: &self.server,
            ha_config_path: &self.ha,
            shares_path: &self.shares,
            token_path: &self.token,
            bundle_path: &self.bundle,
            mount: "secret",
            bundle_sha256: &self.digest,
            budget_seconds: Some(60),
        }
    }
}
struct Fixture {
    // Keep the original private root alive until this fixture is dropped.
    _root: Root,
    configs: Vec<crate::http::Config>,
    ha_configs: Vec<HaProcessConfig>,
    peers: Vec<Option<Owner>>,
    inputs: Inputs,
    shares: Zeroizing<Vec<String>>,
    token: Zeroizing<String>,
}
impl Fixture {
    fn new(start_peers: bool) -> TestResult<Self> {
        let mut root = Root::new();
        private_dir(&root.path)?;
        root.path = fs::canonicalize(&root.path)?;
        let seed = root.path.join("seed");
        private_dir(&seed)?;
        let mut service = Service::new(seed.join("data"), &seed.join("audit.jsonl"))?;
        let (key, token) = {
            let _scope = RequestDeadlineScope::enter(Instant::now() + Duration::from_secs(30));
            bootstrap(&mut service)?
        };
        let cluster = service
            .state
            .as_ref()
            .ok_or("seed state absent")?
            .cluster_id
            .clone();
        drop(service);
        let pins = certificates(&root.path)?;
        write_private(
            &root.path.join("replication.key"),
            &crate::crypto::random::<32>()?,
        )?;
        let reservations = (0..6)
            .map(|_| TcpListener::bind("127.0.0.1:0"))
            .collect::<Result<Vec<_>, _>>()?;
        let addresses = reservations
            .iter()
            .map(TcpListener::local_addr)
            .collect::<Result<Vec<_>, _>>()?;
        let peers = (1..=3).map(|id| (id.to_string(), json!({
            "node_name":format!("maintenance-{id}"), "address":addresses[(id-1) as usize],
            "cluster_address":format!("https://{}", addresses[(id-1) as usize]),
            "api_address":format!("https://{}", addresses[(id+2) as usize]),
            "server_name":"localhost","certificate_sha256":pins[&id],
        }))).collect::<serde_json::Map<_,_>>();
        let mut configs = Vec::new();
        let mut ha_configs = Vec::new();
        for id in 1..=3 {
            let node = root.path.join(format!("node-{id}"));
            private_dir(&node)?;
            cold_copy(&seed.join("data"), &node.join("state"))?;
            private_dir(&node.join("raft"))?;
            let cert = root.path.join(format!("voter-{id}.crt"));
            let key = root.path.join(format!("voter-{id}.key"));
            let server = json!({
                "listen":addresses[(id+2) as usize], "data_dir":node.join("state"),
                "audit_file":node.join("audit.jsonl"), "tls_cert_file":cert,"tls_key_file":key,
                "storage":{"native_v6_raft":{"path":node,"node_id":format!("maintenance-{id}"),
                    "cluster_addr":format!("https://{}", addresses[(id-1) as usize]),
                    "api_addr":format!("https://{}", addresses[(id+2) as usize])}},
            });
            let ha = json!({
                "node_id":id,"cluster_id":cluster,"raft_dir":node.join("raft"),
                "listen":addresses[(id-1) as usize], "ca_file":root.path.join("ca.crt"),
                "cert_file":cert,"key_file":key,"replication_key_file":root.path.join("replication.key"),
                "peers":peers,"bootstrap":id==1,"peer_timeout_ms":1500,"forward_timeout_ms":8000,"max_inflight":32,
                "allow_legacy_peer_v1":false,"emit_legacy_peer_v1":false,
            });
            let server_bytes = serde_json::to_vec(&server)?;
            let ha_bytes = serde_json::to_vec(&ha)?;
            write_private(&root.path.join(format!("server-{id}.json")), &server_bytes)?;
            write_private(&root.path.join(format!("ha-{id}.json")), &ha_bytes)?;
            configs.push(configuration::parse_server(&server_bytes)?);
            ha_configs.push(configuration::parse_ha(&ha_bytes)?);
        }
        let shares = Zeroizing::new(vec![key]);
        let token = Zeroizing::new(token);
        let encoded = serde_json::to_vec(&bundle())?;
        let inputs = Inputs {
            server: root.path.join("server-1.json"),
            ha: root.path.join("ha-1.json"),
            shares: root.path.join("shares.json"),
            token: root.path.join("token.txt"),
            bundle: root.path.join("bundle.json"),
            digest: hex(Sha256::digest(&encoded).as_ref()),
        };
        write_private(&inputs.shares, &serde_json::to_vec(&*shares)?)?;
        write_private(&inputs.token, token.as_bytes())?;
        write_private(&inputs.bundle, &encoded)?;
        drop(reservations);
        let mut fixture = Self {
            _root: root,
            configs,
            ha_configs,
            peers: vec![None, None, None],
            inputs,
            shares,
            token,
        };
        if start_peers {
            for index in [1, 2] {
                fixture.peers[index] = Some(Owner::start(
                    &fixture.configs[index],
                    &fixture.ha_configs[index],
                )?);
            }
        }
        Ok(fixture)
    }
    fn seed_bytes(&self) -> TestResult<Vec<Vec<u8>>> {
        ["state.hbs", "journal.hbj", "ledger.hbl", "seal.json"]
            .into_iter()
            .map(|name| fs::read(self.configs[0].data_dir.join(name)).map_err(Into::into))
            .collect()
    }
    fn stop_peers(&mut self) -> TestResult {
        let mut failed = false;
        for peer in &mut self.peers {
            if let Some(mut owner) = peer.take() {
                failed |= owner.close().is_err();
            }
        }
        if failed {
            return Err("original fixture peer shutdown rejected".into());
        }
        Ok(())
    }
    // Reconciliation is a new explicitly read-only test operation. It never
    // retries import, changes membership, restores files or manufactures roots.
    fn reconcile(&mut self, imported: bool) -> TestResult {
        let until = Instant::now() + Duration::from_secs(30);
        let _scope = RequestDeadlineScope::enter(until);
        let original = OriginalDeadline::capture()?;
        self.peers[0] = Some(Owner::start(&self.configs[0], &self.ha_configs[0])?);
        let mut active = None;
        while active.is_none() && Instant::now() < until {
            for (index, peer) in self.peers.iter().enumerate() {
                let Some(peer) = peer else {
                    continue;
                };
                let process = peer
                    .process()?
                    .lock_for_request()
                    .map_err(|_| "reconcile process lock")?;
                if process.is_leader()? && process.membership().is_ok() {
                    active = Some(index);
                    break;
                }
            }
            if active.is_none() {
                std::thread::sleep(Duration::from_millis(20));
            }
        }
        let index = active.ok_or("actual reconcile leader absent")?;
        let owner = self.peers[index].as_mut().ok_or("reconcile owner absent")?;
        // This exact fresh quorum selection precedes real cold unseal.
        let expected = selection(owner, original)?;
        unseal(owner, &self.shares, &|| live(original).map_err(Into::into))?;
        verify_graph(owner, expected, original, &|| {
            live(original).map_err(Into::into)
        })?;
        for n in 0..8 {
            let service = owner.service()?;
            let mut response = service.handle(
                "GET",
                &format!("secret/data/item-{n:03}"),
                "",
                &self.token,
                json!({}),
            );
            assert_eq!(response.status, if imported { 200 } else { 404 });
            if imported {
                assert_eq!(response.body["data"]["data"]["ordinal"], json!(n));
                assert_eq!(response.body["data"]["metadata"]["version"], json!(3));
            }
            erase_json(&mut response.body);
            if imported {
                let mut metadata = service.handle(
                    "GET",
                    &format!("secret/metadata/item-{n:03}"),
                    "",
                    &self.token,
                    json!({}),
                );
                assert_eq!(metadata.status, 200);
                assert_eq!(metadata.body["data"]["current_metadata_version"], json!(2));
                assert_eq!(
                    metadata.body["data"]["versions"]["1"]["destroyed"],
                    json!(true)
                );
                assert_eq!(
                    metadata.body["data"]["versions"]["2"]["deletion_time"],
                    json!("1970-01-01T00:01:36.000000113Z")
                );
                erase_json(&mut metadata.body);
            }
        }
        Ok(())
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = self.stop_peers();
    }
}

#[test]
fn maintenance_ha_import_real_quorum_writer_and_cold_readindex_preserve_history() -> TestResult {
    let mut fixture = Fixture::new(true)?;
    let receipt = import_kv2_ha(fixture.inputs.options())?;
    assert!(
        receipt.imported_once
            && receipt.real_native_writer_used
            && receipt.cold_quorum_readindex_verified
    );
    assert!(
        receipt.cold_selection_exact
            && receipt.cold_root_and_local_generation_exact
            && receipt.complete_cold_graph_verified
    );
    assert!(
        receipt.first_owner_peer_workers_joined > 0 && receipt.cold_owner_peer_workers_joined > 0
    );
    assert!(
        !receipt.http_listener_started
            && !receipt.http_latency_qualified
            && !receipt.physical_failover_qualified
            && !receipt.full_replacement_qualified
    );
    let encoded = serde_json::to_string(&receipt)?;
    for secret in [
        &fixture.shares[0],
        fixture.token.as_str(),
        "maintenance-secret-sentinel",
    ] {
        assert!(!encoded.contains(secret));
    }
    fixture.reconcile(true)?;
    Ok(())
}

#[test]
fn maintenance_ha_wrong_formal_config_rejected_before_owner_effect() -> TestResult {
    let fixture = Fixture::new(false)?;
    let before = fixture.seed_bytes()?;
    let mut config: serde_json::Value = serde_json::from_slice(&fs::read(&fixture.inputs.server)?)?;
    config["storage"]["native_v6_raft"]["cluster_addr"] = json!("https://127.0.0.1:1");
    fs::write(&fixture.inputs.server, serde_json::to_vec(&config)?)?;
    assert!(matches!(
        import_kv2_ha(fixture.inputs.options()),
        Err(HaImportError::ConfigurationRejected)
    ));
    assert_eq!(fixture.seed_bytes()?, before);
    assert_eq!(fs::read_dir(&fixture.ha_configs[0].raft_dir)?.count(), 0);
    Ok(())
}

#[test]
fn maintenance_ha_empty_quorum_never_admits_import() -> TestResult {
    let fixture = Fixture::new(false)?;
    let before = fixture.seed_bytes()?;
    let mut phases = Vec::new();
    let started = Instant::now();
    let result = import_before(
        fixture.inputs.options(),
        started,
        started + Duration::from_secs(12),
        |phase| phases.push(phase),
    );
    assert!(matches!(
        result,
        Err(HaImportError::QuorumUnavailable) | Err(HaImportError::Deadline)
    ));
    assert!(
        !phases.contains(&Phase::LeaderReady)
            && !phases.contains(&Phase::Prepared)
            && !phases.contains(&Phase::Committed)
    );
    assert_eq!(fixture.seed_bytes()?, before);
    Ok(())
}

#[test]
fn maintenance_ha_expired_original_budget_has_no_owner_or_import() -> TestResult {
    let fixture = Fixture::new(false)?;
    let before = fixture.seed_bytes()?;
    let started = Instant::now();
    let mut phases = Vec::new();
    let result = import_before(
        fixture.inputs.options(),
        started,
        started - Duration::from_millis(1),
        |phase| phases.push(phase),
    );
    assert!(matches!(result, Err(HaImportError::Deadline)));
    assert!(phases.is_empty());
    assert_eq!(fixture.seed_bytes()?, before);
    assert_eq!(fs::read_dir(&fixture.ha_configs[0].raft_dir)?.count(), 0);
    Ok(())
}

#[test]
fn maintenance_ha_original_deadline_expiring_after_prepare_does_not_publish_import() -> TestResult {
    let mut fixture = Fixture::new(true)?;
    let inputs = fixture.inputs.clone();
    let started = Instant::now();
    let until = started + Duration::from_secs(15);
    let mut prepared = 0;
    let result = import_before(inputs.options(), started, until, |phase| {
        if phase == Phase::Prepared {
            prepared += 1;
            std::thread::sleep(
                until.saturating_duration_since(Instant::now()) + Duration::from_millis(5),
            );
        }
    });
    assert_eq!(prepared, 1);
    assert!(result.is_err());
    fixture.reconcile(false)?;
    Ok(())
}

#[test]
fn maintenance_ha_actual_commit_with_lost_delivery_requires_readonly_reconciliation() -> TestResult
{
    let mut fixture = Fixture::new(true)?;
    let inputs = fixture.inputs.clone();
    let started = Instant::now();
    let until = started + Duration::from_secs(15);
    let mut committed = 0;
    let result = import_before(inputs.options(), started, until, |phase| {
        if phase == Phase::Committed {
            committed += 1;
            std::thread::sleep(
                until.saturating_duration_since(Instant::now()) + Duration::from_millis(5),
            );
        }
    });
    assert_eq!(committed, 1);
    assert!(matches!(result, Err(HaImportError::OutcomeUnknown)));
    fixture.reconcile(true)?;
    Ok(())
}

#[test]
fn maintenance_ha_cold_restart_without_quorum_never_reports_success() -> TestResult {
    let mut fixture = Fixture::new(true)?;
    let inputs = fixture.inputs.clone();
    let started = Instant::now();
    let mut committed = 0;
    let mut stopped = false;
    let mut stop_failed = false;
    let result = import_before(
        inputs.options(),
        started,
        started + Duration::from_secs(30),
        |phase| {
            if phase == Phase::Committed {
                committed += 1;
            }
            if phase == Phase::FirstOwnerClosed {
                stopped = true;
                stop_failed = fixture.stop_peers().is_err();
            }
        },
    );
    assert_eq!(committed, 1);
    assert!(stopped && !stop_failed);
    assert!(matches!(result, Err(HaImportError::OutcomeUnknown)));
    Ok(())
}
