//! Explicit private multi-target ciphertext delivery over pinned mTLS.
//!
//! This combines successful *local-only* fsync receipts for an exact ciphertext
//! closure; it is not a transferable Raft quorum certificate.  Peer enrollment,
//! barrier/Actor authority, current cluster epoch, exact committed log index,
//! immutable root CAS, and crash replay are NOT authorized by this module.
//! The production V6/HA exclusion remains unchanged.
use super::{
    HaError, MutualTlsPeerTransport, NodeId, encode_v6_replica_probe, encode_v6_replica_request,
    verify_v6_local_receipt,
};
use heptabao_raft_runtime::{LocalV6BlobStage, RecordObjectRef};
use std::collections::BTreeSet;
use std::fmt;
use std::time::Instant;

/// A preconfigured destination and its independently trusted server leaf pin.
///
/// Creating this object does not validate real Raft membership.  The network
/// exchange checks the enrolled mTLS leaf before sending any ciphertext.
pub struct V6ReplicaCopyTarget {
    node: NodeId,
    transport: MutualTlsPeerTransport,
    expected_server_leaf_sha256: [u8; 32],
}

impl V6ReplicaCopyTarget {
    pub fn new(
        node: NodeId,
        transport: MutualTlsPeerTransport,
        expected_server_leaf_sha256: [u8; 32],
    ) -> Result<Self, HaError> {
        if expected_server_leaf_sha256 == [0; 32] {
            return Err(HaError::PeerAuthenticationFailed);
        }
        Ok(Self {
            node,
            transport,
            expected_server_leaf_sha256,
        })
    }
}

impl fmt::Debug for V6ReplicaCopyTarget {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("V6ReplicaCopyTarget")
            .field("node", &self.node)
            .field("transport", &"[PINNED_MTLS]")
            .field("expected_server_leaf_sha256", &"[REDACTED]")
            .finish()
    }
}

/// Correlated *local custody* observations over independently authenticated
/// TCP/TLS sessions.  The type intentionally has no quorum/commit/ACK API.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct V6ReplicaCustodyObservation {
    manifest_sha256: [u8; 32],
    object_count: usize,
    ciphertext_bytes: u64,
    completed_recipients: Vec<NodeId>,
}

impl V6ReplicaCustodyObservation {
    pub fn manifest_sha256(&self) -> [u8; 32] {
        self.manifest_sha256
    }
    pub fn object_count(&self) -> usize {
        self.object_count
    }
    pub fn ciphertext_bytes(&self) -> u64 {
        self.ciphertext_bytes
    }
    pub fn completed_recipients(&self) -> &[NodeId] {
        &self.completed_recipients
    }
}

/// A private, fail-closed sender for the same operation and closure on two or
/// more independently pinned peers.  A partial transfer returns OutcomeUnknown
/// even though some destination objects may already be durable.
pub struct V6ReplicaCustodyFanout {
    cluster: String,
    epoch: u64,
    operation: [u8; 32],
    targets: Vec<V6ReplicaCopyTarget>,
}

impl fmt::Debug for V6ReplicaCustodyFanout {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("V6ReplicaCustodyFanout")
            .field("cluster", &self.cluster)
            .field("epoch", &self.epoch)
            .field("operation", &"[REDACTED]")
            .field(
                "recipients",
                &self.targets.iter().map(|t| &t.node).collect::<Vec<_>>(),
            )
            .finish()
    }
}

impl V6ReplicaCustodyFanout {
    pub fn new(
        cluster: impl Into<String>,
        epoch: u64,
        operation: [u8; 32],
        mut targets: Vec<V6ReplicaCopyTarget>,
    ) -> Result<Self, HaError> {
        let cluster = cluster.into();
        // Match the private ingress cluster grammar and reject absent
        // independently prepared membership/epoch/operation claims.
        if NodeId::parse(cluster.clone()).is_err()
            || epoch == 0
            || operation == [0; 32]
            || !(2..=super::MAX_PEERS).contains(&targets.len())
        {
            return Err(HaError::InvalidMembership);
        }
        targets.sort_by(|left, right| left.node.cmp(&right.node));
        let mut pins = BTreeSet::new();
        for pair in targets.windows(2) {
            if pair[0].node == pair[1].node {
                return Err(HaError::InvalidMembership);
            }
        }
        if targets
            .iter()
            .any(|target| !pins.insert(target.expected_server_leaf_sha256))
        {
            // Two different node identities must never silently share the
            // same pinned server leaf identity.
            return Err(HaError::PeerAuthenticationFailed);
        }
        Ok(Self {
            cluster,
            epoch,
            operation,
            targets,
        })
    }

    /// Reconcile a previously unknown local-custody outcome WITHOUT writing
    /// any ciphertext over the network. Each independently pinned recipient
    /// must physically reauthenticate the exact stored leaf and return its
    /// original operation-bound, local-only receipt.  No quorum or Raft root
    /// authority can be derived from this observation.
    pub fn reconcile_local_copies(
        &self,
        source: &LocalV6BlobStage,
        references: &[RecordObjectRef],
        deadline: Instant,
    ) -> Result<V6ReplicaCustodyObservation, HaError> {
        if Instant::now() >= deadline {
            return Err(HaError::OutcomeUnknown);
        }
        let initial = source
            .observe_local_closure(references)
            .map_err(|_| HaError::OutcomeUnknown)?;
        let mut ordered = references.iter().collect::<Vec<_>>();
        ordered.sort_by_key(|reference| reference.id);
        let mut completed_recipients = Vec::with_capacity(self.targets.len());
        for target in &self.targets {
            for reference in &ordered {
                if Instant::now() >= deadline {
                    return Err(HaError::OutcomeUnknown);
                }
                let query =
                    encode_v6_replica_probe(&self.cluster, self.epoch, self.operation, reference)
                        .map_err(|_| HaError::OutcomeUnknown)?;
                let response = target
                    .transport
                    .exchange_before_pinned_server(
                        &target.node,
                        &query,
                        deadline,
                        target.expected_server_leaf_sha256,
                    )
                    .map_err(|_| HaError::OutcomeUnknown)?;
                verify_v6_local_receipt(
                    &self.cluster,
                    self.epoch,
                    self.operation,
                    reference,
                    &response,
                )
                .map_err(|_| HaError::OutcomeUnknown)?;
            }
            completed_recipients.push(target.node.clone());
        }
        let after = source
            .observe_local_closure(references)
            .map_err(|_| HaError::OutcomeUnknown)?;
        if after != initial || Instant::now() >= deadline {
            return Err(HaError::OutcomeUnknown);
        }
        Ok(V6ReplicaCustodyObservation {
            manifest_sha256: initial.manifest_sha256(),
            object_count: initial.object_count(),
            ciphertext_bytes: initial.ciphertext_bytes(),
            completed_recipients,
        })
    }

    /// Deliver an exact locally verified closure to every configured receiver.
    ///
    /// Only the original absolute deadline is used.  No automatic retry is
    /// performed after an ambiguous transport/final-fsync outcome.  A caller
    /// must reconcile each object ID on the same authenticated peer before
    /// retrying, and MUST NOT infer a Raft commit from this return value.
    pub fn deliver_local_copies(
        &self,
        source: &LocalV6BlobStage,
        references: &[RecordObjectRef],
        deadline: Instant,
    ) -> Result<V6ReplicaCustodyObservation, HaError> {
        if Instant::now() >= deadline {
            return Err(HaError::OutcomeUnknown);
        }
        let initial = source
            .observe_local_closure(references)
            .map_err(|_| HaError::InvalidRoot)?;
        let mut ordered = references.iter().collect::<Vec<_>>();
        ordered.sort_by_key(|reference| reference.id);
        let mut completed_recipients = Vec::with_capacity(self.targets.len());
        for target in &self.targets {
            for reference in &ordered {
                if Instant::now() >= deadline {
                    return Err(HaError::OutcomeUnknown);
                }
                let ciphertext = source
                    .read_local(reference)
                    .map_err(|_| HaError::OutcomeUnknown)?;
                let frame = encode_v6_replica_request(
                    &self.cluster,
                    self.epoch,
                    self.operation,
                    reference,
                    &ciphertext,
                )
                .map_err(|_| HaError::OutcomeUnknown)?;
                let response = target
                    .transport
                    .exchange_before_pinned_server(
                        &target.node,
                        &frame,
                        deadline,
                        target.expected_server_leaf_sha256,
                    )
                    .map_err(|_| HaError::OutcomeUnknown)?;
                verify_v6_local_receipt(
                    &self.cluster,
                    self.epoch,
                    self.operation,
                    reference,
                    &response,
                )
                .map_err(|_| HaError::OutcomeUnknown)?;
            }
            completed_recipients.push(target.node.clone());
        }
        let after = source
            .observe_local_closure(references)
            .map_err(|_| HaError::OutcomeUnknown)?;
        if after != initial || Instant::now() >= deadline {
            return Err(HaError::OutcomeUnknown);
        }
        Ok(V6ReplicaCustodyObservation {
            manifest_sha256: initial.manifest_sha256(),
            object_count: initial.object_count(),
            ciphertext_bytes: initial.ciphertext_bytes(),
            completed_recipients,
        })
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use crate::{
        AuthenticatedV6ReplicaReceiver, PinnedClientCertificateMap, RAFT_ALPN_PROTOCOL,
        TlsPeerEndpoint,
    };
    use heptabao_raft_runtime::SealedRecordObject;
    use ring::digest::{SHA256, digest};
    use rustls::pki_types::{CertificateDer, PrivateKeyDer};
    use rustls::server::WebPkiClientVerifier;
    use rustls::{ClientConfig, RootCertStore, ServerConfig};
    use std::collections::BTreeMap;
    use std::fs;
    use std::fs::File;
    use std::io::BufReader;
    use std::net::TcpListener;
    use std::os::unix::fs::PermissionsExt;
    use std::path::{Path, PathBuf};
    use std::process::{Command, Stdio};
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::thread;
    use std::time::Duration;

    static ID: AtomicU64 = AtomicU64::new(1);
    fn private_dir(base: &Path, name: &str) -> std::io::Result<PathBuf> {
        let dir = base.join(name);
        fs::create_dir(&dir)?;
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o700))?;
        Ok(dir)
    }
    fn certs(path: &Path) -> Result<Vec<CertificateDer<'static>>, Box<dyn std::error::Error>> {
        Ok(
            rustls_pemfile::certs(&mut BufReader::new(File::open(path)?))
                .collect::<Result<Vec<_>, _>>()?,
        )
    }
    fn key(path: &Path) -> Result<PrivateKeyDer<'static>, Box<dyn std::error::Error>> {
        rustls_pemfile::private_key(&mut BufReader::new(File::open(path)?))?
            .ok_or_else(|| "missing test key".into())
    }
    fn openssl(root: &Path, args: &[&str]) -> Result<(), Box<dyn std::error::Error>> {
        if !Command::new("openssl")
            .current_dir(root)
            .args(args)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()?
            .success()
        {
            return Err("private fixture openssl invocation failed".into());
        }
        Ok(())
    }
    fn make_pki(root: &Path) -> Result<(), Box<dyn std::error::Error>> {
        openssl(
            root,
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
                "/CN=HBVR-Fanout-CA",
                "-addext",
                "basicConstraints=critical,CA:TRUE",
                "-addext",
                "keyUsage=critical,keyCertSign,cRLSign",
            ],
        )?;
        for (name, role) in [
            ("mac", "clientAuth"),
            ("x230", "serverAuth"),
            ("rog", "serverAuth"),
        ] {
            openssl(
                root,
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
                root.join(format!("{name}.ext")),
                format!(
                    "basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage={role}\nsubjectAltName=DNS:localhost,IP:127.0.0.1\n"
                ),
            )?;
            openssl(
                root,
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
        }
        Ok(())
    }
    type TestTlsConfigs = (
        Arc<ClientConfig>,
        Arc<ServerConfig>,
        Arc<ServerConfig>,
        [u8; 32],
        [u8; 32],
        [u8; 32],
    );
    fn configurations(root: &Path) -> Result<TestTlsConfigs, Box<dyn std::error::Error>> {
        let mut roots = RootCertStore::empty();
        roots.add(certs(&root.join("ca.crt"))?[0].clone())?;
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let mut client = ClientConfig::builder_with_provider(provider.clone())
            .with_safe_default_protocol_versions()?
            .with_root_certificates(roots.clone())
            .with_client_auth_cert(certs(&root.join("mac.crt"))?, key(&root.join("mac.key"))?)?;
        client.alpn_protocols = vec![RAFT_ALPN_PROTOCOL.to_vec()];
        let server = |name: &str| -> Result<Arc<ServerConfig>, Box<dyn std::error::Error>> {
            let mut config = ServerConfig::builder_with_provider(provider.clone())
                .with_safe_default_protocol_versions()?
                .with_client_cert_verifier(
                    WebPkiClientVerifier::builder(Arc::new(roots.clone())).build()?,
                )
                .with_single_cert(
                    certs(&root.join(format!("{name}.crt")))?,
                    key(&root.join(format!("{name}.key")))?,
                )?;
            config.alpn_protocols = vec![RAFT_ALPN_PROTOCOL.to_vec()];
            Ok(Arc::new(config))
        };
        let fp = |name: &str| -> Result<[u8; 32], Box<dyn std::error::Error>> {
            Ok(digest(
                &SHA256,
                certs(&root.join(format!("{name}.crt")))?[0].as_ref(),
            )
            .as_ref()
            .try_into()?)
        };
        Ok((
            Arc::new(client),
            server("x230")?,
            server("rog")?,
            fp("mac")?,
            fp("x230")?,
            fp("rog")?,
        ))
    }

    #[test]
    fn two_distinct_pinned_mtls_receivers_return_exact_complete_local_closure()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = std::env::temp_dir().join(format!(
            "hb-v6-private-fanout-{}-{}",
            std::process::id(),
            ID.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&root)?;
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700))?;
        let pki = private_dir(&root, "pki")?;
        let source_dir = private_dir(&root, "source")?;
        let x230_dir = private_dir(&root, "x230")?;
        let rog_dir = private_dir(&root, "rog")?;
        make_pki(&pki)?;
        let (client, x230_tls, rog_tls, mac_pin, x230_pin, rog_pin) = configurations(&pki)?;
        let pinmap =
            PinnedClientCertificateMap::new(BTreeMap::from([(mac_pin, NodeId::parse("mac")?)]))?;
        let mut threads = Vec::new();
        let mut endpoints = BTreeMap::new();
        for (name, store, tls) in [
            ("x230", x230_dir.clone(), x230_tls),
            ("rog", rog_dir.clone(), rog_tls),
        ] {
            let peer = NodeId::parse(name)?;
            let receiver = AuthenticatedV6ReplicaReceiver::open_existing(
                peer.clone(),
                "synthetic-cluster",
                7,
                [4; 32],
                BTreeSet::from([NodeId::parse("mac")?]),
                &store,
            )?;
            let listener = TcpListener::bind("127.0.0.1:0")?;
            endpoints.insert(
                peer.clone(),
                TlsPeerEndpoint::new(listener.local_addr()?, "localhost")?,
            );
            let pins = pinmap.clone();
            threads.push(thread::spawn(move || -> Result<(), HaError> {
                for _ in 0..4 {
                    receiver.serve_one_mtls(
                        &listener,
                        tls.clone(),
                        &pins,
                        Duration::from_secs(8),
                    )?;
                }
                Ok(())
            }));
        }
        let transport = MutualTlsPeerTransport::new(endpoints, client, Duration::from_secs(8))?;
        let fanout = V6ReplicaCustodyFanout::new(
            "synthetic-cluster",
            7,
            [4; 32],
            vec![
                V6ReplicaCopyTarget::new(NodeId::parse("x230")?, transport.clone(), x230_pin)?,
                V6ReplicaCopyTarget::new(NodeId::parse("rog")?, transport, rog_pin)?,
            ],
        )?;
        let source = LocalV6BlobStage::open_existing(&source_dir)?;
        let first = SealedRecordObject::new_native_v6_ciphertext_chunk(vec![0x67; 4096])?;
        let second = SealedRecordObject::new_native_v6_ciphertext_chunk(vec![0x68; 8192])?;
        let refs = vec![first.reference().clone(), second.reference().clone()];
        source.stage_local(first.sealed())?;
        source.stage_local(second.sealed())?;
        let local = source.observe_local_closure(&refs)?;
        let observation = fanout.deliver_local_copies(
            &source,
            &refs,
            Instant::now() + Duration::from_secs(18),
        )?;
        assert_eq!(observation.manifest_sha256(), local.manifest_sha256());
        assert_eq!(observation.object_count(), 2);
        assert_eq!(observation.ciphertext_bytes(), 12288);
        assert_eq!(observation.completed_recipients().len(), 2);
        let after_restart_reconciliation = fanout.reconcile_local_copies(
            &source,
            &refs,
            Instant::now() + Duration::from_secs(18),
        )?;
        assert_eq!(
            observation, after_restart_reconciliation,
            "read-only mTLS probes must observe the identical local custody",
        );
        for handle in threads {
            handle.join().map_err(|_| "receiver thread panic")??;
        }
        for dir in [&x230_dir, &rog_dir] {
            let store = LocalV6BlobStage::open_existing(dir)?;
            assert_eq!(store.observe_local_closure(&refs)?, local);
            assert_eq!(store.read_local(&refs[0])?, first.sealed());
            assert_eq!(store.read_local(&refs[1])?, second.sealed());
            assert_eq!(fs::read_dir(dir)?.count(), 2);
        }
        drop(source);
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn rejects_duplicate_node_or_leaf_identity_before_any_network()
    -> Result<(), Box<dyn std::error::Error>> {
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let client = ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()?
            .with_root_certificates(RootCertStore::empty())
            .with_no_client_auth();
        let a = NodeId::parse("x230")?;
        let b = NodeId::parse("rog")?;
        let transport = MutualTlsPeerTransport::new(
            BTreeMap::from([
                (
                    a.clone(),
                    TlsPeerEndpoint::new("127.0.0.1:12701".parse()?, "localhost")?,
                ),
                (
                    b.clone(),
                    TlsPeerEndpoint::new("127.0.0.1:12702".parse()?, "localhost")?,
                ),
            ]),
            Arc::new(client),
            Duration::from_secs(1),
        )?;
        assert!(
            V6ReplicaCustodyFanout::new(
                "synthetic",
                0,
                [4; 32],
                vec![
                    V6ReplicaCopyTarget::new(a.clone(), transport.clone(), [1; 32])?,
                    V6ReplicaCopyTarget::new(b.clone(), transport.clone(), [2; 32])?,
                ]
            )
            .is_err()
        );
        assert!(
            V6ReplicaCustodyFanout::new(
                "synthetic",
                7,
                [0; 32],
                vec![
                    V6ReplicaCopyTarget::new(a.clone(), transport.clone(), [1; 32])?,
                    V6ReplicaCopyTarget::new(b.clone(), transport.clone(), [2; 32])?,
                ]
            )
            .is_err()
        );
        assert!(
            V6ReplicaCustodyFanout::new(
                "synthetic",
                7,
                [4; 32],
                vec![
                    V6ReplicaCopyTarget::new(a.clone(), transport.clone(), [1; 32])?,
                    V6ReplicaCopyTarget::new(a, transport.clone(), [2; 32])?,
                ]
            )
            .is_err()
        );
        assert!(
            V6ReplicaCustodyFanout::new(
                "synthetic",
                7,
                [4; 32],
                vec![
                    V6ReplicaCopyTarget::new(NodeId::parse("x230")?, transport.clone(), [1; 32])?,
                    V6ReplicaCopyTarget::new(b, transport, [1; 32])?,
                ]
            )
            .is_err()
        );
        Ok(())
    }

    #[test]
    fn partial_physical_delivery_returns_unknown_not_a_false_all_peer_receipt()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = std::env::temp_dir().join(format!(
            "hb-v6-fanout-partial-{}-{}",
            std::process::id(),
            ID.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&root)?;
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700))?;
        let pki = private_dir(&root, "pki")?;
        let source_dir = private_dir(&root, "source")?;
        let rog_dir = private_dir(&root, "rog")?;
        let x230_dir = private_dir(&root, "x230")?;
        make_pki(&pki)?;
        let (client, _x230_tls, rog_tls, mac_pin, x230_pin, rog_pin) = configurations(&pki)?;
        let pins =
            PinnedClientCertificateMap::new(BTreeMap::from([(mac_pin, NodeId::parse("mac")?)]))?;
        let receiver = AuthenticatedV6ReplicaReceiver::open_existing(
            NodeId::parse("rog")?,
            "synthetic-cluster",
            7,
            [4; 32],
            BTreeSet::from([NodeId::parse("mac")?]),
            &rog_dir,
        )?;
        let listener = TcpListener::bind("127.0.0.1:0")?;
        let rog_endpoint = TlsPeerEndpoint::new(listener.local_addr()?, "localhost")?;
        // A port that had a listener but was deliberately closed is an
        // isolated peer outage; it cannot create a local receipt.
        let offline = TcpListener::bind("127.0.0.1:0")?;
        let offline_addr = offline.local_addr()?;
        drop(offline);
        let mut endpoints = BTreeMap::new();
        endpoints.insert(NodeId::parse("rog")?, rog_endpoint);
        endpoints.insert(
            NodeId::parse("x230")?,
            TlsPeerEndpoint::new(offline_addr, "localhost")?,
        );
        let transport = MutualTlsPeerTransport::new(endpoints, client, Duration::from_secs(5))?;
        let fanout = V6ReplicaCustodyFanout::new(
            "synthetic-cluster",
            7,
            [4; 32],
            vec![
                V6ReplicaCopyTarget::new(NodeId::parse("x230")?, transport.clone(), x230_pin)?,
                V6ReplicaCopyTarget::new(NodeId::parse("rog")?, transport, rog_pin)?,
            ],
        )?;
        let handle = thread::spawn(move || {
            receiver.serve_one_mtls(&listener, rog_tls, &pins, Duration::from_secs(5))
        });
        let source = LocalV6BlobStage::open_existing(&source_dir)?;
        let object = SealedRecordObject::new_native_v6_ciphertext_chunk(vec![0x75; 8192])?;
        let reference = object.reference().clone();
        source.stage_local(object.sealed())?;
        assert!(matches!(
            fanout.deliver_local_copies(
                &source,
                std::slice::from_ref(&reference),
                Instant::now() + Duration::from_secs(9)
            ),
            Err(HaError::OutcomeUnknown)
        ));
        handle.join().map_err(|_| "receiver thread panic")??;
        let rog = LocalV6BlobStage::open_existing(&rog_dir)?;
        assert_eq!(rog.read_local(&reference)?, object.sealed());
        assert_eq!(fs::read_dir(&rog_dir)?.count(), 1);
        assert_eq!(fs::read_dir(&x230_dir)?.count(), 0);
        // A stopped peer and a partial durable recipient copy cannot be
        // converted into a success by rechecking only the sender's source.
        drop(rog);
        drop(source);
        fs::remove_dir_all(root)?;
        Ok(())
    }
}
