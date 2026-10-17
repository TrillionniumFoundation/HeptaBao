//! Explicit private multi-target ciphertext delivery over pinned mTLS.
//!
//! This combines successful *local-only* fsync receipts for an exact ciphertext
//! closure; it is not a transferable Raft quorum certificate.  Peer enrollment,
//! barrier/Actor authority, current cluster epoch, exact committed log index,
//! immutable root CAS, and crash replay are NOT authorized by this module.
//! The production V6/HA exclusion remains unchanged.
use super::v6_replica_ingress::cluster_binding;
use super::{
    HaError, MutualTlsPeerTransport, NodeId, encode_v6_replica_probe, encode_v6_replica_request,
    verify_v6_local_receipt,
};
use heptabao_raft_runtime::{
    CommitReceipt, LocalV6BlobStage, MembershipObservation, NativeV6CommitIntent, ProcessRaftNode,
    RecordObjectRef,
};
use std::collections::{BTreeMap, BTreeSet};
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

    /// Read-only physical multi-peer custody observation constrained by one
    /// strictly encoded V6 Raft-stage intent. All cluster/epoch/original-op
    /// fields must match this independently configured mTLS fixture; the exact
    /// ciphertext count/size/hash must match local disk BEFORE the network
    /// calls and all separately pinned recipients AFTER the calls.
    ///
    /// The typed intent is still a CLAIM, not current Raft membership or a
    /// committed log-index/Actor authorization. No majority, root publication,
    /// read permission or client ACK is produced by this method.
    pub fn reconcile_intent_local_copies(
        &self,
        source: &LocalV6BlobStage,
        references: &[RecordObjectRef],
        intent: &NativeV6CommitIntent,
        deadline: Instant,
    ) -> Result<V6ReplicaCustodyObservation, HaError> {
        if Instant::now() >= deadline
            || intent.cluster_digest != cluster_binding(&self.cluster)?
            || intent.epoch != self.epoch
            || intent.operation_digest != self.operation
        {
            return Err(HaError::OutcomeUnknown);
        }
        let physical = source
            .observe_intent_local_closure(intent, references)
            .map_err(|_| HaError::OutcomeUnknown)?;
        if Instant::now() >= deadline {
            return Err(HaError::OutcomeUnknown);
        }
        // This rechecks the source after every physical mTLS receiver and
        // refuses partial/out-of-date/forged replies. It cannot promote a
        // local receipt to a cryptographic Raft quorum.
        let observed = self.reconcile_local_copies(source, references, deadline)?;
        if u64::try_from(observed.object_count()).ok() != Some(intent.object_count)
            || observed.ciphertext_bytes() != intent.ciphertext_bytes
            || observed.manifest_sha256() != intent.closure_manifest_sha256
            || observed.manifest_sha256() != physical.manifest_sha256()
            || Instant::now() >= deadline
        {
            return Err(HaError::OutcomeUnknown);
        }
        Ok(observed)
    }

    /// Require two **fresh, actual** Raft quorum proofs around the complete
    /// pinned-mTLS, physically reopened ciphertext closure observation.
    ///
    /// The leader's Raft state proves the original staged operation at its
    /// exact applied LogId, including after snapshot compaction. The peer set
    /// must correspond one-to-one to the current non-joint committed voters;
    /// each configured peer must have a distinct pinned TLS server leaf.
    /// An original absolute deadline covers both quorum checks and all wire
    /// I/O. Loss of quorum or membership/term change after the physical probes
    /// makes the entire observation unavailable.
    ///
    /// LIMIT: voter_identities are independently configured, not authenticated
    /// Raft node-name bindings. This returns ONLY LOCAL-CUSTODY OBSERVATION;
    /// it is NOT an atomic majority fsync certificate, V6 root CAS, Actor/ACL
    /// authorization, root publication, or client acknowledgement. Production
    /// server routing remains excluded by the opt-in feature.
    pub async fn reconcile_committed_intent_local_copies(
        &self,
        raft: &ProcessRaftNode,
        voter_identities: &BTreeMap<u64, NodeId>,
        source: &LocalV6BlobStage,
        references: &[RecordObjectRef],
        intent_receipt: (&NativeV6CommitIntent, &CommitReceipt),
        deadline: Instant,
    ) -> Result<V6ReplicaCustodyObservation, HaError> {
        let (intent, receipt) = intent_receipt;
        fn denied() -> HaError {
            HaError::OutcomeUnknown
        }
        if Instant::now() >= deadline
            || receipt.log_index <= intent.expected_previous_commit_index
            || intent.cluster_digest != cluster_binding(&self.cluster).map_err(|_| denied())?
            || intent.epoch != self.epoch
            || intent.operation_digest != self.operation
        {
            return Err(denied());
        }
        let deadline_async = tokio::time::Instant::from_std(deadline);
        tokio::time::timeout_at(
            deadline_async,
            raft.reconcile_exact_staged_v6_intent(intent, receipt),
        )
        .await
        .map_err(|_| denied())?
        .map_err(|_| denied())?;
        let before = tokio::time::timeout_at(deadline_async, raft.membership_observation())
            .await
            .map_err(|_| denied())?
            .map_err(|_| denied())?;
        if !self.matches_current_voters(&before, raft.id(), voter_identities) {
            return Err(denied());
        }
        // Each response is an authenticated, pinned-mTLS local fsync/readback
        // claim, NOT an independent Raft vote. No mutation is issued here.
        let observed = self
            .reconcile_intent_local_copies(source, references, intent, deadline)
            .map_err(|_| denied())?;
        if Instant::now() >= deadline {
            return Err(denied());
        }
        // Never reuse the first witness after a peer I/O delay, timeout or
        // leadership/epoch change: obtain a new real quorum ReadIndex.
        tokio::time::timeout_at(
            deadline_async,
            raft.reconcile_exact_staged_v6_intent(intent, receipt),
        )
        .await
        .map_err(|_| denied())?
        .map_err(|_| denied())?;
        let after = tokio::time::timeout_at(deadline_async, raft.membership_observation())
            .await
            .map_err(|_| denied())?
            .map_err(|_| denied())?;
        if !self.matches_current_voters(&after, raft.id(), voter_identities)
            || before.term != after.term
            || before.membership_index != after.membership_index
            || before.voters != after.voters
            || Instant::now() >= deadline
        {
            return Err(denied());
        }
        Ok(observed)
    }

    fn matches_current_voters(
        &self,
        actual: &MembershipObservation,
        local_id: u64,
        enrolled: &BTreeMap<u64, NodeId>,
    ) -> bool {
        actual.committed
            && !actual.joint
            && actual.leader == Some(local_id)
            && actual.local_id == local_id
            && actual.voters.len() >= 3
            && actual.voters.len() == enrolled.len()
            && self.targets.len().checked_add(1) == Some(enrolled.len())
            && enrolled.keys().copied().collect::<BTreeSet<_>>() == actual.voters
            && enrolled
                .get(&local_id)
                .is_some_and(|local| !self.targets.iter().any(|target| &target.node == local))
            && self.targets.iter().all(|target| {
                enrolled
                    .iter()
                    .any(|(id, node)| *id != local_id && node == &target.node)
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

    // Actual three-voter durable OpenRaft engine with its existing bounded
    // RPC codec; the router is deliberately IN-PROCESS, not a physical-host
    // consensus transport. Peer ciphertext probes below use real pinned TLS.
    #[derive(Default, Clone)]
    struct IntentQuorumRouter {
        peers: Arc<tokio::sync::RwLock<BTreeMap<u64, heptabao_raft_runtime::RaftRpcService>>>,
        deny_append: Arc<std::sync::atomic::AtomicBool>,
    }
    impl std::fmt::Debug for IntentQuorumRouter {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str("V6PrivateDurableQuorumRouter")
        }
    }
    impl heptabao_raft_runtime::RaftPeerRpc for IntentQuorumRouter {
        fn exchange(
            &self,
            source: u64,
            target: u64,
            kind: heptabao_raft_runtime::RaftRpcKind,
            bytes: Vec<u8>,
            _timeout: Duration,
        ) -> futures::future::BoxFuture<
            'static,
            Result<Vec<u8>, heptabao_raft_runtime::RemoteRaftError>,
        > {
            let router = self.clone();
            Box::pin(async move {
                if router.deny_append.load(std::sync::atomic::Ordering::SeqCst)
                    && matches!(kind, heptabao_raft_runtime::RaftRpcKind::AppendEntries)
                {
                    return Err(heptabao_raft_runtime::RemoteRaftError::Transport(
                        "isolated private Raft quorum".into(),
                    ));
                }
                let handler = router
                    .peers
                    .read()
                    .await
                    .get(&target)
                    .cloned()
                    .ok_or(heptabao_raft_runtime::RemoteRaftError::InvalidTopology)?;
                handler.handle(source, kind, bytes).await
            })
        }
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
        let raft_router = IntentQuorumRouter::default();
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
            let fault_router = raft_router.clone();
            threads.push(thread::spawn(move || -> Result<(), HaError> {
                for completed in 0..10 {
                    receiver.serve_one_mtls(
                        &listener,
                        tls.clone(),
                        &pins,
                        Duration::from_secs(8),
                    )?;
                    // On the second composite observation, after receiving
                    // the penultimate real pinned-mTLS probe on the last peer,
                    // destroy quorum BEFORE the final peer response. This is
                    // a deterministic post-I/O stale-quorum negative control.
                    if name == "rog" && completed == 8 {
                        fault_router
                            .deny_append
                            .store(true, std::sync::atomic::Ordering::SeqCst);
                    }
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
        // Bootstrap a separate REAL durable three-voter Raft instance using
        // only public ProcessRaftNode interfaces. Keep the root absent.
        let raft_runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(4)
            .enable_all()
            .build()?;
        let raft_root = private_dir(&root, "raft")?;
        let (nodes, last_applied) = raft_runtime.block_on(async {
            let mut nodes = Vec::new();
            for id in 1..=3_u64 {
                let network = heptabao_raft_runtime::RemoteNetworkFactory::new(
                    id,
                    BTreeSet::from([1, 2, 3]),
                    Arc::new(raft_router.clone()),
                )?;
                let node =
                    ProcessRaftNode::create(raft_root.join(id.to_string()), id, network).await?;
                raft_router
                    .peers
                    .write()
                    .await
                    .insert(id, node.rpc_service());
                nodes.push(node);
            }
            nodes[0].initialize_single().await?;
            tokio::time::timeout(Duration::from_secs(8), async {
                while nodes[0].current_leader().await != Some(1) {
                    tokio::time::sleep(Duration::from_millis(20)).await;
                }
            })
            .await?;
            nodes[0].ensure_linearizable().await?;
            nodes[0].add_learner(2).await?;
            nodes[0].add_learner(3).await?;
            nodes[0]
                .change_membership(BTreeSet::from([1, 2, 3]))
                .await?;
            nodes[0].ensure_linearizable().await?;
            let applied = nodes[0]
                .membership_observation()
                .await?
                .applied_index
                .ok_or("missing actual committed predecessor")?;
            Ok::<_, Box<dyn std::error::Error>>((nodes, applied))
        })?;
        // A well-formed Raft-staged intent still must be tied to the
        // exact physical source AND the original authenticated peer fixture.
        let intent = NativeV6CommitIntent {
            cluster_digest: cluster_binding("synthetic-cluster")?,
            epoch: 7,
            operation_digest: [4; 32],
            closure_manifest_sha256: local.manifest_sha256(),
            object_count: 2,
            ciphertext_bytes: local.ciphertext_bytes(),
            prior_root_digest: [11; 32],
            proposed_root_digest: [12; 32],
            prior_generation: 10,
            proposed_generation: 11,
            expected_previous_commit_index: last_applied,
        };
        for invalid in [
            NativeV6CommitIntent {
                cluster_digest: [9; 32],
                ..intent
            },
            NativeV6CommitIntent { epoch: 8, ..intent },
            NativeV6CommitIntent {
                operation_digest: [9; 32],
                ..intent
            },
            NativeV6CommitIntent {
                closure_manifest_sha256: [9; 32],
                ..intent
            },
            NativeV6CommitIntent {
                object_count: 3,
                ..intent
            },
            NativeV6CommitIntent {
                ciphertext_bytes: local.ciphertext_bytes() + 1,
                ..intent
            },
        ] {
            assert!(
                matches!(
                    fanout.reconcile_intent_local_copies(
                        &source,
                        &refs,
                        &invalid,
                        Instant::now() + Duration::from_secs(18)
                    ),
                    Err(HaError::OutcomeUnknown),
                ),
                "forged intent must never consume peer sessions or acquire authority"
            );
        }
        let observed_intent = fanout.reconcile_intent_local_copies(
            &source,
            &refs,
            &intent,
            Instant::now() + Duration::from_secs(18),
        )?;
        assert_eq!(
            after_restart_reconciliation, observed_intent,
            "typed intent can only describe the exact same physically observed peers"
        );
        let raft_object = SealedRecordObject::new_native_v6_commit_intent(intent)?;
        let original_receipt = raft_runtime.block_on(async {
            let serial = nodes[0].next_production_client_serial().await?;
            nodes[0]
                .stage_application_object(serial, &raft_object)
                .await
        })?;
        let matched_voters = BTreeMap::from([
            (1, NodeId::parse("mac")?),
            (2, NodeId::parse("x230")?),
            (3, NodeId::parse("rog")?),
        ]);
        let both = raft_runtime.block_on(fanout.reconcile_committed_intent_local_copies(
            &nodes[0],
            &matched_voters,
            &source,
            &refs,
            (&intent, &original_receipt),
            Instant::now() + Duration::from_secs(20),
        ))?;
        assert_eq!(both, observed_intent);
        // Existing committed intent does not allow a changed voter map or
        // unrelated original Raft slot to create a usable observation.
        let wrong_voters = BTreeMap::from([
            (1, NodeId::parse("mac")?),
            (2, NodeId::parse("x230")?),
            (4, NodeId::parse("rog")?),
        ]);
        assert!(
            raft_runtime
                .block_on(fanout.reconcile_committed_intent_local_copies(
                    &nodes[0],
                    &wrong_voters,
                    &source,
                    &refs,
                    (&intent, &original_receipt),
                    Instant::now() + Duration::from_secs(2),
                ))
                .is_err()
        );
        let mut wrong_receipt = original_receipt.clone();
        wrong_receipt.envelope_digest[0] ^= 1;
        assert!(
            raft_runtime
                .block_on(fanout.reconcile_committed_intent_local_copies(
                    &nodes[0],
                    &matched_voters,
                    &source,
                    &refs,
                    (&intent, &wrong_receipt),
                    Instant::now() + Duration::from_secs(2),
                ))
                .is_err()
        );
        for node in &nodes {
            assert!(
                raft_runtime
                    .block_on(node.record_root_at_generation())?
                    .1
                    .is_none(),
                "neither the original quorum nor physical pinned copies publish a V6 root",
            );
        }
        // The first real Raft witness is valid and all pinned-mTLS probes
        // return, but the final (ROG) receiver partitions Raft after its
        // penultimate reply. The method MUST acquire a new quorum witness and
        // reject, rather than reusing the earlier certified intent.
        let denied_after_probes =
            raft_runtime.block_on(fanout.reconcile_committed_intent_local_copies(
                &nodes[0],
                &matched_voters,
                &source,
                &refs,
                (&intent, &original_receipt),
                Instant::now() + Duration::from_secs(5),
            ));
        assert!(
            raft_router
                .deny_append
                .load(std::sync::atomic::Ordering::SeqCst),
            "last peer must actually partition Raft during TLS proof",
        );
        assert!(
            denied_after_probes.is_err(),
            "successful physical mTLS reads cannot reuse old quorum after partition",
        );
        // Tear down all mTLS listeners before a second quorum-loss control.
        // The failed FIRST fresh ReadIndex must NOT attempt additional peer I/O.
        for handle in threads {
            handle.join().map_err(|_| "receiver thread panic")??;
        }
        let refused = raft_runtime.block_on(fanout.reconcile_committed_intent_local_copies(
            &nodes[0],
            &matched_voters,
            &source,
            &refs,
            (&intent, &original_receipt),
            Instant::now() + Duration::from_millis(350),
        ));
        assert!(
            refused.is_err(),
            "old quorum proof cannot bypass live partition"
        );
        raft_router
            .deny_append
            .store(false, std::sync::atomic::Ordering::SeqCst);
        for node in nodes {
            raft_runtime.block_on(node.shutdown())?;
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
