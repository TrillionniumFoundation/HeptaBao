//! Feature-gated *local* replica delivery over the EXISTING authenticated mTLS
//! transport. This is not wired to the production HA listener, does not
//! authenticate Raft leadership, and cannot acknowledge a V6 root.
//!
//! Each physical leaf is accepted only after rustls verifies a peer certificate,
//! the configured leaf fingerprint resolves to an enrolled NodeId, and the
//! fixed cluster/epoch/operation and immutable object ID match. A reply proves
//! local fsync/no-replace only, never quorum or root publication.

use super::{HaError, NodeId, PinnedClientCertificateMap, serve_one_mtls_peer_frame_with_origin};
use heptabao_raft_runtime::{
    LocalV6BlobError, LocalV6BlobStage, RecordObjectKind, RecordObjectRef,
};
use ring::digest::{SHA256, digest};
use std::collections::BTreeSet;
use std::fmt;
use std::net::TcpListener;
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant};

const REQUEST_MAGIC: &[u8; 5] = b"HBVR1";
const PROBE_MAGIC: &[u8; 5] = b"HBVQ1";
const RECEIPT_MAGIC: &[u8; 5] = b"HBVA1";
const MAX_CIPHERTEXT: usize = 256 * 1024;
const REQUEST_PREFIX: usize = 5 + 32 + 8 + 32 + 32 + 4;
const RECEIPT_BYTES: usize = REQUEST_PREFIX + 32;
const DOMAIN: &[u8] = b"heptabao.v6.replica-mtls.cluster.v1\0";

fn cluster_binding(cluster: &str) -> Result<[u8; 32], HaError> {
    if cluster.is_empty()
        || cluster.len() > 128
        || !cluster
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
    {
        return Err(HaError::InvalidCluster);
    }
    let mut bytes = Vec::with_capacity(DOMAIN.len() + cluster.len());
    bytes.extend_from_slice(DOMAIN);
    bytes.extend_from_slice(cluster.as_bytes());
    digest(&SHA256, &bytes)
        .as_ref()
        .try_into()
        .map_err(|_| HaError::InvalidCluster)
}

fn validate_reference(reference: &RecordObjectRef, len: usize) -> Result<(), HaError> {
    if reference.kind != RecordObjectKind::NativeV6CiphertextChunk
        || reference.record_count != 0
        || !(25..=MAX_CIPHERTEXT).contains(&len)
        || reference.encoded_bytes as usize != len
        || reference.payload_bytes != len as u64
    {
        return Err(HaError::InvalidFrame);
    }
    Ok(())
}

/// Only call this on the enrolled and authenticated RAFT_ALPN_PROTOCOL mTLS
/// channel, never on the public API or a forwarded application request.
pub fn encode_v6_replica_request(
    cluster: &str,
    epoch: u64,
    operation: [u8; 32],
    reference: &RecordObjectRef,
    ciphertext: &[u8],
) -> Result<Vec<u8>, HaError> {
    if epoch == 0 || operation == [0; 32] {
        return Err(HaError::InvalidFrame);
    }
    validate_reference(reference, ciphertext.len())?;
    let mut result = Vec::with_capacity(REQUEST_PREFIX + ciphertext.len());
    result.extend_from_slice(REQUEST_MAGIC);
    result.extend_from_slice(&cluster_binding(cluster)?);
    result.extend_from_slice(&epoch.to_be_bytes());
    result.extend_from_slice(&operation);
    result.extend_from_slice(&reference.id);
    result.extend_from_slice(&(ciphertext.len() as u32).to_be_bytes());
    result.extend_from_slice(ciphertext);
    Ok(result)
}

/// Authenticated *read-only* local ciphertext custody probe. A successful
/// response means only that the exact immutable bytes were physically reopened
/// at the receiver during this mTLS request. It is not a commit, vote, root or
/// transferable quorum proof, and performs no staging or file mutation.
pub fn encode_v6_replica_probe(
    cluster: &str,
    epoch: u64,
    operation: [u8; 32],
    reference: &RecordObjectRef,
) -> Result<Vec<u8>, HaError> {
    if epoch == 0 || operation == [0; 32] {
        return Err(HaError::InvalidFrame);
    }
    let length = usize::try_from(reference.payload_bytes).map_err(|_| HaError::InvalidFrame)?;
    validate_reference(reference, length)?;
    let mut result = Vec::with_capacity(REQUEST_PREFIX);
    result.extend_from_slice(PROBE_MAGIC);
    result.extend_from_slice(&cluster_binding(cluster)?);
    result.extend_from_slice(&epoch.to_be_bytes());
    result.extend_from_slice(&operation);
    result.extend_from_slice(&reference.id);
    result.extend_from_slice(&(length as u32).to_be_bytes());
    Ok(result)
}

/// A single, private, explicit receiver for local ciphertext staging. This
/// object cannot be constructed from untrusted frame fields. Its enrolled
/// peer set and epoch are caller-managed inputs from separate cluster state.
pub struct AuthenticatedV6ReplicaReceiver {
    node: NodeId,
    binding: [u8; 32],
    epoch: u64,
    allowed_operation: [u8; 32],
    allowed_senders: BTreeSet<NodeId>,
    storage: LocalV6BlobStage,
}

impl fmt::Debug for AuthenticatedV6ReplicaReceiver {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AuthenticatedV6ReplicaReceiver")
            .field("node", &self.node)
            .field("epoch", &self.epoch)
            .field("operation", &"[REDACTED]")
            .field("members", &self.allowed_senders)
            .field("storage", &"[PRIVATE_LOCAL_CIPHERTEXT]")
            .finish()
    }
}

impl AuthenticatedV6ReplicaReceiver {
    pub fn open_existing(
        node: NodeId,
        cluster: &str,
        epoch: u64,
        allowed_operation: [u8; 32],
        allowed_senders: BTreeSet<NodeId>,
        directory: &Path,
    ) -> Result<Self, HaError> {
        if epoch == 0
            || allowed_operation == [0; 32]
            || allowed_senders.is_empty()
            || allowed_senders.len() > 254
            || allowed_senders.contains(&node)
        {
            return Err(HaError::InvalidMembership);
        }
        Ok(Self {
            node,
            binding: cluster_binding(cluster)?,
            epoch,
            allowed_operation,
            allowed_senders,
            storage: LocalV6BlobStage::open_existing(directory)
                .map_err(|_| HaError::InvalidRoot)?,
        })
    }

    /// The only network ingress: uses existing strict mTLS leaf pins and ALPN.
    /// The internal parser cannot be called by a public server route.
    pub fn serve_one_mtls(
        &self,
        listener: &TcpListener,
        server_config: Arc<rustls::ServerConfig>,
        pinned: &PinnedClientCertificateMap,
        timeout: Duration,
    ) -> Result<(), HaError> {
        serve_one_mtls_peer_frame_with_origin(
            listener,
            server_config,
            pinned,
            timeout,
            false,
            |sender, request, accepted_at| {
                self.receive_verified_peer(&sender, &request, accepted_at, timeout)
            },
        )
    }

    /// Only an existing, immutable ciphertext leaf may be observed. The
    /// private read-only listener explicitly refuses any mutating HBVR1 frame,
    /// even from a correctly certificate-pinned sender. Neither a successful
    /// probe nor its local receipt grants Raft or root authority.
    pub fn serve_one_mtls_probe_only(
        &self,
        listener: &TcpListener,
        server_config: Arc<rustls::ServerConfig>,
        pinned: &PinnedClientCertificateMap,
        timeout: Duration,
    ) -> Result<(), HaError> {
        serve_one_mtls_peer_frame_with_origin(
            listener,
            server_config,
            pinned,
            timeout,
            false,
            |sender, request, accepted_at| {
                if request.get(..5) != Some(PROBE_MAGIC.as_slice()) {
                    return Err(HaError::InvalidFrame);
                }
                self.receive_verified_peer(&sender, &request, accepted_at, timeout)
            },
        )
    }

    fn receive_verified_peer(
        &self,
        sender: &NodeId,
        bytes: &[u8],
        accepted_at: Instant,
        budget: Duration,
    ) -> Result<Vec<u8>, HaError> {
        if !self.allowed_senders.contains(sender) {
            return Err(HaError::UnknownPeer);
        }
        let deadline = accepted_at.checked_add(budget).ok_or(HaError::Transport)?;
        let is_stage = bytes.get(..5) == Some(REQUEST_MAGIC.as_slice());
        let is_probe = bytes.get(..5) == Some(PROBE_MAGIC.as_slice());
        if Instant::now() >= deadline
            || (!is_stage && !is_probe)
            || bytes.len() < REQUEST_PREFIX
            || bytes.len() > REQUEST_PREFIX + MAX_CIPHERTEXT
            || bytes.get(5..37) != Some(self.binding.as_slice())
        {
            return Err(HaError::InvalidFrame);
        }
        let epoch = u64::from_be_bytes(
            bytes[37..45]
                .try_into()
                .map_err(|_| HaError::InvalidFrame)?,
        );
        let operation: [u8; 32] = bytes[45..77]
            .try_into()
            .map_err(|_| HaError::InvalidFrame)?;
        let id: [u8; 32] = bytes[77..109]
            .try_into()
            .map_err(|_| HaError::InvalidFrame)?;
        let len = u32::from_be_bytes(
            bytes[109..113]
                .try_into()
                .map_err(|_| HaError::InvalidFrame)?,
        ) as usize;
        let expected_size = if is_probe {
            REQUEST_PREFIX
        } else {
            REQUEST_PREFIX + len
        };
        if epoch != self.epoch
            || operation != self.allowed_operation
            || !(25..=MAX_CIPHERTEXT).contains(&len)
            || bytes.len() != expected_size
        {
            return Err(HaError::InvalidFrame);
        }
        let reference = RecordObjectRef {
            id,
            kind: RecordObjectKind::NativeV6CiphertextChunk,
            encoded_bytes: len as u32,
            record_count: 0,
            payload_bytes: len as u64,
        };
        if is_probe {
            // A probe never creates, replaces or repairs any file. Any absent,
            // changed or unreadable leaf has unknown current custody status.
            drop(
                self.storage
                    .read_local(&reference)
                    .map_err(|_| HaError::OutcomeUnknown)?,
            );
        } else {
            self.storage
                .stage_received_replica(&reference, &bytes[REQUEST_PREFIX..])
                .map_err(|error| match error {
                    LocalV6BlobError::InvalidCiphertext
                    | LocalV6BlobError::CorruptOrChanged
                    | LocalV6BlobError::InvalidClosure => HaError::InvalidFrame,
                    _ => HaError::OutcomeUnknown,
                })?;
        }
        // A timed-out but already fsynced leaf has UNKNOWN reply status. It
        // must be reconciled by ID on the next authenticated attempt, never
        // interpreted as a no-effect or quorum acknowledgement.
        if Instant::now() >= deadline {
            return Err(HaError::OutcomeUnknown);
        }
        let mut ack = Vec::with_capacity(RECEIPT_BYTES);
        ack.extend_from_slice(RECEIPT_MAGIC);
        ack.extend_from_slice(&self.binding);
        ack.extend_from_slice(&self.epoch.to_be_bytes());
        ack.extend_from_slice(&operation);
        ack.extend_from_slice(&reference.id);
        ack.extend_from_slice(&(len as u32).to_be_bytes());
        // Local physically rechecked ciphertext digest is the object ID, not
        // a detached caller claim or a Raft root commitment.
        ack.extend_from_slice(&reference.id);
        Ok(ack)
    }
}

/// Verify the returned local-only receipt on the established mTLS connection.
/// A successful result is NEVER a quorum vote, Raft commit or client ACK.
pub fn verify_v6_local_receipt(
    cluster: &str,
    epoch: u64,
    operation: [u8; 32],
    reference: &RecordObjectRef,
    encoded: &[u8],
) -> Result<(), HaError> {
    validate_reference(reference, reference.payload_bytes as usize)?;
    if epoch == 0
        || operation == [0; 32]
        || encoded.len() != RECEIPT_BYTES
        || encoded.get(..5) != Some(RECEIPT_MAGIC.as_slice())
        || encoded.get(5..37) != Some(cluster_binding(cluster)?.as_slice())
        || encoded.get(37..45) != Some(epoch.to_be_bytes().as_slice())
        || encoded.get(45..77) != Some(operation.as_slice())
        || encoded.get(77..109) != Some(reference.id.as_slice())
        || encoded.get(109..113) != Some(reference.encoded_bytes.to_be_bytes().as_slice())
        || encoded.get(113..145) != Some(reference.id.as_slice())
    {
        return Err(HaError::StaleLeaderResponse);
    }
    Ok(())
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use heptabao_raft_runtime::SealedRecordObject;
    use std::fs;
    use std::os::unix::fs::PermissionsExt;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};

    static ID: AtomicU64 = AtomicU64::new(1);
    fn root() -> PathBuf {
        let p = std::env::temp_dir().join(format!(
            "hb-v6-mtls-replica-{}-{}",
            std::process::id(),
            ID.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&p).unwrap();
        fs::set_permissions(&p, fs::Permissions::from_mode(0o700)).unwrap();
        p
    }
    fn fixture(operation: [u8; 32]) -> (PathBuf, AuthenticatedV6ReplicaReceiver, NodeId) {
        let path = root();
        let sender = NodeId::parse("sender").unwrap();
        let receiver = AuthenticatedV6ReplicaReceiver::open_existing(
            NodeId::parse("target").unwrap(),
            "cluster-x",
            7,
            operation,
            BTreeSet::from([sender.clone()]),
            &path,
        )
        .unwrap();
        (path, receiver, sender)
    }
    #[test]
    fn authenticated_receiver_rejects_foreign_peer_epoch_bytes_and_wrong_op_before_disk() {
        let (dir, receiver, sender) = fixture([3; 32]);
        let object = SealedRecordObject::new_native_v6_ciphertext_chunk(vec![8; 4096]).unwrap();
        let mut req =
            encode_v6_replica_request("cluster-x", 7, [3; 32], object.reference(), object.sealed())
                .unwrap();
        let start = Instant::now();
        assert!(matches!(
            receiver.receive_verified_peer(
                &NodeId::parse("foreign").unwrap(),
                &req,
                start,
                Duration::from_secs(10),
            ),
            Err(HaError::UnknownPeer)
        ));
        req[5] ^= 1;
        assert!(
            receiver
                .receive_verified_peer(&sender, &req, start, Duration::from_secs(10))
                .is_err()
        );
        req[5] ^= 1;
        req[44] ^= 1;
        assert!(
            receiver
                .receive_verified_peer(&sender, &req, start, Duration::from_secs(10))
                .is_err()
        );
        req[44] ^= 1;
        req[76] ^= 3;
        assert!(
            receiver
                .receive_verified_peer(&sender, &req, start, Duration::from_secs(10))
                .is_err()
        );
        req[76] ^= 3;
        req[77] ^= 1;
        assert!(
            receiver
                .receive_verified_peer(&sender, &req, start, Duration::from_secs(10))
                .is_err()
        );
        assert_eq!(fs::read_dir(&dir).unwrap().count(), 0);
        fs::remove_dir_all(dir).unwrap();
    }
    #[test]
    fn authenticated_local_receipt_reconciles_lost_reply_without_claiming_quorum() {
        let (dir, receiver, sender) = fixture([5; 32]);
        let object =
            SealedRecordObject::new_native_v6_ciphertext_chunk(vec![13; 256 * 1024]).unwrap();
        let op = [5; 32];
        let req =
            encode_v6_replica_request("cluster-x", 7, op, object.reference(), object.sealed())
                .unwrap();
        let first = receiver
            .receive_verified_peer(&sender, &req, Instant::now(), Duration::from_secs(10))
            .unwrap();
        verify_v6_local_receipt("cluster-x", 7, op, object.reference(), &first).unwrap();
        assert!(verify_v6_local_receipt("cluster-x", 8, op, object.reference(), &first).is_err());
        assert!(
            verify_v6_local_receipt("cluster-x", 7, [1; 32], object.reference(), &first).is_err()
        );
        drop(receiver);
        let receiver = AuthenticatedV6ReplicaReceiver::open_existing(
            NodeId::parse("target").unwrap(),
            "cluster-x",
            7,
            [5; 32],
            BTreeSet::from([sender.clone()]),
            &dir,
        )
        .unwrap();
        let second = receiver
            .receive_verified_peer(&sender, &req, Instant::now(), Duration::from_secs(10))
            .unwrap();
        assert_eq!(first, second);
        drop(receiver);
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn read_only_probe_requires_existing_exact_ciphertext_and_preserves_custody()
    -> Result<(), Box<dyn std::error::Error>> {
        let (dir, receiver, sender) = fixture([5; 32]);
        let ciphertext = vec![0x35_u8; 4096];
        let object = SealedRecordObject::new_native_v6_ciphertext_chunk(ciphertext.clone())?;
        let probe = encode_v6_replica_probe("cluster-x", 7, [5; 32], object.reference())?;
        assert_eq!(probe.len(), REQUEST_PREFIX);
        assert!(matches!(
            receiver.receive_verified_peer(
                &sender,
                &probe,
                Instant::now(),
                Duration::from_secs(10),
            ),
            Err(HaError::OutcomeUnknown),
        ));
        assert_eq!(
            fs::read_dir(&dir)?.count(),
            0,
            "probe cannot stage an object"
        );
        receiver.storage.stage_local(&ciphertext)?;
        let receipt = receiver.receive_verified_peer(
            &sender,
            &probe,
            Instant::now(),
            Duration::from_secs(10),
        )?;
        verify_v6_local_receipt("cluster-x", 7, [5; 32], object.reference(), &receipt)?;
        assert_eq!(fs::read_dir(&dir)?.count(), 1);
        // Reject an otherwise valid read-only frame with the wrong operation
        // or digest, without mutating the existing ciphertext.
        let mut changed = probe.clone();
        changed[76] ^= 1;
        assert!(
            receiver
                .receive_verified_peer(&sender, &changed, Instant::now(), Duration::from_secs(10),)
                .is_err()
        );
        let missing = SealedRecordObject::new_native_v6_ciphertext_chunk(vec![0x36; 4096])?;
        let missing_probe = encode_v6_replica_probe("cluster-x", 7, [5; 32], missing.reference())?;
        assert!(matches!(
            receiver.receive_verified_peer(
                &sender,
                &missing_probe,
                Instant::now(),
                Duration::from_secs(10),
            ),
            Err(HaError::OutcomeUnknown),
        ));
        drop(receiver);
        let receiver = AuthenticatedV6ReplicaReceiver::open_existing(
            NodeId::parse("target")?,
            "cluster-x",
            7,
            [5; 32],
            BTreeSet::from([sender.clone()]),
            &dir,
        )?;
        assert_eq!(
            receipt,
            receiver.receive_verified_peer(
                &sender,
                &probe,
                Instant::now(),
                Duration::from_secs(10),
            )?,
            "cold reopen must reauthenticate exact existing bytes",
        );
        let only_path = fs::read_dir(&dir)?
            .next()
            .ok_or("missing persisted leaf")??
            .path();
        fs::write(only_path, vec![0x37_u8; 4096])?;
        assert!(matches!(
            receiver.receive_verified_peer(
                &sender,
                &probe,
                Instant::now(),
                Duration::from_secs(10),
            ),
            Err(HaError::OutcomeUnknown),
        ));
        assert_eq!(
            fs::read_dir(&dir)?.count(),
            1,
            "probe must not repair tampering"
        );
        drop(receiver);
        fs::remove_dir_all(dir)?;
        Ok(())
    }

    // Real pinned-certificate mTLS over a private loopback TCP socket. This
    // exercises the same TLS/ALPN/frame verifier used by production HA peers,
    // but NEVER installs a handler on the production server listener.
    #[test]
    fn pinned_mtls_transport_persists_exact_replica_and_rejects_wrong_certificate_identity()
    -> Result<(), Box<dyn std::error::Error>> {
        use crate::{MutualTlsPeerTransport, RAFT_ALPN_PROTOCOL, TlsPeerEndpoint};
        use rustls::pki_types::{CertificateDer, PrivateKeyDer};
        use rustls::server::WebPkiClientVerifier;
        use rustls::{ClientConfig, RootCertStore, ServerConfig};
        use std::collections::BTreeMap;
        use std::fs::File;
        use std::io::BufReader;
        use std::process::{Command, Stdio};
        use std::thread;

        fn run_openssl(root: &Path, args: &[&str]) -> Result<(), Box<dyn std::error::Error>> {
            let status = Command::new("openssl")
                .current_dir(root)
                .args(args)
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status()?;
            if !status.success() {
                return Err("fixture TLS certificate generation failed".into());
            }
            Ok(())
        }
        fn certificates(
            path: &Path,
        ) -> Result<Vec<CertificateDer<'static>>, Box<dyn std::error::Error>> {
            Ok(
                rustls_pemfile::certs(&mut BufReader::new(File::open(path)?))
                    .collect::<Result<Vec<_>, _>>()?,
            )
        }
        fn key(path: &Path) -> Result<PrivateKeyDer<'static>, Box<dyn std::error::Error>> {
            rustls_pemfile::private_key(&mut BufReader::new(File::open(path)?))?
                .ok_or_else(|| "synthetic TLS private key absent".into())
        }

        let root = root();
        let storage_path = root.join("replicas");
        fs::create_dir(&storage_path)?;
        fs::set_permissions(&storage_path, fs::Permissions::from_mode(0o700))?;
        run_openssl(
            &root,
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
                "/CN=HBVR-Private-CA",
                "-addext",
                "basicConstraints=critical,CA:TRUE",
                "-addext",
                "keyUsage=critical,keyCertSign,cRLSign",
            ],
        )?;
        for (name, role) in [("server", "serverAuth"), ("client", "clientAuth")] {
            run_openssl(
                &root,
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
            run_openssl(
                &root,
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
        let ca = certificates(&root.join("ca.crt"))?;
        let mut roots = RootCertStore::empty();
        roots.add(ca[0].clone())?;
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let mut server_tls = ServerConfig::builder_with_provider(provider.clone())
            .with_safe_default_protocol_versions()?
            .with_client_cert_verifier(
                WebPkiClientVerifier::builder(Arc::new(roots.clone())).build()?,
            )
            .with_single_cert(
                certificates(&root.join("server.crt"))?,
                key(&root.join("server.key"))?,
            )?;
        server_tls.alpn_protocols = vec![RAFT_ALPN_PROTOCOL.to_vec()];
        let mut client_tls = ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()?
            .with_root_certificates(roots)
            .with_client_auth_cert(
                certificates(&root.join("client.crt"))?,
                key(&root.join("client.key"))?,
            )?;
        client_tls.alpn_protocols = vec![RAFT_ALPN_PROTOCOL.to_vec()];
        let client_leaf = certificates(&root.join("client.crt"))?;
        let client_digest: [u8; 32] = digest(&SHA256, client_leaf[0].as_ref())
            .as_ref()
            .try_into()?;
        let sender = NodeId::parse("sender")?;
        let receiver_node = NodeId::parse("target")?;
        let pins =
            PinnedClientCertificateMap::new(BTreeMap::from([(client_digest, sender.clone())]))?;
        let server_leaf = certificates(&root.join("server.crt"))?;
        let server_pin: [u8; 32] = digest(&SHA256, server_leaf[0].as_ref())
            .as_ref()
            .try_into()?;
        // A valid TLS client certificate mapped to a foreign (unenrolled)
        // NodeId must be refused after authentication, without local receipt.
        let foreign_pins = PinnedClientCertificateMap::new(BTreeMap::from([(
            client_digest,
            NodeId::parse("foreign")?,
        )]))?;
        let receiver = AuthenticatedV6ReplicaReceiver::open_existing(
            receiver_node.clone(),
            "cluster-x",
            7,
            [5; 32],
            BTreeSet::from([sender]),
            &storage_path,
        )?;
        let listener = TcpListener::bind("127.0.0.1:0")?;
        let endpoint = TlsPeerEndpoint::new(listener.local_addr()?, "localhost")?;
        let transport = MutualTlsPeerTransport::new(
            BTreeMap::from([(receiver_node.clone(), endpoint)]),
            Arc::new(client_tls),
            Duration::from_secs(8),
        )?;
        let object = SealedRecordObject::new_native_v6_ciphertext_chunk(vec![0x61; 256 * 1024])?;
        let request = encode_v6_replica_request(
            "cluster-x",
            7,
            [5; 32],
            object.reference(),
            object.sealed(),
        )?;
        let server = thread::spawn(move || -> Result<(), HaError> {
            for _ in 0..2 {
                receiver.serve_one_mtls(
                    &listener,
                    Arc::new(server_tls.clone()),
                    &pins,
                    Duration::from_secs(8),
                )?;
            }
            assert!(matches!(
                receiver.serve_one_mtls(
                    &listener,
                    Arc::new(server_tls.clone()),
                    &foreign_pins,
                    Duration::from_secs(8),
                ),
                Err(HaError::UnknownPeer),
            ));
            // A second, correctly CA-signed leaf with the same DNS name is
            // not enough. Client must bind to the expected server leaf
            // before any ciphertext frame is sent, so the server observes EOF.
            assert!(
                receiver
                    .serve_one_mtls(
                        &listener,
                        Arc::new(server_tls),
                        &pins,
                        Duration::from_secs(8),
                    )
                    .is_err()
            );
            Ok(())
        });
        for _ in 0..2 {
            let response = transport.exchange_before_pinned_server(
                &receiver_node,
                &request,
                Instant::now() + Duration::from_secs(8),
                server_pin,
            )?;
            verify_v6_local_receipt("cluster-x", 7, [5; 32], object.reference(), &response)?;
        }
        // The third TLS connection negotiates successfully but maps its
        // pinned client leaf to an unauthorized member. It must not ACK.
        assert!(
            transport
                .exchange_before_pinned_server(
                    &receiver_node,
                    &request,
                    Instant::now() + Duration::from_secs(8),
                    server_pin,
                )
                .is_err()
        );
        let mut wrong_pin = server_pin;
        wrong_pin[0] ^= 1;
        assert!(matches!(
            transport.exchange_before_pinned_server(
                &receiver_node,
                &request,
                Instant::now() + Duration::from_secs(8),
                wrong_pin,
            ),
            Err(HaError::PeerAuthenticationFailed),
        ));
        server
            .join()
            .map_err(|_| "mTLS server test thread panicked")??;
        let reopened = LocalV6BlobStage::open_existing(&storage_path)?;
        assert_eq!(reopened.read_local(object.reference())?, object.sealed());
        assert_eq!(fs::read_dir(&storage_path)?.count(), 1);
        drop(reopened);
        fs::remove_dir_all(root)?;
        Ok(())
    }
}
