//! Feature-gated V6 ciphertext transport admission. The existing mTLS listener
//! verifies a peer's certificate and supplies its NodeId to this routine.
//! This is NOT registered as a production listener or a Raft root writer.
//! An authenticated receipt proves this host's exact fsync'd object only.

use heptabao_ha_service::{
    HaError, NodeId, PeerAuthenticator, PeerEnvelope, PeerMessageKind, PersistentPeerSequences,
    admit_peer_envelope,
};
use heptabao_raft_runtime::{
    LocalV6BlobError, LocalV6BlobStage, RecordObjectKind, RecordObjectRef, SealedRecordObject,
};
use std::fmt;

const REQUEST_MAGIC: &[u8; 5] = b"HBVC1";
const RECEIPT_MAGIC: &[u8; 5] = b"HBVA1";
const PREFIX: usize = 5 + 8 + 32 + 32 + 4;
const MAX_CHUNK: usize = 256 * 1024;

#[derive(Clone)]
pub struct V6ReplicaTicket {
    pub sender: NodeId,
    pub receiver: NodeId,
    pub term: u64,
    pub epoch: u64,
    pub operation_digest: [u8; 32],
    pub object: RecordObjectRef,
}
impl fmt::Debug for V6ReplicaTicket {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("V6ReplicaTicket")
            .field("sender", &self.sender)
            .field("receiver", &self.receiver)
            .field("term", &self.term)
            .field("epoch", &self.epoch)
            .field("digest_and_ciphertext", &"[REDACTED]")
            .finish()
    }
}
impl V6ReplicaTicket {
    pub fn new(
        sender: NodeId,
        receiver: NodeId,
        term: u64,
        epoch: u64,
        operation_digest: [u8; 32],
        object: RecordObjectRef,
    ) -> Result<Self, HaError> {
        if sender == receiver
            || term == 0
            || epoch == 0
            || operation_digest == [0; 32]
            || object.kind != RecordObjectKind::NativeV6CiphertextChunk
            || object.record_count != 0
            || object.payload_bytes != u64::from(object.encoded_bytes)
            || !(25..=MAX_CHUNK).contains(&(object.encoded_bytes as usize))
        {
            return Err(HaError::InvalidFrame);
        }
        Ok(Self {
            sender,
            receiver,
            term,
            epoch,
            operation_digest,
            object,
        })
    }
    fn payload(&self, magic: &[u8; 5]) -> Vec<u8> {
        let mut v = Vec::with_capacity(PREFIX);
        v.extend_from_slice(magic);
        v.extend_from_slice(&self.epoch.to_be_bytes());
        v.extend_from_slice(&self.operation_digest);
        v.extend_from_slice(&self.object.id);
        v.extend_from_slice(&self.object.encoded_bytes.to_be_bytes());
        v
    }
    /// The source cannot sign a different payload under this object ID.
    pub fn encode_stage(&self, bytes: &[u8]) -> Result<Vec<u8>, HaError> {
        self.validate_bytes(bytes)?;
        let mut v = self.payload(REQUEST_MAGIC);
        v.extend_from_slice(bytes);
        Ok(v)
    }
    fn validate_bytes(&self, bytes: &[u8]) -> Result<(), HaError> {
        if bytes.len() != self.object.encoded_bytes as usize {
            return Err(HaError::InvalidFrame);
        }
        let object = SealedRecordObject::new_native_v6_ciphertext_chunk(bytes.to_vec())
            .map_err(|_| HaError::InvalidFrame)?;
        if object.reference() != &self.object {
            return Err(HaError::Tampered);
        }
        Ok(())
    }
    fn decode_stage<'a>(&self, bytes: &'a [u8]) -> Result<&'a [u8], HaError> {
        if bytes.len() < PREFIX + 25
            || bytes.len() > PREFIX + MAX_CHUNK
            || bytes.get(..PREFIX) != Some(self.payload(REQUEST_MAGIC).as_slice())
        {
            return Err(HaError::InvalidFrame);
        }
        let ciphertext = &bytes[PREFIX..];
        self.validate_bytes(ciphertext)?;
        Ok(ciphertext)
    }
    /// Validate a signed local-durable receipt. This deliberately does NOT
    /// establish quorum, replicated-root publication, or client success.
    pub fn verify_local_receipt(
        &self,
        observed_tls_peer: &NodeId,
        local_node: &NodeId,
        auth: &PeerAuthenticator,
        receipt: &PeerEnvelope,
    ) -> Result<(), HaError> {
        if observed_tls_peer != &self.receiver
            || local_node != &self.sender
            || receipt.sender != self.receiver
            || receipt.receiver != self.sender
            || receipt.term != self.term
            || receipt.kind != PeerMessageKind::V6CiphertextReceipt
        {
            return Err(HaError::PeerAuthenticationFailed);
        }
        auth.verify(local_node, receipt)?;
        if receipt.payload() != self.payload(RECEIPT_MAGIC) {
            return Err(HaError::InvalidFrame);
        }
        Ok(())
    }
    /// Signed local-only acknowledgement, admitted once by persistent peer
    /// sequence. Never a quorum or root-publication certificate.
    pub fn accept_local_receipt(
        &self,
        observed_tls_peer: &NodeId,
        local_node: &NodeId,
        auth: &PeerAuthenticator,
        sequences: &mut PersistentPeerSequences,
        receipt: &PeerEnvelope,
    ) -> Result<(), HaError> {
        self.verify_local_receipt(observed_tls_peer, local_node, auth, receipt)?;
        sequences.accept_incoming(&self.receiver, receipt.sequence)
    }
}
fn disk_error(e: LocalV6BlobError) -> HaError {
    match e {
        LocalV6BlobError::InvalidCiphertext | LocalV6BlobError::InvalidClosure => {
            HaError::InvalidFrame
        }
        LocalV6BlobError::CorruptOrChanged => HaError::Tampered,
        LocalV6BlobError::Publication(_) => HaError::OutcomeUnknown,
        LocalV6BlobError::InvalidRoot | LocalV6BlobError::Guard(_) | LocalV6BlobError::Io(_) => {
            HaError::Io
        }
    }
}
/// Called only with the certificate-verified actual mTLS peer identity and
/// an independently prepared local ticket, never a ticket decoded from wire.
/// Consumes the authenticated sequence BEFORE fsync. On a lost acknowledgement
/// the sender must submit a NEW sequence for the same immutable ID.
pub fn receive_authenticated_replica(
    observed_tls_peer: &NodeId,
    local_node: &NodeId,
    ticket: &V6ReplicaTicket,
    auth: &PeerAuthenticator,
    sequences: &mut PersistentPeerSequences,
    store: &LocalV6BlobStage,
    request: &PeerEnvelope,
) -> Result<PeerEnvelope, HaError> {
    if observed_tls_peer != &ticket.sender
        || local_node != &ticket.receiver
        || request.sender != ticket.sender
        || request.receiver != ticket.receiver
        || request.term != ticket.term
        || request.kind != PeerMessageKind::V6CiphertextStage
    {
        return Err(HaError::PeerAuthenticationFailed);
    }
    // Authenticate envelope and cluster before interpreting untrusted bytes.
    auth.verify(local_node, request)?;
    let ciphertext = ticket.decode_stage(request.payload())?;
    admit_peer_envelope(local_node, auth, sequences, request)?;
    store
        .stage_received_replica(&ticket.object, ciphertext)
        .map_err(disk_error)?;
    let sequence = sequences.next_outgoing(&ticket.sender)?;
    auth.seal(
        local_node.clone(),
        ticket.sender.clone(),
        ticket.term,
        sequence,
        PeerMessageKind::V6CiphertextReceipt,
        ticket.payload(RECEIPT_MAGIC),
    )
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;
    use std::fs;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNT: AtomicU64 = AtomicU64::new(1);
    struct Cell(PathBuf);
    impl Cell {
        fn new() -> Result<Self, Box<dyn std::error::Error>> {
            let p = fs::canonicalize(std::env::temp_dir())?.join(format!(
                "hb-v6-peer-{}-{}",
                std::process::id(),
                COUNT.fetch_add(1, Ordering::Relaxed),
            ));
            fs::create_dir(&p)?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                fs::set_permissions(&p, fs::Permissions::from_mode(0o700))?;
            }
            Ok(Self(p))
        }
    }
    impl Drop for Cell {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }
    fn fixture() -> Result<(V6ReplicaTicket, PeerAuthenticator, Vec<u8>), Box<dyn std::error::Error>>
    {
        let sender = NodeId::parse("sender")?;
        let receiver = NodeId::parse("receiver")?;
        let ciphertext = vec![0x73; 256 * 1024];
        let object = SealedRecordObject::new_native_v6_ciphertext_chunk(ciphertext.clone())?;
        let ticket = V6ReplicaTicket::new(
            sender.clone(),
            receiver.clone(),
            7,
            9,
            [5; 32],
            object.reference().clone(),
        )?;
        let auth = PeerAuthenticator::new(
            "cell",
            BTreeMap::from([(sender, [1; 32]), (receiver, [2; 32])]),
        )?;
        Ok((ticket, auth, ciphertext))
    }
    fn send(
        auth: &PeerAuthenticator,
        t: &V6ReplicaTicket,
        seq: u64,
        body: Vec<u8>,
    ) -> Result<PeerEnvelope, HaError> {
        auth.seal(
            t.sender.clone(),
            t.receiver.clone(),
            t.term,
            seq,
            PeerMessageKind::V6CiphertextStage,
            body,
        )
    }
    #[test]
    fn authentic_and_durable_recovery_with_lost_receipt() -> Result<(), Box<dyn std::error::Error>>
    {
        let (t, a, bytes) = fixture()?;
        let cell = Cell::new()?;
        for name in ["blobs", "seq"] {
            let path = cell.0.join(name);
            fs::create_dir(&path)?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                fs::set_permissions(&path, fs::Permissions::from_mode(0o700))?;
            }
        }
        let store = LocalV6BlobStage::open_existing(&cell.0.join("blobs"))?;
        let mut seq = PersistentPeerSequences::open(cell.0.join("seq"), [6; 32])?;
        let request = send(&a, &t, 1, t.encode_stage(&bytes)?)?;
        let receipt = receive_authenticated_replica(
            &t.sender,
            &t.receiver,
            &t,
            &a,
            &mut seq,
            &store,
            &request,
        )?;
        t.verify_local_receipt(&t.receiver, &t.sender, &a, &receipt)?;
        // Sender-side receipt replay must be fenced across a process restart.
        let sender_state = cell.0.join("sender-sequences");
        fs::create_dir(&sender_state)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&sender_state, fs::Permissions::from_mode(0o700))?;
        }
        let mut sender_sequences = PersistentPeerSequences::open(&sender_state, [8; 32])?;
        t.accept_local_receipt(&t.receiver, &t.sender, &a, &mut sender_sequences, &receipt)?;
        assert_eq!(
            t.accept_local_receipt(&t.receiver, &t.sender, &a, &mut sender_sequences, &receipt)
                .unwrap_err(),
            HaError::ReplayDetected,
        );
        drop(sender_sequences);
        let mut sender_sequences = PersistentPeerSequences::open(&sender_state, [8; 32])?;
        assert_eq!(
            t.accept_local_receipt(&t.receiver, &t.sender, &a, &mut sender_sequences, &receipt)
                .unwrap_err(),
            HaError::ReplayDetected,
        );
        drop(sender_sequences);
        assert_eq!(store.read_local(&t.object)?, bytes);
        assert_eq!(
            receive_authenticated_replica(
                &t.sender,
                &t.receiver,
                &t,
                &a,
                &mut seq,
                &store,
                &request
            )
            .unwrap_err(),
            HaError::ReplayDetected
        );
        drop(store);
        drop(seq);
        let store = LocalV6BlobStage::open_existing(&cell.0.join("blobs"))?;
        let mut seq = PersistentPeerSequences::open(cell.0.join("seq"), [6; 32])?;
        let retry = send(&a, &t, 2, t.encode_stage(&bytes)?)?;
        let acknowledged = receive_authenticated_replica(
            &t.sender,
            &t.receiver,
            &t,
            &a,
            &mut seq,
            &store,
            &retry,
        )?;
        t.verify_local_receipt(&t.receiver, &t.sender, &a, &acknowledged)?;
        assert_eq!(store.observe_local_closure(&[t.object])?.object_count(), 1);
        Ok(())
    }
    #[test]
    fn forged_tls_identity_epoch_operation_and_bytes_do_not_stage()
    -> Result<(), Box<dyn std::error::Error>> {
        let (t, a, bytes) = fixture()?;
        let cell = Cell::new()?;
        for name in ["blobs", "seq"] {
            let path = cell.0.join(name);
            fs::create_dir(&path)?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                fs::set_permissions(&path, fs::Permissions::from_mode(0o700))?;
            }
        }
        let store = LocalV6BlobStage::open_existing(&cell.0.join("blobs"))?;
        let mut seq = PersistentPeerSequences::open(cell.0.join("seq"), [6; 32])?;
        let valid = send(&a, &t, 1, t.encode_stage(&bytes)?)?;
        // HMAC tampering is denied before the receiver inspects object bytes.
        let mut wire = heptabao_ha_service::encode_peer_envelope(&valid)?;
        let last = wire.len() - 1;
        wire[last] ^= 0x40;
        let forged = heptabao_ha_service::decode_peer_envelope(&wire)?;
        assert_eq!(
            receive_authenticated_replica(
                &t.sender,
                &t.receiver,
                &t,
                &a,
                &mut seq,
                &store,
                &forged
            )
            .unwrap_err(),
            HaError::PeerAuthenticationFailed,
        );
        let foreign = NodeId::parse("foreign")?;
        assert_eq!(
            receive_authenticated_replica(&foreign, &t.receiver, &t, &a, &mut seq, &store, &valid)
                .unwrap_err(),
            HaError::PeerAuthenticationFailed
        );
        for index in [7, 20, 60, 80, PREFIX] {
            let mut body = t.encode_stage(&bytes)?;
            body[index] ^= 1;
            let bad = send(&a, &t, 1, body)?;
            assert!(
                receive_authenticated_replica(
                    &t.sender,
                    &t.receiver,
                    &t,
                    &a,
                    &mut seq,
                    &store,
                    &bad
                )
                .is_err()
            );
        }
        let wrong = send(&a, &t, 1, t.encode_stage(&bytes)?[..PREFIX + 1].to_vec())?;
        assert!(
            receive_authenticated_replica(&t.sender, &t.receiver, &t, &a, &mut seq, &store, &wrong)
                .is_err()
        );
        assert_eq!(fs::read_dir(cell.0.join("blobs"))?.count(), 0);
        let receipt = receive_authenticated_replica(
            &t.sender,
            &t.receiver,
            &t,
            &a,
            &mut seq,
            &store,
            &valid,
        )?;
        t.verify_local_receipt(&t.receiver, &t.sender, &a, &receipt)?;
        let mut changed = t.clone();
        changed.epoch += 1;
        assert_eq!(
            changed
                .verify_local_receipt(&t.receiver, &t.sender, &a, &receipt)
                .unwrap_err(),
            HaError::InvalidFrame
        );
        Ok(())
    }
    /// Synthetic verified loopback TLS transport, using the exact same
    /// mTLS peer adapter as HA. Does not register any production HA route.
    #[test]
    fn private_mtls_tls_peer_certificate_stage_roundtrip() -> Result<(), Box<dyn std::error::Error>>
    {
        use heptabao_ha_service::{
            MutualTlsPeerTransport, PinnedClientCertificateMap, RAFT_ALPN_PROTOCOL,
            TlsPeerEndpoint, decode_peer_envelope, encode_peer_envelope, serve_one_mtls_peer_frame,
        };
        use rustls::RootCertStore;
        use rustls::pki_types::{CertificateDer, PrivateKeyDer};
        use std::io::{self, BufReader};
        use std::net::TcpListener;
        use std::process::{Command, Stdio};
        use std::sync::Arc;
        use std::thread;
        use std::time::{Duration, Instant};

        fn openssl(dir: &std::path::Path, args: &[&str]) -> io::Result<()> {
            let status = Command::new("openssl")
                .args(args)
                .current_dir(dir)
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status()?;
            if status.success() {
                Ok(())
            } else {
                Err(io::Error::other("synthetic TLS fixture failed"))
            }
        }
        fn certificates(
            path: &std::path::Path,
        ) -> Result<Vec<CertificateDer<'static>>, Box<dyn std::error::Error>> {
            Ok(
                rustls_pemfile::certs(&mut BufReader::new(fs::File::open(path)?))
                    .collect::<Result<Vec<_>, _>>()?,
            )
        }
        fn private_key(
            path: &std::path::Path,
        ) -> Result<PrivateKeyDer<'static>, Box<dyn std::error::Error>> {
            Ok(
                rustls_pemfile::private_key(&mut BufReader::new(fs::File::open(path)?))?
                    .ok_or_else(|| io::Error::other("missing synthetic private key"))?,
            )
        }
        let (ticket, auth, ciphertext) = fixture()?;
        let cell = Cell::new()?;
        let base = cell.0.clone();
        openssl(
            &base,
            &[
                "req",
                "-x509",
                "-newkey",
                "rsa:2048",
                "-nodes",
                "-keyout",
                "ca.key",
                "-out",
                "ca.pem",
                "-days",
                "1",
                "-sha256",
                "-subj",
                "/CN=HeptaBao synthetic replica CA",
                "-addext",
                "basicConstraints=critical,CA:TRUE",
                "-addext",
                "keyUsage=critical,keyCertSign,cRLSign",
            ],
        )?;
        fs::write(
            base.join("server.ext"),
            "basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\nsubjectAltName=DNS:localhost,IP:127.0.0.1\n",
        )?;
        fs::write(
            base.join("client.ext"),
            "basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=clientAuth\n",
        )?;
        for role in ["server", "client"] {
            openssl(
                &base,
                &[
                    "req",
                    "-new",
                    "-newkey",
                    "rsa:2048",
                    "-nodes",
                    "-keyout",
                    &format!("{role}.key"),
                    "-out",
                    &format!("{role}.csr"),
                    "-subj",
                    &format!("/CN={role}"),
                ],
            )?;
            openssl(
                &base,
                &[
                    "x509",
                    "-req",
                    "-in",
                    &format!("{role}.csr"),
                    "-CA",
                    "ca.pem",
                    "-CAkey",
                    "ca.key",
                    "-CAcreateserial",
                    "-out",
                    &format!("{role}.pem"),
                    "-days",
                    "1",
                    "-sha256",
                    "-extfile",
                    &format!("{role}.ext"),
                ],
            )?;
        }
        let ca = certificates(&base.join("ca.pem"))?;
        let client_chain = certificates(&base.join("client.pem"))?;
        let server_chain = certificates(&base.join("server.pem"))?;
        let mut roots = RootCertStore::empty();
        roots.add(ca[0].clone())?;
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let verifier = rustls::server::WebPkiClientVerifier::builder_with_provider(
            Arc::new(roots.clone()),
            provider.clone(),
        )
        .build()?;
        let mut server_config = rustls::ServerConfig::builder_with_provider(provider.clone())
            .with_safe_default_protocol_versions()?
            .with_client_cert_verifier(verifier)
            .with_single_cert(server_chain, private_key(&base.join("server.key"))?)?;
        let mut client_config = rustls::ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()?
            .with_root_certificates(roots)
            .with_client_auth_cert(client_chain.clone(), private_key(&base.join("client.key"))?)?;
        server_config.alpn_protocols = vec![RAFT_ALPN_PROTOCOL.to_vec()];
        client_config.alpn_protocols = vec![RAFT_ALPN_PROTOCOL.to_vec()];
        let leaf = ring::digest::digest(&ring::digest::SHA256, client_chain[0].as_ref());
        let mut pinned_leaf = [0u8; 32];
        pinned_leaf.copy_from_slice(leaf.as_ref());
        let identities = PinnedClientCertificateMap::new(BTreeMap::from([(
            pinned_leaf,
            ticket.sender.clone(),
        )]))?;
        for subdir in ["blobs", "sequences"] {
            let dir = base.join(subdir);
            fs::create_dir(&dir)?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                fs::set_permissions(&dir, fs::Permissions::from_mode(0o700))?;
            }
        }
        let listener = TcpListener::bind("127.0.0.1:0")?;
        let address = listener.local_addr()?;
        let transport = MutualTlsPeerTransport::new(
            BTreeMap::from([(
                ticket.receiver.clone(),
                TlsPeerEndpoint::new(address, "localhost")?,
            )]),
            Arc::new(client_config),
            Duration::from_secs(10),
        )?;
        let server_ticket = ticket.clone();
        let receiver_base = base.clone();
        let server = thread::spawn(move || -> Result<(), HaError> {
            let store = LocalV6BlobStage::open_existing(&receiver_base.join("blobs"))
                .map_err(disk_error)?;
            let mut sequences =
                PersistentPeerSequences::open(receiver_base.join("sequences"), [6; 32])?;
            serve_one_mtls_peer_frame(
                &listener,
                Arc::new(server_config),
                &identities,
                Duration::from_secs(10),
                false,
                |verified_tls_peer, wire| {
                    let request = decode_peer_envelope(&wire)?;
                    let receipt = receive_authenticated_replica(
                        &verified_tls_peer,
                        &server_ticket.receiver,
                        &server_ticket,
                        &auth,
                        &mut sequences,
                        &store,
                        &request,
                    )?;
                    encode_peer_envelope(&receipt)
                },
            )
        });
        let sender_auth = PeerAuthenticator::new(
            "cell",
            BTreeMap::from([
                (ticket.sender.clone(), [1; 32]),
                (ticket.receiver.clone(), [2; 32]),
            ]),
        )?;
        let request = sender_auth.seal(
            ticket.sender.clone(),
            ticket.receiver.clone(),
            ticket.term,
            1,
            PeerMessageKind::V6CiphertextStage,
            ticket.encode_stage(&ciphertext)?,
        )?;
        let response = transport.exchange_before(
            &ticket.receiver,
            &encode_peer_envelope(&request)?,
            Instant::now() + Duration::from_secs(10),
        )?;
        let signed = decode_peer_envelope(&response)?;
        ticket.verify_local_receipt(&ticket.receiver, &ticket.sender, &sender_auth, &signed)?;
        server
            .join()
            .map_err(|_| io::Error::other("synthetic TLS receiver panicked"))??;
        let reopened = LocalV6BlobStage::open_existing(&base.join("blobs"))?;
        assert_eq!(reopened.read_local(&ticket.object)?, ciphertext);
        Ok(())
    }
}
