//! PRIVATE synthetic ciphertext to TWO physical pinned-mTLS recipients only.
//! No production V6/HA listener, Raft quorum, root CAS, or client acknowledgement.
use std::collections::BTreeMap;
use std::env;
use std::error::Error;
use std::fs;
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use heptabao_ha_service::{
    MutualTlsPeerTransport, NodeId, RAFT_ALPN_PROTOCOL, TlsPeerEndpoint, V6ReplicaCopyTarget,
    V6ReplicaCustodyFanout,
};
use heptabao_raft_runtime::LocalV6BlobStage;
use ring::digest::{SHA256, digest};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::{ClientConfig, RootCertStore};

const CLUSTER: &str = "hb-private-v6-crosshost";
const EPOCH: u64 = 7;
const OPERATION: [u8; 32] = [5; 32];
const PAYLOAD_BYTES: usize = 256 * 1024;
const PEER_TIMEOUT: Duration = Duration::from_secs(15);
const TOTAL_DEADLINE: Duration = Duration::from_secs(280);

fn test_only_tailnet(address: SocketAddr) -> Result<SocketAddr, Box<dyn Error>> {
    if let IpAddr::V4(ip) = address.ip() {
        let octets = ip.octets();
        if octets[0] == 100 && (64..128).contains(&octets[1]) && address.port() != 0 {
            return Ok(address);
        }
    }
    Err("only explicitly provided Tailnet test receiver addresses are allowed".into())
}
fn certificate(dir: &Path, leaf: &str) -> Result<Vec<CertificateDer<'static>>, Box<dyn Error>> {
    Ok(vec![CertificateDer::from(fs::read(dir.join(leaf))?)])
}
fn client_tls(dir: &Path) -> Result<Arc<ClientConfig>, Box<dyn Error>> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut roots = RootCertStore::empty();
    roots.add(certificate(dir, "ca.crt.der")?.remove(0))?;
    let mut tls = ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()?
        .with_root_certificates(roots)
        .with_client_auth_cert(
            certificate(dir, "client.crt.der")?,
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(fs::read(
                dir.join("client.key.der"),
            )?)),
        )?;
    tls.alpn_protocols = vec![RAFT_ALPN_PROTOCOL.to_vec()];
    Ok(Arc::new(tls))
}
fn receiver(
    name: &str,
    endpoint: SocketAddr,
    dir: &Path,
) -> Result<V6ReplicaCopyTarget, Box<dyn Error>> {
    let node = NodeId::parse(name)?;
    let pin: [u8; 32] = digest(&SHA256, certificate(dir, "server.crt.der")?[0].as_ref())
        .as_ref()
        .try_into()?;
    let transport = MutualTlsPeerTransport::new(
        BTreeMap::from([(
            node.clone(),
            TlsPeerEndpoint::new(test_only_tailnet(endpoint)?, "localhost")?,
        )]),
        client_tls(dir)?,
        PEER_TIMEOUT,
    )?;
    Ok(V6ReplicaCopyTarget::new(node, transport, pin)?)
}
fn parse_range(value: &str) -> Result<(usize, usize), Box<dyn Error>> {
    let (first, last) = value.split_once(':').ok_or("expected start:end")?;
    let first: usize = first.parse()?;
    let last: usize = last.parse()?;
    if first >= last || last > 556 {
        return Err("invalid synthetic V6 object interval".into());
    }
    Ok((first, last))
}
fn main() -> Result<(), Box<dyn Error>> {
    if env::var("HEPTABAO_PRIVATE_LAN_REPLICA_TEST").as_deref() != Ok("YES") {
        return Err("fixture requires explicit private enable".into());
    }
    let args: Vec<String> = env::args().collect();
    if args.len() != 7 {
        return Err(
            "usage: example X230_ADDR X230_CLIENT_PKI ROG_ADDR ROG_CLIENT_PKI SOURCE_DIR start:end"
                .into(),
        );
    }
    let x230: SocketAddr = args[1].parse()?;
    let rog: SocketAddr = args[3].parse()?;
    let pki_x230 = PathBuf::from(&args[2]);
    let pki_rog = PathBuf::from(&args[4]);
    let source_dir = PathBuf::from(&args[5]);
    let (first, last) = parse_range(&args[6])?;
    let source = LocalV6BlobStage::open_existing(&source_dir)?;
    let mut references = Vec::with_capacity(last - first);
    // Exactly the same deterministic 256 KiB unique ciphertext objects as
    // the original PR #132/#134 physical 139 MiB fixture.
    for n in first..last {
        let mut payload = vec![0x6a_u8; PAYLOAD_BYTES];
        payload[..8].copy_from_slice(&(n as u64).to_be_bytes());
        references.push(source.stage_local(&payload)?.reference().clone());
    }
    let before = source.observe_local_closure(&references)?;
    let fanout = V6ReplicaCustodyFanout::new(
        CLUSTER,
        EPOCH,
        OPERATION,
        vec![
            receiver("x230", x230, &pki_x230)?,
            receiver("rog", rog, &pki_rog)?,
        ],
    )?;
    let started = Instant::now();
    let result = fanout.deliver_local_copies(&source, &references, started + TOTAL_DEADLINE)?;
    if result.manifest_sha256() != before.manifest_sha256()
        || result.object_count() != last - first
        || result.ciphertext_bytes() != (last - first) as u64 * PAYLOAD_BYTES as u64
        || result.completed_recipients().len() != 2
    {
        return Err("two-target local custody observation mismatch".into());
    }
    println!(
        "RESULT=PRIVATE_TWO_PEER_LOCAL_FSYNC_ONLY_NOT_RAFT_QUORUM objects={} bytes_per_peer={} recipients=2 elapsed_ms={}",
        result.object_count(),
        result.ciphertext_bytes(),
        started.elapsed().as_millis()
    );
    Ok(())
}
