//! Explicitly opt-in, ephemeral Mac↔X230 ciphertext test ONLY.
//! Never installs a production HA handler, never publishes a native V6 root.
//! TLS keys are local private fixture files. No product credentials accepted.
use std::collections::{BTreeMap, BTreeSet};
use std::env;
use std::error::Error;
use std::fs;
use std::net::{SocketAddr, TcpListener};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use heptabao_ha_service::{
    AuthenticatedV6ReplicaReceiver, MutualTlsPeerTransport, NodeId, PinnedClientCertificateMap,
    RAFT_ALPN_PROTOCOL, TlsPeerEndpoint, encode_v6_replica_request, verify_v6_local_receipt,
};
use heptabao_raft_runtime::{LocalV6BlobStage, SealedRecordObject};
use ring::digest::{SHA256, digest};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::server::WebPkiClientVerifier;
use rustls::{ClientConfig, RootCertStore, ServerConfig};

const CLUSTER: &str = "hb-private-v6-crosshost";
const EPOCH: u64 = 7;
const OPERATION: [u8; 32] = [5; 32];
const PAYLOAD_BYTES: usize = 256 * 1024;
const TIMEOUT: Duration = Duration::from_secs(15);

fn cert(path: &Path) -> Result<Vec<CertificateDer<'static>>, Box<dyn Error>> {
    Ok(vec![CertificateDer::from(fs::read(path)?)])
}
fn key(path: &Path) -> Result<PrivateKeyDer<'static>, Box<dyn Error>> {
    Ok(PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(fs::read(
        path,
    )?)))
}
fn roots(dir: &Path) -> Result<RootCertStore, Box<dyn Error>> {
    let mut roots = RootCertStore::empty();
    roots.add(cert(&dir.join("ca.crt.der"))?.remove(0))?;
    Ok(roots)
}
fn make_server_tls(dir: &Path) -> Result<Arc<ServerConfig>, Box<dyn Error>> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut config = ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()?
        .with_client_cert_verifier(WebPkiClientVerifier::builder(Arc::new(roots(dir)?)).build()?)
        .with_single_cert(
            cert(&dir.join("server.crt.der"))?,
            key(&dir.join("server.key.der"))?,
        )?;
    config.alpn_protocols = vec![RAFT_ALPN_PROTOCOL.to_vec()];
    Ok(Arc::new(config))
}
fn make_client_tls(dir: &Path, mode: &str) -> Result<Arc<ClientConfig>, Box<dyn Error>> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let prefix = if mode == "rogue" { "rogue" } else { "client" };
    let mut config = ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()?
        .with_root_certificates(roots(dir)?)
        .with_client_auth_cert(
            cert(&dir.join(format!("{prefix}.crt.der")))?,
            key(&dir.join(format!("{prefix}.key.der")))?,
        )?;
    config.alpn_protocols = vec![RAFT_ALPN_PROTOCOL.to_vec()];
    Ok(Arc::new(config))
}
fn expected_object() -> Result<SealedRecordObject, Box<dyn Error>> {
    let mut payload = vec![0x61_u8; PAYLOAD_BYTES];
    payload[..8].copy_from_slice(b"HBV6TEST");
    Ok(SealedRecordObject::new_native_v6_ciphertext_chunk(payload)?)
}
fn server(
    listen: SocketAddr,
    pki: PathBuf,
    storage: PathBuf,
    expected: &str,
) -> Result<(), Box<dyn Error>> {
    if !matches!(expected, "accept" | "deny") {
        return Err("unknown server expectation".into());
    }
    let mut pin = BTreeMap::new();
    let client_leaf = cert(&pki.join("client.crt.der"))?;
    let id: [u8; 32] = digest(&SHA256, client_leaf[0].as_ref())
        .as_ref()
        .try_into()?;
    pin.insert(id, NodeId::parse("mac")?);
    let pins = PinnedClientCertificateMap::new(pin)?;
    let receiver = AuthenticatedV6ReplicaReceiver::open_existing(
        NodeId::parse("x230")?,
        CLUSTER,
        EPOCH,
        OPERATION,
        BTreeSet::from([NodeId::parse("mac")?]),
        &storage,
    )?;
    let listener = TcpListener::bind(listen)?;
    println!("READY=TRUE EXPECT={expected}"); // no addresses, identities, secrets
    let prior = fs::read_dir(&storage)?.count();
    let result = receiver.serve_one_mtls(&listener, make_server_tls(&pki)?, &pins, TIMEOUT);
    match expected {
        "accept" => result?,
        "deny" => {
            if result.is_ok() {
                return Err("negative case incorrectly acknowledged".into());
            }
            if fs::read_dir(&storage)?.count() != prior {
                return Err("rejected frame unexpectedly changed storage".into());
            }
        }
        _ => unreachable!(),
    }
    drop(receiver);
    if expected == "accept" {
        let store = LocalV6BlobStage::open_existing(&storage)?;
        let object = expected_object()?;
        if store.read_local(object.reference())? != object.sealed() {
            return Err("post-run physical ciphertext readback mismatch".into());
        }
        if fs::read_dir(&storage)?.count() != 1 {
            return Err("duplicate ciphertext object publication".into());
        }
    }
    println!(
        "RESULT={}",
        if expected == "accept" {
            "LOCAL_FSYNC_ONLY"
        } else {
            "DENIED_NO_EFFECT"
        }
    );
    Ok(())
}
fn client(endpoint: SocketAddr, dir: PathBuf, mode: &str) -> Result<(), Box<dyn Error>> {
    if !matches!(
        mode,
        "valid" | "wrong-op" | "wrong-epoch" | "wrong-id" | "rogue"
    ) {
        return Err("unknown client test mode".into());
    }
    let peer = NodeId::parse("x230")?;
    let mut reference = expected_object()?.reference().clone();
    if mode == "wrong-id" {
        reference.id[0] ^= 1;
    }
    let epoch = if mode == "wrong-epoch" {
        EPOCH + 1
    } else {
        EPOCH
    };
    let operation = if mode == "wrong-op" {
        [4; 32]
    } else {
        OPERATION
    };
    let body = expected_object()?;
    let frame = encode_v6_replica_request(CLUSTER, epoch, operation, &reference, body.sealed())?;
    let transport = MutualTlsPeerTransport::new(
        BTreeMap::from([(peer.clone(), TlsPeerEndpoint::new(endpoint, "localhost")?)]),
        make_client_tls(&dir, mode)?,
        TIMEOUT,
    )?;
    let reply = transport.exchange_before(&peer, &frame, Instant::now() + TIMEOUT);
    if mode == "valid" {
        let reply = reply?;
        verify_v6_local_receipt(CLUSTER, EPOCH, OPERATION, body.reference(), &reply)?;
        println!("RESULT=LOCAL_RECEIPT_VERIFIED_NOT_QUORUM");
    } else {
        if reply.is_ok() {
            return Err("invalid request unexpectedly returned a local receipt".into());
        }
        println!("RESULT=DENIED_NO_RECEIPT");
    }
    Ok(())
}
/// Exercise two independent physical phases of a synthetic 139 MiB collection.
/// Each frame receives its own mTLS-authenticated, local-only fsync receipt;
/// no Raft operation/root/quorum is claimed by this fixture.
fn batch_object(index: usize) -> Result<SealedRecordObject, Box<dyn Error>> {
    if index >= 556 {
        return Err("synthetic bounded index exceeded".into());
    }
    let mut payload = vec![0x6a_u8; PAYLOAD_BYTES];
    payload[..8].copy_from_slice(&(index as u64).to_be_bytes());
    Ok(SealedRecordObject::new_native_v6_ciphertext_chunk(payload)?)
}
fn parse_batch_range(raw: &str) -> Result<(usize, usize), Box<dyn Error>> {
    let (first, last) = raw.split_once(':').ok_or("expected start:end")?;
    let first: usize = first.parse()?;
    let last: usize = last.parse()?;
    if first >= last || last > 556 {
        return Err("invalid bounded replica range".into());
    }
    Ok((first, last))
}
fn batch_server(
    address: SocketAddr,
    pki: PathBuf,
    storage: PathBuf,
    first: usize,
    last: usize,
) -> Result<(), Box<dyn Error>> {
    let receiver = AuthenticatedV6ReplicaReceiver::open_existing(
        NodeId::parse("x230")?,
        CLUSTER,
        EPOCH,
        OPERATION,
        BTreeSet::from([NodeId::parse("mac")?]),
        &storage,
    )?;
    let leaf = cert(&pki.join("client.crt.der"))?;
    let fingerprint: [u8; 32] = digest(&SHA256, leaf[0].as_ref()).as_ref().try_into()?;
    let pins =
        PinnedClientCertificateMap::new(BTreeMap::from([(fingerprint, NodeId::parse("mac")?)]))?;
    let tls = make_server_tls(&pki)?;
    let listener = TcpListener::bind(address)?;
    println!("READY=BATCH COUNT={}", last - first);
    let started = Instant::now();
    for _ in first..last {
        receiver.serve_one_mtls(&listener, tls.clone(), &pins, TIMEOUT)?;
    }
    drop(receiver);
    let store = LocalV6BlobStage::open_existing(&storage)?;
    let refs = (0..last)
        .map(batch_object)
        .collect::<Result<Vec<_>, _>>()?
        .into_iter()
        .map(|o| o.reference().clone())
        .collect::<Vec<_>>();
    let observed = store.observe_local_closure(&refs)?;
    if observed.object_count() != last
        || observed.ciphertext_bytes() != last as u64 * PAYLOAD_BYTES as u64
        || fs::read_dir(&storage)?.count() != last
    {
        return Err("incorrect bounded physical collection after transfer".into());
    }
    println!(
        "RESULT=BATCH_LOCAL_FSYNC_NOT_QUORUM count={} bytes={} elapsed_ms={}",
        last,
        observed.ciphertext_bytes(),
        started.elapsed().as_millis()
    );
    Ok(())
}
fn batch_client(
    address: SocketAddr,
    pki: PathBuf,
    first: usize,
    last: usize,
) -> Result<(), Box<dyn Error>> {
    let peer = NodeId::parse("x230")?;
    let transport = MutualTlsPeerTransport::new(
        BTreeMap::from([(peer.clone(), TlsPeerEndpoint::new(address, "localhost")?)]),
        make_client_tls(&pki, "valid")?,
        TIMEOUT,
    )?;
    let started = Instant::now();
    for index in first..last {
        let object = batch_object(index)?;
        let frame = encode_v6_replica_request(
            CLUSTER,
            EPOCH,
            OPERATION,
            object.reference(),
            object.sealed(),
        )?;
        let reply = transport.exchange_before(&peer, &frame, Instant::now() + TIMEOUT)?;
        verify_v6_local_receipt(CLUSTER, EPOCH, OPERATION, object.reference(), &reply)?;
    }
    println!(
        "RESULT=BATCH_RECEIPTS_NOT_QUORUM count={} elapsed_ms={}",
        last - first,
        started.elapsed().as_millis()
    );
    Ok(())
}

fn main() -> Result<(), Box<dyn Error>> {
    if env::var("HEPTABAO_PRIVATE_LAN_REPLICA_TEST").as_deref() != Ok("YES") {
        return Err("private fixture must be explicitly enabled".into());
    }
    let args: Vec<String> = env::args().collect();
    if args.len() != 5 {
        return Err("usage: example server LISTEN PKIDIR STORAGEDIR/accept|deny or client ENDPOINT PKIDIR MODE".into());
    }
    let socket: SocketAddr = args[2].parse()?;
    let pki = PathBuf::from(&args[3]);
    if args[1] == "server" {
        // Client sends one request for exactly one lifetime-scoped server process.
        let (store, expectation) = args[4]
            .split_once(':')
            .ok_or("server requires private_storage_path:accept|deny")?;
        server(socket, pki, PathBuf::from(store), expectation)
    } else if args[1] == "client" {
        client(socket, pki, &args[4])
    } else if args[1] == "server-batch" {
        let (dir, range) = args[4].split_once('@').ok_or("expected DIR@start:end")?;
        let (first, last) = parse_batch_range(range)?;
        batch_server(socket, pki, PathBuf::from(dir), first, last)
    } else if args[1] == "client-batch" {
        let (first, last) = parse_batch_range(&args[4])?;
        batch_client(socket, pki, first, last)
    } else {
        Err("unsupported mode".into())
    }
}
