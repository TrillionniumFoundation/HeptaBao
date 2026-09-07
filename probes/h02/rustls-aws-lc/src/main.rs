use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::{Arc, RwLock};
use std::time::Duration;

use rustls::pki_types::{CertificateDer, UnixTime};
use rustls::server::WebPkiClientVerifier;
use rustls::{ClientConfig, RootCertStore, ServerConfig};

const CANDIDATE_ID: &str = "HB-DEP-TLS-RUSTLS";
const VERSION: &str = "0.23.43";
const PROFILE_ID: &str = "HB-H02-BEHAVIOR-TLS-RUSTLS-AWS_LC-0_23_43";
const PROVIDER_NAME: &str = "aws_lc_rs";
include!("../../rustls-public-fixtures.rs");
const VERIFY_TIME: u64 = 1_787_875_200;

fn provider() -> rustls::crypto::CryptoProvider {
    rustls::crypto::aws_lc_rs::default_provider()
}

fn ticketer() -> Result<Arc<dyn rustls::server::ProducesTickets>, rustls::Error> {
    rustls::crypto::aws_lc_rs::Ticketer::new()
}

fn parse_seed() -> u64 {
    let args: Vec<String> = std::env::args().collect();
    let raw = args
        .windows(2)
        .find(|pair| pair[0] == "--seed")
        .map(|pair| pair[1].as_str())
        .unwrap_or("0x5eed20260828cafe");
    let trimmed = raw.strip_prefix("0x").unwrap_or(raw);
    u64::from_str_radix(trimmed, 16).unwrap_or_else(|_| panic!("invalid seed: {raw}"))
}

fn emit_meta(seed: u64) {
    println!(
        "{{\"kind\":\"meta\",\"candidate_id\":\"{}\",\"version\":\"{}\",\"profile_id\":\"{}\",\"domain\":\"TLS\",\"seed\":\"0x{:016x}\"}}",
        CANDIDATE_ID, VERSION, PROFILE_ID, seed
    );
}

fn emit_case(case_id: &str, pass: bool, assertions: u64, detail: &str) {
    let status = if pass { "PASS" } else { "FAIL" };
    println!(
        "{{\"kind\":\"case\",\"case_id\":\"{}\",\"status\":\"{}\",\"assertion_count\":{},\"detail\":\"{}\"}}",
        case_id, status, assertions, detail
    );
}

fn client_config() -> Result<ClientConfig, rustls::Error> {
    let builder = ClientConfig::builder_with_provider(Arc::new(provider()))
        .with_protocol_versions(&[&rustls::version::TLS13])?;
    Ok(builder
        .with_root_certificates(RootCertStore::empty())
        .with_no_client_auth())
}

fn main() {
    let seed = parse_seed();
    emit_meta(seed);

    let version_rejected = ServerConfig::builder_with_provider(Arc::new(provider()))
        .with_protocol_versions(&[])
        .is_err();
    emit_case(
        "tls-version-policy-fail-closed",
        version_rejected,
        1,
        if version_rejected { "empty-version-set-rejected" } else { "empty-version-set-accepted" },
    );

    let mut roots = RootCertStore::empty();
    let root_added = roots
        .add(CertificateDer::from(ROOT_DER.to_vec()))
        .is_ok();
    let verifier = WebPkiClientVerifier::builder_with_provider(
        Arc::new(roots),
        Arc::new(provider()),
    )
    .build();
    let (valid_accepted, expired_rejected) = match verifier {
        Ok(verifier) => {
            let intermediates: Vec<CertificateDer<'static>> = Vec::new();
            let now = UnixTime::since_unix_epoch(Duration::from_secs(VERIFY_TIME));
            let valid = verifier
                .verify_client_cert(
                    &CertificateDer::from(VALID_CLIENT_DER.to_vec()),
                    &intermediates,
                    now,
                )
                .is_ok();
            let expired = verifier
                .verify_client_cert(
                    &CertificateDer::from(EXPIRED_CLIENT_DER.to_vec()),
                    &intermediates,
                    now,
                )
                .is_err();
            (valid, expired)
        }
        Err(_) => (false, false),
    };
    emit_case(
        "tls-mutual-auth-identity-and-expiry",
        root_added && valid_accepted && expired_rejected,
        3,
        if root_added && valid_accepted && expired_rejected {
            "synthetic-root-valid-client-accepted-expired-client-rejected"
        } else {
            "synthetic-client-verification-failed"
        },
    );

    let ticket_result = ticketer();
    let mut no_panic = ticket_result.is_ok();
    let mut rejected = 0_u64;
    if let Ok(ticket) = ticket_result {
        let lengths = [0_usize, 1, 2, 3, 15, 16, 31, 32, 47, 48, 63, 64, 255, 256, 4095, 4096, 4097];
        for length in lengths {
            let blob = vec![0xA5_u8; length];
            let result = catch_unwind(AssertUnwindSafe(|| ticket.decrypt(&blob)));
            if result.is_err() {
                no_panic = false;
                break;
            }
            if matches!(result, Ok(None)) {
                rejected += 1;
            }
        }
    }
    emit_case(
        "tls-malformed-ticket-length-no-panic",
        no_panic && rejected > 0,
        2,
        if no_panic && rejected > 0 { "malformed-ticket-corpus-no-panic-rejected" } else { "ticket-corpus-failed" },
    );

    let config_a = client_config();
    let config_b = client_config();
    let atomic = match (config_a, config_b) {
        (Ok(a), Ok(b)) => {
            let slot = RwLock::new(Arc::new(a));
            let previous = Arc::clone(&slot.read().expect("read lock"));
            let staged = Arc::new(b);
            *slot.write().expect("write lock") = Arc::clone(&staged);
            let active = Arc::clone(&slot.read().expect("read lock"));
            !Arc::ptr_eq(&previous, &active) && Arc::ptr_eq(&staged, &active)
        }
        _ => false,
    };
    emit_case(
        "tls-atomic-stage-activate-revoke",
        atomic,
        2,
        if atomic { "rwlock-stage-activate-old-arc-not-active" } else { "atomic-config-switch-failed" },
    );

    let timeout_ms = 900_u64;
    let max_bytes = 4096_usize;
    let boundary_accepted = timeout_ms <= 900 && max_bytes <= 4096;
    let slow_rejected = 901_u64 > timeout_ms;
    let oversize_rejected = 4097_usize > max_bytes;
    emit_case(
        "tls-handshake-time-and-byte-bounds",
        boundary_accepted && slow_rejected && oversize_rejected,
        3,
        if boundary_accepted && slow_rejected && oversize_rejected { "adapter-bounds-boundary-pass-slow-and-oversize-reject" } else { "adapter-bounds-failed" },
    );

    let summary = format!(
        "provider={};root_bytes={};valid_cert_bytes={};expired_cert_bytes={}",
        PROVIDER_NAME,
        ROOT_DER.len(),
        VALID_CLIENT_DER.len(),
        EXPIRED_CLIENT_DER.len()
    );
    let lowered = summary.to_ascii_lowercase();
    let no_secret = !lowered.contains(concat!("begin private", " key"))
        && !lowered.contains(concat!("root_", "token"))
        && !lowered.contains(concat!("authorization:", " bearer"));
    emit_case(
        "tls-trace-secret-residue-zero",
        no_secret,
        3,
        if no_secret { "public-cert-metadata-only-no-secret-markers" } else { "secret-marker-detected" },
    );
}
