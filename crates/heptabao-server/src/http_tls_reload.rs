//! SIGHUP requests a leaf/key reload by one independent background worker.
//! Only the two startup-selected files may change. Client trust, protocol
//! policy, application state and listener ownership retain their original owners.
//! The signal action merely sets a lock-free flag; parsing never runs in it.
use super::bounded_file;
use arc_swap::ArcSwap;
use rustls::crypto::CryptoProvider;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;
use std::fmt;
use std::io::BufReader;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Weak};
use std::time::Duration;

pub(super) struct LeafResolver {
    cert_path: PathBuf,
    key_path: PathBuf,
    provider: Arc<CryptoProvider>,
    current: ArcSwap<CertifiedKey>,
    requested: Arc<AtomicBool>,
    completed: AtomicUsize,
    signal: signal_hook::SigId,
}

impl fmt::Debug for LeafResolver {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("LeafResolver { startup_selected_paths, private_key_redacted }")
    }
}

impl Drop for LeafResolver {
    fn drop(&mut self) {
        // All active TLS connections retain this resolver through ServerConfig.
        // Removing its signal action is only the final listener-owner cleanup.
        let _ = signal_hook::low_level::unregister(self.signal);
    }
}

impl LeafResolver {
    pub(super) fn new(
        cert_path: PathBuf,
        key_path: PathBuf,
        certificates: Vec<CertificateDer<'static>>,
        key: PrivateKeyDer<'static>,
        provider: Arc<CryptoProvider>,
    ) -> Result<Arc<Self>, String> {
        let current = CertifiedKey::from_der(certificates, key, &provider)
            .map_err(|_| "TLS key and certificate do not match")?;
        current
            .keys_match()
            .map_err(|_| "TLS leaf public key binding cannot be verified")?;
        let requested = Arc::new(AtomicBool::new(false));
        let signal = signal_hook::flag::register(
            signal_hook::consts::signal::SIGHUP,
            Arc::clone(&requested),
        )
        .map_err(|_| "cannot install TLS leaf reload signal action")?;
        let resolver = Arc::new(Self {
            cert_path,
            key_path,
            provider,
            current: ArcSwap::from_pointee(current),
            requested,
            completed: AtomicUsize::new(0),
            signal,
        });
        let weak = Arc::downgrade(&resolver);
        std::thread::Builder::new()
            .name("heptabao-tls-leaf-reload".into())
            .spawn(move || Self::worker(weak))
            .map_err(|_| "cannot start TLS leaf reload worker")?;
        Ok(resolver)
    }

    fn load_candidate(&self) -> Result<CertifiedKey, String> {
        // Preserve the exact startup bounded-file and owner-only key checks.
        // No request field, environment variable or API can select these paths.
        let raw_certificates = bounded_file(&self.cert_path, false)?;
        let certificates = rustls_pemfile::certs(&mut BufReader::new(raw_certificates.as_slice()))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| "invalid TLS certificate chain")?;
        if certificates.is_empty() {
            return Err("TLS certificate chain is empty".into());
        }
        let raw_key = bounded_file(&self.key_path, true)?;
        let key = rustls_pemfile::private_key(&mut BufReader::new(raw_key.as_slice()))
            .map_err(|_| "invalid TLS key")?
            .ok_or("missing TLS private key")?;
        let candidate = CertifiedKey::from_der(certificates, key, &self.provider)
            .map_err(|_| "TLS key and certificate do not match")?;
        candidate
            .keys_match()
            .map_err(|_| "TLS leaf public key binding cannot be verified")?;
        Ok(candidate)
    }

    fn worker(weak: Weak<Self>) {
        while let Some(owner) = weak.upgrade() {
            if owner.requested.swap(false, Ordering::AcqRel) {
                // No key lock is held during filesystem I/O or parsing. Slow
                // storage cannot occupy a TLS Future or delay another reader.
                match owner.load_candidate() {
                    Ok(candidate) => {
                        let candidate = Arc::new(candidate);
                        let previous = owner.current.swap(candidate);
                        // Reclamation is outside publication. Readers retain a
                        // complete old or new Arc without a certificate gap.
                        drop(previous);
                        eprintln!("HeptaBao TLS leaf reload completed");
                    }
                    Err(_) => {
                        // A failed or partial file replacement never clears the
                        // previously working key. A new signal authorizes a retry.
                        eprintln!("HeptaBao TLS leaf reload rejected; prior TLS leaf retained");
                    }
                }
                owner.completed.fetch_add(1, Ordering::Release);
            }
            drop(owner);
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    fn selected_key(&self) -> Option<Arc<CertifiedKey>> {
        // Readers never serialize with each other, reject a healthy handshake
        // due to publication, or wait for filesystem I/O/private-key cleanup.
        Some(self.current.load_full())
    }
}

impl ResolvesServerCert for LeafResolver {
    fn resolve(&self, _hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        self.selected_key()
    }
}

#[cfg(test)]
#[path = "http_tls_reload_tests.rs"]
mod tests;
