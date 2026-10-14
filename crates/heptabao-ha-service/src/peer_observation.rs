//! Per-exchange diagnostics contain only typed categories and numeric metadata.
use crate::HaError;
use std::io;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PeerIoStage {
    Unstarted,
    PeerLookup,
    ServerName,
    FrameValidate,
    TcpConnect,
    SocketConfig,
    TlsSetup,
    TlsHandshake,
    Alpn,
    LeafPin,
    WriteLength,
    WritePayload,
    Flush,
    ReadLength,
    ReadPayload,
    Deadline,
    PeerRegistry,
    RequestDecode,
    RequestBinding,
    ForwardAdmission,
    ForwardHandlerRegistry,
    Service,
    ResponseEncode,
    ResponseDecode,
    ResponseBinding,
    CompletionDigest,
    CompletionMissing,
    CompletionVerify,
    LocalAppliedWait,
    ResponseUnwrap,
    RaftAdmission,
    BlockingTaskWait,
    Accept,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PeerOperation {
    Append,
    Vote,
    PreVote,
    Snapshot,
    Transfer,
    ReadIndex,
    Forward,
    Inbound,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TlsPhase {
    Handshake,
    Application,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TlsFailureCategory {
    CertificateEncoding,
    CertificateExpired,
    CertificateNotYetValid,
    CertificateRevoked,
    CertificateUnknownIssuer,
    CertificateSignature,
    CertificateName,
    CertificatePurpose,
    CertificateOther,
    NoCertificate,
    Incompatible,
    Misbehaved,
    Alert,
    InvalidMessage,
    Decrypt,
    Encrypt,
    General,
    Other,
}
fn tls_category(error: &rustls::Error) -> TlsFailureCategory {
    use TlsFailureCategory as T;
    use rustls::{CertificateError as C, Error as E};
    match error {
        E::InvalidCertificate(certificate) => match certificate {
            C::BadEncoding => T::CertificateEncoding,
            C::Expired | C::ExpiredContext { .. } => T::CertificateExpired,
            C::NotValidYet | C::NotValidYetContext { .. } => T::CertificateNotYetValid,
            C::Revoked => T::CertificateRevoked,
            C::UnknownIssuer => T::CertificateUnknownIssuer,
            C::BadSignature => T::CertificateSignature,
            C::NotValidForName | C::NotValidForNameContext { .. } => T::CertificateName,
            C::InvalidPurpose | C::InvalidPurposeContext { .. } => T::CertificatePurpose,
            _ => T::CertificateOther,
        },
        E::NoCertificatesPresented => T::NoCertificate,
        E::PeerIncompatible(_) => T::Incompatible,
        E::PeerMisbehaved(_) => T::Misbehaved,
        E::AlertReceived(_) => T::Alert,
        E::InvalidMessage(_) => T::InvalidMessage,
        E::DecryptError => T::Decrypt,
        E::EncryptError => T::Encrypt,
        E::General(_) => T::General,
        _ => T::Other,
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PeerIoObservation {
    pub stage: PeerIoStage,
    pub io_kind: Option<io::ErrorKind>,
    pub os_errno: Option<i32>,
    pub tls_category: Option<TlsFailureCategory>,
    pub tls_phase: Option<TlsPhase>,
    pub authenticated_source: Option<u64>,
    pub response_status: Option<u16>,
}
impl Default for PeerIoObservation {
    fn default() -> Self {
        Self {
            stage: PeerIoStage::Unstarted,
            io_kind: None,
            os_errno: None,
            tls_category: None,
            tls_phase: None,
            authenticated_source: None,
            response_status: None,
        }
    }
}
impl PeerIoObservation {
    pub fn enter(&mut self, stage: PeerIoStage) {
        self.stage = stage;
        // A new phase cannot inherit an unrelated earlier I/O failure.
        self.io_kind = None;
        self.os_errno = None;
        self.tls_category = None;
        self.tls_phase = None;
    }
    pub fn record_io(&mut self, error: &io::Error) {
        self.io_kind = Some(error.kind());
        self.os_errno = error.raw_os_error();
        self.tls_category = error
            .get_ref()
            .and_then(|inner| inner.downcast_ref::<rustls::Error>())
            .map(tls_category);
    }
    pub fn record_tls(&mut self, error: &rustls::Error) {
        self.tls_category = Some(tls_category(error));
    }
    pub fn mark_tls_phase(&mut self, handshaking: bool) {
        self.tls_phase = Some(if handshaking {
            TlsPhase::Handshake
        } else {
            TlsPhase::Application
        });
    }
    /// Rate limiting shares only timestamps. Every cause belongs to this call.
    pub fn emit(
        &self,
        operation: PeerOperation,
        source: u64,
        target: u64,
        error: HaError,
        budget: Duration,
        started: Instant,
    ) {
        static ORIGIN: OnceLock<Instant> = OnceLock::new();
        static LAST: [AtomicU64; 40] = [const { AtomicU64::new(u64::MAX) }; 40];
        let relative = ORIGIN.get_or_init(Instant::now).elapsed();
        let slot = &LAST[self.stage as usize];
        let bucket = relative.as_secs();
        let previous = slot.load(Ordering::Relaxed);
        if previous != u64::MAX && bucket <= previous
            || slot
                .compare_exchange(previous, bucket, Ordering::Relaxed, Ordering::Relaxed)
                .is_err()
        {
            return;
        }
        let unix_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |v| v.as_millis());
        eprintln!(
            "heptabao-peer-failure: operation={operation:?} source={source} target={target} stage={:?} io_kind={:?} os_errno={:?} tls={:?} tls_phase={:?} error={error:?} response_status={:?} budget_ms={} elapsed_ms={} relative_ms={} unix_ms={unix_ms}",
            self.stage,
            self.io_kind,
            self.os_errno,
            self.tls_category,
            self.tls_phase,
            self.response_status,
            budget.as_millis(),
            started.elapsed().as_millis(),
            relative.as_millis()
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Cursor, Write};
    type Result = std::result::Result<(), Box<dyn std::error::Error>>;
    #[test]
    fn frame_failures_distinguish_length_payload_and_invalid_length() -> Result {
        let mut observation = PeerIoObservation::default();
        assert_eq!(
            crate::read_bounded_frame_observed(&mut Cursor::new(vec![0, 0]), &mut observation),
            Err(HaError::Transport)
        );
        assert_eq!(observation.stage, PeerIoStage::ReadLength);
        assert_eq!(observation.io_kind, Some(io::ErrorKind::UnexpectedEof));
        assert_eq!(
            crate::read_bounded_frame_observed(
                &mut Cursor::new(vec![0, 0, 0, 3, 1]),
                &mut observation
            ),
            Err(HaError::Transport)
        );
        assert_eq!(observation.stage, PeerIoStage::ReadPayload);
        assert_eq!(
            crate::read_bounded_frame_observed(
                &mut Cursor::new(vec![0, 0, 0, 0]),
                &mut observation
            ),
            Err(HaError::InvalidFrame)
        );
        assert_eq!(observation.stage, PeerIoStage::FrameValidate);
        assert_eq!(observation.io_kind, None);
        Ok(())
    }
    #[derive(Debug)]
    struct FlushFailure;
    impl Write for FlushFailure {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            Ok(bytes.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Err(io::Error::from(io::ErrorKind::BrokenPipe))
        }
    }
    #[test]
    fn failed_flush_keeps_original_transport_error_and_actual_io_category() -> Result {
        let mut observation = PeerIoObservation::default();
        assert_eq!(
            crate::write_bounded_frame_observed(
                &mut FlushFailure,
                b"private-body",
                &mut observation
            ),
            Err(HaError::Transport)
        );
        assert_eq!(observation.stage, PeerIoStage::Flush);
        assert_eq!(observation.io_kind, Some(io::ErrorKind::BrokenPipe));
        assert!(!format!("{observation:?}").contains("private-body"));
        Ok(())
    }
    #[test]
    fn tls_categories_exclude_rustls_strings_and_certificate_context() -> Result {
        let mut observation = PeerIoObservation::default();
        observation.enter(PeerIoStage::TlsHandshake);
        observation.record_io(&io::Error::other(rustls::Error::General(
            "secret-token-and-peer-name".into(),
        )));
        assert_eq!(observation.tls_category, Some(TlsFailureCategory::General));
        assert!(!format!("{observation:?}").contains("secret-token"));
        observation.record_io(&io::Error::other(rustls::Error::InvalidCertificate(
            rustls::CertificateError::UnknownIssuer,
        )));
        assert_eq!(
            observation.tls_category,
            Some(TlsFailureCategory::CertificateUnknownIssuer)
        );
        observation.enter(PeerIoStage::ResponseBinding);
        assert_eq!(observation.tls_category, None);
        assert_eq!(observation.io_kind, None);
        Ok(())
    }
    #[test]
    fn concurrent_exchanges_keep_separate_failure_phases() -> Result {
        let handles = [
            (vec![0, 0], PeerIoStage::ReadLength),
            (vec![0, 0, 0, 3, 1], PeerIoStage::ReadPayload),
        ]
        .map(|(bytes, stage)| {
            std::thread::spawn(move || {
                let mut observation = PeerIoObservation::default();
                let result =
                    crate::read_bounded_frame_observed(&mut Cursor::new(bytes), &mut observation);
                (result, observation.stage, stage)
            })
        });
        for handle in handles {
            let (result, observed, expected) = handle
                .join()
                .map_err(|_| io::Error::other("diagnostic test worker failed"))?;
            assert_eq!(result, Err(HaError::Transport));
            assert_eq!(observed, expected);
        }
        Ok(())
    }
}
