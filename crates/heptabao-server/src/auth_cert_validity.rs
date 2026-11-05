//! Validate each presented leaf at the existing trusted request clock.
//! TLS handshakes may precede this request and never replace this check.
use super::{AuthError, AuthorityTime, denied, parse_x509_certificate};

const NANOS_PER_SECOND: i128 = 1_000_000_000;

pub(super) fn validate(leaf: &[u8], time: AuthorityTime) -> Result<(), AuthError> {
    let (remaining, certificate) = parse_x509_certificate(leaf).map_err(|_| denied())?;
    if !remaining.is_empty() {
        return Err(denied());
    }
    let validity = certificate.validity();
    let not_before = i128::from(validity.not_before.timestamp()) * NANOS_PER_SECOND;
    let not_after = i128::from(validity.not_after.timestamp()) * NANOS_PER_SECOND;
    let observed = match time {
        AuthorityTime::Coarse(seconds) => i128::from(seconds) * NANOS_PER_SECOND,
        AuthorityTime::Precise(at) => {
            i128::from(at.seconds()) * NANOS_PER_SECOND
                + i128::from(at.duration_since_epoch().subsec_nanos())
        }
    };
    // X.509 validity is inclusive at both endpoints. Preserve the original
    // subsecond request time: truncating would admit an expired certificate.
    if not_before > not_after || observed < not_before || observed > not_after {
        return Err(denied());
    }
    Ok(())
}
