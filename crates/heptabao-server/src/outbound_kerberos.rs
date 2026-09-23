//! The deliberately small Kerberos acceptor boundary.
//!
//! The operating system GSS-API performs the cryptographic AP-REQ/SPNEGO
//! validation against the deployment's host keytab. Application state only
//! binds the exact service principal and keeps a durable replay fence; it never
//! stores a ticket, session key, or provider error text.

use super::*;
#[cfg(target_os = "linux")]
use base64::{Engine as _, engine::general_purpose::STANDARD};
#[cfg(target_os = "linux")]
use cross_krb5::{AcceptFlags, K5Ctx, K5ServerCtx, ServerCtx, Step};

pub(crate) const MAX_KERBEROS_TOKEN: usize = 128 * 1024;
pub(crate) const MAX_KERBEROS_PRINCIPAL: usize = 512;
pub(crate) const MAX_KERBEROS_TICKET_LIFETIME: u64 = 24 * 60 * 60;

#[derive(Debug, Eq, PartialEq)]
pub(crate) struct KerberosObservation {
    pub(crate) principal: String,
    pub(crate) realm: String,
    pub(crate) service: String,
    pub(crate) expires_at: u64,
}

#[cfg(any(target_os = "linux", test))]
fn principal_realm(principal: &str) -> Option<&str> {
    let (name, realm) = principal.rsplit_once('@')?;
    (!name.is_empty() && !name.contains('@') && !realm.is_empty() && !realm.contains('@'))
        .then_some(realm)
}

#[cfg(any(target_os = "linux", test))]
fn bounded_principal(principal: &str) -> Result<(), &'static str> {
    if principal.is_empty()
        || principal.len() > MAX_KERBEROS_PRINCIPAL
        || !principal.is_ascii()
        || principal.bytes().any(|byte| byte <= 0x20 || byte == 0x7f)
    {
        return Err("invalid Kerberos principal");
    }
    Ok(())
}

#[cfg(target_os = "linux")]
impl Outbound {
    /// Accept one complete HTTP Negotiate token. HTTP multi-round negotiation
    /// is intentionally outside this slice: a continuation is a denial, never
    /// an implicit second provider request.
    pub(crate) fn kerberos_authenticate(
        &self,
        authorization: &str,
        service_principal: &str,
        now: u64,
    ) -> Result<KerberosObservation, &'static str> {
        bounded_principal(service_principal)?;
        let token = authorization
            .strip_prefix("Negotiate ")
            .ok_or("Kerberos login requires a Negotiate authorization")?;
        if token.is_empty() || token.len() > MAX_KERBEROS_TOKEN * 2 || !token.is_ascii() {
            return Err("invalid Kerberos authorization token");
        }
        let token = Zeroizing::new(
            STANDARD
                .decode(token)
                .map_err(|_| "invalid Kerberos authorization encoding")?,
        );
        if token.is_empty() || token.len() > MAX_KERBEROS_TOKEN {
            return Err("Kerberos authorization token exceeds bounds");
        }

        // Requiring neither confidentiality nor mutual authentication keeps
        // this HTTP acceptor compatible with ordinary SPNEGO clients while the
        // AP-REQ, service principal and ticket lifetime remain authenticated.
        let pending = ServerCtx::new(
            AcceptFlags::DISABLE_MUTUAL_AUTH | AcceptFlags::DISABLE_CONFIDENTIALITY,
            Some(service_principal),
            None,
        )
        .map_err(|_| "Kerberos acceptor credentials unavailable")?;
        let context = match pending
            .step(token.as_slice())
            .map_err(|_| "Kerberos authorization rejected")?
        {
            Step::Finished((context, None)) => context,
            Step::Finished((_, Some(_))) | Step::Continue(_) => {
                return Err("Kerberos multi-round negotiation is not supported");
            }
        };
        let mut context = context;
        let lifetime = context
            .ttl()
            .map_err(|_| "Kerberos ticket lifetime unavailable")?;
        let lifetime = lifetime.as_secs();
        if !(1..=MAX_KERBEROS_TICKET_LIFETIME).contains(&lifetime) {
            return Err("Kerberos ticket lifetime is outside bounds");
        }
        let principal = context
            .client()
            .map_err(|_| "Kerberos client principal unavailable")?;
        bounded_principal(&principal)?;
        let realm = principal_realm(&principal)
            .ok_or("Kerberos client realm unavailable")?
            .to_owned();
        let expires_at = now
            .checked_add(lifetime)
            .ok_or("Kerberos ticket expiry overflow")?;
        Ok(KerberosObservation {
            principal,
            realm,
            service: service_principal.to_owned(),
            expires_at,
        })
    }
}

#[cfg(not(target_os = "linux"))]
impl Outbound {
    /// The real acceptor is intentionally Linux-only: the compatibility slice
    /// is accepted against MIT Kerberos on Linux, while macOS remains safe to
    /// build and test without silently substituting a mock provider.
    pub(crate) fn kerberos_authenticate(
        &self,
        _authorization: &str,
        _service_principal: &str,
        _now: u64,
    ) -> Result<KerberosObservation, &'static str> {
        Err("Kerberos provider is unavailable on this platform")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn principal_realm_is_strict_and_bounded() {
        assert_eq!(principal_realm("alice@EXAMPLE.COM"), Some("EXAMPLE.COM"));
        assert!(principal_realm("alice").is_none());
        assert!(principal_realm("alice@EXAMPLE@COM").is_none());
        assert!(bounded_principal("alice@EXAMPLE.COM").is_ok());
        assert!(bounded_principal("alice\n@EXAMPLE.COM").is_err());
    }
}
