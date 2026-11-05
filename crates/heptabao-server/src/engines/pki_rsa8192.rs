//! Schema108 covers actual RSA8192 keys and signed public objects. This only
//! identifies durable representations; cryptographic/state validation remains
//! mandatory, and this scan grants no actor, private key or request time.
use super::*;
use openssl::pkey::{Id, PKey};
use x509_parser::prelude::{FromDer, X509Certificate};

pub(super) fn certificate_owned(bytes: &[u8]) -> bool {
    X509Certificate::from_der(bytes)
        .ok()
        .is_some_and(|(rest, cert)| {
            rest.is_empty()
                && PKey::public_key_from_der(cert.public_key().raw)
                    .ok()
                    .is_some_and(|key| key.id() == Id::RSA && key.bits() == 8192)
        })
}
impl RootCa {
    pub(super) fn has_rsa8192_state(&self) -> bool {
        self.local_material
            .as_ref()
            .is_some_and(|key| key.kind() == LocalKeyKind::Rsa8192)
            || certificate_owned(&self.certificate_der)
            || self
                .local_chain
                .as_ref()
                .is_some_and(|chain| chain.has_rsa8192_state())
    }
}
impl Pki {
    pub(in crate::engines) fn has_rsa8192_state(&self) -> bool {
        self.local_key_instances().any(RootCa::has_rsa8192_state)
            || self
                .roles
                .values()
                .any(|role| role.local_key_kind == Some(LocalKeyKind::Rsa8192))
            || self
                .issued
                .values()
                .any(|issued| certificate_owned(&issued.certificate_der))
            || self
                .local_issuers
                .as_ref()
                .is_some_and(|issuers| issuers.has_rsa8192_state())
            || self
                .local_intermediate
                .as_ref()
                .is_some_and(|intermediate| intermediate.has_rsa8192_state())
            || self.external_has_rsa8192_state()
            || self.acme_protocol.as_ref().is_some_and(|protocol| {
                protocol.orders.values().any(|order| {
                    order
                        .certificate
                        .as_ref()
                        .is_some_and(|certificate| certificate_owned(&certificate.der))
                })
            })
    }
}
