//! OpenBao 2.7 named groups using the maintained rustls AWS-LC provider.
//! The P-384 hybrid uses the IETF ECDHE-MLKEM wire layout. No group implements
//! a classical fallback: rustls can select only an explicitly configured group.
use aws_lc_rs::{agreement, rand::SystemRandom};
use rustls::crypto::aws_lc_rs::kx_group;
use rustls::ffdhe_groups::FfdheGroup;
use rustls::{
    Error, NamedGroup, PeerMisbehaved, ProtocolVersion, SupportedProtocolVersion,
    crypto::{
        ActiveKeyExchange, CompletedKeyExchange, CryptoProvider, SharedSecret, SupportedKxGroup,
    },
};

const P384_MLKEM1024_NAME: NamedGroup = NamedGroup::Unknown(0x11ed);
static P384_MLKEM1024: &dyn SupportedKxGroup = &P384MlKem1024;
static P521: &dyn SupportedKxGroup = &P521Group;

/// The documentation leaves nil preferences to the TLS implementation. Offer
/// all four supported PQ groups before the classical groups; this is our
/// provider policy, not a claim about Go's unspecified default ordering.
pub(crate) fn default_provider() -> CryptoProvider {
    let mut provider = rustls::crypto::aws_lc_rs::default_provider();
    provider.kx_groups = vec![
        kx_group::X25519MLKEM768,
        kx_group::SECP256R1MLKEM768,
        P384_MLKEM1024,
        kx_group::MLKEM1024,
        kx_group::X25519,
        kx_group::SECP256R1,
        kx_group::SECP384R1,
        P521,
    ];
    provider
}

pub(crate) fn provider(preferences: Option<&[String]>) -> Result<CryptoProvider, &'static str> {
    let mut provider = default_provider();
    if let Some(names) = preferences.filter(|names| !names.is_empty()) {
        provider.kx_groups = names
            .iter()
            .map(|name| named_group(name))
            .collect::<Result<_, _>>()?;
    }
    Ok(provider)
}

fn named_group(name: &str) -> Result<&'static dyn SupportedKxGroup, &'static str> {
    match name {
        "CurveP256" => Ok(kx_group::SECP256R1),
        "CurveP384" => Ok(kx_group::SECP384R1),
        "CurveP521" => Ok(P521),
        "SecP256r1MLKEM768" => Ok(kx_group::SECP256R1MLKEM768),
        "SecP384r1MLKEM1024" => Ok(P384_MLKEM1024),
        "X25519" => Ok(kx_group::X25519),
        "X25519MLKEM768" => Ok(kx_group::X25519MLKEM768),
        "MLKEM1024" => Ok(kx_group::MLKEM1024),
        _ => Err("unknown TLS key exchange preference"),
    }
}

pub(crate) fn protocol_versions(
    minimum: Option<&str>,
    maximum: Option<&str>,
) -> Result<Vec<&'static SupportedProtocolVersion>, &'static str> {
    fn version(value: &str) -> Result<ProtocolVersion, &'static str> {
        match value {
            "tls12" => Ok(ProtocolVersion::TLSv1_2),
            "tls13" => Ok(ProtocolVersion::TLSv1_3),
            _ => Err("unsupported TLS protocol version; supported values are tls12 and tls13"),
        }
    }
    let minimum = version(minimum.unwrap_or("tls12"))?;
    let maximum = version(maximum.unwrap_or("tls13"))?;
    match (minimum, maximum) {
        (ProtocolVersion::TLSv1_2, ProtocolVersion::TLSv1_3) => {
            Ok(vec![&rustls::version::TLS13, &rustls::version::TLS12])
        }
        (ProtocolVersion::TLSv1_2, ProtocolVersion::TLSv1_2) => Ok(vec![&rustls::version::TLS12]),
        (ProtocolVersion::TLSv1_3, ProtocolVersion::TLSv1_3) => Ok(vec![&rustls::version::TLS13]),
        _ => Err("TLS minimum version exceeds maximum version"),
    }
}

fn invalid_share() -> Error {
    PeerMisbehaved::InvalidKeyShare.into()
}

/// IANA 4589: P-384 uncompressed point (97) || ML-KEM-1024 (1568).
/// The shared secret is ECDH (48) || ML-KEM (32), as specified in
/// draft-ietf-tls-ecdhe-mlkem. Both component operations remain in rustls/AWS-LC.
#[derive(Debug)]
struct P384MlKem1024;

impl SupportedKxGroup for P384MlKem1024 {
    fn start(&self) -> Result<Box<dyn ActiveKeyExchange>, Error> {
        let classical = kx_group::SECP384R1.start()?;
        let kem = kx_group::MLKEM1024.start()?;
        if classical.pub_key().len() != 97 || kem.pub_key().len() != 1568 {
            return Err(Error::General(
                "invalid generated P384MLKEM1024 share".into(),
            ));
        }
        let public = [classical.pub_key(), kem.pub_key()].concat();
        Ok(Box::new(P384MlKem1024Active {
            classical,
            kem,
            public,
        }))
    }

    fn start_and_complete(&self, peer: &[u8]) -> Result<CompletedKeyExchange, Error> {
        let (classical, kem) = split_p384_hybrid(peer)?;
        let classical = kx_group::SECP384R1.start_and_complete(classical)?;
        let kem = kx_group::MLKEM1024.start_and_complete(kem)?;
        if classical.pub_key.len() != 97 || kem.pub_key.len() != 1568 {
            return Err(Error::General(
                "invalid generated P384MLKEM1024 response".into(),
            ));
        }
        Ok(CompletedKeyExchange {
            group: self.name(),
            pub_key: [classical.pub_key.as_slice(), kem.pub_key.as_slice()].concat(),
            secret: join_p384_secret(classical.secret, kem.secret)?,
        })
    }

    fn name(&self) -> NamedGroup {
        P384_MLKEM1024_NAME
    }
    fn ffdhe_group(&self) -> Option<FfdheGroup<'static>> {
        None
    }
    fn usable_for_version(&self, version: ProtocolVersion) -> bool {
        version == ProtocolVersion::TLSv1_3
    }
}

fn split_p384_hybrid(peer: &[u8]) -> Result<(&[u8], &[u8]), Error> {
    if peer.len() != 1665 || peer.first() != Some(&4) {
        return Err(invalid_share());
    }
    Ok(peer.split_at(97))
}

fn join_p384_secret(classical: SharedSecret, kem: SharedSecret) -> Result<SharedSecret, Error> {
    if classical.secret_bytes().len() != 48 || kem.secret_bytes().len() != 32 {
        return Err(Error::General(
            "invalid P384MLKEM1024 shared secret length".into(),
        ));
    }
    // Ownership goes directly into rustls::SharedSecret, which zeroizes on Drop.
    Ok(SharedSecret::from(
        [classical.secret_bytes(), kem.secret_bytes()].concat(),
    ))
}

struct P384MlKem1024Active {
    classical: Box<dyn ActiveKeyExchange>,
    kem: Box<dyn ActiveKeyExchange>,
    public: Vec<u8>,
}

impl ActiveKeyExchange for P384MlKem1024Active {
    fn complete(self: Box<Self>, peer: &[u8]) -> Result<SharedSecret, Error> {
        let (classical, kem) = split_p384_hybrid(peer)?;
        join_p384_secret(self.classical.complete(classical)?, self.kem.complete(kem)?)
    }
    fn pub_key(&self) -> &[u8] {
        &self.public
    }
    fn group(&self) -> NamedGroup {
        P384_MLKEM1024_NAME
    }
    fn ffdhe_group(&self) -> Option<FfdheGroup<'static>> {
        None
    }
}

#[derive(Debug)]
struct P521Group;

impl SupportedKxGroup for P521Group {
    fn start(&self) -> Result<Box<dyn ActiveKeyExchange>, Error> {
        let private =
            agreement::EphemeralPrivateKey::generate(&agreement::ECDH_P521, &SystemRandom::new())
                .map_err(|_| Error::General("P521 ephemeral key generation failed".into()))?;
        let public = private
            .compute_public_key()
            .map_err(|_| Error::General("P521 public key generation failed".into()))?;
        if public.as_ref().len() != 133 || public.as_ref().first() != Some(&4) {
            return Err(Error::General("invalid generated P521 point".into()));
        }
        Ok(Box::new(P521Active { private, public }))
    }
    fn name(&self) -> NamedGroup {
        NamedGroup::secp521r1
    }
    fn ffdhe_group(&self) -> Option<FfdheGroup<'static>> {
        None
    }
}

struct P521Active {
    private: agreement::EphemeralPrivateKey,
    public: agreement::PublicKey,
}

impl ActiveKeyExchange for P521Active {
    fn complete(self: Box<Self>, peer: &[u8]) -> Result<SharedSecret, Error> {
        if peer.len() != 133 || peer.first() != Some(&4) {
            return Err(invalid_share());
        }
        // Enforce TLS's uncompressed encoding before the SDK's real on-curve
        // and subgroup validation. The consumed private key cannot be reused.
        let peer = agreement::UnparsedPublicKey::new(&agreement::ECDH_P521, peer);
        agreement::agree_ephemeral(self.private, peer, invalid_share(), |secret| {
            Ok(SharedSecret::from(secret))
        })
    }
    fn pub_key(&self) -> &[u8] {
        self.public.as_ref()
    }
    fn group(&self) -> NamedGroup {
        NamedGroup::secp521r1
    }
    fn ffdhe_group(&self) -> Option<FfdheGroup<'static>> {
        None
    }
}

#[cfg(test)]
#[path = "tls_key_exchange_tests.rs"]
mod tests;
