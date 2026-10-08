//! OpenSSH encoding uses ssh-key; private cryptographic operations use the
//! server's existing OpenSSL/AWS-LC provider. No shell or key file is used.
use super::*;
use openssl::{
    bn::{BigNum, BigNumContext},
    ec::{EcGroup, EcKey, EcPoint, PointConversionForm},
    ecdsa::EcdsaSig,
    hash::MessageDigest,
    nid::Nid,
    pkey::{Id, PKey, Private},
    rsa::Rsa,
    sign::Signer,
};
use ssh_key::{Algorithm, EcdsaCurve, HashAlg, Mpint, PublicKey, Signature};
use zeroize::Zeroize;

#[derive(Clone, Serialize, Deserialize)]
#[serde(transparent)]
pub(super) struct PrivateMaterial(String);
impl Drop for PrivateMaterial {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}
fn failure() -> EngineError {
    error(503, "SSH cryptographic operation failed")
}
fn invalid() -> EngineError {
    bad("invalid SSH private key")
}

pub(super) fn deadline() -> Result<()> {
    if crate::request_deadline::current().is_some_and(|end| std::time::Instant::now() >= end) {
        return Err(error(503, "SSH original request deadline expired"));
    }
    Ok(())
}
fn curve_group(curve: EcdsaCurve) -> Result<EcGroup> {
    let nid = match curve {
        EcdsaCurve::NistP256 => Nid::X9_62_PRIME256V1,
        EcdsaCurve::NistP384 => Nid::SECP384R1,
        EcdsaCurve::NistP521 => Nid::SECP521R1,
    };
    EcGroup::from_curve_name(nid).map_err(|_| failure())
}
fn ec_curve(key: &EcKey<Private>) -> Result<EcdsaCurve> {
    match key.group().curve_name() {
        Some(Nid::X9_62_PRIME256V1) => Ok(EcdsaCurve::NistP256),
        Some(Nid::SECP384R1) => Ok(EcdsaCurve::NistP384),
        Some(Nid::SECP521R1) => Ok(EcdsaCurve::NistP521),
        _ => Err(bad("unsupported SSH elliptic curve")),
    }
}
fn canonical(key: PKey<Private>) -> Result<PrivateMaterial> {
    public(&key)?;
    let bytes = zeroize::Zeroizing::new(key.private_key_to_pem_pkcs8().map_err(|_| failure())?);
    if bytes.len() > 16384 {
        return Err(bad("SSH private key exceeds bound"));
    }
    let text = String::from_utf8(bytes.to_vec()).map_err(|_| failure())?;
    let material = PrivateMaterial(text);
    material.validate()?;
    Ok(material)
}
pub(super) fn generate(kind: &str, bits: u32) -> Result<PrivateMaterial> {
    deadline()?;
    let key = match kind {
        "rsa" | "ssh-rsa" => {
            let bits = if bits == 0 { 4096 } else { bits };
            if !matches!(bits, 2048 | 3072 | 4096 | 8192) {
                return Err(bad("invalid SSH RSA key bits"));
            }
            PKey::from_rsa(Rsa::generate(bits).map_err(|_| failure())?).map_err(|_| failure())?
        }
        "ec" | "ecdsa" | "ecdsa-sha2-nistp256" | "ecdsa-sha2-nistp384" | "ecdsa-sha2-nistp521" => {
            let named = match kind {
                "ecdsa-sha2-nistp256" => Some(256),
                "ecdsa-sha2-nistp384" => Some(384),
                "ecdsa-sha2-nistp521" => Some(521),
                _ => None,
            };
            let bits = named.unwrap_or(if bits == 0 { 256 } else { bits });
            let curve = match bits {
                256 => EcdsaCurve::NistP256,
                384 => EcdsaCurve::NistP384,
                521 => EcdsaCurve::NistP521,
                _ => return Err(bad("invalid SSH EC key bits")),
            };
            let group = curve_group(curve)?;
            PKey::from_ec_key(EcKey::generate(&group).map_err(|_| failure())?)
                .map_err(|_| failure())?
        }
        "ed25519" | "ssh-ed25519" => PKey::generate_ed25519().map_err(|_| failure())?,
        _ => return Err(bad("invalid SSH key type")),
    };
    deadline()?;
    canonical(key)
}
fn imported_openssh(text: &str) -> Result<PKey<Private>> {
    use ssh_key::private::{EcdsaKeypair, KeypairData};
    let key = ssh_key::PrivateKey::from_openssh(text.as_bytes()).map_err(|_| invalid())?;
    if key.is_encrypted() {
        return Err(bad("encrypted SSH private keys are not supported"));
    }
    let result = match key.key_data() {
        KeypairData::Rsa(pair) => {
            let bn = |m: &Mpint| -> Result<BigNum> {
                BigNum::from_slice(m.as_positive_bytes().ok_or_else(invalid)?)
                    .map_err(|_| invalid())
            };
            let n = bn(&pair.public.n)?;
            let e = bn(&pair.public.e)?;
            let d = bn(&pair.private.d)?;
            let p = bn(&pair.private.p)?;
            let q = bn(&pair.private.q)?;
            let iqmp = bn(&pair.private.iqmp)?;
            let mut pm1 = p.to_owned().map_err(|_| invalid())?;
            let mut qm1 = q.to_owned().map_err(|_| invalid())?;
            pm1.sub_word(1).map_err(|_| invalid())?;
            qm1.sub_word(1).map_err(|_| invalid())?;
            let mut ctx = BigNumContext::new().map_err(|_| failure())?;
            let mut dp = BigNum::new().map_err(|_| failure())?;
            let mut dq = BigNum::new().map_err(|_| failure())?;
            dp.nnmod(&d, &pm1, &mut ctx).map_err(|_| invalid())?;
            dq.nnmod(&d, &qm1, &mut ctx).map_err(|_| invalid())?;
            let rsa =
                Rsa::from_private_components(n, e, d, p, q, dp, dq, iqmp).map_err(|_| invalid())?;
            if !rsa.check_key().map_err(|_| invalid())? {
                return Err(invalid());
            }
            PKey::from_rsa(rsa).map_err(|_| invalid())?
        }
        KeypairData::Ed25519(pair) => {
            PKey::private_key_from_raw_bytes(pair.private.as_ref(), Id::ED25519)
                .map_err(|_| invalid())?
        }
        KeypairData::Ecdsa(pair) => {
            let (curve, scalar, point): (EcdsaCurve, &[u8], &[u8]) = match pair {
                EcdsaKeypair::NistP256 { private, public } => {
                    (EcdsaCurve::NistP256, private.as_slice(), public.as_bytes())
                }
                EcdsaKeypair::NistP384 { private, public } => {
                    (EcdsaCurve::NistP384, private.as_slice(), public.as_bytes())
                }
                EcdsaKeypair::NistP521 { private, public } => {
                    (EcdsaCurve::NistP521, private.as_slice(), public.as_bytes())
                }
            };
            let group = curve_group(curve)?;
            let mut ctx = BigNumContext::new().map_err(|_| failure())?;
            let point = EcPoint::from_bytes(&group, point, &mut ctx).map_err(|_| invalid())?;
            let scalar = BigNum::from_slice(scalar).map_err(|_| invalid())?;
            let ec =
                EcKey::from_private_components(&group, &scalar, &point).map_err(|_| invalid())?;
            ec.check_key().map_err(|_| invalid())?;
            PKey::from_ec_key(ec).map_err(|_| invalid())?
        }
        _ => return Err(bad("unsupported SSH private key type")),
    };
    if public(&result)?.key_data() != key.public_key().key_data() {
        return Err(invalid());
    }
    Ok(result)
}
pub(super) fn import(text: &str) -> Result<PrivateMaterial> {
    if text.is_empty() || text.len() > 16384 {
        return Err(invalid());
    }
    deadline()?;
    let key = if text.contains("BEGIN OPENSSH PRIVATE KEY") {
        imported_openssh(text)?
    } else {
        PKey::private_key_from_pem(text.as_bytes()).map_err(|_| invalid())?
    };
    deadline()?;
    canonical(key)
}
impl PrivateMaterial {
    pub(super) fn key(&self) -> Result<PKey<Private>> {
        PKey::private_key_from_pem(self.0.as_bytes()).map_err(|_| invalid())
    }
    pub(super) fn public(&self) -> Result<PublicKey> {
        public(&self.key()?)
    }
    pub(super) fn pem(&self) -> &str {
        &self.0
    }
    pub(super) fn issued_pem(&self) -> Result<zeroize::Zeroizing<String>> {
        let key = self.key()?;
        let bytes = zeroize::Zeroizing::new(match key.id() {
            Id::RSA => key
                .rsa()
                .map_err(|_| invalid())?
                .private_key_to_pem()
                .map_err(|_| failure())?,
            Id::EC => key
                .ec_key()
                .map_err(|_| invalid())?
                .private_key_to_pem()
                .map_err(|_| failure())?,
            Id::ED25519 => key.private_key_to_pem_pkcs8().map_err(|_| failure())?,
            _ => return Err(invalid()),
        });
        String::from_utf8(bytes.to_vec())
            .map(zeroize::Zeroizing::new)
            .map_err(|_| failure())
    }
    pub(super) fn validate(&self) -> Result<()> {
        if self.0.is_empty() || self.0.len() > 16384 {
            return Err(invalid());
        }
        let key = self.key()?;
        match key.id() {
            Id::RSA => {
                if !key
                    .rsa()
                    .map_err(|_| invalid())?
                    .check_key()
                    .map_err(|_| invalid())?
                {
                    return Err(invalid());
                }
            }
            Id::EC => {
                key.ec_key()
                    .map_err(|_| invalid())?
                    .check_key()
                    .map_err(|_| invalid())?;
            }
            Id::ED25519 => {}
            _ => return Err(invalid()),
        }
        public(&key)?;
        Ok(())
    }
}
fn public(key: &PKey<Private>) -> Result<PublicKey> {
    use ssh_key::public::{EcdsaPublicKey, Ed25519PublicKey, KeyData, RsaPublicKey};
    let data = match key.id() {
        Id::RSA => {
            let rsa = key.rsa().map_err(|_| invalid())?;
            if rsa.n().num_bits() < 2048 || rsa.n().num_bits() > 8192 {
                return Err(bad("SSH RSA key size outside bounds"));
            }
            KeyData::Rsa(RsaPublicKey {
                n: Mpint::from_positive_bytes(&rsa.n().to_vec()).map_err(|_| invalid())?,
                e: Mpint::from_positive_bytes(&rsa.e().to_vec()).map_err(|_| invalid())?,
            })
        }
        Id::EC => {
            let ec = key.ec_key().map_err(|_| invalid())?;
            ec_curve(&ec)?;
            let mut ctx = BigNumContext::new().map_err(|_| failure())?;
            let point = ec
                .public_key()
                .to_bytes(ec.group(), PointConversionForm::UNCOMPRESSED, &mut ctx)
                .map_err(|_| invalid())?;
            KeyData::Ecdsa(EcdsaPublicKey::from_sec1_bytes(&point).map_err(|_| invalid())?)
        }
        Id::ED25519 => {
            let bytes = key.raw_public_key().map_err(|_| invalid())?;
            KeyData::Ed25519(Ed25519PublicKey::try_from(bytes.as_slice()).map_err(|_| invalid())?)
        }
        _ => return Err(bad("unsupported SSH key type")),
    };
    Ok(PublicKey::new(data, ""))
}

pub(super) struct CaSigner {
    key: PKey<Private>,
    public: ssh_key::public::KeyData,
    algorithm: Algorithm,
}
impl CaSigner {
    pub(super) fn new(material: &PrivateMaterial, requested: &str) -> Result<Self> {
        let key = material.key()?;
        let public = public(&key)?.key_data().clone();
        if key.id() != Id::RSA && !matches!(requested, "" | "default") {
            return Err(error(
                500,
                "SSH signing algorithm does not match issuer key",
            ));
        }
        let algorithm = match key.id() {
            Id::RSA => Algorithm::Rsa {
                hash: Some(match requested {
                    "" | "default" | "rsa-sha2-256" => HashAlg::Sha256,
                    "rsa-sha2-512" => HashAlg::Sha512,
                    _ => return Err(bad("unsupported SSH RSA signing algorithm")),
                }),
            },
            Id::EC => Algorithm::Ecdsa {
                curve: ec_curve(&key.ec_key().map_err(|_| invalid())?)?,
            },
            Id::ED25519 => Algorithm::Ed25519,
            _ => return Err(invalid()),
        };
        Ok(Self {
            key,
            public,
            algorithm,
        })
    }
}
impl ssh_key::SigningKey for CaSigner {
    fn public_key(&self) -> ssh_key::public::KeyData {
        self.public.clone()
    }
}
impl signature::Signer<Signature> for CaSigner {
    fn try_sign(&self, message: &[u8]) -> std::result::Result<Signature, signature::Error> {
        let fail = || signature::Error::new();
        let digest = match self.algorithm {
            Algorithm::Rsa {
                hash: Some(HashAlg::Sha256),
            } => Some(MessageDigest::sha256()),
            Algorithm::Rsa {
                hash: Some(HashAlg::Sha512),
            } => Some(MessageDigest::sha512()),
            Algorithm::Ecdsa {
                curve: EcdsaCurve::NistP256,
            } => Some(MessageDigest::sha256()),
            Algorithm::Ecdsa {
                curve: EcdsaCurve::NistP384,
            } => Some(MessageDigest::sha384()),
            Algorithm::Ecdsa {
                curve: EcdsaCurve::NistP521,
            } => Some(MessageDigest::sha512()),
            Algorithm::Ed25519 => None,
            _ => return Err(fail()),
        };
        let mut signer = match digest {
            Some(digest) => Signer::new(digest, &self.key).map_err(|_| fail())?,
            None => Signer::new_without_digest(&self.key).map_err(|_| fail())?,
        };
        let mut bytes = signer.sign_oneshot_to_vec(message).map_err(|_| fail())?;
        if matches!(self.algorithm, Algorithm::Ecdsa { .. }) {
            let sig = EcdsaSig::from_der(&bytes).map_err(|_| fail())?;
            bytes.clear();
            for bn in [sig.r(), sig.s()] {
                let mpint = Mpint::from_positive_bytes(&bn.to_vec()).map_err(|_| fail())?;
                let len = u32::try_from(mpint.as_bytes().len()).map_err(|_| fail())?;
                bytes.extend_from_slice(&len.to_be_bytes());
                bytes.extend_from_slice(mpint.as_bytes());
            }
        }
        Signature::new(self.algorithm.clone(), bytes).map_err(|_| fail())
    }
}
