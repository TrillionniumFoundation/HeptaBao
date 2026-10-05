//! Local PKI key ownership and API encodings. Cryptographic operations belong to
//! the pinned maintained providers; a durable ML-DSA seed is not PKCS8.
use super::*;
use ml_dsa::{
    Keypair as _, MlDsa44, MlDsa65, MlDsa87, MlDsaParams, Seed, SigningKey, VerifyingKey,
    pkcs8::{
        DecodePrivateKey, DecodePublicKey, EncodePrivateKey, EncodePublicKey, der::AnyRef,
        spki::AssociatedAlgorithmIdentifier,
    },
};
use openssl::{
    bn::BigNum,
    ec::{EcGroup, EcKey},
    hash::MessageDigest,
    nid::Nid,
    pkey::{Id, PKey, Private, Public},
    rsa::{Padding, Rsa},
    sign::{RsaPssSaltlen, Signer, Verifier},
};
use x509_parser::prelude::{FromDer, SubjectPublicKeyInfo, X509Certificate};

const MAX_PRIVATE_DER: usize = 4096;
const MAX_PUBLIC_DER: usize = 8192;

#[derive(Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub(super) enum LocalKeyKind {
    Ed25519,
    Rsa2048,
    Rsa3072,
    Rsa4096,
    Ec224,
    Ec256,
    Ec384,
    Ec521,
    Mldsa44,
    Mldsa65,
    Mldsa87,
}

impl LocalKeyKind {
    pub(super) fn from_body(body: &Value) -> Result<Self> {
        let key_type = match body.get("key_type") {
            None => "rsa",
            Some(value) => value.as_str().ok_or_else(|| bad("invalid PKI key type"))?,
        };
        let bits = optional_u64(body, "key_bits")?.unwrap_or(0);
        match (key_type, bits) {
            ("rsa", 0 | 2048) => Ok(Self::Rsa2048),
            ("rsa", 3072) => Ok(Self::Rsa3072),
            ("rsa", 4096) => Ok(Self::Rsa4096),
            ("ec", 224) => Ok(Self::Ec224),
            ("ec", 0 | 256) => Ok(Self::Ec256),
            ("ec", 384) => Ok(Self::Ec384),
            ("ec", 521) => Ok(Self::Ec521),
            ("ed25519", _) => Ok(Self::Ed25519),
            ("mldsa", 0 | 44) => Ok(Self::Mldsa44),
            ("mldsa", 65) => Ok(Self::Mldsa65),
            ("mldsa", 87) => Ok(Self::Mldsa87),
            _ => Err(bad("unsupported PKI key type or size")),
        }
    }

    pub(super) fn key_type(self) -> &'static str {
        match self {
            Self::Ed25519 => "ed25519",
            Self::Rsa2048 | Self::Rsa3072 | Self::Rsa4096 => "rsa",
            Self::Ec224 | Self::Ec256 | Self::Ec384 | Self::Ec521 => "ec",
            Self::Mldsa44 | Self::Mldsa65 | Self::Mldsa87 => "mldsa",
        }
    }

    pub(super) fn bits(self) -> u32 {
        match self {
            Self::Ed25519 => 0,
            Self::Rsa2048 => 2048,
            Self::Rsa3072 => 3072,
            Self::Rsa4096 => 4096,
            Self::Ec224 => 224,
            Self::Ec256 => 256,
            Self::Ec384 => 384,
            Self::Ec521 => 521,
            Self::Mldsa44 => 44,
            Self::Mldsa65 => 65,
            Self::Mldsa87 => 87,
        }
    }

    fn curve(self) -> Option<Nid> {
        match self {
            Self::Ec224 => Some(Nid::SECP224R1),
            Self::Ec256 => Some(Nid::X9_62_PRIME256V1),
            Self::Ec384 => Some(Nid::SECP384R1),
            Self::Ec521 => Some(Nid::SECP521R1),
            _ => None,
        }
    }

    fn is_mldsa(self) -> bool {
        matches!(self, Self::Mldsa44 | Self::Mldsa65 | Self::Mldsa87)
    }

    fn digest(self) -> MessageDigest {
        match self {
            Self::Ec384 => MessageDigest::sha384(),
            Self::Ec521 => MessageDigest::sha512(),
            _ => MessageDigest::sha256(),
        }
    }

    pub(super) fn signature_algorithm(self) -> Vec<u8> {
        match self {
            Self::Ed25519 => algorithm_ed25519(),
            Self::Rsa2048 | Self::Rsa3072 | Self::Rsa4096 => seq(&[
                oid(&[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b]),
                der(0x05, &[]),
            ]),
            Self::Ec224 | Self::Ec256 | Self::Ec384 | Self::Ec521 => {
                let suffix = match self {
                    Self::Ec384 => 3,
                    Self::Ec521 => 4,
                    _ => 2,
                };
                seq(&[oid(&[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, suffix])])
            }
            Self::Mldsa44 | Self::Mldsa65 | Self::Mldsa87 => {
                let suffix = match self {
                    Self::Mldsa44 => 17,
                    Self::Mldsa65 => 18,
                    _ => 19,
                };
                seq(&[oid(&[0x60, 0x86, 0x48, 1, 0x65, 3, 4, 3, suffix])])
            }
        }
    }
}

/// An explicit encoding marker prevents a seed from being mistaken for DER.
#[derive(Clone, Serialize, Deserialize)]
#[serde(tag = "encoding", rename_all = "snake_case", deny_unknown_fields)]
pub(super) enum LocalPrivateMaterial {
    Pkcs8 { kind: LocalKeyKind, der: Vec<u8> },
    MldsaSeed32 { kind: LocalKeyKind, seed: [u8; 32] },
}

impl Drop for LocalPrivateMaterial {
    fn drop(&mut self) {
        match self {
            Self::Pkcs8 { der, .. } => der.zeroize(),
            Self::MldsaSeed32 { seed, .. } => seed.zeroize(),
        }
    }
}

#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(untagged)]
pub(super) enum LocalPublicKey {
    // Existing external Ed leaf projections retain their exact array encoding.
    Ed25519([u8; 32]),
    Typed(LocalPublicDer),
}

#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(super) struct LocalPublicDer {
    kind: LocalKeyKind,
    spki_der: Vec<u8>,
}

fn invalid_key() -> EngineError {
    error(503, "invalid local PKI key material")
}

fn crypto_failure<T>(_: T) -> EngineError {
    error(503, "local PKI cryptographic operation failed")
}

trait MldsaParameter: MlDsaParams + AssociatedAlgorithmIdentifier<Params = AnyRef<'static>> {}
impl<P> MldsaParameter for P where
    P: MlDsaParams + AssociatedAlgorithmIdentifier<Params = AnyRef<'static>>
{
}

fn mldsa_key<P: MldsaParameter>(seed: &[u8]) -> Result<SigningKey<P>> {
    let seed = Zeroizing::new(Seed::try_from(seed).map_err(|_| invalid_key())?);
    Ok(SigningKey::<P>::from_seed(&seed))
}

fn mldsa_public<P: MldsaParameter>(seed: &[u8]) -> Result<Vec<u8>> {
    Ok(mldsa_key::<P>(seed)?
        .verifying_key()
        .to_public_key_der()
        .map_err(crypto_failure)?
        .as_bytes()
        .to_vec())
}

fn mldsa_sign<P: MldsaParameter>(seed: &[u8], input: &[u8]) -> Result<Vec<u8>> {
    Ok(mldsa_key::<P>(seed)?
        .expanded_key()
        .sign_randomized(input, b"", &mut getrandom::SysRng)
        .map_err(crypto_failure)?
        .encode()
        .to_vec())
}

fn mldsa_verify<P: MldsaParameter>(spki: &[u8], input: &[u8], bytes: &[u8]) -> Result<bool> {
    let public = VerifyingKey::<P>::from_public_key_der(spki).map_err(|_| invalid_key())?;
    if public
        .to_public_key_der()
        .map_err(crypto_failure)?
        .as_bytes()
        != spki
    {
        return Err(invalid_key());
    }
    let Ok(signature) = ml_dsa::Signature::<P>::try_from(bytes) else {
        return Ok(false);
    };
    Ok(public.verify_with_context(input, b"", &signature))
}

fn mldsa_validate<P: MldsaParameter>(spki: &[u8]) -> Result<()> {
    let public = VerifyingKey::<P>::from_public_key_der(spki).map_err(|_| invalid_key())?;
    if public
        .to_public_key_der()
        .map_err(crypto_failure)?
        .as_bytes()
        != spki
    {
        return Err(invalid_key());
    }
    Ok(())
}

fn mldsa_pkcs8<P: MldsaParameter>(seed: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    // The maintained provider encodes standard PKCS8 seed form. Its internal
    // seed_der Vec cleanup is not proved by wrapping our owned result.
    Ok(Zeroizing::new(
        mldsa_key::<P>(seed)?
            .to_pkcs8_der()
            .map_err(crypto_failure)?
            .as_bytes()
            .to_vec(),
    ))
}

fn mldsa_import_pkcs8<P: MldsaParameter>(der: &[u8]) -> Result<LocalPrivateMaterial> {
    let key = SigningKey::<P>::from_pkcs8_der(der).map_err(|_| invalid_key())?;
    if key.to_pkcs8_der().map_err(crypto_failure)?.as_bytes() != der {
        return Err(invalid_key());
    }
    let seed: [u8; 32] = key
        .as_seed()
        .as_slice()
        .try_into()
        .map_err(|_| invalid_key())?;
    let kind = match P::ALGORITHM_IDENTIFIER.oid.to_string().as_str() {
        "2.16.840.1.101.3.4.3.17" => LocalKeyKind::Mldsa44,
        "2.16.840.1.101.3.4.3.18" => LocalKeyKind::Mldsa65,
        "2.16.840.1.101.3.4.3.19" => LocalKeyKind::Mldsa87,
        _ => return Err(invalid_key()),
    };
    Ok(LocalPrivateMaterial::MldsaSeed32 { kind, seed })
}

macro_rules! mldsa_dispatch {
    ($kind:expr, $function:ident, $($argument:expr),+) => {
        match $kind {
            LocalKeyKind::Mldsa44 => $function::<MlDsa44>($($argument),+),
            LocalKeyKind::Mldsa65 => $function::<MlDsa65>($($argument),+),
            LocalKeyKind::Mldsa87 => $function::<MlDsa87>($($argument),+),
            _ => Err(invalid_key()),
        }
    };
}

fn public_matches(kind: LocalKeyKind, key: &PKey<Public>) -> Result<bool> {
    if let Some(curve) = kind.curve() {
        if key.id() != Id::EC {
            return Ok(false);
        }
        let ec = key.ec_key().map_err(|_| invalid_key())?;
        ec.check_key().map_err(|_| invalid_key())?;
        return Ok(ec.group().curve_name() == Some(curve));
    }
    if kind.key_type() != "rsa" || key.id() != Id::RSA || key.bits() != kind.bits() {
        return Ok(false);
    }
    let rsa = key.rsa().map_err(|_| invalid_key())?;
    let minimum = BigNum::from_u32(3).map_err(crypto_failure)?;
    Ok(!rsa.n().is_negative()
        && rsa.n().is_odd()
        && !rsa.e().is_negative()
        && rsa.e().is_odd()
        && rsa.e().ucmp(&minimum) != std::cmp::Ordering::Less
        && rsa.e().ucmp(rsa.n()) == std::cmp::Ordering::Less)
}

impl LocalPrivateMaterial {
    pub(super) fn kind(&self) -> LocalKeyKind {
        match self {
            Self::Pkcs8 { kind, .. } | Self::MldsaSeed32 { kind, .. } => *kind,
        }
    }

    pub(super) fn generate(kind: LocalKeyKind) -> Result<Self> {
        if kind.is_mldsa() {
            return Ok(Self::MldsaSeed32 {
                kind,
                seed: crate::crypto::random::<32>().map_err(crypto_failure)?,
            });
        }
        let der = if kind == LocalKeyKind::Ed25519 {
            Zeroizing::new(
                Ed25519KeyPair::generate_pkcs8(&SystemRandom::new())
                    .map_err(crypto_failure)?
                    .as_ref()
                    .to_vec(),
            )
        } else {
            let key = if let Some(curve) = kind.curve() {
                let group = EcGroup::from_curve_name(curve).map_err(crypto_failure)?;
                PKey::from_ec_key(EcKey::generate(&group).map_err(crypto_failure)?)
            } else {
                PKey::from_rsa(Rsa::generate(kind.bits()).map_err(crypto_failure)?)
            }
            .map_err(crypto_failure)?;
            Zeroizing::new(key.private_key_to_pkcs8().map_err(crypto_failure)?)
        };
        let material = Self::Pkcs8 {
            kind,
            der: der.to_vec(),
        };
        material.public()?;
        Ok(material)
    }

    pub(super) fn import_der(label: &str, bytes: &[u8]) -> Result<Self> {
        if bytes.is_empty() || bytes.len() > 64 * 1024 {
            return Err(bad("PKI imported private key exceeds bounds"));
        }
        let document = ml_dsa::pkcs8::SecretDocument::try_from(bytes)
            .map_err(|_| bad("invalid bounded PKI private key DER"))?;
        let bytes = document.as_bytes();
        if label == "PRIVATE KEY" {
            for kind in [
                LocalKeyKind::Mldsa44,
                LocalKeyKind::Mldsa65,
                LocalKeyKind::Mldsa87,
            ] {
                if let Ok(material) = mldsa_dispatch!(kind, mldsa_import_pkcs8, bytes) {
                    material.public()?;
                    return Ok(material);
                }
            }
        }
        let key = match label {
            "PRIVATE KEY" => PKey::private_key_from_pkcs8(bytes),
            "RSA PRIVATE KEY" => Rsa::private_key_from_der(bytes).and_then(PKey::from_rsa),
            "EC PRIVATE KEY" => EcKey::private_key_from_der(bytes).and_then(PKey::from_ec_key),
            _ => return Err(bad("unsupported PKI private key PEM label")),
        }
        .map_err(|_| bad("invalid unencrypted PKI private key"))?;
        let public = LocalPublicKey::from_spki(&key.public_key_to_der().map_err(crypto_failure)?)?;
        let kind = public.kind();
        let canonical = if kind == LocalKeyKind::Ed25519 {
            let seed = Zeroizing::new(key.raw_private_key().map_err(crypto_failure)?);
            let public_bytes = key.raw_public_key().map_err(crypto_failure)?;
            Ed25519KeyPair::from_seed_and_public_key(seed.as_slice(), &public_bytes)
                .map_err(|_| bad("invalid imported Ed25519 key pair"))?;
            // Store the same RFC 5958 v2 grammar used by the owned ring path,
            // including its actual derived public key. Temporary seed-bearing
            // DER allocations retain explicit erasing owners.
            let seed_value = Zeroizing::new(octet_string(seed.as_slice()));
            let private_field = Zeroizing::new(octet_string(seed_value.as_slice()));
            let mut content = Zeroizing::new(Vec::new());
            content.extend_from_slice(&integer(&[1]));
            content.extend_from_slice(&algorithm_ed25519());
            content.extend_from_slice(private_field.as_slice());
            let mut bit_value = vec![0];
            bit_value.extend_from_slice(&public_bytes);
            content.extend_from_slice(&context_primitive(1, &bit_value));
            Zeroizing::new(der(0x30, content.as_slice()))
        } else {
            Zeroizing::new(key.private_key_to_pkcs8().map_err(crypto_failure)?)
        };
        let material = Self::Pkcs8 {
            kind,
            der: canonical.to_vec(),
        };
        let actual = material.public()?;
        if actual != public
            || !actual.verify(
                b"heptabao-owned-PKI-key-import",
                &material.sign(b"heptabao-owned-PKI-key-import")?,
            )?
        {
            return Err(bad("imported PKI key ownership verification failed"));
        }
        Ok(material)
    }

    fn maintained_private(&self) -> Result<PKey<Private>> {
        let Self::Pkcs8 { kind, der } = self else {
            return Err(invalid_key());
        };
        if der.is_empty() || der.len() > MAX_PRIVATE_DER || kind.is_mldsa() {
            return Err(invalid_key());
        }
        let key = PKey::private_key_from_der(der).map_err(|_| invalid_key())?;
        if *kind == LocalKeyKind::Ed25519 {
            let legacy = Ed25519KeyPair::from_pkcs8(der).map_err(|_| invalid_key())?;
            if key.id() != Id::ED25519
                || key.raw_public_key().map_err(|_| invalid_key())?.as_slice()
                    != legacy.public_key().as_ref()
            {
                return Err(invalid_key());
            }
        } else {
            let encoded = Zeroizing::new(key.private_key_to_pkcs8().map_err(crypto_failure)?);
            let public = key.public_key_to_der().map_err(crypto_failure)?;
            let public = PKey::public_key_from_der(&public).map_err(crypto_failure)?;
            if encoded.as_slice() != der || !public_matches(*kind, &public)? {
                return Err(invalid_key());
            }
            if key.id() == Id::RSA {
                if !key
                    .rsa()
                    .map_err(crypto_failure)?
                    .check_key()
                    .map_err(crypto_failure)?
                {
                    return Err(invalid_key());
                }
            } else {
                key.ec_key()
                    .map_err(crypto_failure)?
                    .check_key()
                    .map_err(crypto_failure)?;
            }
        }
        Ok(key)
    }

    pub(super) fn public(&self) -> Result<LocalPublicKey> {
        match self {
            Self::Pkcs8 {
                kind: LocalKeyKind::Ed25519,
                ..
            } => {
                let key = self.maintained_private()?;
                Ok(LocalPublicKey::Ed25519(
                    key.raw_public_key()
                        .map_err(crypto_failure)?
                        .as_slice()
                        .try_into()
                        .map_err(|_| invalid_key())?,
                ))
            }
            Self::Pkcs8 { kind, .. } => Ok(LocalPublicKey::Typed(LocalPublicDer {
                kind: *kind,
                spki_der: self
                    .maintained_private()?
                    .public_key_to_der()
                    .map_err(crypto_failure)?,
            })),
            Self::MldsaSeed32 { kind, seed } => Ok(LocalPublicKey::Typed(LocalPublicDer {
                kind: *kind,
                spki_der: mldsa_dispatch!(*kind, mldsa_public, seed)?,
            })),
        }
    }

    pub(super) fn sign(&self, input: &[u8]) -> Result<Vec<u8>> {
        match self {
            Self::Pkcs8 {
                kind: LocalKeyKind::Ed25519,
                der,
            } => {
                let pair = Ed25519KeyPair::from_pkcs8(der).map_err(|_| invalid_key())?;
                Ok(pair.sign(input).as_ref().to_vec())
            }
            Self::Pkcs8 { kind, .. } => {
                let key = self.maintained_private()?;
                let mut signer = Signer::new(kind.digest(), &key).map_err(crypto_failure)?;
                if key.id() == Id::RSA {
                    signer
                        .set_rsa_padding(Padding::PKCS1)
                        .map_err(crypto_failure)?;
                }
                signer.update(input).map_err(crypto_failure)?;
                signer.sign_to_vec().map_err(crypto_failure)
            }
            Self::MldsaSeed32 { kind, seed } => mldsa_dispatch!(*kind, mldsa_sign, seed, input),
        }
    }

    pub(super) fn sign_leaf(&self, input: &[u8], scheme: LeafSignature) -> Result<Vec<u8>> {
        let Some(digest) = scheme.digest() else {
            return self.sign(input);
        };
        let key = self.maintained_private()?;
        if (key.id() == Id::RSA) != matches!(scheme, LeafSignature::Rsa { .. }) {
            return Err(invalid_key());
        }
        let mut signer = Signer::new(digest, &key).map_err(crypto_failure)?;
        if key.id() == Id::RSA {
            signer
                .set_rsa_padding(if scheme.pss() {
                    Padding::PKCS1_PSS
                } else {
                    Padding::PKCS1
                })
                .map_err(crypto_failure)?;
            if scheme.pss() {
                signer.set_rsa_mgf1_md(digest).map_err(crypto_failure)?;
                signer
                    .set_rsa_pss_saltlen(RsaPssSaltlen::DIGEST_LENGTH)
                    .map_err(crypto_failure)?;
            }
        }
        signer.update(input).map_err(crypto_failure)?;
        signer.sign_to_vec().map_err(crypto_failure)
    }

    pub(super) fn private_der(&self) -> Result<Zeroizing<Vec<u8>>> {
        match self {
            Self::Pkcs8 { der, .. } => {
                self.public()?;
                Ok(Zeroizing::new(der.clone()))
            }
            Self::MldsaSeed32 { kind, seed } => mldsa_dispatch!(*kind, mldsa_pkcs8, seed),
        }
    }

    pub(super) fn root_export_der(
        &self,
        pkcs8: bool,
    ) -> Result<(Zeroizing<Vec<u8>>, &'static str)> {
        if self.kind().is_mldsa() {
            return Ok((self.private_der()?, "PRIVATE KEY"));
        }
        let key = self.maintained_private()?;
        let (bytes, label) = if pkcs8 || self.kind() == LocalKeyKind::Ed25519 {
            (
                key.private_key_to_pkcs8().map_err(crypto_failure)?,
                "PRIVATE KEY",
            )
        } else if self.kind().key_type() == "rsa" {
            (
                key.rsa()
                    .map_err(crypto_failure)?
                    .private_key_to_der()
                    .map_err(crypto_failure)?,
                "RSA PRIVATE KEY",
            )
        } else {
            (
                key.ec_key()
                    .map_err(crypto_failure)?
                    .private_key_to_der()
                    .map_err(crypto_failure)?,
                "EC PRIVATE KEY",
            )
        };
        Ok((Zeroizing::new(bytes), label))
    }

    pub(super) fn private_pem(
        kind: LocalKeyKind,
        bytes: &[u8],
        pkcs8: bool,
    ) -> Result<Zeroizing<String>> {
        if kind == LocalKeyKind::Ed25519 {
            return leaf_private_key_pem(bytes);
        }
        let material = if kind.is_mldsa() {
            mldsa_dispatch!(kind, mldsa_import_pkcs8, bytes)?
        } else {
            Self::Pkcs8 {
                kind,
                der: bytes.to_vec(),
            }
        };
        material.public()?;
        let (encoded, label) = material.root_export_der(pkcs8)?;
        let base64 = Zeroizing::new(BASE64.encode(encoded.as_slice()));
        let mut pem = Zeroizing::new(String::from("-----BEGIN "));
        pem.push_str(label);
        pem.push_str("-----\n");
        for chunk in base64.as_bytes().chunks(64) {
            pem.push_str(std::str::from_utf8(chunk).map_err(crypto_failure)?);
            pem.push('\n');
        }
        pem.push_str("-----END ");
        pem.push_str(label);
        pem.push_str("-----\n");
        Ok(pem)
    }
}

impl LocalPublicKey {
    /// Decode the maintained key representation from the actual CSR/certificate
    /// SPKI. Key kind is never inferred from a caller supplied label.
    pub(super) fn from_spki(bytes: &[u8]) -> Result<Self> {
        if bytes.is_empty() || bytes.len() > MAX_PUBLIC_DER {
            return Err(invalid_key());
        }
        let (rest, info) = SubjectPublicKeyInfo::from_der(bytes).map_err(crypto_failure)?;
        if !rest.is_empty() || info.subject_public_key.unused_bits != 0 {
            return Err(invalid_key());
        }
        let algorithm = info.algorithm.algorithm.to_id_string();
        let kind = match algorithm.as_str() {
            "1.3.101.112" => {
                let public = info
                    .subject_public_key
                    .data
                    .as_ref()
                    .try_into()
                    .map_err(|_| invalid_key())?;
                let value = Self::Ed25519(public);
                if value.spki()? != bytes {
                    return Err(invalid_key());
                }
                return Ok(value);
            }
            "2.16.840.1.101.3.4.3.17" => LocalKeyKind::Mldsa44,
            "2.16.840.1.101.3.4.3.18" => LocalKeyKind::Mldsa65,
            "2.16.840.1.101.3.4.3.19" => LocalKeyKind::Mldsa87,
            _ => {
                let key = PKey::public_key_from_der(bytes).map_err(crypto_failure)?;
                match key.id() {
                    Id::RSA => match key.bits() {
                        2048 => LocalKeyKind::Rsa2048,
                        3072 => LocalKeyKind::Rsa3072,
                        4096 => LocalKeyKind::Rsa4096,
                        _ => return Err(invalid_key()),
                    },
                    Id::EC => match key.ec_key().map_err(crypto_failure)?.group().curve_name() {
                        Some(Nid::SECP224R1) => LocalKeyKind::Ec224,
                        Some(Nid::X9_62_PRIME256V1) => LocalKeyKind::Ec256,
                        Some(Nid::SECP384R1) => LocalKeyKind::Ec384,
                        Some(Nid::SECP521R1) => LocalKeyKind::Ec521,
                        _ => return Err(invalid_key()),
                    },
                    _ => return Err(invalid_key()),
                }
            }
        };
        let public = Self::Typed(LocalPublicDer {
            kind,
            spki_der: bytes.to_vec(),
        });
        public.validate()?;
        if public.spki()? != bytes {
            return Err(invalid_key());
        }
        Ok(public)
    }
    pub(super) fn kind(&self) -> LocalKeyKind {
        match self {
            Self::Ed25519(_) => LocalKeyKind::Ed25519,
            Self::Typed(public) => public.kind,
        }
    }

    fn maintained_public(&self) -> Result<PKey<Public>> {
        let Self::Typed(public) = self else {
            return Err(invalid_key());
        };
        if public.spki_der.is_empty() || public.spki_der.len() > MAX_PUBLIC_DER {
            return Err(invalid_key());
        }
        let key = PKey::public_key_from_der(&public.spki_der).map_err(|_| invalid_key())?;
        if key.public_key_to_der().map_err(crypto_failure)? != public.spki_der
            || !public_matches(public.kind, &key)?
        {
            return Err(invalid_key());
        }
        Ok(key)
    }

    pub(super) fn validate(&self) -> Result<()> {
        match self {
            Self::Ed25519(_) => Ok(()),
            Self::Typed(public) if public.kind.is_mldsa() => {
                if public.spki_der.is_empty() || public.spki_der.len() > MAX_PUBLIC_DER {
                    return Err(invalid_key());
                }
                mldsa_dispatch!(public.kind, mldsa_validate, public.spki_der.as_slice())
            }
            Self::Typed(_) => self.maintained_public().map(|_| ()),
        }
    }

    pub(super) fn spki(&self) -> Result<Vec<u8>> {
        self.validate()?;
        match self {
            Self::Ed25519(public) => Ok(seq(&[algorithm_ed25519(), bit_string(public, 0)])),
            Self::Typed(public) => Ok(public.spki_der.clone()),
        }
    }

    pub(super) fn subject_key_bits(&self) -> Result<Vec<u8>> {
        let spki = self.spki()?;
        let (rest, parsed) = SubjectPublicKeyInfo::from_der(&spki).map_err(crypto_failure)?;
        if !rest.is_empty() || parsed.subject_public_key.unused_bits != 0 {
            return Err(invalid_key());
        }
        Ok(parsed.subject_public_key.data.to_vec())
    }

    pub(super) fn verify(&self, input: &[u8], signature: &[u8]) -> Result<bool> {
        match self {
            Self::Ed25519(public) => Ok(ring::signature::UnparsedPublicKey::new(
                &ring::signature::ED25519,
                public,
            )
            .verify(input, signature)
            .is_ok()),
            Self::Typed(public) if public.kind.is_mldsa() => {
                mldsa_dispatch!(
                    public.kind,
                    mldsa_verify,
                    public.spki_der.as_slice(),
                    input,
                    signature
                )
            }
            Self::Typed(public) => {
                let key = self.maintained_public()?;
                let mut verifier =
                    Verifier::new(public.kind.digest(), &key).map_err(crypto_failure)?;
                if key.id() == Id::RSA {
                    verifier
                        .set_rsa_padding(Padding::PKCS1)
                        .map_err(crypto_failure)?;
                }
                verifier.update(input).map_err(crypto_failure)?;
                verifier.verify(signature).map_err(crypto_failure)
            }
        }
    }

    pub(super) fn verify_leaf(
        &self,
        input: &[u8],
        signature: &[u8],
        scheme: LeafSignature,
    ) -> Result<bool> {
        let Some(digest) = scheme.digest() else {
            return self.verify(input, signature);
        };
        let key = self.maintained_public()?;
        if (key.id() == Id::RSA) != matches!(scheme, LeafSignature::Rsa { .. }) {
            return Err(invalid_key());
        }
        let mut verifier = Verifier::new(digest, &key).map_err(crypto_failure)?;
        if key.id() == Id::RSA {
            verifier
                .set_rsa_padding(if scheme.pss() {
                    Padding::PKCS1_PSS
                } else {
                    Padding::PKCS1
                })
                .map_err(crypto_failure)?;
            if scheme.pss() {
                verifier.set_rsa_mgf1_md(digest).map_err(crypto_failure)?;
                verifier
                    .set_rsa_pss_saltlen(RsaPssSaltlen::DIGEST_LENGTH)
                    .map_err(crypto_failure)?;
            }
        }
        verifier.update(input).map_err(crypto_failure)?;
        verifier.verify(signature).map_err(crypto_failure)
    }

    pub(super) fn validate_certificate(&self, bytes: &[u8]) -> Result<()> {
        let (rest, certificate) = X509Certificate::from_der(bytes).map_err(crypto_failure)?;
        let algorithm_der = self.kind().signature_algorithm();
        let (algorithm_rest, algorithm) =
            x509_parser::x509::AlgorithmIdentifier::from_der(&algorithm_der)
                .map_err(crypto_failure)?;
        if !algorithm_rest.is_empty() || certificate.signature_algorithm != algorithm {
            return Err(invalid_key());
        }
        if !rest.is_empty()
            || certificate.public_key().raw != self.spki()?
            || certificate.signature_value.unused_bits != 0
            || certificate.signature_algorithm != certificate.tbs_certificate.signature
            || !self.verify(
                certificate.tbs_certificate.as_ref(),
                &certificate.signature_value.data,
            )?
        {
            return Err(invalid_key());
        }
        Ok(())
    }
}

#[cfg(test)]
#[path = "pki_local_key_tests.rs"]
mod tests;
