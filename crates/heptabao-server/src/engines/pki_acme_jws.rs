//! Public ACME keys and signed request parsing. Verified requests contain no
//! Vault bearer authority and never construct a request clock.
use super::*;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use openssl::{
    bn::BigNum,
    ec::{EcGroup, EcKey},
    ecdsa::EcdsaSig,
    hash::MessageDigest,
    nid::Nid,
    pkey::{Id, PKey, Public},
    rsa::{Padding, Rsa},
    sign::{RsaPssSaltlen, Verifier},
};

const MAX_JWS_BODY: usize = 128 * 1024;
const MAX_HEADER: usize = 16 * 1024;
const MAX_PAYLOAD: usize = 64 * 1024;

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kty", deny_unknown_fields)]
pub(crate) enum Jwk {
    #[serde(rename = "EC")]
    Ec { crv: String, x: String, y: String },
    #[serde(rename = "RSA")]
    Rsa { n: String, e: String },
    #[serde(rename = "OKP")]
    Okp { crv: String, x: String },
}

fn malformed(message: &str) -> EngineError {
    bad(message)
}

fn decoded(value: &str, maximum: usize, allow_empty: bool) -> Result<Vec<u8>> {
    if value.len() > maximum.div_ceil(3) * 4 || !allow_empty && value.is_empty() {
        return Err(malformed("ACME base64url value exceeds bounds"));
    }
    let bytes = URL_SAFE_NO_PAD
        .decode(value)
        .map_err(|_| malformed("invalid ACME base64url value"))?;
    if bytes.len() > maximum || URL_SAFE_NO_PAD.encode(&bytes) != value {
        return Err(malformed("invalid canonical ACME base64url value"));
    }
    Ok(bytes)
}

impl Jwk {
    pub(crate) fn from_public_json(value: &Value) -> Result<Self> {
        let map = value
            .as_object()
            .ok_or_else(|| malformed("received invalid jwk"))?;
        if map.len() > 16
            || ["d", "p", "q", "dp", "dq", "qi", "oth", "k"]
                .iter()
                .any(|field| map.contains_key(*field))
        {
            return Err(malformed("ACME JWK must contain only public key material"));
        }
        let field = |name: &str| -> Result<String> {
            map.get(name)
                .and_then(Value::as_str)
                .filter(|s| s.len() <= 4096)
                .map(str::to_owned)
                .ok_or_else(|| malformed("received invalid jwk"))
        };
        let key = match field("kty")?.as_str() {
            "EC" => Self::Ec {
                crv: field("crv")?,
                x: field("x")?,
                y: field("y")?,
            },
            "RSA" => Self::Rsa {
                n: field("n")?,
                e: field("e")?,
            },
            "OKP" => Self::Okp {
                crv: field("crv")?,
                x: field("x")?,
            },
            _ => return Err(malformed("unsupported ACME JWK type")),
        };
        key.public_key()?;
        Ok(key)
    }

    pub(crate) fn public_key(&self) -> Result<PKey<Public>> {
        let cause = |_| malformed("received invalid jwk");
        match self {
            Self::Ec { crv, x, y } => {
                let (nid, size) = match crv.as_str() {
                    "P-256" => (Nid::X9_62_PRIME256V1, 32),
                    "P-384" => (Nid::SECP384R1, 48),
                    "P-521" => (Nid::SECP521R1, 66),
                    _ => return Err(malformed("unsupported ACME JWK curve")),
                };
                let x = decoded(x, size, false)?;
                let y = decoded(y, size, false)?;
                if x.len() != size || y.len() != size {
                    return Err(malformed("invalid ACME JWK coordinate length"));
                }
                let group = EcGroup::from_curve_name(nid).map_err(cause)?;
                let x = BigNum::from_slice(&x).map_err(cause)?;
                let y = BigNum::from_slice(&y).map_err(cause)?;
                let key =
                    EcKey::from_public_key_affine_coordinates(&group, &x, &y).map_err(cause)?;
                key.check_key().map_err(cause)?;
                PKey::from_ec_key(key).map_err(cause)
            }
            Self::Rsa { n, e } => {
                let n = decoded(n, 1024, false)?;
                let e = decoded(e, 8, false)?;
                if n[0] == 0 || e[0] == 0 {
                    return Err(malformed("invalid canonical RSA JWK integer"));
                }
                let n = BigNum::from_slice(&n).map_err(cause)?;
                let e = BigNum::from_slice(&e).map_err(cause)?;
                if !(2048..=8192).contains(&n.num_bits()) || !e.is_odd() || e.num_bits() < 2 {
                    return Err(malformed("invalid ACME RSA JWK parameters"));
                }
                let key = Rsa::from_public_components(n, e).map_err(cause)?;
                PKey::from_rsa(key).map_err(cause)
            }
            Self::Okp { crv, x } => {
                if crv != "Ed25519" {
                    return Err(malformed("unsupported ACME JWK curve"));
                }
                let x = decoded(x, 32, false)?;
                if x.len() != 32 {
                    return Err(malformed("invalid ACME JWK coordinate length"));
                }
                PKey::public_key_from_raw_bytes(&x, Id::ED25519).map_err(cause)
            }
        }
    }

    pub(crate) fn thumbprint(&self) -> Result<String> {
        self.public_key()?;
        let canonical = match self {
            Self::Ec { crv, x, y } => json!({"crv":crv,"kty":"EC","x":x,"y":y}),
            Self::Rsa { n, e } => json!({"e":e,"kty":"RSA","n":n}),
            Self::Okp { crv, x } => json!({"crv":crv,"kty":"OKP","x":x}),
        };
        let bytes = serde_json::to_vec(&canonical).map_err(|_| malformed("invalid ACME JWK"))?;
        Ok(URL_SAFE_NO_PAD.encode(crate::crypto::digest(&bytes)))
    }

    fn verify(&self, algorithm: &str, message: &[u8], signature: &[u8]) -> Result<()> {
        let key = self.public_key()?;
        let fail = |_| malformed("failed to verify ACME signature");
        let (digest, ec_size, pss) = match (self, algorithm) {
            (Self::Ec { crv, .. }, "ES256") if crv == "P-256" => {
                (Some(MessageDigest::sha256()), Some(32), false)
            }
            (Self::Ec { crv, .. }, "ES384") if crv == "P-384" => {
                (Some(MessageDigest::sha384()), Some(48), false)
            }
            (Self::Ec { crv, .. }, "ES512") if crv == "P-521" => {
                (Some(MessageDigest::sha512()), Some(66), false)
            }
            (Self::Rsa { .. }, "RS256") => (Some(MessageDigest::sha256()), None, false),
            (Self::Rsa { .. }, "RS384") => (Some(MessageDigest::sha384()), None, false),
            (Self::Rsa { .. }, "RS512") => (Some(MessageDigest::sha512()), None, false),
            (Self::Rsa { .. }, "PS256") => (Some(MessageDigest::sha256()), None, true),
            (Self::Rsa { .. }, "PS384") => (Some(MessageDigest::sha384()), None, true),
            (Self::Rsa { .. }, "PS512") => (Some(MessageDigest::sha512()), None, true),
            (Self::Okp { crv, .. }, "EdDSA") if crv == "Ed25519" => (None, None, false),
            _ => return Err(malformed("ACME algorithm does not match its JWK")),
        };
        let mut der_signature = None;
        if let Some(size) = ec_size {
            if signature.len() != size * 2 {
                return Err(malformed("invalid ACME ECDSA signature length"));
            }
            let r = BigNum::from_slice(&signature[..size]).map_err(fail)?;
            let s = BigNum::from_slice(&signature[size..]).map_err(fail)?;
            der_signature = Some(
                EcdsaSig::from_private_components(r, s)
                    .map_err(fail)?
                    .to_der()
                    .map_err(fail)?,
            );
        }
        let signature = der_signature.as_deref().unwrap_or(signature);
        let mut verifier = match digest {
            Some(digest) => Verifier::new(digest, &key).map_err(fail)?,
            None => Verifier::new_without_digest(&key).map_err(fail)?,
        };
        if matches!(self, Self::Rsa { .. }) {
            verifier
                .set_rsa_padding(if pss {
                    Padding::PKCS1_PSS
                } else {
                    Padding::PKCS1
                })
                .map_err(fail)?;
            if pss {
                verifier
                    .set_rsa_mgf1_md(digest.ok_or_else(|| malformed("invalid ACME RSA digest"))?)
                    .map_err(fail)?;
                verifier
                    .set_rsa_pss_saltlen(RsaPssSaltlen::DIGEST_LENGTH)
                    .map_err(fail)?;
            }
        }
        if verifier.verify_oneshot(signature, message).map_err(fail)? {
            Ok(())
        } else {
            Err(error(
                500,
                "failed to verify signature: go-jose/go-jose: error in cryptographic primitive",
            ))
        }
    }
}

pub(crate) struct ParsedJws {
    pub algorithm: String,
    pub nonce: String,
    pub url: String,
    pub kid: Option<String>,
    pub embedded_key: Option<Jwk>,
    protected: String,
    payload: String,
    signature: String,
}

pub(crate) struct VerifiedJws {
    key_thumbprint: String,
    payload: Option<Value>,
    raw_embedded_jwk: Option<zeroize::Zeroizing<Vec<u8>>>,
}

impl VerifiedJws {
    pub(crate) fn key_thumbprint(&self) -> &str {
        &self.key_thumbprint
    }
    pub(crate) fn raw_embedded_jwk(&self) -> Option<&[u8]> {
        self.raw_embedded_jwk.as_deref().map(Vec::as_slice)
    }
    pub(crate) fn payload(&self) -> Option<&Value> {
        self.payload.as_ref()
    }
}
impl Drop for VerifiedJws {
    fn drop(&mut self) {
        self.key_thumbprint.zeroize();
        if let Some(payload) = self.payload.as_mut() {
            wipe_json(payload);
        }
    }
}
impl Drop for ParsedJws {
    fn drop(&mut self) {
        self.algorithm.zeroize();
        self.nonce.zeroize();
        self.url.zeroize();
        if let Some(kid) = self.kid.as_mut() {
            kid.zeroize();
        }
        self.protected.zeroize();
        self.payload.zeroize();
        self.signature.zeroize();
    }
}

impl ParsedJws {
    pub(crate) fn parse(body: &Value) -> Result<Self> {
        if serde_json::to_vec(body)
            .map_err(|_| malformed("invalid ACME request"))?
            .len()
            > MAX_JWS_BODY
        {
            return Err(malformed("ACME request exceeds bounds"));
        }
        let field = |key: &str| -> Result<String> {
            body.get(key)
                .and_then(Value::as_str)
                .map(str::to_owned)
                .ok_or_else(|| malformed("missing required ACME signed request field"))
        };
        let protected = field("protected")?;
        let raw = decoded(&protected, MAX_HEADER, false)?;
        let header: Value =
            serde_json::from_slice(&raw).map_err(|_| malformed("invalid ACME protected header"))?;
        let map = header
            .as_object()
            .filter(|map| map.len() <= 32)
            .ok_or_else(|| malformed("invalid ACME protected header"))?;
        if map.get("b64").is_some_and(|v| v != &Value::Bool(true))
            || map
                .get("crit")
                .is_some_and(|v| v.as_array().is_none_or(|a| !a.is_empty()))
        {
            return Err(malformed("unsupported critical ACME protected header"));
        }
        let string = |key: &str| -> Result<String> {
            map.get(key)
                .and_then(Value::as_str)
                .filter(|s| !s.is_empty() && s.len() <= 4096)
                .map(str::to_owned)
                .ok_or_else(|| malformed("missing required ACME protected header"))
        };
        let algorithm = string("alg")?;
        if !matches!(
            algorithm.as_str(),
            "ES256"
                | "ES384"
                | "ES512"
                | "RS256"
                | "RS384"
                | "RS512"
                | "PS256"
                | "PS384"
                | "PS512"
                | "EdDSA"
        ) {
            return Err(malformed("unexpected ACME protected algorithm"));
        }
        let kid = match map.get("kid") {
            None => None,
            Some(v) => Some(
                v.as_str()
                    .filter(|s| !s.is_empty() && s.len() <= 4096)
                    .ok_or_else(|| malformed("invalid ACME account key identifier"))?
                    .to_owned(),
            ),
        };
        let embedded_key = map.get("jwk").map(Jwk::from_public_json).transpose()?;
        if kid.is_some() == embedded_key.is_some() {
            return Err(malformed(
                "ACME protected header requires exactly one kid or jwk",
            ));
        }
        let nonce = match map.get("nonce") {
            None => String::new(),
            Some(v) => v
                .as_str()
                .filter(|s| s.len() <= 4096)
                .ok_or_else(|| malformed("invalid ACME nonce header"))?
                .to_owned(),
        };
        let url = string("url")?;
        let payload = field("payload")?;
        let signature = field("signature")?;
        Ok(Self {
            algorithm,
            nonce,
            url,
            kid,
            embedded_key,
            protected,
            payload,
            signature,
        })
    }

    pub(crate) fn verify(self, key: &Jwk) -> Result<VerifiedJws> {
        if self
            .embedded_key
            .as_ref()
            .is_some_and(|embedded| embedded != key)
        {
            return Err(malformed("ACME signed request key changed"));
        }
        let input = zeroize::Zeroizing::new(format!("{}.{}", self.protected, self.payload));
        let signature = decoded(&self.signature, 2048, false)?;
        key.verify(&self.algorithm, input.as_bytes(), &signature)?;
        let bytes = zeroize::Zeroizing::new(decoded(&self.payload, MAX_PAYLOAD, true)?);
        let payload = if bytes.is_empty() {
            None
        } else {
            let value: Value = serde_json::from_slice(&bytes)
                .map_err(|_| malformed("failed to JSON unmarshal ACME payload"))?;
            if value.is_null() {
                None
            } else if value.is_object() {
                Some(value)
            } else {
                return Err(malformed("ACME payload must contain an object"));
            }
        };
        // EAB compares the signed protected JWK's original JSON bytes. A
        // semantically equal object with a different encoding is not this proof.
        let protected = zeroize::Zeroizing::new(decoded(&self.protected, MAX_HEADER, false)?);
        let raw_header: BTreeMap<String, Box<serde_json::value::RawValue>> =
            serde_json::from_slice(&protected)
                .map_err(|_| malformed("invalid ACME protected header"))?;
        let raw_embedded_jwk = raw_header
            .get("jwk")
            .map(|raw| zeroize::Zeroizing::new(raw.get().as_bytes().to_vec()));
        Ok(VerifiedJws {
            raw_embedded_jwk,
            key_thumbprint: key.thumbprint()?,
            payload,
        })
    }
}
