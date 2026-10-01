//! Public issuer key material. No CA private key is parsed, copied or persisted.
//! The legacy Ed25519 array keeps its original canonical representation.
use super::*;
use openssl::{
    bn::{BigNum, BigNumContext},
    ec::PointConversionForm,
    hash::{MessageDigest, hash},
    nid::Nid,
    pkey::{Id, PKey, Public},
    rsa::Padding,
    sign::Verifier,
};

const MAX_SPKI: usize = 8192;

#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(untagged)]
pub(crate) enum ExternalPkiPublicKey {
    Ed25519([u8; 32]),
    Asymmetric(AsymmetricPublic),
}

#[cfg(test)]
mod tests {
    use super::*;
    use openssl::{
        ec::{EcGroup, EcKey, EcPoint},
        pkey::Private,
        rsa::Rsa,
        sign::Signer,
        x509::{X509, X509Req},
    };

    fn fixture_error<T>(_: T) -> EngineError {
        bad("synthetic maintained crypto fixture failure")
    }

    fn provider(kind: &str) -> Result<PKey<Private>> {
        match kind {
            "ecdsa-p256" | "ecdsa-p384" | "ecdsa-p521" => {
                let nid = match kind {
                    "ecdsa-p256" => Nid::X9_62_PRIME256V1,
                    "ecdsa-p384" => Nid::SECP384R1,
                    _ => Nid::SECP521R1,
                };
                let group = EcGroup::from_curve_name(nid).map_err(fixture_error)?;
                PKey::from_ec_key(EcKey::generate(&group).map_err(fixture_error)?)
                    .map_err(fixture_error)
            }
            _ => {
                let bits = match kind {
                    "rsa-2048" => 2048,
                    "rsa-3072" => 3072,
                    _ => 4096,
                };
                PKey::from_rsa(Rsa::generate(bits).map_err(fixture_error)?).map_err(fixture_error)
            }
        }
    }

    fn public(pair: &PKey<Private>, kind: &str) -> Result<ExternalPkiPublicKey> {
        let pem = pair.public_key_to_pem().map_err(fixture_error)?;
        ExternalPkiPublicKey::from_metadata(kind, std::str::from_utf8(&pem).map_err(fixture_error)?)
    }

    fn sign(
        pair: &PKey<Private>,
        public: &ExternalPkiPublicKey,
        tbs: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>> {
        let mut signer = Signer::new(public.digest(), pair).map_err(fixture_error)?;
        if pair.id() == Id::RSA {
            signer
                .set_rsa_padding(Padding::PKCS1)
                .map_err(fixture_error)?;
        }
        signer.update(tbs).map_err(fixture_error)?;
        Ok(Zeroizing::new(signer.sign_to_vec().map_err(fixture_error)?))
    }

    #[test]
    fn external_pki_ed_public_array_canonical_unchanged_and_unknown_typed_fields_rejected()
    -> Result<()> {
        let bytes = [23u8; 32];
        let public = ExternalPkiPublicKey::from(bytes);
        assert!(
            serde_json::to_vec(&public).map_err(fixture_error)?
                == serde_json::to_vec(&bytes).map_err(fixture_error)?,
            "legacy Ed public array exactly retained"
        );
        let decoded: ExternalPkiPublicKey =
            serde_json::from_slice(&serde_json::to_vec(&bytes).map_err(fixture_error)?)
                .map_err(fixture_error)?;
        assert!(decoded == public, "legacy array decode bound");
        assert!(
            serde_json::from_value::<ExternalPkiPublicKey>(
                json!({"kind":"rsa-2048","spki_der":[],"private_key":[]})
            )
            .is_err(),
            "unknown typed public fields rejected"
        );
        assert!(
            serde_json::from_value::<ExternalPkiPublicKey>(json!(vec![0; 31])).is_err(),
            "wrong legacy key length rejected"
        );
        Ok(())
    }

    #[test]
    fn external_pki_typed_spki_rejects_kind_substitution_trailing_der_and_size() -> Result<()> {
        let pair = provider("ecdsa-p256")?;
        let public = public(&pair, "ecdsa-p256")?;
        let mut encoded = serde_json::to_value(&public).map_err(fixture_error)?;
        encoded["kind"] = json!("ecdsa-p384");
        let altered: ExternalPkiPublicKey =
            serde_json::from_value(encoded).map_err(fixture_error)?;
        assert!(altered.validate().is_err(), "curve substitution rejected");
        let ExternalPkiPublicKey::Asymmetric(mut altered) = public else {
            return Err(bad("test typed variant"));
        };
        altered.spki_der.push(0);
        assert!(
            ExternalPkiPublicKey::Asymmetric(altered)
                .validate()
                .is_err(),
            "trailing SPKI DER rejected"
        );
        assert!(
            ExternalPkiPublicKey::Asymmetric(AsymmetricPublic {
                kind: "rsa-4096".into(),
                spki_der: vec![0; MAX_SPKI + 1]
            })
            .validate()
            .is_err(),
            "oversize public DER rejected"
        );
        Ok(())
    }

    #[test]
    fn external_pki_invalid_public_parameters_are_rejected() -> Result<()> {
        let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).map_err(|_| bad("ec group"))?;
        let infinity = EcPoint::new(&group).map_err(|_| bad("ec infinity point"))?;
        assert!(
            EcKey::from_public_key(&group, &infinity).is_err(),
            "maintained EC constructor rejects infinity"
        );
        let public = ExternalPkiPublicKey::Asymmetric(AsymmetricPublic {
            kind: "ecdsa-p256".into(),
            spki_der: seq(&[
                seq(&[
                    oid(&[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01]),
                    oid(&[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07]),
                ]),
                bit_string(&[0], 0),
            ]),
        });
        assert!(
            public.validate().is_err(),
            "maintained SPKI parser rejects infinity"
        );
        let pair = provider("rsa-2048")?;
        let rsa = pair.rsa().map_err(|_| bad("rsa fixture"))?;
        for exponent in [0, 1, 2] {
            let invalid = Rsa::from_public_components(
                rsa.n().to_owned().map_err(|_| bad("rsa public access"))?,
                BigNum::from_u32(exponent).map_err(|_| bad("rsa modulus copy"))?,
            )
            .map_err(|_| bad("rsa exponent value"))?;
            let key = PKey::from_rsa(invalid).map_err(|_| bad("rsa public constructor"))?;
            let public = ExternalPkiPublicKey::Asymmetric(AsymmetricPublic {
                kind: "rsa-2048".into(),
                spki_der: key
                    .public_key_to_der()
                    .map_err(|_| bad("rsa PKey constructor"))?,
            });
            assert!(public.validate().is_err(), "invalid RSA exponent rejected");
        }
        let mut modulus = rsa.n().to_owned().map_err(|_| bad("rsa public export"))?;
        modulus
            .clear_bit(0)
            .map_err(|_| bad("rsa modulus second copy"))?;
        let invalid = Rsa::from_public_components(
            modulus,
            rsa.e().to_owned().map_err(|_| bad("rsa modulus even"))?,
        )
        .map_err(|_| bad("rsa exponent copy"))?;
        let key = PKey::from_rsa(invalid).map_err(|_| bad("rsa even public constructor"))?;
        let public = ExternalPkiPublicKey::Asymmetric(AsymmetricPublic {
            kind: "rsa-2048".into(),
            spki_der: key
                .public_key_to_der()
                .map_err(|_| bad("rsa even PKey constructor"))?,
        });
        assert!(public.validate().is_err(), "even RSA modulus rejected");
        Ok(())
    }

    #[test]
    fn external_pki_all_six_maintained_actual_signatures_roots_csrs_crls_and_reopen() -> Result<()>
    {
        for kind in [
            "ecdsa-p256",
            "ecdsa-p384",
            "ecdsa-p521",
            "rsa-2048",
            "rsa-3072",
            "rsa-4096",
        ] {
            let pair = provider(kind)?;
            let public = public(&pair, kind)?;
            let message = b"synthetic remote authority binding";
            let signature = sign(&pair, &public, message)?;
            public.verify(message, &signature)?;
            assert!(
                public
                    .verify(b"changed synthetic authority binding", &signature)
                    .is_err(),
                "changed TBS rejected"
            );
            let expected = if kind == "ecdsa-p384" {
                48
            } else if kind == "ecdsa-p521" {
                64
            } else {
                32
            };
            assert!(
                public.signing_input(message)?.len() == expected,
                "curve-specific digest length bound"
            );
            for operation in ["root/generate/kms", "intermediate/generate/kms"] {
                let mut pki = Pki::default();
                let template=pki.prepare_external("POST",operation,&json!({"external_key_ref":"provider:fixed","common_name":"synthetic-ca.example.test","ttl":"1h"}),100)?.ok_or_else(|| bad("test template"))?;
                let material = template.materialize(public.clone())?;
                let signatures = material
                    .tbs_parts()
                    .map(|tbs| sign(&pair, &public, tbs))
                    .collect::<Result<Vec<_>>>()?;
                pki.publish_external(material, &signatures, 100)?;
                pki.validate("", "pki/", 100)?;
                assert!(
                    pki.has_typed_external_pki_state(),
                    "typed public state identified"
                );
                if operation.starts_with("root") {
                    let root = pki.root.as_ref().ok_or_else(|| bad("test root"))?;
                    assert!(root.pkcs8.is_empty(), "remote CA private material absent");
                    let cert = X509::from_der(&root.certificate_der).map_err(fixture_error)?;
                    assert!(
                        cert.verify(&pair).map_err(fixture_error)?,
                        "maintained root self-signature verifies"
                    );
                    assert!(
                        cert.public_key()
                            .map_err(fixture_error)?
                            .public_key_to_der()
                            .map_err(fixture_error)?
                            == public.spki()?,
                        "root remote SPKI bound"
                    );
                } else {
                    let csr = pki
                        .external
                        .intermediate
                        .as_ref()
                        .ok_or_else(|| bad("test CSR"))?;
                    let request = X509Req::from_der(&csr.csr_der).map_err(fixture_error)?;
                    assert!(
                        request.verify(&pair).map_err(fixture_error)?,
                        "native CSR uses real remote authority"
                    );
                }
                let bytes = serde_json::to_vec(&pki).map_err(|_| bad("test encode"))?;
                let reopened: Pki =
                    serde_json::from_slice(&bytes).map_err(|_| bad("test reopen"))?;
                reopened.validate("", "pki/", 100)?;
                assert!(
                    serde_json::to_vec(&reopened).map_err(|_| bad("test reencode"))? == bytes,
                    "typed state canonical reopen stable"
                );
            }
        }
        Ok(())
    }
}

#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct AsymmetricPublic {
    kind: String,
    spki_der: Vec<u8>,
}

impl From<[u8; 32]> for ExternalPkiPublicKey {
    fn from(value: [u8; 32]) -> Self {
        Self::Ed25519(value)
    }
}

fn invalid_public() -> EngineError {
    error(503, "invalid external PKI public-key material")
}

impl ExternalPkiPublicKey {
    pub(crate) fn from_metadata(kind: &str, text: &str) -> Result<Self> {
        if kind == "ed25519" {
            if text.len() != 44 {
                return Err(invalid_public());
            }
            let bytes = BASE64.decode(text).map_err(|_| invalid_public())?;
            if BASE64.encode(&bytes) != text {
                return Err(invalid_public());
            }
            return Ok(Self::Ed25519(
                bytes.try_into().map_err(|_| invalid_public())?,
            ));
        }
        if !matches!(
            kind,
            "ecdsa-p256" | "ecdsa-p384" | "ecdsa-p521" | "rsa-2048" | "rsa-3072" | "rsa-4096"
        ) {
            return Err(error(501, "external PKI key algorithm is unsupported"));
        }
        if text.len() > MAX_SPKI {
            return Err(invalid_public());
        }
        let key = PKey::public_key_from_pem(text.as_bytes()).map_err(|_| invalid_public())?;
        let spki_der = key.public_key_to_der().map_err(|_| invalid_public())?;
        let public = Self::Asymmetric(AsymmetricPublic {
            kind: kind.into(),
            spki_der,
        });
        public.validate()?;
        Ok(public)
    }

    fn maintained_public(&self) -> Result<PKey<Public>> {
        let Self::Asymmetric(public) = self else {
            return Err(invalid_public());
        };
        if public.spki_der.is_empty() || public.spki_der.len() > MAX_SPKI {
            return Err(invalid_public());
        }
        let key = PKey::public_key_from_der(&public.spki_der).map_err(|_| invalid_public())?;
        if key.public_key_to_der().map_err(|_| invalid_public())? != public.spki_der {
            return Err(invalid_public());
        }
        let valid = match public.kind.as_str() {
            "ecdsa-p256" | "ecdsa-p384" | "ecdsa-p521" if key.id() == Id::EC => {
                let expected = match public.kind.as_str() {
                    "ecdsa-p256" => Nid::X9_62_PRIME256V1,
                    "ecdsa-p384" => Nid::SECP384R1,
                    _ => Nid::SECP521R1,
                };
                let ec = key.ec_key().map_err(|_| invalid_public())?;
                ec.check_key().map_err(|_| invalid_public())?;
                ec.group().curve_name() == Some(expected)
            }
            "rsa-2048" | "rsa-3072" | "rsa-4096" if key.id() == Id::RSA => {
                let bits = match public.kind.as_str() {
                    "rsa-2048" => 2048,
                    "rsa-3072" => 3072,
                    _ => 4096,
                };
                let rsa = key.rsa().map_err(|_| invalid_public())?;
                let minimum = BigNum::from_u32(3).map_err(|_| invalid_public())?;
                key.bits() == bits
                    && !rsa.n().is_negative()
                    && rsa.n().is_odd()
                    && !rsa.e().is_negative()
                    && rsa.e().is_odd()
                    && rsa.e().ucmp(&minimum) != std::cmp::Ordering::Less
                    && rsa.e().ucmp(rsa.n()) == std::cmp::Ordering::Less
            }
            _ => false,
        };
        if !valid {
            return Err(invalid_public());
        }
        Ok(key)
    }

    pub(crate) fn validate(&self) -> Result<()> {
        if self.is_asymmetric() {
            self.maintained_public()?;
        }
        Ok(())
    }

    pub(crate) fn is_asymmetric(&self) -> bool {
        matches!(self, Self::Asymmetric(_))
    }

    pub(crate) fn spki(&self) -> Result<Vec<u8>> {
        match self {
            Self::Ed25519(public) => Ok(seq(&[algorithm_ed25519(), bit_string(public, 0)])),
            Self::Asymmetric(public) => {
                self.validate()?;
                Ok(public.spki_der.clone())
            }
        }
    }

    pub(crate) fn subject_key_bits(&self) -> Result<Vec<u8>> {
        match self {
            Self::Ed25519(public) => Ok(public.to_vec()),
            Self::Asymmetric(_) => {
                let key = self.maintained_public()?;
                if key.id() == Id::EC {
                    let key = key.ec_key().map_err(|_| invalid_public())?;
                    let mut context = BigNumContext::new().map_err(|_| invalid_public())?;
                    key.public_key()
                        .to_bytes(key.group(), PointConversionForm::UNCOMPRESSED, &mut context)
                        .map_err(|_| invalid_public())
                } else {
                    key.rsa()
                        .map_err(|_| invalid_public())?
                        .public_key_to_der_pkcs1()
                        .map_err(|_| invalid_public())
                }
            }
        }
    }

    fn digest(&self) -> MessageDigest {
        match self {
            Self::Asymmetric(public) if public.kind == "ecdsa-p384" => MessageDigest::sha384(),
            Self::Asymmetric(public) if public.kind == "ecdsa-p521" => MessageDigest::sha512(),
            _ => MessageDigest::sha256(),
        }
    }

    pub(crate) fn hash_algorithm(&self) -> Option<&'static str> {
        match self {
            Self::Ed25519(_) => None,
            Self::Asymmetric(public) if public.kind == "ecdsa-p384" => Some("sha2-384"),
            Self::Asymmetric(public) if public.kind == "ecdsa-p521" => Some("sha2-512"),
            Self::Asymmetric(_) => Some("sha2-256"),
        }
    }

    pub(crate) fn signing_input(&self, tbs: &[u8]) -> Result<Vec<u8>> {
        if self.is_asymmetric() {
            self.validate()?;
            hash(self.digest(), tbs)
                .map(|digest| digest.to_vec())
                .map_err(|_| invalid_public())
        } else {
            Ok(tbs.to_vec())
        }
    }

    pub(crate) fn signature_algorithm(&self) -> Vec<u8> {
        match self {
            Self::Ed25519(_) => algorithm_ed25519(),
            Self::Asymmetric(public) if public.kind.starts_with("ecdsa-") => {
                let suffix = match public.kind.as_str() {
                    "ecdsa-p384" => 3,
                    "ecdsa-p521" => 4,
                    _ => 2,
                };
                seq(&[oid(&[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, suffix])])
            }
            Self::Asymmetric(_) => seq(&[
                oid(&[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b]),
                der(0x05, &[]),
            ]),
        }
    }

    pub(crate) fn signature_size_bound(&self) -> usize {
        match self {
            Self::Ed25519(_) => 64,
            Self::Asymmetric(public) => match public.kind.as_str() {
                "ecdsa-p256" => 72,
                "ecdsa-p384" => 104,
                "ecdsa-p521" => 141,
                "rsa-2048" => 256,
                "rsa-3072" => 384,
                "rsa-4096" => 512,
                _ => 0,
            },
        }
    }

    pub(crate) fn verify(&self, tbs: &[u8], signature: &[u8]) -> Result<()> {
        if signature.is_empty() || signature.len() > self.signature_size_bound() {
            return Err(invalid_public());
        }
        let valid = match self {
            Self::Ed25519(public) => {
                signature.len() == 64
                    && UnparsedPublicKey::new(&ED25519, public)
                        .verify(tbs, signature)
                        .is_ok()
            }
            Self::Asymmetric(_) => {
                let key = self.maintained_public()?;
                let mut verifier =
                    Verifier::new(self.digest(), &key).map_err(|_| invalid_public())?;
                if key.id() == Id::RSA {
                    verifier
                        .set_rsa_padding(Padding::PKCS1)
                        .map_err(|_| invalid_public())?;
                }
                verifier.update(tbs).map_err(|_| invalid_public())?;
                verifier.verify(signature).map_err(|_| invalid_public())?
            }
        };
        if !valid {
            return Err(invalid_public());
        }
        Ok(())
    }
}
