//! Local public SPKI keys use a bounded same-algorithm verification set.
//! PEM keys have no configured JWS kid. Other key sources retain exact-kid
//! selection; this source discriminator is protected by the schema-69 reader.
use super::*;
use openssl::{
    bn::BigNumContext,
    ec::PointConversionForm,
    nid::Nid,
    pkey::{Id, PKey},
};

const MAX_PEM_KEYS: usize = 64;
const MAX_PEM_BYTES: usize = 16 * 1024;
const MAX_PEM_TOTAL_BYTES: usize = MAX_PEM_KEYS * MAX_PEM_BYTES;

fn parse_public_key(value: &str) -> Result<JwtKeyRecord, AuthError> {
    if value.is_empty() || value.len() > MAX_PEM_BYTES || !value.is_ascii() {
        return Err(bad("JWT PEM public key is outside bounds"));
    }
    let pem = value.trim();
    if !pem.starts_with("-----BEGIN PUBLIC KEY-----")
        || !pem.ends_with("-----END PUBLIC KEY-----")
        || pem.matches("-----BEGIN ").count() != 1
        || pem.matches("-----END ").count() != 1
    {
        return Err(bad("JWT PEM must contain one SPKI public key"));
    }
    // Never parse a private-key envelope or include provider error details.
    let key =
        PKey::public_key_from_pem(pem.as_bytes()).map_err(|_| bad("invalid JWT PEM public key"))?;
    let (algorithm, bytes) = match key.id() {
        Id::RSA => {
            let rsa = key.rsa().map_err(|_| bad("invalid JWT RSA public key"))?;
            let n = rsa.n().to_vec();
            let e = rsa.e().to_vec();
            if !(256..=512).contains(&n.len())
                || n.first().is_none_or(|value| *value < 0x80)
                || e != [1, 0, 1]
            {
                return Err(bad(
                    "JWT RSA key requires 2048..4096 bits and exponent 65537",
                ));
            }
            let mut bytes = Vec::with_capacity(n.len() + 5);
            bytes.extend_from_slice(&(n.len() as u16).to_be_bytes());
            bytes.extend(n);
            bytes.extend(e);
            ("RS256", bytes)
        }
        Id::EC => {
            let ec = key.ec_key().map_err(|_| bad("invalid JWT EC public key"))?;
            if ec.group().curve_name() != Some(Nid::X9_62_PRIME256V1) {
                return Err(bad("JWT PEM EC key requires P-256"));
            }
            ec.check_key()
                .map_err(|_| bad("invalid JWT EC public point"))?;
            let mut context = BigNumContext::new().map_err(|_| bad("JWT EC parser unavailable"))?;
            let point = ec
                .public_key()
                .to_bytes(ec.group(), PointConversionForm::UNCOMPRESSED, &mut context)
                .map_err(|_| bad("invalid JWT EC public point"))?;
            ("ES256", point)
        }
        Id::ED25519 => (
            "EdDSA",
            key.raw_public_key()
                .map_err(|_| bad("invalid JWT Ed25519 public key"))?,
        ),
        _ => return Err(bad("unsupported JWT PEM public key type")),
    };
    let algorithm_type = match algorithm {
        "RS256" => JwtAlgorithm::Rs256,
        "ES256" => JwtAlgorithm::Es256,
        "EdDSA" => JwtAlgorithm::Ed25519,
        _ => return Err(bad("unsupported JWT PEM algorithm")),
    };
    VerificationKey::new("pem-shape", algorithm_type, bytes.clone())
        .map_err(|_| bad("invalid JWT PEM verification key"))?;
    Ok(JwtKeyRecord {
        algorithm: algorithm.into(),
        bytes,
    })
}

pub(super) fn derive_keys(values: &[String]) -> Result<BTreeMap<String, JwtKeyRecord>, AuthError> {
    if values.is_empty() || values.len() > MAX_PEM_KEYS {
        return Err(bad("JWT PEM key count is outside bounds"));
    }
    let mut total = 0usize;
    let mut keys = BTreeMap::new();
    for (index, value) in values.iter().enumerate() {
        total = total
            .checked_add(value.len())
            .ok_or_else(|| bad("JWT PEM keys exceed byte bound"))?;
        if total > MAX_PEM_TOTAL_BYTES {
            return Err(bad("JWT PEM keys exceed byte bound"));
        }
        keys.insert(format!("pem-{index}"), parse_public_key(value)?);
    }
    Ok(keys)
}

pub(super) fn parse(
    values: &Value,
) -> Result<(Vec<String>, BTreeMap<String, JwtKeyRecord>), AuthError> {
    let supplied: Vec<&str> = match values {
        Value::String(value) if value.len() <= MAX_PEM_TOTAL_BYTES => {
            value.split(',').take(MAX_PEM_KEYS + 1).collect()
        }
        Value::Array(values) if values.len() <= MAX_PEM_KEYS => values
            .iter()
            .map(|value| {
                value
                    .as_str()
                    .ok_or_else(|| bad("JWT PEM keys must be strings"))
            })
            .collect::<Result<_, _>>()?,
        _ => return Err(bad("JWT PEM keys must be a bounded string or array")),
    };
    if supplied.is_empty() || supplied.len() > MAX_PEM_KEYS {
        return Err(bad("JWT PEM key count is outside bounds"));
    }
    // Parse the entire input before constructing the persisted public strings.
    for value in &supplied {
        parse_public_key(value)?;
    }
    let values: Vec<String> = supplied
        .into_iter()
        .map(|value| value.trim().to_owned())
        .collect();
    let keys = derive_keys(&values)?;
    Ok((values, keys))
}

impl AuthState {
    pub(crate) fn has_jwt_pem_keyset_state(&self) -> bool {
        self.jwt_mounts
            .values()
            .flat_map(|mounts| mounts.values())
            .any(|mount| {
                mount
                    .config
                    .as_ref()
                    .is_some_and(|config| config.jwt_validation_pubkeys.is_some())
            })
    }

    pub(crate) fn validate_jwt_pem_keyset_state(&self) -> Result<(), AuthError> {
        for (namespace, mounts) in &self.jwt_mounts {
            for config in mounts.values().filter_map(|mount| mount.config.as_ref()) {
                if let Some(pems) = &config.jwt_validation_pubkeys {
                    if config.remote.is_some()
                        || config.keys != derive_keys(pems)?
                        || config
                            .required_namespace
                            .as_ref()
                            .is_some_and(|value| value != namespace)
                        || config.jwt_supported_algs.as_ref().is_some_and(|algs| {
                            algs.is_empty()
                                || algs
                                    .iter()
                                    .any(|alg| !matches!(alg.as_str(), "RS256" | "ES256" | "EdDSA"))
                        })
                    {
                        return Err(bad("invalid persisted JWT PEM source binding"));
                    }
                    // Roles can supply the login audience. Admission validates
                    // configuration shape without requiring an active key from
                    // an intentionally disjoint algorithm allowlist.
                    let mut audiences = config.audiences.clone();
                    if audiences.is_empty() {
                        audiences.insert("configuration-shape-only".into());
                    }
                    TrustPolicy::new(
                        config.issuer.clone(),
                        audiences,
                        config
                            .required_namespace
                            .clone()
                            .filter(|value| !value.is_empty()),
                        config.clock_skew_seconds.unwrap_or(30),
                        config.maximum_token_lifetime_seconds.unwrap_or(86400),
                    )
                    .map_err(|_| bad("invalid persisted JWT PEM trust policy"))?;
                }
            }
        }
        Ok(())
    }
}
