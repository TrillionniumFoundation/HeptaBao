//! Leaf signature choices derive from the original issuer and captured role.
//! RSA-PSS parameters are explicit and use the digest-sized salt in the real
//! official producer. Root and CRL signatures retain their historical default.
use super::*;
use openssl::hash::MessageDigest;

#[derive(Clone, Copy)]
pub(super) enum LeafSignature {
    Legacy(LocalKeyKind),
    Rsa { bits: u16, pss: bool },
    Ec { bits: u16 },
}

impl LeafSignature {
    pub(super) fn for_key(kind: LocalKeyKind, policy: Option<&RoleNamePolicy>) -> Self {
        let requested = policy.map_or(0, |policy| policy.signature_bits);
        let bits = match requested {
            256 | 384 | 512 => requested as u16,
            _ if kind.key_type() == "ec" => match kind {
                LocalKeyKind::Ec384 => 384,
                LocalKeyKind::Ec521 => 512,
                _ => 256,
            },
            _ => 256,
        };
        match kind.key_type() {
            "rsa" => Self::Rsa {
                bits,
                pss: policy.is_some_and(|policy| policy.use_pss),
            },
            "ec" => Self::Ec { bits },
            _ => Self::Legacy(kind),
        }
    }

    pub(super) fn digest(self) -> Option<MessageDigest> {
        match self {
            Self::Legacy(_) => None,
            Self::Rsa { bits, .. } | Self::Ec { bits } => Some(match bits {
                384 => MessageDigest::sha384(),
                512 => MessageDigest::sha512(),
                _ => MessageDigest::sha256(),
            }),
        }
    }

    pub(super) fn hash_algorithm(self) -> Option<&'static str> {
        match self {
            Self::Legacy(_) => None,
            Self::Rsa { bits: 384, .. } | Self::Ec { bits: 384 } => Some("sha2-384"),
            Self::Rsa { bits: 512, .. } | Self::Ec { bits: 512 } => Some("sha2-512"),
            _ => Some("sha2-256"),
        }
    }

    pub(super) fn pss(self) -> bool {
        matches!(self, Self::Rsa { pss: true, .. })
    }

    pub(super) fn algorithm(self) -> Vec<u8> {
        match self {
            Self::Legacy(kind) => kind.signature_algorithm(),
            Self::Ec { bits } => {
                let suffix = match bits {
                    384 => 3,
                    512 => 4,
                    _ => 2,
                };
                seq(&[oid(&[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, suffix])])
            }
            Self::Rsa { bits, pss: false } => {
                let suffix = match bits {
                    384 => 12,
                    512 => 13,
                    _ => 11,
                };
                seq(&[
                    oid(&[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 1, 1, suffix]),
                    der(0x05, &[]),
                ])
            }
            Self::Rsa { bits, pss: true } => {
                let (suffix, size) = match bits {
                    384 => (2, 48),
                    512 => (3, 64),
                    _ => (1, 32),
                };
                let hash = seq(&[
                    oid(&[0x60, 0x86, 0x48, 1, 0x65, 3, 4, 2, suffix]),
                    der(0x05, &[]),
                ]);
                let mgf = seq(&[
                    oid(&[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 1, 1, 8]),
                    hash.clone(),
                ]);
                seq(&[
                    oid(&[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 1, 1, 10]),
                    seq(&[
                        context_explicit(0, &hash),
                        context_explicit(1, &mgf),
                        context_explicit(2, &integer(&[size])),
                    ]),
                ])
            }
        }
    }
}

pub(super) fn signature_bits(body: &Value) -> Result<i64> {
    let invalid = || {
        bad(
            "Field validation failed: error converting input for field \"signature_bits\": cannot parse value as 'int'",
        )
    };
    match body.get("signature_bits") {
        None | Some(Value::Null) => Ok(0),
        Some(Value::Bool(value)) => Ok(i64::from(*value)),
        Some(Value::Number(value)) => value.as_i64().ok_or_else(invalid),
        Some(Value::String(value)) if value.is_empty() => Ok(0),
        Some(Value::String(value)) => value.parse().map_err(|_| invalid()),
        _ => Err(invalid()),
    }
}
