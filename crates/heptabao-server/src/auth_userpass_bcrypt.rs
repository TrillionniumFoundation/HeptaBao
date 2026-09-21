//! Import admission follows Go Cost, independently of the library's strict
//! verification parser. Cryptographic verification is delegated to rust-bcrypt.
use super::*;

// This does not lower the existing ordinary HTTP body bound. It also bounds
// direct embedded AuthState callers before copying an imported credential.
const MAX_HASH_BYTES: usize = 256 * 1024;

#[derive(Clone, Serialize, Deserialize)]
#[serde(transparent)]
pub(super) struct ImportedBcrypt {
    hash: String,
}

impl std::fmt::Debug for ImportedBcrypt {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ImportedBcrypt([REDACTED])")
    }
}
impl Zeroize for ImportedBcrypt {
    fn zeroize(&mut self) {
        self.hash.zeroize();
    }
}
impl Drop for ImportedBcrypt {
    fn drop(&mut self) {
        self.zeroize();
    }
}

/// Go x/crypto v0.53.0 newFromHash/decodeVersion/decodeCost. This is format
/// parsing, not a bcrypt implementation. Go does not validate separators,
/// salt encoding or hash length beyond a total minimum of59 at import time.
fn go_cost(hash: &str) -> Result<(u32, usize), AuthError> {
    let bytes = hash.as_bytes();
    if !(59..=MAX_HASH_BYTES).contains(&bytes.len()) || bytes[0] != b'$' || bytes[1] > b'2' {
        return Err(bad("password_hash is not a valid bcrypt hash"));
    }
    let cost_start = if bytes[2] == b'$' { 3 } else { 4 };
    let first = bytes[cost_start];
    let second = bytes[cost_start + 1];
    // strconv.Atoi accepts a leading '+'; negative values are outside5..12.
    let cost = if first == b'+' && second.is_ascii_digit() {
        u32::from(second - b'0')
    } else if first.is_ascii_digit() && second.is_ascii_digit() {
        u32::from(first - b'0') * 10 + u32::from(second - b'0')
    } else {
        return Err(bad("password_hash is not a valid bcrypt hash"));
    };
    if !(5..=12).contains(&cost) {
        return Err(bad("bcrypt import cost must be between 5 and 12"));
    }
    Ok((cost, cost_start + 3))
}

impl ImportedBcrypt {
    pub(super) fn new(hash: &str) -> Result<Self, AuthError> {
        go_cost(hash)?;
        Ok(Self {
            hash: hash.to_owned(),
        })
    }

    fn verifier_input(&self) -> Option<Zeroizing<[u8; 60]>> {
        let (cost, salt_start) = go_cost(&self.hash).ok()?;
        let raw = self.hash.as_bytes();
        let salt_text = raw.get(salt_start..salt_start + 22)?;
        // Go Hash compares only the first31 hash bytes and ignores an extra
        // suffix. A short/malformed hash may be admitted but cannot verify.
        let hash_text = raw.get(salt_start + 22..salt_start + 53)?;
        let engine = base64::engine::general_purpose::GeneralPurpose::new(
            &base64::alphabet::BCRYPT,
            base64::engine::general_purpose::GeneralPurposeConfig::new()
                .with_encode_padding(false)
                .with_decode_padding_mode(base64::engine::DecodePaddingMode::RequireNone)
                .with_decode_allow_trailing_bits(true),
        );
        let mut salt = Zeroizing::new([0u8; 16]);
        if engine.decode_slice(salt_text, &mut salt[..]).ok()? != 16 {
            return None;
        }
        let mut normalized = Zeroizing::new([0u8; 60]);
        normalized[..7].copy_from_slice(b"$2b$00$");
        normalized[4] = b'0' + u8::try_from(cost / 10).ok()?;
        normalized[5] = b'0' + u8::try_from(cost % 10).ok()?;
        // The Go parser's version label does not alter its bcrypt algorithm.
        // Normalize format only; the library performs the actual computation.
        if engine
            .encode_slice(&salt[..], &mut normalized[7..29])
            .ok()?
            != 22
        {
            return None;
        }
        normalized[29..].copy_from_slice(hash_text);
        Some(normalized)
    }

    pub(super) fn verify(&self, password: &[u8]) -> bool {
        let Some(normalized) = self.verifier_input() else {
            return false;
        };
        let Ok(hash) = std::str::from_utf8(&normalized[..]) else {
            return false;
        };
        bcrypt::verify(password, hash).unwrap_or(false)
    }
}

pub(super) fn validate_user(user: &User) -> Result<(), AuthError> {
    if let Some(imported) = &user.imported_bcrypt {
        go_cost(&imported.hash)?;
        if !user.salt.is_empty()
            || !user.verifier.is_empty()
            || user.rounds != 0
            || user.password_semantics.is_some()
        {
            return Err(bad("ambiguous imported password credential"));
        }
    }
    Ok(())
}
