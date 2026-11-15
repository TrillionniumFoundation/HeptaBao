use crate::crypto::random;
use crate::{Result, VaultError};
use ring::hmac;
use serde::{Deserialize, Serialize};
use std::fmt;
use zeroize::{Zeroize, Zeroizing};
#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum TotpAlgorithm {
    Sha1,
    Sha256,
    Sha512,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TotpConfig {
    pub secret_base32: String,
    pub algorithm: TotpAlgorithm,
    pub digits: u32,
    pub period: u64,
}
impl fmt::Debug for TotpConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TotpConfig")
            .field("algorithm", &self.algorithm)
            .field("digits", &self.digits)
            .finish_non_exhaustive()
    }
}
impl Drop for TotpConfig {
    fn drop(&mut self) {
        self.secret_base32.zeroize();
    }
}
impl TotpConfig {
    pub fn validate(&self) -> Result<()> {
        if !(6..=8).contains(&self.digits) || !(15..=120).contains(&self.period) {
            return Err(VaultError::InvalidInput);
        }
        let _ = decode_base32(&self.secret_base32)?;
        Ok(())
    }
}
fn decode_base32(s: &str) -> Result<Zeroizing<Vec<u8>>> {
    if s.len() < 26 || s.len() > 208 || !s.is_ascii() {
        return Err(VaultError::InvalidInput);
    }
    let mut out = Zeroizing::new(Vec::with_capacity(s.len() * 5 / 8));
    let mut bits = 0u16;
    let mut count = 0u8;
    for ch in s.bytes() {
        let v = match ch {
            b'A'..=b'Z' => ch - b'A',
            b'2'..=b'7' => ch - b'2' + 26,
            _ => return Err(VaultError::InvalidInput),
        };
        bits = (bits << 5) | u16::from(v);
        count += 5;
        if count >= 8 {
            count -= 8;
            out.push((bits >> count) as u8);
            bits &= (1 << count) - 1;
        }
    }
    if bits != 0 || !matches!(s.len() % 8, 0 | 2 | 4 | 5 | 7) || out.len() < 16 || out.len() > 128 {
        return Err(VaultError::InvalidInput);
    }
    Ok(out)
}
pub fn totp(config: &TotpConfig, unix_seconds: u64) -> Result<Zeroizing<String>> {
    config.validate()?;
    let secret = decode_base32(&config.secret_base32)?;
    let algorithm = match config.algorithm {
        TotpAlgorithm::Sha1 => hmac::HMAC_SHA1_FOR_LEGACY_USE_ONLY,
        TotpAlgorithm::Sha256 => hmac::HMAC_SHA256,
        TotpAlgorithm::Sha512 => hmac::HMAC_SHA512,
    };
    let key = hmac::Key::new(algorithm, &secret);
    let tag = hmac::sign(&key, &(unix_seconds / config.period).to_be_bytes());
    let bytes = tag.as_ref();
    let off = usize::from(bytes[bytes.len() - 1] & 15);
    let binary = (u32::from(bytes[off] & 127) << 24)
        | (u32::from(bytes[off + 1]) << 16)
        | (u32::from(bytes[off + 2]) << 8)
        | u32::from(bytes[off + 3]);
    let value = binary % 10u32.pow(config.digits);
    Ok(Zeroizing::new(format!(
        "{:0width$}",
        value,
        width = config.digits as usize
    )))
}
pub fn generate_password(length: usize) -> Result<Zeroizing<String>> {
    if !(16..=128).contains(&length) {
        return Err(VaultError::InvalidInput);
    }
    // 64-character alphabet gives exactly six unbiased bits per CSPRNG byte.
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut output = Zeroizing::new(String::with_capacity(length));
    for _ in 0..length {
        output.push(char::from(ALPHABET[usize::from(random::<1>()?[0] & 63)]));
    }
    Ok(output)
}
