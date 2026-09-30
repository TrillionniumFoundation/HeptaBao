//! Runtime-only cryptographic fixtures for tests.
//!
//! Passwords, shared keys, salts and nonces are generated from the operating
//! system at test execution time. This keeps protocol tests exact without
//! embedding reusable cryptographic material in the source tree.

use ring::rand::{SecureRandom, SystemRandom};
use zeroize::Zeroizing;

pub(crate) fn random_bytes<const N: usize>() -> [u8; N] {
    let mut bytes = [0_u8; N];
    if SystemRandom::new().fill(&mut bytes).is_err() {
        std::process::abort();
    }
    bytes
}

pub(crate) fn random_ascii(length: usize) -> Zeroizing<String> {
    let mut bytes = Zeroizing::new(vec![0_u8; length]);
    if SystemRandom::new().fill(bytes.as_mut_slice()).is_err() {
        std::process::abort();
    }
    let value = bytes
        .iter()
        .map(|byte| char::from(b'a' + (byte % 26)))
        .collect();
    Zeroizing::new(value)
}

pub(crate) fn runtime_secret(label: &str) -> Zeroizing<String> {
    let suffix = random_ascii(32);
    Zeroizing::new(format!("{label}-{}", suffix.as_str()))
}
