use crate::{MAX_FILE_BYTES, Result, VaultError};
use argon2::{Algorithm, Argon2, Block, Params, Version};
use base64::{Engine, engine::general_purpose::STANDARD_NO_PAD};
use ring::{
    aead, digest,
    rand::{SecureRandom, SystemRandom},
};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

const CIPHER: &str = "AES-256-GCM";
type CreatedEnvelope = (Envelope, Zeroizing<[u8; 32]>, Zeroizing<[u8; 32]>);
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Kdf {
    algorithm: String,
    version: u32,
    memory_kib: u32,
    iterations: u32,
    parallelism: u32,
}
impl Kdf {
    fn standard() -> Self {
        Self {
            algorithm: "argon2id".into(),
            version: 19,
            memory_kib: 65536,
            iterations: 3,
            parallelism: 4,
        }
    }
    fn valid(&self) -> bool {
        self.algorithm == "argon2id"
            && self.version == 19
            && self.memory_kib == 65536
            && self.iterations == 3
            && self.parallelism == 4
    }
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Sealed {
    nonce: String,
    ciphertext: String,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Envelope {
    format: u32,
    cipher: String,
    kdf: Kdf,
    pub(crate) vault_id: String,
    pub(crate) revision: u64,
    salt: String,
    password_wrap: Sealed,
    recovery_wrap: Sealed,
    body: Sealed,
}
#[derive(Serialize)]
struct Header<'a> {
    domain: &'static str,
    format: u32,
    cipher: &'a str,
    kdf: &'a Kdf,
    vault_id: &'a str,
    revision: u64,
    salt: &'a str,
    password_wrap: &'a Sealed,
    recovery_wrap: &'a Sealed,
}
impl Envelope {
    pub(crate) fn new(password: &[u8]) -> Result<CreatedEnvelope> {
        validate_password(password)?;
        let key = Zeroizing::new(random::<32>()?);
        let recovery = Zeroizing::new(random::<32>()?);
        let salt = random::<16>()?;
        let vault_id = encode(&random::<16>()?);
        let wrapping = derive(password, &salt)?;
        let password_wrap = seal(&wrapping, &wrap_aad(&vault_id, "password")?, &*key)?;
        let recovery_wrap = seal(&recovery, &wrap_aad(&vault_id, "recovery")?, &*key)?;
        let envelope = Self {
            format: 1,
            cipher: CIPHER.into(),
            kdf: Kdf::standard(),
            vault_id,
            revision: 0,
            salt: encode(&salt),
            password_wrap,
            recovery_wrap,
            body: Sealed {
                nonce: String::new(),
                ciphertext: String::new(),
            },
        };
        Ok((envelope, key, recovery))
    }
    pub(crate) fn parse(bytes: &[u8]) -> Result<Self> {
        if bytes.len() > MAX_FILE_BYTES {
            return Err(VaultError::TooLarge);
        }
        let e: Self = serde_json::from_slice(bytes).map_err(|_| VaultError::InvalidFormat)?;
        if e.format != 1 || e.cipher != CIPHER || !e.kdf.valid() {
            return Err(VaultError::InvalidFormat);
        }
        decode_exact::<16>(&e.vault_id)?;
        decode_exact::<16>(&e.salt)?;
        for wrap in [&e.password_wrap, &e.recovery_wrap] {
            decode_exact::<12>(&wrap.nonce)?;
            decode_exact::<48>(&wrap.ciphertext)?;
        }
        decode_exact::<12>(&e.body.nonce)?;
        if e.body.ciphertext.len() < 22 || e.body.ciphertext.len() > MAX_FILE_BYTES {
            return Err(VaultError::InvalidFormat);
        }
        Ok(e)
    }
    pub(crate) fn unlock_password(&self, password: &[u8]) -> Result<Zeroizing<[u8; 32]>> {
        validate_password(password)?;
        let salt = decode_exact::<16>(&self.salt)?;
        let wrapping = derive(password, &salt)?;
        self.unwrap(&wrapping, &self.password_wrap, "password")
    }
    pub(crate) fn unlock_recovery(&self, recovery: &[u8; 32]) -> Result<Zeroizing<[u8; 32]>> {
        self.unwrap(recovery, &self.recovery_wrap, "recovery")
    }
    fn unwrap(
        &self,
        wrapping: &[u8; 32],
        sealed: &Sealed,
        role: &str,
    ) -> Result<Zeroizing<[u8; 32]>> {
        let clear = open(wrapping, &wrap_aad(&self.vault_id, role)?, sealed)?;
        let mut key = Zeroizing::new([0; 32]);
        if clear.len() != 32 {
            return Err(VaultError::WrongKeyOrCorrupt);
        }
        key.copy_from_slice(&clear);
        Ok(key)
    }
    pub(crate) fn rewrap_password(&mut self, password: &[u8], key: &[u8; 32]) -> Result<()> {
        let salt = random::<16>()?;
        let wrapping = derive(password, &salt)?;
        let sealed = seal(&wrapping, &wrap_aad(&self.vault_id, "password")?, key)?;
        self.salt = encode(&salt);
        self.password_wrap = sealed;
        Ok(())
    }
    fn aad(&self) -> Result<Vec<u8>> {
        serde_json::to_vec(&Header {
            domain: "heptabao-personal-vault/body/v1",
            format: self.format,
            cipher: &self.cipher,
            kdf: &self.kdf,
            vault_id: &self.vault_id,
            revision: self.revision,
            salt: &self.salt,
            password_wrap: &self.password_wrap,
            recovery_wrap: &self.recovery_wrap,
        })
        .map_err(|_| VaultError::InvalidFormat)
    }
    pub(crate) fn encrypt(&mut self, key: &[u8; 32], plaintext: &[u8]) -> Result<()> {
        self.body = seal(key, &self.aad()?, plaintext)?;
        Ok(())
    }
    pub(crate) fn decrypt(&self, key: &[u8; 32]) -> Result<Zeroizing<Vec<u8>>> {
        open(key, &self.aad()?, &self.body)
    }
}
fn wrap_aad(vault_id: &str, role: &str) -> Result<Vec<u8>> {
    serde_json::to_vec(&("heptabao-personal-vault/key-wrap/v1", 1, vault_id, role))
        .map_err(|_| VaultError::InvalidFormat)
}
fn derive(password: &[u8], salt: &[u8; 16]) -> Result<Zeroizing<[u8; 32]>> {
    let params = Params::new(65536, 3, 4, Some(32)).map_err(|_| VaultError::InvalidFormat)?;
    // Own the work area so every return path clears the 64 MiB KDF state.
    let mut memory = Zeroizing::new(vec![Block::default(); params.block_count()]);
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut out = Zeroizing::new([0; 32]);
    argon
        .hash_password_into_with_memory(password, salt, &mut *out, &mut *memory)
        .map_err(|_| VaultError::InvalidInput)?;
    Ok(out)
}
pub(crate) fn validate_password(password: &[u8]) -> Result<()> {
    if password.len() < 12 || password.len() > 1024 {
        Err(VaultError::InvalidInput)
    } else {
        Ok(())
    }
}
pub(crate) fn random<const N: usize>() -> Result<[u8; N]> {
    let mut bytes = [0; N];
    SystemRandom::new()
        .fill(&mut bytes)
        .map_err(|_| VaultError::RandomUnavailable)?;
    Ok(bytes)
}
fn seal(key: &[u8; 32], aad: &[u8], plaintext: &[u8]) -> Result<Sealed> {
    let key = aead::LessSafeKey::new(
        aead::UnboundKey::new(&aead::AES_256_GCM, key).map_err(|_| VaultError::InvalidFormat)?,
    );
    let nonce = random::<12>()?;
    let mut buffer = Zeroizing::new(plaintext.to_vec());
    key.seal_in_place_append_tag(
        aead::Nonce::assume_unique_for_key(nonce),
        aead::Aad::from(aad),
        &mut *buffer,
    )
    .map_err(|_| VaultError::WrongKeyOrCorrupt)?;
    Ok(Sealed {
        nonce: encode(&nonce),
        ciphertext: encode(&buffer),
    })
}
fn open(key: &[u8; 32], aad: &[u8], sealed: &Sealed) -> Result<Zeroizing<Vec<u8>>> {
    let key = aead::LessSafeKey::new(
        aead::UnboundKey::new(&aead::AES_256_GCM, key).map_err(|_| VaultError::InvalidFormat)?,
    );
    let nonce = decode_exact::<12>(&sealed.nonce)?;
    let mut buffer = Zeroizing::new(decode(&sealed.ciphertext)?);
    let len = key
        .open_in_place(
            aead::Nonce::assume_unique_for_key(nonce),
            aead::Aad::from(aad),
            &mut buffer,
        )
        .map_err(|_| VaultError::WrongKeyOrCorrupt)?
        .len();
    buffer.truncate(len);
    Ok(buffer)
}
pub(crate) fn digest(bytes: &[u8]) -> [u8; 32] {
    let hash = digest::digest(&digest::SHA256, bytes);
    let mut out = [0; 32];
    out.copy_from_slice(hash.as_ref());
    out
}
pub(crate) fn encode(bytes: &[u8]) -> String {
    STANDARD_NO_PAD.encode(bytes)
}
pub(crate) fn decode(value: &str) -> Result<Vec<u8>> {
    if value.len() > MAX_FILE_BYTES {
        return Err(VaultError::TooLarge);
    }
    let bytes = STANDARD_NO_PAD
        .decode(value)
        .map_err(|_| VaultError::InvalidFormat)?;
    if encode(&bytes) != value {
        return Err(VaultError::InvalidFormat);
    }
    Ok(bytes)
}
pub(crate) fn decode_exact<const N: usize>(value: &str) -> Result<[u8; N]> {
    if value.len() > N * 2 {
        return Err(VaultError::InvalidFormat);
    }
    let bytes = Zeroizing::new(decode(value)?);
    if bytes.len() != N {
        return Err(VaultError::InvalidFormat);
    }
    let mut out = [0; N];
    out.copy_from_slice(&bytes);
    Ok(out)
}
