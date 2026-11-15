//! Single-use external account binding keys remain inside encrypted PKI state.
//! An EAB proof authorizes only an ACME account, never a Vault Principal.
use super::acme_state::{Binding, Protocol, valid_directory, valid_identifier};
use super::*;
use crate::auth::Timestamp;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use openssl::{hash::MessageDigest, pkey::PKey, sign::Signer};

const MAX_KEYS: usize = 4096;
const PREFIX: &[u8] = b"\xbd\xab\xa5\xb7\xe7\x9a\x6f\xed\x3e";
pub(crate) const REQUIRED: &str =
    "the request must include a value for the 'externalAccountBinding' field";

#[derive(Clone, Serialize, Deserialize)]
#[serde(transparent)]
pub(crate) struct PrivateKey(Vec<u8>);
impl Drop for PrivateKey {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Registration {
    pub id: String,
    pub url: String,
    pub raw_jwk: Vec<u8>,
    pub private: PrivateKey,
    pub(in crate::engines) proof: SecretJson,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Key {
    pub id: String,
    pub owner: Binding,
    pub directory: String,
    pub created: Timestamp,
    pub created_on: String,
    pub key_digest: [u8; 32],
    pub private: Option<PrivateKey>,
    pub terminal: Option<Timestamp>,
    pub consumed_by: Option<String>,
}
impl Key {
    pub(crate) fn new(owner: &Binding, directory: &str, at: Timestamp) -> Result<Self> {
        owner.validate()?;
        if !valid_directory(directory) {
            return Err(error(503, "EAB directory owner rejected"));
        }
        let mut bytes = zeroize::Zeroizing::new(PREFIX.to_vec());
        bytes.extend_from_slice(
            &crate::crypto::random::<32>()
                .map_err(|_| error(503, "EAB key generation unavailable"))?,
        );
        let created_on = at
            .truncate_seconds()
            .local_rfc3339()
            .map_err(|_| error(503, "EAB public timestamp unavailable"))?;
        Ok(Self {
            id: identifier()?,
            owner: owner.clone(),
            directory: directory.to_owned(),
            created: at,
            created_on,
            key_digest: crate::crypto::digest(&bytes),
            private: Some(PrivateKey(bytes.to_vec())),
            terminal: None,
            consumed_by: None,
        })
    }
    pub(crate) fn descriptor(&self) -> Result<Value> {
        let private = self
            .private
            .as_ref()
            .ok_or_else(|| error(503, "EAB key is retired"))?;
        Ok(
            json!({"id":self.id,"key_type":"hs","key":URL_SAFE_NO_PAD.encode(&private.0),
            "acme_directory":format!("{}directory",self.directory),"created_on":self.created_on}),
        )
    }
    pub(crate) fn info(&self) -> Value {
        json!({"key_type":"hs","acme_directory":format!("{}directory",self.directory),"created_on":self.created_on})
    }
    pub(crate) fn retire(&mut self, at: Timestamp, account: Option<&str>) {
        self.private = None;
        self.terminal = Some(at);
        self.consumed_by = account.map(str::to_owned);
    }
}
pub(crate) fn identifier() -> Result<String> {
    let bytes = crate::crypto::random::<16>()
        .map_err(|_| error(503, "ACME identifier generation unavailable"))?;
    Ok(crate::crypto::uuid_from_bytes(&bytes))
}
impl Protocol {
    pub(crate) fn validate_eab(&self) -> Result<()> {
        if self.eab_keys.len() > MAX_KEYS {
            return Err(error(503, "EAB durable capacity rejected"));
        }
        for (id, key) in &self.eab_keys {
            if id != &key.id
                || !valid_identifier(id)
                || key.owner != self.owner
                || !valid_directory(&key.directory)
                || key.created > self.clock
                || !chrono::DateTime::parse_from_rfc3339(&key.created_on).is_ok_and(|at| {
                    u64::try_from(at.timestamp()).ok() == Some(key.created.seconds())
                })
                || key.private.is_some() != key.terminal.is_none()
                || key
                    .terminal
                    .is_some_and(|at| at < key.created || at > self.clock)
                || key.private.as_ref().is_some_and(|p| {
                    p.0.len() != 41
                        || !p.0.starts_with(PREFIX)
                        || crate::crypto::digest(&p.0) != key.key_digest
                })
                || key.consumed_by.as_ref().is_some_and(|account| {
                    self.accounts.get(account).is_none_or(|a| {
                        a.directory != key.directory
                            || a.created != key.terminal.unwrap_or(key.created)
                            || a.eab.as_ref().is_none_or(|r| r.id != key.id)
                    })
                })
            {
                return Err(error(503, "EAB durable key owner rejected"));
            }
        }
        for account in self.accounts.values() {
            if let Some(binding) = &account.eab {
                let key = self
                    .eab_keys
                    .get(&binding.id)
                    .ok_or_else(|| error(503, "EAB account key history missing"))?;
                if key.consumed_by.as_deref() != Some(&account.id)
                    || key.directory != account.directory
                    || binding.proof.0.as_object().is_none_or(|p| p.len() > 16)
                    || binding.proof.0["protected"]
                        .as_str()
                        .is_none_or(|s| s.len() > 16384)
                    || binding.proof.0["payload"]
                        .as_str()
                        .is_none_or(|s| s.len() > 32768)
                    || binding.proof.0["signature"]
                        .as_str()
                        .is_none_or(|s| s.len() > 1024)
                {
                    return Err(error(503, "EAB durable account binding rejected"));
                }
                let header = decode(
                    binding.proof.0["protected"].as_str().unwrap_or_default(),
                    16384,
                )?;
                let header: Value = serde_json::from_slice(&header)
                    .map_err(|_| error(503, "EAB durable proof rejected"))?;
                if header["kid"].as_str() != Some(&binding.id)
                    || header["url"].as_str() != Some(&binding.url)
                    || binding.url.len() > 4096
                    || !binding.url.ends_with("/new-account")
                    || binding.private.0.len() != 41
                    || !binding.private.0.starts_with(PREFIX)
                    || crate::crypto::digest(&binding.private.0) != key.key_digest
                    || binding.raw_jwk.len() > 16384
                {
                    return Err(error(503, "EAB durable proof owner rejected"));
                }
                let raw_jwk: Value = serde_json::from_slice(&binding.raw_jwk)
                    .map_err(|_| error(503, "EAB durable public JWK rejected"))?;
                if super::acme_jws::Jwk::from_public_json(&raw_jwk)? != account.jwk {
                    return Err(error(503, "EAB durable account JWK changed"));
                }
                verify_mac(
                    &binding.private,
                    &binding.url,
                    &binding.raw_jwk,
                    &binding.proof.0,
                )
                .map_err(|_| error(503, "EAB durable MAC or original JWK rejected"))?;
            }
        }
        Ok(())
    }
    pub(crate) fn validate_eab_successor(&self, previous: &Self) -> Result<()> {
        for (id, old) in &previous.eab_keys {
            let next = self
                .eab_keys
                .get(id)
                .ok_or_else(|| error(503, "EAB key history cannot disappear"))?;
            if old.owner != next.owner
                || old.directory != next.directory
                || old.created != next.created
                || old.created_on != next.created_on
                || old.key_digest != next.key_digest
                || old.terminal.is_some()
                    && (next.terminal != old.terminal
                        || next.consumed_by != old.consumed_by
                        || next.private.is_some())
                || old
                    .private
                    .as_ref()
                    .is_some_and(|private| next.private.as_ref().is_some_and(|n| private.0 != n.0))
            {
                return Err(error(503, "EAB key ownership or consumption regressed"));
            }
        }
        for (id, old) in &previous.accounts {
            let next = self
                .accounts
                .get(id)
                .ok_or_else(|| error(503, "EAB account history disappeared"))?;
            match (&old.eab, &next.eab) {
                (None, None) => {}
                (Some(a), Some(b))
                    if a.id == b.id
                        && a.proof.0 == b.proof.0
                        && a.url == b.url
                        && a.raw_jwk == b.raw_jwk
                        && a.private.0 == b.private.0 => {}
                _ => return Err(error(503, "EAB account binding cannot change")),
            }
        }
        Ok(())
    }
    pub(crate) fn insert_eab(&mut self, key: Key) -> Result<()> {
        if self.eab_keys.len() >= MAX_KEYS || self.eab_keys.contains_key(&key.id) {
            return Err(error(507, "EAB key capacity or collision rejected"));
        }
        self.eab_keys.insert(key.id.clone(), key);
        self.validate_eab()
    }
    pub(crate) fn verify_eab(
        &self,
        directory: &str,
        url: &str,
        raw_jwk: &[u8],
        proof: &Value,
    ) -> Result<Registration> {
        let field = |name: &str| {
            proof.get(name).and_then(Value::as_str).ok_or_else(|| {
                bad("invalid externalAccountBinding: the request message was malformed")
            })
        };
        let protected = field("protected")?;
        field("payload")?;
        field("signature")?;
        let header = decode(protected, 16384)?;
        let header: Value = serde_json::from_slice(&header)
            .map_err(|_| bad("invalid eab protected header: the request message was malformed"))?;
        let id=header["kid"].as_str().filter(|id|!id.is_empty())
            .ok_or_else(||bad("failed to json unmarshal eab 'protected': invalid header: got missing required field 'kid': the request message was malformed"))?;
        if !matches!(header["alg"].as_str(), Some("HS256" | "HS384" | "HS512")) {
            return Err(bad(
                "failed to json unmarshal eab 'protected': invalid header: unexpected value for 'algo': the request message was malformed",
            ));
        }
        let got = header["url"].as_str().unwrap_or_default();
        if got.is_empty() {
            return Err(bad(
                "missing required parameter 'url' in eab 'protected': the request message was malformed",
            ));
        }
        if got != url {
            return Err(error(
                401,
                &format!(
                    "invalid value for 'url' in eab 'protected': got '{got}' expected '{url}': the client lacks sufficient authorization"
                ),
            ));
        }
        if header.get("nonce").is_some_and(|v| v.as_str() != Some("")) {
            return Err(bad(
                "nonce should not be provided in eab 'protected': the request message was malformed",
            ));
        }
        let key = self
            .eab_keys
            .get(id)
            .filter(|key| key.directory == directory && key.private.is_some())
            .ok_or_else(|| {
                error(
                    401,
                    "the client lacks sufficient authorization: failed to verify eab",
                )
            })?;
        let private = key.private.as_ref().ok_or_else(|| {
            error(
                401,
                "the client lacks sufficient authorization: failed to verify eab",
            )
        })?;
        verify_mac(private, url, raw_jwk, proof)?;
        Ok(Registration {
            id: id.to_owned(),
            url: url.to_owned(),
            raw_jwk: raw_jwk.to_vec(),
            private: private.clone(),
            proof: SecretJson(proof.clone()),
        })
    }
}
fn decode(value: &str, maximum: usize) -> Result<Vec<u8>> {
    if value.len() > maximum.div_ceil(3) * 4 {
        return Err(bad("EAB proof exceeds bounds"));
    }
    let bytes = URL_SAFE_NO_PAD
        .decode(value)
        .map_err(|_| bad("invalid EAB base64url"))?;
    if bytes.len() > maximum || URL_SAFE_NO_PAD.encode(&bytes) != value {
        return Err(bad("invalid canonical EAB base64url"));
    }
    Ok(bytes)
}

fn verify_mac(private: &PrivateKey, url: &str, raw_jwk: &[u8], proof: &Value) -> Result<()> {
    let protected = proof["protected"]
        .as_str()
        .ok_or_else(|| bad("invalid EAB protected"))?;
    let payload = proof["payload"]
        .as_str()
        .ok_or_else(|| bad("invalid EAB payload"))?;
    let signature = proof["signature"]
        .as_str()
        .ok_or_else(|| bad("invalid EAB signature"))?;
    let header: Value = serde_json::from_slice(&decode(protected, 16384)?)
        .map_err(|_| bad("invalid EAB protected"))?;
    if header["url"].as_str() != Some(url)
        || header.get("nonce").is_some_and(|v| v.as_str() != Some(""))
    {
        return Err(bad("invalid EAB original URL or nonce"));
    }
    let digest = match header["alg"].as_str() {
        Some("HS256") => MessageDigest::sha256(),
        Some("HS384") => MessageDigest::sha384(),
        Some("HS512") => MessageDigest::sha512(),
        _ => {
            return Err(bad(
                "unsupported eab algorithm: the request message was malformed",
            ));
        }
    };
    let crypt = || error(500, "go-jose/go-jose: error in cryptographic primitive");
    // Genuine Go JOSE rejects its own 41-byte EAB key for HS384/HS512.
    if private.0.len() < digest.size() {
        return Err(crypt());
    }
    let hmac = PKey::hmac(&private.0).map_err(|_| crypt())?;
    let mut signer = Signer::new(digest, &hmac).map_err(|_| crypt())?;
    signer
        .update(format!("{protected}.{payload}").as_bytes())
        .map_err(|_| crypt())?;
    let expected = zeroize::Zeroizing::new(signer.sign_to_vec().map_err(|_| crypt())?);
    let signature = decode(signature, 1024)?;
    if expected.len() != signature.len() || !openssl::memcmp::eq(&expected, &signature) {
        return Err(crypt());
    }
    let submitted = decode(payload, 32768)?;
    if submitted != raw_jwk {
        return Err(bad(
            "eab payload does not match outer JWK key: the request message was malformed",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod native_identifier_tests {
    use super::*;
    #[test]
    fn pki_acme99_eab_native_identifier_bits_remain_readable_in_typed_key_state() -> Result<()> {
        let owner = Binding {
            cluster_id: "actual-native-id-bits".into(),
            namespace: "".into(),
            namespace_incarnation: Some(0),
            mount: "acmeca/".into(),
            mount_incarnation: 1,
        };
        for bytes in [
            [0u8; 16],
            [255u8; 16],
            [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
        ] {
            let id = crate::crypto::uuid_from_bytes(&bytes);
            let at =
                Timestamp::whole(100).map_err(|_| error(503, "fixture timestamp unavailable"))?;
            let mut protocol = Protocol::new(owner.clone(), at)?;
            let mut key = Key::new(&owner, "acme/", at)?;
            key.id = id.clone();
            protocol.eab_keys.insert(id.clone(), key);
            protocol.validate()?;
            assert_eq!(
                id.replace('-', ""),
                bytes.iter().map(|b| format!("{b:02x}")).collect::<String>()
            );
        }
        Ok(())
    }
}
