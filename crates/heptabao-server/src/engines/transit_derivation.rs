//! Measured OpenBao 2.7 ECDH and native context-derived Ed25519.
//! Scalar/curve/export extensions not yet measured remain explicit boundaries.
use super::*;
use openssl::{derive::Deriver, pkey::PKey};
use ring::hkdf;

#[derive(Clone, Copy, Eq, PartialEq, Serialize, Deserialize)]
pub(super) enum Format {
    #[serde(rename = "transit_derived_ed_v1")]
    V1,
}
pub(super) fn is_ed(key: &Key) -> bool {
    key.kind == "ed25519" && key.derived
}
struct Length(usize);
impl hkdf::KeyType for Length {
    fn len(&self) -> usize { self.0 }
}
pub(super) fn hkdf_material(master: &[u8], info: &[u8], length: usize) -> Result<Zeroizing<Vec<u8>>> {
    let salt = hkdf::Salt::new(hkdf::HKDF_SHA256, &[]);
    let prk = salt.extract(master);
    let info = [info];
    let okm = prk.expand(&info, Length(length)).map_err(|_| error(500, "key derivation failed"))?;
    let mut out = Zeroizing::new(vec![0; length]);
    okm.fill(&mut out).map_err(|_| error(500, "key derivation failed"))?;
    Ok(out)
}
pub(super) fn validate_ed_master(master: &[u8]) -> Result<()> {
    if master.len() != 64 { return Err(error(503, "invalid derived Ed25519 master length")); }
    let pair = signature::Ed25519KeyPair::from_seed_unchecked(&master[..32])
        .map_err(|_| error(503, "invalid derived Ed25519 master seed"))?;
    if pair.public_key().as_ref() != &master[32..] {
        return Err(error(503, "derived Ed25519 master seed and public key disagree"));
    }
    Ok(())
}
pub(super) fn generate_ed_version(now: u64) -> Result<KeyVersion> {
    let mut version = KeyVersion::generate("ed25519", now)?;
    let der = stored_material(&version.material)?;
    let pair = PKey::private_key_from_der(&der).map_err(|_| error(503, "generated Ed25519 key rejected"))?;
    let mut master = Zeroizing::new(pair.raw_private_key().map_err(|_| error(503, "generated Ed25519 seed unavailable"))?);
    master.extend(pair.raw_public_key().map_err(|_| error(503, "generated Ed25519 public key unavailable"))?);
    validate_ed_master(&master)?;
    version.material.zeroize();
    version.material = BASE64.encode(master.as_slice());
    Ok(version)
}
pub(super) fn ed_pair(key: &Key, version: &KeyVersion, body: &Value) -> Result<signature::Ed25519KeyPair> {
    if !is_ed(key) { return Err(error(503, "unexpected derived signing key type")); }
    let context = match body.get("context") {
        None | Some(Value::Null) => Zeroizing::new(Vec::new()),
        Some(Value::String(value)) => decode(value)?,
        _ => return Err(bad("context must be base64")),
    };
    if context.is_empty() {
        return Err(openbao_compatibility_error("error deriving key: missing 'context' for key derivation; the key was created using a derived key, which means additional, per-request information must be included in order to perform operations with the key"));
    }
    let master = stored_material(&version.material)?;
    validate_ed_master(&master)?;
    let seed = hkdf_material(&master, &context, 32)?;
    signature::Ed25519KeyPair::from_seed_unchecked(&seed)
        .map_err(|_| error(500, "derived signing seed is invalid"))
}
// Raw exports own the complete master or its base public half. Standard exports
// own a PKCS8/SPKI projection of that same master, never a context-derived child.
pub(super) fn export_ed(version: &KeyVersion, public: bool, format: &str) -> Result<Zeroizing<String>> {
    let master = stored_material(&version.material)?;
    validate_ed_master(&master)?;
    if matches!(format, "" | "raw") {
        return Ok(Zeroizing::new(BASE64.encode(if public { &master[32..] } else { master.as_slice() })));
    }
    let pair = PKey::private_key_from_raw_bytes(&master[..32], openssl::pkey::Id::ED25519)
        .map_err(|_| error(500, "derived Ed25519 export seed rejected"))?;
    let der = Zeroizing::new(pair.private_key_to_pkcs8().map_err(|_| error(500, "derived Ed25519 export projection rejected"))?);
    asymmetric::export_standard("ed25519", &der, public, format)
}
impl Transit {
    pub(in crate::engines) fn has_derived_ed_state(&self) -> bool {
        self.derived_ed_format.is_some() || self.keys.values().any(|key|
            is_ed(key) || (key.kind == "ed25519" && key.versions.values().any(|version|
                stored_material(&version.material).is_ok_and(|raw| raw.len() == 64))))
    }
    pub(in crate::engines) fn validate_derived_ed_state(&self, previous: Option<&Self>) -> Result<()> {
        if previous.is_some_and(Self::has_derived_ed_state) && self.derived_ed_format != Some(Format::V1) {
            return Err(error(503, "derived Ed25519 custody marker cannot be removed"));
        }
        for key in self.keys.values() {
            if key.kind == "ed25519" && !key.derived
                && key.versions.values().any(|version|
                    stored_material(&version.material).is_ok_and(|raw| raw.len() == 64))
            {
                return Err(error(503, "derived Ed25519 master cannot become an ordinary signing key"));
            }
            if !is_ed(key) { continue; }
            if self.derived_ed_format != Some(Format::V1) || key.convergent_encryption || key.legacy_counter_kdf
                || key.byok.is_some() || key.convergent_write_min_version != 0
                || key.latest_version == 0 || key.versions.keys().next_back() != Some(&key.latest_version)
            {
                return Err(error(503, "derived Ed25519 custody rejected"));
            }
            for version in key.versions.values() {
                if version.public_key_only.is_some() || version.external_key_ref.is_some()
                    || version.heptabao_convergent_version.is_some()
                    || stored_material(&version.hmac_material)?.len() != 32
                { return Err(error(503, "derived Ed25519 version owner rejected")); }
                validate_ed_master(&stored_material(&version.material)?)?;
            }
            backup::validate_key(key)?;
        }
        Ok(())
    }
    pub(super) fn derive_key(&mut self, method: &str, output: &str, body: &Value, now: u64) -> Result<EngineResponse> {
        if !write_method(method) { return Err(unsupported()); }
        valid_path(output)?;
        if output.is_empty() || output.contains('/') { return Err(bad("invalid derived key name")); }
        reject_unknown(body, &["base_key_name", "base_key_version", "derived_key_type", "key_derivation_algorithm", "peer_public_key"])?;
        let algorithm = body.get("key_derivation_algorithm").and_then(Value::as_str).unwrap_or("ecdh");
        if algorithm != "ecdh" { return Err(bad(&format!("key derivation algorithm {algorithm} not supported"))); }
        let kind = body.get("derived_key_type").map(|v| v.as_str().ok_or_else(|| bad("derived key type must be a string"))).transpose()?.unwrap_or("aes256-gcm96");
        if !symmetric::is_kind(kind) { return Err(bad(&format!("unknown key type {kind}"))); }
        let base = self.cached_policy(string(body, "base_key_name")?)?;
        base.alive()?;
        if !matches!(base.kind.as_str(), "ecdsa-p256" | "ecdsa-p384" | "ecdsa-p521") {
            return Err(bad("ECDH requires an EC base key"));
        }
        let requested = optional_u64(body, "base_key_version")?.unwrap_or(0);
        let selected = if requested == 0 { base.latest_version } else { requested };
        let version = base.versions.get(&selected).ok_or_else(|| openbao_compatibility_error("requested version of the base key is higher than the latest key version"))?;
        if version.public_key_only.is_some() { return Err(openbao_compatibility_error("base key does not contain a private part")); }
        let material = stored_material(&version.material)?;
        asymmetric_byok::validate_private(&base.kind, &material)?;
        let own = PKey::private_key_from_der(&material).map_err(|_| error(500, "stored EC base key rejected"))?;
        let pem = string(body, "peer_public_key")?;
        if pem.len() > MAX_INPUT_BYTES { return Err(error(413, "peer public key exceeds supported size")); }
        let peer = PKey::public_key_from_pem(pem.as_bytes()).map_err(|_| openbao_compatibility_error("failed to parse supplied peer public key PEM: data does not contain any valid public keys "))?;
        let own_ec = own.ec_key().map_err(|_| bad("ECDH requires an EC base key"))?;
        let peer_ec = peer.ec_key().map_err(|_| bad("ECDH peer requires an EC public key"))?;
        if own_ec.group().curve_name() != peer_ec.group().curve_name() {
            return Err(openbao_compatibility_error(&format!("base private key type {} does not match peer public key curve", base.kind)));
        }
        peer_ec.check_key().map_err(|_| bad("ECDH peer public key rejected"))?;
        let mut agreement = Deriver::new(&own).map_err(|_| error(500, "ECDH agreement rejected"))?;
        agreement.set_peer(&peer).map_err(|_| error(500, "ECDH peer rejected"))?;
        let shared = Zeroizing::new(agreement.derive_to_vec().map_err(|_| error(500, "ECDH agreement failed"))?);
        let derived = hkdf_material(&shared, &[], symmetric::key_len(kind))?;
        // The measured repeated-derive lane appends and preserves every old key/HMAC version.
        let mut prepared = self.clone();
        if let Some(key) = prepared.keys.get_mut(output) {
            key.alive()?;
            if key.kind != kind { return Err(bad("existing derived key has a different type")); }
            if !byok::imported_key(key) || key.derived || key.convergent_encryption {
                return Err(error(501, "ECDH into an existing native or protected key requires a measured contract"));
            }
            if key.versions.len() >= 10_000 { return Err(bad("key version retention limit reached")); }
            let next = key.latest_version.checked_add(1).ok_or_else(|| bad("key version limit reached"))?;
            let mut version = KeyVersion::generate(kind, now)?;
            version.material.zeroize();
            version.material = BASE64.encode(derived.as_slice());
            key.versions.insert(next, version);
            key.latest_version = next;
        } else {
            let mut key = Key::new(&json!({"type":kind}), now)?;
            let version = key.versions.get_mut(&1).ok_or_else(|| error(503, "new derived key version unavailable"))?;
            version.material.zeroize();
            version.material = BASE64.encode(derived.as_slice());
            key.byok = Some(byok::ecdh_import_policy());
            prepared.keys.insert(output.into(), key);
        }
        if prepared.wrapping_key.is_none() { prepared.wrapping_key = Some(byok::WrappingKey::new()?); }
        prepared.validate_byok_state()?;
        prepared.validate_derived_ed_state(Some(self))?;
        *self = prepared;
        Ok(empty(true))
    }
}
#[cfg(test)]
#[path = "transit_derivation_tests.rs"]
mod tests;
