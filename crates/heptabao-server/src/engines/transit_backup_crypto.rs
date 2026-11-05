//! Typed native private-key backup fields. Decimal integers never pass through f64 or Value.
use super::*;
use openssl::{
    bn::{BigNum, BigNumContext},
    ec::{EcGroup, EcKey, EcPoint},
    nid::Nid,
    pkey::{Id, PKey},
    rsa::Rsa,
};
use serde_json::value::RawValue;

#[derive(Clone, PartialEq)]
pub(super) struct Decimal(String);
impl Drop for Decimal {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}
impl Decimal {
    fn from_bn(n: &openssl::bn::BigNumRef) -> Result<Self> {
        let decimal = n.to_dec_str().map_err(|_| bad("invalid backup integer"))?;
        Self::parse(decimal.as_ref()).map_err(|_| bad("invalid backup integer"))
    }
    fn parse(raw: &str) -> std::result::Result<Self, &'static str> {
        if raw.is_empty()
            || raw.len() > 1234
            || raw.as_bytes().iter().any(|c| !c.is_ascii_digit())
            || (raw.len() > 1 && raw.starts_with('0'))
        {
            return Err("a bounded canonical unsigned decimal integer is required");
        }
        let mut n = BigNum::from_dec_str(raw).map_err(|_| "invalid decimal integer")?;
        let bits = n.num_bits();
        n.clear();
        if bits > 4096 {
            return Err("backup integer exceeds 4096 bits");
        }
        Ok(Self(raw.into()))
    }
    fn bn(&self) -> Result<BigNum> {
        BigNum::from_dec_str(&self.0).map_err(|_| bad("invalid backup integer"))
    }
}
impl Serialize for Decimal {
    fn serialize<S: serde::Serializer>(&self, s: S) -> std::result::Result<S::Ok, S::Error> {
        RawValue::from_string(self.0.clone())
            .map_err(serde::ser::Error::custom)?
            .serialize(s)
    }
}
impl<'de> Deserialize<'de> for Decimal {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> std::result::Result<Self, D::Error> {
        let token = <&'de RawValue>::deserialize(d)?;
        Self::parse(token.get()).map_err(serde::de::Error::custom)
    }
}
#[derive(Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub(super) struct RsaCrt {
    #[serde(rename = "Dp")]
    dp: Decimal,
    #[serde(rename = "Dq")]
    dq: Decimal,
    #[serde(rename = "Qinv")]
    qinv: Decimal,
    #[serde(rename = "CRTValues")]
    crt_values: Vec<Value>,
}
#[derive(Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub(super) struct RsaPrivate {
    #[serde(rename = "N")]
    n: Decimal,
    #[serde(rename = "E")]
    e: u64,
    #[serde(rename = "D")]
    d: Decimal,
    #[serde(rename = "Primes")]
    primes: Vec<Decimal>,
    #[serde(rename = "Precomputed")]
    precomputed: RsaCrt,
}
fn curve(kind: &str) -> Result<Nid> {
    match kind {
        "ecdsa-p256" => Ok(Nid::X9_62_PRIME256V1),
        "ecdsa-p384" => Ok(Nid::SECP384R1),
        "ecdsa-p521" => Ok(Nid::SECP521R1),
        _ => Err(bad("invalid backup curve")),
    }
}
fn raw_key(entry: &Entry, max: usize) -> Result<Zeroizing<Vec<u8>>> {
    let raw = entry
        .key
        .as_deref()
        .ok_or_else(|| bad("backup key material is missing"))?;
    if raw.len() > max * 4 / 3 + 4 {
        return Err(bad("backup key material exceeds type bounds"));
    }
    let bytes = stored_material(raw)?;
    if bytes.len() > max || BASE64.encode(bytes.as_slice()) != raw {
        return Err(bad("invalid canonical backup key material"));
    }
    Ok(bytes)
}
fn no_math(entry: &Entry) -> bool {
    entry.ec_x.is_none() && entry.ec_y.is_none() && entry.ec_d.is_none() && entry.rsa_key.is_none()
}
pub(super) fn from_version(key: &Key, v: &KeyVersion, time: String) -> Result<Entry> {
    if v.public_key_only.is_some()
        || v.external_key_ref.is_some()
        || v.heptabao_convergent_version.is_some()
    {
        return Err(bad("backup requires complete native private material"));
    }
    let mut out = Entry::empty();
    out.hmac_key = Some(v.hmac_material.clone());
    out.creation_time = v.created_at;
    out.time = time;
    if derivation::is_ed(key) {
        let master = stored_material(&v.material)?;
        derivation::validate_ed_master(&master)?;
        out.key = Some(v.material.clone());
        out.public_key = BASE64.encode(&master[32..]);
    } else if symmetric::is_kind(&key.kind) {
        out.key = Some(v.material.clone());
    } else if key.kind == "hmac" {
        // Legacy unmarked HMAC keys retain their existing MAC material.
        out.key = Some(hmac_material(key, v).into());
    } else if mldsa::is_kind(&key.kind) {
        let seed = stored_material(&v.material)?;
        out.key = Some(v.material.clone());
        out.public_key = BASE64.encode(mldsa::public(&key.kind, &seed)?);
    } else {
        let bytes = stored_material(&v.material)?;
        let pair = PKey::private_key_from_der(&bytes)
            .map_err(|_| bad("invalid stored private backup key"))?;
        if asymmetric::is_rsa(&key.kind) {
            let r = pair.rsa().map_err(|_| bad("invalid backup RSA key"))?;
            let exponent = r
                .e()
                .to_dec_str()
                .map_err(|_| bad("invalid RSA exponent"))?
                .parse::<u64>()
                .map_err(|_| bad("RSA exponent exceeds supported bounds"))?;
            out.rsa_key = Some(RsaPrivate {
                n: Decimal::from_bn(r.n())?,
                e: exponent,
                d: Decimal::from_bn(r.d())?,
                primes: vec![
                    Decimal::from_bn(r.p().ok_or_else(|| bad("RSA prime missing"))?)?,
                    Decimal::from_bn(r.q().ok_or_else(|| bad("RSA prime missing"))?)?,
                ],
                precomputed: RsaCrt {
                    dp: Decimal::from_bn(r.dmp1().ok_or_else(|| bad("RSA CRT missing"))?)?,
                    dq: Decimal::from_bn(r.dmq1().ok_or_else(|| bad("RSA CRT missing"))?)?,
                    qinv: Decimal::from_bn(r.iqmp().ok_or_else(|| bad("RSA CRT missing"))?)?,
                    crt_values: Vec::new(),
                },
            });
        } else if key.kind == "ed25519" {
            let seed = Zeroizing::new(
                pair.raw_private_key()
                    .map_err(|_| bad("invalid Ed25519 seed"))?,
            );
            let public = pair
                .raw_public_key()
                .map_err(|_| bad("invalid Ed25519 public key"))?;
            if seed.len() != 32 || public.len() != 32 {
                return Err(bad("invalid Ed25519 backup key"));
            }
            let mut combined = Zeroizing::new(seed.to_vec());
            combined.extend_from_slice(&public);
            out.key = Some(BASE64.encode(combined.as_slice()));
            out.public_key = BASE64.encode(public);
        } else {
            let ec = pair.ec_key().map_err(|_| bad("invalid backup EC key"))?;
            let mut ctx = BigNumContext::new().map_err(|_| bad("EC context unavailable"))?;
            let mut x = BigNum::new().map_err(|_| bad("EC integer unavailable"))?;
            let mut y = BigNum::new().map_err(|_| bad("EC integer unavailable"))?;
            ec.public_key()
                .affine_coordinates_gfp(ec.group(), &mut x, &mut y, &mut ctx)
                .map_err(|_| bad("invalid backup EC coordinates"))?;
            out.ec_x = Some(Decimal::from_bn(&x)?);
            out.ec_y = Some(Decimal::from_bn(&y)?);
            out.ec_d = Some(Decimal::from_bn(ec.private_key())?);
            out.public_key = String::from_utf8(
                pair.public_key_to_pem()
                    .map_err(|_| bad("EC public encoding failed"))?,
            )
            .map_err(|_| bad("EC public encoding failed"))?;
        }
    }
    // Enforce the same complete typed and mathematical checks for export and import.
    material(&out, &key.kind, hmac_key_size(key))?;
    Ok(out)
}
pub(super) fn material(entry: &Entry, kind: &str, key_size: Option<u64>) -> Result<String> {
    if !entry.rsa_public_key.is_null()
        || !entry.certificate_chain.is_null()
        || !entry.external_key_ref.is_empty()
        || entry.convergent_version != 0
        || time_seconds(&entry.time)? != entry.creation_time
    {
        return Err(bad("invalid native backup key entry"));
    }
    let hmac = entry
        .hmac_key
        .as_deref()
        .ok_or_else(|| bad("backup HMAC material is missing"))?;
    if hmac.len() != 44
        || stored_material(hmac)?.len() != 32
        || BASE64.encode(stored_material(hmac)?.as_slice()) != hmac
    {
        return Err(bad("invalid backup HMAC material"));
    }
    if symmetric::is_kind(kind) || kind == "hmac" {
        if !no_math(entry) || !entry.public_key.is_empty() {
            return Err(bad("mixed symmetric backup material"));
        }
        let length = if kind == "hmac" {
            usize::try_from(key_size.ok_or_else(|| bad("HMAC key_size is missing"))?)
                .map_err(|_| bad("invalid HMAC key_size"))?
        } else {
            symmetric::key_len(kind)
        };
        if kind == "hmac" && !(32..=512).contains(&length) {
            return Err(bad("invalid HMAC key_size"));
        }
        let bytes = raw_key(entry, length)?;
        if bytes.len() != length {
            return Err(bad("invalid symmetric backup key length"));
        }
        return Ok(entry
            .key
            .as_deref()
            .ok_or_else(|| bad("backup key missing"))?
            .into());
    }
    if mldsa::is_kind(kind) {
        if !no_math(entry) {
            return Err(bad("mixed ML-DSA backup material"));
        }
        let seed = raw_key(entry, 32)?;
        if seed.len() != 32 || entry.public_key != BASE64.encode(mldsa::public(kind, &seed)?) {
            return Err(bad("ML-DSA backup seed and public key do not match"));
        }
        return Ok(BASE64.encode(seed.as_slice()));
    }
    let pair = if asymmetric::is_rsa(kind) {
        if entry.key.is_some()
            || entry.ec_x.is_some()
            || entry.ec_y.is_some()
            || entry.ec_d.is_some()
            || !entry.public_key.is_empty()
        {
            return Err(bad("mixed RSA backup material"));
        }
        let r = entry
            .rsa_key
            .as_ref()
            .ok_or_else(|| bad("RSA private backup fields are missing"))?;
        if r.primes.len() != 2 || !r.precomputed.crt_values.is_empty() || r.e < 3 || r.e % 2 == 0 {
            return Err(bad("unsupported or invalid RSA backup components"));
        }
        let rsa = Rsa::from_private_components(
            r.n.bn()?,
            BigNum::from_slice(&r.e.to_be_bytes()).map_err(|_| bad("RSA exponent invalid"))?,
            r.d.bn()?,
            r.primes[0].bn()?,
            r.primes[1].bn()?,
            r.precomputed.dp.bn()?,
            r.precomputed.dq.bn()?,
            r.precomputed.qinv.bn()?,
        )
        .map_err(|_| bad("invalid RSA backup components"))?;
        if !rsa
            .check_key()
            .map_err(|_| bad("invalid RSA backup arithmetic"))?
        {
            return Err(bad("invalid RSA backup arithmetic"));
        }
        PKey::from_rsa(rsa).map_err(|_| bad("invalid RSA backup key"))?
    } else if kind == "ed25519" {
        if !no_math(entry) {
            return Err(bad("mixed Ed25519 backup material"));
        }
        let combined = raw_key(entry, 64)?;
        if combined.len() != 64 {
            return Err(bad("invalid Ed25519 backup key length"));
        }
        let pair = PKey::private_key_from_raw_bytes(&combined[..32], Id::ED25519)
            .map_err(|_| bad("invalid Ed25519 backup seed"))?;
        let public = pair
            .raw_public_key()
            .map_err(|_| bad("invalid Ed25519 public key"))?;
        if public.as_slice() != &combined[32..] || entry.public_key != BASE64.encode(&public) {
            return Err(bad("Ed25519 backup seed and public key do not match"));
        }
        pair
    } else {
        if entry.key.is_some() || entry.rsa_key.is_some() {
            return Err(bad("mixed EC backup material"));
        }
        let group =
            EcGroup::from_curve_name(curve(kind)?).map_err(|_| bad("invalid backup curve"))?;
        let x = entry
            .ec_x
            .as_ref()
            .ok_or_else(|| bad("EC coordinate missing"))?
            .bn()?;
        let y = entry
            .ec_y
            .as_ref()
            .ok_or_else(|| bad("EC coordinate missing"))?
            .bn()?;
        let d = entry
            .ec_d
            .as_ref()
            .ok_or_else(|| bad("EC scalar missing"))?
            .bn()?;
        let mut ctx = BigNumContext::new().map_err(|_| bad("EC context unavailable"))?;
        let mut public = EcPoint::new(&group).map_err(|_| bad("EC point unavailable"))?;
        public
            .set_affine_coordinates_gfp(&group, &x, &y, &mut ctx)
            .map_err(|_| bad("invalid EC backup point"))?;
        let ec = EcKey::from_private_components(&group, &d, &public)
            .map_err(|_| bad("invalid EC backup components"))?;
        ec.check_key()
            .map_err(|_| bad("invalid EC backup arithmetic"))?;
        let pair = PKey::from_ec_key(ec).map_err(|_| bad("invalid EC backup key"))?;
        let encoded = String::from_utf8(
            pair.public_key_to_pem()
                .map_err(|_| bad("EC public encoding failed"))?,
        )
        .map_err(|_| bad("EC public encoding failed"))?;
        if entry.public_key != encoded {
            return Err(bad("EC backup public key does not match private key"));
        }
        pair
    };
    let der = Zeroizing::new(
        pair.private_key_to_pkcs8()
            .map_err(|_| bad("backup private encoding failed"))?,
    );
    asymmetric_byok::validate_private(kind, &der)?;
    Ok(BASE64.encode(der.as_slice()))
}
pub(super) fn validate_version(key: &Key, v: &KeyVersion) -> Result<()> {
    if v.public_key_only.is_some()
        || v.external_key_ref.is_some()
        || v.heptabao_convergent_version.is_some()
        || stored_material(&v.hmac_material)?.len() != 32
    {
        return Err(bad("invalid complete backup version"));
    }
    let raw = stored_material(&v.material)?;
    if derivation::is_ed(key) {
        derivation::validate_ed_master(&raw)?;
    } else if symmetric::is_kind(&key.kind) {
        if raw.len() != symmetric::key_len(&key.kind) {
            return Err(bad("invalid symmetric backup key length"));
        }
    } else if key.kind == "hmac" {
        if raw.len() != hmac_key_size(key).ok_or_else(|| bad("HMAC key_size missing"))? as usize {
            return Err(bad("invalid HMAC backup key length"));
        }
    } else if mldsa::is_kind(&key.kind) {
        mldsa::public(&key.kind, &raw)?;
    } else {
        asymmetric_byok::validate_private(&key.kind, &raw)?;
    }
    Ok(())
}
