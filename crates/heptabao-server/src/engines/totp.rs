//! RFC 6238 provider and generator. HMAC is supplied by ring. Successful
//! validation advances a persisted counter before the service releases `valid`.
use super::*;
use ring::{
    hmac,
    rand::{SecureRandom, SystemRandom},
};
use zeroize::Zeroizing;

#[derive(Clone, Serialize, Deserialize, Default)]
pub(super) struct Totp {
    keys: BTreeMap<String, Key>,
}

#[derive(Clone, Serialize, Deserialize)]
struct Key {
    secret: Vec<u8>,
    issuer: String,
    account_name: String,
    algorithm: String,
    digits: u32,
    period: u64,
    skew: u64,
    last_accepted_counter: Option<u64>,
    failed_window: u64,
    failures: u32,
}

impl Drop for Key {
    fn drop(&mut self) {
        self.secret.zeroize();
        self.issuer.zeroize();
        self.account_name.zeroize();
    }
}

impl Totp {
    pub(super) fn contains(&self, name: &str) -> bool {
        self.keys.contains_key(name)
    }

    pub(super) fn handle(
        &mut self,
        method: &str,
        path: &str,
        body: &Value,
        now: u64,
    ) -> Result<EngineResponse> {
        if path == "keys" || path == "keys/" {
            if method != "LIST" {
                return Err(unsupported());
            }
            let keys = list_keys(self.keys.keys(), "", false, body)?;
            if keys.is_empty() {
                return Err(not_found());
            }
            return Ok(ok(json!({"keys":keys}), false));
        }
        let (operation, name) = path
            .split_once('/')
            .ok_or_else(|| error(404, "unknown TOTP operation"))?;
        valid_path(name)?;
        if name.contains('/') {
            return Err(bad("TOTP key names must be a single path segment"));
        }
        match operation {
            "keys" if write_method(method) => self.write(name, body),
            "keys" if method == "DELETE" => Ok(empty(self.keys.remove(name).is_some())),
            "keys" if method == "GET" => {
                let key = self.keys.get(name).ok_or_else(not_found)?;
                Ok(ok(
                    json!({"issuer":key.issuer,"account_name":key.account_name,"algorithm":key.algorithm,"digits":key.digits,"period":key.period}),
                    false,
                ))
            }
            "code" if method == "GET" => {
                let key = self.keys.get(name).ok_or_else(not_found)?;
                let counter = now / key.period;
                let expiry = counter
                    .checked_add(1)
                    .and_then(|counter| counter.checked_mul(key.period))
                    .ok_or_else(|| bad("TOTP time overflow"))?;
                Ok(ok(
                    json!({"code":code(key, counter)?,"generated":now,"expire_time":expiry,"period":format!("{}s",key.period)}),
                    false,
                ))
            }
            "code" if write_method(method) => self.validate(name, body, now),
            _ => Err(unsupported()),
        }
    }

    fn write(&mut self, name: &str, body: &Value) -> Result<EngineResponse> {
        reject_unknown(
            body,
            &[
                "generate",
                "exported",
                "key_size",
                "url",
                "key",
                "issuer",
                "account_name",
                "period",
                "algorithm",
                "digits",
                "skew",
                "qr_size",
            ],
        )?;
        let generated = optional_bool(body, "generate")?.unwrap_or(false);
        let exported = optional_bool(body, "exported")?.unwrap_or(true);
        let mut parameters = SecretJson(body.clone());
        if let Some(url) = body.get("url").filter(|v| v.as_str() != Some("")) {
            if generated || body.get("key").is_some() {
                return Err(bad("specify exactly one TOTP secret source"));
            }
            let parsed = SecretJson(parse_url(
                url.as_str()
                    .ok_or_else(|| bad("TOTP URL must be a string"))?,
            )?);
            let map = parsed
                .as_object()
                .ok_or_else(|| bad("invalid TOTP URL parameters"))?;
            for (field, value) in map {
                if parameters
                    .get(field)
                    .is_some_and(|existing| existing != value)
                {
                    return Err(bad("TOTP URL conflicts with an explicit parameter"));
                }
                parameters[field] = value.clone();
            }
        }
        let issuer = parameters
            .get("issuer")
            .map(|v| v.as_str().ok_or_else(|| bad("issuer must be a string")))
            .transpose()?
            .unwrap_or("");
        let account = parameters
            .get("account_name")
            .map(|v| {
                v.as_str()
                    .ok_or_else(|| bad("account_name must be a string"))
            })
            .transpose()?
            .unwrap_or("");
        if issuer.len() > 256
            || account.len() > 256
            || issuer.contains(':')
            || issuer.chars().chain(account.chars()).any(char::is_control)
        {
            return Err(bad("invalid TOTP issuer or account label"));
        }
        if generated && (issuer.is_empty() || account.is_empty()) {
            return Err(bad("generated TOTP keys require issuer and account_name"));
        }
        if generated && (body.get("key").is_some() || body.get("url").is_some()) {
            return Err(bad("generated TOTP keys cannot also import a key"));
        }
        if generated && exported && optional_u64(body, "qr_size")?.unwrap_or(200) != 0 {
            return Err(error(
                501,
                "QR image generation is not implemented; set qr_size=0 for an otpauth URL",
            ));
        }
        let algorithm = parameters
            .get("algorithm")
            .map(|v| v.as_str().ok_or_else(|| bad("algorithm must be a string")))
            .transpose()?
            .unwrap_or("SHA1");
        hmac_algorithm(algorithm)?;
        let digits = optional_u64(&parameters, "digits")?.unwrap_or(6);
        if !matches!(digits, 6 | 8) {
            return Err(bad("TOTP digits must be 6 or 8"));
        }
        let period = optional_u64(&parameters, "period")?.unwrap_or(30);
        if !(1..=3600).contains(&period) {
            return Err(bad("TOTP period must be between 1 and 3600 seconds"));
        }
        let skew = optional_u64(&parameters, "skew")?.unwrap_or(1);
        if skew > 1 {
            return Err(bad("TOTP skew must be 0 or 1"));
        }
        let secret = if generated {
            let size = optional_u64(body, "key_size")?.unwrap_or(20);
            if !(10..=128).contains(&size) {
                return Err(bad("TOTP key_size must be between 10 and 128 bytes"));
            }
            let mut secret = Zeroizing::new(vec![0; size as usize]);
            SystemRandom::new()
                .fill(&mut secret)
                .map_err(|_| error(503, "system entropy is unavailable"))?;
            secret
        } else {
            decode_base32(string(&parameters, "key")?)?
        };
        if !(10..=128).contains(&secret.len()) {
            return Err(bad("TOTP secrets must contain between 10 and 128 bytes"));
        }
        let mut key = Key {
            secret: secret.to_vec(),
            issuer: issuer.into(),
            account_name: account.into(),
            algorithm: algorithm.into(),
            digits: digits as u32,
            period,
            skew,
            last_accepted_counter: None,
            failed_window: 0,
            failures: 0,
        };
        if let Some(previous) = self.keys.get(name)
            && previous.secret == key.secret
            && previous.algorithm == key.algorithm
            && previous.period == key.period
            && previous.digits == key.digits
        {
            // Metadata changes and re-import of the same seed cannot reset replay
            // or guessing protection. A different seed creates a new credential.
            key.last_accepted_counter = previous.last_accepted_counter;
            key.failed_window = previous.failed_window;
            key.failures = previous.failures;
        }
        let response = if generated && exported {
            let encoded_secret = Zeroizing::new(encode_base32(&secret));
            let url = Zeroizing::new(format!(
                "otpauth://totp/{}:{}?algorithm={}&digits={}&issuer={}&period={}&secret={}",
                percent_encode(issuer),
                percent_encode(account),
                algorithm,
                digits,
                percent_encode(issuer),
                period,
                *encoded_secret
            ));
            ok(json!({"url":&*url}), true)
        } else {
            empty(true)
        };
        self.keys.insert(name.into(), key);
        Ok(response)
    }

    fn validate(&mut self, name: &str, body: &Value, now: u64) -> Result<EngineResponse> {
        reject_unknown(body, &["code"])?;
        let submitted = string(body, "code")?;
        let key = self.keys.get_mut(name).ok_or_else(not_found)?;
        if submitted.len() != key.digits as usize || !submitted.bytes().all(|v| v.is_ascii_digit())
        {
            return Err(bad(
                "TOTP code must contain exactly the configured number of decimal digits",
            ));
        }
        let current = now / key.period;
        if current > key.failed_window {
            key.failed_window = current;
            key.failures = 0;
        }
        if key.failures >= 10 {
            return Err(error(
                429,
                "TOTP validation attempt limit reached for this period",
            ));
        }
        let mut matched = None;
        for counter in current.saturating_sub(key.skew)..=current.saturating_add(key.skew) {
            let expected = Zeroizing::new(code(key, counter)?);
            // A keyed constant-time verification from ring compares equal-length
            // OTP strings without an early exit revealing a matching prefix.
            let comparison_key = hmac::Key::new(hmac::HMAC_SHA256, &key.secret);
            let expected_tag = hmac::sign(&comparison_key, expected.as_bytes());
            if hmac::verify(&comparison_key, submitted.as_bytes(), expected_tag.as_ref()).is_ok()
                && key
                    .last_accepted_counter
                    .is_none_or(|accepted| counter > accepted)
            {
                matched = Some(counter);
            }
        }
        if let Some(counter) = matched {
            key.last_accepted_counter = Some(counter);
            key.failures = 0;
            Ok(ok(json!({"valid":true}), true))
        } else {
            key.failures += 1;
            Ok(ok(json!({"valid":false}), true))
        }
    }
}

fn hmac_algorithm(algorithm: &str) -> Result<hmac::Algorithm> {
    match algorithm {
        "SHA1" => Ok(hmac::HMAC_SHA1_FOR_LEGACY_USE_ONLY),
        "SHA256" => Ok(hmac::HMAC_SHA256),
        "SHA512" => Ok(hmac::HMAC_SHA512),
        _ => Err(bad("TOTP algorithm must be SHA1, SHA256 or SHA512")),
    }
}

fn code(key: &Key, counter: u64) -> Result<String> {
    let key_bytes = hmac::Key::new(hmac_algorithm(&key.algorithm)?, &key.secret);
    let tag = hmac::sign(&key_bytes, &counter.to_be_bytes());
    let bytes = tag.as_ref();
    let offset = usize::from(bytes[bytes.len() - 1] & 15);
    let truncated = (u32::from(bytes[offset] & 0x7f) << 24)
        | (u32::from(bytes[offset + 1]) << 16)
        | (u32::from(bytes[offset + 2]) << 8)
        | u32::from(bytes[offset + 3]);
    Ok(format!(
        "{:0width$}",
        truncated % 10u32.pow(key.digits),
        width = key.digits as usize
    ))
}

const BASE32: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

fn encode_base32(bytes: &[u8]) -> String {
    let mut output = String::new();
    let mut accumulator = 0u32;
    let mut bits = 0;
    for byte in bytes {
        accumulator = (accumulator << 8) | u32::from(*byte);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            output.push(BASE32[((accumulator >> bits) & 31) as usize] as char);
        }
        accumulator &= (1 << bits) - 1;
    }
    if bits > 0 {
        output.push(BASE32[((accumulator << (5 - bits)) & 31) as usize] as char);
    }
    output
}

fn decode_base32(text: &str) -> Result<Zeroizing<Vec<u8>>> {
    if text.len() > 256 {
        return Err(bad("TOTP key encoding exceeds supported size"));
    }
    let unpadded = text.trim_end_matches('=');
    if text.len() != unpadded.len()
        && (!text.len().is_multiple_of(8) || text.len() - unpadded.len() > 6)
    {
        return Err(bad("invalid base32 padding"));
    }
    let mut bytes = Zeroizing::new(Vec::new());
    let mut accumulator = 0u32;
    let mut bits = 0;
    for ch in unpadded.bytes() {
        let uppercase = ch.to_ascii_uppercase();
        let value = BASE32
            .iter()
            .position(|candidate| *candidate == uppercase)
            .ok_or_else(|| bad("invalid base32 TOTP key"))?;
        accumulator = (accumulator << 5) | value as u32;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            bytes.push((accumulator >> bits) as u8);
            accumulator &= (1 << bits) - 1;
        }
    }
    if accumulator != 0 || bits >= 5 {
        return Err(bad("noncanonical base32 TOTP key"));
    }
    Ok(bytes)
}

fn percent_decode(text: &str) -> Result<String> {
    let mut output = Zeroizing::new(Vec::new());
    let bytes = text.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'%' => {
                let pair = bytes
                    .get(i + 1..i + 3)
                    .ok_or_else(|| bad("invalid URL percent encoding"))?;
                let pair =
                    std::str::from_utf8(pair).map_err(|_| bad("invalid URL percent encoding"))?;
                output.push(
                    u8::from_str_radix(pair, 16)
                        .map_err(|_| bad("invalid URL percent encoding"))?,
                );
                i += 3;
            }
            b'+' => {
                output.push(b' ');
                i += 1;
            }
            byte => {
                output.push(byte);
                i += 1;
            }
        }
    }
    String::from_utf8(output.to_vec()).map_err(|_| bad("URL values must be UTF-8"))
}

fn percent_encode(text: &str) -> String {
    let mut result = String::new();
    for byte in text.bytes() {
        if byte.is_ascii_alphanumeric() || b"-._~".contains(&byte) {
            result.push(byte as char);
        } else {
            result.push_str(&format!("%{byte:02X}"));
        }
    }
    result
}

fn parse_url(url: &str) -> Result<Value> {
    if url.len() > 2048 || url.contains('#') {
        return Err(bad("invalid TOTP URL"));
    }
    let rest = url
        .strip_prefix("otpauth://totp/")
        .ok_or_else(|| bad("only otpauth TOTP URLs are supported"))?;
    let (label, query) = rest
        .split_once('?')
        .ok_or_else(|| bad("TOTP URL has no key parameters"))?;
    let label = Zeroizing::new(percent_decode(label)?);
    let mut params = SecretJson(json!({}));
    for pair in query.split('&') {
        let (field, value) = pair
            .split_once('=')
            .ok_or_else(|| bad("invalid TOTP URL parameter"))?;
        let field = percent_decode(field)?;
        let value = Zeroizing::new(percent_decode(value)?);
        let mapped = match field.as_str() {
            "secret" => "key",
            "issuer" => "issuer",
            "algorithm" => "algorithm",
            "digits" => "digits",
            "period" => "period",
            _ => return Err(bad("unsupported TOTP URL parameter")),
        };
        if params.get(mapped).is_some() {
            return Err(bad("duplicate TOTP URL parameter"));
        }
        params[mapped] = json!(&*value);
    }
    if let Some((issuer, account)) = label.split_once(':') {
        if params.get("issuer").is_some_and(|v| v != issuer) {
            return Err(bad("TOTP URL label and issuer disagree"));
        }
        params["issuer"] = json!(issuer);
        params["account_name"] = json!(account);
    } else {
        params["account_name"] = json!(&*label);
    }
    Ok(std::mem::take(&mut params.0))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc6238_all_eighteen_vectors() -> std::result::Result<(), Box<dyn std::error::Error>> {
        let vectors = [
            (59, ["94287082", "46119246", "90693936"]),
            (1111111109, ["07081804", "68084774", "25091201"]),
            (1111111111, ["14050471", "67062674", "99943326"]),
            (1234567890, ["89005924", "91819424", "93441116"]),
            (2000000000, ["69279037", "90698825", "38618901"]),
            (20000000000, ["65353130", "77737706", "47863826"]),
        ];
        for (index, (algorithm, size)) in [("SHA1", 20), ("SHA256", 32), ("SHA512", 64)]
            .iter()
            .enumerate()
        {
            let secret: Vec<u8> = (0..*size)
                .map(|n| b'1' + (n % 10) as u8)
                .map(|b| if b == b':' { b'0' } else { b })
                .collect();
            let key = Key {
                secret,
                issuer: String::new(),
                account_name: String::new(),
                algorithm: (*algorithm).into(),
                digits: 8,
                period: 30,
                skew: 1,
                last_accepted_counter: None,
                failed_window: 0,
                failures: 0,
            };
            for (time, expected) in vectors {
                assert_eq!(code(&key, time / 30)?, expected[index]);
            }
        }
        Ok(())
    }

    #[test]
    fn rfc4648_base32_encoding_and_invalid_forms()
    -> std::result::Result<(), Box<dyn std::error::Error>> {
        for (plain, encoded) in [
            ("f", "MY"),
            ("fo", "MZXQ"),
            ("foo", "MZXW6"),
            ("foob", "MZXW6YQ"),
            ("fooba", "MZXW6YTB"),
            ("foobar", "MZXW6YTBOI"),
        ] {
            assert_eq!(encode_base32(plain.as_bytes()), encoded);
            assert_eq!(&*decode_base32(encoded)?, plain.as_bytes());
        }
        for invalid in ["M", "MZ", "MY====", "MY======!", "M!", "MY=AAAAA"] {
            assert!(decode_base32(invalid).is_err());
        }
        Ok(())
    }
}
