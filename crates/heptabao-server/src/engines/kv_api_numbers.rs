//! OpenBao 2.7.1's KV2 data response decodes JSON numbers through float64.
//! This projection owns a separate response copy. The exact stored owner,
//! import, native payload graph and snapshot representation never pass here.
use super::*;
use zeroize::Zeroizing;

fn rejected() -> EngineError {
    error(500, "stored KV2 data cannot be represented by the OpenBao JSON API")
}

pub(super) fn project(data: &Value) -> Result<SecretJson> {
    let mut projected = SecretJson(data.clone());
    project_value(&mut projected.0)?;
    Ok(projected)
}

// The observed 2.7.1 public write rejects binary64 overflow before creating
// a version. This only validates ordinary KV2 POST/PUT/PATCH input; it neither
// rewrites finite tokens nor restricts lossless import or persisted history.
pub(super) fn validate_write(data: &Value) -> Result<()> {
    match data {
        Value::Number(number) => {
            let token = Zeroizing::new(number.to_string());
            if !token.parse::<f64>().is_ok_and(f64::is_finite) {
                return Err(bad("KV2 JSON number is outside the OpenBao API range"));
            }
        }
        Value::Array(values) => { for value in values { validate_write(value)?; } }
        Value::Object(values) => { for value in values.values() { validate_write(value)?; } }
        Value::Null | Value::Bool(_) | Value::String(_) => {}
    }
    Ok(())
}

fn project_value(value: &mut Value) -> Result<()> {
    match value {
        Value::Number(number) => {
            let exact = Zeroizing::new(number.to_string());
            let binary: f64 = exact.parse().map_err(|_| rejected())?;
            if !binary.is_finite() {
                return Err(rejected());
            }
            let encoded = go_float64(binary)?;
            *number = if encoded.as_str() == "-0" {
                // The pinned serde_json 1.0.151 parser reads this token as i64
                // zero. Its arbitrary-precision constructor is used solely
                // for this constant valid JSON token, never untrusted text.
                serde_json::Number::from_string_unchecked("-0".into())
            } else {
                encoded.parse().map_err(|_| rejected())?
            };
        }
        Value::Array(values) => {
            for value in values {
                project_value(value)?;
            }
        }
        Value::Object(values) => {
            // Private serde names in user objects remain ordinary field names.
            for value in values.values_mut() {
                project_value(value)?;
            }
        }
        Value::Null | Value::Bool(_) | Value::String(_) => {}
    }
    Ok(())
}

// encoding/json uses the shortest float64 decimal, fixed notation in
// [1e-6, 1e21), and an unpadded signed positive exponent outside that range.
// Rust's shortest LowerExp coefficient supplies the same binary64 digits;
// assembling the token here avoids serde's integral-float ".0" suffix.
fn go_float64(value: f64) -> Result<Zeroizing<String>> {
    if value == 0.0 {
        return Ok(Zeroizing::new(if value.is_sign_negative() {
            "-0".into()
        } else {
            "0".into()
        }));
    }
    let scientific = Zeroizing::new(format!("{value:e}"));
    let (coefficient, exponent) = scientific.split_once('e').ok_or_else(rejected)?;
    let exponent: i32 = exponent.parse().map_err(|_| rejected())?;
    if value.abs() < 1e-6 || value.abs() >= 1e21 {
        return Ok(Zeroizing::new(format!("{coefficient}e{exponent:+}")));
    }
    let (negative, coefficient) = coefficient
        .strip_prefix('-')
        .map_or((false, coefficient), |coefficient| (true, coefficient));
    let digits = Zeroizing::new(coefficient.replace('.', ""));
    let point = exponent + 1;
    let mut fixed = Zeroizing::new(String::with_capacity(32));
    if negative {
        fixed.push('-');
    }
    if point <= 0 {
        fixed.push_str("0.");
        fixed.extend(std::iter::repeat_n('0', (-point) as usize));
        fixed.push_str(&digits);
    } else if point as usize >= digits.len() {
        fixed.push_str(&digits);
        fixed.extend(std::iter::repeat_n('0', point as usize - digits.len()));
    } else {
        fixed.push_str(&digits[..point as usize]);
        fixed.push('.');
        fixed.push_str(&digits[point as usize..]);
    }
    Ok(fixed)
}

#[cfg(test)]
mod tests {
    use super::*;
    type TestResult = std::result::Result<(), Box<dyn std::error::Error>>;

    #[test]
    fn kv2_api_271_rounds_response_numbers_without_changing_stored_tokens() -> TestResult {
        // Actual OpenBao 2.7.1 Mac GET and sys/raw observations, bound in the
        // continuation receipt 9d46e5113eff82506ab1bc410ca86290410317b9786cdf76c5aec5a5c3e4d825.
        let source = lossless::decode_lossless_json(br#"{"wide_integer":9007199254740993,"exact_decimal":0.123456789012345678901234567890,"nested":[true,null,{"$serde_json::private::Number":"keep","n":9007199254740993}]}"#)?;
        let exact = serde_json::to_vec(&source)?;
        let mut owner = Kv2::default();
        owner.handle("POST", "data/item", &json!({"data":source}), 100)?;
        let stored = serde_json::to_vec(&owner)?;
        let reopened: Kv2 = serde_json::from_slice(&stored)?;
        let expected = lossless::decode_lossless_json(br#"{"wide_integer":9007199254740992,"exact_decimal":0.12345678901234568,"nested":[true,null,{"$serde_json::private::Number":"keep","n":9007199254740992}]}"#)?;
        for engine in [&owner, &reopened] {
            let read = engine.handle_read("GET", "data/item", &json!({}), 101)?;
            assert_eq!(read.status, 200);
            assert_eq!(read.body["data"]["data"], expected);
            assert_eq!(read.body["data"]["metadata"]["version"], 1);
            let value = engine.entries.get("item").ok_or("entry")?
                .versions.get(&1).ok_or("version")?.data.as_ref().ok_or("payload")?;
            assert_eq!(serde_json::to_vec(value.expose())?, exact);
            assert_eq!(serde_json::to_vec(engine)?, stored);
        }
        Ok(())
    }

    #[test]
    fn kv2_api_271_uses_go_float_notation_and_keeps_metadata_integers_exact() -> TestResult {
        // Actual six finite API observations: summary SHA256
        // 1281990796a3be2fc0064f0ffcb7fd2696b6bb7bf800e886e2534120e087481d.
        for (input, expected) in [
            ("1.0", "1"), ("-0", "-0"), ("1e-6", "0.000001"),
            ("1e-7", "1e-7"), ("1e20", "100000000000000000000"),
            ("1e21", "1e+21"),
            ("18446744073709551615", "18446744073709552000"),
        ] {
            let data = lossless::decode_lossless_json(format!("{{\"n\":{input}}}").as_bytes())?;
            let stored = serde_json::to_vec(&data)?;
            let projected = project(&data)?;
            assert_eq!(projected["n"].as_number().ok_or("number")?.to_string(), expected, "{input}");
            assert_eq!(serde_json::to_vec(&data)?, stored);
            let mut owner = Kv2::default();
            owner.handle("POST", "data/notation", &json!({"data":data}), 100)?;
            let persisted = serde_json::to_vec(&owner)?;
            let response = owner.handle_read("GET", "data/notation", &json!({}), 101)?;
            assert_eq!(serde_json::to_string(&response.body["data"]["data"])?,
                format!("{{\"n\":{expected}}}"), "{input}");
            assert_eq!(serde_json::to_vec(&owner)?, persisted);
        }
        let mut owner = Kv2::default();
        owner.handle("POST", "data/item", &json!({"data":{"n":1}}), 100)?;
        let entry = owner.entries.get_mut("item").ok_or("entry")?;
        entry.current_metadata_version = 9_007_199_254_740_993;
        let read = owner.handle_read("GET", "metadata/item", &json!({}), 101)?;
        assert_eq!(read.body["data"]["current_metadata_version"].as_u64(), Some(9_007_199_254_740_993));
        Ok(())
    }

    #[test]
    fn kv2_api_271_overflow_write_is_atomic_while_imported_storage_stays_exact() -> TestResult {
        let data = lossless::decode_lossless_json(br#"{"n":1e400}"#)?;
        let mut owner = Kv2::default();
        let before = serde_json::to_vec(&owner)?;
        let rejected = owner.handle("POST", "data/absent", &json!({"data":data,"options":{"cas":0}}), 100)
            .err().ok_or("overflow must be rejected")?;
        assert_eq!(rejected.status,400);
        assert_eq!(serde_json::to_vec(&owner)?,before);
        assert!(!owner.entries.contains_key("absent"));
        assert_eq!(owner.handle_read("GET","data/absent",&json!({}),101)
            .err().ok_or("absent version")?.status,404);
        owner.handle("POST","data/item",&json!({"data":{"kept":true}}),100)?;
        let before=serde_json::to_vec(&owner)?;
        assert_eq!(owner.handle("PATCH","data/item",&json!({"data":data,"options":{"cas":1}}),101)
            .err().ok_or("overflow PATCH must be rejected")?.status,400);
        assert_eq!(serde_json::to_vec(&owner)?,before);
        let bundle=json!({
            "schema":"openbao270-kv2-lossless-v1",
            "config":{"max_versions":1,"cas_required":false,"metadata_cas_required":false,"delete_version_after":"0s"},
            "entries":{"imported":{
                "created_time":"1970-01-01T00:01:40Z","updated_time":"1970-01-01T00:01:40Z",
                "current_version":1,"oldest_version":0,"current_metadata_version":0,
                "max_versions":1,"cas_required":false,"metadata_cas_required":false,
                "delete_version_after":"0s","custom_metadata":null,
                "versions":{"1":{"created_time":"1970-01-01T00:01:40Z","deletion_time":"","destroyed":false,"data":data}}
            }}
        });
        let imported=Kv2::from_lossless_import_json(&serde_json::to_vec(&bundle)?)?;
        let persisted=serde_json::to_vec(&imported)?;
        let reopened:Kv2=serde_json::from_slice(&persisted)?;
        for engine in [&imported,&reopened] {
            assert_eq!(engine.entries.get("imported").ok_or("entry")?.versions.get(&1)
                .ok_or("version")?.data.as_ref().ok_or("payload")?.expose(),&data);
            assert_eq!(engine.handle_read("GET","data/imported",&json!({}),101)
                .err().ok_or("nonfinite API projection must fail")?.status,500);
            assert_eq!(serde_json::to_vec(engine)?,persisted);
        }
        Ok(())
    }
}
