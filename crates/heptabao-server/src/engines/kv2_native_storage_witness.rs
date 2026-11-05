//! Exact single-version evidence from the authenticated paged payload reader.
//! This codec does not grant an Actor, request clock, physical source or delivery.
use super::*;
use serde::ser::{SerializeMap, SerializeSeq};

fn rejected() -> EngineError {
    error(
        503,
        "native KV2 storage witness custody or payload rejected",
    )
}

// The independent profile uses Python's exact Decimal string form for JSON
// tokens containing a decimal point or exponent. This affects evidence bytes
// only: the retained Number and its storage/export representation never change.
// Keep exponent arithmetic decimal and bounded by the input's byte length;
// neither a machine-integer exponent nor a floating-point conversion is needed.
#[derive(Clone)]
struct NumberExponent {
    negative: bool,
    digits: Zeroizing<Vec<u8>>,
}

fn magnitude(left: &[u8], right: &[u8]) -> std::cmp::Ordering {
    left.len().cmp(&right.len()).then_with(|| left.cmp(right))
}

fn combine_digits(left: &[u8], right: &[u8], subtract: bool) -> CodecResult<Zeroizing<Vec<u8>>> {
    let mut output = Zeroizing::new(Vec::with_capacity(left.len().max(right.len()) + 1));
    let mut left = left.iter().rev();
    let mut right = right.iter().rev();
    let mut carry = 0;
    for _ in 0..left.len().max(right.len()) {
        let a = left.next().map_or(0, |digit| digit - b'0');
        let b = right.next().map_or(0, |digit| digit - b'0');
        let digit = if subtract {
            let subtrahend = b + carry;
            carry = u8::from(a < subtrahend);
            a + 10 * carry - subtrahend
        } else {
            let sum = a + b + carry;
            carry = sum / 10;
            sum % 10
        };
        output.push(b'0' + digit);
    }
    if carry != 0 {
        if subtract {
            return Err(RecordError::Invalid);
        }
        output.push(b'0' + carry);
    }
    while output.len() > 1 && output.last() == Some(&b'0') {
        output.pop();
    }
    output.reverse();
    Ok(output)
}

impl NumberExponent {
    fn parse(text: &str) -> CodecResult<Self> {
        let negative = text.starts_with('-');
        let digits = text.strip_prefix(['+', '-']).unwrap_or(text);
        if digits.is_empty() || !digits.bytes().all(|byte| byte.is_ascii_digit()) {
            return Err(RecordError::Invalid);
        }
        let trimmed = digits.trim_start_matches('0');
        let digits = if trimmed.is_empty() { "0" } else { trimmed };
        Ok(Self {
            negative: negative && digits != "0",
            digits: Zeroizing::new(digits.as_bytes().to_vec()),
        })
    }

    fn shift(&mut self, subtract: bool, amount: usize) -> CodecResult<()> {
        if amount == 0 {
            return Ok(());
        }
        let amount = amount.to_string();
        let digits = amount.as_bytes();
        if self.negative == subtract {
            self.digits = combine_digits(&self.digits, digits, false)?;
        } else {
            match magnitude(&self.digits, digits) {
                std::cmp::Ordering::Greater => {
                    self.digits = combine_digits(&self.digits, digits, true)?;
                }
                std::cmp::Ordering::Equal => {
                    self.digits = Zeroizing::new(vec![b'0']);
                    self.negative = false;
                }
                std::cmp::Ordering::Less => {
                    self.digits = combine_digits(digits, &self.digits, true)?;
                    self.negative = subtract;
                }
            }
        }
        Ok(())
    }

    fn positive(&self) -> bool {
        !self.negative && self.digits.as_slice() != b"0"
    }

    fn below_fixed_threshold(&self) -> bool {
        self.negative && magnitude(&self.digits, b"6").is_gt()
    }

    fn fixed_places(&self) -> CodecResult<usize> {
        // Only reached when the adjusted exponent is at least -6 and the
        // quantum is nonpositive, so expansion is bounded by the coefficient.
        self.digits.iter().try_fold(0_usize, |number, digit| {
            number
                .checked_mul(10)
                .and_then(|number| number.checked_add(usize::from(digit - b'0')))
                .ok_or(RecordError::TooLarge)
        })
    }
}

fn number_capacity(parts: &[usize]) -> CodecResult<usize> {
    let bytes = parts
        .iter()
        .try_fold(0_usize, |bytes, part| bytes.checked_add(*part))
        .ok_or(RecordError::TooLarge)?;
    if bytes > MAX_VALUE_BYTES {
        return Err(RecordError::TooLarge);
    }
    Ok(bytes)
}

fn canonical_number(value: &serde_json::Number) -> CodecResult<Zeroizing<String>> {
    let text = value.as_str();
    number_capacity(&[text.len()])?;
    let negative = text.starts_with('-');
    let unsigned = text.strip_prefix('-').unwrap_or(text);
    let (mantissa, explicit) = unsigned.split_once(['e', 'E']).unwrap_or((unsigned, "0"));
    if !unsigned.contains(['.', 'e', 'E']) {
        return Ok(Zeroizing::new(text.to_owned()));
    }
    let fractional_digits = mantissa
        .split_once('.')
        .map_or(0, |(_, fraction)| fraction.len());
    let coefficient = Zeroizing::new(
        mantissa
            .chars()
            .filter(|character| *character != '.')
            .collect::<String>(),
    );
    let trimmed = coefficient.trim_start_matches('0');
    let coefficient = if trimmed.is_empty() { "0" } else { trimmed };
    let mut quantum = NumberExponent::parse(explicit)?;
    quantum.shift(true, fractional_digits)?;
    let mut adjusted = quantum.clone();
    adjusted.shift(false, coefficient.len() - 1)?;
    let scientific = quantum.positive() || adjusted.below_fixed_threshold();
    let places = if scientific {
        0
    } else {
        quantum.fixed_places()?
    };
    let capacity = if scientific {
        number_capacity(&[
            usize::from(negative),
            coefficient.len(),
            usize::from(coefficient.len() > 1),
            2,
            adjusted.digits.len(),
        ])?
    } else if places == 0 {
        number_capacity(&[usize::from(negative), coefficient.len()])?
    } else {
        let integer_and_fraction = coefficient
            .len()
            .max(places.checked_add(1).ok_or(RecordError::TooLarge)?);
        number_capacity(&[usize::from(negative), integer_and_fraction, 1])?
    };
    let mut output = Zeroizing::new(String::with_capacity(capacity));
    if negative {
        output.push('-');
    }
    if scientific {
        output.push(char::from(coefficient.as_bytes()[0]));
        if coefficient.len() > 1 {
            output.push('.');
            output.push_str(&coefficient[1..]);
        }
        output.push('E');
        output.push(if adjusted.negative { '-' } else { '+' });
        output.extend(adjusted.digits.iter().map(|byte| char::from(*byte)));
    } else if places == 0 {
        output.push_str(coefficient);
    } else if places < coefficient.len() {
        let split = coefficient.len() - places;
        output.push_str(&coefficient[..split]);
        output.push('.');
        output.push_str(&coefficient[split..]);
    } else {
        output.push_str("0.");
        output.extend(std::iter::repeat_n('0', places - coefficient.len()));
        output.push_str(coefficient);
    }
    Ok(output)
}

struct CanonicalJson<'a>(&'a Value);
impl Serialize for CanonicalJson<'_> {
    fn serialize<S: serde::Serializer>(
        &self,
        serializer: S,
    ) -> std::result::Result<S::Ok, S::Error> {
        match self.0 {
            Value::Null => serializer.serialize_none(),
            Value::Bool(value) => serializer.serialize_bool(*value),
            Value::Number(value) => {
                let canonical = canonical_number(value).map_err(|_| {
                    <S::Error as serde::ser::Error>::custom("canonical witness number rejected")
                })?;
                // Borrow the generated numeric token as raw JSON. Parsing it
                // back into Number would normalize E to e again; serialize_str
                // would instead change its JSON type. Neither is this profile.
                let raw = serde_json::from_str::<&serde_json::value::RawValue>(&canonical)
                    .map_err(|_| {
                        <S::Error as serde::ser::Error>::custom("canonical witness number rejected")
                    })?;
                raw.serialize(serializer)
            }
            Value::String(value) => serializer.serialize_str(value),
            Value::Array(values) => {
                let mut sequence = serializer.serialize_seq(Some(values.len()))?;
                for value in values {
                    sequence.serialize_element(&CanonicalJson(value))?;
                }
                sequence.end()
            }
            Value::Object(values) => {
                // Explicit order makes the profile independent of serde's map
                // implementation. Valid UTF-8 lexicographic order agrees with
                // Unicode scalar-value order used by the controller.
                let ordered: BTreeMap<&str, &Value> = values
                    .iter()
                    .map(|(key, value)| (key.as_str(), value))
                    .collect();
                let mut map = serializer.serialize_map(Some(ordered.len()))?;
                for (key, value) in ordered {
                    map.serialize_entry(key, &CanonicalJson(value))?;
                }
                map.end()
            }
        }
    }
}

fn fingerprint(value: &Value) -> Result<(String, usize)> {
    let bytes = serialize(&CanonicalJson(value), MAX_VALUE_BYTES).map_err(|_| rejected())?;
    let digest = crate::crypto::digest(&bytes);
    let hash = digest
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    Ok((hash, bytes.len()))
}

impl NativeReadView {
    pub(crate) fn storage_version_witness(
        &self,
        path: &str,
        selected: u64,
        reader: &impl RecordReader,
        check: &impl Fn() -> CodecResult<()>,
    ) -> Result<Value> {
        check().map_err(|_| rejected())?;
        if selected == 0 {
            return Err(bad("a positive explicit version is required"));
        }
        valid_path(path)?;
        if !self.is_paged() {
            return Err(error(501, "storage witness requires native paged KV2"));
        }
        self.validate_paged_metadata().map_err(|_| rejected())?;
        let entry = self.owner.entries.get(path).ok_or_else(not_found)?;
        let version = entry.versions.get(&selected).ok_or_else(not_found)?;
        let precise = entry.version_precision(selected);
        let graph = self.graph.as_ref().ok_or_else(rejected)?;
        let descriptor = graph
            .paged
            .as_ref()
            .ok_or_else(rejected)?
            .descriptors
            .get(path)
            .and_then(|versions| versions.get(&selected));
        let (hash, bytes) = if version.destroyed {
            if descriptor.is_some() || version.data.is_some() {
                return Err(rejected());
            }
            (None, 0)
        } else {
            // Soft deletion controls public readability only. Retained bytes
            // are authenticated using the original path/version descriptor,
            // without changing time, undeleting, or using the API projection.
            let data = descriptor
                .ok_or_else(rejected)?
                .read(&graph.key, path, selected, reader, check)
                .map_err(|_| rejected())?;
            check().map_err(|_| rejected())?;
            let (hash, bytes) = fingerprint(data.expose())?;
            drop(data);
            check().map_err(|_| rejected())?;
            (Some(hash), bytes)
        };
        check().map_err(|_| rejected())?;
        Ok(json!({
            "schema":"heptabao-native-kv2-storage-witness-v1",
            "canonical_profile":"heptabao-lossless-json-v1",
            "path":path, "version":selected,
            "created_time":lossless::display_time(version.created_at, precise.created_at),
            "deletion_time":version.deletion_at
                .map(|seconds| lossless::display_time(seconds, precise.deletion_at)).unwrap_or_default(),
            "destroyed":version.destroyed,
            "payload_present":!version.destroyed,
            "payload_canonical_sha256":hash,
            "payload_canonical_bytes":bytes,
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    type TestResult = std::result::Result<(), Box<dyn std::error::Error>>;

    fn vector() -> Result<Value> {
        lossless::decode_lossless_json(
            r#"{"z":9007199254740993,"unicode":"凭证迁移试验🧪","nested":[null,true,{"zero":"\\u0000"}],"a":0.123456789012345678901234567890}"#.as_bytes(),
        )
    }

    #[test]
    fn native_kv2_storage_witness_canonical_profile_matches_independent_python_vector() -> TestResult
    {
        let data = vector()?;
        let (hash, bytes) = fingerprint(&data)?;
        assert_eq!(bytes, 134);
        assert_eq!(
            hash,
            "8f55c32f8c1f2f2a8d0e5cc14f08b7007ae6ca496782cdc2ae84143879b40395"
        );
        assert_eq!(
            data["a"].as_number().ok_or("decimal")?.to_string(),
            "0.123456789012345678901234567890"
        );
        assert_eq!(
            data["z"].as_number().ok_or("integer")?.to_string(),
            "9007199254740993"
        );
        assert_eq!(
            data["nested"][2]["zero"]
                .as_str()
                .ok_or("escaped string")?
                .len(),
            6
        );
        Ok(())
    }

    #[test]
    fn native_kv2_storage_witness_reads_retained_soft_delete_and_rejects_torn_payload() -> TestResult
    {
        let mut owner = Kv2::default();
        for _ in 0..3 {
            owner.handle("POST", "data/history", &json!({"data":vector()?}), 100)?;
        }
        owner.handle("POST", "delete/history", &json!({"versions":[1]}), 101)?;
        owner.handle("POST", "destroy/history", &json!({"versions":[2]}), 102)?;
        let parent = AddressKey::from_bytes([67; 32]);
        let scope = NativeScope {
            namespace: "",
            mount: "secret/",
            incarnation: 1,
        };
        let graph = NativeCellGraph::encode_paged(&owner, &parent, scope, &|| Ok(()))?;
        let mut objects = GraphObjects(BTreeMap::new());
        graph.visit_objects(
            |object| {
                objects.0.insert(object.reference().id, Arc::clone(object));
                Ok(())
            },
            &|| Ok(()),
        )?;
        let view =
            NativeReadView::open_paged_checked(&parent, scope, graph.root(), &objects, &|| Ok(()))?;
        let original_root = graph.root();
        for number in [1, 3] {
            let witness = view.storage_version_witness("history", number, &objects, &|| Ok(()))?;
            assert_eq!(witness["payload_canonical_bytes"], 134);
            assert_eq!(
                witness["payload_canonical_sha256"],
                "8f55c32f8c1f2f2a8d0e5cc14f08b7007ae6ca496782cdc2ae84143879b40395"
            );
            assert_eq!(witness["payload_present"], true);
            assert_eq!(witness["destroyed"], false);
            assert_eq!(
                witness["deletion_time"].as_str().ok_or("time")?.is_empty(),
                number == 3
            );
        }
        let absent = view.storage_version_witness("history", 2, &objects, &|| Ok(()))?;
        assert_eq!(absent["destroyed"], true);
        assert_eq!(absent["payload_present"], false);
        assert_eq!(absent["payload_canonical_bytes"], 0);
        assert!(absent["payload_canonical_sha256"].is_null());
        assert_eq!(
            view.read_with_source(
                "GET",
                "data/history",
                &json!({"version":1}),
                Timestamp::checked(103, 0)?,
                &objects
            )?
            .status,
            404
        );
        let public = view.read_with_source(
            "GET",
            "data/history",
            &json!({"version":3}),
            Timestamp::checked(103, 0)?,
            &objects,
        )?;
        assert_eq!(
            public.body["data"]["data"]["z"]
                .as_number()
                .ok_or("public integer")?
                .to_string(),
            "9007199254740992"
        );
        assert_eq!(
            view.graph.as_ref().ok_or("graph")?.index.root(),
            original_root
        );
        assert!(
            view.storage_version_witness("history", 0, &objects, &|| Ok(()))
                .is_err()
        );
        assert!(
            view.storage_version_witness("history", 4, &objects, &|| Ok(()))
                .is_err()
        );
        assert!(
            view.storage_version_witness("history", 3, &objects, &|| Err(RecordError::Invalid))
                .is_err()
        );
        let reference = view
            .graph
            .as_ref()
            .ok_or("graph")?
            .paged
            .as_ref()
            .ok_or("paged")?
            .descriptors
            .get("history")
            .ok_or("path")?
            .get(&3)
            .ok_or("version")?
            .blocks[0]
            .id;
        objects.0.remove(&reference).ok_or("stored block")?;
        assert!(
            view.storage_version_witness("history", 3, &objects, &|| Ok(()))
                .is_err()
        );
        Ok(())
    }

    #[test]
    fn witness_decimal_profile_matches_original_python_number_vectors() -> TestResult {
        // Expected spellings come from the unchanged Python canonical helper.
        for (input, expected) in [
            ("0", "0"),
            ("1", "1"),
            ("-1", "-1"),
            ("18446744073709551617", "18446744073709551617"),
            ("-18446744073709551617", "-18446744073709551617"),
            ("0.0", "0.0"),
            ("-0.0", "-0.0"),
            ("0.000", "0.000"),
            ("-0.000", "-0.000"),
            ("0e0", "0"),
            ("-0e0", "-0"),
            ("0e-6", "0.000000"),
            ("-0e-6", "-0.000000"),
            ("0e-7", "0E-7"),
            ("-0e-7", "-0E-7"),
            ("0e10", "0E+10"),
            ("-0e10", "-0E+10"),
            ("1e-50", "1E-50"),
            ("1E-50", "1E-50"),
            ("1e-6", "0.000001"),
            ("1e-7", "1E-7"),
            ("-1e-6", "-0.000001"),
            ("-1e-7", "-1E-7"),
            ("1e0", "1"),
            ("1.0e0", "1.0"),
            ("10e2", "1.0E+3"),
            ("100e-2", "1.00"),
            ("1.00e-2", "0.0100"),
            ("0.0000010", "0.0000010"),
            ("0.00000010", "1.0E-7"),
            ("0.000000000123", "1.23E-10"),
            ("1000000e-6", "1.000000"),
            ("123000.00e-6", "0.12300000"),
            ("1.2300E+0010", "1.2300E+10"),
            ("1.2300E-0010", "1.2300E-10"),
            ("1.00E+0000", "1.00"),
            ("1.00E-0000", "1.00"),
            ("100.00e-2", "1.0000"),
            (
                "0.123456789012345678901234567890",
                "0.123456789012345678901234567890",
            ),
            (
                "3.141592653589793238462643383279",
                "3.141592653589793238462643383279",
            ),
            (
                "1.2345678901234567890123456789012345678900e100",
                "1.2345678901234567890123456789012345678900E+100",
            ),
            (
                "1.2345678901234567890123456789012345678900e-100",
                "1.2345678901234567890123456789012345678900E-100",
            ),
            ("1e999999999999999999", "1E+999999999999999999"),
            ("1e-999999999999999999", "1E-999999999999999999"),
            (
                "999999999999999999999999999999999999999.00000",
                "999999999999999999999999999999999999999.00000",
            ),
            (
                "0.0000000000000000000000000000000000000000000000000010000",
                "1.0000E-51",
            ),
        ] {
            let value = lossless::decode_lossless_json(input.as_bytes())?;
            let before = serialize(&value, MAX_VALUE_BYTES)?;
            let actual = serialize(&CanonicalJson(&value), MAX_VALUE_BYTES)?;
            assert_eq!(actual.as_slice(), expected.as_bytes(), "{input}");
            assert_eq!(
                serialize(&value, MAX_VALUE_BYTES)?.as_slice(),
                before.as_slice()
            );
        }
        Ok(())
    }

    #[test]
    fn witness_decimal_profile_keeps_json_kinds_strings_and_signed_zero() -> TestResult {
        let value = lossless::decode_lossless_json(
            br#"{"E":"e","tiny":1e-50,"text":"1e-50|1E-50","nested":[false,null,{"$serde_json::private::Number":"1e-50"}]}"#,
        )?;
        let expected = br#"{"E":"e","nested":[false,null,{"$serde_json::private::Number":"1e-50"}],"text":"1e-50|1E-50","tiny":1E-50}"#;
        let actual = serialize(&CanonicalJson(&value), MAX_VALUE_BYTES)?;
        assert_eq!(actual.as_slice(), expected);
        assert!(serialize(&CanonicalJson(&value), expected.len() - 1).is_err());
        let mut changed = value.clone();
        changed["tiny"] = Value::String("1E-50".to_owned());
        assert_ne!(fingerprint(&changed)?, fingerprint(&value)?);
        changed["tiny"] = lossless::decode_lossless_json(b"1.0e-50")?;
        assert_ne!(fingerprint(&changed)?, fingerprint(&value)?);
        let negative = lossless::decode_lossless_json(b"-0.0")?;
        let positive = lossless::decode_lossless_json(b"0.0")?;
        assert_ne!(fingerprint(&negative)?, fingerprint(&positive)?);
        // The domain deliberately retains integer -0 as -0.0. The old Python
        // parse_int=int oracle loses that sign; do not alter stored data to hide
        // this separate, pre-existing profile qualification boundary.
        let integer_negative = lossless::decode_lossless_json(b"-0")?;
        assert_eq!(
            serialize(&integer_negative, MAX_VALUE_BYTES)?.as_slice(),
            b"-0.0"
        );
        assert_eq!(fingerprint(&integer_negative)?, fingerprint(&negative)?);
        assert_ne!(
            fingerprint(&integer_negative)?,
            fingerprint(&lossless::decode_lossless_json(b"0")?)?
        );
        Ok(())
    }

    #[test]
    fn witness_decimal_profile_matches_post_v6_large_python_payload() -> TestResult {
        let mut value = lossless::decode_lossless_json(
            r#"{"ordinal":20,"payload":"","wide_integer":18446744073709551617,"exact_decimal":0.123456789012345678901234567891,"tiny":1e-50,"unicode":"V6之后的真实写入🧪","nested":[false,null,{"one":1}]}"#.as_bytes(),
        )?;
        value["payload"] = Value::String("V".repeat(2 * 1024 * 1024));
        let before = serialize(&value, MAX_VALUE_BYTES)?;
        let (hash, bytes) = fingerprint(&value)?;
        assert_eq!(bytes, 2_097_349);
        assert_eq!(
            hash,
            "3a69c9338194481ba06bcd5c6f3b5479e501eb0a5a049585bed80547da9ee34f"
        );
        assert_eq!(value["tiny"].as_number().ok_or("tiny")?.as_str(), "1e-50");
        assert_eq!(
            serialize(&value, MAX_VALUE_BYTES)?.as_slice(),
            before.as_slice()
        );
        value["wide_integer"] = lossless::decode_lossless_json(b"18446744073709551618")?;
        assert_ne!(fingerprint(&value)?.0, hash);
        Ok(())
    }

    #[test]
    fn witness_decimal_profile_bounds_exponent_work_without_machine_integer_overflow() -> TestResult
    {
        // These grammar/work bounds go beyond Python Decimal's admitted
        // exponent range; they do not claim a Python cross-language oracle.
        // Scientific output must stay proportional to the token, not 10^e.
        let nines = "9".repeat(4096);
        let positive = lossless::decode_lossless_json(format!("10e{nines}").as_bytes())?;
        let expected = format!("1.0E+1{}", "0".repeat(4096));
        assert_eq!(
            serialize(&CanonicalJson(&positive), MAX_VALUE_BYTES)?.as_slice(),
            expected.as_bytes()
        );
        let negative =
            lossless::decode_lossless_json(format!("10e-1{}", "0".repeat(4096)).as_bytes())?;
        let expected = format!("1.0E-{nines}");
        assert_eq!(
            serialize(&CanonicalJson(&negative), MAX_VALUE_BYTES)?.as_slice(),
            expected.as_bytes()
        );
        assert!(serialize(&CanonicalJson(&negative), expected.len() - 1).is_err());
        assert!(number_capacity(&[MAX_VALUE_BYTES, 1]).is_err());
        assert!(number_capacity(&[usize::MAX, 1]).is_err());
        Ok(())
    }

    #[test]
    fn witness_decimal_profile_reopens_paged_numbers_and_requires_current_payload() -> TestResult {
        let value = lossless::decode_lossless_json(
            br#"{"tiny":1e-50,"scaled":100e-2,"wide":18446744073709551617}"#,
        )?;
        let expected = fingerprint(&value)?;
        let mut owner = Kv2::default();
        owner.handle("POST", "data/history", &json!({"data":value}), 100)?;
        owner.handle("POST", "delete/history", &json!({"versions":[1]}), 101)?;
        let parent = AddressKey::from_bytes([69; 32]);
        let scope = NativeScope {
            namespace: "",
            mount: "secret/",
            incarnation: 1,
        };
        let graph = NativeCellGraph::encode_paged(&owner, &parent, scope, &|| Ok(()))?;
        let mut objects = GraphObjects(BTreeMap::new());
        graph.visit_objects(
            |object| {
                objects.0.insert(object.reference().id, Arc::clone(object));
                Ok(())
            },
            &|| Ok(()),
        )?;
        let root = graph.root();
        drop(graph);
        drop(owner);
        let view = NativeReadView::open_paged_checked(&parent, scope, root, &objects, &|| Ok(()))?;
        let witness = view.storage_version_witness("history", 1, &objects, &|| Ok(()))?;
        assert_eq!(witness["payload_canonical_sha256"], expected.0);
        assert_eq!(witness["payload_canonical_bytes"], expected.1);
        assert!(!witness["deletion_time"].as_str().ok_or("time")?.is_empty());
        assert!(
            view.storage_version_witness("history", 1, &objects, &|| Err(RecordError::Invalid))
                .is_err()
        );
        let reference = view
            .graph
            .as_ref()
            .ok_or("graph")?
            .paged
            .as_ref()
            .ok_or("paged")?
            .descriptors
            .get("history")
            .ok_or("path")?
            .get(&1)
            .ok_or("version")?
            .blocks[0]
            .id;
        objects.0.remove(&reference).ok_or("stored block")?;
        assert!(
            view.storage_version_witness("history", 1, &objects, &|| Ok(()))
                .is_err()
        );
        Ok(())
    }
}
