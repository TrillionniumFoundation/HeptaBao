//! Private producer facts for native public responses. These values carry no
//! token, namespace, parent, alias, policy or lease authority.
use super::*;
use chrono::{DateTime, FixedOffset, Local};

#[derive(Clone, Copy, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum Floor {
    V1,
}

#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(
    tag = "input",
    content = "value",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub(super) enum MetadataInput {
    Absent,
    ExplicitNull,
    // WeakDecode can retain a nil map for a non-null JSON input such as [null].
    // Keep that genuine decoded fact separate from an explicit input null.
    DecodedNull,
    Map(BTreeMap<String, String>),
}
impl Drop for MetadataInput {
    fn drop(&mut self) {
        if let Self::Map(map) = self {
            approle_metadata::erase(map);
        }
    }
}
impl MetadataInput {
    pub(super) fn parse(body: &Value) -> Result<Self, AuthError> {
        match body.get("meta") {
            None => Ok(Self::Absent),
            Some(Value::Null) => Ok(Self::ExplicitNull),
            Some(value) => {
                // Pinned TypeKVPairs first WeakDecodes into map[string]string.
                // A failed map attempt is discarded before the independent
                // []string attempt; no partial map can escape on an error.
                let mut decoded = None;
                let mut map = if weak_map(value, &mut decoded) {
                    let Some(map) = decoded else {
                        return Ok(Self::DecodedNull);
                    };
                    map
                } else {
                    if let Some(mut map) = decoded {
                        approle_metadata::erase(&mut map);
                    }
                    weak_pairs(value)?
                };
                if !crate::login_metadata::within_limit(&map) {
                    approle_metadata::erase(&mut map);
                    return Err(err(413, "token metadata exceeds supported bounds"));
                }
                Ok(Self::Map(map))
            }
        }
    }
    pub(super) fn issued_json(&self) -> Value {
        match self {
            Self::Absent | Self::ExplicitNull | Self::DecodedNull => Value::Null,
            Self::Map(map) => json!(map),
        }
    }
    pub(super) fn map(&self) -> BTreeMap<String, String> {
        match self {
            Self::Map(map) => map.clone(),
            Self::Absent | Self::ExplicitNull | Self::DecodedNull => BTreeMap::new(),
        }
    }
    fn validate(&self) -> Result<(), AuthError> {
        if let Self::Map(map) = self
            && !crate::login_metadata::within_limit(map)
        {
            return Err(err(503, "invalid public metadata owner"));
        }
        Ok(())
    }
    pub(super) fn batch_origin(&self) -> BatchOrigin {
        BatchOrigin {
            input: match self {
                Self::Absent => BatchMetadataInput::Absent,
                Self::ExplicitNull => BatchMetadataInput::ExplicitNull,
                Self::DecodedNull => BatchMetadataInput::DecodedNull,
                Self::Map(_) => BatchMetadataInput::Map,
            },
        }
    }
}

/// The JSON domain of pinned mapstructure v2.5.0 WeakDecode. JSON null leaves
/// the destination unchanged; an empty object/slice allocates an empty map;
/// nonempty slices recursively merge into the same destination in input order.
/// JSON depth is already bounded by the ordinary strict HTTP JSON decoder.
fn weak_map(value: &Value, result: &mut Option<BTreeMap<String, String>>) -> bool {
    match value {
        Value::Null => true,
        Value::Object(values) => {
            let map = result.get_or_insert_with(BTreeMap::new);
            for (name, value) in values {
                let Some(value) = token_policies::weak_string(value) else {
                    return false;
                };
                replace_value(map, name, value);
            }
            true
        }
        Value::Array(values) => {
            if values.is_empty() {
                result.get_or_insert_with(BTreeMap::new);
            }
            values.iter().all(|value| weak_map(value, result))
        }
        _ => false,
    }
}

fn replace_value(map: &mut BTreeMap<String, String>, name: &str, value: String) {
    if let Some(previous) = map.get_mut(name) {
        previous.zeroize();
        *previous = value;
    } else {
        map.insert(name.into(), value);
    }
}

fn weak_pairs(value: &Value) -> Result<BTreeMap<String, String>, AuthError> {
    // WeakDecode lifts a scalar or a nonempty map into a single-element slice;
    // []string conversion errors accumulate in actual input index order. Null
    // string elements decode to an empty slot, rather than being filtered out.
    let values = match value {
        Value::Array(values) => values.as_slice(),
        _ => std::slice::from_ref(value),
    };
    let mut strings = Zeroizing::new(Vec::with_capacity(values.len()));
    let mut failures = Vec::new();
    for (index, value) in values.iter().enumerate() {
        if let Some(value) = token_policies::weak_string(value) {
            strings.push(value);
        } else {
            let kind = if value.is_object() {
                "map[string]interface {}"
            } else {
                "[]interface {}"
            };
            failures.push(format!(
                "'[{index}]' expected type 'string', got unconvertible type '{kind}'"
            ));
        }
    }
    if !failures.is_empty() {
        return Err(bad(&format!(
            "Field validation failed: error converting input for field \"meta\": decoding failed due to the following error(s):\n\n{}",
            failures.join("\n")
        )));
    }
    let mut map = BTreeMap::new();
    for (index, pair) in strings.iter().enumerate() {
        let Some((name, value)) = pair.split_once('=').filter(|(name, _)| !name.is_empty()) else {
            approle_metadata::erase(&mut map);
            return Err(bad(&format!(
                "Field validation failed: error converting input for field \"meta\": invalid key pair at index {index} in field \"meta\""
            )));
        };
        replace_value(&mut map, name, value.into());
    }
    Ok(map)
}

#[derive(Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum BatchMetadataInput {
    Absent,
    ExplicitNull,
    DecodedNull,
    Map,
}
/// Actual native Token API batch provenance. The metadata map remains owned
/// once by the AEAD claims. Empty-map lookup follows pinned protobuf semantics.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct BatchOrigin {
    input: BatchMetadataInput,
}
impl BatchOrigin {
    pub(super) fn validate(&self, metadata: &BTreeMap<String, String>) -> Result<(), AuthError> {
        if (!matches!(self.input, BatchMetadataInput::Map) && !metadata.is_empty())
            || !crate::login_metadata::within_limit(metadata)
        {
            return Err(err(503, "invalid native batch metadata owner"));
        }
        Ok(())
    }
    pub(super) fn issued_json(&self, metadata: &BTreeMap<String, String>) -> Value {
        match self.input {
            BatchMetadataInput::Absent
            | BatchMetadataInput::ExplicitNull
            | BatchMetadataInput::DecodedNull => Value::Null,
            BatchMetadataInput::Map => json!(metadata),
        }
    }
    pub(super) fn lookup_json(&self, metadata: &BTreeMap<String, String>) -> Value {
        if metadata.is_empty() {
            Value::Null
        } else {
            json!(metadata)
        }
    }
    pub(super) fn issue_time(&self, issued_at: u64) -> Option<String> {
        // The pinned batch lease producer uses time.Unix(CreationTime,0), not
        // a reconstructed nanosecond observation or a persisted service lease.
        CreationStamp::local_epoch(issued_at, 0).ok()?.render().ok()
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct TokenApiOrigin {
    metadata: MetadataInput,
    creation_path: String,
}
impl Drop for TokenApiOrigin {
    fn drop(&mut self) {
        self.creation_path.zeroize();
    }
}
impl TokenApiOrigin {
    pub(super) fn new(metadata: MetadataInput, creation_path: &str) -> Result<Self, AuthError> {
        validate_path(creation_path, false)?;
        Ok(Self {
            metadata,
            creation_path: creation_path.into(),
        })
    }
    pub(super) fn issued_json(&self) -> Value {
        self.metadata.issued_json()
    }
    fn validate(&self) -> Result<(), AuthError> {
        self.metadata.validate()?;
        validate_path(&self.creation_path, false)
    }
    pub(super) fn project_lookup(&self, info: &mut Value) {
        info["meta"] = self.metadata.issued_json();
        info["path"] = json!(self.creation_path);
    }
}

/// A genuine producer observation. None remains None for historical tokens or
/// direct explicit-clock Service tests; old integer seconds never gain nanos.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct CreationStamp {
    seconds: u64,
    nanoseconds: u32,
    offset_seconds: i32,
}
impl CreationStamp {
    pub(super) fn capture(created_at: u64) -> Result<Option<Self>, AuthError> {
        let Some(observed) = crate::service::public_origin_observation() else {
            return Ok(None);
        };
        if observed.as_secs() < created_at {
            return Err(err(503, "creation clock is behind the durable owner"));
        }
        Self::local_epoch(observed.as_secs(), observed.subsec_nanos()).map(Some)
    }
    fn local_epoch(seconds: u64, nanoseconds: u32) -> Result<Self, AuthError> {
        let seconds_signed =
            i64::try_from(seconds).map_err(|_| err(503, "invalid public creation timestamp"))?;
        let epoch = DateTime::from_timestamp(seconds_signed, nanoseconds)
            .ok_or_else(|| err(503, "invalid public creation timestamp"))?;
        let stamp = Self {
            seconds,
            nanoseconds,
            offset_seconds: epoch.with_timezone(&Local).offset().local_minus_utc(),
        };
        stamp.validate()?;
        Ok(stamp)
    }
    fn validate(&self) -> Result<(), AuthError> {
        if self.nanoseconds >= 1_000_000_000
            || self.offset_seconds % 60 != 0
            || self.offset_seconds.unsigned_abs() >= 24 * 60 * 60
        {
            return Err(err(503, "invalid public creation timestamp"));
        }
        let seconds = i64::try_from(self.seconds)
            .map_err(|_| err(503, "invalid public creation timestamp"))?;
        let epoch = DateTime::from_timestamp(seconds, self.nanoseconds)
            .ok_or_else(|| err(503, "invalid public creation timestamp"))?;
        let offset = FixedOffset::east_opt(self.offset_seconds)
            .ok_or_else(|| err(503, "invalid public creation timestamp"))?;
        let year = epoch.with_timezone(&offset).format("%Y").to_string();
        if year.len() != 4 || !year.bytes().all(|byte| byte.is_ascii_digit()) {
            return Err(err(503, "invalid public creation timestamp"));
        }
        Ok(())
    }
    pub(super) fn render(&self) -> Result<String, AuthError> {
        self.validate()?;
        let epoch = DateTime::from_timestamp(self.seconds as i64, self.nanoseconds)
            .ok_or_else(|| err(503, "invalid public creation timestamp"))?;
        let offset = FixedOffset::east_opt(self.offset_seconds)
            .ok_or_else(|| err(503, "invalid public creation timestamp"))?;
        let mut rendered = epoch
            .with_timezone(&offset)
            .format("%Y-%m-%dT%H:%M:%S")
            .to_string();
        if self.nanoseconds != 0 {
            rendered.push('.');
            rendered.push_str(format!("{:09}", self.nanoseconds).trim_end_matches('0'));
        }
        if self.offset_seconds == 0 {
            rendered.push('Z');
        } else {
            let minutes = self.offset_seconds.unsigned_abs() / 60;
            rendered.push(if self.offset_seconds < 0 { '-' } else { '+' });
            rendered.push_str(&format!("{:02}:{:02}", minutes / 60, minutes % 60));
        }
        Ok(rendered)
    }
    pub(super) fn validate_since(&self, created_at: u64) -> Result<(), AuthError> {
        self.validate()?;
        if self.seconds < created_at {
            return Err(err(503, "invalid public creation timestamp owner"));
        }
        Ok(())
    }
}

impl Token {
    pub(super) fn has_public_origin(&self) -> bool {
        self.public_origin.is_some()
            || self.issue_stamp.is_some()
            || self
                .wrapping
                .as_ref()
                .is_some_and(wrapping::WrappedResponse::has_creation_stamp)
    }
    pub(super) fn validate_public_origin(&self) -> Result<(), AuthError> {
        if let Some(origin) = &self.public_origin {
            if !matches!(
                self.auth_provenance,
                Some(TokenAuthProvenance::TokenApi { .. })
            ) {
                return Err(err(503, "native Token API public owner is missing"));
            }
            origin.validate()?;
            if let Some(role) = &self.token_role
                && origin.creation_path != role.path
            {
                return Err(err(503, "native Token API creation path owner rejected"));
            }
        }
        if let Some(stamp) = &self.issue_stamp {
            stamp.validate_since(self.created_at)?;
        }
        if let Some(wrapped) = &self.wrapping {
            wrapped.validate_creation_stamp(self.created_at)?;
        }
        Ok(())
    }
}
impl AuthState {
    /// Format-only historical service-token fixtures omit all facts unavailable
    /// before reader 86. Never used by runtime retirement or live publication.
    #[cfg(test)]
    pub(crate) fn omit_unwrapped_public_origin_for_legacy_fixture(&mut self) {
        assert!(self.tokens.values().all(|token| token.wrapping.is_none()));
        assert!(
            self.batch_authority
                .as_ref()
                .is_none_or(BatchKeyAuthority::is_unused_for_legacy_fixture)
        );
        for token in self.tokens.values_mut() {
            token.public_origin = None;
            token.issue_stamp = None;
        }
        self.public_origin_floor = None;
        assert!(!self.has_public_origin_state());
    }
    pub(crate) fn has_public_origin_state(&self) -> bool {
        self.public_origin_floor.is_some() || self.tokens.values().any(Token::has_public_origin)
    }
    pub(crate) fn validate_public_origin_state(&self) -> Result<(), AuthError> {
        if self.tokens.values().any(Token::has_public_origin) && self.public_origin_floor.is_none()
        {
            return Err(err(503, "native public origin floor is missing"));
        }
        for token in self.tokens.values() {
            token.validate_public_origin()?;
        }
        Ok(())
    }
    pub(crate) fn validate_public_origin_successor(
        &self,
        previous: &Self,
    ) -> Result<(), AuthError> {
        self.validate_public_origin_state()?;
        previous.validate_public_origin_state()?;
        if previous.public_origin_floor.is_some() && self.public_origin_floor.is_none() {
            return Err(err(503, "native public origin floor cannot retire"));
        }
        Ok(())
    }
    pub(super) fn store_token(&mut self, id: String, token: Token) -> Option<Token> {
        if token.has_public_origin() {
            self.public_origin_floor = Some(Floor::V1);
        }
        self.tokens.insert(id, token)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn token_metadata_weak_decode_map_first_nil_allocation_and_ordered_merge()
    -> Result<(), Box<dyn std::error::Error>> {
        // Public synthetic outputs observed by the pinned official R45/R47
        // matrices, including recursive slice merges and nil-map provenance.
        for (value, expected) in [
            (
                json!({"": "synthetic-public"}),
                json!({"": "synthetic-public"}),
            ),
            (
                json!({"yes":true,"no":false,"n":123,"nil":null}),
                json!({"yes":"1","no":"0","n":"123","nil":""}),
            ),
            (
                json!([{"marker":"first"},{"marker":"last","flag":true}]),
                json!({"marker":"last","flag":"1"}),
            ),
            (json!([[{"a":1}],[{"b":null}]]), json!({"a":"1","b":""})),
            (json!([null]), Value::Null),
            (
                json!([null,{"marker":"public"}]),
                json!({"marker":"public"}),
            ),
            (json!([[], []]), json!({})),
            (json!([]), json!({})),
            (
                json!([" key = spaced ", "value=x=y"]),
                json!({" key ":" spaced ","value":"x=y"}),
            ),
            (
                json!(["marker=first", "marker=last", "empty="]),
                json!({"marker":"last","empty":""}),
            ),
            (json!("marker=value"), json!({"marker":"value"})),
        ] {
            let parsed = MetadataInput::parse(&json!({"meta":value}))?;
            assert_eq!(parsed.issued_json(), expected);
            let encoded = serde_json::to_vec(&parsed)?;
            let restored: MetadataInput = serde_json::from_slice(&encoded)?;
            restored.validate()?;
            assert_eq!(restored.issued_json(), expected);
            let batch = restored.batch_origin();
            let map = restored.map();
            batch.validate(&map)?;
            assert_eq!(batch.issued_json(&map), expected);
            assert_eq!(
                batch.lookup_json(&map),
                if map.is_empty() {
                    Value::Null
                } else {
                    expected
                }
            );
        }
        assert!(matches!(
            MetadataInput::parse(&json!({"meta":[null]}))?,
            MetadataInput::DecodedNull
        ));
        assert!(matches!(
            MetadataInput::parse(&json!({"meta":null}))?,
            MetadataInput::ExplicitNull
        ));
        assert!(
            serde_json::from_value::<MetadataInput>(
                json!({"input":"decoded_null","permission":true})
            )
            .is_err()
        );
        Ok(())
    }

    #[test]
    fn token_metadata_weak_decode_independent_fallback_has_exact_joined_errors() {
        let prefix = "Field validation failed: error converting input for field \"meta\": ";
        for (value, suffix) in [
            (
                json!({"nested":{}}),
                "decoding failed due to the following error(s):\n\n'[0]' expected type 'string', got unconvertible type 'map[string]interface {}'",
            ),
            (
                json!([{},[],{"bad":[1]}]),
                "decoding failed due to the following error(s):\n\n'[0]' expected type 'string', got unconvertible type 'map[string]interface {}'\n'[1]' expected type 'string', got unconvertible type '[]interface {}'\n'[2]' expected type 'string', got unconvertible type 'map[string]interface {}'",
            ),
            (
                json!([{"valid":"first"},"bad=second"]),
                "decoding failed due to the following error(s):\n\n'[0]' expected type 'string', got unconvertible type 'map[string]interface {}'",
            ),
            (
                json!([["a=1"], ["b=2"]]),
                "decoding failed due to the following error(s):\n\n'[0]' expected type 'string', got unconvertible type '[]interface {}'\n'[1]' expected type 'string', got unconvertible type '[]interface {}'",
            ),
            (json!(true), "invalid key pair at index 0 in field \"meta\""),
            (json!(""), "invalid key pair at index 0 in field \"meta\""),
            (json!(42), "invalid key pair at index 0 in field \"meta\""),
            (
                json!(["good=first", "=invalid"]),
                "invalid key pair at index 1 in field \"meta\"",
            ),
        ] {
            let error = MetadataInput::parse(&json!({"meta":value})).err();
            assert!(error.is_some());
            if let Some(error) = error {
                assert_eq!(error.status, 400);
                assert_eq!(error.message, format!("{prefix}{suffix}"));
            }
        }
    }

    #[test]
    fn real_input_nil_empty_and_batch_proto_lookup_remain_distinct()
    -> Result<(), Box<dyn std::error::Error>> {
        for (body, expected) in [
            (json!({}), Value::Null),
            (json!({"meta":null}), Value::Null),
            (json!({"meta":{}}), json!({})),
            (
                json!({"meta":{"public":"value"}}),
                json!({"public":"value"}),
            ),
        ] {
            let input = MetadataInput::parse(&body)?;
            assert_eq!(input.issued_json(), expected);
            let map = input.map();
            let batch = input.batch_origin();
            assert_eq!(batch.issued_json(&map), expected);
            assert_eq!(
                batch.lookup_json(&map),
                if map.is_empty() {
                    Value::Null
                } else {
                    expected
                }
            );
        }
        Ok(())
    }
    #[test]
    fn stamp_preserves_real_fraction_offset_and_rejects_unknown_grammar()
    -> Result<(), Box<dyn std::error::Error>> {
        let stamp = CreationStamp {
            seconds: 1_791_156_311,
            nanoseconds: 314_879_806,
            offset_seconds: 28_800,
        };
        assert_eq!(stamp.render()?, "2026-10-05T07:25:11.314879806+08:00");
        let bytes = serde_json::to_vec(&stamp)?;
        let restored: CreationStamp = serde_json::from_slice(&bytes)?;
        assert_eq!(restored.render()?, stamp.render()?);
        assert!(
            serde_json::from_value::<CreationStamp>(
                json!({"seconds":1,"nanoseconds":1,"offset_seconds":0,"permission":true})
            )
            .is_err()
        );
        assert!(
            CreationStamp {
                nanoseconds: 1_000_000_000,
                ..stamp.clone()
            }
            .render()
            .is_err()
        );
        assert!(
            CreationStamp {
                offset_seconds: 1,
                ..stamp.clone()
            }
            .render()
            .is_err()
        );
        assert!(stamp.validate_since(stamp.seconds + 1).is_err());
        Ok(())
    }
}
