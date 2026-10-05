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
            Some(Value::Object(values)) => {
                let mut map = BTreeMap::new();
                for (name, value) in values {
                    let Some(value) = value.as_str() else {
                        approle_metadata::erase(&mut map);
                        return Err(bad("meta must be a map of strings"));
                    };
                    map.insert(name.clone(), value.to_owned());
                }
                if !crate::login_metadata::within_limit(&map) {
                    approle_metadata::erase(&mut map);
                    return Err(err(413, "token metadata exceeds supported bounds"));
                }
                Ok(Self::Map(map))
            }
            _ => Err(bad("meta must be a map of strings")),
        }
    }
    pub(super) fn issued_json(&self) -> Value {
        match self {
            Self::Absent | Self::ExplicitNull => Value::Null,
            Self::Map(map) => json!(map),
        }
    }
    pub(super) fn map(&self) -> BTreeMap<String, String> {
        match self {
            Self::Map(map) => map.clone(),
            Self::Absent | Self::ExplicitNull => BTreeMap::new(),
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
                Self::Map(_) => BatchMetadataInput::Map,
            },
        }
    }
}

#[derive(Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum BatchMetadataInput {
    Absent,
    ExplicitNull,
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
            BatchMetadataInput::Absent | BatchMetadataInput::ExplicitNull => Value::Null,
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
