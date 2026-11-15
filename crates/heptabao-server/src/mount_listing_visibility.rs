//! Persisted discovery metadata; this never grants a backend capability.
use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub(crate) enum ListingVisibility {
    Hidden,
    Unauth,
}

impl ListingVisibility {
    pub(crate) fn parse(value: &Value) -> Result<Option<Self>, &'static str> {
        match value {
            Value::Null => Ok(None),
            Value::String(value) => match value.as_str() {
                "" => Ok(None),
                "hidden" => Ok(Some(Self::Hidden)),
                "unauth" => Ok(Some(Self::Unauth)),
                _ => Err("invalid listing_visibility"),
            },
            _ => Err("listing_visibility must be a string"),
        }
    }

    pub(crate) fn name(self) -> &'static str {
        match self {
            Self::Hidden => "hidden",
            Self::Unauth => "unauth",
        }
    }

    pub(crate) fn is_unauth(descriptor: &Value) -> bool {
        descriptor
            .get("config")
            .and_then(|config| config.get("listing_visibility"))
            .and_then(Value::as_str)
            == Some("unauth")
    }
}
