//! Issuer time policy captured independently by each signed leaf owner.
use super::*;

#[derive(Clone, Copy, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub(super) enum IssuerLeafNotAfterBehavior {
    #[default]
    Err,
    Permit,
    Truncate,
}
impl IssuerLeafNotAfterBehavior {
    pub(super) fn label(self) -> &'static str {
        match self {
            Self::Err => "err",
            Self::Permit => "permit",
            Self::Truncate => "truncate",
        }
    }
    pub(super) fn apply(self, not_after: u64, ca_not_after: u64) -> Result<u64> {
        if not_after <= ca_not_after {
            return Ok(not_after);
        }
        match self {
            Self::Permit => Ok(not_after),
            Self::Truncate => Ok(ca_not_after),
            Self::Err => Err(bad(&format!(
                "cannot satisfy request, as TTL would result in notAfter of {} that is beyond the expiration of the CA certificate at {}",
                timestamp(not_after),
                timestamp(ca_not_after)
            ))),
        }
    }
}
impl Pki {
    pub(super) fn issuer_leaf_time_update(
        &mut self,
        reference: &str,
        body: &Value,
    ) -> Result<EngineResponse> {
        reject_unknown(body, &["leaf_not_after_behavior"])?;
        let value = match body.get("leaf_not_after_behavior") {
            None => return self.local_issuer_management_read(reference, &json!({})),
            Some(Value::String(value)) => value.as_str(),
            _ => {
                return Err(bad(
                    "Unknown value for field `leaf_not_after_behavior`. Possible values are `err`, `truncate`, and `permit`.",
                ));
            }
        };
        let behavior = match value {
            "err" => IssuerLeafNotAfterBehavior::Err,
            "permit" => IssuerLeafNotAfterBehavior::Permit,
            "truncate" => IssuerLeafNotAfterBehavior::Truncate,
            _ => {
                return Err(bad(
                    "Unknown value for field `leaf_not_after_behavior`. Possible values are `err`, `truncate`, and `permit`.",
                ));
            }
        };
        let selected = self.selected_issuer(reference)?;
        let external = selected.is_external();
        let id = selected.issuer_id.clone();
        let selected = if external || self.root.as_ref().is_some_and(|root| root.issuer_id == id) {
            self.root.as_mut().ok_or_else(not_found)?
        } else {
            self.local_issuers
                .as_mut()
                .and_then(|state| state.other.get_mut(&id))
                .ok_or_else(not_found)?
        };
        let changed = selected.leaf_not_after_behavior != Some(behavior);
        selected.leaf_not_after_behavior = Some(behavior);
        let mut response = self.local_issuer_management_read(reference, &json!({}))?;
        response.mutated = changed;
        Ok(response)
    }
}
