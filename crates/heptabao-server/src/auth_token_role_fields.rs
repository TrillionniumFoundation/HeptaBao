//! Token-role framework field conversions, isolated from login and listener APIs.
//! Pinned: OpenBao 2.7.0 FieldData; mapstructure v2.5.0; parseutil v0.2.0;
//! Go 1.27.1 duration units, checked signed nanoseconds and error formatting.
use super::super::token_duration::{parse_duration, signed_int};
use super::{AuthError, Value, bad, token_policies};

pub(super) fn boolean(body: &Value, field: &str) -> Result<bool, AuthError> {
    token_policies::weak_boolean(body.get(field), field).map_err(|error| {
        // Role handlers return conversion errors directly. Ordinary token creation
        // retains its framework validation prefix in the Token API helper.
        bad(error
            .message
            .strip_prefix("Field validation failed: ")
            .unwrap_or(&error.message))
    })
}

pub(super) fn uses(body: &Value) -> Result<u64, AuthError> {
    let field = "token_num_uses";
    let value = match body.get(field) {
        None | Some(Value::Null) => return Ok(0),
        Some(Value::Bool(value)) => return Ok(u64::from(*value)),
        Some(Value::String(value)) => value.clone(),
        Some(Value::Number(value)) => value.to_string(),
        Some(Value::Array(_)) => {
            return Err(convert(
                field,
                "'' expected type 'int', got unconvertible type '[]interface {}'",
            ));
        }
        Some(Value::Object(_)) => {
            return Err(convert(
                field,
                "'' expected type 'int', got unconvertible type 'map[string]interface {}'",
            ));
        }
    };
    let value = if value.is_empty() { "0" } else { &value };
    let parsed = signed_int(value, true).map_err(|error| {
        convert(
            field,
            &format!("'' cannot parse value as 'int': strconv.ParseInt: {error}"),
        )
    })?;
    u64::try_from(parsed)
        .map_err(|_| bad("error parsing role fields: 'token_num_uses' cannot be negative"))
}

pub(super) fn duration(body: &Value, field: &str) -> Result<u64, AuthError> {
    let value = match body.get(field) {
        None | Some(Value::Null) => return Ok(0),
        Some(Value::String(value)) => value.clone(),
        Some(Value::Number(value)) => value.to_string(),
        Some(_) => return Err(convert(field, "could not parse duration from input")),
    };
    let nanos = parse_duration(&value).map_err(|error| convert(field, &error))?;
    // Framework TypeDurationSecond converts Duration.Seconds() (float64) to
    // int64, truncating toward zero. A negative subsecond duration becomes zero.
    let seconds = (nanos as f64 / 1_000_000_000_f64) as i64;
    u64::try_from(seconds)
        .map_err(|_| convert(field, &format!("cannot provide negative value '{seconds}'")))
}

fn convert(field: &str, message: &str) -> AuthError {
    bad(&format!(
        "error converting input for field {field:?}: {message}"
    ))
}
