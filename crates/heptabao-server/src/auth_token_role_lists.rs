//! Role field conversions use parseutil's v1 mapstructure comma-list decoder.
//! Ordinary token policies use a different decoder and keep their own errors.
use super::*;

fn kind(value: &Value) -> &'static str {
    match value {
        Value::Array(_) => "[]interface {}",
        Value::Object(_) => "map[string]interface {}",
        _ => "unsupported",
    }
}

// Go fmt's container representation appears in this decoder's public errors.
fn display(value: &Value) -> String {
    match value {
        Value::Null => "<nil>".into(),
        Value::String(value) => value.clone(),
        Value::Bool(value) => value.to_string(),
        Value::Number(value) => value.to_string(),
        Value::Array(values) => format!(
            "[{}]",
            values.iter().map(display).collect::<Vec<_>>().join(" ")
        ),
        Value::Object(values) => format!(
            "map[{}]",
            values
                .iter()
                .map(|(key, value)| format!("{key}:{}", display(value)))
                .collect::<Vec<_>>()
                .join(" ")
        ),
    }
}

pub(super) fn string(body: &Value, field: &str) -> Result<String, AuthError> {
    let value = &body[field];
    token_policies::weak_string(value).ok_or_else(|| {
        bad(&format!(
            "error converting input for field {field:?}: '' expected type 'string', got unconvertible type '{}'",
            kind(value)
        ))
    })
}

pub(super) fn comma_strings(body: &Value, field: &str) -> Result<Vec<String>, AuthError> {
    let value = &body[field];
    let values = match value {
        Value::Null => return Ok(Vec::new()),
        Value::String(value) => {
            return Ok(if value.is_empty() {
                Vec::new()
            } else {
                value.split(',').map(|s| s.trim().to_owned()).collect()
            });
        }
        Value::Object(values) if values.is_empty() => return Ok(Vec::new()),
        Value::Array(values) => values.iter().collect::<Vec<_>>(),
        value => vec![value],
    };
    let mut result = Vec::with_capacity(values.len());
    let mut failures = Vec::new();
    for (index, value) in values.into_iter().enumerate() {
        if let Some(value) = token_policies::weak_string(value) {
            result.push(value.trim().to_owned());
        } else {
            failures.push(format!(
                "* '[{index}]' expected type 'string', got unconvertible type '{}', value: '{}'",
                kind(value),
                display(value)
            ));
        }
    }
    if failures.is_empty() {
        Ok(result)
    } else {
        failures.sort();
        Err(bad(&format!(
            "error converting input for field {field:?}: {} error(s) decoding:\n\n{}",
            failures.len(),
            failures.join("\n")
        )))
    }
}

pub(super) fn cidrs(body: &Value, field: &str) -> Result<Vec<String>, AuthError> {
    let values = comma_strings(body, field)?;
    if values.len() > 128 {
        return Err(bad("too many token bound CIDRs"));
    }
    values
        .iter()
        .map(|value| {
            token_cidrs::canonical(value).map_err(|_| {
                let prefix = if field == "bound_cidrs" {
                    "error parsing bound_cidrs"
                } else {
                    "error parsing role fields"
                };
                let quoted = token_policies::quote_policy(value);
                bad(&format!(
                    "{prefix}: error parsing address {quoted}: Unable to convert {quoted} to an IPv4 or IPv6 address, or a UNIX Socket"
                ))
            })
        })
        .collect()
}
