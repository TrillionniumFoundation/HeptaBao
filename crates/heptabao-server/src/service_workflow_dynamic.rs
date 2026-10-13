//! Typed dynamic data stays request-local; the Service interpreter owns effects.
use super::*;
use crate::workflow_runtime::Value as RuntimeValue;
#[path = "service_workflow_cel.rs"]
mod cel_consumer;
#[path = "service_workflow_fields.rs"]
mod field_consumer;
#[path = "service_workflow_template.rs"]
mod template_consumer;

// Workflow HCL has decimal defaults; the shared policy lexer is u64-only.
// Retain its exact quoted-string/comment/block grammar here, with typed finite
// numbers. Bare HCL null is rejected as observed at the official2.7 installer;
// JSON input null remains a separate FieldData conversion.
#[derive(Clone, PartialEq)]
enum HclToken {
    Word(String),
    String(String),
    Number(serde_json::Number),
    Symbol(char),
}
fn workflow_take(
    tokens: &[HclToken],
    cursor: &mut usize,
    wanted: HclToken,
) -> Result<(), Response> {
    if tokens.get(*cursor) != Some(&wanted) {
        return Err(bad_profile("malformed workflow HCL value"));
    }
    *cursor += 1;
    Ok(())
}
fn workflow_symbol(tokens: &[HclToken], cursor: &mut usize, wanted: char) -> Result<(), Response> {
    workflow_take(tokens, cursor, HclToken::Symbol(wanted))
}
fn workflow_label(tokens: &[HclToken], cursor: &mut usize) -> Result<String, Response> {
    let Some(HclToken::String(label)) = tokens.get(*cursor) else {
        return Err(bad_profile("workflow profile block requires a quoted name"));
    };
    if !validate_name(label, MAX_WORKFLOW_NAME_BYTES) {
        return Err(bad_profile("invalid workflow profile name"));
    }
    *cursor += 1;
    Ok(label.clone())
}
fn workflow_attributes(tokens: &[HclToken], cursor: &mut usize) -> Result<Value, Response> {
    workflow_value(tokens, cursor, 0)
}
fn workflow_lex_hcl(source: &str) -> Result<Vec<HclToken>, Response> {
    let bytes = source.as_bytes();
    let mut index = 0;
    let mut result = Vec::new();
    while index < bytes.len() {
        if bytes[index].is_ascii_whitespace() {
            index += 1;
            continue;
        }
        if bytes[index] == b'#' || bytes[index..].starts_with(b"//") {
            while index < bytes.len() && bytes[index] != b'\n' {
                index += 1;
            }
            continue;
        }
        if bytes[index..].starts_with(b"/*") {
            index += 2;
            while index + 1 < bytes.len() && !bytes[index..].starts_with(b"*/") {
                index += 1;
            }
            if index + 1 >= bytes.len() {
                return Err(bad_profile("unterminated HCL comment"));
            }
            index += 2;
            continue;
        }
        if b"{}[]=,".contains(&bytes[index]) {
            result.push(HclToken::Symbol(bytes[index] as char));
            index += 1;
            continue;
        }
        if bytes[index] == b'"' {
            let start = index;
            index += 1;
            let mut escaped = false;
            while index < bytes.len() {
                if bytes[index] == b'"' && !escaped {
                    break;
                }
                escaped = bytes[index] == b'\\' && !escaped;
                index += 1;
            }
            if index >= bytes.len() {
                return Err(bad_profile("unterminated HCL string"));
            }
            index += 1;
            let value: String = serde_json::from_str(&source[start..index])
                .map_err(|_| bad_profile("invalid HCL string escape"))?;
            result.push(HclToken::String(value));
            continue;
        }
        if bytes[index].is_ascii_alphabetic() || bytes[index] == b'_' {
            let start = index;
            while index < bytes.len()
                && (bytes[index].is_ascii_alphanumeric() || matches!(bytes[index], b'_' | b'-'))
            {
                index += 1;
            }
            result.push(HclToken::Word(source[start..index].into()));
            continue;
        }
        if bytes[index].is_ascii_digit() || matches!(bytes[index], b'-' | b'.') {
            let start = index;
            let leading_dot = bytes[index] == b'.';
            if bytes[index] == b'-' {
                index += 1;
            }
            let integer = index;
            while index < bytes.len() && bytes[index].is_ascii_digit() {
                index += 1;
            }
            if index == integer && !leading_dot {
                return Err(bad_profile("invalid workflow HCL number"));
            }
            if !leading_dot
                && &source[integer..index] == "0"
                && matches!(bytes.get(index), Some(b'x' | b'X'))
            {
                index += 1;
                let hexadecimal = index;
                while index < bytes.len() && bytes[index].is_ascii_hexdigit() {
                    index += 1;
                }
                if index == hexadecimal {
                    return Err(bad_profile("invalid workflow HCL integer"));
                }
            } else {
                if bytes.get(index) == Some(&b'.') {
                    index += 1;
                    let fraction = index;
                    while index < bytes.len() && bytes[index].is_ascii_digit() {
                        index += 1;
                    }
                    if leading_dot && index == fraction {
                        return Err(bad_profile("invalid workflow HCL fraction"));
                    }
                }
                if matches!(bytes.get(index), Some(b'e' | b'E')) {
                    // Actual HCL1 rejects an exponent after a leading-dot fraction.
                    if leading_dot {
                        return Err(bad_profile("invalid workflow HCL leading-dot exponent"));
                    }
                    index += 1;
                    if matches!(bytes.get(index), Some(b'+' | b'-')) {
                        index += 1;
                    }
                    let exponent = index;
                    while index < bytes.len() && bytes[index].is_ascii_digit() {
                        index += 1;
                    }
                    if index == exponent {
                        return Err(bad_profile("invalid workflow HCL exponent"));
                    }
                }
            }
            result.push(HclToken::Number(workflow_hcl_number(
                &source[start..index],
            )?));
            continue;
        }
        return Err(bad_profile("unsupported character in HCL policy"));
    }
    Ok(result)
}

fn workflow_hcl_number(raw: &str) -> Result<serde_json::Number, Response> {
    let integer_text = raw.trim_start_matches('-');
    let hexadecimal = integer_text.starts_with("0x") || integer_text.starts_with("0X");
    if raw.contains(['.', 'e', 'E']) && !hexadecimal {
        let mut normalized = Zeroizing::new(raw.to_owned());
        if normalized.starts_with('.') {
            normalized.insert(0, '0');
        }
        if let Some(dot) = normalized.find('.')
            && (dot + 1 == normalized.len()
                || matches!(normalized.as_bytes().get(dot + 1), Some(b'e' | b'E')))
        {
            normalized.insert(dot + 1, '0');
        }
        let value = normalized
            .parse::<f64>()
            .map_err(|_| bad_profile("invalid workflow HCL number"))?;
        if !value.is_finite() {
            return Err(bad_profile("workflow HCL number exceeds finite range"));
        }
        let mut wire = Zeroizing::new(
            serde_json::Number::from_f64(value)
                .ok_or_else(|| bad_profile("invalid workflow HCL number"))?
                .to_string(),
        );
        if wire.ends_with(".0") && !(value == 0.0 && value.is_sign_negative()) {
            let end = wire.len() - 2;
            wire.truncate(end);
        }
        return wire
            .parse::<serde_json::Number>()
            .map_err(|_| bad_profile("invalid workflow HCL number"));
    }
    let (negative, digits) = raw.strip_prefix('-').map_or((false, raw), |v| (true, v));
    let (radix, magnitude) = if let Some(value) = digits
        .strip_prefix("0x")
        .or_else(|| digits.strip_prefix("0X"))
    {
        (16, value)
    } else if digits.len() > 1 && digits.starts_with('0') {
        (8, digits)
    } else {
        (10, digits)
    };
    let signed = Zeroizing::new(if negative {
        format!("-{magnitude}")
    } else {
        magnitude.to_owned()
    });
    let value = i64::from_str_radix(&signed, radix)
        .map_err(|_| bad_profile("invalid workflow HCL integer"))?;
    Ok(serde_json::Number::from(value))
}

fn workflow_value(
    tokens: &[HclToken],
    cursor: &mut usize,
    depth: usize,
) -> Result<Value, Response> {
    // Bound recursion before constructing a child, not after serializing it.
    // The policy byte limit alone still permits thousands of nested arrays.
    if depth > MAX_JSON_DEPTH + 3 {
        return Err(bad_profile("HCL policy value nesting exceeds bound"));
    }
    match tokens.get(*cursor).cloned() {
        Some(HclToken::String(value)) => {
            *cursor += 1;
            Ok(Value::String(value))
        }
        Some(HclToken::Number(value)) => {
            *cursor += 1;
            Ok(Value::Number(value))
        }
        Some(HclToken::Word(value)) if matches!(value.as_str(), "true" | "false") => {
            *cursor += 1;
            Ok(Value::Bool(value == "true"))
        }
        Some(HclToken::Symbol('[')) => {
            *cursor += 1;
            let mut values = Vec::new();
            while tokens.get(*cursor) != Some(&HclToken::Symbol(']')) {
                values.push(workflow_value(tokens, cursor, depth + 1)?);
                if tokens.get(*cursor) == Some(&HclToken::Symbol(',')) {
                    *cursor += 1;
                } else if tokens.get(*cursor) != Some(&HclToken::Symbol(']')) {
                    return Err(bad_profile("malformed HCL value array"));
                }
            }
            *cursor += 1;
            Ok(Value::Array(values))
        }
        Some(HclToken::Symbol('{')) => {
            *cursor += 1;
            let mut values = serde_json::Map::new();
            while tokens.get(*cursor) != Some(&HclToken::Symbol('}')) {
                let key = workflow_key(tokens, cursor)?;
                if values.contains_key(&key) {
                    return Err(bad_profile("duplicate HCL object key"));
                }
                workflow_take(tokens, cursor, HclToken::Symbol('='))?;
                values.insert(key, workflow_value(tokens, cursor, depth + 1)?);
                if tokens.get(*cursor) == Some(&HclToken::Symbol(',')) {
                    *cursor += 1;
                }
            }
            *cursor += 1;
            Ok(Value::Object(values))
        }
        _ => Err(bad_profile("unsupported HCL policy value")),
    }
}

fn workflow_key(tokens: &[HclToken], cursor: &mut usize) -> Result<String, Response> {
    match tokens.get(*cursor) {
        Some(HclToken::String(value)) | Some(HclToken::Word(value)) => {
            *cursor += 1;
            Ok(value.clone())
        }
        _ => Err(bad_profile("HCL object key must be a string or identifier")),
    }
}

#[derive(Clone, Copy)]
enum Kind {
    Any,
    String,
    Int,
    UnsupportedInt64,
    Float,
    Bool,
    Strings,
    Map,
}
impl Kind {
    fn result(raw: &str) -> Result<Self, Response> {
        match raw {
            "any" | "interface{}" => Ok(Self::Any),
            "string" => Ok(Self::String),
            "int" => Ok(Self::Int),
            "int64" => Ok(Self::UnsupportedInt64),
            "float64" => Ok(Self::Float),
            "bool" => Ok(Self::Bool),
            "[]string" => Ok(Self::Strings),
            "map" | "map[string]any" | "map[string]interface{}" => Ok(Self::Map),
            _ => Err(bad_profile("unsupported dynamic workflow result type")),
        }
    }
    fn value(self, value: &Value) -> Result<Value, Response> {
        let valid = match self {
            Self::Any => true,
            Self::String => value.is_string(),
            Self::Int => value.as_i64().is_some(),
            Self::UnsupportedInt64 => false,
            Self::Float => value.as_f64().is_some_and(f64::is_finite),
            Self::Bool => value.is_boolean(),
            Self::Strings => value
                .as_array()
                .is_some_and(|items| items.iter().all(Value::is_string)),
            Self::Map => value.is_object(),
        };
        if valid {
            Ok(value.clone())
        } else {
            Err(bad_profile(
                "dynamic workflow value has the wrong declared type",
            ))
        }
    }
    fn runtime_value(self, value: &RuntimeValue) -> Result<RuntimeValue, Response> {
        if matches!(self, Self::UnsupportedInt64) {
            return Err(Response::error(500, "unsupported type conversion: int64"));
        }
        if matches!(self, Self::Any) || matches!(self, Self::Map) && value.is_object() {
            return Ok(value.clone());
        }
        if let Some(number) = value.actual_float() {
            let mut converted = match self {
                Self::Float => return Ok(value.clone()),
                Self::String => json!(RuntimeValue::float_text(number)),
                Self::Int => json!(RuntimeValue::go_int(number)),
                Self::Bool => json!(number != 0.0),
                Self::Strings => json!([RuntimeValue::float_text(number)]),
                _ => return Err(Response::error(500, "workflow runtime conversion rejected")),
            };
            let result = RuntimeValue::from_json(&converted);
            erase_json(&mut converted);
            return Ok(result);
        }
        let original = crate::http::ocsp::CarrierBody(
            value
                .to_json()
                .map_err(|_| Response::error(500, "workflow runtime conversion rejected"))?,
        );
        let mut converted = self.value(&original.0)?;
        let result = RuntimeValue::from_json(&converted);
        erase_json(&mut converted);
        Ok(result)
    }
}

#[derive(Clone, Copy)]
enum InputKind {
    Value(Kind),
    Slice,
    Field(field_consumer::FieldKind),
}
impl InputKind {
    fn parse(raw: &str) -> Result<Self, Response> {
        match raw {
            "string" => Ok(Self::Value(Kind::String)),
            "int" | "int64" => Ok(Self::Value(Kind::Int)),
            "bool" => Ok(Self::Value(Kind::Bool)),
            "map" => Ok(Self::Value(Kind::Map)),
            "slice" => Ok(Self::Slice),
            _ => field_consumer::FieldKind::parse(raw)
                .map(Self::Field)
                .ok_or_else(|| {
                    bad_profile("workflow input field type is not supported by this consumer")
                }),
        }
    }
    fn value(self, value: &Value) -> Result<Value, Response> {
        match self {
            Self::Value(Kind::String) => field_consumer::weak_string(value).map(Value::String),
            Self::Value(Kind::Int) => field_consumer::weak_int(value).map(|value| json!(value)),
            Self::Value(Kind::Bool) => field_consumer::weak_bool(value),
            Self::Value(Kind::Map) => field_consumer::weak_map(value),
            Self::Value(kind) => kind.value(value),
            Self::Slice => field_consumer::weak_slice(value),
            Self::Field(kind) => kind.value(value),
        }
    }

    fn runtime_value(self, value: &Value) -> Result<RuntimeValue, Response> {
        if let Self::Field(kind) = self {
            return kind.runtime_value(value);
        }
        let mut converted = self.value(value)?;
        let result = RuntimeValue::from_json(&converted);
        erase_json(&mut converted);
        Ok(result)
    }
}
struct Field {
    kind: InputKind,
    required: bool,
    query: bool,
    default: Option<Value>,
    allowed: Vec<Value>,
}
#[derive(Clone)]
enum Source {
    Input(String),
    Request(String, Vec<String>),
    Response(String, Vec<String>),
}
#[derive(Clone)]
enum Expr {
    Literal(Value),
    Object(BTreeMap<String, Expr>),
    Array(Vec<Expr>),
    Source(Kind, Source),
    Cel(Kind, cel_consumer::CelSource),
    Template(Kind, template_consumer::TemplateSource, Box<Expr>),
}
impl Expr {
    fn has_expression_sources(&self) -> bool {
        match self {
            Self::Cel(..) | Self::Template(..) => true,
            Self::Object(values) => values.values().any(Self::has_expression_sources),
            Self::Array(values) => values.iter().any(Self::has_expression_sources),
            _ => false,
        }
    }
    fn compile(
        value: &Value,
        fields: &BTreeMap<String, Field>,
        prior: &BTreeSet<String>,
        feature: &mut bool,
        depth: usize,
    ) -> Result<Self, Response> {
        if depth > MAX_JSON_DEPTH {
            return Err(bad_profile(
                "dynamic workflow expression nesting is outside bounds",
            ));
        }
        if let Some(object) = value.as_object() {
            if let Some(source) = object.get("eval_source") {
                *feature = true;
                let source = source
                    .as_str()
                    .ok_or_else(|| bad_profile("invalid workflow source"))?;
                let kind = Kind::result(
                    object
                        .get("eval_type")
                        .and_then(Value::as_str)
                        .ok_or_else(|| bad_profile("workflow source requires a result type"))?,
                )?;
                let allowed: &[&str] = match source {
                    "input" => &["eval_source", "eval_type", "field_name"],
                    "request" => &[
                        "eval_source",
                        "eval_type",
                        "flow_name",
                        "request_name",
                        "field_selector",
                    ],
                    "response" => &[
                        "eval_source",
                        "eval_type",
                        "flow_name",
                        "response_name",
                        "field_selector",
                    ],
                    "cel" => &["eval_source", "eval_type", "expression", "variables"],
                    "template" => &["eval_source", "eval_type", "template", "data"],
                    _ => return Err(bad_profile("workflow source requires a separate consumer")),
                };
                if object.keys().any(|key| !allowed.contains(&key.as_str())) {
                    return Err(bad_profile("unknown dynamic workflow source attribute"));
                }
                if source == "cel" {
                    return Ok(Self::Cel(kind, cel_consumer::CelSource::compile(object)?));
                }
                if source == "template" {
                    let data = object.get("data").cloned().unwrap_or_else(empty_object);
                    let data = Self::compile(&data, fields, prior, feature, depth + 1)?;
                    return Ok(Self::Template(
                        kind,
                        template_consumer::TemplateSource::compile(object)?,
                        Box::new(data),
                    ));
                }
                let source = if source == "input" {
                    let field = object
                        .get("field_name")
                        .and_then(Value::as_str)
                        .filter(|name| fields.contains_key(*name))
                        .ok_or_else(|| {
                            bad_profile("workflow source references an undeclared input")
                        })?;
                    Source::Input(field.into())
                } else {
                    let flow = object
                        .get("flow_name")
                        .and_then(Value::as_str)
                        .ok_or_else(|| bad_profile("workflow source requires a flow"))?;
                    let member = if source == "request" {
                        "request_name"
                    } else {
                        "response_name"
                    };
                    let name = object
                        .get(member)
                        .and_then(Value::as_str)
                        .ok_or_else(|| bad_profile("workflow source requires a prior request"))?;
                    let key = step_key(flow, name);
                    if !prior.contains(&key) {
                        return Err(bad_profile(
                            "workflow source must refer to an earlier request",
                        ));
                    }
                    let selector = match object.get("field_selector") {
                        None => Vec::new(),
                        Some(Value::String(field)) => vec![field.clone()],
                        Some(Value::Array(fields)) => fields
                            .iter()
                            .map(|field| {
                                field.as_str().map(str::to_owned).ok_or_else(|| {
                                    bad_profile("workflow selector members must be strings")
                                })
                            })
                            .collect::<Result<Vec<_>, _>>()?,
                        _ => {
                            return Err(bad_profile("workflow field selector has an invalid type"));
                        }
                    };
                    if selector.len() > MAX_FIELD_SELECTOR
                        || selector
                            .iter()
                            .any(|field| field.is_empty() || field.len() > MAX_JSON_STRING_BYTES)
                    {
                        return Err(bad_profile("workflow field selector is outside bounds"));
                    }
                    if source == "request" {
                        Source::Request(key, selector)
                    } else {
                        Source::Response(key, selector)
                    }
                };
                return Ok(Self::Source(kind, source));
            }
            return object
                .iter()
                .map(|(key, value)| {
                    Ok((
                        key.clone(),
                        Self::compile(value, fields, prior, feature, depth + 1)?,
                    ))
                })
                .collect::<Result<BTreeMap<_, _>, Response>>()
                .map(Self::Object);
        }
        if let Some(array) = value.as_array() {
            return array
                .iter()
                .map(|value| Self::compile(value, fields, prior, feature, depth + 1))
                .collect::<Result<Vec<_>, _>>()
                .map(Self::Array);
        }
        Ok(Self::Literal(value.clone()))
    }
    fn needs_history(&self) -> bool {
        match self {
            Self::Source(_, Source::Request(..) | Source::Response(..))
            | Self::Cel(..)
            | Self::Template(..) => true,
            Self::Object(object) => object.values().any(Self::needs_history),
            Self::Array(array) => array.iter().any(Self::needs_history),
            _ => false,
        }
    }
    fn has_deferred_cast(&self) -> bool {
        match self {
            Self::Source(Kind::UnsupportedInt64, _)
            | Self::Cel(Kind::UnsupportedInt64, _)
            | Self::Template(Kind::UnsupportedInt64, _, _) => true,
            Self::Object(values) => values.values().any(Self::has_deferred_cast),
            Self::Array(values) => values.iter().any(Self::has_deferred_cast),
            _ => false,
        }
    }
    fn validate_inputs(&self, context: &Context) -> Result<(), Response> {
        match self {
            Self::Template(_, source, data) => {
                source.preflight(&context.meter)?;
                data.validate_inputs(context)?;
            }
            Self::Cel(_, source) => {
                let (input, requests, responses) = context.expression_bindings();
                source.preflight_runtime(&input, &requests, &responses, &context.meter)?;
            }
            Self::Source(kind, Source::Input(name)) => {
                let value = context
                    .input
                    .get(name)
                    .ok_or_else(|| bad_profile("declared workflow input is unavailable"))?;
                // A declared slice may be accepted by the input consumer even
                // when an element is not a string. Reject an invalid later
                // []string projection before an earlier provider write.
                // All other eval_type casts (notably int64 and float runtime
                // casts) deliberately retain their original execution stage.
                if matches!(kind, Kind::Strings) {
                    kind.runtime_value(value).map_err(|_| {
                        Response::error(400, "workflow []string input projection is invalid")
                    })?;
                }
            }
            Self::Object(object) => {
                for value in object.values() {
                    value.validate_inputs(context)?;
                }
            }
            Self::Array(array) => {
                for value in array {
                    value.validate_inputs(context)?;
                }
            }
            _ => (),
        }
        Ok(())
    }
    fn resolve(&self, context: &Context, depth: usize) -> Result<RuntimeValue, Response> {
        if depth > MAX_JSON_DEPTH {
            return Err(bad_profile(
                "workflow evaluated value nesting is outside bounds",
            ));
        }
        match self {
            Self::Template(kind, source, data) => {
                let (input, requests, responses) = context.expression_bindings();
                let data = data.resolve(context, depth + 1)?;
                let value = source.evaluate_runtime(
                    &input,
                    &requests,
                    &responses,
                    &data,
                    &context.meter,
                )?;
                kind.runtime_value(&value)
            }
            Self::Cel(kind, source) => {
                let (input, requests, responses) = context.expression_bindings();
                let value =
                    source.evaluate_runtime(&input, &requests, &responses, &context.meter)?;
                kind.runtime_value(&value)
            }
            Self::Literal(value) => Ok(RuntimeValue::from_json(value)),
            Self::Object(object) => {
                let mut result = RuntimeValue::object();
                for (key, value) in object {
                    result.insert(key.clone(), value.resolve(context, depth + 1)?);
                }
                Ok(result)
            }
            Self::Array(array) => array
                .iter()
                .map(|value| value.resolve(context, depth + 1))
                .collect::<Result<Vec<_>, _>>()
                .map(RuntimeValue::array),
            Self::Source(kind, source) => {
                let selected = match source {
                    Source::Input(name) => context.input.get(name),
                    Source::Request(name, selector) => context
                        .requests
                        .get(name)
                        .and_then(|value| select(value, selector)),
                    Source::Response(name, selector) => context
                        .responses
                        .get(name)
                        .and_then(|value| select(value, selector)),
                }
                .ok_or_else(|| {
                    bad_profile("workflow source has not executed or its field is unavailable")
                })?;
                kind.runtime_value(selected)
            }
        }
    }
}
fn select<'a>(mut value: &'a RuntimeValue, selector: &[String]) -> Option<&'a RuntimeValue> {
    for field in selector {
        value = if let Some(object) = value.as_object() {
            object.get(field)?
        } else {
            let array = value.as_array()?;
            array.get(field.parse::<usize>().ok()?)?
        };
    }
    Some(value)
}
fn boolean(
    attrs: &serde_json::Map<String, Value>,
    name: &str,
    default: bool,
) -> Result<bool, Response> {
    match attrs.get(name) {
        None => Ok(default),
        Some(Value::Bool(value)) => Ok(*value),
        _ => Err(bad_profile("workflow field metadata must be boolean")),
    }
}
fn text(attrs: &serde_json::Map<String, Value>, name: &str) -> Result<Option<String>, Response> {
    attrs
        .get(name)
        .map(|value| {
            value
                .as_str()
                .map(str::to_owned)
                .ok_or_else(|| bad_profile("workflow field metadata must be a string"))
        })
        .transpose()
}
fn input_fields(
    tokens: &[HclToken],
    cursor: &mut usize,
) -> Result<BTreeMap<String, Field>, Response> {
    workflow_symbol(tokens, cursor, '{')?;
    let mut fields = BTreeMap::new();
    while tokens.get(*cursor) != Some(&HclToken::Symbol('}')) {
        if tokens.get(*cursor) != Some(&HclToken::Word("field".into())) {
            return Err(bad_profile("workflow input accepts only field blocks"));
        }
        *cursor += 1;
        let mut labels = Vec::new();
        while let Some(HclToken::String(value)) = tokens.get(*cursor) {
            labels.push(value.clone());
            *cursor += 1;
        }
        if labels.len() > 2 || fields.len() >= 64 {
            return Err(bad_profile(
                "workflow input field labels or count exceed bounds",
            ));
        }
        let value = workflow_attributes(tokens, cursor)?;
        let attrs = value
            .as_object()
            .ok_or_else(|| bad_profile("workflow input field is invalid"))?;
        if attrs.keys().any(|key| {
            !matches!(
                key.as_str(),
                "type"
                    | "name"
                    | "default"
                    | "description"
                    | "required"
                    | "deprecated"
                    | "query"
                    | "allowed_values"
            )
        }) {
            return Err(bad_profile("unknown workflow input field attribute"));
        }
        let mut ty = text(attrs, "type")?;
        let mut name = text(attrs, "name")?;
        match labels.as_slice() {
            [] => (),
            [first] if ty.is_none() && name.is_some() => ty = Some(first.clone()),
            [first] => {
                if name.as_ref().is_some_and(|name| name != first) {
                    return Err(bad_profile("workflow input name labels conflict"));
                }
                name = Some(first.clone());
            }
            [first, second] => {
                if ty.as_ref().is_some_and(|ty| ty != first)
                    || name.as_ref().is_some_and(|name| name != second)
                {
                    return Err(bad_profile("workflow input type or name labels conflict"));
                }
                ty = Some(first.clone());
                name = Some(second.clone());
            }
            _ => return Err(bad_profile("invalid workflow input labels")),
        }
        let name = name
            .filter(|name| validate_name(name, MAX_WORKFLOW_NAME_BYTES))
            .ok_or_else(|| bad_profile("workflow input requires a valid name"))?;
        let kind = InputKind::parse(
            ty.as_deref()
                .ok_or_else(|| bad_profile("workflow input requires a type"))?,
        )?;
        let required = boolean(attrs, "required", false)?;
        let _ = boolean(attrs, "deprecated", false)?;
        let query = boolean(attrs, "query", false)?;
        if text(attrs, "description")?.is_some_and(|text| text.len() > MAX_JSON_STRING_BYTES) {
            return Err(bad_profile("workflow input description is outside bounds"));
        }
        // FieldData returns a supplied default verbatim when a field is absent.
        // Conversion applies only to an explicitly supplied value, including null.
        let default = attrs.get("default").cloned();
        let allowed = match attrs.get("allowed_values") {
            None => Vec::new(),
            Some(Value::Array(values)) if values.len() <= 64 => values
                .iter()
                .map(|value| kind.value(value))
                .collect::<Result<Vec<_>, _>>()?,
            _ => {
                return Err(bad_profile(
                    "workflow input allowed values must be a bounded array",
                ));
            }
        };
        if let Some(default) = &default
            && !allowed.is_empty()
            && !allowed.contains(default)
        {
            return Err(bad_profile(
                "workflow input default is outside its allowed values",
            ));
        }
        if fields
            .insert(
                name,
                Field {
                    kind,
                    required,
                    query,
                    default,
                    allowed,
                },
            )
            .is_some()
        {
            return Err(bad_profile("duplicate workflow input field"));
        }
    }
    *cursor += 1;
    Ok(fields)
}
fn declared_source(value: &Value) -> bool {
    match value {
        Value::Object(object) => {
            matches!(
                object.get("eval_source").and_then(Value::as_str),
                Some("input" | "request" | "response" | "cel" | "template" | "env" | "file")
            ) || object.values().any(declared_source)
        }
        Value::Array(array) => array.iter().any(declared_source),
        _ => false,
    }
}
struct RawFlow {
    name: String,
    when: Value,
    requests: Vec<(String, Value)>,
}
pub(super) struct Step {
    name: String,
    flow_when: Expr,
    when: Expr,
    operation: Expr,
    path: Expr,
    body: Expr,
    allow_failure: Expr,
    token: Option<Expr>,
    headers: Option<Expr>,
}
pub(in crate::service::workflows) struct Program {
    fields: BTreeMap<String, Field>,
    pub(super) steps: Vec<Step>,
    output: Expr,
}
// Input conversion clones caller/default data before a Context exists. Keep
// partial and admission-only results under the same erase-on-drop custody.
// Input admission uses the actual listener payload budget once for the whole
// caller map. The smaller persisted step-data bound remains independent.
fn bounded_input_json(
    value: &Value,
    depth: usize,
    bytes: &mut usize,
    fields: &BTreeMap<String, Field>,
    logical_header_map: bool,
) -> Result<(), &'static str> {
    if depth > MAX_JSON_DEPTH {
        return Err("workflow input nesting is too deep");
    }
    if depth == 0 {
        let encoded = Zeroizing::new(
            serde_json::to_vec(value).map_err(|_| "workflow input is not serializable")?,
        );
        *bytes = encoded.len();
        if *bytes > crate::http::MAX_BODY {
            return Err("workflow input exceeds the listener payload bound");
        }
    }
    match value {
        Value::Array(values) => {
            if values.len() > 64 {
                return Err("workflow input array exceeds the bounded size");
            }
            for value in values {
                bounded_input_json(value, depth + 1, bytes, fields, false)?;
            }
        }
        Value::Object(values) => {
            if values.len() > 64 {
                return Err("workflow input object exceeds the bounded size");
            }
            for (key, value) in values {
                if (key.is_empty() && !logical_header_map) || key.len() > MAX_JSON_STRING_BYTES {
                    return Err("workflow input object key exceeds the bounded size");
                }
                // Only the declared Header map has SDK logical header names.
                // The raw caller map and all ordinary nested JSON retain their gate.
                let header = depth == 0
                    && fields.get(key).is_some_and(|field| {
                        matches!(
                            field.kind,
                            InputKind::Field(field_consumer::FieldKind::Header)
                        )
                    });
                bounded_input_json(value, depth + 1, bytes, fields, header)?;
            }
        }
        _ => {}
    }
    Ok(())
}
struct InputValues(BTreeMap<String, RuntimeValue>);
impl Drop for InputValues {
    fn drop(&mut self) {
        for (mut key, value) in std::mem::take(&mut self.0) {
            key.zeroize();
            drop(value);
        }
    }
}
pub(super) struct Context {
    input: BTreeMap<String, RuntimeValue>,
    requests: BTreeMap<String, RuntimeValue>,
    responses: BTreeMap<String, RuntimeValue>,
    meter: std::sync::Arc<cel_consumer::Meter>,
}
impl Program {
    pub(in crate::service::workflows) fn has_logical_data(&self) -> bool {
        self.fields
            .values()
            .any(|field| field.query || matches!(field.kind, InputKind::Field(_)))
            || self.steps.iter().any(|step| step.headers.is_some())
    }
    pub(in crate::service) fn raw_input(
        &self,
        body: &Value,
        _query: &BTreeMap<String, Vec<String>>,
    ) -> Result<crate::http::ocsp::CarrierBody, Response> {
        // POST/PUT workflow execution receives the JSON map. Field.query is
        // schema metadata; URL values do not replace the request body.
        let raw = crate::http::ocsp::CarrierBody(if body.is_null() {
            empty_object()
        } else {
            body.clone()
        });
        if !raw.0.is_object() {
            return Err(bad_profile("workflow input must be an object"));
        }
        let mut bytes = 0;
        bounded_input_json(&raw.0, 0, &mut bytes, &self.fields, false).map_err(bad_profile)?;
        Ok(raw)
    }
    pub(in crate::service) fn effective_input(
        &self,
        body: &Value,
        query: &BTreeMap<String, Vec<String>>,
    ) -> Result<Value, Response> {
        let mut raw = self.raw_input(body, query)?;
        self.input_values(&raw.0)?;
        // Keep the original caller input in the sealed transport. Re-running
        // conversion at execution must not coerce an absent field's raw default.
        Ok(std::mem::take(&mut raw.0))
    }
    fn input_values(&self, body: &Value) -> Result<InputValues, Response> {
        let supplied = body.as_object();
        if supplied.is_none() && !body.is_null() {
            return Err(bad_profile("workflow input must be an object"));
        }
        let mut bytes = 0;
        bounded_input_json(body, 0, &mut bytes, &self.fields, false).map_err(bad_profile)?;
        let mut input = InputValues(BTreeMap::new());
        for (name, field) in &self.fields {
            // The established public FieldData conversion and missing-input
            // error contract returns 500. This is separate from the 400
            // pre-effect rejection for a malformed []string output projection.
            let selected = match supplied.and_then(|object| object.get(name)) {
                Some(value) => field
                    .kind
                    .runtime_value(value)
                    .map_err(|_| Response::error(500, "workflow input field conversion failed"))?,
                None if field.required => {
                    return Err(Response::error(500, "required workflow input is missing"));
                }
                None => match &field.default {
                    Some(default) => RuntimeValue::from_json(default),
                    None => field.kind.runtime_value(&Value::Null).map_err(|_| {
                        Response::error(500, "workflow input default conversion failed")
                    })?,
                },
            };
            if !selected.within_bounds() {
                return Err(bad_profile("workflow runtime input exceeds bound"));
            }
            if !field.allowed.is_empty() {
                let mut converted =
                    crate::http::ocsp::CarrierBody(selected.to_json().map_err(|_| {
                        Response::error(500, "workflow input is outside its allowed values")
                    })?);
                if !field.allowed.contains(&converted.0) {
                    return Err(Response::error(
                        500,
                        "workflow input is outside its allowed values",
                    ));
                }
                erase_json(&mut converted.0);
            }
            input.0.insert(name.clone(), selected);
        }
        Ok(input)
    }
    pub(super) fn has_request_credentials(&self) -> bool {
        self.steps.iter().any(|step| step.token.is_some())
    }
    pub(super) fn has_expression_sources(&self) -> bool {
        self.output.has_expression_sources()
            || self.steps.iter().any(|step| {
                [
                    &step.flow_when,
                    &step.when,
                    &step.operation,
                    &step.path,
                    &step.body,
                    &step.allow_failure,
                ]
                .iter()
                .any(|value| value.has_expression_sources())
                    || step
                        .token
                        .as_ref()
                        .is_some_and(Expr::has_expression_sources)
                    || step
                        .headers
                        .as_ref()
                        .is_some_and(Expr::has_expression_sources)
            })
    }
    pub(in crate::service::workflows) fn compile(document: &str) -> Result<Option<Self>, Response> {
        if document.is_empty() || document.len() > MAX_PROFILE_BYTES {
            return Err(bad_profile("workflow profile text is outside bounds"));
        }
        let tokens = workflow_lex_hcl(document).map_err(|_| bad_profile("invalid workflow HCL"))?;
        let mut nesting = 0usize;
        for token in &tokens {
            match token {
                HclToken::Symbol('{' | '[') => {
                    nesting += 1;
                    if nesting > MAX_JSON_DEPTH + 3 {
                        return Err(bad_profile("workflow profile nesting is outside bounds"));
                    }
                }
                HclToken::Symbol('}' | ']') => nesting = nesting.saturating_sub(1),
                _ => (),
            }
        }
        let mut cursor = 0;
        let mut input = None;
        let mut flows = Vec::new();
        let mut flow_names = BTreeSet::new();
        let mut output = None;
        let mut feature = false;
        while cursor < tokens.len() {
            match tokens.get(cursor) {
                Some(HclToken::Word(word)) if word == "input" => {
                    cursor += 1;
                    if input.is_some() {
                        return Err(bad_profile("duplicate workflow input block"));
                    }
                    input = Some(input_fields(&tokens, &mut cursor)?);
                    feature = true;
                }
                Some(HclToken::Word(word)) if word == "flow" => {
                    cursor += 1;
                    let name = workflow_label(&tokens, &mut cursor)?;
                    if !flow_names.insert(name.clone()) || flows.len() >= MAX_STEPS {
                        return Err(bad_profile("duplicate or excessive workflow flow"));
                    }
                    workflow_symbol(&tokens, &mut cursor, '{')?;
                    let mut when = None;
                    let mut requests = Vec::new();
                    while tokens.get(cursor) != Some(&HclToken::Symbol('}')) {
                        match tokens.get(cursor) {
                            Some(HclToken::Word(word)) if word == "when" => {
                                cursor += 1;
                                workflow_symbol(&tokens, &mut cursor, '=')?;
                                if when.is_some() {
                                    return Err(bad_profile("duplicate workflow flow condition"));
                                }
                                when = Some(workflow_attributes(&tokens, &mut cursor)?);
                                feature = true;
                            }
                            Some(HclToken::Word(word)) if word == "request" => {
                                cursor += 1;
                                let request = workflow_label(&tokens, &mut cursor)?;
                                requests
                                    .push((request, workflow_attributes(&tokens, &mut cursor)?));
                                if requests.len() > MAX_STEPS {
                                    return Err(bad_profile("excessive workflow request"));
                                }
                            }
                            _ => return Err(bad_profile("unknown workflow flow statement")),
                        }
                    }
                    cursor += 1;
                    if requests.is_empty() {
                        return Err(bad_profile("workflow flow has no requests"));
                    }
                    flows.push(RawFlow {
                        name,
                        when: when.unwrap_or(Value::Bool(true)),
                        requests,
                    });
                }
                Some(HclToken::Word(word)) if word == "output" => {
                    cursor += 1;
                    if output.is_some() {
                        return Err(bad_profile("duplicate workflow output block"));
                    }
                    let value = workflow_attributes(&tokens, &mut cursor)?;
                    let attrs = value
                        .as_object()
                        .ok_or_else(|| bad_profile("workflow output must be an object"))?;
                    if attrs.keys().any(|key| key != "data") {
                        return Err(bad_profile(
                            "workflow output headers require a header consumer",
                        ));
                    }
                    output = Some(attrs.get("data").cloned().unwrap_or_else(empty_object));
                }
                _ => return Err(bad_profile("unknown workflow profile statement")),
            }
        }
        let output = output.unwrap_or_else(empty_object);
        let names: BTreeSet<_> = flows
            .iter()
            .flat_map(|flow| {
                flow.requests
                    .iter()
                    .map(|(name, _)| step_key(&flow.name, name))
            })
            .collect();
        // The old compiler owns ordinary literal objects (including arbitrary
        // eval_source keys in payloads) unless a real dynamic position opts in.
        if !feature
            && flows.iter().all(|flow| {
                flow.requests.iter().all(|(_, attrs)| {
                    !attrs.as_object().is_some_and(|attrs| {
                        attrs.contains_key("when")
                            || attrs.contains_key("token")
                            || attrs.contains_key("headers")
                    }) && !declared_source(attrs)
                })
            })
            && validate_output(&output, &names, 0).is_ok()
        {
            return Ok(None);
        }
        let fields = input.unwrap_or_default();
        let mut prior = BTreeSet::new();
        let mut steps = Vec::new();
        for flow in flows {
            let flow_when = Expr::compile(&flow.when, &fields, &prior, &mut feature, 0)?;
            for (name, value) in flow.requests {
                let name = step_key(&flow.name, &name);
                let attrs = value
                    .as_object()
                    .ok_or_else(|| bad_profile("workflow request must be an object"))?;
                if attrs.keys().any(|key| {
                    !matches!(
                        key.as_str(),
                        "operation"
                            | "path"
                            | "data"
                            | "allow_failure"
                            | "when"
                            | "token"
                            | "headers"
                    )
                }) {
                    return Err(bad_profile(
                        "workflow request attribute requires a separate consumer",
                    ));
                }
                let operation = attrs
                    .get("operation")
                    .ok_or_else(|| bad_profile("workflow operation is required"))?;
                let path = attrs
                    .get("path")
                    .ok_or_else(|| bad_profile("workflow path is required"))?;
                let body = attrs.get("data").cloned().unwrap_or_else(empty_object);
                let when = attrs.get("when").cloned().unwrap_or(Value::Bool(true));
                let allow_failure = attrs
                    .get("allow_failure")
                    .cloned()
                    .unwrap_or(Value::Bool(false));
                if attrs.contains_key("when")
                    || attrs.contains_key("token")
                    || attrs.contains_key("headers")
                {
                    feature = true;
                }
                let mut bytes = 0;
                bounded_json(&body, 0, &mut bytes).map_err(bad_profile)?;
                let step = Step {
                    name: name.clone(),
                    flow_when: flow_when.clone(),
                    when: Expr::compile(&when, &fields, &prior, &mut feature, 0)?,
                    operation: Expr::compile(operation, &fields, &prior, &mut feature, 0)?,
                    path: Expr::compile(path, &fields, &prior, &mut feature, 0)?,
                    body: Expr::compile(&body, &fields, &prior, &mut feature, 0)?,
                    allow_failure: Expr::compile(&allow_failure, &fields, &prior, &mut feature, 0)?,
                    token: attrs
                        .get("token")
                        .map(|value| Expr::compile(value, &fields, &prior, &mut feature, 0))
                        .transpose()?,
                    headers: attrs
                        .get("headers")
                        .map(|value| Expr::compile(value, &fields, &prior, &mut feature, 0))
                        .transpose()?,
                };
                if !prior.insert(name) || steps.len() >= MAX_STEPS {
                    return Err(bad_profile("duplicate or excessive workflow request"));
                }
                steps.push(step);
            }
        }
        if steps.is_empty() {
            return Err(bad_profile("workflow profile has no requests"));
        }
        if !output.is_object() {
            return Err(bad_profile("workflow output data must be an object"));
        }
        let mut bytes = 0;
        bounded_json(&output, 0, &mut bytes).map_err(bad_profile)?;
        // An ordinary static output reference retains the original 121 compiler.
        let before_output = feature;
        let legacy_output = validate_output(&output, &prior, 0).is_ok();
        let output = Expr::compile(&output, &fields, &prior, &mut feature, 0)?;
        if !before_output && legacy_output {
            return Ok(None);
        }
        Ok(Some(Self {
            fields,
            steps,
            output,
        }))
    }
    pub(super) fn context_at(
        &self,
        body: &Value,
        started: std::time::Instant,
    ) -> Result<Context, Response> {
        let mut input = self.input_values(body)?;
        let context = Context {
            input: std::mem::take(&mut input.0),
            requests: BTreeMap::new(),
            responses: BTreeMap::new(),
            meter: cel_consumer::Meter::new(started),
        };
        for step in &self.steps {
            for value in [
                &step.flow_when,
                &step.when,
                &step.operation,
                &step.path,
                &step.body,
                &step.allow_failure,
            ] {
                value.validate_inputs(&context)?;
            }
            if let Some(token) = &step.token {
                token.validate_inputs(&context)?;
            }
            if let Some(headers) = &step.headers {
                headers.validate_inputs(&context)?;
            }
            step.preflight(&context)?;
        }
        self.output.validate_inputs(&context)?;
        Ok(context)
    }
    pub(super) fn runtime_output(&self, context: &Context) -> Result<RuntimeValue, Response> {
        let output = self.output.resolve(context, 0)?;
        if !output.within_bounds() {
            return Err(bad_profile("workflow runtime output exceeds bound"));
        }
        if output.is_object() {
            Ok(output)
        } else {
            Err(bad_profile("workflow output must resolve to an object"))
        }
    }
}
pub(super) struct Resolved {
    pub(super) step: WorkflowStep,
    history: Value,
    pub(super) token: Option<Zeroizing<String>>,
    pub(super) data_frame: Option<crate::request_metadata::DataFrame>,
}
fn operation_method(operation: &str) -> Result<&'static str, Response> {
    match operation {
        "read" => Ok("GET"),
        "list" => Ok("LIST"),
        "create" | "update" => Ok("POST"),
        "delete" => Ok("DELETE"),
        "patch" => Ok("PATCH"),
        "scan" => Ok("SCAN"),
        _ => Err(bad_profile("invalid resolved workflow operation")),
    }
}
impl Step {
    fn resolved_headers(
        &self,
        context: &Context,
    ) -> Result<Option<crate::request_metadata::DataFrame>, Response> {
        let Some(expression) = &self.headers else {
            return Ok(None);
        };
        let value = expression.resolve(context, 0)?;
        let headers = (|| {
            let object = value
                .as_object()
                .ok_or_else(|| bad_profile("workflow headers must be an object"))?;
            let mut frame = crate::request_metadata::DataFrame::default();
            if object.len() > 64 {
                return Err(bad_profile("logical header count exceeds bound"));
            }
            for (name, value) in object {
                if name.eq_ignore_ascii_case(crate::request_metadata::AUTH_FORM_CODEC_HEADER) {
                    return Err(bad_profile(
                        "workflow cannot set a reserved transport codec header",
                    ));
                }
                let values = value
                    .as_array()
                    .filter(|values| {
                        values.len() <= 64 && values.iter().all(RuntimeValue::is_string)
                    })
                    .ok_or_else(|| {
                        bad_profile("workflow headers must contain bounded string arrays")
                    })?;
                frame.headers.insert(
                    name.clone(),
                    values
                        .iter()
                        .filter_map(RuntimeValue::as_str)
                        .map(str::to_owned)
                        .collect(),
                );
            }
            frame.validate().map_err(bad_profile)?;
            Ok(frame)
        })();
        drop(value);
        headers.map(Some)
    }
    fn resolved_token(&self, context: &Context) -> Result<Option<Zeroizing<String>>, Response> {
        let Some(token) = &self.token else {
            return Ok(None);
        };
        let value = token.resolve(context, 0)?;
        let result = value
            .as_str()
            .filter(|token| token.len() <= 16 * 1024)
            .map(|token| Zeroizing::new(token.to_owned()));
        drop(value);
        result
            .map(Some)
            .ok_or_else(|| bad_profile("workflow token must resolve to a bounded string"))
    }
    fn preflight(&self, context: &Context) -> Result<(), Response> {
        // Inputs and independent positions are checked for the complete program
        // before the first provider. History-dependent values are checked only
        // against actual earlier responses, immediately before their own effect.
        for condition in [&self.flow_when, &self.when, &self.allow_failure] {
            if !condition.needs_history() && !condition.resolve(context, 0)?.is_boolean() {
                return Err(bad_profile("workflow condition must resolve to boolean"));
            }
        }
        if !self.operation.needs_history() {
            let value = self.operation.resolve(context, 0)?;
            let operation = value
                .as_str()
                .ok_or_else(|| bad_profile("workflow operation must resolve to a string"))?;
            operation_method(operation)?;
        }
        if !self.path.needs_history() {
            let value = self.path.resolve(context, 0)?;
            validate_workflow_path(
                value
                    .as_str()
                    .ok_or_else(|| bad_profile("workflow path must resolve to a string"))?,
            )
            .map_err(bad_profile)?;
        }
        if !self.body.needs_history() && !self.body.has_deferred_cast() {
            let value = self.body.resolve(context, 0)?;
            if !value.is_object() {
                return Err(bad_profile(
                    "workflow request data must resolve to an object",
                ));
            }
            if !value.within_bounds() {
                return Err(bad_profile("workflow runtime request exceeds bound"));
            }
        }
        if self
            .token
            .as_ref()
            .is_some_and(|token| !token.needs_history())
        {
            self.resolved_token(context)?;
        }
        if self
            .headers
            .as_ref()
            .is_some_and(|headers| !headers.needs_history())
        {
            self.resolved_headers(context)?;
        }
        Ok(())
    }
    pub(super) fn resolve(&self, context: &Context) -> Result<Option<Resolved>, Response> {
        let flow_when = self.flow_when.resolve(context, 0)?;
        let flow_when = flow_when
            .as_bool()
            .ok_or_else(|| bad_profile("workflow flow condition must be boolean"))?;
        if !flow_when {
            return Ok(None);
        }
        let when = self.when.resolve(context, 0)?;
        let when = when
            .as_bool()
            .ok_or_else(|| bad_profile("workflow request condition must be boolean"))?;
        if !when {
            return Ok(None);
        }
        let operation = self.operation.resolve(context, 0)?;
        let operation = operation
            .as_str()
            .ok_or_else(|| bad_profile("workflow operation must resolve to a string"))?;
        let method = operation_method(operation)?;
        let path = self.path.resolve(context, 0)?;
        let path = path
            .as_str()
            .ok_or_else(|| bad_profile("workflow path must resolve to a string"))?;
        validate_workflow_path(path).map_err(bad_profile)?;
        let body = self.body.resolve(context, 0)?;
        if !body.is_object() {
            return Err(bad_profile(
                "workflow request data must resolve to an object",
            ));
        }
        if !body.within_bounds() {
            return Err(bad_profile("workflow runtime request exceeds bound"));
        }
        // This request's save boundary is after preceding steps committed.
        let mut body = crate::http::ocsp::CarrierBody(
            body.to_json()
                .map_err(|_| Response::error(500, "workflow request JSON encoding failed"))?,
        );
        let allow_failure = self.allow_failure.resolve(context, 0)?;
        let allow_failure = allow_failure
            .as_bool()
            .ok_or_else(|| bad_profile("workflow allow_failure must be boolean"))?;
        let token = self.resolved_token(context)?;
        let data_frame = self.resolved_headers(context)?;
        let mut history = json!({"name":self.name, "operation":operation, "path":path,
            "data":&body.0, "allow_failure":allow_failure, "when":when});
        if let Some(token) = &token {
            history["token"] = Value::String(token.to_string());
        }
        if let Some(frame) = &data_frame {
            history["headers"] = serde_json::to_value(&frame.headers)
                .map_err(|_| bad_profile("workflow header encoding failed"))?;
        }
        Ok(Some(Resolved {
            step: WorkflowStep {
                name: self.name.clone(),
                method: method.into(),
                path: path.into(),
                body: std::mem::take(&mut body.0),
                allow_failure,
            },
            history,
            token,
            data_frame,
        }))
    }
}
impl Context {
    fn expression_bindings(&self) -> (RuntimeValue, RuntimeValue, RuntimeValue) {
        fn nested(values: &BTreeMap<String, RuntimeValue>) -> RuntimeValue {
            let mut flows = RuntimeValue::object();
            for (name, value) in values {
                if let Some((flow, member)) = name.split_once('/') {
                    let mut members = flows
                        .as_object()
                        .and_then(|flows| flows.get(flow))
                        .cloned()
                        .unwrap_or_else(RuntimeValue::object);
                    members.insert(member.to_owned(), value.clone());
                    flows.insert(flow.to_owned(), members);
                }
            }
            flows
        }
        let mut input = RuntimeValue::object();
        for (name, value) in &self.input {
            input.insert(name.clone(), value.clone());
        }
        (input, nested(&self.requests), nested(&self.responses))
    }
    pub(super) fn record_response(&mut self, resolved: Resolved, response: &mut Response) {
        if let Some(output) = response
            .unwrapped_json
            .as_ref()
            .and_then(|origin| origin.workflow_value())
        {
            let mut value = RuntimeValue::object();
            value.insert("data".into(), output.clone());
            let mut resolved = resolved;
            let name = resolved.step.name.clone();
            self.requests
                .insert(name.clone(), RuntimeValue::from_json(&resolved.history));
            erase_json(&mut resolved.history);
            self.responses.insert(name, value);
        } else {
            self.record(resolved, std::mem::take(&mut response.body));
        }
    }
    pub(super) fn record(&mut self, mut resolved: Resolved, mut response: Value) {
        let name = resolved.step.name.clone();
        self.requests
            .insert(name.clone(), RuntimeValue::from_json(&resolved.history));
        erase_json(&mut resolved.history);
        self.responses
            .insert(name, RuntimeValue::from_response_json(&response));
        erase_json(&mut response);
    }
}
impl Drop for Context {
    fn drop(&mut self) {
        for values in [&mut self.input, &mut self.requests, &mut self.responses] {
            for (mut key, value) in std::mem::take(values) {
                key.zeroize();
                drop(value);
            }
        }
    }
}

impl Drop for Resolved {
    fn drop(&mut self) {
        erase_json(&mut self.step.body);
        erase_json(&mut self.history);
    }
}

#[cfg(test)]
mod approle_form_tests {
    use super::*;
    #[test]
    fn workflow_cannot_forge_transport_codec_but_content_type_is_data() {
        let context = Context {
            input: BTreeMap::new(),
            requests: BTreeMap::new(),
            responses: BTreeMap::new(),
            meter: cel_consumer::Meter::new(std::time::Instant::now()),
        };
        for name in [
            crate::request_metadata::AUTH_FORM_CODEC_HEADER.to_owned(),
            crate::request_metadata::AUTH_FORM_CODEC_HEADER.to_ascii_uppercase(),
            "content-type".to_owned(),
        ] {
            let step = Step {
                name: "store/kv".into(),
                flow_when: Expr::Literal(json!(true)),
                when: Expr::Literal(json!(true)),
                operation: Expr::Literal(json!("update")),
                path: Expr::Literal(json!("secret/data/key")),
                body: Expr::Literal(json!({"data":{"value":"synthetic"}})),
                allow_failure: Expr::Literal(json!(false)),
                token: None,
                headers: Some(Expr::Literal(json!({name.clone(): ["approle-form-v1"]}))),
            };
            match step.resolved_headers(&context) {
                Err(error) => {
                    assert_ne!(name, "content-type");
                    assert_eq!(error.status, 400);
                }
                Ok(Some(data)) => {
                    assert_eq!(name, "content-type");
                    assert!(!data.is_approle_form());
                }
                Ok(None) => panic!("declared headers disappeared"),
            }
        }
    }
}
