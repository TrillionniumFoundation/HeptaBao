//! Typed dynamic data stays request-local; the Service interpreter owns effects.
use super::*;
#[path = "service_workflow_cel.rs"]
mod cel_consumer;
#[path = "service_workflow_template.rs"]
mod template_consumer;

#[derive(Clone, Copy)]
enum Kind {
    Any,
    String,
    Int,
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
            "int" | "int64" => Ok(Self::Int),
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
}

#[derive(Clone, Copy)]
enum InputKind {
    Value(Kind),
    Slice,
}
impl InputKind {
    fn parse(raw: &str) -> Result<Self, Response> {
        match raw {
            "string" => Ok(Self::Value(Kind::String)),
            "int" | "int64" => Ok(Self::Value(Kind::Int)),
            "bool" => Ok(Self::Value(Kind::Bool)),
            "map" => Ok(Self::Value(Kind::Map)),
            "slice" => Ok(Self::Slice),
            _ => Err(bad_profile(
                "workflow input field type is not supported by this consumer",
            )),
        }
    }
    fn value(self, value: &Value) -> Result<Value, Response> {
        match self {
            Self::Value(kind) => kind.value(value),
            Self::Slice if value.is_array() => Ok(value.clone()),
            Self::Slice => Err(bad_profile("workflow input must be an array")),
        }
    }
}
struct Field {
    kind: InputKind,
    required: bool,
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
                    return Ok(Self::Template(kind, template_consumer::TemplateSource::compile(object)?, Box::new(data)));
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
            Self::Source(_, Source::Request(..) | Source::Response(..)) | Self::Cel(..) | Self::Template(..) => true,
            Self::Object(object) => object.values().any(Self::needs_history),
            Self::Array(array) => array.iter().any(Self::needs_history),
            _ => false,
        }
    }
    fn validate_inputs(&self, context: &Context) -> Result<(), Response> {
        match self {
            Self::Template(_, source, data) => {
                source.preflight(&context.meter)?;
                data.validate_inputs(context)?;
            }
            Self::Cel(kind, source) => {
                let (input, requests, responses) = context.expression_bindings();
                if let Some(value) = source.preflight(&input, &requests, &responses, &context.meter)? {
                    kind.value(&value).map_err(|_| Response::error(500, "workflow expression result type rejected"))?;
                }
            }
            Self::Source(kind, Source::Input(name)) => {
                let value = context
                    .input
                    .get(name)
                    .ok_or_else(|| bad_profile("declared workflow input is unavailable"))?;
                kind.value(value)?;
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
    fn resolve(&self, context: &Context, depth: usize) -> Result<Value, Response> {
        if depth > MAX_JSON_DEPTH {
            return Err(bad_profile(
                "workflow evaluated value nesting is outside bounds",
            ));
        }
        match self {
            Self::Template(kind, source, data) => {
                let (input, requests, responses) = context.expression_bindings();
                let data = data.resolve(context, depth + 1)?;
                let value = source.evaluate(&input, &requests, &responses, &data, &context.meter)?;
                kind.value(&value).map_err(|_| Response::error(500, "workflow template result type rejected"))
            }
            Self::Cel(kind, source) => {
                let (input, requests, responses) = context.expression_bindings();
                let value = source.evaluate(&input, &requests, &responses, &context.meter)?;
                kind.value(&value).map_err(|_| Response::error(500, "workflow expression result type rejected"))
            }
            Self::Literal(value) => Ok(value.clone()),
            Self::Object(object) => object
                .iter()
                .map(|(key, value)| Ok((key.clone(), value.resolve(context, depth + 1)?)))
                .collect::<Result<serde_json::Map<_, _>, Response>>()
                .map(Value::Object),
            Self::Array(array) => array
                .iter()
                .map(|value| value.resolve(context, depth + 1))
                .collect::<Result<Vec<_>, _>>()
                .map(Value::Array),
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
                kind.value(selected)
            }
        }
    }
}
fn select<'a>(mut value: &'a Value, selector: &[String]) -> Option<&'a Value> {
    for field in selector {
        value = match value {
            Value::Object(object) => object.get(field)?,
            Value::Array(array) => array.get(field.parse::<usize>().ok()?)?,
            _ => return None,
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
fn input_fields(tokens: &[Lex], cursor: &mut usize) -> Result<BTreeMap<String, Field>, Response> {
    symbol(tokens, cursor, '{')?;
    let mut fields = BTreeMap::new();
    while tokens.get(*cursor) != Some(&Lex::Symbol('}')) {
        if tokens.get(*cursor) != Some(&Lex::Word("field".into())) {
            return Err(bad_profile("workflow input accepts only field blocks"));
        }
        *cursor += 1;
        let mut labels = Vec::new();
        while let Some(Lex::String(value)) = tokens.get(*cursor) {
            labels.push(value.clone());
            *cursor += 1;
        }
        if labels.len() > 2 || fields.len() >= 64 {
            return Err(bad_profile(
                "workflow input field labels or count exceed bounds",
            ));
        }
        let value = attributes(tokens, cursor)?;
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
        if boolean(attrs, "query", false)? {
            return Err(bad_profile(
                "workflow query input requires a query carrier consumer",
            ));
        }
        if text(attrs, "description")?.is_some_and(|text| text.len() > MAX_JSON_STRING_BYTES) {
            return Err(bad_profile("workflow input description is outside bounds"));
        }
        let default = attrs
            .get("default")
            .map(|value| kind.value(value))
            .transpose()?;
        if !required && default.is_none() {
            return Err(bad_profile(
                "optional workflow input requires a typed default",
            ));
        }
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
}
pub(in crate::service::workflows) struct Program {
    fields: BTreeMap<String, Field>,
    pub(super) steps: Vec<Step>,
    output: Expr,
}
pub(super) struct Context {
    input: BTreeMap<String, Value>,
    requests: BTreeMap<String, Value>,
    responses: BTreeMap<String, Value>,
    meter: std::sync::Arc<cel_consumer::Meter>,
}
impl Program {
    pub(super) fn has_request_credentials(&self) -> bool {
        self.steps.iter().any(|step| step.token.is_some())
    }
    pub(super) fn has_expression_sources(&self) -> bool {
        self.output.has_expression_sources() || self.steps.iter().any(|step| [&step.flow_when, &step.when, &step.operation, &step.path, &step.body, &step.allow_failure].iter().any(|value| value.has_expression_sources()) || step.token.as_ref().is_some_and(Expr::has_expression_sources))
    }
    pub(super) fn compile(document: &str) -> Result<Option<Self>, Response> {
        if document.is_empty() || document.len() > MAX_PROFILE_BYTES {
            return Err(bad_profile("workflow profile text is outside bounds"));
        }
        let tokens = lex_hcl(document).map_err(|_| bad_profile("invalid workflow HCL"))?;
        let mut nesting = 0usize;
        for token in &tokens {
            match token {
                Lex::Symbol('{' | '[') => {
                    nesting += 1;
                    if nesting > MAX_JSON_DEPTH + 3 {
                        return Err(bad_profile("workflow profile nesting is outside bounds"));
                    }
                }
                Lex::Symbol('}' | ']') => nesting = nesting.saturating_sub(1),
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
                Some(Lex::Word(word)) if word == "input" => {
                    cursor += 1;
                    if input.is_some() {
                        return Err(bad_profile("duplicate workflow input block"));
                    }
                    input = Some(input_fields(&tokens, &mut cursor)?);
                    feature = true;
                }
                Some(Lex::Word(word)) if word == "flow" => {
                    cursor += 1;
                    let name = label(&tokens, &mut cursor)?;
                    if !flow_names.insert(name.clone()) || flows.len() >= MAX_STEPS {
                        return Err(bad_profile("duplicate or excessive workflow flow"));
                    }
                    symbol(&tokens, &mut cursor, '{')?;
                    let mut when = None;
                    let mut requests = Vec::new();
                    while tokens.get(cursor) != Some(&Lex::Symbol('}')) {
                        match tokens.get(cursor) {
                            Some(Lex::Word(word)) if word == "when" => {
                                cursor += 1;
                                symbol(&tokens, &mut cursor, '=')?;
                                if when.is_some() {
                                    return Err(bad_profile("duplicate workflow flow condition"));
                                }
                                when = Some(attributes(&tokens, &mut cursor)?);
                                feature = true;
                            }
                            Some(Lex::Word(word)) if word == "request" => {
                                cursor += 1;
                                let request = label(&tokens, &mut cursor)?;
                                requests.push((request, attributes(&tokens, &mut cursor)?));
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
                Some(Lex::Word(word)) if word == "output" => {
                    cursor += 1;
                    if output.is_some() {
                        return Err(bad_profile("duplicate workflow output block"));
                    }
                    let value = attributes(&tokens, &mut cursor)?;
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
                    !attrs
                        .as_object()
                        .is_some_and(|attrs| attrs.contains_key("when") || attrs.contains_key("token"))
                        && !declared_source(attrs)
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
                        "operation" | "path" | "data" | "allow_failure" | "when" | "token"
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
                if attrs.contains_key("when") || attrs.contains_key("token") {
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
                    token: attrs.get("token").map(|value| Expr::compile(value, &fields, &prior, &mut feature, 0)).transpose()?,
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
    #[cfg(test)]
    pub(super) fn context(&self, body: &Value) -> Result<Context, Response> {
        self.context_at(body, std::time::Instant::now())
    }
    pub(super) fn context_at(&self, body: &Value, started: std::time::Instant) -> Result<Context, Response> {
        let supplied = body
            .as_object()
            .ok_or_else(|| bad_profile("workflow input must be an object"))?;
        let mut bytes = 0;
        bounded_json(body, 0, &mut bytes).map_err(bad_profile)?;
        let mut input = BTreeMap::new();
        for (name, field) in &self.fields {
            let selected = match supplied.get(name) {
                Some(value) => field.kind.value(value)?,
                None if field.required => {
                    return Err(bad_profile("required workflow input is missing"));
                }
                None => field
                    .default
                    .clone()
                    .ok_or_else(|| bad_profile("workflow input default is unavailable"))?,
            };
            let mut selected_bytes = 0;
            bounded_json(&selected, 0, &mut selected_bytes).map_err(bad_profile)?;
            if !field.allowed.is_empty() && !field.allowed.contains(&selected) {
                return Err(bad_profile("workflow input is outside its allowed values"));
            }
            input.insert(name.clone(), selected);
        }
        let context = Context {
            input,
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
            if let Some(token) = &step.token { token.validate_inputs(&context)?; }
            step.preflight(&context)?;
        }
        self.output.validate_inputs(&context)?;
        Ok(context)
    }
    pub(super) fn output(&self, context: &Context) -> Result<Value, Response> {
        let output = self.output.resolve(context, 0)?;
        let mut bytes = 0;
        bounded_json(&output, 0, &mut bytes).map_err(bad_profile)?;
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
    fn resolved_token(&self, context: &Context) -> Result<Option<Zeroizing<String>>, Response> {
        let Some(token) = &self.token else { return Ok(None); };
        let mut value = token.resolve(context, 0)?;
        let result = value.as_str().filter(|token| token.len() <= 16 * 1024)
            .map(|token| Zeroizing::new(token.to_owned()));
        erase_json(&mut value);
        result.map(Some).ok_or_else(|| bad_profile("workflow token must resolve to a bounded string"))
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
        if !self.body.needs_history() {
            let value = self.body.resolve(context, 0)?;
            if !value.is_object() {
                return Err(bad_profile(
                    "workflow request data must resolve to an object",
                ));
            }
            let mut bytes = 0;
            bounded_json(&value, 0, &mut bytes).map_err(bad_profile)?;
        }
        if self.token.as_ref().is_some_and(|token| !token.needs_history()) {
            self.resolved_token(context)?;
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
        let mut bytes = 0;
        bounded_json(&body, 0, &mut bytes).map_err(bad_profile)?;
        let allow_failure = self.allow_failure.resolve(context, 0)?;
        let allow_failure = allow_failure
            .as_bool()
            .ok_or_else(|| bad_profile("workflow allow_failure must be boolean"))?;
        let token = self.resolved_token(context)?;
        let mut history = json!({"name":self.name, "operation":operation, "path":path,
            "data":body, "allow_failure":allow_failure, "when":when});
        if let Some(token) = &token { history["token"] = Value::String(token.to_string()); }
        Ok(Some(Resolved {
            step: WorkflowStep {
                name: self.name.clone(),
                method: method.into(),
                path: path.into(),
                body,
                allow_failure,
            },
            history,
            token,
        }))
    }
}
impl Context {
    fn expression_bindings(&self) -> (Value, Value, Value) {
        fn nested(history: &BTreeMap<String, Value>) -> Value {
            let mut flows = serde_json::Map::new();
            for (key, value) in history {
                if let Some((flow, name)) = key.split_once('/') {
                    let flow = flows.entry(flow.to_owned()).or_insert_with(empty_object);
                    if let Some(flow) = flow.as_object_mut() { flow.insert(name.to_owned(), value.clone()); }
                }
            }
            Value::Object(flows)
        }
        (Value::Object(self.input.clone().into_iter().collect()), nested(&self.requests), nested(&self.responses))
    }
    pub(super) fn record(&mut self, mut resolved: Resolved, response: Value) {
        let name = resolved.step.name.clone();
        self.requests.insert(name.clone(), std::mem::take(&mut resolved.history));
        self.responses.insert(name, response);
    }
}

impl Drop for Context {
    fn drop(&mut self) {
        for value in self.input.values_mut().chain(self.requests.values_mut()).chain(self.responses.values_mut()) {
            erase_json(value);
        }
    }
}
impl Drop for Resolved {
    fn drop(&mut self) {
        erase_json(&mut self.step.body);
        erase_json(&mut self.history);
    }
}
