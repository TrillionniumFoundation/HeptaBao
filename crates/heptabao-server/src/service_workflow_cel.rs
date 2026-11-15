//! The maintained CEL parser and evaluator run behind one request-owned meter.
use super::*;
use cel::common::ast::{CallExpr, EntryExpr, Expr as AstExpr, IdedExpr, LiteralValue};
use cel::objects::{Key, Map, Opaque, OptionalValue};
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant};

const GUARD: &str = "__heptabao_workflow_meter_125";
const MAX_SOURCE: usize = 16 * 1024;
const MAX_AST_NODES: usize = 4096;
const MAX_AST_DEPTH: usize = 64;
const MAX_VALUE: usize = 64 * 1024;
const MAX_TICKS: u64 = 20_000;
const MAX_WORK: u64 = 512 * 1024 * 1024;
const MAX_OUTPUT: u64 = 32 * 1024 * 1024;
const MAX_ELAPSED: Duration = Duration::from_secs(5);

fn failed() -> Response {
    Response::error(500, "workflow expression evaluation failed")
}
fn execution_failed() -> cel::ExecutionError {
    cel::ExecutionError::function_error(GUARD, "workflow execution budget or value rejected")
}
pub(super) struct Meter {
    deadline: Instant,
    ticks: AtomicU64,
    work: AtomicU64,
    output: AtomicU64,
    exhausted: AtomicBool,
}
impl Meter {
    pub(super) fn new(started: Instant) -> Arc<Self> {
        Arc::new(Self {
            deadline: started.checked_add(MAX_ELAPSED).unwrap_or(started),
            ticks: AtomicU64::new(MAX_TICKS),
            work: AtomicU64::new(MAX_WORK),
            output: AtomicU64::new(MAX_OUTPUT),
            exhausted: AtomicBool::new(false),
        })
    }
    fn reject(&self) -> cel::ExecutionError {
        self.exhausted.store(true, Ordering::Relaxed);
        execution_failed()
    }
    fn take(&self, counter: &AtomicU64, amount: u64) -> Result<(), cel::ExecutionError> {
        counter
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |left| {
                left.checked_sub(amount)
            })
            .map(|_| ())
            .map_err(|_| self.reject())
    }
    pub(super) fn check(&self) -> Result<(), Response> {
        if self.exhausted.load(Ordering::Relaxed) || Instant::now() >= self.deadline {
            self.exhausted.store(true, Ordering::Relaxed);
            Err(failed())
        } else {
            Ok(())
        }
    }
    pub(super) fn tick(&self) -> Result<(), cel::ExecutionError> {
        self.check().map_err(|_| execution_failed())?;
        self.take(&self.ticks, 1)?;
        // Every primitive consumes a conservative full-value work allowance.
        self.take(&self.work, MAX_VALUE as u64)
    }
    pub(super) fn template_bytes(&self, bytes: usize) -> Result<(), Response> {
        self.check()?;
        if bytes > MAX_VALUE {
            let _ = self.reject();
            return Err(failed());
        }
        self.take(&self.output, bytes as u64)
            .map_err(|_| failed())?;
        self.check()
    }
    fn value(&self, value: &cel::Value) -> Result<(), cel::ExecutionError> {
        let bytes = value_size(value, 0).ok_or_else(|| self.reject())?;
        if bytes > MAX_VALUE {
            return Err(self.reject());
        }
        self.take(&self.output, bytes as u64)?;
        self.check().map_err(|_| execution_failed())
    }
}
#[derive(Debug, PartialEq, Eq)]
struct TypeValue(&'static str);
impl Opaque for TypeValue {
    fn runtime_type_name(&self) -> &str {
        "heptabao.cel.type"
    }
}
fn type_value(value: cel::Value) -> cel::ResolveResult {
    let name = match value {
        cel::Value::Null => "null_type",
        cel::Value::Bool(_) => "bool",
        cel::Value::Int(_) => "int",
        cel::Value::UInt(_) => "uint",
        cel::Value::Float(_) => "double",
        cel::Value::String(_) => "string",
        cel::Value::List(_) => "list",
        cel::Value::Map(_) => "map",
        cel::Value::Opaque(ref value) if value.downcast_ref::<TypeValue>().is_some() => "type",
        _ => return Err(execution_failed()),
    };
    Ok(cel::Value::Opaque(Arc::new(TypeValue(name))))
}
fn value_size(value: &cel::Value, depth: usize) -> Option<usize> {
    if depth > MAX_AST_DEPTH {
        return None;
    }
    let add = |a: usize, b: usize| a.checked_add(b).filter(|n| *n <= MAX_VALUE);
    match value {
        cel::Value::Null | cel::Value::Bool(_) | cel::Value::Int(_) | cel::Value::UInt(_) => {
            Some(16)
        }
        cel::Value::Float(_) => Some(16),
        cel::Value::String(value) => add(8, value.len()),
        cel::Value::List(values) => values
            .iter()
            .try_fold(8, |sum, value| add(sum, value_size(value, depth + 1)?)),
        cel::Value::Map(values) => values.map.iter().try_fold(8, |sum, (key, value)| {
            let key_bytes = match key {
                Key::String(value) => value.len(),
                _ => 16,
            };
            add(add(sum, key_bytes)?, value_size(value, depth + 1)?)
        }),
        cel::Value::Opaque(value) => {
            if value.downcast_ref::<TypeValue>().is_some() {
                return Some(16);
            }
            let optional = value.downcast_ref::<OptionalValue>()?;
            optional
                .value()
                .map_or(Some(8), |value| value_size(value, depth + 1))
        }
        _ => None,
    }
}
fn json_to_cel(
    value: &Value,
    response_numbers: bool,
    depth: usize,
) -> Result<cel::Value, Response> {
    if depth > MAX_AST_DEPTH {
        return Err(failed());
    }
    let result = match value {
        Value::Null => cel::Value::Null,
        Value::Bool(value) => cel::Value::Bool(*value),
        Value::String(value) => cel::Value::String(Arc::new(value.clone())),
        Value::Number(value) if response_numbers => cel::Value::Float(
            value
                .as_f64()
                .filter(|v| v.is_finite())
                .ok_or_else(failed)?,
        ),
        Value::Number(value) => {
            if let Some(value) = value.as_i64() {
                cel::Value::Int(value)
            } else if let Some(value) = value.as_u64() {
                cel::Value::UInt(value)
            } else {
                cel::Value::Float(
                    value
                        .as_f64()
                        .filter(|v| v.is_finite())
                        .ok_or_else(failed)?,
                )
            }
        }
        Value::Array(values) => cel::Value::List(Arc::new(
            values
                .iter()
                .map(|value| json_to_cel(value, response_numbers, depth + 1))
                .collect::<Result<_, _>>()?,
        )),
        Value::Object(values) => cel::Value::Map(Map {
            map: Arc::new(
                values
                    .iter()
                    .map(|(key, value)| {
                        Ok((
                            Key::String(Arc::new(key.clone())),
                            json_to_cel(value, response_numbers, depth + 1)?,
                        ))
                    })
                    .collect::<Result<HashMap<_, _>, Response>>()?,
            ),
        }),
    };
    if value_size(&result, 0).is_none() {
        return Err(failed());
    }
    Ok(result)
}
fn runtime_to_cel(
    value: &RuntimeValue,
    response_numbers: bool,
    depth: usize,
) -> Result<cel::Value, Response> {
    if depth > MAX_AST_DEPTH {
        return Err(failed());
    }
    let result = if let Some(value) = value.actual_float() {
        cel::Value::Float(value)
    } else if let Some(value) = value.json_scalar() {
        json_to_cel(value, response_numbers, depth)?
    } else if let Some(values) = value.as_array() {
        cel::Value::List(Arc::new(
            values
                .iter()
                .map(|value| runtime_to_cel(value, response_numbers, depth + 1))
                .collect::<Result<Vec<_>, _>>()?,
        ))
    } else if let Some(values) = value.as_object() {
        cel::Value::Map(Map {
            map: Arc::new(
                values
                    .iter()
                    .map(|(key, value)| {
                        Ok((
                            Key::String(Arc::new(key.clone())),
                            runtime_to_cel(value, response_numbers, depth + 1)?,
                        ))
                    })
                    .collect::<Result<HashMap<_, _>, Response>>()?,
            ),
        })
    } else {
        return Err(failed());
    };
    if value_size(&result, 0).is_none() {
        return Err(failed());
    }
    Ok(result)
}
fn cel_to_runtime(value: &cel::Value, depth: usize) -> Result<RuntimeValue, Response> {
    if depth > MAX_AST_DEPTH {
        return Err(failed());
    }
    match value {
        cel::Value::Null => Ok(RuntimeValue::from_json(&Value::Null)),
        cel::Value::Bool(value) => Ok(RuntimeValue::from_json(&Value::Bool(*value))),
        cel::Value::Int(value) => Ok(RuntimeValue::from_json(&Value::from(*value))),
        cel::Value::UInt(value) => Ok(RuntimeValue::from_json(&Value::from(*value))),
        cel::Value::Float(value) => Ok(RuntimeValue::float(*value)),
        cel::Value::String(value) => Ok(RuntimeValue::string(value.as_ref().clone())),
        cel::Value::List(values) => values
            .iter()
            .map(|value| cel_to_runtime(value, depth + 1))
            .collect::<Result<Vec<_>, _>>()
            .map(RuntimeValue::array),
        cel::Value::Map(values) => {
            let mut result = RuntimeValue::object();
            for (key, value) in values.map.iter() {
                let Key::String(key) = key else {
                    return Err(failed());
                };
                result.insert(key.as_ref().clone(), cel_to_runtime(value, depth + 1)?);
            }
            Ok(result)
        }
        _ => Err(failed()),
    }
}
fn instrument(
    mut expression: IdedExpr,
    depth: usize,
    count: &mut usize,
) -> Result<IdedExpr, Response> {
    *count = count.checked_add(1).ok_or_else(failed)?;
    if depth > MAX_AST_DEPTH || *count > MAX_AST_NODES {
        return Err(failed());
    }
    match &mut expression.expr {
        AstExpr::Unspecified | AstExpr::Struct(_) | AstExpr::Literal(LiteralValue::Bytes(_)) => {
            return Err(failed());
        }
        AstExpr::Ident(name) if name == GUARD => return Err(failed()),
        AstExpr::Call(call) => {
            if call.func_name == GUARD || call.func_name == "bytes" {
                return Err(failed());
            }
            if let Some(target) = &mut call.target {
                // Maintained CEL uses an identifier target for qualified function lookup.
                if !matches!(target.expr, AstExpr::Ident(_)) {
                    **target = instrument((**target).clone(), depth + 1, count)?;
                }
            }
            for argument in &mut call.args {
                *argument = instrument(argument.clone(), depth + 1, count)?;
            }
        }
        AstExpr::Select(select) => {
            *select.operand = instrument((*select.operand).clone(), depth + 1, count)?;
        }
        AstExpr::List(list) => {
            if list
                .optional_indices
                .iter()
                .any(|index| *index >= list.elements.len())
            {
                return Err(failed());
            }
            for item in &mut list.elements {
                *item = instrument(item.clone(), depth + 1, count)?;
            }
        }
        AstExpr::Map(map) => {
            for entry in &mut map.entries {
                let EntryExpr::MapEntry(entry) = &mut entry.expr else {
                    return Err(failed());
                };
                entry.key = instrument(entry.key.clone(), depth + 1, count)?;
                entry.value = instrument(entry.value.clone(), depth + 1, count)?;
            }
        }
        AstExpr::Comprehension(comprehension) => {
            if [&comprehension.iter_var, &comprehension.accu_var]
                .iter()
                .any(|name| name.as_str() == GUARD)
                || comprehension.iter_var2.as_deref() == Some(GUARD)
            {
                return Err(failed());
            }
            for item in [
                &mut comprehension.iter_range,
                &mut comprehension.accu_init,
                &mut comprehension.loop_cond,
                &mut comprehension.loop_step,
                &mut comprehension.result,
            ] {
                *item = instrument(item.clone(), depth + 1, count)?;
            }
        }
        _ => (),
    }
    Ok(IdedExpr {
        id: expression.id,
        expr: AstExpr::Call(CallExpr {
            func_name: GUARD.into(),
            target: None,
            args: vec![expression],
        }),
    })
}
fn parse(source: &str, meter: &Meter) -> Result<IdedExpr, Response> {
    meter.check()?;
    if source.is_empty() || source.len() > MAX_SOURCE {
        return Err(failed());
    }
    let expression = cel::parser::Parser::new()
        .max_recursion_depth(48)
        .parse(source)
        .map_err(|_| failed())?;
    meter.check()?;
    let mut count = 0;
    instrument(expression, 0, &mut count)
}
#[derive(Clone)]
pub(super) struct CelSource {
    expression: String,
    variables: Vec<(String, String)>,
}
impl CelSource {
    pub(super) fn compile(object: &serde_json::Map<String, Value>) -> Result<Self, Response> {
        let expression = object
            .get("expression")
            .and_then(Value::as_str)
            .filter(|value| !value.is_empty() && value.len() <= MAX_SOURCE)
            .ok_or_else(|| bad_profile("CEL expression is outside bounds"))?
            .to_owned();
        let mut variables = Vec::new();
        let mut names = BTreeSet::new();
        if let Some(raw) = object.get("variables") {
            let raw = raw
                .as_array()
                .filter(|items| items.len() <= 64)
                .ok_or_else(|| bad_profile("CEL variables must be a bounded ordered array"))?;
            for variable in raw {
                let variable = variable
                    .as_object()
                    .ok_or_else(|| bad_profile("invalid CEL variable"))?;
                if variable.len() != 2
                    || !variable.contains_key("name")
                    || !variable.contains_key("expression")
                {
                    return Err(bad_profile("invalid CEL variable attributes"));
                }
                let name = variable["name"]
                    .as_str()
                    .filter(|name| validate_name(name, 64))
                    .ok_or_else(|| bad_profile("invalid CEL variable name"))?;
                if matches!(
                    name,
                    "input"
                        | "requests"
                        | "responses"
                        | "int"
                        | "uint"
                        | "double"
                        | "bool"
                        | "string"
                        | "list"
                        | "map"
                        | "type"
                        | "null_type"
                ) || name == GUARD
                    || !names.insert(name.to_owned())
                {
                    return Err(bad_profile("reserved or duplicate CEL variable name"));
                }
                let source = variable["expression"]
                    .as_str()
                    .filter(|source| !source.is_empty() && source.len() <= MAX_SOURCE)
                    .ok_or_else(|| bad_profile("CEL variable expression is outside bounds"))?;
                variables.push((name.to_owned(), source.to_owned()));
            }
        }
        Ok(Self {
            expression,
            variables,
        })
    }
    pub(super) fn preflight_runtime(
        &self,
        input: &RuntimeValue,
        requests: &RuntimeValue,
        responses: &RuntimeValue,
        meter: &Arc<Meter>,
    ) -> Result<Option<RuntimeValue>, Response> {
        let mut history = false;
        for source in self
            .variables
            .iter()
            .map(|(_, source)| source.as_str())
            .chain(std::iter::once(self.expression.as_str()))
        {
            let parsed = parse(source, meter)?;
            let references = parsed.references();
            history |= references.has_variable("requests") || references.has_variable("responses");
        }
        if history {
            Ok(None)
        } else {
            self.evaluate_runtime(input, requests, responses, meter)
                .map(Some)
        }
    }
    pub(super) fn evaluate_runtime(
        &self,
        input: &RuntimeValue,
        requests: &RuntimeValue,
        responses: &RuntimeValue,
        meter: &Arc<Meter>,
    ) -> Result<RuntimeValue, Response> {
        meter.check()?;
        // Parse all ordered expressions before the evaluator can run any one of them.
        let parsed = self
            .variables
            .iter()
            .map(|(_, source)| parse(source, meter))
            .collect::<Result<Vec<_>, _>>()?;
        let expression = parse(&self.expression, meter)?;
        let mut context = cel::Context::default();
        context.add_variable_from_value("input", runtime_to_cel(input, false, 0)?);
        context.add_variable_from_value("requests", runtime_to_cel(requests, false, 0)?);
        context.add_variable_from_value("responses", runtime_to_cel(responses, true, 0)?);
        for name in [
            "int",
            "uint",
            "double",
            "bool",
            "string",
            "list",
            "map",
            "type",
            "null_type",
        ] {
            context.add_variable_from_value(name, cel::Value::Opaque(Arc::new(TypeValue(name))));
        }
        context.add_function("type", type_value);
        let shared = meter.clone();
        context.add_function(
            GUARD,
            move |function: &cel::FunctionContext| -> cel::ResolveResult {
                shared.tick()?;
                if function.args.len() != 1 {
                    return Err(shared.reject());
                }
                let result = cel::Value::resolve(&function.args[0], function.ptx)?;
                shared.value(&result)?;
                Ok(result)
            },
        );
        // contains scans an already bounded value, with an additional check per list/map member.
        let shared = meter.clone();
        context.add_function(
            "contains",
            move |function: &cel::FunctionContext| -> cel::ResolveResult {
                let (target, argument) = if let Some(target) = &function.this {
                    if function.args.len() != 1 {
                        return Err(shared.reject());
                    }
                    (
                        target.clone(),
                        cel::Value::resolve(&function.args[0], function.ptx)?,
                    )
                } else {
                    if function.args.len() != 2 {
                        return Err(shared.reject());
                    }
                    (
                        cel::Value::resolve(&function.args[0], function.ptx)?,
                        cel::Value::resolve(&function.args[1], function.ptx)?,
                    )
                };
                shared.value(&target)?;
                shared.value(&argument)?;
                let found = match (&target, &argument) {
                    (cel::Value::String(target), cel::Value::String(argument)) => {
                        target.contains(argument.as_str())
                    }
                    (cel::Value::List(target), _) => {
                        let mut found = false;
                        for value in target.iter() {
                            shared.tick()?;
                            if value == &argument {
                                found = true;
                                break;
                            }
                        }
                        found
                    }
                    (cel::Value::Map(target), _) => {
                        let key = match argument {
                            cel::Value::String(value) => Key::String(value),
                            cel::Value::Int(value) => Key::Int(value),
                            cel::Value::UInt(value) => Key::Uint(value),
                            cel::Value::Bool(value) => Key::Bool(value),
                            _ => return Err(execution_failed()),
                        };
                        target.map.contains_key(&key)
                    }
                    _ => false,
                };
                Ok(cel::Value::Bool(found))
            },
        );
        for ((name, _), expression) in self.variables.iter().zip(parsed) {
            let value = cel::Value::resolve(&expression, &context).map_err(|_| failed())?;
            meter.check()?;
            meter.value(&value).map_err(|_| failed())?;
            context.add_variable_from_value(name.clone(), value);
        }
        let value = cel::Value::resolve(&expression, &context).map_err(|_| failed())?;
        // CEL logical/optional operators may absorb a child error; fuel exhaustion never is absorbed.
        meter.check()?;
        meter.value(&value).map_err(|_| failed())?;
        let value = cel_to_runtime(&value, 0)?;
        meter.check()?;
        Ok(value)
    }
    #[cfg(test)]
    pub(super) fn evaluate(
        &self,
        input: &Value,
        requests: &Value,
        responses: &Value,
        meter: &Arc<Meter>,
    ) -> Result<Value, Response> {
        self.evaluate_runtime(
            &RuntimeValue::from_json(input),
            &RuntimeValue::from_json(requests),
            &RuntimeValue::from_json(responses),
            meter,
        )?
        .to_json()
        .map_err(|_| failed())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn source(expression: &str, variables: Value) -> Result<CelSource, Response> {
        let value = json!({"expression":expression,"variables":variables});
        CelSource::compile(value.as_object().ok_or_else(failed)?)
    }
    #[test]
    fn workflow125_cel_numeric_domains_and_ordered_bindings_remain_distinct()
    -> Result<(), Box<dyn std::error::Error>> {
        let input = json!({"a":2,"b":3,"word":"synthetic"});
        let responses = json!({"probe":{"read":{"data":{"n":7}}}});
        let requests = json!({});
        for (expression, expected) in [
            ("type(input.a) == int", json!(true)),
            ("type(responses.probe.read.data.n) == double", json!(true)),
            ("type(responses.probe.read.data.n) == int", json!(false)),
            ("int(responses.probe.read.data.n)", json!(7)),
            ("input.a + input.b", json!(5)),
            ("optional.none().hasValue()", json!(false)),
            ("''.contains('')", json!(true)),
        ] {
            let result = source(expression, json!([]))
                .map_err(|_| "source")?
                .evaluate(&input, &requests, &responses, &Meter::new(Instant::now()))
                .map_err(|_| "evaluation")?;
            assert_eq!(result, expected);
        }
        let ordered = source("twice", json!([{"name":"sum","expression":"input.a + input.b"},{"name":"twice","expression":"sum * 2"}])).map_err(|_| "source")?;
        assert_eq!(
            ordered
                .evaluate(&input, &requests, &responses, &Meter::new(Instant::now()))
                .map_err(|_| "ordered")?,
            10
        );
        let mixed =
            source("input.a + responses.probe.read.data.n", json!([])).map_err(|_| "source")?;
        assert_eq!(
            mixed
                .evaluate(&input, &requests, &responses, &Meter::new(Instant::now()))
                .err()
                .ok_or("mixed should fail")?
                .status,
            500
        );
        let forward = source(
            "first",
            json!([{"name":"first","expression":"later"},{"name":"later","expression":"1"}]),
        )
        .map_err(|_| "source")?;
        assert_eq!(
            forward
                .evaluate(&input, &requests, &responses, &Meter::new(Instant::now()))
                .err()
                .ok_or("forward")?
                .status,
            500
        );
        Ok(())
    }
    #[test]
    fn workflow125_maintained_cel_macro_fuel_is_sticky_and_deadline_is_original()
    -> Result<(), Box<dyn std::error::Error>> {
        let input = json!({"items":vec![1;256]});
        let source = source(
            "input.items.all(x, input.items.all(y, x >= 0 && y >= 0)) || true",
            json!([]),
        )
        .map_err(|_| "source")?;
        let meter = Meter::new(Instant::now());
        assert_eq!(
            source
                .evaluate(&input, &json!({}), &json!({}), &meter)
                .err()
                .ok_or("fuel")?
                .status,
            500
        );
        assert!(meter.exhausted.load(Ordering::Relaxed));
        assert_eq!(meter.check().err().ok_or("sticky")?.status, 500);
        let past = Instant::now()
            .checked_sub(Duration::from_secs(6))
            .ok_or("clock")?;
        let simple = super::tests::source("true", json!([])).map_err(|_| "source")?;
        assert_eq!(
            simple
                .evaluate(&json!({}), &json!({}), &json!({}), &Meter::new(past))
                .err()
                .ok_or("deadline")?
                .status,
            500
        );
        for expression in [
            "b''.contains(b'')",
            "bytes('')",
            "synthetic.Message{}",
            "1 / 0",
        ] {
            let candidate = super::tests::source(expression, json!([])).map_err(|_| "source")?;
            assert_eq!(
                candidate
                    .evaluate(
                        &json!({}),
                        &json!({}),
                        &json!({}),
                        &Meter::new(Instant::now())
                    )
                    .err()
                    .ok_or("closed unsupported or arithmetic")?
                    .status,
                500
            );
        }
        let deep = "(".repeat(200) + "true" + &")".repeat(200);
        let candidate = super::tests::source(&deep, json!([])).map_err(|_| "source")?;
        assert_eq!(
            candidate
                .evaluate(
                    &json!({}),
                    &json!({}),
                    &json!({}),
                    &Meter::new(Instant::now())
                )
                .err()
                .ok_or("parser depth")?
                .status,
            500
        );
        Ok(())
    }
}
