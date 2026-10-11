//! Bounded maintained template evaluation preserves source-specific numeric scalars.
use super::*;
use std::fmt::Write;
use std::sync::Arc;

const MAX_TEMPLATE: usize = 16 * 1024;
const MAX_TEMPLATE_VALUE: usize = 64 * 1024;
fn failed() -> Response {
    Response::error(500, "workflow template evaluation failed")
}
fn template_error() -> gotmpl::TemplateError {
    gotmpl::TemplateError::Exec("workflow template budget or value rejected".into())
}
fn size(value: &gotmpl::Value, depth: usize) -> Option<usize> {
    if depth > MAX_JSON_DEPTH {
        return None;
    }
    let add = |a: usize, b: usize| {
        a.checked_add(b)
            .filter(|bytes| *bytes <= MAX_TEMPLATE_VALUE)
    };
    match value {
        gotmpl::Value::Nil
        | gotmpl::Value::Bool(_)
        | gotmpl::Value::Int(_)
        | gotmpl::Value::Uint(_) => Some(16),
        gotmpl::Value::Float(_) => Some(16),
        gotmpl::Value::String(value) | gotmpl::Value::JsonNumber(value) => add(8, value.len()),
        gotmpl::Value::List(values) => values
            .iter()
            .try_fold(8, |sum, value| add(sum, size(value, depth + 1)?)),
        gotmpl::Value::Map(values) => values.iter().try_fold(8, |sum, (key, value)| {
            add(add(sum, key.len())?, size(value, depth + 1)?)
        }),
        _ => None,
    }
}
fn convert(value: &Value, input_numbers: bool, depth: usize) -> Result<gotmpl::Value, Response> {
    if depth > MAX_JSON_DEPTH {
        return Err(failed());
    }
    let result = match value {
        Value::Null => gotmpl::Value::Nil,
        Value::Bool(value) => gotmpl::Value::Bool(*value),
        Value::String(value) => gotmpl::Value::String(Arc::from(value.as_str())),
        Value::Number(value) if input_numbers => {
            gotmpl::Value::JsonNumber(Arc::from(value.to_string()))
        }
        Value::Number(value) => gotmpl::Value::Float(
            value
                .as_f64()
                .filter(|value| value.is_finite())
                .ok_or_else(failed)?,
        ),
        Value::Array(values) => gotmpl::Value::List(Arc::from(
            values
                .iter()
                .map(|value| convert(value, input_numbers, depth + 1))
                .collect::<Result<Vec<_>, _>>()?,
        )),
        Value::Object(values) => gotmpl::Value::Map(Arc::new(
            values
                .iter()
                .map(|(key, value)| {
                    Ok((
                        Arc::from(key.as_str()),
                        convert(value, input_numbers, depth + 1)?,
                    ))
                })
                .collect::<Result<BTreeMap<_, _>, Response>>()?,
        )),
    };
    if size(&result, 0).is_none() {
        return Err(failed());
    }
    Ok(result)
}
fn convert_runtime(
    value: &RuntimeValue,
    input_numbers: bool,
    depth: usize,
) -> Result<gotmpl::Value, Response> {
    if depth > MAX_JSON_DEPTH {
        return Err(failed());
    }
    let result = if let Some(value) = value.actual_float() {
        gotmpl::Value::Float(value)
    } else if let Some(value) = value.json_scalar() {
        convert(value, input_numbers, depth)?
    } else if let Some(values) = value.as_array() {
        gotmpl::Value::List(Arc::from(
            values
                .iter()
                .map(|value| convert_runtime(value, input_numbers, depth + 1))
                .collect::<Result<Vec<_>, _>>()?,
        ))
    } else if let Some(values) = value.as_object() {
        gotmpl::Value::Map(Arc::new(
            values
                .iter()
                .map(|(key, value)| {
                    Ok((
                        Arc::from(key.as_str()),
                        convert_runtime(value, input_numbers, depth + 1)?,
                    ))
                })
                .collect::<Result<BTreeMap<_, _>, Response>>()?,
        ))
    } else {
        return Err(failed());
    };
    if size(&result, 0).is_none() {
        return Err(failed());
    }
    Ok(result)
}
struct Writer<'a> {
    text: String,
    meter: &'a cel_consumer::Meter,
}
impl Drop for Writer<'_> {
    fn drop(&mut self) {
        zeroize::Zeroize::zeroize(&mut self.text);
    }
}
impl Write for Writer<'_> {
    fn write_str(&mut self, text: &str) -> std::fmt::Result {
        if self
            .text
            .len()
            .checked_add(text.len())
            .is_none_or(|bytes| bytes > MAX_TEMPLATE_VALUE)
            || self.meter.template_bytes(text.len()).is_err()
        {
            return Err(std::fmt::Error);
        }
        self.text.push_str(text);
        Ok(())
    }
}
#[derive(Clone)]
pub(super) struct TemplateSource {
    source: String,
}
impl TemplateSource {
    pub(super) fn compile(object: &serde_json::Map<String, Value>) -> Result<Self, Response> {
        let source = object
            .get("template")
            .and_then(Value::as_str)
            .filter(|source| !source.is_empty() && source.len() <= MAX_TEMPLATE)
            .ok_or_else(|| bad_profile("workflow template is outside bounds"))?
            .to_owned();
        Ok(Self { source })
    }
    fn build(&self, meter: &Arc<cel_consumer::Meter>) -> Result<gotmpl::Template, Response> {
        meter.check()?;
        let shared = meter.clone();
        let hook: gotmpl::ExecutionHook = Arc::new(move |value| {
            if let Some(value) = value {
                let bytes = size(value, 0).ok_or_else(template_error)?;
                shared.template_bytes(bytes).map_err(|_| template_error())
            } else {
                shared.tick().map_err(|_| template_error())
            }
        });
        let shared = meter.clone();
        let template = gotmpl::Template::new("workflow")
            .missing_key(gotmpl::MissingKey::Error)
            .max_range_iters(20_000)
            .execution_hook(hook)
            .func("sha256", move |arguments| {
                shared.tick().map_err(|_| template_error())?;
                if arguments.len() != 1 {
                    return Err(template_error());
                }
                let value = arguments[0].as_str().ok_or_else(template_error)?;
                shared
                    .template_bytes(value.len())
                    .map_err(|_| template_error())?;
                Ok(gotmpl::Value::String(Arc::from(crate::service::hex(
                    &crypto::digest(value.as_bytes()),
                ))))
            })
            .parse(&self.source)
            .map_err(|_| failed())?;
        meter.check()?;
        Ok(template)
    }
    pub(super) fn preflight(&self, meter: &Arc<cel_consumer::Meter>) -> Result<(), Response> {
        self.build(meter).map(|_| ())
    }
    pub(super) fn evaluate_runtime(
        &self,
        input: &RuntimeValue,
        requests: &RuntimeValue,
        responses: &RuntimeValue,
        additional: &RuntimeValue,
        meter: &Arc<cel_consumer::Meter>,
    ) -> Result<RuntimeValue, Response> {
        let template = self.build(meter)?;
        let additional = additional.as_object().ok_or_else(failed)?;
        if additional
            .keys()
            .any(|key| matches!(key.as_str(), "input" | "requests" | "responses"))
        {
            return Err(failed());
        }
        let mut context = additional
            .iter()
            .map(|(key, value)| Ok((Arc::from(key.as_str()), convert_runtime(value, false, 0)?)))
            .collect::<Result<BTreeMap<_, _>, Response>>()?;
        context.insert(Arc::from("input"), convert_runtime(input, true, 0)?);
        context.insert(Arc::from("requests"), convert_runtime(requests, true, 0)?);
        context.insert(
            Arc::from("responses"),
            convert_runtime(responses, false, 0)?,
        );
        let context = gotmpl::Value::Map(Arc::new(context));
        let mut writer = Writer {
            text: String::new(),
            meter,
        };
        template
            .execute_fmt(&mut writer, &context)
            .map_err(|_| failed())?;
        meter.check()?;
        Ok(RuntimeValue::string(std::mem::take(&mut writer.text)))
    }
    #[cfg(test)]
    pub(super) fn evaluate(
        &self,
        input: &Value,
        requests: &Value,
        responses: &Value,
        additional: &Value,
        meter: &Arc<cel_consumer::Meter>,
    ) -> Result<Value, Response> {
        self.evaluate_runtime(
            &RuntimeValue::from_json(input),
            &RuntimeValue::from_json(requests),
            &RuntimeValue::from_json(responses),
            &RuntimeValue::from_json(additional),
            meter,
        )?
        .to_json()
        .map_err(|_| failed())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn source(template: &str) -> Result<TemplateSource, Response> {
        let value = json!({"template":template});
        TemplateSource::compile(value.as_object().ok_or_else(failed)?)
    }
    #[test]
    fn workflow125_template_observed_number_types_plain_text_and_hash_are_preserved()
    -> Result<(), Box<dyn std::error::Error>> {
        let input = json!({"a":2,"word":"h<>&\"'"});
        let responses = json!({"probe":{"read":{"data":{"n":7}}}});
        for (template, expected) in [
            (
                "{{printf \"%v/%T/%d/%f\" .input.a .input.a .input.a .input.a}}",
                "2/json.Number/%!d(json.Number=2)/%!f(json.Number=2)",
            ),
            (
                "{{printf \"%v/%T/%d/%f\" .responses.probe.read.data.n .responses.probe.read.data.n .responses.probe.read.data.n .responses.probe.read.data.n}}",
                "7/float64/%!d(float64=7)/7.000000",
            ),
            ("{{.input.word}}{{.suffix}}", "h<>&\"'-extra"),
            (
                "{{.input.word | sha256}}",
                "5948bee484ffacec33e6440a88250037c5e29bcc0d58a755d4fd3d5c4066d4a1",
            ),
        ] {
            let evaluated = source(template)
                .map_err(|_| "source")?
                .evaluate(
                    &input,
                    &json!({}),
                    &responses,
                    &json!({"suffix":"-extra"}),
                    &cel_consumer::Meter::new(std::time::Instant::now()),
                )
                .map_err(|_| "template")?;
            assert_eq!(evaluated, expected);
        }
        for template in [
            "{{eq .responses.probe.read.data.n \"7\"}}",
            "{{.input.missing}}",
            "{{env \"HOME\"}}",
            "{{.input.word",
        ] {
            assert_eq!(
                source(template)
                    .map_err(|_| "source")?
                    .evaluate(
                        &input,
                        &json!({}),
                        &responses,
                        &json!({}),
                        &cel_consumer::Meter::new(std::time::Instant::now())
                    )
                    .err()
                    .ok_or("template must fail")?
                    .status,
                500
            );
        }
        Ok(())
    }
    #[test]
    fn workflow125_template_empty_ranges_output_and_original_deadline_are_bounded()
    -> Result<(), Box<dyn std::error::Error>> {
        let input = json!({"rows":vec![0;256]});
        let nested = source("{{range .input.rows}}{{range $.input.rows}}{{end}}{{end}}OK")
            .map_err(|_| "source")?;
        let meter = cel_consumer::Meter::new(std::time::Instant::now());
        assert_eq!(
            nested
                .evaluate(&input, &json!({}), &json!({}), &json!({}), &meter)
                .err()
                .ok_or("empty loop fuel")?
                .status,
            500
        );
        assert_eq!(meter.check().err().ok_or("sticky")?.status, 500);
        let oversized =
            source("{{printf \"%65535s%65535s\" \"a\" \"b\"}}").map_err(|_| "source")?;
        assert_eq!(
            oversized
                .evaluate(
                    &json!({}),
                    &json!({}),
                    &json!({}),
                    &json!({}),
                    &cel_consumer::Meter::new(std::time::Instant::now())
                )
                .err()
                .ok_or("output")?
                .status,
            500
        );
        let past = std::time::Instant::now()
            .checked_sub(std::time::Duration::from_secs(6))
            .ok_or("clock")?;
        let literal = source("OK").map_err(|_| "source")?;
        assert_eq!(
            literal
                .evaluate(
                    &json!({}),
                    &json!({}),
                    &json!({}),
                    &json!({}),
                    &cel_consumer::Meter::new(past)
                )
                .err()
                .ok_or("deadline")?
                .status,
            500
        );
        Ok(())
    }
}
