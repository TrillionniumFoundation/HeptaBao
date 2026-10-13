//! Private framed RPC between the actual Agent owner and the full Go evaluator.
//! Credentials never enter argv, environment, or diagnostics.
use gotmpl::{MissingKey, Template, TemplateError, Value};
use serde_json::{Value as Json, json};
use std::{
    collections::BTreeMap,
    fmt,
    io::{self, BufRead, BufReader, Write},
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};

const MAX_FRAME: usize = 1_048_576;
const MAX_SOURCE: usize = 65_536;
const MAX_OUTPUT: usize = 65_536;

fn main() -> std::process::ExitCode {
    let passed = run().is_ok();
    if !passed {
        let _ignored = frame(&json!({"op":"result","ok":false,"error":"template_render_blocked"}));
    }
    if passed {
        std::process::ExitCode::SUCCESS
    } else {
        std::process::ExitCode::FAILURE
    }
}

fn read_frame(reader: &mut impl BufRead) -> Result<Json, ()> {
    let mut bytes = Vec::new();
    loop {
        let available = reader.fill_buf().map_err(|_| ())?;
        if available.is_empty() {
            return Err(());
        }
        let position = available.iter().position(|byte| *byte == b'\n');
        let count = position.map_or(available.len(), |value| value + 1);
        if bytes.len().saturating_add(count) > MAX_FRAME {
            return Err(());
        }
        bytes.extend_from_slice(&available[..count]);
        reader.consume(count);
        if position.is_some() {
            break;
        }
    }
    serde_json::from_slice(&bytes).map_err(|_| ())
}

fn frame(value: &Json) -> Result<(), ()> {
    let data = serde_json::to_vec(value).map_err(|_| ())?;
    if data.len() > MAX_FRAME {
        return Err(());
    }
    let mut output = io::stdout().lock();
    output.write_all(&data).map_err(|_| ())?;
    output.write_all(b"\n").map_err(|_| ())?;
    output.flush().map_err(|_| ())
}

fn value(json: &Json, depth: usize) -> Result<Value, ()> {
    if depth > 64 {
        return Err(());
    }
    Ok(match json {
        Json::Null => Value::Nil,
        Json::Bool(value) => Value::Bool(*value),
        Json::Number(number) => {
            if let Some(integer) = number.as_i64() {
                Value::Int(integer)
            } else if let Some(integer) = number.as_u64() {
                Value::Uint(integer)
            } else {
                Value::JsonNumber(Arc::from(number.to_string()))
            }
        }
        Json::String(text) => Value::String(Arc::from(text.as_str())),
        Json::Array(items) => Value::List(
            items
                .iter()
                .map(|item| value(item, depth + 1))
                .collect::<Result<Vec<_>, _>>()?
                .into(),
        ),
        Json::Object(items) => Value::Map(Arc::new(
            items
                .iter()
                .map(|(key, item)| Ok((Arc::from(key.as_str()), value(item, depth + 1)?)))
                .collect::<Result<BTreeMap<Arc<str>, Value>, ()>>()?,
        )),
    })
}

#[derive(Debug, Default)]
struct BoundedOutput(String);
impl fmt::Write for BoundedOutput {
    fn write_str(&mut self, text: &str) -> fmt::Result {
        if self.0.len().saturating_add(text.len()) > MAX_OUTPUT {
            return Err(fmt::Error);
        }
        self.0.push_str(text);
        Ok(())
    }
}

fn run() -> Result<(), ()> {
    if std::env::args().len() != 1 {
        return Err(());
    }
    let input = Arc::new(Mutex::new(BufReader::new(io::stdin())));
    let initial = read_frame(&mut *input.lock().map_err(|_| ())?)?;
    let source = initial.get("template").and_then(Json::as_str).ok_or(())?;
    if source.len() > MAX_SOURCE {
        return Err(());
    }
    let timeout = initial.get("timeout_ms").and_then(Json::as_u64).ok_or(())?;
    if !(1..=60_000).contains(&timeout) {
        return Err(());
    }
    let deadline = Instant::now()
        .checked_add(Duration::from_millis(timeout))
        .ok_or(())?;
    let steps = Arc::new(AtomicU64::new(0));
    let calls = Arc::new(AtomicU64::new(0));
    let hook_steps = Arc::clone(&steps);
    let secret_calls = Arc::clone(&calls);
    let secret_input = Arc::clone(&input);
    let template = Template::new("owned-agent-template")
        .missing_key(MissingKey::Error)
        .max_range_iters(100_000)
        .execution_hook(Arc::new(move |_| {
            if Instant::now() >= deadline || hook_steps.fetch_add(1, Ordering::Relaxed) >= 200_000 {
                return Err(TemplateError::Exec(
                    "owned template budget exhausted".into(),
                ));
            }
            Ok(())
        }))
        .func("secret", move |args| {
            if Instant::now() >= deadline || secret_calls.fetch_add(1, Ordering::Relaxed) >= 128 {
                return Err(TemplateError::Exec(
                    "owned secret request budget exhausted".into(),
                ));
            }
            let path = args
                .first()
                .and_then(Value::as_str)
                .ok_or_else(|| TemplateError::Exec("secret path required".into()))?;
            if args.len() != 1 || path.len() > 8192 {
                return Err(TemplateError::Exec("secret arguments blocked".into()));
            }
            frame(&json!({"op":"secret","path":path}))
                .map_err(|_| TemplateError::Exec("secret RPC blocked".into()))?;
            let response = read_frame(
                &mut *secret_input
                    .lock()
                    .map_err(|_| TemplateError::Exec("secret RPC blocked".into()))?,
            )
            .map_err(|_| TemplateError::Exec("secret RPC blocked".into()))?;
            if response.get("ok").and_then(Json::as_bool) != Some(true) {
                return Err(TemplateError::Exec("secret request blocked".into()));
            }
            value(
                response
                    .get("secret")
                    .ok_or_else(|| TemplateError::Exec("secret response blocked".into()))?,
                0,
            )
            .map_err(|_| TemplateError::Exec("secret response blocked".into()))
        })
        .parse(source)
        .map_err(|_| ())?;
    let mut output = BoundedOutput::default();
    template
        .execute_fmt(&mut output, &Value::Nil)
        .map_err(|_| ())?;
    frame(&json!({"op":"result","ok":true,"output":output.0,
                  "secret_calls":calls.load(Ordering::Relaxed),"steps":steps.load(Ordering::Relaxed)}))
}
