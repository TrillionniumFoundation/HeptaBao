//! Actual framed process boundary; every value is a synthetic test fixture.
use serde_json::{Value, json};
use std::io::Write;
use std::process::{Command, Stdio};

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn invoke(frames: &[Value]) -> Result<std::process::Output, Box<dyn std::error::Error>> {
    let mut process = Command::new(env!("CARGO_BIN_EXE_heptabao-agent-renderer"))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    {
        let mut input = process.stdin.take().ok_or("missing original input pipe")?;
        for frame in frames {
            serde_json::to_writer(&mut input, frame)?;
            input.write_all(b"\n")?;
        }
    }
    Ok(process.wait_with_output()?)
}

#[test]
fn literal_template_completes_without_requesting_secrets() -> TestResult {
    let output = invoke(&[json!({"template":"synthetic literal", "timeout_ms":1000})])?;
    assert!(output.status.success());
    let result: Value = serde_json::from_slice(&output.stdout)?;
    assert_eq!(result["op"], "result");
    assert_eq!(result["output"], "synthetic literal");
    assert_eq!(result["secret_calls"], 0);
    assert!(output.stderr.is_empty());
    Ok(())
}

#[test]
fn secret_template_uses_only_its_private_rpc_response() -> TestResult {
    let output = invoke(&[
        json!({"template":"{{with secret \"kv/synthetic\"}}{{.data.value}}{{end}}", "timeout_ms":1000}),
        json!({"ok":true, "secret":{"data":{"value":"synthetic-secret"}}}),
    ])?;
    assert!(output.status.success());
    let frames: Vec<Value> = output
        .stdout
        .split(|byte| *byte == b'\n')
        .filter(|line| !line.is_empty())
        .map(serde_json::from_slice)
        .collect::<Result<_, _>>()?;
    assert_eq!(frames.len(), 2);
    assert_eq!(frames[0], json!({"op":"secret", "path":"kv/synthetic"}));
    assert_eq!(frames[1]["output"], "synthetic-secret");
    assert_eq!(frames[1]["secret_calls"], 1);
    assert!(output.stderr.is_empty());
    Ok(())
}

#[test]
fn refused_secret_cannot_leak_rpc_payload_in_errors() -> TestResult {
    let output = invoke(&[
        json!({"template":"{{secret \"kv/synthetic\"}}", "timeout_ms":1000}),
        json!({"ok":false, "secret":"synthetic-denied-response-sentinel"}),
    ])?;
    assert!(!output.status.success());
    assert!(
        !String::from_utf8_lossy(&output.stdout).contains("synthetic-denied-response-sentinel")
    );
    assert!(output.stderr.is_empty());
    let terminal: Value = serde_json::from_slice(
        output
            .stdout
            .split(|byte| *byte == b'\n')
            .rfind(|line| !line.is_empty())
            .ok_or("missing terminal frame")?,
    )?;
    assert_eq!(
        terminal,
        json!({"op":"result", "ok":false, "error":"template_render_blocked"})
    );
    Ok(())
}
