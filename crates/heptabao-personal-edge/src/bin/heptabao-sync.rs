use heptabao_personal_edge::sync::{CiphertextStore, decode_ciphertext, encode_ciphertext};
use serde::Deserialize;
use serde_json::json;
use std::{
    io::{Read, Write},
    path::Path,
};

#[derive(Deserialize)]
#[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
enum Request {
    Head,
    Publish {
        operation_id: String,
        expected_head: Option<String>,
        ciphertext: String,
    },
    Receipt {
        operation_id: String,
    },
    Fetch {
        ciphertext_sha256: String,
    },
}

fn run() -> Result<serde_json::Value, String> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 3 {
        return Err("usage: heptabao-sync ABSOLUTE_PRIVATE_ROOT VAULT_ID".into());
    }
    let mut raw = Vec::new();
    std::io::stdin()
        .take(6 * 1024 * 1024 + 1)
        .read_to_end(&mut raw)
        .map_err(|_| "input_unavailable")?;
    if raw.len() > 6 * 1024 * 1024 {
        return Err("input_limit".into());
    }
    let request: Request = serde_json::from_slice(&raw).map_err(|_| "invalid_request")?;
    let mut store =
        CiphertextStore::open(Path::new(&args[1]), &args[2]).map_err(|e| format!("{e:?}"))?;
    match request {
        Request::Head => Ok(json!({"head": store.head().map_err(|e| format!("{e:?}"))?})),
        Request::Publish {
            operation_id,
            expected_head,
            ciphertext,
        } => {
            let bytes = decode_ciphertext(&ciphertext).map_err(|e| format!("{e:?}"))?;
            let receipt = store
                .publish(&operation_id, expected_head.as_deref(), &bytes)
                .map_err(|e| format!("{e:?}"))?;
            Ok(json!({"receipt": receipt}))
        }
        Request::Receipt { operation_id } => {
            Ok(json!({"receipt": store.receipt(&operation_id).map_err(|e| format!("{e:?}"))?}))
        }
        Request::Fetch { ciphertext_sha256 } => {
            let bytes = store
                .fetch(&ciphertext_sha256)
                .map_err(|e| format!("{e:?}"))?;
            Ok(
                json!({"ciphertext": encode_ciphertext(&bytes), "ciphertext_sha256": ciphertext_sha256}),
            )
        }
    }
}

fn main() {
    let (result, failed) = match run() {
        Ok(value) => (value, false),
        Err(error) => (json!({"error": error}), true),
    };
    let stdout = std::io::stdout();
    let mut writer = stdout.lock();
    if serde_json::to_writer(&mut writer, &result).is_err() || writer.write_all(b"\n").is_err() {
        std::process::exit(2);
    }
    if failed {
        std::process::exit(1);
    }
}
