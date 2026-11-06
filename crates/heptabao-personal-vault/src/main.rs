#![forbid(unsafe_code)]
use base64::{Engine, engine::general_purpose::STANDARD_NO_PAD};
use heptabao_personal_vault::{
    MAX_FILE_BYTES, Result, VaultError, VaultItem, VaultSession, generate_password,
    read_private_file, totp, write_private_file,
};
use serde::Deserialize;
use std::io::{IsTerminal, Read};
use std::path::Path;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use zeroize::{Zeroize, Zeroizing};

#[derive(Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct Request {
    #[serde(default)]
    password: String,
    #[serde(default)]
    new_password: String,
    #[serde(default)]
    recovery_key: String,
    #[serde(default)]
    id: String,
    item: Option<VaultItem>,
    expected_revision: Option<u64>,
    output: Option<String>,
    input: Option<String>,
    length: Option<usize>,
    unix_seconds: Option<u64>,
    #[serde(default)]
    confirm_plaintext_export: bool,
    #[serde(default)]
    confirm_replace: bool,
}
impl Drop for Request {
    fn drop(&mut self) {
        self.password.zeroize();
        self.new_password.zeroize();
        self.recovery_key.zeroize();
    }
}
fn main() {
    match run() {
        Ok(value) => println!("{value}"),
        Err(e) => {
            // No source error, input, secret, or pathname enters stderr.
            eprintln!("{{\"ok\":false,\"error\":\"{}\"}}", e.code());
            std::process::exit(1);
        }
    }
}
fn run() -> Result<serde_json::Value> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 3 {
        return Err(VaultError::InvalidInput);
    }
    let root = Path::new(&args[1]);
    if !root.is_absolute() {
        return Err(VaultError::UnsafePath);
    }
    if std::io::stdin().is_terminal() {
        return Err(VaultError::InvalidInput);
    }
    let mut input = Zeroizing::new(Vec::new());
    std::io::stdin()
        .take((MAX_FILE_BYTES + 1) as u64)
        .read_to_end(&mut input)
        .map_err(|_| VaultError::Io)?;
    if input.len() > MAX_FILE_BYTES {
        return Err(VaultError::TooLarge);
    }
    let mut request: Request =
        serde_json::from_slice(&input).map_err(|_| VaultError::InvalidInput)?;
    input.zeroize();
    let ttl = Duration::from_secs(300);
    let command = args[2].as_str();
    if command == "generate" {
        let output = output(&request)?;
        let password = generate_password(request.length.unwrap_or(24))?;
        write_private_file(output, password.as_bytes())?;
        return Ok(serde_json::json!({"ok":true,"operation":"generate","secret_written":true}));
    }
    if command == "init" {
        let output = output(&request)?.to_path_buf();
        let mut session = VaultSession::create_with_recovery_file(
            root,
            request.password.as_bytes(),
            ttl,
            &output,
        )?;
        let metadata = session.metadata()?;
        session.lock();
        drop(session);
        return Ok(
            serde_json::json!({"ok":true,"operation":"init","metadata":metadata,"recovery_written":true}),
        );
    }
    if command == "restore" {
        let bytes = read_private_file(Path::new(
            request.input.as_deref().ok_or(VaultError::InvalidInput)?,
        ))?;
        let mut session = if request.recovery_key.is_empty() {
            VaultSession::restore(root, &bytes, request.password.as_bytes(), ttl)?
        } else {
            let key = recovery_key(&request.recovery_key)?;
            VaultSession::restore_with_recovery(root, &bytes, &key, ttl)?
        };
        let metadata = session.metadata()?;
        session.lock();
        return Ok(serde_json::json!({"ok":true,"operation":"restore","metadata":metadata}));
    }
    // Load import before taking the vault directory writer lock; this also permits
    // an explicitly selected private export stored in the same directory.
    let imported = if command == "import" {
        Some(read_private_file(Path::new(
            request.input.as_deref().ok_or(VaultError::InvalidInput)?,
        ))?)
    } else {
        None
    };
    let mut session = if request.recovery_key.is_empty() {
        VaultSession::open(root, request.password.as_bytes(), ttl)?
    } else {
        let key = recovery_key(&request.recovery_key)?;
        VaultSession::open_with_recovery(root, &key, ttl)?
    };
    request.password.zeroize();
    request.recovery_key.zeroize();
    let expected = || request.expected_revision.ok_or(VaultError::InvalidInput);
    let mut exported: Option<Zeroizing<Vec<u8>>> = None;
    let extra = match command {
        "list" => serde_json::json!({"items":session.summaries()?}),
        "put" => {
            let revision = expected()?;
            session.put(
                request.item.take().ok_or(VaultError::InvalidInput)?,
                revision,
            )?;
            serde_json::Value::Null
        }
        "delete" => {
            session.delete(&request.id, expected()?)?;
            serde_json::Value::Null
        }
        "get" => {
            let _ = output(&request)?;
            exported = Some(Zeroizing::new(
                serde_json::to_vec(session.get(&request.id)?)
                    .map_err(|_| VaultError::InvalidFormat)?,
            ));
            serde_json::Value::Null
        }
        "totp" => {
            let _ = output(&request)?;
            let config = session
                .get(&request.id)?
                .totp
                .as_ref()
                .ok_or(VaultError::Missing)?;
            let time = match request.unix_seconds {
                Some(t) => t,
                None => SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .map_err(|_| VaultError::InvalidInput)?
                    .as_secs(),
            };
            let code = totp(config, time)?;
            exported = Some(Zeroizing::new(code.as_bytes().to_vec()));
            serde_json::Value::Null
        }
        "backup" => {
            let _ = output(&request)?;
            exported = Some(Zeroizing::new(session.encrypted_backup()?));
            serde_json::Value::Null
        }
        "export" => {
            if !request.confirm_plaintext_export {
                return Err(VaultError::InvalidInput);
            }
            let _ = output(&request)?;
            exported = Some(session.export_plaintext()?);
            serde_json::Value::Null
        }
        "import" => {
            if !request.confirm_replace {
                return Err(VaultError::InvalidInput);
            }
            session.import_plaintext(
                imported.as_ref().ok_or(VaultError::InvalidInput)?,
                expected()?,
            )?;
            serde_json::Value::Null
        }
        "health" => {
            serde_json::to_value(session.health()?).map_err(|_| VaultError::InvalidFormat)?
        }
        "change-password" => {
            session.change_password(request.new_password.as_bytes(), expected()?)?;
            serde_json::Value::Null
        }
        _ => return Err(VaultError::InvalidInput),
    };
    let metadata = session.metadata()?;
    session.lock();
    drop(session);
    let written = exported.is_some();
    if let Some(bytes) = exported {
        write_private_file(output(&request)?, &bytes)?;
    }
    Ok(
        serde_json::json!({"ok":true,"operation":command,"metadata":metadata,"result":extra,"output_written":written,"locked":true}),
    )
}
fn output(request: &Request) -> Result<&Path> {
    request
        .output
        .as_deref()
        .map(Path::new)
        .ok_or(VaultError::InvalidInput)
}
fn recovery_key(value: &str) -> Result<Zeroizing<[u8; 32]>> {
    if value.len() != 43 {
        return Err(VaultError::InvalidInput);
    }
    let bytes = Zeroizing::new(
        STANDARD_NO_PAD
            .decode(value)
            .map_err(|_| VaultError::InvalidInput)?,
    );
    if bytes.len() != 32 || STANDARD_NO_PAD.encode(&bytes) != value {
        return Err(VaultError::InvalidInput);
    }
    let mut key = Zeroizing::new([0; 32]);
    key.copy_from_slice(&bytes);
    Ok(key)
}
