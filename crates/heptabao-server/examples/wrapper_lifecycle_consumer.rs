//! Genuine provider lifecycle consumer. Private configuration is read from a
//! file; only lifecycle/crypto verdicts are written to the collector.

#[cfg(target_os = "linux")]
fn main() -> std::process::ExitCode {
    match run() {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("wrapper lifecycle consumer: {error}");
            std::process::ExitCode::FAILURE
        }
    }
}

#[cfg(not(target_os = "linux"))]
fn main() -> std::process::ExitCode {
    std::process::ExitCode::FAILURE
}

#[cfg(target_os = "linux")]
fn run() -> Result<(), Box<dyn std::error::Error>> {
    use heptabao_openbao_grpc::protocol::wrapping::RpcOptions;
    use heptabao_server::{Service, WrapperCleanupState, WrapperOperation, WrapperReply};
    use std::io::{BufRead, Write};
    use std::path::PathBuf;
    use std::time::{Duration, Instant};
    use zeroize::Zeroizing;

    let arguments: Vec<_> = std::env::args_os().skip(1).collect();
    if arguments.len() != 2 {
        return Err("expected private Wrapper configuration and fresh fixture root".into());
    }
    let root = PathBuf::from(&arguments[1]);
    let config = serde_json::from_slice(&std::fs::read(&arguments[0])?)?;
    let mut service = Service::new(root.join("data"), &root.join("audit.jsonl"))?;
    let plan = service
        .install_openbao_wrapper(Some(config))?
        .ok_or("Wrapper startup plan absent")?;
    // A request thread performs admission and then actually terminates. The
    // persistent ownership thread, rather than this caller, spawns the provider.
    std::thread::spawn(move || plan.execute())
        .join()
        .map_err(|_| "Wrapper admission caller panicked")??;
    if service.openbao_wrapper_cleanup_state() != Some(WrapperCleanupState::Live) {
        return Err("provider is not live after caller-thread exit".into());
    }
    println!(
        "{}",
        serde_json::json!({"ready":true,"caller_thread_joined":true})
    );
    std::io::stdout().flush()?;
    for line in std::io::stdin().lock().lines() {
        match line?.as_str() {
            "crypto" => {
                let plaintext = Zeroizing::new(vec![0x6d; 32]);
                let options = RpcOptions {
                    with_key_id: String::new(),
                    with_aad: Vec::new(),
                    with_config_map: std::collections::BTreeMap::new(),
                    with_disallow_env_vars: true,
                };
                let encrypt =
                    service.prepare_openbao_wrapper_operation(WrapperOperation::Encrypt {
                        plaintext: plaintext.clone(),
                        options: options.clone(),
                    })?;
                let encrypted = service.finish_openbao_wrapper_operation(encrypt.execute())?;
                let WrapperReply::Encrypted(blob) = encrypted else {
                    return Err("unexpected Encrypt completion".into());
                };
                let decrypt =
                    service.prepare_openbao_wrapper_operation(WrapperOperation::Decrypt {
                        blob,
                        options,
                    })?;
                let decrypted = service.finish_openbao_wrapper_operation(decrypt.execute())?;
                let WrapperReply::Decrypted(actual) = decrypted else {
                    return Err("unexpected Decrypt completion".into());
                };
                if actual.as_slice() != plaintext.as_slice()
                    || service.openbao_wrapper_cleanup_state() != Some(WrapperCleanupState::Live)
                {
                    return Err("genuine crypto or retained owner failed".into());
                }
                println!(
                    "{}",
                    serde_json::json!({"genuine_encrypt_decrypt":true,"owner_live":true})
                );
            }
            "retire" => {
                // The first retirement revokes the runtime. It cannot remove
                // the owner before the ownership worker has actually waited.
                let _retirement = service.install_openbao_wrapper(None);
                let deadline = Instant::now() + Duration::from_secs(3);
                while service.openbao_wrapper_cleanup_state()
                    != Some(WrapperCleanupState::TerminalReaped)
                {
                    if Instant::now() >= deadline {
                        return Err("retirement lacks an actual terminal wait".into());
                    }
                    std::thread::sleep(Duration::from_millis(2));
                }
                service.install_openbao_wrapper(None)?;
                println!("{}", serde_json::json!({"actual_terminal_reaped":true}));
                std::io::stdout().flush()?;
                return Ok(());
            }
            "exit" => return Ok(()),
            _ => return Err("unknown fixture command".into()),
        }
        std::io::stdout().flush()?;
    }
    Err("fixture input closed before explicit completion".into())
}
