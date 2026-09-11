use std::{fs::OpenOptions, io::Read, path::Path};

use serde::de::DeserializeOwned;

fn main() -> std::process::ExitCode {
    match run() {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("heptabao-server: {error}");
            std::process::ExitCode::FAILURE
        }
    }
}

fn run() -> Result<(), String> {
    let arguments: Vec<_> = std::env::args().skip(1).collect();
    let (server_path, ha_path) = match arguments.as_slice() {
        [config, path] if config == "--config" => (path.as_str(), None),
        [config, path, ha_config, ha_path] if config == "--config" && ha_config == "--ha-config" => {
            (path.as_str(), Some(ha_path.as_str()))
        }
        _ => {
            return Err(
                "usage: heptabao-server --config /absolute/server.json [--ha-config /absolute/raft.json] (TLS is required)"
                    .into(),
            );
        }
    };
    let config = read_config(server_path)?;
    let _ha = match ha_path {
        Some(path) => Some(heptabao_server::ha::HaProcess::start(read_config(path)?)?),
        None => None,
    };
    heptabao_server::http::serve(config)
}

fn read_config<T: DeserializeOwned>(argument: &str) -> Result<T, String> {
    let path = Path::new(argument);
    if !path.is_absolute() {
        return Err("config path must be absolute".into());
    }
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(target_os = "linux")]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(0o400000 | 0o2000000 | 0o4000);
    }
    let file = options
        .open(path)
        .map_err(|_| "cannot open configuration")?;
    let metadata = file
        .metadata()
        .map_err(|_| "cannot inspect configuration")?;
    if !metadata.is_file() || metadata.len() > 65536 {
        return Err("configuration must be a bounded regular file".into());
    }
    let mut bytes = Vec::new();
    file.take(65537)
        .read_to_end(&mut bytes)
        .map_err(|_| "cannot read configuration")?;
    if bytes.len() > 65536 {
        return Err("configuration exceeds limit".into());
    }
    serde_json::from_slice(&bytes).map_err(|_| "invalid configuration schema".into())
}
