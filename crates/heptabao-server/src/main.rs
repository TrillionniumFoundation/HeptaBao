use std::{
    fs::OpenOptions,
    io::Read,
    path::Path,
    sync::{Arc, Mutex},
};

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
    if !matches!(arguments.as_slice(), [flag, _] if flag == "--config")
        && !matches!(arguments.as_slice(), [flag, _, ha_flag, _] if flag == "--config" && ha_flag == "--ha-config")
    {
        return Err(
            "usage: heptabao-server --config /absolute/server.json [--ha-config /absolute/ha.json] (TLS is required)"
                .into(),
        );
    }
    let server_path = Path::new(&arguments[1]);
    let server_bytes = read_bounded_config(server_path)?;
    let config = serde_json::from_slice(&server_bytes)
        .map_err(|_| "invalid server configuration schema".to_owned())?;

    if arguments.len() == 2 {
        return heptabao_server::http::serve(config);
    }

    let ha_path = Path::new(&arguments[3]);
    let ha_bytes = read_bounded_config(ha_path)?;
    let ha_config = serde_json::from_slice(&ha_bytes)
        .map_err(|_| "invalid HA configuration schema".to_owned())?;
    let ha = Arc::new(Mutex::new(heptabao_server::ha::HaProcess::start(ha_config)?));
    heptabao_server::http::serve_with_ha(config, ha)
}

fn read_bounded_config(path: &Path) -> Result<Vec<u8>, String> {
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
    if !metadata.is_file() || metadata.len() > 65_536 {
        return Err("configuration must be a bounded regular file".into());
    }
    let mut bytes = Vec::new();
    file.take(65_537)
        .read_to_end(&mut bytes)
        .map_err(|_| "cannot read configuration")?;
    if bytes.len() > 65_536 {
        return Err("configuration exceeds limit".into());
    }
    Ok(bytes)
}
