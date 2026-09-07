use std::{fs::OpenOptions, io::Read, path::Path};

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
    if arguments.len() != 2 || arguments[0] != "--config" {
        return Err(
            "usage: heptabao-server --config /absolute/server.json (TLS is required)".into(),
        );
    }
    let path = Path::new(&arguments[1]);
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
    let config = serde_json::from_slice(&bytes).map_err(|_| "invalid configuration schema")?;
    heptabao_server::http::serve(config)
}
