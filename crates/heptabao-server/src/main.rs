use std::{
    fs::OpenOptions,
    io::Read,
    path::Path,
    sync::{Arc, Mutex},
};
use zeroize::Zeroizing;

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
    #[cfg(feature = "fixture-native-v6-service")]
    let (arguments, native_candidate) = {
        let mut arguments = arguments;
        let count = arguments
            .iter()
            .filter(|argument| argument.as_str() == "--fixture-native-v6-service")
            .count();
        if count > 1 {
            return Err("duplicate native Service candidate option".into());
        }
        arguments.retain(|argument| argument.as_str() != "--fixture-native-v6-service");
        (arguments, count == 1)
    };
    #[cfg(all(feature = "fixture-native-restore-faults", target_os = "linux"))]
    let (arguments, fixture) = {
        let mut arguments = arguments;
        let fixture = heptabao_server::fixture_native_restore::take_arguments(&mut arguments)?;
        (arguments, fixture)
    };
    if !matches!(arguments.as_slice(), [flag, _] if flag == "--config")
        && !matches!(arguments.as_slice(), [flag, _, ha_flag, _] if flag == "--config" && ha_flag == "--ha-config")
    {
        return Err(
            "usage: heptabao-server --config /absolute/server.json-or-hcl [--ha-config /absolute/ha.json-or-hcl] (TLS is required)"
                .into(),
        );
    }
    let server_path = Path::new(&arguments[1]);
    let server_bytes = read_bounded_config(server_path)?;
    let config = heptabao_server::configuration::parse_server(&server_bytes)?;

    #[cfg(feature = "fixture-native-v6-service")]
    if native_candidate {
        if arguments.len() != 2 {
            return Err("native Service candidate requires standalone root namespace".into());
        }
        return heptabao_server::http::serve_native_v6_candidate(config);
    }
    if arguments.len() == 2 {
        return heptabao_server::http::serve(config);
    }

    let ha_path = Path::new(&arguments[3]);
    let ha_bytes = read_bounded_config(ha_path)?;
    let ha_config = heptabao_server::configuration::parse_ha(&ha_bytes)?;
    let ha = Arc::new(Mutex::new(heptabao_server::ha::HaProcess::start(
        ha_config,
    )?));
    #[cfg(all(feature = "fixture-native-restore-faults", target_os = "linux"))]
    if let Some(fixture) = fixture {
        return heptabao_server::http::serve_with_ha_fixture(config, ha, fixture);
    }
    heptabao_server::http::serve_with_ha(config, ha)
}

fn read_bounded_config(path: &Path) -> Result<Zeroizing<Vec<u8>>, String> {
    if !path.is_absolute() {
        return Err("config path must be absolute".into());
    }
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(target_os = "linux")]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK);
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
    let mut bytes = Zeroizing::new(Vec::new());
    file.take(65_537)
        .read_to_end(&mut bytes)
        .map_err(|_| "cannot read configuration")?;
    if bytes.len() > 65_536 {
        return Err("configuration exceeds limit".into());
    }
    Ok(bytes)
}
