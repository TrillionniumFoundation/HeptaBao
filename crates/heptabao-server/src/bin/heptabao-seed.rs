//! Explicit offline Shamir seed transport and authenticated cold bootstrap.
//! No server is started and a cold bootstrap never claims current HA recovery.
use std::process::ExitCode;

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("heptabao-seed: {error}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(unix)]
fn run() -> Result<(), String> {
    use heptabao_server::native_seed;
    use std::io::Write;
    use std::path::Path;
    let arguments: Vec<_> = std::env::args().skip(1).collect();
    let encoded = match arguments.as_slice() {
        #[cfg(feature = "native-v6-ha")]
        [operation, config, ha, shares, token, bundle, mount, digest]
            if operation == "import-kv2-ha" =>
        {
            encode_receipt(native_seed::import_kv2_ha(native_seed::HaKv2Import {
                server_config_path: Path::new(config), ha_config_path: Path::new(ha),
                shares_path: Path::new(shares), token_path: Path::new(token),
                bundle_path: Path::new(bundle), mount, bundle_sha256: digest,
                budget_seconds: None,
            }))
        }
        #[cfg(feature = "native-v6-ha")]
        [operation, config, ha, shares, token, bundle, mount, digest, seconds]
            if operation == "import-kv2-ha" =>
        {
            let seconds = seconds.parse::<u64>().map_err(|_| "invalid HA maintenance import budget")?;
            encode_receipt(native_seed::import_kv2_ha(native_seed::HaKv2Import {
                server_config_path: Path::new(config), ha_config_path: Path::new(ha),
                shares_path: Path::new(shares), token_path: Path::new(token),
                bundle_path: Path::new(bundle), mount, bundle_sha256: digest,
                budget_seconds: Some(seconds),
            }))
        }
        #[cfg(feature = "native-v6-storage")]
        [operation, data, audit, shares, token, bundle, mount, digest]
            if operation == "import-kv2" =>
        {
            encode_receipt(native_seed::import_kv2(native_seed::OfflineKv2Import {
                data_dir: Path::new(data), audit_path: Path::new(audit),
                shares_path: Path::new(shares), token_path: Path::new(token),
                bundle_path: Path::new(bundle), mount, bundle_sha256: digest,
                budget_seconds: None,
            }))
        }
        #[cfg(feature = "native-v6-storage")]
        [operation, data, audit, shares, token, bundle, mount, digest, seconds]
            if operation == "import-kv2" =>
        {
            let seconds = seconds.parse::<u64>().map_err(|_| "invalid offline import budget")?;
            encode_receipt(native_seed::import_kv2(native_seed::OfflineKv2Import {
                data_dir: Path::new(data), audit_path: Path::new(audit),
                shares_path: Path::new(shares), token_path: Path::new(token),
                bundle_path: Path::new(bundle), mount, bundle_sha256: digest,
                budget_seconds: Some(seconds),
            }))
        }
        [operation, source, destination] if operation == "export" => {
            encode_receipt(native_seed::export(Path::new(source), Path::new(destination)))
        }
        [operation, source, destination, receipt, digest] if operation == "stage" => {
            encode_receipt(native_seed::stage(Path::new(source), Path::new(destination), Path::new(receipt), digest))
        }
        #[cfg(feature = "native-v6-ha")]
        [operation, archive, seal, shares_file, destination, archive_digest, seal_digest]
            if operation == "recover-ha" =>
        {
            encode_receipt(native_seed::recover_ha_seed(
                Path::new(archive), Path::new(seal), Path::new(shares_file),
                Path::new(destination), archive_digest, seal_digest,
            ))
        }
        _ => return Err("usage: heptabao-seed import-kv2-ha /absolute/server.json /absolute/ha.json /absolute/private-shares.json /absolute/private-token /absolute/bundle.json mount bundle-sha256 [seconds: default 300, maximum 360; isolated enrolled cohort] | import-kv2 /absolute/stopped-native-data /absolute/audit /absolute/private-shares.json /absolute/private-token /absolute/bundle.json mount bundle-sha256 [seconds: default 300, maximum 360] | export /absolute/stopped-seed /absolute/new-bundle | stage /absolute/transferred-bundle /absolute/new-state /absolute/export-receipt.json lowercase-sha256 | recover-ha /absolute/snapshot /absolute/seal.json /absolute/private-shares.json /absolute/new-seed archive-sha256 seal-sha256 (native-v6-ha build)".into()),
    }?;
    let mut output = std::io::stdout().lock();
    output.write_all(&encoded).and_then(|()| output.write_all(b"\n"))
        .map_err(|_| "seed publication may have succeeded but its receipt could not be delivered; reconcile without retry".into())
}

#[cfg(unix)]
fn encode_receipt<T: serde::Serialize, E: std::fmt::Display>(
    receipt: Result<T, E>,
) -> Result<Vec<u8>, String> {
    let receipt = receipt.map_err(|error| error.to_string())?;
    serde_json::to_vec(&receipt).map_err(|_| "cannot encode seed receipt".into())
}

#[cfg(not(unix))]
fn run() -> Result<(), String> {
    Err("offline seed transport requires supported descriptor-bound Unix custody".into())
}
