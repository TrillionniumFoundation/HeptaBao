//! Bounded, inspection-only OpenBao Raft snapshot validator.
//!
//! The command intentionally has no restore or conversion mode.  It reads one
//! operator-supplied archive, validates its bounded format/integrity and emits
//! a sanitized JSON summary.  Snapshot bytes are never written or extracted.

use std::collections::BTreeSet;
use std::env;
use std::ffi::OsString;
use std::fs::File;
#[cfg(unix)]
use std::fs::OpenOptions;
#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use heptabao_migration::{SnapshotInspectionLimits, inspect_openbao_raft_snapshot_with_limits};
use serde_json::json;

#[derive(Debug)]
struct Options {
    input: PathBuf,
    limits: SnapshotInspectionLimits,
}

fn usage() {
    println!(
        "usage: inspect-openbao-snapshot --input PATH [--max-compressed-bytes N] \
         [--max-uncompressed-bytes N] [--max-state-bytes N] [--max-meta-bytes N] \
         [--max-sums-bytes N] [--max-sealed-bytes N]"
    );
}

fn parse_u64(value: Option<OsString>, flag: &str) -> Result<u64, String> {
    value
        .ok_or_else(|| format!("missing value for {flag}"))?
        .to_str()
        .ok_or_else(|| format!("invalid value for {flag}"))?
        .parse::<u64>()
        .map_err(|_| format!("invalid value for {flag}"))
}

fn parse_options(mut args: impl Iterator<Item = OsString>) -> Result<Option<Options>, String> {
    let mut input = None;
    let mut limits = SnapshotInspectionLimits::default();
    let mut seen = BTreeSet::new();
    while let Some(flag) = args.next() {
        let flag = flag.to_str().ok_or_else(|| "invalid argument".to_owned())?;
        if !seen.insert(flag.to_owned()) {
            return Err("duplicate argument".to_owned());
        }
        match flag {
            "--help" | "-h" if seen.len() == 1 && args.next().is_none() => return Ok(None),
            "--input" => {
                let path = args
                    .next()
                    .ok_or_else(|| "missing value for --input".to_owned())?;
                input = Some(PathBuf::from(path));
            }
            "--max-compressed-bytes" => {
                limits.max_compressed_bytes = parse_u64(args.next(), flag)?;
            }
            "--max-uncompressed-bytes" => {
                limits.max_uncompressed_bytes = parse_u64(args.next(), flag)?;
            }
            "--max-state-bytes" => {
                limits.max_state_bytes = parse_u64(args.next(), flag)?;
            }
            "--max-meta-bytes" => {
                limits.max_meta_bytes = parse_u64(args.next(), flag)?;
            }
            "--max-sums-bytes" => {
                limits.max_sums_bytes = parse_u64(args.next(), flag)?;
            }
            "--max-sealed-bytes" => {
                limits.max_sealed_bytes = parse_u64(args.next(), flag)?;
            }
            _ => return Err("unknown argument".to_owned()),
        }
    }
    let input = input.ok_or_else(|| "--input is required".to_owned())?;
    Ok(Some(Options { input, limits }))
}

#[cfg(unix)]
fn open_regular(path: &Path) -> Result<File, ()> {
    // Verify the opened descriptor, not a preceding path lookup. O_NOFOLLOW
    // rejects a substituted symlink and O_NONBLOCK prevents a FIFO replacement
    // from hanging before its non-regular type can be rejected.
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
        .map_err(|_| ())?;
    if !file.metadata().map_err(|_| ())?.is_file() {
        return Err(());
    }
    Ok(file)
}

#[cfg(not(unix))]
fn open_regular(_path: &Path) -> Result<File, ()> {
    // No path-check/open fallback with weaker no-follow semantics.
    Err(())
}

fn inspect(options: Options) -> Result<(), ()> {
    let file = open_regular(&options.input)?;
    let result = inspect_openbao_raft_snapshot_with_limits(file, options.limits).map_err(|_| ())?;
    let output = json!({
        "schema": "heptabao.openbao-raft-snapshot-inspection.v1",
        "status": "passed",
        "metadata_version": result.metadata_version,
        "index": result.index,
        "term": result.term,
        "configuration_index": result.configuration_index,
        "configuration_servers": result.configuration_servers,
        "state_size": result.state_size,
        "meta_sha256": result.meta_sha256,
        "state_sha256": result.state_sha256,
        "sealed_sums_present": result.sealed_sums_present,
        "compressed_bytes": result.compressed_bytes,
        "uncompressed_bytes": result.uncompressed_bytes,
        "restore_performed": false,
        "conversion_performed": false,
        "migration_authority": false,
    });
    println!("{}", serde_json::to_string(&output).map_err(|_| ())?);
    Ok(())
}

fn main() -> ExitCode {
    let options = match parse_options(env::args_os().skip(1)) {
        Ok(None) => {
            usage();
            return ExitCode::SUCCESS;
        }
        Ok(Some(options)) => options,
        Err(_) => {
            eprintln!("openbao snapshot inspection: invalid arguments");
            return ExitCode::from(2);
        }
    };
    match inspect(options) {
        Ok(()) => ExitCode::SUCCESS,
        Err(()) => {
            eprintln!("openbao snapshot inspection: rejected");
            ExitCode::from(1)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::parse_options;

    #[test]
    fn ambiguous_or_incomplete_options_are_rejected() {
        for args in [
            vec!["--input", "a", "--input", "b"],
            vec![
                "--input",
                "a",
                "--max-state-bytes",
                "1",
                "--max-state-bytes",
                "999",
            ],
            vec!["--input", "a", "--max-state-bytes"],
            vec!["--input", "a", "--max-state-bytes", "-1"],
            vec!["--input", "a", "--max-state-bytes", "18446744073709551616"],
            vec!["--help", "--unexpected"],
        ] {
            assert!(parse_options(args.into_iter().map(Into::into)).is_err());
        }
    }

    #[cfg(unix)]
    #[test]
    fn non_utf8_input_path_is_supported_without_panicking() {
        use std::ffi::OsString;
        use std::os::unix::ffi::OsStringExt;

        let path = OsString::from_vec(vec![0xff]);
        let parsed = parse_options([OsString::from("--input"), path.clone()].into_iter());
        assert!(matches!(parsed, Ok(Some(options)) if options.input.as_os_str() == path));
        assert!(parse_options([path].into_iter()).is_err());
    }
}
