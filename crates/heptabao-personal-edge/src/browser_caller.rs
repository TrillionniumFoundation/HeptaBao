//! Native-host launch routing for a trusted local OS account.
//!
//! Browser-provided arguments and a private installation are not caller or
//! Runtime attestations. A hostile process with the same UID is out of scope.
use heptabao_personal_vault::read_private_file;
use ring::digest::{SHA256, digest};
use serde::Deserialize;
use std::path::{Component, Path, PathBuf};

pub(super) const FIREFOX_ADDON: &str = "heptabao-firefox-feasibility@heptabao.invalid";
pub(super) const FIREFOX_HOST: &str = "org.heptabao.personal_vault_firefox_feasibility";
const FIREFOX_DESCRIPTION: &str = "HeptaBao local encrypted vault Firefox candidate";

pub(super) struct SessionConfig {
    pub(super) vault_root: PathBuf,
    pub(super) unlock_seconds: u64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ChromiumConfig {
    vault_root: PathBuf,
    extension_id: String,
    unlock_seconds: u64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct FirefoxConfig {
    vault_root: PathBuf,
    addon_id: String,
    unlock_seconds: u64,
    manifest_path: PathBuf,
    manifest_sha256: String,
    launcher_path: PathBuf,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct FirefoxManifest {
    name: String,
    description: String,
    path: PathBuf,
    #[serde(rename = "type")]
    transport: String,
    allowed_extensions: Vec<String>,
}

fn configuration(path: &str) -> Result<zeroize::Zeroizing<Vec<u8>>, &'static str> {
    let raw = read_private_file(Path::new(path)).map_err(|_| "configuration_rejected")?;
    if raw.len() > 8192 {
        return Err("configuration_rejected");
    }
    Ok(raw)
}

fn normalized_absolute(path: &Path) -> bool {
    path.is_absolute()
        && path
            .components()
            .all(|part| matches!(part, Component::RootDir | Component::Normal(_)))
        && path.components().collect::<PathBuf>().as_os_str() == path.as_os_str()
}

fn canonical_private_launcher(path: &Path) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let Ok(meta) = std::fs::symlink_metadata(path) else {
            return false;
        };
        normalized_absolute(path)
            && meta.is_file()
            && meta.uid() == rustix::process::geteuid().as_raw()
            && meta.nlink() == 1
            && meta.mode() & 0o777 == 0o700
            && std::fs::canonicalize(path)
                .is_ok_and(|canonical| canonical.as_os_str() == path.as_os_str())
    }
    #[cfg(not(unix))]
    {
        let _ = path;
        false
    }
}

fn firefox(args: &[String]) -> Result<SessionConfig, &'static str> {
    let raw = configuration(&args[2])?;
    let config: FirefoxConfig =
        serde_json::from_slice(&raw).map_err(|_| "configuration_rejected")?;
    if config.addon_id != FIREFOX_ADDON
        || args[4] != config.addon_id
        || std::ffi::OsStr::new(&args[3]) != config.manifest_path.as_os_str()
        || !normalized_absolute(&config.vault_root)
        || !normalized_absolute(&config.manifest_path)
        || config.manifest_path.file_name()
            != Some(std::ffi::OsStr::new(&format!("{FIREFOX_HOST}.json")))
        || !(1..=300).contains(&config.unlock_seconds)
        || config.manifest_sha256.len() != 64
        || !config
            .manifest_sha256
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err("caller_or_configuration_rejected");
    }
    if !canonical_private_launcher(&config.launcher_path) {
        return Err("manifest_rejected");
    }
    let manifest_raw = read_private_file(&config.manifest_path).map_err(|_| "manifest_rejected")?;
    if manifest_raw.len() > 8192 {
        return Err("manifest_rejected");
    }
    let mut actual_digest = String::with_capacity(64);
    const HEX: &[u8; 16] = b"0123456789abcdef";
    for byte in digest(&SHA256, &manifest_raw).as_ref() {
        actual_digest.push(char::from(HEX[usize::from(byte >> 4)]));
        actual_digest.push(char::from(HEX[usize::from(byte & 15)]));
    }
    if actual_digest != config.manifest_sha256 {
        return Err("manifest_rejected");
    }
    let manifest: FirefoxManifest =
        serde_json::from_slice(&manifest_raw).map_err(|_| "manifest_rejected")?;
    if manifest.name != FIREFOX_HOST
        || manifest.description != FIREFOX_DESCRIPTION
        || manifest.transport != "stdio"
        || manifest.path.as_os_str() != config.launcher_path.as_os_str()
        || manifest.allowed_extensions.len() != 1
        || manifest.allowed_extensions[0] != config.addon_id
    {
        return Err("manifest_rejected");
    }
    Ok(SessionConfig {
        vault_root: config.vault_root,
        unlock_seconds: config.unlock_seconds,
    })
}

pub(super) fn config_for_args(args: &[String]) -> Result<SessionConfig, &'static str> {
    if args.len() == 5 && args[1] == "--firefox-config" {
        return firefox(args);
    }
    // Preserve the existing Chromium argv, JSON schema, validation and error
    // ordering. Firefox never constructs a synthetic chrome-extension origin.
    if args.len() != 4 || args[1] != "--config" {
        return Err("configuration_required");
    }
    let raw = configuration(&args[2])?;
    let config: ChromiumConfig =
        serde_json::from_slice(&raw).map_err(|_| "configuration_rejected")?;
    if config.extension_id.len() != 32
        || !config
            .extension_id
            .bytes()
            .all(|b| (b'a'..=b'p').contains(&b))
        || args[3] != format!("chrome-extension://{}/", config.extension_id)
        || !config.vault_root.is_absolute()
        || !(1..=300).contains(&config.unlock_seconds)
    {
        return Err("caller_or_configuration_rejected");
    }
    Ok(SessionConfig {
        vault_root: config.vault_root,
        unlock_seconds: config.unlock_seconds,
    })
}
