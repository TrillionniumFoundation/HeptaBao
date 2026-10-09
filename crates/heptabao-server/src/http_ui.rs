//! Deployment-owned official UI assets, frozen before listener admission.
//! Request text selects a prevalidated table entry and never a filesystem path.
use super::*;
use std::{
    fs,
    path::{Component, Path},
};

const MAX_ASSET_BYTES: usize = MAX_RESPONSE;
const MAX_TOTAL_BYTES: usize = 64 * 1024 * 1024;
const MAX_ASSETS: usize = 4096;
const MAX_MANIFEST_BYTES: usize = 1024 * 1024;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AssetPin {
    path: String,
    bytes: u64,
    sha256: String,
}

pub(super) struct Assets {
    files: BTreeMap<String, Asset>,
}
struct Asset {
    bytes: Arc<[u8]>,
    media: &'static str,
}
pub(super) struct Request {
    path: String,
    pub(super) head: bool,
}
pub(super) struct Reply {
    status: u16,
    bytes: Arc<[u8]>,
    media: &'static str,
    redirect: bool,
    worker: bool,
}

fn sha256(bytes: &[u8]) -> String {
    ring::digest::digest(&ring::digest::SHA256, bytes)
        .as_ref()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn physical_file(path: &Path, limit: usize) -> Result<Vec<u8>, String> {
    let before = fs::symlink_metadata(path).map_err(|_| "cannot inspect UI asset")?;
    if !before.is_file()
        || before.len() > limit as u64
        || path.canonicalize().map_err(|_| "cannot resolve UI asset")? != path
    {
        return Err("UI assets require bounded regular files without symlinks".into());
    }
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
        if before.permissions().mode() & 0o022 != 0 || before.nlink() != 1 {
            return Err("UI assets must not be writable by other users or hard-linked".into());
        }
        options.custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK);
    }
    let file = options.open(path).map_err(|_| "cannot open UI asset")?;
    let opened = file
        .metadata()
        .map_err(|_| "cannot inspect opened UI asset")?;
    if !opened.is_file() || opened.len() != before.len() {
        return Err("UI asset changed during admission".into());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if opened.dev() != before.dev() || opened.ino() != before.ino() {
            return Err("UI asset changed during admission".into());
        }
    }
    let mut bytes = Vec::new();
    file.take(limit as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| "cannot read UI asset")?;
    if bytes.len() > limit || bytes.len() as u64 != opened.len() {
        return Err("UI asset changed or exceeded limit".into());
    }
    Ok(bytes)
}

fn safe_relative(path: &str) -> bool {
    !path.is_empty()
        && path.len() <= 4096
        && path.is_ascii()
        && !path
            .bytes()
            .any(|byte| byte < 33 || byte == 127 || b"\\%?#".contains(&byte))
        && !path.starts_with('/')
        && !path.ends_with('/')
        && !path.contains("//")
        && path
            .split('/')
            .all(|part| !matches!(part, "." | "..") && !part.starts_with('.'))
        && Path::new(path)
            .components()
            .all(|part| matches!(part, Component::Normal(_)))
}

fn media(path: &str) -> Option<&'static str> {
    match path.rsplit('.').next()? {
        "html" => Some("text/html; charset=utf-8"),
        "css" => Some("text/css; charset=utf-8"),
        "js" => Some("text/javascript; charset=utf-8"),
        "json" | "map" => Some("application/json"),
        "svg" => Some("image/svg+xml"),
        "png" => Some("image/png"),
        "jpg" | "jpeg" => Some("image/jpeg"),
        "gif" => Some("image/gif"),
        "webp" => Some("image/webp"),
        "ico" => Some("image/x-icon"),
        "woff" => Some("font/woff"),
        "woff2" => Some("font/woff2"),
        "ttf" => Some("font/ttf"),
        "otf" => Some("font/otf"),
        "wasm" => Some("application/wasm"),
        "txt" => Some("text/plain; charset=utf-8"),
        _ => None,
    }
}

impl Assets {
    pub(super) fn configured(config: &Config) -> Result<Option<Arc<Self>>, String> {
        if !config.ui {
            if config.ui_assets_dir.is_some()
                || config.ui_assets_manifest.is_some()
                || config.ui_assets_manifest_sha256.is_some()
            {
                return Err("UI asset settings require ui=true".into());
            }
            return Ok(None);
        }
        let directory = config
            .ui_assets_dir
            .as_deref()
            .ok_or("UI asset directory is required")?;
        let manifest = config
            .ui_assets_manifest
            .as_deref()
            .ok_or("UI asset manifest is required")?;
        let expected = config
            .ui_assets_manifest_sha256
            .as_deref()
            .ok_or("UI manifest SHA256 is required")?;
        Self::load(directory, manifest, expected).map(|assets| Some(Arc::new(assets)))
    }

    fn load(directory: &Path, manifest: &Path, expected: &str) -> Result<Self, String> {
        if !directory.is_absolute()
            || !manifest.is_absolute()
            || directory
                .canonicalize()
                .map_err(|_| "cannot resolve UI directory")?
                != directory
            || !fs::symlink_metadata(directory)
                .map_err(|_| "cannot inspect UI directory")?
                .is_dir()
            || expected.len() != 64
            || !expected
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
        {
            return Err("invalid deployment-owned UI asset configuration".into());
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if fs::metadata(directory)
                .map_err(|_| "cannot inspect UI directory")?
                .permissions()
                .mode()
                & 0o022
                != 0
            {
                return Err("UI directory must not be writable by other users".into());
            }
        }
        let raw = physical_file(manifest, MAX_MANIFEST_BYTES)?;
        if sha256(&raw) != expected {
            return Err("UI manifest SHA256 mismatch".into());
        }
        let pins: Vec<AssetPin> =
            serde_json::from_slice(&raw).map_err(|_| "invalid UI manifest")?;
        if pins.is_empty() || pins.len() > MAX_ASSETS {
            return Err("invalid UI asset count".into());
        }
        let mut files = BTreeMap::new();
        let mut seen = std::collections::BTreeSet::new();
        let mut total = 0usize;
        for pin in pins {
            // The upstream build emits directory placeholder files. Validate
            // their bytes but never expose them as a static resource.
            let placeholder = pin.path.ends_with("/.gitkeep") || pin.path == ".gitkeep";
            let checked = if placeholder {
                pin.path.replace(".gitkeep", "gitkeep")
            } else {
                pin.path.clone()
            };
            if !safe_relative(&checked)
                || !seen.insert(pin.path.clone())
                || pin.bytes > MAX_ASSET_BYTES as u64
            {
                return Err("invalid or duplicate UI asset pin".into());
            }
            total = total
                .checked_add(pin.bytes as usize)
                .filter(|value| *value <= MAX_TOTAL_BYTES)
                .ok_or("UI assets exceed total limit")?;
            let bytes = physical_file(&directory.join(&pin.path), MAX_ASSET_BYTES)?;
            if bytes.len() as u64 != pin.bytes || sha256(&bytes) != pin.sha256 {
                return Err("UI asset bytes do not match manifest".into());
            }
            if !placeholder && let Some(media) = media(&pin.path) {
                files.insert(
                    pin.path,
                    Asset {
                        bytes: bytes.into(),
                        media,
                    },
                );
            }
        }
        if !files.contains_key("index.html") {
            return Err("official UI index.html is required".into());
        }
        Ok(Self { files })
    }

    pub(super) fn reply(&self, request: &Request) -> Reply {
        if matches!(request.path.as_str(), "/" | "/ui") {
            return Reply {
                status: 307,
                bytes: Arc::from([]),
                media: "text/plain; charset=utf-8",
                redirect: true,
                worker: false,
            };
        }
        let path = request.path.strip_prefix("/ui/").unwrap_or("");
        let asset = self.files.get(path).or_else(|| {
            if path.is_empty() || spa_route(path) {
                self.files.get("index.html")
            } else {
                None
            }
        });
        match asset {
            Some(asset) => Reply {
                status: 200,
                bytes: Arc::clone(&asset.bytes),
                media: asset.media,
                redirect: false,
                worker: path == "service-worker.js",
            },
            None => Reply {
                status: 404,
                bytes: Arc::from(&b"UI resource not found\n"[..]),
                media: "text/plain; charset=utf-8",
                redirect: false,
                worker: false,
            },
        }
    }
}

fn spa_route(path: &str) -> bool {
    // Official app/routes/vault.js fixes the single cluster name to "vault".
    // Its router includes namespace OIDC callbacks and a client-side catchall.
    // Asset namespaces remain outside this fallback and missing assets are 404.
    path == "vault" || path.starts_with("vault/")
}

pub(super) fn selected(target: &str) -> bool {
    matches!(target.split('?').next(), Some("/" | "/ui")) || target.starts_with("/ui/")
}

pub(super) fn request(method: &str, target: &str) -> Result<Request, ParseError> {
    if !matches!(method, "GET" | "HEAD") {
        return Err(ParseError {
            status: 405,
            ..bad("UI resources require GET or HEAD")
        });
    }
    if target.contains('#') || !target.bytes().all(|byte| (33..=126).contains(&byte)) {
        return Err(bad("invalid UI request target"));
    }
    let raw = target.split('?').next().unwrap_or("");
    let mut decoded = Vec::with_capacity(raw.len());
    let mut bytes = raw.bytes();
    while let Some(byte) = bytes.next() {
        if byte == b'%' {
            let high = bytes.next().and_then(|value| (value as char).to_digit(16));
            let low = bytes.next().and_then(|value| (value as char).to_digit(16));
            let value = match (high, low) {
                (Some(high), Some(low)) => (high * 16 + low) as u8,
                _ => return Err(outer_bad("invalid UI URI escape")),
            };
            if matches!(value, b'/' | b'\\' | b'%' | b'?' | b'#') || value < 33 || value == 127 {
                return Err(bad("ambiguous UI URI escape"));
            }
            decoded.push(value);
        } else if byte == b'\\' {
            return Err(bad("invalid UI request path"));
        } else {
            decoded.push(byte);
        }
    }
    let path = String::from_utf8(decoded).map_err(|_| bad("invalid UI URI encoding"))?;
    if path.contains("//")
        || path
            .split('/')
            .any(|part| matches!(part, "." | "..") || part.starts_with('.'))
    {
        return Err(bad("invalid UI request path"));
    }
    Ok(Request {
        path,
        head: method == "HEAD",
    })
}

impl Reply {
    pub(super) fn write(self, writer: &mut impl Write, head: bool) -> io::Result<()> {
        let reason = match self.status {
            200 => "OK",
            307 => "Temporary Redirect",
            _ => "Not Found",
        };
        write!(
            writer,
            "HTTP/1.1 {} {reason}\r\nContent-Type: {}\r\nContent-Length: {}\r\n",
            self.status,
            self.media,
            self.bytes.len()
        )?;
        if self.redirect {
            writer.write_all(b"Location: /ui/\r\n")?;
        }
        write_standard_headers(writer, "")?;
        writer.write_all(b"X-Content-Type-Options: nosniff\r\nReferrer-Policy: same-origin\r\nContent-Security-Policy: default-src 'none'; script-src 'self'; font-src 'self'; connect-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; media-src 'self'; worker-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'self'; form-action 'none'\r\n")?;
        if self.worker {
            writer.write_all(b"Service-Worker-Allowed: /v1/sys/storage/raft/snapshot\r\n")?;
        }
        writer.write_all(b"\r\n")?;
        if !head {
            writer.write_all(&self.bytes)?;
        }
        writer.flush()
    }
}

#[cfg(test)]
#[path = "http_ui_tests.rs"]
mod tests;
