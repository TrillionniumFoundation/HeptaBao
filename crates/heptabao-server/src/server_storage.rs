//! Configuration adapters select real existing durable consumers.
//! Native on-disk/SQL formats are not OpenBao physical formats; migration is explicit.
use super::{Invalid, Tree, optional_listener_bool, unique};
use crate::{ha::HaProcessConfig, http::Config, outbound::Target};
use serde::Deserialize;
use serde_json::{Map, Value, json};
use std::path::{Path, PathBuf};
use zeroize::Zeroizing;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub enum StorageConfig {
    #[serde(rename = "pebbledb")]
    PebbleDb { path: PathBuf },
    #[serde(rename = "raft")]
    Raft {
        path: PathBuf,
        #[serde(default)]
        node_id: Option<String>,
        cluster_addr: String,
        #[serde(default)]
        api_addr: Option<String>,
    },
    #[serde(rename = "postgresql")]
    PostgreSql {},
}

fn path_checked(path: &Path) -> Result<(), Invalid> {
    let text = path.to_str().ok_or(())?;
    if !path.is_absolute()
        || text.len() > 4096
        || text.trim_end_matches('/').len() < 2
        || text.chars().any(char::is_control)
        || text
            .trim_end_matches('/')
            .split('/')
            .skip(1)
            .any(|part| matches!(part, "" | "." | ".."))
    {
        return Err(());
    }
    Ok(())
}

fn origin(address: &str) -> Result<String, Invalid> {
    let target = crate::outbound::parse_auth_https_target(
        address,
        Some(&crate::outbound::AuthHttpsTransport::default()),
    )
    .map_err(|_| ())?;
    if target.path != "/" {
        return Err(());
    }
    Ok(target.origin)
}

/// Pure enrollment admission; this runs before HaProcess::start creates any files/listeners.
pub fn validate_storage(config: &Config, ha: Option<&HaProcessConfig>) -> Result<(), String> {
    validate_storage_runtime(config, ha.is_some())?;
    let Some(StorageConfig::Raft {
        path,
        node_id,
        cluster_addr,
        api_addr,
    }) = config.storage.as_ref()
    else {
        return Ok(());
    };
    let ha = ha.ok_or("raft storage requires explicit enrolled HA configuration")?;
    if ha.raft_dir != path.join("raft") {
        return Err("raft storage path disagrees with enrolled HA directory".into());
    }
    let local = ha
        .peers
        .get(&ha.node_id)
        .ok_or("raft storage local peer is not enrolled")?;
    if node_id.as_ref().is_some_and(|id| id != &local.node_name) {
        return Err("raft storage node_id disagrees with enrolled local peer".into());
    }
    let configured = local
        .cluster_address
        .as_deref()
        .ok_or("raft storage requires enrolled cluster address")?;
    if origin(cluster_addr).map_err(|_| "invalid raft cluster address")?
        != origin(configured).map_err(|_| "invalid enrolled raft cluster address")?
    {
        return Err("raft cluster address disagrees with enrolled local peer".into());
    }
    if let Some(address) = api_addr {
        let configured = local
            .api_address
            .as_deref()
            .ok_or("raft storage requires enrolled API address")?;
        if origin(address).map_err(|_| "invalid raft API address")?
            != origin(configured).map_err(|_| "invalid enrolled raft API address")?
        {
            return Err("raft API address disagrees with enrolled local peer".into());
        }
    }
    Ok(())
}

/// Recheck the immutable running consumer for direct library serve callers.
pub fn validate_storage_running(config: &Config, ha: &crate::ha::HaProcess) -> Result<(), String> {
    let Some(StorageConfig::Raft {
        path,
        node_id,
        cluster_addr,
        api_addr,
    }) = config.storage.as_ref()
    else {
        return Ok(());
    };
    let crate::ha::StorageBinding {
        directory,
        name,
        cluster_address: cluster,
        api_address: api,
    } = ha.storage_binding()?;
    if directory != path.join("raft") || node_id.as_ref().is_some_and(|id| id != &name) {
        return Err("raft storage disagrees with running enrolled consumer".into());
    }
    let cluster = cluster.ok_or("running raft consumer has no enrolled cluster address")?;
    if origin(cluster_addr).map_err(|_| "invalid raft cluster address")?
        != origin(&cluster).map_err(|_| "invalid running raft cluster address")?
    {
        return Err("raft cluster address disagrees with running enrolled consumer".into());
    }
    if let Some(address) = api_addr {
        let api = api.ok_or("running raft consumer has no enrolled API address")?;
        if origin(address).map_err(|_| "invalid raft API address")?
            != origin(&api).map_err(|_| "invalid running raft API address")?
        {
            return Err("raft API address disagrees with running enrolled consumer".into());
        }
    }
    Ok(())
}

/// Every serve entry, including direct library calls, checks the selected consumer.
pub fn validate_storage_runtime(config: &Config, ha: bool) -> Result<(), String> {
    match config.storage.as_ref() {
        None => Ok(()),
        Some(StorageConfig::PebbleDb { path }) => {
            path_checked(path).map_err(|_| "invalid durable storage path")?;
            if config.data_dir != *path || ha || config.postgres_durable.is_some() {
                return Err(
                    "local durable storage conflicts with selected deployment consumer".into(),
                );
            }
            Ok(())
        }
        Some(StorageConfig::Raft {
            path,
            cluster_addr,
            api_addr,
            ..
        }) => {
            path_checked(path).map_err(|_| "invalid raft storage path")?;
            origin(cluster_addr).map_err(|_| "invalid raft cluster address")?;
            if let Some(address) = api_addr {
                origin(address).map_err(|_| "invalid raft API address")?;
            }
            if !ha {
                return Err("raft storage requires explicit enrolled HA configuration".into());
            }
            if config.data_dir != path.join("state") || config.postgres_durable.is_some() {
                return Err("raft storage conflicts with selected deployment consumer".into());
            }
            Ok(())
        }
        Some(StorageConfig::PostgreSql {}) => {
            if ha || config.postgres_durable.is_none() {
                return Err(
                    "PostgreSQL storage requires the enrolled PostgreSQL durable consumer".into(),
                );
            }
            Ok(())
        }
    }
}

fn string(fields: &mut Map<String, Value>, key: &str) -> Result<Zeroizing<String>, Invalid> {
    let value = Tree(fields.remove(key).ok_or(())?);
    value
        .0
        .as_str()
        .map(|text| Zeroizing::new(text.to_owned()))
        .ok_or(())
}

fn decode_component(encoded: &str) -> Result<Zeroizing<String>, Invalid> {
    if encoded.is_empty() || encoded.len() > 2048 {
        return Err(());
    }
    let mut bytes = Zeroizing::new(Vec::new());
    let raw = encoded.as_bytes();
    let mut offset = 0;
    while offset < raw.len() {
        if raw[offset] == b'%' {
            let digits = encoded.get(offset + 1..offset + 3).ok_or(())?;
            if !digits.bytes().all(|byte| byte.is_ascii_hexdigit()) {
                return Err(());
            }
            bytes.push(u8::from_str_radix(digits, 16).map_err(|_| ())?);
            offset += 3;
        } else {
            if !raw[offset].is_ascii() {
                return Err(());
            }
            bytes.push(raw[offset]);
            offset += 1;
        }
    }
    let text = std::str::from_utf8(&bytes).map_err(|_| ())?;
    if text.is_empty() || text.len() > 256 || text.chars().any(char::is_control) {
        return Err(());
    }
    Ok(Zeroizing::new(text.to_owned()))
}

// A finite URI subset feeds the existing canonical Target parser and enrolled
// TLS endpoint. It never resolves DNS, reads environments, downgrades TLS or connects.
fn postgres(root: &Map<String, Value>, fields: &mut Map<String, Value>) -> Result<Tree, Invalid> {
    let url = string(fields, "connection_url")?;
    if url.len() > 2048 || url.chars().any(char::is_control) {
        return Err(());
    }
    let rest = url
        .strip_prefix("postgres://")
        .or_else(|| url.strip_prefix("postgresql://"))
        .ok_or(())?;
    let (authority, path) = rest.split_once('/').ok_or(())?;
    let (user_info, host) = authority.split_once('@').ok_or(())?;
    if host.contains('@') {
        return Err(());
    }
    let (user, password) = user_info.split_once(':').ok_or(())?;
    let user = decode_component(user)?;
    let password = decode_component(password)?;
    let database = if let Some((database, query)) = path.split_once('?') {
        if query != "sslmode=verify-full" {
            return Err(());
        }
        database
    } else {
        path
    };
    if database.is_empty() || database.contains('/') {
        return Err(());
    }
    let authority = if host.contains(':') {
        host.to_owned()
    } else {
        format!("{host}:5432")
    };
    let connection = format!("postgresql://{authority}/{database}");
    let target = Target::parse(&connection, "postgresql").map_err(|_| ())?;
    let endpoints = root
        .get("outbound_endpoints")
        .and_then(Value::as_array)
        .ok_or(())?;
    let mut matching = endpoints.iter().filter(|endpoint| {
        endpoint.get("origin").and_then(Value::as_str) == Some(target.origin.as_str())
    });
    let endpoint = matching.next().ok_or(())?;
    if matching.next().is_some() {
        return Err(());
    }
    if let Some(table) = fields.remove("table") {
        let table = Tree(table);
        if table.0.as_str() != Some("openbao_kv_store") {
            return Err(());
        }
    }
    if optional_listener_bool(fields, "ha_enabled")? == Some(true)
        || optional_listener_bool(fields, "skip_create_table")? == Some(true)
        || !fields.is_empty()
    {
        return Err(());
    }
    Ok(Tree(json!({
        "endpoint": endpoint, "connection_url": connection,
        "username": user.as_str(), "password": password.as_str(), "scope": "openbao270"
    })))
}

pub(super) fn normalize(root: &mut Map<String, Value>) -> Result<(), Invalid> {
    let Some(value) = root.remove("storage") else {
        return Ok(());
    };
    let mut storage = Tree(value);
    let kinds = storage.0.as_object_mut().ok_or(())?;
    if kinds.len() != 1 {
        return Err(());
    }
    let name = kinds.keys().next().ok_or(())?.to_owned();
    let mut settings = Tree(kinds.remove(&name).ok_or(())?);
    let fields = settings.0.as_object_mut().ok_or(())?;
    let selector = match name.as_str() {
        "pebbledb" => {
            let path = string(fields, "path")?;
            path_checked(Path::new(path.as_str()))?;
            if optional_listener_bool(fields, "read_only")? == Some(true) || !fields.is_empty() {
                return Err(());
            }
            unique(root, "data_dir", Value::String(path.as_str().to_owned()))?;
            Tree(json!({"pebbledb": {"path": path.as_str()}}))
        }
        "raft" => {
            let path = string(fields, "path")?;
            path_checked(Path::new(path.as_str()))?;
            let node_id = fields.remove("node_id");
            if node_id.as_ref().is_some_and(|id| {
                !id.as_str()
                    .is_some_and(|id| !id.is_empty() && id.len() <= 128)
            }) {
                return Err(());
            }
            if !fields.is_empty() {
                return Err(());
            }
            let cluster_addr = string(root, "cluster_addr")?;
            origin(cluster_addr.as_str())?;
            let api_addr = root.remove("api_addr");
            if api_addr.as_ref().is_some_and(|address| {
                !address
                    .as_str()
                    .is_some_and(|address| origin(address).is_ok())
            }) {
                return Err(());
            }
            let state = Path::new(path.as_str()).join("state");
            unique(
                root,
                "data_dir",
                Value::String(state.to_str().ok_or(())?.to_owned()),
            )?;
            Tree(json!({"raft": {"path": path.as_str(), "node_id": node_id,
                                "cluster_addr": cluster_addr.as_str(), "api_addr": api_addr}}))
        }
        "postgresql" => {
            let mut config = postgres(root, fields)?;
            unique(root, "postgres_durable", config.take())?;
            Tree(json!({"postgresql": {}}))
        }
        _ => return Err(()),
    };
    let mut selector = selector;
    unique(root, "storage", selector.take())
}
