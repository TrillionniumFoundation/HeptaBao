//! OpenBao 2.7.1 /sys/config/state/sanitized process-owned allowlist.
//! Never serialize the source Config: it can hold TLS keys, seal bindings,
//! provider credentials, plugin parameters and audit transport secrets.
use super::Config;
use crate::configuration::StorageConfig;
use serde_json::{Value, json};

pub(super) fn project(config: &Config) -> Value {
    let (kind, api_addr, cluster_addr) = match config.storage.as_ref() {
        Some(StorageConfig::Raft {
            api_addr,
            cluster_addr,
            ..
        }) => (
            "raft",
            api_addr.as_deref().unwrap_or(""),
            cluster_addr.as_str(),
        ),
        Some(StorageConfig::PostgreSql {}) => ("postgresql", "", ""),
        Some(StorageConfig::PebbleDb { .. }) => ("pebbledb", "", ""),
        None => ("heptabao-native", "", ""),
    };
    // Only fields that are either fixed runtime properties or selected
    // non-secret values from the trusted listener/storage enums may be emitted.
    // NEVER include a map from StorageConfig or arbitrary extra HCL keys.
    json!({
        "api_addr": api_addr,
        "cache_size": 0,
        "cluster_addr": cluster_addr,
        "cluster_cipher_suites": "",
        "cluster_name": "",
        "default_lease_ttl": 0,
        "default_max_request_duration": 0,
        "disable_cache": false,
        "disable_clustering": false,
        "disable_indexing": false,
        "disable_performance_standby": false,
        "disable_printable_check": false,
        "disable_sealwrap": false,
        "raw_storage_endpoint": false,
        "detect_deadlocks": "",
        "introspection_endpoint": false,
        "disable_sentinel_trace": false,
        "enable_ui": config.ui,
        "log_format": "",
        "log_level": "",
        "max_lease_ttl": 0,
        "pid_file": "",
        "plugin_directory": "",
        "plugin_file_uid": 0,
        "plugin_file_permissions": 0,
        "enable_response_header_hostname": false,
        "enable_response_header_raft_node_id": false,
        "log_requests_level": "",
        "listeners": [{
            "type": "tcp",
            "config": {"address": config.listen.to_string(), "tls_disable": false}
        }],
        // OpenBao 2.7.1 omits telemetry entirely when no telemetry stanza exists.
        // Native Config has no telemetry stanza: do not invent an empty object.
        "storage": {
            "type": kind,
            "redirect_addr": api_addr,
            "cluster_addr": cluster_addr,
            "disable_clustering": false
        },
        "seals": [{"type": if config.openbao_wrapper.as_ref().is_some_and(|v| v.seal_barrier) {"wrapper"} else {"shamir"}, "disabled": false}],
        "imprecise_lease_role_tracking": false,
        "unsafe_cross_namespace_identity": false,
        "unsafe_allow_api_audit_creation": false,
        "allow_audit_log_prefixing": false,
        "disable_standby_reads": false,
        "allow_unauthenticated_workflows": false,
        "unsafe_relative_paths": false,
        "disable_ssct_tokens": true
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn fixture() -> Result<Config, serde_json::Error> {
        serde_json::from_value(json!({
            "listen": "127.0.0.1:38413",
            "data_dir": "/tmp/unexposed-durable-storage",
            "audit_file": "/tmp/unexposed-audit-credential",
            "tls_cert_file": "/tmp/unexposed-leaf.pem",
            "tls_key_file": "/tmp/tls-acme-eab-mac-key-sentinel.pem",
            "ui": true,
            "storage": {"pebbledb":{"path":"/tmp/private-db-sentinel"}}
        }))
    }

    #[test]
    fn sanitized_projection_only_emits_safe_runtime_fields() -> Result<(), serde_json::Error> {
        let config = fixture()?;
        let projection = project(&config);
        let encoded = projection.to_string().to_lowercase();
        for forbidden in [
            "eab-mac-key-sentinel",
            "private-db-sentinel",
            "unexposed-audit",
            "unexposed-durable",
            "unexposed-leaf",
            "tls_key_file",
            "tls_cert_file",
            "ca_pem",
            "shared_secret",
        ] {
            assert!(!encoded.contains(forbidden), "{forbidden} leaked");
        }
        assert_eq!(projection["enable_ui"], true);
        assert_eq!(
            projection["listeners"][0]["config"]["address"],
            "127.0.0.1:38413"
        );
        assert_eq!(projection["listeners"][0]["config"]["tls_disable"], false);
        assert!(projection.get("telemetry").is_none());
        assert_eq!(projection["storage"]["type"], "pebbledb");
        assert_eq!(projection["seals"][0]["type"], "shamir");
        Ok(())
    }

    #[test]
    fn raft_configuration_excludes_node_id_and_private_storage_path()
    -> Result<(), serde_json::Error> {
        let mut config = fixture()?;
        config.storage = Some(StorageConfig::Raft {
            path: "/tmp/private-raft-path-sentinel".into(),
            node_id: Some("private-raft-node-sentinel".to_string()),
            cluster_addr: "https://127.0.0.1:8201".to_string(),
            api_addr: Some("https://127.0.0.1:8200".to_string()),
        });
        let projection = project(&config);
        let serialized = projection.to_string();
        assert_eq!(projection["storage"]["type"], "raft");
        assert_eq!(
            projection["storage"]["cluster_addr"],
            "https://127.0.0.1:8201"
        );
        assert!(!serialized.contains("private-raft-node-sentinel"));
        assert!(!serialized.contains("private-raft-path-sentinel"));
        Ok(())
    }
}
