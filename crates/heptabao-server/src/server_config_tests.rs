use super::*;
use std::path::PathBuf;

const NATIVE: &str = r#"
listen = "127.0.0.1:8200"
data_dir = "/synthetic/data"
audit_file = "/synthetic/audit"
tls_cert_file = "/synthetic/cert"
tls_key_file = "/synthetic/key"
"#;

fn rejected(source: &str) -> Result<(), String> {
    let error = parse_server(source.as_bytes())
        .err()
        .ok_or("invalid config accepted")?;
    assert_eq!(error, SERVER_SCHEMA);
    Ok(())
}

#[test]
fn hcl_native_literals_preserve_server_defaults_arrays_and_owned_audit() -> Result<(), String> {
    let source = format!(
        r#"{NATIVE}
        # Comments do not enter configuration strings.
        ui = false
        max_connections = 9
        timeout_seconds = 17
        tls_min_version = "tls12"
        tls_max_version = "tls13"
        tls_key_exchange_preferences = ["X25519MLKEM768", "X25519",]
        /* Native configuration objects remain schema checked. */
        outbound_endpoints = []
        plugin_auth = []
        postgres_durable = null
        lifecycle_interval_seconds = 0
        "#
    );
    let config = parse_server(source.as_bytes())?;
    assert_eq!(config.listen.to_string(), "127.0.0.1:8200");
    assert_eq!(config.data_dir, PathBuf::from("/synthetic/data"));
    assert_eq!(config.audit_file, PathBuf::from("/synthetic/audit"));
    assert_eq!(config.max_connections, 9);
    assert_eq!(config.timeout_seconds, 17);
    assert_eq!(config.lifecycle_interval_seconds, 0);
    assert_eq!(config.tls_min_version.as_deref(), Some("tls12"));
    assert_eq!(config.tls_max_version.as_deref(), Some("tls13"));
    assert_eq!(
        config.tls_key_exchange_preferences,
        Some(vec!["X25519MLKEM768".into(), "X25519".into()])
    );
    assert!(config.disable_unauthed_rekey_endpoints);
    assert!(config.postgres_durable.is_none());
    assert!(config.outbound_endpoints.is_empty());
    assert!(config.plugin_auth.is_empty());
    Ok(())
}

#[test]
fn hcl_documented_tcp_aliases_preserve_tls_security_and_reject_storage() -> Result<(), String> {
    // Non-Go v2.7 TCP documentation fields. Backend blocks are rejected until
    // their actual owner exists; deployment data and audit remain explicit.
    let source = r#"
        data_dir = "/synthetic/data"
        listener "tcp" {
            address = "[::1]:8200"
            tls_disable = false
            tls_cert_file = "/synthetic/cert"
            tls_key_file = "/synthetic/key"
            tls_key_exchange_preferences = ["SecP256r1MLKEM768"]
            tls_client_ca_file = "/synthetic/client-ca"
            tls_require_and_verify_client_cert = true
            disable_unauthed_rekey_endpoints = false
        }
        audit_file = "/synthetic/audit"
    "#;
    let config = parse_server(source.as_bytes())?;
    assert_eq!(config.listen.to_string(), "[::1]:8200");
    assert_eq!(config.data_dir, PathBuf::from("/synthetic/data"));
    assert_eq!(config.audit_file, PathBuf::from("/synthetic/audit"));
    assert_eq!(
        config.tls_client_ca_file,
        Some(PathBuf::from("/synthetic/client-ca"))
    );
    assert!(!config.tls_client_auth_optional);
    assert!(!config.disable_unauthed_rekey_endpoints);
    let optional = source.replace(
        "tls_require_and_verify_client_cert = true",
        "tls_require_and_verify_client_cert = false",
    );
    assert!(parse_server(optional.as_bytes())?.tls_client_auth_optional);
    let quoted = source
        .replace("tls_disable = false", "tls_disable = \"false\"")
        .replace(
            "tls_require_and_verify_client_cert = true",
            "tls_require_and_verify_client_cert = \"true\"",
        );
    assert!(!parse_server(quoted.as_bytes())?.tls_client_auth_optional);
    rejected(&source.replace("tls_disable = false", "tls_disable = \"FALSE\""))?;
    for storage in [
        "storage \"pebbledb\" { path = \"/synthetic/pebble\" }",
        "storage \"pebbledb\" { path = \":memory:\" }",
        "storage \"raft\" { path = \"/synthetic/raft\" }",
    ] {
        rejected(&format!("{source}\n{storage}"))?;
    }
    let inherited = source.replace("tls_require_and_verify_client_cert = true", "");
    assert!(!parse_server(inherited.as_bytes())?.tls_client_auth_optional);
    let default_address = source.replace("address = \"[::1]:8200\"", "");
    assert_eq!(
        parse_server(default_address.as_bytes())?.listen.to_string(),
        "127.0.0.1:8200"
    );
    rejected(&source.replace("tls_disable = false", "tls_disable = true"))?;
    rejected(&source.replace("tls_client_ca_file = \"/synthetic/client-ca\"", ""))?;
    rejected(&source.replace(
        "tls_require_and_verify_client_cert = true",
        "tls_require_and_verify_client_cert = true\n tls_client_auth_optional = true",
    ))?;
    rejected(&source.replace(
        "tls_require_and_verify_client_cert = true",
        "tls_require_and_verify_client_cert = true\n tls_disable_client_certs = true",
    ))?;
    Ok(())
}

#[test]
fn hcl_duplicate_aliases_unknown_fields_and_unsupported_features_are_rejected() -> Result<(), String>
{
    for suffix in [
        "listen = \"127.0.0.1:9999\"",
        "max_connections = \"16\"",
        "ui = \"false\"",
        "future_flag = true",
        "telemetry { statsite_address = \"127.0.0.1:8125\" }",
        "seal \"transit\" { address = \"https://kms.invalid\" }",
        "listener \"tcp\" { address = \"127.0.0.1:8200\" }",
        "storage \"pebbledb\" { path = \"/other-data\" }",
        "timeout_seconds = 1 + 2",
        "ui = env(\"UNTRUSTED_CONFIG\")",
        "audit_file = \"%{if UNTRUSTED_CONFIG}\"",
    ] {
        rejected(&format!("{NATIVE}\n{suffix}"))?;
    }
    rejected(&format!(
        "{NATIVE}\naudit_file = \"{}{{UNTRUSTED_CONFIG}}\"",
        '$'
    ))?;
    for source in [
        r#"listener "tcp" {
 tls_cert_file = "/c"
 tls_key_file = "/k"
 }
           listener "tcp" { address = "127.0.0.1:8201" }
           data_dir = "/d"
 audit_file = "/a""#,
        r#"listener "tcp" {
 tls_cert_file = "/c"
 tls_key_file = "/k"
 bogus = false
 }
           data_dir = "/d"
           audit_file = "/a""#,
        r#"listener "unix" { address = "/synthetic/socket" }
           data_dir = "/d"
           audit_file = "/a""#,
        r#"storage "raft" {
 path = "/d"
 node_id = "raft_node_1"
 }
           listen = "127.0.0.1:8200"
 audit_file = "/a"
           tls_cert_file = "/c"
 tls_key_file = "/k""#,
        r#"listen = "127.0.0.1:8200"
 data_dir = "/d"
           tls_cert_file = "/c"
           tls_key_file = "/k""#,
    ] {
        rejected(source)?;
    }
    Ok(())
}

#[test]
fn hcl_static_bounds_comments_escapes_and_credential_errors_are_finite() -> Result<(), String> {
    let source = format!(
        r#"{NATIVE}
        ui_assets_dir = "/assets/\u4e2d\U0001f512/%%{{literal}}"
        // terminal comment
        "#
    );
    assert_eq!(
        parse_server(source.as_bytes())?.ui_assets_dir,
        Some(PathBuf::from("/assets/中🔒/%{literal}"))
    );
    let dollar = '$';
    let escaped = format!("{NATIVE}\nui_assets_dir = \"/assets/{dollar}{dollar}{{literal}}\"");
    assert_eq!(
        parse_server(escaped.as_bytes())?.ui_assets_dir,
        Some(PathBuf::from(format!("/assets/{dollar}{{literal}}")))
    );
    for suffix in [
        "/* incomplete",
        "ui = true }",
        "ui_assets_dir = \"unfinished",
        "ui_assets_dir = \"\\q\"",
        "ui_assets_dir = \"\\ud800\"",
        "ui_assets_dir = \"\\U00110000\"",
        "ui_assets_dir = \"%{if secret}\"",
        "tls_key_exchange_preferences = [\"X25519\" \"CurveP256\"]",
        "ui = false max_connections = 16",
        "timeout_seconds = 1rate_limit_burst = 2",
        "timeout_seconds = 18446744073709551616",
        "timeout_seconds = 1e9999",
        "postgres_durable = { password = \"PRIVATE_SENTINEL_NEVER_LOGGED\" password = \"other\" }",
        "postgres_durable = { unknown = \"PRIVATE_SENTINEL_NEVER_LOGGED\" }",
    ] {
        rejected(&format!("{NATIVE}\n{suffix}"))?;
    }
    let deep = format!(
        "{NATIVE}\nplugin_auth = {}null{}",
        "[".repeat(40),
        "]".repeat(40)
    );
    rejected(&deep)?;
    let many = format!(
        "{NATIVE}\ntls_key_exchange_preferences = [{}]",
        "\"X25519\",".repeat(MAX_NODES + 1)
    );
    assert!(many.len() < MAX_BYTES);
    rejected(&many)?;
    assert_eq!(
        parse_server(&vec![b' '; MAX_BYTES + 1])
            .err()
            .ok_or("oversize config accepted")?,
        "configuration exceeds limit"
    );
    assert_eq!(
        parse_server(&[0xff])
            .err()
            .ok_or("non-UTF8 config accepted")?,
        SERVER_SCHEMA
    );
    Ok(())
}

#[test]
fn hcl_ha_native_peer_enrollment_keeps_typed_fields_and_rejects_drift() -> Result<(), String> {
    let source = r#"
        node_id = 1
        cluster_id = "fixed-cluster"
        raft_dir = "/synthetic/raft"
        listen = "127.0.0.1:8201"
        ca_file = "/synthetic/cluster-ca"
        cert_file = "/synthetic/cluster-cert"
        key_file = "/synthetic/cluster-key"
        replication_key_file = "/synthetic/replication-key"
        bootstrap = true
        initial_voters = [1,]
        peers = {
            "1" = {
                node_name = "one"
                address = "127.0.0.1:8201"
                api_address = "https://127.0.0.1:8200"
                cluster_address = "https://127.0.0.1:8202"
                server_name = "one.test"
                certificate_sha256 = "fixed-deployment-certificate-pin"
            }
        }
    "#;
    let config = parse_ha(source.as_bytes())?;
    assert_eq!(config.node_id, 1);
    assert_eq!(config.cluster_id, "fixed-cluster");
    assert!(config.bootstrap);
    assert_eq!(
        config.initial_voters,
        Some(std::collections::BTreeSet::from([1]))
    );
    let peer = config.peers.get(&1).ok_or("pinned peer missing")?;
    assert_eq!(peer.node_name, "one");
    assert_eq!(peer.server_name, "one.test");
    assert_eq!(peer.certificate_sha256, "fixed-deployment-certificate-pin");
    assert_eq!(peer.api_address.as_deref(), Some("https://127.0.0.1:8200"));
    assert_eq!(
        peer.cluster_address.as_deref(),
        Some("https://127.0.0.1:8202")
    );
    assert!(!config.allow_legacy_peer_v1);
    for invalid in [
        format!("{source}\nnode_id = 2"),
        format!("{source}\nretry_join = []"),
        source.replace("bootstrap = true", "bootstrap = \"true\""),
        source.replace("node_id = 1", "node_id = \"one\""),
    ] {
        assert_eq!(
            parse_ha(invalid.as_bytes())
                .err()
                .ok_or("invalid HA accepted")?,
            HA_SCHEMA
        );
    }
    Ok(())
}

#[test]
fn hcl_json_decoder_and_actual_serve_admission_remain_strict() -> Result<(), String> {
    let json = br#"{"listen":"127.0.0.1:8200","data_dir":"/synthetic/data",
        "audit_file":"/synthetic/audit","tls_cert_file":"/synthetic/cert","tls_key_file":"/synthetic/key"}"#;
    let old: Config = serde_json::from_slice(json).map_err(|error| error.to_string())?;
    let loaded = parse_server(json)?;
    assert_eq!(loaded.listen, old.listen);
    assert_eq!(loaded.data_dir, old.data_dir);
    assert_eq!(loaded.audit_file, old.audit_file);
    assert_eq!(loaded.timeout_seconds, old.timeout_seconds);
    assert_eq!(loaded.max_connections, old.max_connections);
    assert_eq!(
        loaded.disable_unauthed_rekey_endpoints,
        old.disable_unauthed_rekey_endpoints
    );
    for suffix in [
        r#","unknown":true}"#,
        r#","ui":"false"}"#,
        r#","listen":"127.0.0.1:9999"}"#,
    ] {
        let mut invalid = json[..json.len() - 1].to_vec();
        invalid.extend_from_slice(suffix.as_bytes());
        assert!(serde_json::from_slice::<Config>(&invalid).is_err());
        assert_eq!(
            parse_server(&invalid)
                .err()
                .ok_or("invalid JSON accepted")?,
            SERVER_SCHEMA
        );
    }
    // These real production serve() checks reject before filesystem/listener I/O.
    let zero = parse_server(format!("{NATIVE}\nmax_connections = 0").as_bytes())?;
    assert_eq!(
        crate::http::serve(zero),
        Err("invalid bounded connection policy".into())
    );
    let optional = parse_server(format!("{NATIVE}\ntls_client_auth_optional = true").as_bytes())?;
    assert_eq!(
        crate::http::serve(optional),
        Err("optional TLS client authentication requires a client CA bundle".into())
    );
    let relative = parse_server(
        NATIVE
            .replace("/synthetic/cert", "relative-cert")
            .as_bytes(),
    )?;
    assert_eq!(
        crate::http::serve(relative),
        Err("TLS paths must be absolute".into())
    );
    Ok(())
}

fn storage_fixture(stanza: &str) -> String {
    format!(
        r#"
audit_file = "/synthetic/audit"
listener "tcp" {{
 address = "127.0.0.1:8200"
 tls_cert_file = "/synthetic/cert"
 tls_key_file = "/synthetic/key"
}}
{stanza}
"#
    )
}

fn storage_ha_fixture() -> Result<HaProcessConfig, String> {
    parse_ha(br#"{
      "node_id":1,"cluster_id":"fixed-cluster","raft_dir":"/synthetic/storage/raft",
      "listen":"127.0.0.1:8202","ca_file":"/synthetic/ca",
      "cert_file":"/synthetic/cert","key_file":"/synthetic/key",
      "replication_key_file":"/synthetic/replication",
      "bootstrap":true,"initial_voters":[1,2,3],
      "peers":{
        "1":{"node_name":"one","address":"127.0.0.1:8202","server_name":"one.test",
             "certificate_sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
             "api_address":"https://one.test:8200","cluster_address":"https://one.test:8202"},
        "2":{"node_name":"two","address":"127.0.0.1:8302","server_name":"two.test",
             "certificate_sha256":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"},
        "3":{"node_name":"three","address":"127.0.0.1:8402","server_name":"three.test",
             "certificate_sha256":"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"}
      }}"#)
}

#[test]
fn hcl_storage_durable_selection_rejects_aliases_ha_and_unimplemented_modes() -> Result<(), String>
{
    let source = storage_fixture(r#"storage "pebbledb" { path = "/synthetic/storage" }"#);
    let mut config = parse_server(source.as_bytes())?;
    assert_eq!(config.data_dir, PathBuf::from("/synthetic/storage"));
    assert!(
        matches!(config.storage.as_ref(), Some(StorageConfig::PebbleDb { path }) if path == &config.data_dir)
    );
    validate_storage(&config, None)?;
    assert_eq!(
        validate_storage(&config, Some(&storage_ha_fixture()?)),
        Err("local durable storage conflicts with selected deployment consumer".into())
    );
    config.data_dir = PathBuf::from("/synthetic/other");
    assert_eq!(
        crate::http::serve(config),
        Err("local durable storage conflicts with selected deployment consumer".into())
    );
    for unsupported in [
        r#"storage "pebbledb" { path = ":memory:" }"#,
        "storage \"pebbledb\" {\npath = \"/synthetic/storage\"\nread_only = true\n}",
        "storage \"pebbledb\" {\npath = \"/synthetic/storage\"\nunknown = true\n}",
        r#"storage "file" { path = "/synthetic/storage" }"#,
        r#"storage "pebbledb" { path = "/synthetic/../other" }"#,
    ] {
        rejected(&storage_fixture(unsupported))?;
    }
    rejected(&format!("{source}\ndata_dir = \"/synthetic/shadow\""))?;
    assert!(parse_server(NATIVE.as_bytes())?.storage.is_none());
    Ok(())
}

#[test]
fn hcl_storage_raft_path_identity_and_addresses_bind_before_process_start() -> Result<(), String> {
    let source = storage_fixture(
        r#"
storage "raft" {
 path = "/synthetic/storage"
 node_id = "one"
}
cluster_addr = "https://one.test:8202"
api_addr = "https://one.test:8200"
"#,
    );
    let config = parse_server(source.as_bytes())?;
    let mut ha = storage_ha_fixture()?;
    assert_eq!(config.data_dir, PathBuf::from("/synthetic/storage/state"));
    assert_eq!(ha.raft_dir, PathBuf::from("/synthetic/storage/raft"));
    validate_storage(&config, Some(&ha))?;
    assert_eq!(
        ha.initial_voters,
        Some(std::collections::BTreeSet::from([1, 2, 3]))
    );
    assert_eq!(
        validate_storage(&config, None),
        Err("raft storage requires explicit enrolled HA configuration".into())
    );
    ha.raft_dir = PathBuf::from("/synthetic/other/raft");
    assert_eq!(
        validate_storage(&config, Some(&ha)),
        Err("raft storage path disagrees with enrolled HA directory".into())
    );
    ha.raft_dir = PathBuf::from("/synthetic/storage/raft");
    ha.peers.get_mut(&1).ok_or("local peer missing")?.node_name = "different".into();
    assert_eq!(
        validate_storage(&config, Some(&ha)),
        Err("raft storage node_id disagrees with enrolled local peer".into())
    );
    ha.peers.get_mut(&1).ok_or("local peer missing")?.node_name = "one".into();
    ha.peers
        .get_mut(&1)
        .ok_or("local peer missing")?
        .cluster_address = Some("https://other.test:8202".into());
    assert_eq!(
        validate_storage(&config, Some(&ha)),
        Err("raft cluster address disagrees with enrolled local peer".into())
    );
    ha.peers
        .get_mut(&1)
        .ok_or("local peer missing")?
        .cluster_address = Some("https://one.test:8202".into());
    ha.peers
        .get_mut(&1)
        .ok_or("local peer missing")?
        .api_address = Some("https://other.test:8200".into());
    assert_eq!(
        validate_storage(&config, Some(&ha)),
        Err("raft API address disagrees with enrolled local peer".into())
    );
    assert_eq!(
        crate::http::serve(parse_server(source.as_bytes())?),
        Err("raft storage requires explicit enrolled HA configuration".into())
    );
    rejected(&storage_fixture(
        r#"storage "raft" { path = "/synthetic/storage" }"#,
    ))?;
    rejected(&source.replace("https://one.test:8202", "http://one.test:8202"))?;
    rejected(&source.replace("node_id = \"one\"", "node_id = \"one\"\nretry_join = []"))?;
    Ok(())
}

#[test]
fn hcl_storage_postgresql_credentials_bind_enrolled_tls_consumer_without_network()
-> Result<(), String> {
    let source = format!(
        "{}\n{}",
        storage_fixture(
            r#"
storage "postgresql" {
 connection_url = "postgres://synthetic-role:p%40ss@db.test/openbao?sslmode=verify-full"
 ha_enabled = "false"
 skip_create_table = false
 table = "openbao_kv_store"
}
data_dir = "/synthetic/local-metadata"
"#
        ),
        r#"
outbound_endpoints = [{
 origin = "postgresql://db.test:5432"
 address = "127.0.0.1:5432"
 server_name = "db.test"
 ca_pem = "PUBLIC-CA-FIXTURE-ONLY"
}]
"#
    );
    let config = parse_server(source.as_bytes())?;
    assert!(matches!(
        config.storage.as_ref(),
        Some(StorageConfig::PostgreSql {})
    ));
    let postgres = config
        .postgres_durable
        .as_ref()
        .ok_or("PostgreSQL consumer missing")?;
    assert_eq!(postgres.connection_url, "postgresql://db.test:5432/openbao");
    assert_eq!(postgres.username, "synthetic-role");
    assert_eq!(postgres.password, "p@ss");
    assert_eq!(postgres.scope, "openbao270");
    assert_eq!(postgres.endpoint.origin, "postgresql://db.test:5432");
    validate_storage(&config, None)?;
    assert_eq!(
        validate_storage(&config, Some(&storage_ha_fixture()?)),
        Err("PostgreSQL storage requires the enrolled PostgreSQL durable consumer".into())
    );
    for (before, after) in [
        ("sslmode=verify-full", "sslmode=disable"),
        ("ha_enabled = \"false\"", "ha_enabled = true"),
        ("skip_create_table = false", "skip_create_table = true"),
        ("openbao_kv_store", "custom_table"),
        ("p%40ss", "p%0ass"),
        ("p%40ss", "p%GGss"),
        ("db.test/openbao", "other.test/openbao"),
        (
            "table = \"openbao_kv_store\"",
            "unknown_storage_option = true",
        ),
    ] {
        rejected(&source.replace(before, after))?;
    }
    rejected(&format!("{source}\npostgres_durable = null"))?;
    let config = parse_server(source.as_bytes())?;
    let mut config = config;
    config.postgres_durable = None;
    assert_eq!(
        crate::http::serve(config),
        Err("PostgreSQL storage requires the enrolled PostgreSQL durable consumer".into())
    );
    Ok(())
}
