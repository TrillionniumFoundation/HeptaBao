use super::*;
use std::path::PathBuf;

fn file_config() -> Result<Config, String> {
    parse_server(
        br#"{
      "listen":"127.0.0.1:8200", "data_dir":"/synthetic/native-storage",
      "audit_file":"/synthetic/audit", "tls_cert_file":"/synthetic/cert",
      "tls_key_file":"/synthetic/key",
      "storage":{"native_v6_file":{"path":"/synthetic/native-storage"}}
    }"#,
    )
}

fn raft_config() -> Result<(Config, HaProcessConfig), String> {
    let config = parse_server(
        br#"{
      "listen":"127.0.0.1:8200", "data_dir":"/synthetic/native-storage/state",
      "audit_file":"/synthetic/audit", "tls_cert_file":"/synthetic/cert",
      "tls_key_file":"/synthetic/key",
      "storage":{"native_v6_raft":{"path":"/synthetic/native-storage", "node_id":"one",
        "cluster_addr":"https://one.test:8202", "api_addr":"https://one.test:8200"}}
    }"#,
    )?;
    let ha = parse_ha(br#"{
      "node_id":1,"cluster_id":"native-config-test","raft_dir":"/synthetic/native-storage/raft",
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
      }}"#)?;
    Ok((config, ha))
}

#[test]
fn native_storage_json_and_hcl_select_the_same_explicit_file_profile() -> Result<(), String> {
    let json = file_config()?;
    let hcl = parse_server(
        br#"
audit_file = "/synthetic/audit"
listener "tcp" {
 address = "127.0.0.1:8200"
 tls_cert_file = "/synthetic/cert"
 tls_key_file = "/synthetic/key"
}
storage "native_v6_file" { path = "/synthetic/native-storage" }
"#,
    )?;
    for config in [&json, &hcl] {
        assert!(
            matches!(config.storage.as_ref(), Some(StorageConfig::NativeV6File { path }) if path == &config.data_dir)
        );
        if cfg!(feature = "native-v6-storage") {
            validate_storage(config, None)?;
        } else {
            assert!(validate_storage(config, None).is_err());
        }
    }
    assert_eq!(json.data_dir, hcl.data_dir);
    Ok(())
}

#[test]
fn native_storage_profile_rejects_key_injection_and_unknown_or_mixed_selectors() {
    for storage in [
        r#"{"native_v6_file":{"path":"/synthetic/native-storage","barrier_key":"forbidden"}}"#,
        r#"{"native_v6_file":{"path":"/synthetic/native-storage","key_provider":"fixture"}}"#,
        r#"{"native_v6_file":{"path":"/synthetic/native-storage"},"pebbledb":{"path":"/synthetic/native-storage"}}"#,
        r#"{"native_v6_file":{"path":"/synthetic/native-storage","namespace":"child"}}"#,
    ] {
        let input = format!(
            r#"{{"listen":"127.0.0.1:8200","data_dir":"/synthetic/native-storage",
          "audit_file":"/synthetic/audit","tls_cert_file":"/synthetic/cert",
          "tls_key_file":"/synthetic/key","storage":{storage}}}"#
        );
        assert!(parse_server(input.as_bytes()).is_err());
    }
}

#[test]
fn native_storage_backend_and_path_mismatches_are_rejected_before_startup() -> Result<(), String> {
    let mut file = file_config()?;
    let (raft, ha) = raft_config()?;
    assert!(validate_storage(&file, Some(&ha)).is_err());
    assert!(validate_storage(&raft, None).is_err());
    file.data_dir = PathBuf::from("/synthetic/another-owner");
    assert!(validate_storage(&file, None).is_err());
    Ok(())
}

#[test]
fn native_raft_storage_binds_the_exact_enrolled_consumer_and_strict_pins() -> Result<(), String> {
    let (config, mut ha) = raft_config()?;
    if !cfg!(feature = "native-v6-ha") {
        assert!(validate_storage(&config, Some(&ha)).is_err());
        return Ok(());
    }
    validate_storage(&config, Some(&ha))?;
    ha.raft_dir = PathBuf::from("/synthetic/other/raft");
    assert!(validate_storage(&config, Some(&ha)).is_err());
    ha.raft_dir = PathBuf::from("/synthetic/native-storage/raft");
    ha.allow_legacy_peer_v1 = true;
    assert!(validate_storage(&config, Some(&ha)).is_err());
    ha.allow_legacy_peer_v1 = false;
    ha.peers
        .get_mut(&1)
        .ok_or("local peer")?
        .certificate_sha256_next =
        Some("dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd".into());
    assert!(validate_storage(&config, Some(&ha)).is_err());
    ha.peers
        .get_mut(&1)
        .ok_or("local peer")?
        .certificate_sha256_next = None;
    ha.peers.get_mut(&1).ok_or("local peer")?.cluster_address =
        Some("https://elsewhere.test:8202".into());
    assert!(validate_storage(&config, Some(&ha)).is_err());
    Ok(())
}
