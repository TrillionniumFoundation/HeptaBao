from pathlib import Path
import json

ROOT = Path(__file__).resolve().parents[1]

inventory = {
    "schema": "heptabao.system-backend-endpoints.v1",
    "surface_id": "HB-SURFACE-SYSTEM-BACKEND",
    "routes": [
        {"path": "sys/health", "methods": ["GET", "HEAD"], "fields": [], "auth": "public", "sealed": "observable"},
        {"path": "sys/init", "methods": ["GET", "POST", "PUT"], "fields": ["secret_shares", "secret_threshold", "recovery_nonce"], "auth": "root_namespace_bootstrap", "sealed": "allowed"},
        {"path": "sys/unseal", "methods": ["POST", "PUT"], "fields": ["key"], "auth": "share_threshold", "sealed": "required"},
        {"path": "sys/seal-status", "methods": ["GET"], "fields": [], "auth": "public", "sealed": "observable"},
        {"path": "sys/seal", "methods": ["POST", "PUT"], "fields": [], "auth": "root", "sealed": "active_only"},
        {"path": "sys/rekey/init", "methods": ["GET", "POST", "PUT", "DELETE"], "fields": ["secret_shares", "secret_threshold", "require_verification"], "auth": "root", "sealed": "active_only"},
        {"path": "sys/rekey/update", "methods": ["POST", "PUT"], "fields": ["nonce", "key"], "auth": "root", "sealed": "active_only"},
    ],
    "error_precedence": [
        "invalid initialization namespace/shape before state creation",
        "sealed denial before authenticated active-only dispatch",
        "root authorization before seal/rekey mutation",
        "rekey nonce/share validation before seal generation publication",
    ],
    "behavior_anchors": [
        "initialization_recovery_survives_response_loss_and_requires_root_ack",
        "shamir_threshold_unseal_and_online_rekey_preserve_the_barrier_key",
        "verified_rekey_survives_response_loss_restart_and_cancel",
        "system_backend_health_seal_and_error_precedence_are_executable",
    ],
}
(ROOT / "planning/HEPTABAO_SYSTEM_BACKEND_ENDPOINT_INVENTORY_V1.json").write_text(
    json.dumps(inventory, indent=2) + "\n"
)

tests_path = ROOT / "crates/heptabao-server/src/service_tests.rs"
text = tests_path.read_text()
name = "system_backend_health_seal_and_error_precedence_are_executable"
if f"fn {name}" in text:
    raise SystemExit("system backend behavior test already present")
text += r'''

#[test]
fn system_backend_health_seal_and_error_precedence_are_executable()
-> Result<(), Box<dyn std::error::Error>> {
    let root = Root::new();
    let mut service = root.service()?;

    let health = call(&mut service, "GET", "sys/health", "", json!({}));
    assert_eq!(health.status, 501);
    assert_eq!(health.body["initialized"], false);
    assert_eq!(health.body["sealed"], true);
    assert_eq!(
        call(&mut service, "GET", "sys/init", "", json!({})).body,
        json!({"initialized":false})
    );
    assert_eq!(
        call(
            &mut service,
            "POST",
            "sys/init",
            "",
            json!({"secret_shares":1,"secret_threshold":1,"unknown":true}),
        )
        .status,
        400
    );
    assert!(!service.initialized());

    let initialized = call(
        &mut service,
        "POST",
        "sys/init",
        "",
        json!({"secret_shares":2,"secret_threshold":2}),
    );
    assert_eq!(initialized.status, 200);
    let shares = initialized.body["keys_base64"]
        .as_array()
        .ok_or("missing initialization shares")?
        .iter()
        .map(|value| value.as_str().ok_or("invalid share").map(str::to_owned))
        .collect::<Result<Vec<_>, _>>()?;
    let root_token = initialized.body["root_token"]
        .as_str()
        .ok_or("missing root token")?
        .to_owned();
    assert_eq!(call(&mut service, "GET", "sys/health", "", json!({})).status, 503);
    assert_eq!(
        call(&mut service, "GET", "secret/data/blocked", &root_token, json!({})).status,
        503,
        "sealed state must win before active authenticated dispatch"
    );
    for share in &shares {
        assert_eq!(
            call(
                &mut service,
                "POST",
                "sys/unseal",
                "",
                json!({"key":share}),
            )
            .status,
            200
        );
    }
    assert_eq!(call(&mut service, "GET", "sys/health", "", json!({})).status, 200);
    assert_eq!(
        call(&mut service, "POST", "sys/seal", "", json!({})).status,
        403,
        "root authorization must precede seal mutation"
    );
    assert_eq!(
        call(
            &mut service,
            "POST",
            "sys/rekey/update",
            &root_token,
            json!({"nonce":"missing","key":"bad"}),
        )
        .status,
        400
    );
    assert_eq!(service.seal.as_ref().ok_or("missing seal")?.generation, 1);
    assert_eq!(
        call(&mut service, "POST", "sys/seal", &root_token, json!({})).status,
        204
    );
    assert_eq!(call(&mut service, "HEAD", "sys/health", "", json!({})).status, 503);
    Ok(())
}
'''
tests_path.write_text(text)

inventory_test = ROOT / "tests/repository/test_system_backend_inventory.py"
inventory_test.write_text(r'''import json
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]

class SystemBackendInventoryTests(unittest.TestCase):
    def setUp(self):
        self.inventory = json.loads((ROOT / 'planning/HEPTABAO_SYSTEM_BACKEND_ENDPOINT_INVENTORY_V1.json').read_text())
        self.service = (ROOT / 'crates/heptabao-server/src/service.rs').read_text()
        self.tests = (ROOT / 'crates/heptabao-server/src/service_tests.rs').read_text()

    def test_inventory_is_closed_and_source_bound(self):
        self.assertEqual(self.inventory['schema'], 'heptabao.system-backend-endpoints.v1')
        expected = {
            'sys/health','sys/init','sys/unseal','sys/seal-status','sys/seal',
            'sys/rekey/init','sys/rekey/update'
        }
        routes = self.inventory['routes']
        self.assertEqual({row['path'] for row in routes}, expected)
        self.assertEqual(len(routes), len(expected))
        for row in routes:
            self.assertIn(f'"{row["path"]}"', self.service)
            self.assertEqual(row['methods'], list(dict.fromkeys(row['methods'])))
            self.assertEqual(row['fields'], list(dict.fromkeys(row['fields'])))

    def test_behavior_anchors_are_real(self):
        anchors = self.inventory['behavior_anchors']
        self.assertGreaterEqual(len(anchors), 4)
        self.assertEqual(len(anchors), len(set(anchors)))
        for name in anchors:
            self.assertIn(f'fn {name}', self.tests)

    def test_required_field_and_precedence_markers_exist(self):
        for marker in [
            'initialization requires the root namespace',
            'server is sealed',
            'permission denied',
            'rekey nonce is required',
            'unseal share is required',
            'unsupported rekey update fields',
        ]:
            self.assertIn(marker, self.service)

if __name__ == '__main__':
    unittest.main()
''')

evidence = {
    "source_paths": [
        "crates/heptabao-server/src/service.rs",
        "planning/HEPTABAO_SYSTEM_BACKEND_ENDPOINT_INVENTORY_V1.json",
    ],
    "test_anchors": [
        {"path": "crates/heptabao-server/src/service_tests.rs", "name": "initialization_recovery_survives_response_loss_and_requires_root_ack"},
        {"path": "crates/heptabao-server/src/service_tests.rs", "name": "shamir_threshold_unseal_and_online_rekey_preserve_the_barrier_key"},
        {"path": "crates/heptabao-server/src/service_tests.rs", "name": "verified_rekey_survives_response_loss_restart_and_cancel"},
        {"path": "crates/heptabao-server/src/service_tests.rs", "name": name},
    ],
    "local_dimensions": [
        "protocol_framing",
        "authorization_before_effect",
        "effect_readback",
        "crash_reopen",
    ],
}

surface_path = ROOT / "planning/HEPTABAO_SURFACE_WORK_V1.json"
surface_doc = json.loads(surface_path.read_text())
surface = next(row for row in surface_doc["surfaces"] if row["surface_id"] == "HB-SURFACE-SYSTEM-BACKEND")
if surface["implementation_status"] != "runtime_partial":
    raise SystemExit(f"unexpected system backend surface status: {surface['implementation_status']}")
surface["implementation_status"] = "runtime_complete"
surface["implementation_evidence"] = evidence
surface_path.write_text(json.dumps(surface_doc, indent=2) + "\n")

execution_path = ROOT / "planning/HEPTABAO_REPLACEMENT_EXECUTION_V2.json"
execution_doc = json.loads(execution_path.read_text())
execution = next(row for row in execution_doc["surfaces"] if row["surface_id"] == "HB-SURFACE-SYSTEM-BACKEND")
if execution["implementation"] != "PARTIAL_RUNTIME":
    raise SystemExit(f"unexpected system backend execution status: {execution['implementation']}")
execution["implementation"] = "RUNTIME_COMPLETE_LOCAL"
execution["implementation_evidence"] = evidence
execution["remaining_scope"] = (
    "Local system endpoint/method/field inventory, sealed/error precedence, initialization reply-loss recovery, "
    "threshold unseal and verified rekey/reopen behavior are executable; format migration, real multi-host "
    "upgrade/fault, full OpenBao 2.6.2 differential and independent admission remain later phases."
)
execution_path.write_text(json.dumps(execution_doc, indent=2) + "\n")
