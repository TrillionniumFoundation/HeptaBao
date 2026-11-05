"""The four-host Autopilot profile stays fixed, fail-closed and scoped."""
import ast
import importlib.util
import json
import sys
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[3]
SOURCE = ROOT / "qa/openbao-acceptance/ha_multihost_autopilot_live.py"
BASE_SOURCE = ROOT / "qa/openbao-acceptance/ha_multihost_live.py"
DOC = ROOT / "docs/operations/HEPTABAO_MULTIHOST_HA_QUALIFICATION.md"
sys.path.insert(0, str(SOURCE.parent))
SPEC = importlib.util.spec_from_file_location("ha_multihost_autopilot_live", SOURCE)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)


class MultiHostAutopilotContractTests(unittest.TestCase):
    def test_fixed_denominator_covers_cleanup_and_explicit_readmission(self):
        required = MODULE.REQUIRED_CHECKS
        self.assertEqual(len(required), 55)
        self.assertEqual(len(required), len(set(required)))
        for name in (
            "four_distinct_remote_hosts",
            "initial_four_voters_committed",
            "autopilot_cleanup_policy_committed",
            "dead_voter_unhealthy_not_fabricated",
            "dead_voter_retained_during_grace",
            "dead_voter_removed_after_real_contact_threshold",
            "safe_three_voters_preserved",
            "removed_node_never_self_rejoined",
            "removed_node_not_automatic_member",
            "explicit_rejoin_acknowledged_as_learner",
            "rejoined_node_promoted_after_stabilization",
            "cannot_remove_below_minimum",
            "autopilot_policy_persists_across_restart",
            "source_and_binary_unchanged",
            "report_excludes_runtime_secrets",
            "autopilot_multihost.complete",
        ):
            self.assertIn(name, required)

    def test_membership_helpers_reject_learner_as_voter(self):
        configuration = {"servers": [
            {"node_id": "1", "voter": True},
            {"node_id": "2", "voter": True},
            {"node_id": "3", "voter": True},
            {"node_id": "4", "voter": False},
        ]}
        self.assertEqual(MODULE.members(configuration), {1, 2, 3, 4})
        self.assertEqual(MODULE.voters(configuration), {1, 2, 3})

    def test_every_membership_mutation_is_single_attempt(self):
        tree = ast.parse(SOURCE.read_text())
        change = next(node for node in tree.body
                      if isinstance(node, ast.FunctionDef) and node.name == "change_once")
        self.assertFalse(any(isinstance(node, (ast.For, ast.While)) for node in ast.walk(change)))
        calls = [node for node in ast.walk(change)
                 if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
                 and node.func.id == "api"]
        self.assertEqual(len(calls), 1)
        source = SOURCE.read_text()
        self.assertIn('"mutating_requests_retried": False', source)
        self.assertLess(
            source.index('"initial_four_voters_committed"'),
            source.index('write_once(context, leader, root_token, baseline_path, baseline_value)'),
        )
        self.assertIn('value.get("committed") is True', source)
        self.assertIn('value.get("joint") is False', source)
        self.assertNotIn("mutation_retry", source)

    def test_four_host_and_real_grace_are_structural(self):
        source = SOURCE.read_text()
        for marker in (
            'len(args.node) != 4',
            '"initial_voters": [1, 2, 3, 4]',
            '"dead_server_last_contact_threshold": "60s"',
            'seconds=82',
            '"min_quorum": 3',
            'victim = nodes[3] if nodes[3] != leader else nodes[2]',
            'len({(node.alias, node.root) for node in nodes}) != 4',
            'wait_member(',
            'present=False',
            'present=True, voter=False',
            'present=True, voter=True',
        ):
            self.assertIn(marker, source)
        self.assertNotIn("time.sleep(60)", source)

    def test_process_and_host_boundaries_reuse_hardened_owner(self):
        source = SOURCE.read_text()
        for marker in (
            "parse_node(", "parse_binary_source(", "install_candidate(",
            "remote_start(", "remote_stop(", "report_is_secret_safe(",
            "secret_safe_report(", "install_signal_handlers()",
            "BASE_RUNNER_PATH", '"base_runner_sha256": initial_base_runner_sha256',
            "sha256_file(BASE_RUNNER_PATH) == initial_base_runner_sha256",
            'name not in REMOTE_EVIDENCE_FILES',
        ):
            self.assertIn(marker, source)
        for forbidden in ("sudo ", "iptables ", "nft ", "ufw ", "systemctl "):
            self.assertNotIn(forbidden, source)
        self.assertIn("printf '%s\\n' \"$name\"", source)
        self.assertNotIn("printf %sn", source)
        for marker in (
            'stage = f"remote_node_{node.node_id}_preflight"',
            'stage = f"remote_node_{node.node_id}_candidate_install"',
            'stage = f"remote_node_{node.node_id}_configuration_upload"',
            'stage = f"remote_node_{node.node_id}_binary_readback"',
        ):
            self.assertIn(marker, source)
        self.assertTrue(BASE_SOURCE.is_file())

    def test_claims_and_uncovered_dimensions_stay_false(self):
        source = SOURCE.read_text()
        for marker in (
            '"qualification": False',
            '"independent_qualification": False',
            '"full_openbao_compatibility": False',
            '"production_authority": False',
            '"mixed_version_autopilot"',
            '"WAN_faults"',
            '"physical_power_loss"',
            '"disk_full"',
            '"clock_discontinuity"',
            '"long_horizon_histories"',
        ):
            self.assertIn(marker, source)

    def test_surface_mapping_is_autopilot_only(self):
        work = json.loads((ROOT / "planning/HEPTABAO_SURFACE_WORK_V1.json").read_text())
        profile = work["profile_definitions"]["ha_multihost_autopilot"]
        self.assertEqual(
            profile["script"],
            "qa/openbao-acceptance/ha_multihost_autopilot_live.py",
        )
        self.assertEqual(
            profile["scope"],
            "repository_controlled_bounded_profile_not_whole_surface",
        )
        mapped = {row["surface_id"] for row in work["surfaces"]
                  if "ha_multihost_autopilot" in row["available_scoped_profiles"]}
        self.assertEqual(mapped, {"HB-SURFACE-CLUSTER-AUTOPILOT"})
        self.assertTrue(all(row["whole_surface_admitted"] is False
                            for row in work["surfaces"]))

    def test_private_lab_profile_is_manual_and_anonymized(self):
        for workflow in (ROOT / ".github/workflows").glob("*.yml"):
            with self.subTest(workflow=workflow.name):
                self.assertNotIn("ha_multihost_autopilot_live.py", workflow.read_text())
        docs = DOC.read_text()
        self.assertIn("Four-host Autopilot cleanup", docs)
        self.assertIn("--allow-private-tailnet", docs)
        self.assertIn("60-second", docs)
        for private_name in (
            "x230-ts", "rog-ts", "pocket4-ts", "claw-j3160-ts",
            "100.97.179.109", "100.118.166.22", "100.119.126.104",
            "100.66.117.33",
        ):
            self.assertNotIn(private_name, docs)


if __name__ == "__main__":
    unittest.main()
