from pathlib import Path
import importlib.util
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "qa/openbao-acceptance"))
spec = importlib.util.spec_from_file_location("migrate_ssh_roles", ROOT / "qa/openbao-acceptance/migrate_ssh_roles.py")
m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)


class SshRoleMigrationTests(unittest.TestCase):
    def test_normalize_exact_supported_otp_profile(self):
        source = {"key_type":"otp","default_user":"deploy","allowed_users":"deploy,backup",
                  "cidr_list":"127.0.0.0/8","exclude_cidr_list":"127.1.0.0/16","port":22,
                  "default_user_template":False,"allowed_users_template":False,"ttl":"","max_ttl":""}
        self.assertEqual(m.normalize_role(source), {k: source[k] for k in m.SUPPORTED_FIELDS})

    def test_ca_template_and_active_extra_semantics_reject(self):
        with self.assertRaises(Exception):
            m.normalize_role({"key_type":"ca","default_user":"deploy","cidr_list":"127.0.0.0/8"})
        for field, value in (("default_user_template", True), ("ttl", "1h"), ("issuer_ref", "default")):
            role={"key_type":"otp","default_user":"deploy","cidr_list":"127.0.0.0/8", field:value}
            with self.assertRaises(Exception, msg=field): m.normalize_role(role)

    def test_checkpoint_binding_cannot_be_reused_for_another_cluster(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d); root.chmod(0o700); cp=root/"checkpoint.json"
            m.Checkpoint(cp, {"source":"a","target":"b"})
            with self.assertRaises(Exception): m.Checkpoint(cp, {"source":"a","target":"c"})

    def test_record_digest_and_name_are_bound(self):
        role={"key_type":"otp","default_user":"deploy","allowed_users":"","cidr_list":"127.0.0.0/8","exclude_cidr_list":"","port":22}
        record={"name":"role-a","role":role,"source_digest":m.digest(role)}
        m.validate_record(record)
        record["role"]["port"]=2222
        with self.assertRaises(Exception): m.validate_record(record)


if __name__ == "__main__": unittest.main()
