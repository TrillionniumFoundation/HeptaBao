import base64
import copy
import hashlib
import importlib.util
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[3]
sys.path.insert(0,str(ROOT/'clients/python'))
sys.path.insert(0,str(ROOT/'qa/openbao-acceptance'))
spec=importlib.util.spec_from_file_location('actual_kubernetes',ROOT/'qa/openbao-acceptance/kubernetes_cluster_live.py')
k=importlib.util.module_from_spec(spec);spec.loader.exec_module(k)


def config():
    value=base64.b64encode(b'synthetic-only-'*4).decode()
    return {'current-context':'kind-hb-test',
            'clusters':[{'name':'kind-hb-test','cluster':{'server':'https://127.0.0.1:16443','certificate-authority-data':value}}],
            'users':[{'name':'kind-hb-test','user':{'client-certificate-data':value,'client-key-data':value}}],
            'contexts':[{'name':'kind-hb-test','context':{'cluster':'kind-hb-test','user':'kind-hb-test'}}]}


class ActualKubernetesBoundaryTests(unittest.TestCase):
    def test_only_generated_single_embedded_context_is_admitted(self):
        self.assertEqual(k.kubeconfig_material(config(),'hb-test')[0],'https://127.0.0.1:16443')

    def test_external_or_insecure_origins_are_rejected(self):
        for origin in ['https://example.com:443','http://127.0.0.1:16443','https://user@127.0.0.1:16443',
                       'https://127.0.0.1:16443/path','https://127.0.0.1:16443?redirect=1','https://127.0.0.1:443']:
            value=config();value['clusters'][0]['cluster']['server']=origin
            with self.subTest(origin=origin),self.assertRaises(k.FixtureFailure):k.kubeconfig_material(value,'hb-test')

    def test_exec_and_token_credentials_are_never_loaded(self):
        for field in ['exec','token','tokenFile','auth-provider','client-key']:
            value=config();value['users'][0]['user'][field]='forbidden'
            with self.subTest(field=field),self.assertRaises(k.FixtureFailure):k.kubeconfig_material(value,'hb-test')

    def test_tls_bypass_and_ambient_ca_paths_are_rejected(self):
        for field in ['insecure-skip-tls-verify','certificate-authority','proxy-url']:
            value=config();value['clusters'][0]['cluster'][field]=True
            with self.subTest(field=field),self.assertRaises(k.FixtureFailure):k.kubeconfig_material(value,'hb-test')

    def test_rebinding_or_multiple_contexts_reject(self):
        for category in ['clusters','users','contexts']:
            value=config();value[category].append(copy.deepcopy(value[category][0]))
            with self.subTest(category=category),self.assertRaises(k.FixtureFailure):k.kubeconfig_material(value,'hb-test')
        value=config();value['contexts'][0]['context']['user']='foreign'
        with self.assertRaises(k.FixtureFailure):k.kubeconfig_material(value,'hb-test')

    def test_invalid_or_oversize_material_reject(self):
        for value in ['!bad!',base64.b64encode(b'x'*40000).decode()]:
            doc=config();doc['clusters'][0]['cluster']['certificate-authority-data']=value
            with self.assertRaises(k.FixtureFailure):k.kubeconfig_material(doc,'hb-test')

    def test_remote_docker_routing_rejects_before_execution(self):
        for env in [{'DOCKER_HOST':'tcp://host:2376'},{'DOCKER_CONTEXT':'production'}]:
            with self.assertRaises(k.FixtureFailure):k.local_environment(env)

    def test_ambient_kubeconfig_and_context_are_not_forwarded(self):
        env=k.local_environment({'KUBECONFIG':'/operator/config','DOCKER_CONTEXT':'default','DOCKER_TLS_VERIFY':'1','PATH':'/bin'})
        self.assertNotIn('KUBECONFIG',env)
        self.assertNotIn('DOCKER_TLS_VERIFY',env)
        self.assertNotIn('DOCKER_CONTEXT',env)
        self.assertEqual(env['DOCKER_HOST'],k.DOCKER_SOCKET)

    def test_kind_digest_mismatch_rejects_before_execute(self):
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'kind';path.write_bytes(b'synthetic');path.chmod(0o700)
            with self.assertRaises(k.FixtureFailure):k.validate_binary(path,'0'*64)
            self.assertEqual(k.validate_binary(path,hashlib.sha256(b'synthetic').hexdigest()),path)

    def test_symlink_binary_rejects_even_with_matching_digest(self):
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'actual';path.write_bytes(b'synthetic');path.chmod(0o700)
            link=Path(directory)/'kind';link.symlink_to(path)
            with self.assertRaises(k.FixtureFailure):k.validate_binary(link,hashlib.sha256(b'synthetic').hexdigest())

    def test_missing_kind_is_not_a_model_fallback(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);root.chmod(0o700)
            with self.assertRaises(k.PrerequisiteMissing):
                k.main(['--binary',str(root/'candidate'),'--kind',str(root/'missing'),
                        '--output',str(root/'report.json'),'--allow-disposable-cluster'])
            self.assertFalse((root/'report.json').exists())

    def test_explicit_cluster_permission_is_required_before_allocation(self):
        with patch.object(k,'admit_output') as output:
            with self.assertRaises(SystemExit):k.main(['--binary','/not/run','--kind','/not/run','--output','/not/run'])
            output.assert_not_called()

    def test_fixed_image_and_workflow_gate_are_retained(self):
        self.assertRegex(k.NODE_IMAGE,r'^kindest/node:v1\.35\.0@sha256:[0-9a-f]{64}$')
        text=(ROOT/'.github/workflows/codex-openbao-replacement-ci.yml').read_text()
        self.assertIn(k.KIND_SHA256,text)
        self.assertIn('kubernetes_cluster_live.py',text)
        self.assertIn('--allow-disposable-cluster',text)


class KindArchitecturePinTests(unittest.TestCase):
    def test_architecture_selects_exact_release_asset_digest(self):
        for machine in ('x86_64', 'amd64'):
            self.assertEqual(k.kind_digest('Linux',machine),k.KIND_SHA256)
        for machine in ('aarch64', 'arm64'):
            self.assertEqual(k.kind_digest('Linux',machine),
                             '8e1014e87c34901cc422a1445866835d1e666f2a61301c27e722bdeab5a1f7e4')
        self.assertNotEqual(k.KIND_ARM64_SHA256,k.KIND_SHA256)

    def test_unsupported_platform_does_not_fall_back_to_another_asset(self):
        for system,machine in [('Darwin','arm64'),('Linux','armv7l'),('Linux',''),('Windows','amd64')]:
            with self.subTest(system=system,machine=machine),self.assertRaises(k.PrerequisiteMissing):
                k.kind_digest(system,machine)

    def test_arm64_main_validates_selected_digest_before_daemon_or_allocation(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);root.chmod(0o700)
            binary=root/'kind';binary.write_bytes(b'wrong-architecture-or-modified');binary.chmod(0o700)
            with patch.object(k.platform,'system',return_value='Linux'), \
                    patch.object(k.platform,'machine',return_value='aarch64'), \
                    patch.object(k.shutil,'which',return_value='/usr/bin/docker'), \
                    patch.object(k.subprocess,'run') as daemon, \
                    self.assertRaisesRegex(k.FixtureFailure,'prerequisite_binary_digest_mismatch'):
                k.main(['--binary',str(root/'candidate'),'--kind',str(binary),
                        '--output',str(root/'report.json'),'--allow-disposable-cluster'])
            daemon.assert_not_called()
            self.assertFalse((root/'report.json').exists())


class ActualKubernetesCompletionTests(unittest.TestCase):
    def test_additional_passing_observations_are_allowed(self):
        from online_evidence import complete_checks
        rows=[{'case':name,'passed':True} for name in sorted(k.REQUIRED_CASES)]
        self.assertTrue(complete_checks(rows,required_cases=k.REQUIRED_CASES))
        self.assertTrue(complete_checks(rows+[{'case':'new_independent_observation','passed':True}],required_cases=k.REQUIRED_CASES))

    def test_each_required_phase_missing_duplicate_or_nonboolean_fails(self):
        from online_evidence import complete_checks
        rows=[{'case':name,'passed':True} for name in sorted(k.REQUIRED_CASES)]
        for case in k.REQUIRED_CASES:
            with self.subTest(case=case):
                self.assertFalse(complete_checks([row for row in rows if row['case'] != case],required_cases=k.REQUIRED_CASES))
        self.assertFalse(complete_checks(rows+[rows[0]],required_cases=k.REQUIRED_CASES))
        self.assertFalse(complete_checks([dict(row,passed=1) if i == 0 else row for i,row in enumerate(rows)],required_cases=k.REQUIRED_CASES))
        self.assertFalse(complete_checks([dict(row,passed=False) if i == 0 else row for i,row in enumerate(rows)],required_cases=k.REQUIRED_CASES))


class KindSelectedPinAdmissionTests(unittest.TestCase):
    def test_main_passes_each_platform_pin_to_executable_admission(self):
        for machine,expected in [('x86_64',k.KIND_SHA256),('aarch64',k.KIND_ARM64_SHA256)]:
            with self.subTest(machine=machine),tempfile.TemporaryDirectory() as directory:
                root=Path(directory);root.chmod(0o700)
                binary=root/'kind';binary.write_bytes(b'synthetic');binary.chmod(0o700)
                with patch.object(k.platform,'system',return_value='Linux'), \
                        patch.object(k.platform,'machine',return_value=machine), \
                        patch.object(k.shutil,'which',return_value='/usr/bin/docker'), \
                        patch.object(k,'validate_binary',side_effect=k.FixtureFailure('stop_before_exec')) as admit, \
                        patch.object(k.subprocess,'run') as daemon, \
                        self.assertRaisesRegex(k.FixtureFailure,'stop_before_exec'):
                    k.main(['--binary',str(root/'candidate'),'--kind',str(binary),
                            '--output',str(root/'report.json'),'--allow-disposable-cluster'])
                admit.assert_called_once_with(binary,expected)
                daemon.assert_not_called()
