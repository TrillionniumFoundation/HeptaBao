"""Packet and qualification rejection tests; no native/SDK execution."""
import argparse
import copy
import gzip
import io
import json
from pathlib import Path
import tarfile
import unittest
from unittest import mock

import authbus_native_openai_once as controller

PACKET_INPUT = None


def archive_bytes(payloads):
    raw = io.BytesIO()
    with tarfile.open(fileobj=raw, mode='w', format=tarfile.USTAR_FORMAT) as archive:
        for name, body in payloads:
            item = tarfile.TarInfo(name)
            item.size = len(body); item.mode = 0o644
            archive.addfile(item, io.BytesIO(body))
    return gzip.compress(raw.getvalue(), mtime=0)


class NativeOpenaiPacketQualification(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if PACKET_INPUT is None:
            raise RuntimeError('explicit_packet_test_input_required')
        cls.raw = PACKET_INPUT.read_bytes()
        cls.manifest, cls.payloads = controller.decode_packet(cls.raw)

    def test_exact_twenty_three_members_and_independent_inventory(self):
        self.assertEqual(len(self.payloads), 23)
        self.assertEqual(len(self.manifest['files']), 22)
        self.assertEqual(self.manifest['expectedControllerCheckCount'], 141)
        self.assertEqual([item['expectedChecks'] for item in self.manifest['workerExpectations'].values()], [87, 80, 80])
        self.assertEqual(self.manifest['originalOuterBudgetSeconds'], 180)
        self.assertFalse(self.manifest['originalNativeFourCaseResultInherited'])
        self.assertFalse(self.manifest['sdk32ScenarioResultInherited'])

    def test_one_byte_packet_mutation_refused(self):
        raw = self.raw[:-1] + bytes([self.raw[-1] ^ 1])
        with self.assertRaisesRegex(controller.Refusal, 'exact_frozen_packet_required'):
            controller.decode_packet(raw)

    def test_unbound_input_packet_refused(self):
        with self.assertRaisesRegex(controller.Refusal, 'exact_frozen_packet_required'):
            controller.decode_packet(b'not-the-frozen-profile')

    def test_extra_member_refused_even_with_transport_pin(self):
        raw = archive_bytes(list(self.payloads.items()) + [('foreign.txt', b'extra')])
        with mock.patch.multiple(controller, PACKET_BYTES=len(raw), PACKET_SHA=controller.sha(raw)):
            with self.assertRaisesRegex(controller.Refusal, 'exact_twenty_three_archive_members_required'):
                controller.decode_packet(raw)

    def test_duplicate_member_refused_even_with_transport_pin(self):
        members = list(self.payloads.items())
        members[-1] = members[0]
        raw = archive_bytes(members)
        with mock.patch.multiple(controller, PACKET_BYTES=len(raw), PACKET_SHA=controller.sha(raw)):
            with self.assertRaisesRegex(controller.Refusal, 'exact_twenty_three_archive_members_required'):
                controller.decode_packet(raw)

    def test_sdk_input_pin_change_refused_under_new_outer_transport_pin(self):
        manifest = copy.deepcopy(self.manifest)
        manifest['sdkInputs']['modules'][0]['originalSha256'] = '0' * 64
        payloads = dict(self.payloads)
        manifest_raw = controller.encoded(manifest)
        payloads['source-manifest.json'] = manifest_raw
        raw = archive_bytes(list(payloads.items()))
        with mock.patch.multiple(controller, PACKET_BYTES=len(raw), PACKET_SHA=controller.sha(raw),
                                 MANIFEST_BYTES=len(manifest_raw), MANIFEST_SHA=controller.sha(manifest_raw)):
            with self.assertRaisesRegex(controller.Refusal, 'exact_sdk_input_manifest_required'):
                controller.decode_packet(raw)

    def test_missing_reordered_and_false_assertions_cannot_pass(self):
        names = self.manifest['orderedControllerCheckNames']
        complete = {'ok': True, 'checksPassed': len(names), 'checks': [{'case': name, 'passed': True} for name in names]}
        controller.exact_checks(complete, names, 'qualification_rejected')
        for kind in ['missing', 'reordered', 'false', 'duplicated']:
            value = copy.deepcopy(complete)
            if kind == 'missing':
                value['checks'].pop()
            elif kind == 'reordered':
                value['checks'][0], value['checks'][1] = value['checks'][1], value['checks'][0]
            elif kind == 'false':
                value['checks'][0]['passed'] = False
            else:
                value['checks'][1] = value['checks'][0]
            with self.subTest(kind=kind), self.assertRaisesRegex(controller.Refusal, 'qualification_rejected'):
                controller.exact_checks(value, names, 'qualification_rejected')

    def test_prior_native_or_sdk_schemas_cannot_qualify_combined_profile(self):
        for schema in ['authbus-refresh-r5-native-cold-live', 'authbus-refresh-r5-actual-openai-sdk']:
            with self.subTest(schema=schema), self.assertRaisesRegex(controller.Refusal, 'public_original_native_driver_binding_required'):
                controller.validate_public({'schema': schema, 'ok': True}, self.manifest, 1, Path('/unopened-fixture'), 1)

    def test_wrong_product_pin_refused_before_any_artifact_read(self):
        manifest = copy.deepcopy(self.manifest)
        manifest['productBuild']['binarySha256'] = '0' * 64
        with mock.patch.object(controller, 'read_regular', side_effect=AssertionError('artifact_must_not_be_read')):
            with self.assertRaisesRegex(controller.Refusal, 'exact_r5_native_product_required'):
                controller.verify_native_product(manifest)


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--packet', type=Path, required=True)
    args, rest = parser.parse_known_args()
    PACKET_INPUT = args.packet
    unittest.main(argv=[__file__] + rest)
