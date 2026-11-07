"""Offline parser/privacy and touch-dispatch checks. Never opens ADB or a device."""
import argparse
import importlib.util
import json
from pathlib import Path
import time
import unittest
import xml.etree.ElementTree as ET

parser = argparse.ArgumentParser()
parser.add_argument('--driver', type=Path, default=Path(__file__).with_name('android_live.py'))
args, unittest_args = parser.parse_known_args()
PATH = args.driver
spec = importlib.util.spec_from_file_location('driver', PATH)
driver = importlib.util.module_from_spec(spec)
spec.loader.exec_module(driver)


def own_dump(identity='aa11', state=''):
    return ('ACTIVITY MANAGER PENDING INTENTS (dumpsys activity intents)\n'
            '  * ' + driver.PROVIDER + ': 1 items\n'
            '    #0: PendingIntentRecord{' + identity + ' ' + driver.PROVIDER + ' startActivity}\n'
            '      uid=12345 packageName=' + driver.PROVIDER + ' featureId=null type=startActivity flags=0x42000000\n'
            '      requestIntent=Intent { act=org.heptabao.personal.preview.AUTHORIZE_FILL dat=heptabao-auth://local/DO_NOT_EXPORT_TOKEN cmp=' + driver.PROVIDER + '/org.heptabao.preview.AuthActivity (has extras) }\n'
            + state + '\n  * WEAK REFS:\n    #0: unrelated_DO_NOT_EXPORT\n  * UID: 99999 total: 8888\n')


class DiagnosticGuards(unittest.TestCase):
    def test_own_metadata_drops_tokens_and_global_tail(self):
        got = driver.pending_intent_metadata(own_dump(), {})
        self.assertTrue(got['available'])
        self.assertEqual(got['own_record_count'], 1)
        self.assertTrue(got['records'][0]['auth_component_present'])
        self.assertTrue(got['records'][0]['one_shot'])
        self.assertTrue(got['records'][0]['mutable'])
        self.assertFalse(got['records'][0]['immutable'])
        rendered = json.dumps(got)
        for prohibited in ['DO_NOT_EXPORT', 'aa11', '12345', '99999', '8888', 'heptabao-auth', 'requestIntent', 'extras']:
            self.assertNotIn(prohibited, rendered)

    def test_foreign_live_records_are_unknown_and_never_serialized(self):
        raw = 'ACTIVITY MANAGER PENDING INTENTS (dumpsys activity intents)\n * unrelated.private: 1 items\n #0: DO_NOT_EXPORT\n * UID: 99999 total: 8888\n'
        self.assertEqual(driver.pending_intent_metadata(raw, {}), {'available': False, 'reason': 'package_filter_not_observed'})

    def test_no_own_records_discards_weak_refs_and_uid_tail(self):
        raw = 'ACTIVITY MANAGER PENDING INTENTS (dumpsys activity intents)\n * WEAK REFS:\n #0: java.lang.ref.WeakReference@aa11\n * UID: 99999 total: 8888\n (nothing)\n'
        self.assertEqual(driver.pending_intent_metadata(raw, {}), {'available': True, 'own_record_count': 0, 'records': []})

    def test_valid_header_unknown_body_is_not_absence(self):
        raw = 'ACTIVITY MANAGER PENDING INTENTS (dumpsys activity intents)\nUnexpected OEM output\n'
        self.assertFalse(driver.pending_intent_metadata(raw, {})['available'])

    def test_unknown_own_section_count_syntax_is_not_absence(self):
        raw = 'ACTIVITY MANAGER PENDING INTENTS (dumpsys activity intents)\n * ' + driver.PROVIDER + ': count=1\n'
        self.assertFalse(driver.pending_intent_metadata(raw, {})['available'])

    def test_unknown_format_is_unknown_not_empty(self):
        self.assertFalse(driver.pending_intent_metadata('Permission denied DO_NOT_EXPORT', {})['available'])
        self.assertFalse(driver.pending_intent_metadata(own_dump().replace('featureId=null', 'featureId=newformat'), {})['available'])

    def test_missing_own_record_is_unknown_not_empty(self):
        self.assertFalse(driver.pending_intent_metadata(own_dump().replace(': 1 items', ': 2 items'), {})['available'])

    def test_cancel_state_is_closed_enum_only(self):
        got = driver.pending_intent_metadata(own_dump(state='      sent=true canceled=true cancelReason=ONE_SHOT_SENT'), {})
        self.assertEqual(got['records'][0]['cancel_reason'], 'ONE_SHOT_SENT')
        got = driver.pending_intent_metadata(own_dump(state='      sent=false canceled=true cancelReason=DO_NOT_EXPORT'), {})
        self.assertIsNone(got['records'][0]['cancel_reason'])
        self.assertNotIn('DO_NOT_EXPORT', json.dumps(got))

    def test_registry_identity_is_an_ephemeral_ordinal(self):
        ids = {}
        a = driver.pending_intent_metadata(own_dump(), ids)
        b = driver.pending_intent_metadata(own_dump(), ids)
        c = driver.pending_intent_metadata(own_dump('bb22'), ids)
        self.assertEqual(a['records'][0]['observation_record_id'], b['records'][0]['observation_record_id'])
        self.assertNotEqual(a['records'][0]['observation_record_id'], c['records'][0]['observation_record_id'])
        self.assertNotIn('bb22', json.dumps(c))

    def device(self, old=False):
        d = driver.Device.__new__(driver.Device)
        node = ET.fromstring('<node text="DO_NOT_EXPORT" content-desc="DO_NOT_EXPORT" resource-id="private-secret" package="org.heptabao.personal.preview" class="android.widget.TextView" bounds="[10,20][30,40]" enabled="true" clickable="false"/>')
        parent = ET.fromstring('<node text="DO_NOT_EXPORT" package="unrelated.private" class="private.secret.Class" bounds="[0,0][100,100]" clickable="true"/>')
        d._ui_parents = {node: parent}
        d._ui_finished_ns = time.monotonic_ns() - (2_000_000_000 if old else 0)
        d._ui_started_ns = d._ui_finished_ns - 1_000_000
        d.expected_fixture = driver.GOOD
        d.current_case = 'locked_fill_refused'
        d.tap_diagnostics = []
        d.wait = lambda *args: node
        d.pending_intents = lambda: {'available': True, 'own_record_count': 1, 'records': []}
        d.foreground = lambda: (driver.GOOD, driver.ACTIVITY)
        d.shell_calls = []
        d.shell = lambda *args: d.shell_calls.append(args)
        return d, node

    def test_geometry_never_serializes_text_description_or_foreign_identity(self):
        d, node = self.device()
        got = d.node_geometry(node)
        rendered = json.dumps(got)
        for prohibited in ['DO_NOT_EXPORT', 'private-secret', 'unrelated.private', 'private.secret.Class']:
            self.assertNotIn(prohibited, rendered)
        self.assertFalse(got[0]['clickable'])
        self.assertTrue(got[1]['clickable'])
        self.assertEqual(got[1]['package'], 'other_omitted')

    def test_instrumentation_preserves_one_system_touch_at_selected_center(self):
        d, _ = self.device()
        d.tap(text='Unlock HeptaBao locally')
        self.assertEqual(d.shell_calls, [('input', 'tap', '20', '30')])
        self.assertEqual(len(d.tap_diagnostics), 1)
        self.assertTrue(d.tap_diagnostics[0]['input_command_completed'])
        self.assertNotIn('DO_NOT_EXPORT', json.dumps(d.tap_diagnostics))

    def test_stale_menu_sample_is_recorded_but_never_tapped(self):
        d, _ = self.device(True)
        with self.assertRaises(driver.Failed): d.tap(text='Unlock HeptaBao locally')
        self.assertEqual(d.shell_calls, [])
        self.assertEqual(len(d.tap_diagnostics), 1)


if __name__ == '__main__':
    unittest.main(argv=[str(Path(__file__)), *unittest_args])
