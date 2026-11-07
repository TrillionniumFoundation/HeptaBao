#!/usr/bin/env python3
"""Five local framing/privacy failures; no claim of actual Mac lsof execution."""
import json
from pathlib import Path
import unittest
from mac_finite_lsof_fields_r1 import parse_fields, match_files, FieldRefused

GOOD = (b'p18437\x00u501\x00\nf9\x00au\x00tREG\x00D0x1000011\x00i12345\x00\n'
        b'f10\x00au\x00tIPv4\x00i0\x00\np964\x00u501\x00\n'
        b'ftxt\x00ar\x00tREG\x00D0x1000011\x00i54321\x00\n')


class Boundaries(unittest.TestCase):
    def test_requested_records_and_exact_inode_match(self):
        parsed = parse_fields(GOOD, {18437,964})
        matches = match_files(parsed, [{'ordinal':0,'kind':'database','member':'base',
                                      'device':16777233,'inode':12345}])
        self.assertEqual(parsed['fileRecords'],3)
        self.assertEqual(len(matches),1)
        self.assertEqual((matches[0]['pid'],matches[0]['access']),(18437,'u'))

    def test_forbidden_path_field_refused(self):
        with self.assertRaises(FieldRefused):
            parse_fields(GOOD.replace(b'i12345\x00',b'i12345\x00n/private/synthetic-credential\x00'),{18437,964})

    def test_truncated_original_stream_refused(self):
        with self.assertRaises(FieldRefused):
            parse_fields(GOOD[:-2],{18437,964})

    def test_regular_file_without_inode_refused(self):
        with self.assertRaises(FieldRefused):
            parse_fields(GOOD.replace(b'i12345\x00',b''),{18437,964})

    def test_repeated_process_identity_refused(self):
        with self.assertRaises(FieldRefused):
            parse_fields(GOOD+b'p18437\x00u501\x00\n',{18437,964})


if __name__=='__main__':
    suite=unittest.defaultTestLoader.loadTestsFromTestCase(Boundaries)
    result=unittest.TestResult();suite.run(result)
    report={'schema':'heptabao.finite-lsof-fields-local5.r1','localOnly':True,'macExecuted':False,
            'tests':result.testsRun,'passed':result.testsRun-len(result.failures)-len(result.errors),
            'ok':result.wasSuccessful(),'failureTypes':[str(test) for test,_ in result.failures+result.errors]}
    raw=json.dumps(report,sort_keys=True,separators=(',',':'))+'\n'
    Path(__file__).with_name('finite-fields-local5.original.json').write_text(raw)
    print(raw,end='');raise SystemExit(0 if result.wasSuccessful() else 1)
