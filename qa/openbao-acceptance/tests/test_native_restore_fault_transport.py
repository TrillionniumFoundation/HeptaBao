import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch
import native_restore_fault_transport as f


class Wire:
    def __init__(self, fail=False):self.sent=[];self.closed=False;self.fail=fail
    def sendall(self,value):
        self.sent.append(value)
        if self.fail and len(self.sent)==2:raise OSError('synthetic-send-error')
    def close(self):self.closed=True
    def recv(self,*_):raise AssertionError('response must never be read')
    def read(self,*_):raise AssertionError('response must never be read')
    def unwrap(self):raise AssertionError('TLS shutdown must not read response')


class FaultTransportGuards(unittest.TestCase):
    def test_complete_body_does_not_claim_acknowledgement_or_commit(self):
        self.exercise(False)

    def test_incomplete_body_really_withholds_last_byte_without_sleep(self):
        self.exercise(True)

    def exercise(self, partial):
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'archive';payload=b'synthetic-archive-final-Z';path.write_bytes(payload)
            wire=Wire();node=SimpleNamespace(http_port=18000,context=SimpleNamespace(wrap_socket=lambda *a,**k:wire))
            with patch.object(f.socket,'create_connection',return_value=wire) as connect:
                owned=f.begin_unobserved_restore(node,'sensitive-sentinel-token',path,omit_final_byte=partial)
                self.assertIn(('Content-Length: '+str(len(payload))).encode(),wire.sent[0])
                self.assertEqual(b''.join(wire.sent[1:]),payload[:-1] if partial else payload)
                observation=owned.safe_observation()
                self.assertFalse(observation['response_read_attempted'])
                self.assertFalse(observation['restore_acknowledged'])
                self.assertFalse(observation['publication_determined_by_transport'])
                self.assertEqual(observation['request_body_complete'],not partial)
                self.assertNotIn('sentinel',json.dumps(observation));self.assertNotIn(payload.decode(),json.dumps(observation))
                self.assertFalse(wire.closed);owned.close();owned.close();self.assertTrue(wire.closed)
                self.assertEqual(connect.call_count,1)

    def test_partial_send_failure_closes_and_is_not_retried(self):
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'archive';path.write_bytes(b'synthetic-archive')
            wire=Wire(fail=True);node=SimpleNamespace(http_port=18000,context=SimpleNamespace(wrap_socket=lambda *a,**k:wire))
            with patch.object(f.socket,'create_connection',return_value=wire) as connect:
                with self.assertRaises(OSError):f.begin_unobserved_restore(node,'synthetic-token',path)
                self.assertEqual(connect.call_count,1);self.assertTrue(wire.closed)

    def test_header_injection_and_oversized_archive_do_no_io(self):
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'archive';path.write_bytes(b'ok')
            with patch.object(f.socket,'create_connection') as connect:
                with self.assertRaises(ValueError):f.begin_unobserved_restore(None,'bad\r\nHeader: x',path)
                with path.open('wb') as stream:stream.truncate(f.MAX_SMALL_ARCHIVE+1)
                with self.assertRaises(ValueError):f.begin_unobserved_restore(None,'synthetic-token',path)
                connect.assert_not_called()

if __name__ == '__main__':unittest.main()
