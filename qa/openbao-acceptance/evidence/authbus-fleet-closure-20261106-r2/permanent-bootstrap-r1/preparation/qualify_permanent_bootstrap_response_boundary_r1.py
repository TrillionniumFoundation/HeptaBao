#!/usr/bin/env python3
"""Only qualify the new response durability ordering; all wire objects are fake.

The unchanged strict framing library already has separate real-TLS evidence.
This fixture neither opens the permanent paths nor claims a real service pass.
"""
import hashlib
import importlib.util
import json
from pathlib import Path
import sys
import time
from unittest.mock import patch

WORK = Path(__file__).resolve().parent
sys.path.insert(0, str(WORK.parent / 'main3-authbus-work/source-api-r5'))
spec = importlib.util.spec_from_file_location('bootstrap_api_under_review', WORK / 'permanent_bootstrap_api_r1.py')
api_module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(api_module)

def run_case(name, *, raw, status=200, durable_error=False, expected=200):
    trace = []
    class Raw:
        closed = False
        def settimeout(self, _): pass
        def close(self): self.closed = True; trace.append('raw-close')
    original = Raw()
    class Tls:
        closed = False
        def settimeout(self, _): pass
        def getpeercert(self, **_): return b'new-synthetic-certificate'
        def version(self): return 'TLSv1.3'
        def sendall(self, value): trace.append('send')
        def close(self): self.closed = True; original.close(); trace.append('tls-close')
    tls = Tls()
    class Context:
        def wrap_socket(self, value, **_): assert value is original; return tls
    class Reader:
        closed = False
    class Stream:
        def __init__(self, *args): self.raw = Reader()
        def close_reader(self): self.raw.closed = True; trace.append('reader-close')
    class Response:
        def __init__(self, *args): self.status = status
        def begin(self): pass
        def close(self): trace.append('response-close')
    class Journal:
        captured = None
        def append(self, category, value):
            if category == 'api-request-result':
                assert tls.closed and original.closed and 'reader-close' in trace
            trace.append(category)
        def response_bytes(self, phase, ordinal, value):
            assert phase == 'initial' and ordinal == 1 and value == raw
            trace.append('private-response-write')
            if durable_error:
                raise OSError('synthetic-fsync-failure')
            self.captured = bytes(value)
            trace.append('private-response-durable')
    class Guard:
        def check(self): pass
    journal = Journal()
    api = api_module.Api.__new__(api_module.Api)
    api.plan = {'port': 31080, 'certificateLeafSha256': hashlib.sha256(b'new-synthetic-certificate').hexdigest()}
    api.phase, api.until, api.journal, api.guard = 'initial', time.monotonic() + 5, journal, Guard()
    api.context, api.rows, api.checks, api.unknown, api.root_token = Context(), [], [], False, None
    decode = json.loads
    def observed_decode(value):
        assert journal.captured == raw
        trace.append('parse-response')
        return decode(value)
    error = None
    with patch.object(api_module.socket, 'create_connection', return_value=original), \
         patch.object(api_module, 'DeadlineSocket', Stream), \
         patch.object(api_module, 'CompleteHTTPResponse', Response), \
         patch.object(api_module, 'read_complete_body', return_value=raw), \
         patch.object(api_module.json, 'loads', observed_decode):
        try:
            api.call('fixture.' + name, 'POST', '/v1/sys/init', {'secret_shares': 1, 'secret_threshold': 1},
                     token='', category='init', expected=expected)
        except api_module.Refused as value:
            error = value
        assert trace.count('send') == 1 and tls.closed and original.closed
        assert api.rows[0]['socketsClosed'] and api.rows[0]['responseReaderClosed']
        if error:
            before = trace.count('send')
            try:
                api.call('fixture.after_failure', 'GET', '/v1/sys/health', token='', category='health')
            except api_module.Refused:
                pass
            else:
                raise AssertionError('request was allowed after original unknown/failed response')
            assert trace.count('send') == before
    if durable_error:
        assert error is not None and api.unknown and api.rows[0]['outcomeUnknown']
        assert 'parse-response' not in trace and not api.rows[0]['responsePrivatelyDurable']
    elif raw == b'not-json':
        assert error is not None and api.unknown and journal.captured == raw
        assert api.rows[0]['responseComplete'] and api.rows[0]['responsePrivatelyDurable']
        assert not api.rows[0]['outcomeUnknown']
    else:
        assert error is None and not api.unknown and api.rows[0]['responsePrivatelyDurable']
        assert trace.index('private-response-durable') < trace.index('parse-response')
    return {'case': name, 'passed': True, 'originalSends': 1, 'allFakeSocketsClosed': True}

checks = [
    run_case('complete_init_durable_before_parse', raw=b'{"root_token":"synthetic-only","keys_base64":["synthetic-only-key"]}'),
    run_case('complete_invalid_json_still_retained_no_replay', raw=b'not-json'),
    run_case('private_fsync_failure_blocks_parsing_and_next_request', raw=b'{"complete":true}', durable_error=True),
    run_case('known_denial_response_durable_and_closed', raw=b'{"errors":["permission denied"]}', status=403, expected=403),
]
print(json.dumps({'schema': 'heptabao.bootstrap-response-durability-boundary.r1', 'ok': True,
    'checks': checks, 'passed': len(checks), 'wireAndPrivateJournalAreSubstituted': True,
    'actualTlsQualifiedByThisFixture': False, 'actualPermanentPathsOpened': False,
    'actualInitializationOrProviderRequests': 0}, sort_keys=True, indent=2))
