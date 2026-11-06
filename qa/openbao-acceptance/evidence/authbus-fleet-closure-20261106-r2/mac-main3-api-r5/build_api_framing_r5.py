#!/usr/bin/env python3
"""Create a new source-bound API attempt; preserve every failed r4 byte."""
import ast
import base64
import difflib
import hashlib
import json
from pathlib import Path

WORK = Path('/workspace/scratch/c9fe536787d9/main3-authbus-work')
OUT = WORK / 'source-api-r5'
old = json.loads((WORK / 'staging-api-r4.public.json').read_text())
old_manifest = json.loads((WORK / 'manifest-api-r4.public.json').read_text())


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def once(text, before, after):
    assert text.count(before) == 1, (before[:120], text.count(before))
    return text.replace(before, after)


def assignment(text, name, value):
    nodes = [n for n in ast.parse(text).body if isinstance(n, ast.Assign) and
             any(isinstance(t, ast.Name) and t.id == name for t in n.targets)]
    assert len(nodes) == 1, name
    node = nodes[0]
    lines = text.splitlines(True)
    lines[node.lineno - 1:node.end_lineno] = [name + '=' + repr(value) + '\n']
    return ''.join(lines)


def revise(text):
    for stem in ('mac-authbus-main3-api', 'mac-authbus-main3-api-preparation',
                 'mac-authbus-main3-api-journal', 'heptabao-authbus-main3-api-inline-capsule'):
        text = text.replace(stem + '-20261106-r4', stem + '-20261106-r5')
    text = text.replace('.r4\'', '.r5\'').replace('.r4"', '.r5"')
    return text


sources = {}
for name, text in old['sources'].items():
    assert sha(text.encode()) == old_manifest['sourcePins'][name]['sha256'], name
    sources[name] = revise(text)

# Rebind the original inline fresh capture to its own new create-only namespace.
# Every payload source is public code or a public receipt; no private values.
parts = sorted(n for n in sources if n.startswith('main3_capture_payload_'))
encoded = ''.join(ast.literal_eval(ast.parse(old['sources'][n]).body[0].value) for n in parts)
old_payload_raw = base64.b64decode(encoded, validate=True)
payload = json.loads(old_payload_raw)
payload['worker'] = revise(payload['worker'])
payload['registryChild'] = revise(payload['registryChild'])
payload_raw = (json.dumps(payload, sort_keys=True, separators=(',', ':')) + '\n').encode()
data = base64.b64encode(payload_raw).decode('ascii')
part_pins = {}
for i, start in enumerate(range(0, len(data), 60000)):
    name = 'main3_capture_payload_%d.py' % i
    source = 'DATA=' + repr(data[start:start + 60000]) + '\n'
    assert len(source.encode()) <= 65536
    sources[name] = source
    part_pins[name] = {'bytes': len(source.encode()), 'sha256': sha(source.encode())}
assert set(part_pins) == set(parts)
launcher = assignment(sources['main3_capture_launcher.py'], 'PAYLOAD_PART_PINS', part_pins)
launcher = once(launcher, sha(old_payload_raw), sha(payload_raw))
sources['main3_capture_launcher.py'] = launcher
capture_pins = {'CAPTURE_WORKER_SHA': sha(payload['worker'].encode()),
                'CAPTURE_LAUNCHER_SHA': sha(launcher.encode()),
                'CAPTURE_GUARD_SHA': sha(payload['guard'].encode()),
                'CAPTURE_REGISTRY_SHA': sha(payload['registryChild'].encode()),
                'CAPTURE_PAYLOAD_SHA': sha(payload_raw)}
helper = sources['main3_inline_capture.py']
for name, value in capture_pins.items():
    helper = assignment(helper, name, value)
sources['main3_inline_capture.py'] = helper

# The only API semantic change: admit bounded complete chunked response framing.
api = sources['main3_api_cycle.py']
api = once(api, 'from main3_source_fence import CapsuleFence,Refused,need,ident',
    'from main3_source_fence import CapsuleFence,Refused,need,ident\n'
    'from main3_http_complete import DeadlineSocket,CompleteHTTPResponse,read_complete_body,safe_failure_code')
api = once(api, 'raw=tls=response=None', 'raw=tls=response=stream=None')
before = '''            tls.settimeout(left());response=http.client.HTTPResponse(tls);response.begin()
            row['status']=response.status
            length=response.getheader('Content-Length')
            need(not response.getheader('Transfer-Encoding') and (length is None or re.fullmatch(r'[0-9]{1,9}',length)),
                 'complete_fixed_http_response_framing')
            if response.status==204:
                need(length in (None,'0'),'empty_204_response_frame');amount=0
            else:
                need(length is not None and int(length)<=MAX_BODY,'bounded_content_length_required');amount=int(length)
            tls.settimeout(left());data=response.read(amount+1)
            need(len(data)==amount and response.isclosed(),'complete_http_body_before_acceptance')
'''
after = '''            stream=DeadlineSocket(tls,left,row)
            response=CompleteHTTPResponse(stream,left,row);response.begin()
            row['status']=response.status
            data=read_complete_body(response,left,row)
'''
api = once(api, before, after)
api = once(api, "            self.unknown=True;row['errorType']=type(error).__name__", 
    "            self.unknown=True;row['errorType']=type(error).__name__\n"
    "            row['failureCode']=safe_failure_code(error)\n"
    "            if isinstance(error,Refused) and error.args==('one_http_original_absolute_deadline',):row['failureCode']='http_original_deadline'\n"
    "            if isinstance(error,json.JSONDecodeError):row['failureCode']='complete_body_json_invalid'")
api = once(api, '            if response is not None:response.close()\n',
    '            if response is not None:response.close()\n'
    '            if stream is not None:stream.close_reader()\n'
    "            row['responseReaderClosed']=stream is None or stream.raw.closed\n")
sources['main3_api_cycle.py'] = api

# Preserve the existing API guard cases with the new parser seam. The original
# test called 'chunked rejected' actually supplied both CL and TE; name it exactly.
tests = sources['test_main3_api_guards.py']
tests = once(tests, '        self.transfer=transfer;self.complete=complete;self.closed=False',
    '        self.transfer=transfer;self.complete=complete;self.closed=False\n'
    '        self.version=11;self.headers=types.SimpleNamespace(defects=[])')
tests = once(tests, "    def getheader(self,name):return self.transfer if name=='Transfer-Encoding' else self.length", 
    "    def getheaders(self):return ([('Content-Length',self.length)] if self.length is not None else []) + ([('Transfer-Encoding',self.transfer)] if self.transfer is not None else [])")
tests = once(tests, "mock.patch.object(a.http.client,'HTTPResponse',return_value=self.response)",
    "mock.patch.object(a,'CompleteHTTPResponse',return_value=self.response)")
tests = once(tests, 'def test_chunked_response_is_rejected(self):',
    'def test_ambiguous_transfer_and_content_length_is_rejected(self):')
sources['test_main3_api_guards.py'] = tests
for name in ('main3_http_complete', 'test_main3_http_complete', 'qualify_main3_http_tls'):
    sources[name + '.py'] = (WORK / (name + '.template.py')).read_text()
sources['main3_api_controller.py'] = assignment(sources['main3_api_controller.py'], 'SOURCE_NAMES', tuple(sources))

OUT.mkdir(exist_ok=True)
for name, source in sources.items():
    ast.parse(source)
    (OUT / name).write_text(source)
source_pins = {n: {'bytes': len(s.encode()), 'sha256': sha(s.encode())} for n, s in sources.items()}
preparer = assignment(revise(old['preparerSource']), 'EXPECTED_PINS', source_pins)
ast.parse(preparer)
(WORK / 'prepare_main3_api_r5.bound.py').write_text(preparer)
bundle = {'sources': sources, 'preparerSource': preparer}
raw = json.dumps(bundle, separators=(',', ':')).encode()
assert len(raw) <= 1048576
(WORK / 'staging-api-r5.public.json').write_bytes(raw)
diff = ''.join(''.join(difflib.unified_diff(old['sources'].get(n, '').splitlines(True), s.splitlines(True),
    fromfile='retained-failed-r4/' + n, tofile='new-bounded-framing-r5/' + n)) for n, s in sources.items()
    if not n.startswith('main3_capture_payload_'))
(WORK / 'main3-api-r5.diff').write_text(diff)
semantic_diff = ''.join(''.join(difflib.unified_diff(revise(old['sources'].get(n, '')).splitlines(True),
    sources[n].splitlines(True), fromfile='r4-with-only-new-root/' + n, tofile='r5/' + n))
    for n in ('main3_api_cycle.py', 'main3_http_complete.py', 'test_main3_api_guards.py',
              'test_main3_http_complete.py', 'qualify_main3_http_tls.py'))
(WORK / 'main3-api-r5-framing.diff').write_text(semantic_diff)
manifest = {**old_manifest, 'schema': 'heptabao.mac-main3-api-source-derivation.r5',
    'sourcePins': source_pins, 'preparer': {'bytes': len(preparer.encode()), 'sha256': sha(preparer.encode())},
    'currentCapture': {'operationKey': 'heptabao-mac-authbus-main3-api-inline-capture-20261106-r5',
        'capsuleRoot': '/Users/qianqi/heptabao-authbus-main3-api-inline-capsule-20261106-r5',
        'authorityKind': 'original_direct_child_wait_and_closed_owned_inner_children',
        'sourcePins': capture_pins, 'payloadParts': part_pins, 'payloadBytes': len(payload_raw),
        'runtimeJobTerminalAssumed': False, 'sameOuter600Seconds': True, 'captureMaximumSeconds': 45},
    'retainedR4Status': {'job': '1a1b208cac2-fc05-7c20', 'terminal': 'failed', 'exitCode': 1,
        'httpDispatches': 14, 'completeHttpResponses': 13, 'lastStatus': 200,
        'lastResponseComplete': False, 'lastResponseUnknown': True,
        'originalResponseHeadersRecorded': False, 'originalFramingCauseProven': False,
        'independentAbsenceJob': '1a1b20cff32-fc05-7c34'},
    'canonicalLargeJsonChunkedCapabilityGapConfirmedInSource': True,
    'businessRequestSeconds': 10, 'readinessSeconds': 15, 'phaseSeconds': 120,
    'outerSeconds': 600, 'decodedBodyLimit': 1048576, 'httpTlsRequestsRetried': False,
    'priorAttemptDataOrReceiptsModified': False}
(WORK / 'manifest-api-r5.public.json').write_text(json.dumps(manifest, indent=2) + '\n')
print(json.dumps({'sourceCount': len(sources), 'bundleBytes': len(raw),
    'parser': source_pins['main3_http_complete.py'], 'api': source_pins['main3_api_cycle.py'],
    'largestSource': max((len(v.encode()), k) for k, v in sources.items())}))
