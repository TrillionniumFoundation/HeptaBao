#!/usr/bin/env python3
"""Read-only interpretation of one existing sample; no original result is changed."""
from pathlib import Path
import hashlib
import json
import re

ROOT = Path(__file__).resolve().parent / 'mac-node3-stack-actual-r1'
RAW = ROOT / 'sample.original.private.txt'
RESULT = ROOT / 'stdout.original.json'

def project(raw, result_raw):
    assert len(raw) == 81764 and hashlib.sha256(raw).hexdigest() == 'e7c78d9a8d37165508a42304852699340fe4c521f52851327481c8079e0cc9f2'
    assert len(result_raw) == 8169 and hashlib.sha256(result_raw).hexdigest() == 'aa0149077ec1201d4912f4b8ebace2af10568baacd8224808f17a6caaae75500'
    result = json.loads(result_raw)
    worker = result['workerFinal']
    observation = worker['firstHealthObservation']
    assert result['ok'] is True and result['remoteClosureUnknown'] is False and result['sourceInputsUnchanged'] is True
    assert worker['listenerPid'] == 35244 and worker['allInputsUnchanged'] is True
    assert worker['processCustody']['original_count'] == 3 and worker['processCustody']['passed_process_custody'] is True
    children = worker['processCustody']['children']
    assert [r['pid'] for r in children] == [35244,35254,35259]
    assert all(r['original_wait_completed'] and r['no_live_members_before_reap'] and r['gaps'] == [] for r in children)
    assert children[0]['birth']['ppid'] == 35236 and children[1]['returncode'] == 0
    assert observation['sameOriginalBirthBeforeAfter'] is True and observation['sampleReturnCode'] == 0
    assert observation['samplePermissionOrCaptureSucceeded'] is False and observation['sampleProjectionError']['code'] == 'sample_exact_original_process'
    text = raw.decode('utf-8', 'strict')
    def one(pattern):
        values = re.findall(pattern, text, re.M)
        assert len(values) == 1
        return values[0]
    assert one(r'^Process:[ \t]+(heptabao-server \[35244\])[ \t]*$') == 'heptabao-server [35244]'
    assert one(r'^Path:[ \t]+(.+)$') == '/Volumes/VOLUME/*/heptabao-server'
    assert one(r'^Parent Process:[ \t]+(.+)$') == 'Python [35236]'
    assert one(r'^Code Type:[ \t]+(.+)$') == 'ARM64'
    assert one(r'^Target Type:[ \t]+(.+)$') == 'live task'
    assert one(r'^Analysis Tool:[ \t]+(.+)$') == '/usr/bin/sample'
    lines = text.splitlines()
    thread_lines = [line.strip() for line in lines if re.search(r' [0-9]+ Thread_[0-9]+',line)]
    assert len(thread_lines) == 8
    return {'schema':'heptabao.existing-mac-sample-redacted-header-projection.r1',
        'ok':True,'originalJob':'1a1b347c2f5-fc05-81b9',
        'originalResultSha256':'aa0149077ec1201d4912f4b8ebace2af10568baacd8224808f17a6caaae75500',
        'sampleWholeSha256':'e7c78d9a8d37165508a42304852699340fe4c521f52851327481c8079e0cc9f2',
        'originalLiveProjectionSucceeded':False,'originalLiveFailureReclassified':False,
        'offlineHeaderBindingSucceeded':True,'sameOriginalPidAndParent':True,
        'samplePathRedactedBySystem':True,'redactedPathUsedAsImageAuthority':False,
        'imageAuthority':'source-pinned worker proc_pidpath plus original held PID and libproc birth before/after',
        'threadHeaders':thread_lines,'mainStackContainsTcpListenerAccept':'TcpListener6accept' in text,
        'mainStackContainsKernelAccept':'__accept' in text,
        'requestThreadObserved':'heptabao-request' in text,
        'rustlsSymbolObserved':'rustls' in text,'tokioSymbolObserved':'tokio' in text,
        'previousTlsFailureCauseEstablished':False,'newProcesses':0,'newTlsRequests':0,
        'firewallWrites':0,'haQualified':False}

if __name__ == '__main__':
    print(json.dumps(project(RAW.read_bytes(), RESULT.read_bytes()),sort_keys=True))
