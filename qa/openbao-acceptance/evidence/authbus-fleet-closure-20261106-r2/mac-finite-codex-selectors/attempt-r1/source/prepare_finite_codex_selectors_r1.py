#!/usr/bin/env python3
"""Freeze the finite read-only selector observer; no remote action."""
import ast
import hashlib
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
ORIGINAL = HERE.parent / 'main3-sdk-outer-r4-work/source-sdk-r4'
PINS = {
    'mac_owned_unreaped_r1.py': 'd735a9e9330e1260d44ad9e4c854d50094e20d85fe5633ddd9042281b3346298',
    'mac_native_process_observer_r1.py': 'cc0fa9917d05c6dc2c295594f980c1f77d089c1196e6279a14f2fdaf2d77ae9b',
}
sha = lambda raw: hashlib.sha256(raw).hexdigest()
sources = {}
for name, pin in PINS.items():
    raw = (ORIGINAL / name).read_bytes()
    assert sha(raw) == pin
    sources[name] = raw.decode()
sources['mac_procargs_selectors_r1.py'] = (HERE / 'mac_procargs_selectors_r1.py').read_text()
for name, source in sources.items():
    compile(source, name, 'exec')
admission = json.loads((HERE / 'selector-admission.public.json').read_text())
assert [row['pid'] for row in admission['processes']] == [66414, 66687, 89324, 89325]
assert admission['priorAuthority']['jobId'] == '1a1b3804d06-fc05-8343'
assert len(admission['publicFilePins']) == 4
payload = {**admission, 'sources': sources, 'sourcePins': {name:sha(source.encode()) for name,source in sources.items()}}
template = (HERE / 'observe_finite_codex_selectors_r1.template.py').read_text()
assert template.count('# PAYLOAD_PLACEHOLDER') == 1
source = template.replace('# PAYLOAD_PLACEHOLDER', 'PAYLOAD=' + repr(payload))
tree = ast.parse(source)
recovered = next(ast.literal_eval(node.value) for node in tree.body if isinstance(node, ast.Assign)
    and any(isinstance(target, ast.Name) and target.id == 'PAYLOAD' for target in node.targets))
assert recovered == payload
(HERE / 'observe_finite_codex_selectors_r1.py').write_text(source)
report = {
    'schema':'heptabao.finite-codex-selector-preparation.r1','actualExecuted':False,
    'launcherBytes':len(source.encode()),'launcherSha256':sha(source.encode()),
    'templateBytes':len(template.encode()),'templateSha256':sha(template.encode()),
    'sourcePins':payload['sourcePins'],'publicFilePins':admission['publicFilePins'],
    'priorAuthority':admission['priorAuthority'],
    'selectedProcesses':4,'fixedPids':[66414,66687,89324,89325],
    'parentSeconds':20,'supervisorSeconds':30,'samplesPerProcess':2,
    'maximumProcargsBytesIncludingArgc':262148,'maximumArgc':512,'maximumEnvironmentEntries':4096,
    'readonlyMibs':[[1,8],[1,49,'fixed_pid']],
    'rawArgumentsOrEnvironmentPersisted':False,'selectorValuesPersistedOnlyPrivately':True,
    'credentialFileReads':0,'keychainReads':0,'productionWrites':0,'signalsToObservedConsumers':0,
    'childProcesses':0,'effectiveCredentialSourceQualified':False,
    'missingEnvironmentIsUnknown':True,'argumentStackIsNotRuntimeConfig':True,
    'sourceReferences':[
        {'repository':'apple-oss-distributions/adv_cmds','path':'ps/print.c','blob':'a6f02a86eb29dec5dc39e54ff3692f191c203879'},
        {'repository':'apple-oss-distributions/xnu','path':'bsd/kern/kern_sysctl.c','blob':'1e9baecfcbe6e56d8deac42fe59022266ab7db46'},
        {'repository':'openai/codex','ref':'rust-v0.133.0','path':'codex-rs/utils/home-dir/src/lib.rs','blob':'caa43569c78bae9f5cc875092f378f4d935b8063'},
    ],
}
(HERE / 'selector-manifest.public.json').write_text(json.dumps(report,sort_keys=True,indent=2)+'\n')
print(json.dumps(report,sort_keys=True))
