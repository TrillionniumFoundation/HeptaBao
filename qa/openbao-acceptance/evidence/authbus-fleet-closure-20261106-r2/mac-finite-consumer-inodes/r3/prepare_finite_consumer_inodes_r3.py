#!/usr/bin/env python3
"""Freeze one finite current-inode observation without dispatching it."""
import ast
import hashlib
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
PRIOR = HERE.parent / 'main3-sdk-outer-r4-work/source-sdk-r4'
PINS = {
    'mac_owned_unreaped_r1.py': 'd735a9e9330e1260d44ad9e4c854d50094e20d85fe5633ddd9042281b3346298',
    'mac_owned_commands_r1.py': '71a11bf9a0510c991b78c9bc3f094f315bf4914485b9cfda81c6e501eaf73530',
    'mac_native_process_observer_r1.py': 'cc0fa9917d05c6dc2c295594f980c1f77d089c1196e6279a14f2fdaf2d77ae9b',
}
sha = lambda raw: hashlib.sha256(raw).hexdigest()
sources = {}
for name, pin in PINS.items():
    raw = (PRIOR / name).read_bytes()
    assert sha(raw) == pin
    sources[name] = raw.decode()
sources['mac_finite_lsof_fields_r2.py'] = (HERE / 'mac_finite_lsof_fields_r2.py').read_text()
pins = {name: sha(source.encode()) for name, source in sources.items()}
processes = json.loads((HERE / 'prior-native-nine.public.json').read_text())
assert len(processes) == 9 and {row['pid'] for row in processes} == {964,983,987,989,18437,66414,66687,89324,89325}
assert all(set(row) == {'pid','uid','identity','name'} and row['uid'] == 501 for row in processes)
for name, source in sources.items():
    compile(source, name, 'exec')
template = (HERE / 'observe_finite_consumer_inodes_r3.template.py').read_text()
assert template.count('# PAYLOAD_PLACEHOLDER') == 1
payload = {'sources': sources, 'sourcePins': pins, 'processes': processes}
assembled = template.replace('# PAYLOAD_PLACEHOLDER', 'PAYLOAD=' + repr(payload))
compile(assembled, 'observe_finite_consumer_inodes_r3.py', 'exec')
extracted = ast.literal_eval(next(node.value for node in ast.parse(assembled).body
    if isinstance(node,ast.Assign) and any(isinstance(target,ast.Name) and target.id=='PAYLOAD' for target in node.targets)))
assert extracted == payload
out = HERE / 'observe_finite_consumer_inodes_r3.py'
out.write_text(assembled)
manifest = {'schema': 'heptabao.finite-consumer-inode-preparation.r3',
    'launcherBytes': len(assembled.encode()), 'launcherSha256': sha(assembled.encode()),
    'sourcePins': pins, 'selectedProcesses': 9, 'fixedFileMetadataTargets': 45,
    'metadataScope': {'databasesAndSidecars':24,'knownAuthBusCaches':6,'knownAgentLegacyFiles':15},
    'parentSeconds':45,'originalLsofSeconds':10,'supervisorSeconds':70,
    'maximumLsofOutputBytes':1048576,'maximumFileRecords':16384,
    'lsofFields':'pufatDi','nulTerminatedFields':True,'fileNameFieldsRequested':False,
    'deviceCacheIgnored':False,'deviceCacheOptionUnsupported':True,'nameAndServiceResolutionDisabled':True,
    'observedProcessesMayNotBeSignalled':True,'credentialReads':0,'keychainReads':0,
    'sqliteCalls':0,'productionWrites':0,'serviceActions':0,
    'allProcessMemoryCredentialUseEstablished':False,'consumerQuiescenceQualified':False,
    'sourceReferences':['https://github.com/lsof-org/lsof/blob/master/docs/manpage.md'],
    'actualExecuted':False}
(HERE / 'finite-consumer-manifest.public.json').write_text(json.dumps(manifest,sort_keys=True,indent=2)+'\n')
print(json.dumps(manifest,sort_keys=True))
