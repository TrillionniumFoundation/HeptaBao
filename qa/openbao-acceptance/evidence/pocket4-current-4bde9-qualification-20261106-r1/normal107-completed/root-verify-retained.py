#!/usr/bin/env python3
"""Independent retained-receipt validation; no remote execution or rehash claim."""
import hashlib,json,sys
from pathlib import Path
QA=Path('/workspace/scratch/c9fe536787d9/HeptaBao-current-924b/qa/openbao-acceptance')
sys.path.insert(0,str(QA))
import x230_current_candidate_qualification as q
import kv2_native_fresh_directory_dr_live as dr
ROOT=Path(__file__).resolve().parent
raw=(ROOT/'linux107.result.original.public.json').read_bytes()
assert hashlib.sha256(raw).hexdigest()=='b52b67303587b3f94f1bed5330dfd2b0edaecabb89feb93d3fd3ff81419a47f5'
selection_raw=(QA/'tests/fixtures/x230-current-candidate-selection.public.json').read_bytes()
selection_sha=hashlib.sha256(selection_raw).hexdigest()
assert selection_sha=='869feff2d8672fe37a26a2fb671cdc853b3c9d7f889edfe76650eed8103f44e9'
assert hashlib.sha256((QA/'kv2_native_fresh_directory_dr_live.py').read_bytes()).hexdigest()=='01993e6c367bf8b896b4832c7723b1f36900fefbc20fcc05394ce401ec6b4f67'
value=json.loads(raw)
server={'bytes':110799168,'sha256':'85c1e21771cc1110e6442ba06cbda31db5ba7040d15f8b5c1930aa6fa40c5e5c'}
seed={'bytes':102211888,'sha256':'434c32ed59201c13d8af498f5a6b19f10935e744b085a4f8029c241523f4d968'}
binding=q.validate_receipt(value,json.loads(selection_raw),selection_sha,server,seed,dr)
print(json.dumps({'schema':'heptabao.root-retained-linux107-validation.r1','ok':True,
 'originalJobId':'1a1b2367cb2-fc05-7cfc','receiptBytes':len(raw),
 'receiptSha256':hashlib.sha256(raw).hexdigest(),'actualPassedCases':value['passed_cases'],
 'actualExecutedPassedCases':value['executed_passed_cases'],'notQualifiedCases':value['not_qualified_cases'],
 'originalSteps':len(value['steps']),'originalGroups':len(value['groups']),
 'binding':binding,'newProductExecution':False,'newRemoteArtifactRehashClaimed':False},sort_keys=True))
