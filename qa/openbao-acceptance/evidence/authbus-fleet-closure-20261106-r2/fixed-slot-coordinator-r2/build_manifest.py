#!/usr/bin/env python3
"""Freeze explicit runtime files and their public source identity, no execution."""
from pathlib import Path
import hashlib,json
ROOT=Path(__file__).resolve().parent
FILES=['cli.mjs','coordinator.mjs','private-journal.mjs','protocol.mjs','source-verification.mjs',
       'transport/bounded-outbox.js','transport/private-outbox-store.js','transport/production-client.js','transport/strict-bao-client.js']
rows=[]
for name in sorted(FILES):
    raw=(ROOT/name).read_bytes();rows.append({'path':name,'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest()})
identity=hashlib.sha256(json.dumps(rows,sort_keys=True,separators=(',',':')).encode()).hexdigest()
value={'schema':'heptabao.fixed-slot-coordinator-source.r1','implementationSha256':identity,'runtimeFiles':rows,
       'sourceOnlyUntilActualQualification':True,'originalTransportByteUnchanged':True,'fixedClientProtocol':'heptabao-authbus-fixed-slots-v1',
       'originalGrantOracle':{'path':'reference/authbus_coordinator.py','sha256':'cc46822439dfd33c86d1068c886941a92c5581871474cef846d2aee14ce80fe0'},
       'perOperationMs':30000,'strictPerRequestMs':15000,'minimumNodeVersion':'22.13','productionActions':0,'providerCalls':0}
(ROOT/'source-manifest.public.json').write_text(json.dumps(value,sort_keys=True,indent=2)+'\n')
print(json.dumps(value,sort_keys=True))
