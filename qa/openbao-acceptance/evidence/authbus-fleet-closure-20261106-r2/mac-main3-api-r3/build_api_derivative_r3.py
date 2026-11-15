#!/usr/bin/env python3
"""Bind a distinct current-source attempt; never edits the failed r2 fixture."""
import ast,difflib,hashlib,json,re,sys
from pathlib import Path
WORK=Path('/workspace/scratch/c9fe536787d9/main3-authbus-work')
OUT=WORK/'source-api-r3'
old=json.loads((WORK/'staging-api-r2.public.json').read_text())
manifest=json.loads((WORK/'manifest-api-r2.public.json').read_text())
capture=json.loads(Path(sys.argv[1]).read_text())
assert set(capture)=={'jobId','workerSha256','capsuleRoot','publicSdkPins','publicResultBlob','authorityBlob'}
assert re.fullmatch(r'[0-9a-f]+-[0-9a-f]+-[0-9a-f]+',capture['jobId'])
assert capture['workerSha256']=='4231b7a3976fd579eaf1deac319287a877365afa44e1240e838518a5dff8daba'
assert capture['capsuleRoot']=='/Users/qianqi/heptabao-authbus-current-sdk-capsule-20261106-r2'
def sha(raw):return hashlib.sha256(raw).hexdigest()
def revise(s):
    for stem in ('mac-authbus-main3-api','mac-authbus-main3-api-preparation','mac-authbus-main3-api-journal'):
        s=s.replace(stem+'-20261106-r2',stem+'-20261106-r3')
    for schema in ('heptabao.mac-main3-api-preparation-terminal','heptabao.mac-main3-api-preparation',
                   'heptabao.mac-main3-api-journal','heptabao.mac-main3-current-api-qualification'):
        s=s.replace(schema+'.r2',schema+'.r3')
    return s
sources={}
for name,s in old['sources'].items():
    assert sha(s.encode())==manifest['sourcePins'][name]['sha256'],name
    sources[name]=revise(s)
s=sources['main3_source_fence.py']
for before,after in (
 ('/Users/qianqi/heptabao-authbus-current-sdk-capsule-20261106-r1',capture['capsuleRoot']),
 ("CAPTURE_JOB='1a1b1a4c29c-fc05-7a0c'",'CAPTURE_JOB='+repr(capture['jobId'])),
 ("CAPTURE_WORKER_SHA='dbbac9f6ee12704b1e6e73ca2587d6f4e6489b58ec36122c49d24a9605274628'",'CAPTURE_WORKER_SHA='+repr(capture['workerSha256']))):
    assert s.count(before)==1,before
    s=s.replace(before,after)
sources['main3_source_fence.py']=s
authority={};exec(compile(sources['main3_source_authority.py'],'<pure-public-authority>','exec'),authority)
assert authority['SDK_SOURCE_PINS']==capture['publicSdkPins'],'fresh SDK source set changed; requires separate source qualification'
OUT.mkdir(exist_ok=False)
for name,s in sources.items():ast.parse(s);(OUT/name).write_text(s)
pins={name:{'bytes':len(s.encode()),'sha256':sha(s.encode())} for name,s in sources.items()}
preparer=revise(old['preparerSource']);lines=preparer.splitlines(True)
indices=[i for i,l in enumerate(lines) if l.startswith('EXPECTED_PINS=')];assert len(indices)==1
lines[indices[0]]='EXPECTED_PINS='+repr(pins)+'\n';preparer=''.join(lines);ast.parse(preparer)
(WORK/'prepare_main3_api_r3.bound.py').write_text(preparer)
(WORK/'staging-api-r3.public.json').write_text(json.dumps({'sources':sources,'preparerSource':preparer},separators=(',',':')))
diff=''.join(''.join(difflib.unified_diff(old['sources'].get(n,'').splitlines(True),s.splitlines(True),fromfile='retained-failed-r2/'+n,tofile='fresh-source-r3/'+n)) for n,s in sources.items())
(WORK/'main3-api-r3.diff').write_text(diff)
manifest.update(schema='heptabao.mac-main3-api-source-derivation.r3',sourcePins=pins,
    preparer={'bytes':len(preparer.encode()),'sha256':sha(preparer.encode())},
    currentCapture=capture,
    retainedR2Status={'preflightJob':'1a1b1dc7351-fc05-7b2e','terminal':'failed','exitCode':1,
        'guardsPassed':108,'serviceActions':0,'httpRequests':0,'errorCode':'current_source_full_generation_exact'},
    previousPrivateQualificationBindingModified=False,fullNineFieldGenerationRuleUnchanged=True)
(WORK/'manifest-api-r3.public.json').write_text(json.dumps(manifest,indent=2)+'\n')
print(json.dumps(manifest,sort_keys=True))
