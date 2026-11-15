#!/usr/bin/env python3
"""Derive a new synthetic fixture from preserved r1 sources; never edits r1."""
from pathlib import Path
import ast,difflib,hashlib,json
ROOT=Path('/workspace/scratch/c9fe536787d9/fresh-r2-work')
SOURCE=ROOT/'original';PATCHED=ROOT/'patched';OUTPUT=ROOT/'source-r2'
OLD={
'mac_public_code_pin_excerpt_r1.py':'7ff262e7ff913eb97aab77855d988cb3a6af8cab5ea9c77940a2782afd91ca4f',
'mac_owned_commands_r1.py':'eb676e6dedb6d594d944e921738cf9b384f2a98a37ee2bd1fa5433b848a36867',
'mac_t5_volume_guard_r1.py':'5b5a9d5dc2af336bdf0decb2d3bdaaea363e8038dc48873c38c02fb50ba06699',
'mac_owned_launchd_r3.py':'045a93a547ba5237b2d787b6e1724ca9ae0c8529b43736d7f98f28cf46078cdf',
'mac_native_process_observer_r1.py':'cc0fa9917d05c6dc2c295594f980c1f77d089c1196e6279a14f2fdaf2d77ae9b',
'mac_owned_unreaped_r1.py':'a143ba334159931d530b49a55c24471f56fa1b62f1e1012e12c75e21f3c22b1d',
'mac_current_server_owner_r1.py':'bb489d899e7284d2d4eb31008d40f8a6bcc7025b8b1ac7628551a02d83a4668e',
'fresh_synthetic_controller_r1.py':'2b22d8e7b83d3bb9b4b26766349eaf5f50bdffd2dca7166c8dca35761727479a',
'test_fresh_synthetic_controller_r1.py':'5b4d3f2cc67196ef2eab036467493edcb90db5e5902e92619b5d78236f754e7a',
'tls_complete_http_probe.py':'e8a060d7d6020f7d62f1db56fb07a82eda57987ae7d181dab1a3af88ebe0329a'}
PATCH={
'mac_owned_unreaped_r1.py':'d735a9e9330e1260d44ad9e4c854d50094e20d85fe5633ddd9042281b3346298',
'mac_owned_commands_r1.py':'71a11bf9a0510c991b78c9bc3f094f315bf4914485b9cfda81c6e501eaf73530',
'tls_complete_http_probe.py':'7e92967416e0dcdc80b9c5d56e0655775630cef9198aba5541fa75bbf98c42fc',
'test_suid_ps_tls_r2.py':'261d38cdf25e873a99fc99c901d1cefcbdc0d434388877caa26d57cac7496bc6'}
def sha(raw):return hashlib.sha256(raw).hexdigest()
def revision(text):
    for stem in ('mac-fresh-synthetic-launchd','mac-fresh-synthetic-preparation',
                 'mac-fresh-synthetic-journal','mac-fresh-synthetic'):
        text=text.replace(stem+'-20261106-r1',stem+'-20261106-r2')
    for name in ('preparation','preparation-terminal','journal','startup-qualification'):
        text=text.replace('heptabao.mac-fresh-synthetic-'+name+'.r1','heptabao.mac-fresh-synthetic-'+name+'.r2')
    return text
sources={};originals={}
for name,pin in OLD.items():
    raw=(SOURCE/name).read_bytes();assert sha(raw)==pin, name
    originals[name]=raw.decode()
    sources[name]=revision(raw.decode())
for name,pin in PATCH.items():
    raw=(PATCHED/name).read_bytes();assert sha(raw)==pin,name
    sources[name]=raw.decode()
key='fresh_synthetic_controller_r1.py'
old="'test_fresh_synthetic_controller_r1.py')"
new="'test_fresh_synthetic_controller_r1.py','test_suid_ps_tls_r2.py')"
assert sources[key].count(old)==1
sources[key]=sources[key].replace(old,new)
OUTPUT.mkdir(exist_ok=True)
for name,source in sources.items():
    ast.parse(source);(OUTPUT/name).write_text(source)
pins={name:{'bytes':len(source.encode()),'sha256':sha(source.encode())} for name,source in sources.items()}
preparer=(SOURCE/'prepare_fresh_synthetic_r1.py').read_bytes()
assert sha(preparer)=='798629bdc4422d1521f688315ce3660eaa1804b6d121524439009ebba132954d'
preparer=revision(preparer.decode())
lines=preparer.splitlines(True)
found=[i for i,l in enumerate(lines) if l.startswith('EXPECTED_PINS=')]
assert len(found)==1
lines[found[0]]='EXPECTED_PINS='+repr(pins)+'\n'
preparer=''.join(lines);ast.parse(preparer)
(ROOT/'prepare_fresh_synthetic_r2.bound.py').write_text(preparer)
payload={'sources':sources,'preparerSource':preparer}
(ROOT/'staging-request-payload-r2.public.json').write_text(json.dumps(payload,separators=(',',':')))
diff=''.join(''.join(difflib.unified_diff(originals.get(n,'').splitlines(True),s.splitlines(True),fromfile='a/'+n,tofile='b/'+n)) for n,s in sources.items())
(ROOT/'complete-derivation-r2.diff').write_text(diff)
manifest={'schema':'heptabao.mac-fresh-synthetic-r2-source-derivation.r1','sourcePins':pins,
    'preparer':{'bytes':len(preparer.encode()),'sha256':sha(preparer.encode())},'originalSourcePins':OLD,
    'fixedPsExactArgvOnly':True,'libprocDenialNotAuthority':True,
    'systemPsNoOtherGroupOrDirectChild':True,'serviceUid501BirthGateUnchanged':True,
    'wrapperSeconds':30,'execObservationSeconds':10,'probeSeconds':15,
    'managerSeconds':600,'cleanupSeconds':60,'childCleanupCaps':{'term':1,'wait':5,'group':3,'psMax':4},
    'originalFailedFixturesModified':False,'productionAdmitted':False}
(ROOT/'source-manifest-r2.public.json').write_text(json.dumps(manifest,indent=2)+'\n')
print(json.dumps(manifest,sort_keys=True))
