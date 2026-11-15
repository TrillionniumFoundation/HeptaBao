import ast,hashlib,json,os
payload=json.load(__import__('sys').stdin)
assert set(payload)=={'runner','candidate','patch_blocks'}
runner=payload['runner'].encode()
candidate=payload['candidate'].encode()
def blob(raw):return hashlib.sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest()
assert blob(runner)=='4f6489dbb3e9b52a9e55df162d8a2f0cc0ed1b8a'
assert blob(candidate)=='807917a7839998a2cc69b6ea437c0c5fa2a1d4a5'
ast.parse(runner)
environment={k:os.environ[k] for k in ('HOME','USER','LOGNAME','LANG','LC_ALL','TZ') if k in os.environ}
environment.update(PATH='/opt/homebrew/bin:/usr/bin:/bin',LC_ALL='C',PYTHONDONTWRITEBYTECODE='1')
os.environ.clear();os.environ.update(environment)
namespace={'__name__':'__main__','__file__':'/Volumes/T5/hepta-vnext-recovery-20261013/continuation-20261106-jwt-default-diagnosis-r1/diagnose_existing_mac_binary.py',
           'SELF_SOURCE':runner,'CANDIDATE_SOURCE':candidate,'PATCH_BLOCKS':payload['patch_blocks']}
exec(compile(runner,namespace['__file__'],'exec'),namespace)
