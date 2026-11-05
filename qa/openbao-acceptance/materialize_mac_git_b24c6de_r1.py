import os,json,hashlib,base64,shutil,subprocess,zlib,importlib.util,sys
sys.dont_write_bytecode=True
from pathlib import Path
root=Path('/Volumes/T5/hepta-vnext-recovery-20261013/continuation-20261018')
source=root/'source-b24c6de';target=root/'source-b24c6de-object-git';receipt=root/'source-b24c6de-object-git-materialization.json'
for p in (target,receipt):
 if os.path.lexists(p):raise RuntimeError('fresh_b24c6de_git_target_exists')
b=(root/'source-b24c6de-manifest.json').read_bytes();assert hashlib.sha256(b).hexdigest()=='739ffe3589e8b8c6ddca5efe56b4ef3d33a2633fce4451853413b14a6be6c3e1'
manifest=json.loads(b);assert manifest['commit']=='b24c6de7831a7389e39ac069277a9e85e858ef98' and manifest['tree']=='3356f0a94616e9e1804f497239f33546e16db577'
assert hashlib.sha256((source/'qa/openbao-acceptance/native_candidate_host_run.py').read_bytes()).hexdigest()=='587eb864f424b236fbc98e41fbc26c5e6c8713ded2e3dee0f2230df7447f66dd'
spec=importlib.util.spec_from_file_location('exact_b24c6de_checker',source/'qa/openbao-acceptance/native_candidate_host_run.py');mod=importlib.util.module_from_spec(spec);spec.loader.exec_module(mod)
before=mod.verify_tree(source,manifest);os.umask(0o077);shutil.copytree(source,target,copy_function=shutil.copy2,symlinks=False);candidate=mod.verify_tree(target,manifest)
env=dict(os.environ);env.update(GIT_CONFIG_NOSYSTEM='1',GIT_CONFIG_GLOBAL='/dev/null',GIT_TERMINAL_PROMPT='0')
def git(*args):return subprocess.run(['/usr/bin/git','-c','core.hooksPath=/dev/null','-c','init.templateDir=','-c','core.autocrlf=false','-c','core.fileMode=true',*args],cwd=target,env=env,capture_output=True,timeout=90,check=True)
git('init','-q');objects=target/'.git/objects';written=set()
def put(kind,content,expected=None):
 encoded=kind.encode()+b' '+str(len(content)).encode()+b'\0'+content;sha=hashlib.sha1(encoded).hexdigest()
 if expected is not None:assert sha==expected,'git_object_sha_mismatch'
 if sha not in written:
  p=objects/sha[:2]/sha[2:];p.parent.mkdir(exist_ok=True)
  with p.open('xb') as f:f.write(zlib.compress(encoded));f.flush();os.fsync(f.fileno())
  written.add(sha)
 return sha
tree={}
for f in manifest['files']:
 assert f['mode'] in ('100644','100755');put('blob',(target/f['path']).read_bytes(),f['sha']);node=tree;parts=f['path'].split('/')
 for part in parts[:-1]:node=node.setdefault(part,{})
 assert parts[-1] not in node;node[parts[-1]]=(f['mode'],f['sha'])
def trees(node):
 rows=[]
 for name,v in node.items():
  if isinstance(v,dict):mode='40000';sha=trees(v);key=name.encode()+b'/'
  else:mode,sha=v;key=name.encode()
  rows.append((key,mode.encode()+b' '+name.encode()+b'\0'+bytes.fromhex(sha)))
 return put('tree',b''.join(v for _,v in sorted(rows)))
assert trees(tree)==manifest['tree']
commit=base64.b64decode("dHJlZSAzMzU2ZjBhOTQ2MTZlOWUxODA0ZjQ5NzIzOWYzMzU0NmUxNmRiNTc3CnBhcmVudCA5NzcwYmRkNGNhNzdhYTgzMmVjODA4M2EwNTQ3NjA2MzdlOTJjZmExCmF1dGhvciBRaWFuIFFJIDwxMDIxNTkyNDArUHJvZkhlcHRhQHVzZXJzLm5vcmVwbHkuZ2l0aHViLmNvbT4gMTc5MjM5NzEyOSAtMDQwMApjb21taXR0ZXIgUWlhbiBRSSA8MTAyMTU5MjQwK1Byb2ZIZXB0YUB1c2Vycy5ub3JlcGx5LmdpdGh1Yi5jb20+IDE3OTIzOTcxMjkgLTA0MDAKCkZpeCBuYXRpdmUgc25hcHNob3QgSlNPTiBBY2NlcHQgY29tcGF0aWJpbGl0eSBhbmQgY29sZCBSZWFkSW5kZXggcmVhZGluZXNzCgpLZWVwIG9yaWdpbmFsIGFjY2VwdGFuY2Ugc2VsZWN0b3JzIGFuZCBidWRnZXRzOyBwcmVzZXJ2ZSBhY3R1YWwgTWFjLCBMaW51eCwgWDIzMCBhbmQgU0RLIGZhaWx1cmVzIGFsb25nc2lkZSBwYXNzZWQgcnVucy4gQmluZCBEYXJ3aW4gY2hpbGQgY3VzdG9keSBmaXhlcyBhbmQgZm9yZWdyb3VuZCBMQU4gd2F0Y2hkb2cgcHJlcGFyYXRpb24gdG8gdGhlIHJldmlld2VkIHNvdXJjZSBjbG9zdXJlLiBQcm9kdWN0aW9uIG1pZ3JhdGlvbiBhbmQgZnVsbCByZXBsYWNlbWVudCByZW1haW4gdW5xdWFsaWZpZWQu",validate=True)
assert len(commit)==618 and hashlib.sha256(commit).hexdigest()=='734853bc528c877c93e6bded9065c3071b6598e103101bf8e6fe73f3a5e63d2e'
put('commit',commit,manifest['commit']);(target/'.git/shallow').write_text(manifest['commit']+'\n');(target/'.git/HEAD').write_text(manifest['commit']+'\n')
git('read-tree','HEAD');status=git('status','--porcelain','--untracked-files=all').stdout;assert status==b''
actual=git('rev-parse','HEAD').stdout.decode().strip();actual_tree=git('rev-parse','HEAD^{tree}').stdout.decode().strip();assert actual==manifest['commit'] and actual_tree==manifest['tree'];fsck=git('fsck','--full','--strict')
after=mod.verify_tree(source,manifest)
out={'status':'verified_exact_git_object_checkout','source':str(target),'commit':actual,'tree':actual_tree,'verified_files':len(manifest['files']),'git_objects_written':len(written),'source_dirty':False,'git_fsck_returncode':fsck.returncode,'git_fsck_output_sha256':hashlib.sha256(fsck.stdout+fsck.stderr).hexdigest(),'commit_object_bytes':len(commit),'commit_object_sha256':hashlib.sha256(commit).hexdigest(),'source_before':before,'candidate_before_git':candidate,'source_after':after,'finished_utc':mod.utc()}
mod.write_json(receipt,out);print(json.dumps(out))

