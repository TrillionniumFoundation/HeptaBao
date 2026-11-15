import os,json,hashlib,base64,shutil,subprocess,zlib,importlib.util,sys
sys.dont_write_bytecode=True
from pathlib import Path
root=Path('/Volumes/T5/hepta-vnext-recovery-20261013/continuation-20261018')
source=root/'source-07a3dda';target=root/'source-07a3dda-object-git';receipt=root/'source-07a3dda-object-git-materialization.json'
for p in (target,receipt):
 if os.path.lexists(p):raise RuntimeError('fresh_07a3dda_git_target_exists')
b=(root/'source-07a3dda-manifest.json').read_bytes();assert hashlib.sha256(b).hexdigest()=='84c27124f6dc213d2199c7cab5797d5cb22dabf4ad8b2947650ae8fa7928f8a8'
manifest=json.loads(b);assert manifest['commit']=='07a3dda57c2996787825ced49e630bb0bf7a30b9' and manifest['tree']=='8c2b23cd1c66ac16b466f16ea97c201e852125aa'
assert hashlib.sha256((source/'qa/openbao-acceptance/native_candidate_host_run.py').read_bytes()).hexdigest()=='587eb864f424b236fbc98e41fbc26c5e6c8713ded2e3dee0f2230df7447f66dd'
spec=importlib.util.spec_from_file_location('exact_07a3dda_checker',source/'qa/openbao-acceptance/native_candidate_host_run.py');mod=importlib.util.module_from_spec(spec);spec.loader.exec_module(mod)
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
commit=base64.b64decode("dHJlZSA4YzJiMjNjZDFjNjZhYzE2YjQ2NmYxNmVhOTdjMjAxZTg1MjEyNWFhCnBhcmVudCBiMjRjNmRlNzgzMWE3Mzg5ZTM5YWMwNjkyNzdhOWU4NWU4NThlZjk4CmF1dGhvciBRaWFuIFFJIDwxMDIxNTkyNDArUHJvZkhlcHRhQHVzZXJzLm5vcmVwbHkuZ2l0aHViLmNvbT4gMTc5MjQwMjIzNSAtMDQwMApjb21taXR0ZXIgUWlhbiBRSSA8MTAyMTU5MjQwK1Byb2ZIZXB0YUB1c2Vycy5ub3JlcGx5LmdpdGh1Yi5jb20+IDE3OTI0MDIyMzUgLTA0MDAKCkZpeCBuYXRpdmUgSlNPTiBuZWdhdGl2ZSB6ZXJvIGFuZCBMQU4gc2VlZCBsb2cgY3VzdG9keTsgcmV0YWluIFI1IGFjdHVhbCBob3N0IGFuZCBBdXRoQnVzIGV2aWRlbmNlCgpQcmVzZXJ2ZSBudW1lcmljIHZhbHVlcyB3aGVuIGJ1aWxkaW5nIHRoZSBwdWJsaWMgcmVzcG9uc2UgZW52ZWxvcGUgYW5kIHZlcmlmeSBleGFjdCBzbmFwc2hvdCBIVFRQIGhpc3RvcnkuIENyZWF0ZSBmaXh0dXJlIHNlZWQgbG9ncyB3aXRoIHByaXZhdGUgcGVybWlzc2lvbnMgc28gdGhlIGV4aXN0aW5nIERhcndpbiB3YXRjaGRvZyBjYW4gYWRtaXQgdGhlbS4KCkluY2x1ZGUgdGhlIHJldmlld2VkIE9wZW5BSSBTREsgQ09OTkVDVCBmaXh0dXJlIGFuZCBuYXRpdmUgY29sZC1yZWNvdmVyeSBqb2ludCBkcml2ZXIuIFJldGFpbiBleGFjdCBSNSBtYWluLCBNYWMsIFgyMzAgYW5kIENJIDU1LWNhc2UgcmVjZWlwdHMsIE1hYyBmdWxsMzQgbWlncmF0aW9uL3Jlc3RvcmUsIEhUVFAzIGFuZCBMQU4gZmFpbHVyZXMsIGFuZCB0aGUgc2NvcGVkIG5hdGl2ZS9PcGVuQUkgMTQxLWNoZWNrIGpvaW50IHJlc3VsdCB3aXRob3V0IHByb21vdGluZyBwcm9kdWN0aW9uIG9yIHJlcGxhY2VtZW50IGVsaWdpYmlsaXR5Lg==",validate=True)
assert len(commit)==868 and hashlib.sha256(commit).hexdigest()=='c097b4e52a49cb8e732696ff1c5440fa4327ba2973ec83f784b81acec7f8e58f'
put('commit',commit,manifest['commit']);(target/'.git/shallow').write_text(manifest['commit']+'\n');(target/'.git/HEAD').write_text(manifest['commit']+'\n')
git('read-tree','HEAD');status=git('status','--porcelain','--untracked-files=all').stdout;assert status==b''
actual=git('rev-parse','HEAD').stdout.decode().strip();actual_tree=git('rev-parse','HEAD^{tree}').stdout.decode().strip();assert actual==manifest['commit'] and actual_tree==manifest['tree'];fsck=git('fsck','--full','--strict')
after=mod.verify_tree(source,manifest)
out={'status':'verified_exact_git_object_checkout','source':str(target),'commit':actual,'tree':actual_tree,'verified_files':len(manifest['files']),'git_objects_written':len(written),'source_dirty':False,'git_fsck_returncode':fsck.returncode,'git_fsck_output_sha256':hashlib.sha256(fsck.stdout+fsck.stderr).hexdigest(),'commit_object_bytes':len(commit),'commit_object_sha256':hashlib.sha256(commit).hexdigest(),'source_before':before,'candidate_before_git':candidate,'source_after':after,'finished_utc':mod.utc()}
mod.write_json(receipt,out);print(json.dumps(out))

