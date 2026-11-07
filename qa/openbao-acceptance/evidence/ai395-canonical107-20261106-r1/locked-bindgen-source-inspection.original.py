from pathlib import Path
import datetime,hashlib,json,os,re,tarfile,tomllib
root=Path('/home/qq/heptabao-kv2-ha-convergence-4bde9-authbus-20261106-r1')
out=root/'clang-bindgen-source-inspection-r1';os.umask(0o077);out.mkdir(mode=0o700)
r={'schema':'heptabao.ai395-locked-bindgen-source-inspection.v1','at_utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),'status':'running','rust_build_executed':False,'production_changed':False,'registry_private_path_omitted':True}
def digest(p):
 with p.open('rb') as f:return hashlib.file_digest(f,'sha256').hexdigest()
try:
 lock=tomllib.loads((root/'source-4bde9/Cargo.lock').read_text());p=[x for x in lock['package'] if x['name']=='aws-lc-sys' and x['version']=='0.41.0'];assert len(p)==1
 archives=[x for x in Path('/home/qq/.cargo/registry/cache').glob('*/aws-lc-sys-0.41.0.crate') if x.is_file() and not x.is_symlink() and digest(x)==p[0]['checksum']];assert len(archives)==1
 sources=[x for x in Path('/home/qq/.cargo/registry/src').glob('*/aws-lc-sys-0.41.0') if x.is_dir() and not x.is_symlink()];assert len(sources)==1
 prefix='aws-lc-sys-0.41.0/';snippets=[];wrappers=[]
 with tarfile.open(archives[0],'r:gz') as archive:
  names=archive.getnames()
  for name in names:
   if not name.startswith(prefix):continue
   rel=name[len(prefix):]
   if rel.startswith('include/') and rel.endswith('.h'):wrappers.append(rel)
   if not (rel.startswith('builder/') and rel.endswith('.rs')):continue
   data=archive.extractfile(name).read();on_disk=sources[0]/rel
   assert on_disk.is_file() and digest(on_disk)==hashlib.sha256(data).hexdigest()
   lines=data.decode().splitlines();indexes=set()
   for i,line in enumerate(lines):
    if any(term in line for term in ('bindgen::','clang_arg','header(','header_contents','generate_bindings','aws_lc_bindings','clang_args','include_paths')):
     indexes.update(range(max(0,i-7),min(len(lines),i+10)))
   if indexes:snippets.append({'relative_path':rel,'sha256':hashlib.sha256(data).hexdigest(),'lines':[{'line':i+1,'text':lines[i]} for i in sorted(indexes)]})
  wrappers_data=[]
  for rel in wrappers:
   data=archive.extractfile(prefix+rel).read();on_disk=sources[0]/rel
   assert on_disk.is_file() and digest(on_disk)==hashlib.sha256(data).hexdigest()
   wrappers_data.append({'relative_path':rel,'bytes':len(data),'sha256':hashlib.sha256(data).hexdigest(),'text':data.decode() if len(data)<16384 else None})
  actual='aws-lc/include/openssl/base.h';data=archive.extractfile(prefix+actual).read()
  assert digest(sources[0]/actual)==hashlib.sha256(data).hexdigest()
 r.update(status='passed',archive_sha256=p[0]['checksum'],actual_failed_base_header_sha256=hashlib.sha256(data).hexdigest(),build_source_snippets=snippets,root_include_headers=wrappers_data,selected_source_matches_locked_archive=True)
except BaseException as e:r.update(status='failed',error_type=type(e).__name__)
finally:
 path=out/'result.public.json'
 with path.open('x') as f:json.dump(r,f,sort_keys=True,indent=2);f.write('\n');f.flush();os.fsync(f.fileno())
 print(json.dumps({'status':r['status'],'result':str(path),'rust_build_executed':False}),flush=True)
raise SystemExit(0 if r['status']=='passed' else 1)
