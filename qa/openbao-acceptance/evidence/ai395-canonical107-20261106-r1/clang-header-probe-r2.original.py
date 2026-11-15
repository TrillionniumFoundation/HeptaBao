from pathlib import Path
import ctypes,datetime,hashlib,json,os,re,stat,tarfile,tomllib
root=Path('/home/qq/heptabao-kv2-ha-convergence-4bde9-authbus-20261106-r1')
out=root/'clang-header-probe-r2'
library=Path('/usr/lib/x86_64-linux-gnu/libclang-21.so.21')
includes=Path('/usr/lib/gcc/x86_64-linux-gnu/15/include')
os.umask(0o077);out.mkdir(mode=0o700)
r={'schema':'heptabao.ai395-actual-bindgen-wrapper-header-locator-probe.v2','at_utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),'status':'running','existing_toolchain_only':True,'tools_installed':False,'rust_build_executed':False,'product_binary_executed':False,'production_changed':False,'not_a_complete_bindgen_or_normal107_result':True,'normal107_qualified':False,'registry_private_path_omitted':True,'cases':[]}
def digest(p):
 with p.open('rb') as f:return hashlib.file_digest(f,'sha256').hexdigest()
def pin(p):
 q=p.resolve(strict=True);s=q.stat();return {'path':str(p),'resolved':str(q),'bytes':s.st_size,'sha256':digest(q),'identity':[s.st_dev,s.st_ino,s.st_mode,s.st_uid,s.st_gid,s.st_nlink,s.st_mtime_ns,s.st_ctime_ns]}
def need(ok,label):
 if not ok:raise RuntimeError(label)
try:
 need(digest(library)=='2c262ccd53ce702daa87c95aa84b2936e13c14f974504dc58f3ed93b12def23b','observed_libclang_pin')
 need(digest(includes/'stddef.h')=='472a84e536689fc48e861b2415b229742e133d09bbf1c8fd8e0fe89ab5712f04','observed_gcc15_stddef_pin')
 lock=tomllib.loads((root/'source-4bde9/Cargo.lock').read_text())
 locked=[p for p in lock['package'] if p['name']=='aws-lc-sys' and p['version']=='0.41.0']
 need(len(locked)==1,'one_locked_aws_lc_package')
 archives=[p for p in Path('/home/qq/.cargo/registry/cache').glob('*/aws-lc-sys-0.41.0.crate') if p.is_file() and not p.is_symlink() and digest(p)==locked[0]['checksum']]
 sources=[p for p in Path('/home/qq/.cargo/registry/src').glob('*/aws-lc-sys-0.41.0') if p.is_dir() and not p.is_symlink()]
 need(len(archives)==len(sources)==1,'one_existing_locked_aws_lc_archive_and_source')
 package=sources[0];prefix='aws-lc-sys-0.41.0/'
 source_pins={}
 with tarfile.open(archives[0],'r:gz') as archive:
  for member in archive.getmembers():
   if not member.isfile() or not member.name.startswith(prefix):continue
   rel=member.name[len(prefix):]
   if not (rel.startswith(('include/','generated-include/','aws-lc/include/')) or rel in ('builder/main.rs','builder/sys_bindgen.rs')):continue
   p=package/rel
   need(not p.is_symlink() and p.is_file(),'locked_source_member_not_regular')
   value=hashlib.sha256(archive.extractfile(member).read()).hexdigest()
   need(digest(p)==value,'locked_source_member_mismatch')
   source_pins[rel]=value
 main=(package/'builder/main.rs').read_text()
 roots=[]
 for function,relative in [('get_rust_include_path','include'),('get_generated_include_path','generated-include'),('get_aws_lc_include_path','aws-lc/include')]:
  found=re.search(r'fn '+function+r'\([^)]*\)[^{]*\{([^}]+)\}',main)
  need(found is not None,'actual_include_function_missing')
  body=found.group(1)
  literal_parts=re.findall(r'\.join\("([^"]+)"\)',body)
  need('/'.join(literal_parts)==relative,'actual_include_function_changed')
  roots.append(package/relative)
 header=package/'include/rust_wrapper.h'
 need(source_pins['include/rust_wrapper.h']=='b0a3f8f3f36f979bf77c83e7f4643e2d76cda65eadbded5d7c1720d93925193d','observed_actual_bindgen_wrapper_pin')
 prior_stdout=root/'build-test-r1/13-normal-release-build.stdout'
 need(digest(prior_stdout)=='56a4bd10cbbafe96daba7372f701acbe991a96da16e4f9029121f85d66d57171','original_cargo_json_pin')
 cargo=[json.loads(line) for line in prior_stdout.read_text().splitlines() if line]
 packages=[x for x in cargo if x.get('reason')=='compiler-artifact' and re.search(r'aws-lc-sys(?:@| )0\.41\.0',x.get('package_id',''))]
 need(packages,'actual_failed_package_features_unavailable')
 features={tuple(sorted(x.get('features',[]))) for x in packages}
 need(len(features)==1,'actual_failed_package_features_ambiguous')
 features=list(next(iter(features)))
 r['original_package_features']=features
 pins={'libclang':pin(library),'cc':pin(Path('/usr/bin/cc'))}
 gcc_pins={}
 for p in sorted(includes.rglob('*')):
  if p.is_file() and not p.is_symlink():gcc_pins[str(p.relative_to(includes))]=digest(p)
 r['host_tool_pins_before']=pins
 r['gcc_standard_header_tree']={'path':str(includes),'files':len(gcc_pins),'manifest_sha256':hashlib.sha256(json.dumps(gcc_pins,sort_keys=True,separators=(',',':')).encode()).hexdigest(),'headers':{name:gcc_pins[name] for name in ('stddef.h','stdint.h','stdarg.h')}}
 r['locked_aws_lc_source']={'archive_sha256':locked[0]['checksum'],'verified_source_files':len(source_pins),'source_manifest_sha256':hashlib.sha256(json.dumps(source_pins,sort_keys=True,separators=(',',':')).encode()).hexdigest(),'wrapper_sha256':source_pins['include/rust_wrapper.h'],'builder_main_sha256':source_pins['builder/main.rs'],'builder_sys_bindgen_sha256':source_pins['builder/sys_bindgen.rs'],'base_header_sha256':source_pins['aws-lc/include/openssl/base.h']}
 class CXString(ctypes.Structure):
  _fields_=[('data',ctypes.c_void_p),('private_flags',ctypes.c_uint)]
 lib=ctypes.CDLL(str(library))
 for name,args,rest in [
 ('clang_getClangVersion',[],CXString),('clang_getCString',[CXString],ctypes.c_char_p),('clang_disposeString',[CXString],None),
 ('clang_createIndex',[ctypes.c_int,ctypes.c_int],ctypes.c_void_p),('clang_disposeIndex',[ctypes.c_void_p],None),
 ('clang_parseTranslationUnit2',[ctypes.c_void_p,ctypes.c_char_p,ctypes.POINTER(ctypes.c_char_p),ctypes.c_int,ctypes.c_void_p,ctypes.c_uint,ctypes.c_uint,ctypes.POINTER(ctypes.c_void_p)],ctypes.c_int),
 ('clang_disposeTranslationUnit',[ctypes.c_void_p],None),('clang_getNumDiagnostics',[ctypes.c_void_p],ctypes.c_uint),
 ('clang_getDiagnostic',[ctypes.c_void_p,ctypes.c_uint],ctypes.c_void_p),('clang_getDiagnosticSeverity',[ctypes.c_void_p],ctypes.c_uint),
 ('clang_getDiagnosticSpelling',[ctypes.c_void_p],CXString),('clang_disposeDiagnostic',[ctypes.c_void_p],None)]:
  f=getattr(lib,name);f.argtypes=args;f.restype=rest
 def string(value):
  try:
   p=lib.clang_getCString(value);return p.decode(errors='replace') if p else ''
  finally:lib.clang_disposeString(value)
 r['libclang_version']=string(lib.clang_getClangVersion())
 common=['-x','c','--target=x86_64-unknown-linux-gnu']
 for path in roots:common+=['-I',str(path)]
 if 'ssl' in features:common+=['-DAWS_LC_RUST_INCLUDE_SSL']
 r['actual_wrapper_relative_path']='include/rust_wrapper.h'
 r['actual_builder_clang_args']=[x.replace(str(package),'[locked-aws-lc-source]') for x in common]
 for label,extra in [('original-no-resource-header',[]),('existing-gcc15-standard-header-locator',['-isystem',str(includes)])]:
  args=common+extra
  raw=(ctypes.c_char_p*len(args))(*[x.encode() for x in args]);index=lib.clang_createIndex(0,0);unit=ctypes.c_void_p();diagnostics=[]
  need(bool(index),'libclang_index_unavailable')
  try:
   code=lib.clang_parseTranslationUnit2(index,str(header).encode(),raw,len(args),None,0,0,ctypes.byref(unit))
   if unit.value:
    for n in range(lib.clang_getNumDiagnostics(unit)):
     diag=lib.clang_getDiagnostic(unit,n)
     try:diagnostics.append({'severity':lib.clang_getDiagnosticSeverity(diag),'message':string(lib.clang_getDiagnosticSpelling(diag)).replace(str(package),'[locked-aws-lc-source]')})
     finally:lib.clang_disposeDiagnostic(diag)
  finally:
   if unit.value:lib.clang_disposeTranslationUnit(unit)
   lib.clang_disposeIndex(index)
  r['cases'].append({'label':label,'parser_return':code,'diagnostics':diagnostics,'fatal_or_error_count':sum(d['severity']>=3 for d in diagnostics),'added_header_locator':extra})
 baseline,candidate=r['cases']
 need(any('stddef.h' in d['message'] and 'not found' in d['message'] for d in baseline['diagnostics']),'original_missing_header_not_reproduced')
 need(candidate['parser_return']==0 and candidate['fatal_or_error_count']==0,'candidate_header_locator_failed')
 r['host_tool_pins_after']={'libclang':pin(library),'cc':pin(Path('/usr/bin/cc'))}
 need(r['host_tool_pins_after']==pins,'host_tool_changed')
 need(all(digest(package/rel)==value for rel,value in source_pins.items()),'locked_source_changed')
 need({str(p.relative_to(includes)):digest(p) for p in sorted(includes.rglob('*')) if p.is_file() and not p.is_symlink()}==gcc_pins,'gcc_header_tree_changed')
 need(digest(archives[0])==locked[0]['checksum'],'locked_archive_changed')
 r.update(status='passed',specific_missing_header_failure_reproduced_and_resolved=True,proposed_environment={'BINDGEN_EXTRA_CLANG_ARGS':'-isystem '+str(includes)},all_observed_inputs_unchanged=True)
except BaseException as e:
 r['status']='failed';r['failure']=str(e) if isinstance(e,RuntimeError) else type(e).__name__
finally:
 p=out/'result.public.json'
 with p.open('x') as f:json.dump(r,f,sort_keys=True,indent=2);f.write('\n');f.flush();os.fsync(f.fileno())
 print(json.dumps({'status':r['status'],'result':str(p),'normal107_qualified':False}),flush=True)
raise SystemExit(0 if r['status']=='passed' else 1)
