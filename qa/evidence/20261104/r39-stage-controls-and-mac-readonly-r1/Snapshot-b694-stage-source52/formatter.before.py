import hashlib,json,os,signal,stat,subprocess,sys,time
from pathlib import Path
START=time.monotonic(); LIMIT=50.0
ROOT=Path('/home/qian-qi/heptabao-native-snapshot-forward-8c95fb0a-format-20261106-r1')
SRC=ROOT
SOURCE=Path('/home/qian-qi/heptabao-native-snapshot-forward-source-8c95fb0a-20261106-r1/source')
FMT=Path('/home/qian-qi/.rustup/toolchains/1.98.0-x86_64-unknown-linux-gnu/bin/rustfmt')
FMT_SHA='5005cdcd39ded526dca8fa6ccd716d42fc7da54469034e055dbf54649bec7877'
EXPECTED={"authenticated_peer_frame.rs":["02b1f11284b1463a3bbd2f35b2f7173a7a4d42758214b4cb73db7f497964caab","cd3c37ffaaaada293f3ab31727cfcd99206f551d9851fbfc6ab5ef06ccb4fac4"],"lib.rs":["f7eac8103954260134e244a1d5d5bf0045ed74f0d7123a01ac5f0b6b7089e7b8","9719e910990ebabe8d4d84e940ec942d1a92f13cec6f1a776934ae66f0d61521"],"native_snapshot_body.rs":[None,"c5371d4d81da56be70655bd618d7fbe321ca52df531cd30f33b92dd014a903a5"],"native_snapshot_body_tests.rs":[None,"c656de0f4ef9b627210e46323f2436adc4b3392d8097cfddcfdc29f2661054dc"],"native_snapshot_peer.rs":[None,"0981114047274df0e10fb986e8db70abd04a1f3a3efa2e3fb0ab2020005a1d14"],"native_snapshot_peer_tests.rs":[None,"aad72978eebeb7183c422cce15786049e860141a3526320b34f1f5f2d8fc7674"],"auth_forward_actor.rs":["8daeaf6bb0336eb1515479d69d6549fdd808b3d982940c53e4a36f6f67e9bdad","c14d38acecd53ecd6583556bcf5d0caf1e799a1a85c59bb77ef5ed09c88048c6"],"auth_snapshot_forward_actor_tests.rs":[None,"8bdf60ffd25054dc02c87e017c79801599ed7f37b8ce437455305e5a6bc5ff61"],"ha.rs":["a56ab6524b658b204cd998fc054ae5124ed615420ded443517bbf49988d6fd1c","b3cd73a6b008189838d131626fec259e498c865e8965d8cb4eede9d702b8f99d"],"ha_snapshot_forward.rs":[None,"d82de887f32993f0db1c0269bd44579f09673c431d4421a5b88c97fe5b432c0f"],"http.rs":["6d90383db0dabca25b6f6806e2b5923352976f4c4a69b2cce9a0a2dde7d727eb","47911a458e22757f47349ef1ca85124ea005d6de30055d456483772f2b577eb2"],"http_snapshot.rs":["1cc98a78d6a037a47456b7c6b93dc13647a261e8217f12a6a4edff3d91fe41e2","c97b724772726f15464abb39539136e3630afa9ffd7aba1e0210396aaee09bc1"],"service.rs":["6df7278a7b90363fe25a563e10e29db35f47868a2d1d1ea225c91c1b9b6add7d","c6fcb7631d424c16b5f86530570172b61f2b090d71384516d267ffaf7ee1dc89"],"service_forward_delivery.rs":["8581fa455395fcdf3933e67360c677d2f53bdcefa8c86c4199d6c7948cad5e26","097371c6ec8a41d95b727fb41be00524dac6a39bdd41f991cbab51b7055d438a"],"service_snapshot_forward.rs":[None,"70cfadda87cad016af530310c525c94e04b6e2e3df5353cc2762bc91d08570bd"],"service_snapshot_forward_client.rs":[None,"786eb9ec00fc1d8d82e78793da18c9b9b33b02609c80153b0fd960de4b75dc17"],"service_snapshot_forward_file.rs":[None,"36256ca40029f4bdd57d961f4c75d020fa089aa59ebc624d8271d28ff6b8c14e"],"service_snapshot_forward_source.rs":[None,"86b55dde688720321fce0c2fdfc59a18a6a185911d9725d6f9b4afb8e71b2062"],"service_snapshot_forward_wire.rs":[None,"458dc1a5c54dd9ee128030012c48e6a800b5e886233392894e485fdfc42fade7"],"service_snapshot_forward_wire_tests.rs":[None,"c189b6999fef57fe2a5c6fc221c49647323c609f31f6d65a2eda6bcb682668cb"],"service_snapshot_transfer.rs":["022be62ccaf26a335103dc106be432d7b8896768cace056e649b65ca920e97b9","3925de0802e77fc331b6e02a96155040a4bbe580cac0fc5619b135875ffecfd5"],"service_snapshot_v6_ha.rs":["d3d6da2c49338d51565b381444cd91c8c4c7b7458b509189c8115087aff8d29a","43dcba00a64eb1602aa84c7c753199db6a4f748a90426f46a6aa9ea44f29d855"],"service_snapshot_v6_ha_restore.rs":["3802288e0f2e3f58b94df509c928467fa2d3d11ee47bb9c68128c6143b9138ff","f0849c391e82b82a195779db8519245b7f27446680458b58b39ba9d034d2876c"]}
SOURCE_SIZES={"authenticated_peer_frame.rs":6204,"lib.rs":85408,"native_snapshot_body.rs":15545,"native_snapshot_body_tests.rs":7450,"native_snapshot_peer.rs":23126,"native_snapshot_peer_tests.rs":24050,"auth_forward_actor.rs":5048,"auth_snapshot_forward_actor_tests.rs":2135,"ha.rs":171691,"ha_snapshot_forward.rs":6330,"http.rs":232657,"http_snapshot.rs":38272,"service.rs":519343,"service_forward_delivery.rs":29010,"service_snapshot_forward.rs":8798,"service_snapshot_forward_client.rs":18255,"service_snapshot_forward_file.rs":1811,"service_snapshot_forward_source.rs":17315,"service_snapshot_forward_wire.rs":15616,"service_snapshot_forward_wire_tests.rs":9844,"service_snapshot_transfer.rs":52229,"service_snapshot_v6_ha.rs":13609,"service_snapshot_v6_ha_restore.rs":46836}
FORMAT_OUTPUT_CAPS={"authenticated_peer_frame.rs":262144,"lib.rs":262144,"native_snapshot_body.rs":262144,"native_snapshot_body_tests.rs":262144,"native_snapshot_peer.rs":262144,"native_snapshot_peer_tests.rs":262144,"auth_forward_actor.rs":262144,"auth_snapshot_forward_actor_tests.rs":262144,"ha.rs":262144,"ha_snapshot_forward.rs":262144,"http.rs":262144,"http_snapshot.rs":262144,"service.rs":655360,"service_forward_delivery.rs":262144,"service_snapshot_forward.rs":262144,"service_snapshot_forward_client.rs":262144,"service_snapshot_forward_file.rs":262144,"service_snapshot_forward_source.rs":262144,"service_snapshot_forward_wire.rs":262144,"service_snapshot_forward_wire_tests.rs":262144,"service_snapshot_transfer.rs":262144,"service_snapshot_v6_ha.rs":262144,"service_snapshot_v6_ha_restore.rs":262144}
SOURCE_RELATIVE={"authenticated_peer_frame.rs":"crates/heptabao-ha-service/src/authenticated_peer_frame.rs","lib.rs":"crates/heptabao-ha-service/src/lib.rs","native_snapshot_body.rs":"crates/heptabao-ha-service/src/native_snapshot_body.rs","native_snapshot_body_tests.rs":"crates/heptabao-ha-service/src/native_snapshot_body_tests.rs","native_snapshot_peer.rs":"crates/heptabao-ha-service/src/native_snapshot_peer.rs","native_snapshot_peer_tests.rs":"crates/heptabao-ha-service/src/native_snapshot_peer_tests.rs","auth_forward_actor.rs":"crates/heptabao-server/src/auth_forward_actor.rs","auth_snapshot_forward_actor_tests.rs":"crates/heptabao-server/src/auth_snapshot_forward_actor_tests.rs","ha.rs":"crates/heptabao-server/src/ha.rs","ha_snapshot_forward.rs":"crates/heptabao-server/src/ha_snapshot_forward.rs","http.rs":"crates/heptabao-server/src/http.rs","http_snapshot.rs":"crates/heptabao-server/src/http_snapshot.rs","service.rs":"crates/heptabao-server/src/service.rs","service_forward_delivery.rs":"crates/heptabao-server/src/service_forward_delivery.rs","service_snapshot_forward.rs":"crates/heptabao-server/src/service_snapshot_forward.rs","service_snapshot_forward_client.rs":"crates/heptabao-server/src/service_snapshot_forward_client.rs","service_snapshot_forward_file.rs":"crates/heptabao-server/src/service_snapshot_forward_file.rs","service_snapshot_forward_source.rs":"crates/heptabao-server/src/service_snapshot_forward_source.rs","service_snapshot_forward_wire.rs":"crates/heptabao-server/src/service_snapshot_forward_wire.rs","service_snapshot_forward_wire_tests.rs":"crates/heptabao-server/src/service_snapshot_forward_wire_tests.rs","service_snapshot_transfer.rs":"crates/heptabao-server/src/service_snapshot_transfer.rs","service_snapshot_v6_ha.rs":"crates/heptabao-server/src/service_snapshot_v6_ha.rs","service_snapshot_v6_ha_restore.rs":"crates/heptabao-server/src/service_snapshot_v6_ha_restore.rs"}
FORMAT_CONFIG=b'edition = "2024"\n'
FORMAT_CONFIG_SHA='f32d2f03b3f4b1e295c79ed49d543f1205c7dac7c3dc74f05a5a27af4fea0584'
os.umask(0o077)
def remain():
 r=LIMIT-(time.monotonic()-START)
 if r<=0: raise RuntimeError('format_total_deadline')
 return r
def sha(b): return hashlib.sha256(b).hexdigest()
def read_pin(p,expected_bytes=None):
 fd=os.open(p,os.O_RDONLY|os.O_NOFOLLOW)
 try:
  a=os.fstat(fd)
  if not stat.S_ISREG(a.st_mode) or a.st_uid!=os.getuid() or a.st_nlink!=1 or not 0<a.st_size<=8*1024*1024: raise RuntimeError('input_custody')
  if expected_bytes is not None and a.st_size!=expected_bytes: raise RuntimeError('source_size_pin')
  out=bytearray()
  while True:
   remain();part=os.read(fd,65536)
   if not part: break
   out.extend(part)
  b=os.fstat(fd);n=os.lstat(p)
  keys=lambda s:(s.st_dev,s.st_ino,s.st_size,s.st_mtime_ns,s.st_ctime_ns,s.st_mode,s.st_uid,s.st_gid,s.st_nlink)
  if keys(a)!=keys(b) or keys(a)!=keys(n): raise RuntimeError('input_changed')
  return bytes(out),{'path':str(p),'sha256':sha(out),'bytes':len(out),'identity':list(keys(a))}
 finally: os.close(fd)
def write_new(p,b):
 fd=os.open(p,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
 try:
  view=memoryview(b)
  while view:
   remain();n=os.write(fd,view)
   if n<=0: raise RuntimeError('short_write')
   view=view[n:]
  os.fsync(fd)
 finally: os.close(fd)
def sync_dir(p):
 fd=os.open(p,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
 try: os.fsync(fd)
 finally: os.close(fd)
report={'schema':'heptabao.native-snapshot-forward-input-rustfmt.v1','status':'failed','productExecuted':False,
 'compileExecuted':False,'productionChanged':False,'sourceCommit':'8c95fb0a8b2f61933a09b04986df2bafc9e7095c',
 'sourceTree':'f412f1524e08a56e23374897d329bfcf6295f4fe','sourceIdentityIsBaseOnly':False,
 'uncommittedCandidateInputs':False,'edition':'2024',
 'sourcePath':str(SOURCE),'sourceInputTotalBytes':1350582,
 'fixedFormattedOutputCaps':FORMAT_OUTPUT_CAPS,
 'fixedSourceRelativePaths':SOURCE_RELATIVE,
 'sourceIdentityFields':['dev','ino','size','mtime_ns','ctime_ns','full_mode','uid','gid','nlink'],
 'internalSeconds':50,'newRemoteSupervisorSeconds':60,'files':[],'children':[]}
created=False;tool_before=None;config_before=None;source_before={}
try:
 raw=sys.stdin.buffer.read(262145)
 if len(raw)>262144: raise RuntimeError('input_size')
 carrier=json.loads(raw)
 if set(carrier)!=set(EXPECTED): raise RuntimeError('input_names')
 if SOURCE.resolve(strict=True)!=SOURCE: raise RuntimeError('source_parent_symlink')
 data={}
 for name in EXPECTED:
  if carrier[name]!={'bytes':SOURCE_SIZES[name],'sha256':EXPECTED[name][1]}: raise RuntimeError('source_manifest_pin')
  path=SOURCE/SOURCE_RELATIVE[name]
  if path.resolve(strict=True)!=path: raise RuntimeError('source_symlink')
  original,pin=read_pin(path,SOURCE_SIZES[name])
  if len(original)!=SOURCE_SIZES[name] or sha(original)!=EXPECTED[name][1]: raise RuntimeError('candidate_input_pin')
  source_before[name]=pin
  data[name]=original.decode('utf-8')
 report['sourceInputsBefore']=source_before
 report['inputCarrierSha256']=sha(raw)
 if FMT.resolve(strict=True)!=FMT: raise RuntimeError('rustfmt_parent_symlink')
 tool_bytes,tool_before=read_pin(FMT)
 if sha(tool_bytes)!=FMT_SHA: raise RuntimeError('rustfmt_pin')
 report['rustfmtBefore']=tool_before
 report['originalSourceProvenance']='Twenty-three fixed files from exact independent 8c95fb0a checkout in two crates; source is only read, formatting writes owned copies'
 report['inputOriginalAndCandidatePins']=EXPECTED
 ROOT.mkdir(mode=0o700);created=True
 (ROOT/'candidate').mkdir(mode=0o700);(ROOT/'formatted').mkdir(mode=0o700)
 write_new(ROOT/'rustfmt.toml',FORMAT_CONFIG)
 config_bytes,config_before=read_pin(ROOT/'rustfmt.toml')
 if config_bytes!=FORMAT_CONFIG or sha(config_bytes)!=FORMAT_CONFIG_SHA: raise RuntimeError('format_config_pin')
 report['formatConfigurationBefore']=config_before
 report['repositoryRustfmtConfigPresent']=False
 report['ownedConfiguration']='Edition 2024 only; all other rustfmt defaults; explicit config path excludes ambient parent configuration'
 for name in EXPECTED:
  text=data[name];write_new(ROOT/'candidate'/name,text.encode())
  argv=[str(FMT),'--config-path',str(ROOT/'rustfmt.toml'),'--edition','2024','--emit','stdout']
  p=subprocess.Popen(argv,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,
      cwd=str(SRC),env={'PATH':'/usr/bin:/bin','LANG':'C.UTF-8'},start_new_session=False)
  child={'pid':p.pid,'argv':argv,'cwd':str(SRC),'timeoutSeconds':10,'stopped':False,'newProcessGroupCreated':False}
  report['children'].append(child)
  try:
   child['pgid']=os.getpgid(p.pid)
   child['supervisorGroup']=os.getpgrp()
   if child['pgid']!=child['supervisorGroup']: raise RuntimeError('child_escaped_supervisor_group')
   out,err=p.communicate(text.encode(),timeout=min(10.0,remain()))
  except BaseException:
   if p.poll() is None:
    p.kill()
    p.wait(timeout=min(5.0,remain()))
   child.update(exitCode=p.returncode,reaped=p.returncode is not None)
   child['stopped']=child['reaped']
   raise
  child.update(exitCode=p.returncode,reaped=True)
  child['stopped']=True
  if len(err)>65536: raise RuntimeError('formatted_stderr_bound')
  write_new(ROOT/(name+'.rustfmt.stderr'),err)
  if p.returncode!=0 or not child['stopped']: raise RuntimeError('rustfmt_failed_or_group_remaining')
  write_new(ROOT/(name+'.rustfmt.stdout'),out)
  if len(out)>FORMAT_OUTPUT_CAPS[name] or not out.startswith(text.splitlines()[0].encode()+b'\n'): raise RuntimeError('formatted_output_shape')
  write_new(ROOT/'formatted'/name,out)
  report['files'].append({'name':name,'beforeSha256':sha(text.encode()),'beforeBytes':len(text.encode()),
      'afterSha256':sha(out),'afterBytes':len(out),'stderrBytes':len(err),'stderrSha256':sha(err)})
 sync_dir(ROOT/'candidate');sync_dir(ROOT/'formatted');sync_dir(ROOT)
 remain();report['status']='passed'
except BaseException as e:
 report['errorType']=type(e).__name__;report['error']=str(e)
finally:
 report['sourceInputsAfter']={}
 for name,before_pin in source_before.items():
  try:
   path=SOURCE/SOURCE_RELATIVE[name]
   if path.resolve(strict=True)!=path: raise RuntimeError('source_symlink')
   original,after_pin=read_pin(path,SOURCE_SIZES[name])
   report['sourceInputsAfter'][name]=after_pin
   if sha(original)!=EXPECTED[name][1] or after_pin!=before_pin: raise RuntimeError('source_changed')
  except BaseException as e:
   report['sourceFenceError']=type(e).__name__+':'+str(e);report['status']='failed'
 report['allFixedSourceInputsUnchanged']=len(source_before)==len(EXPECTED) and report['sourceInputsAfter']==source_before
 if not report['allFixedSourceInputsUnchanged']: report['status']='failed'
 if tool_before is not None:
  try:
   report['rustfmtAfter']=read_pin(FMT)[1]
   if report['rustfmtAfter']!=tool_before: raise RuntimeError('rustfmt_changed')
  except BaseException as e:
   report['fenceError']=type(e).__name__+':'+str(e);report['status']='failed'
 if config_before is not None:
  try:
   config_bytes,report['formatConfigurationAfter']=read_pin(ROOT/'rustfmt.toml')
   if config_bytes!=FORMAT_CONFIG or report['formatConfigurationAfter']!=config_before: raise RuntimeError('format_config_changed')
  except BaseException as e:
   report['configFenceError']=type(e).__name__+':'+str(e);report['status']='failed'
 report['elapsedSeconds']=time.monotonic()-START
 report['withinDeadline']=report['elapsedSeconds']<LIMIT
 report['allOwnedStopped']=all(x.get('stopped') is True for x in report['children'])
 if not report['withinDeadline'] or not report['allOwnedStopped']: report['status']='failed'
 if created:
  try:
   write_new(ROOT/'result.public.json',(json.dumps(report,sort_keys=True,indent=2)+'\n').encode())
   sync_dir(ROOT)
  except BaseException as e:
   report['publicationError']=type(e).__name__;report['status']='failed'
 print(json.dumps({'status':report['status'],'root':str(ROOT),'files':report['files'],
   'allOwnedStopped':report['allOwnedStopped'],'elapsedSeconds':time.monotonic()-START,
   'withinDeadline':time.monotonic()-START<LIMIT,'error':report.get('error'),'publicationError':report.get('publicationError')},sort_keys=True),flush=True)
sys.exit(0 if report['status']=='passed' and time.monotonic()-START<LIMIT else 1)
