#!/usr/bin/env python3
"""Derive one small Mac composition check from bounded original mechanisms."""
from pathlib import Path
import ast
import hashlib
import json

HERE=Path(__file__).resolve().parent
ROOT='/Users/qianqi/heptabao-authbus-poststop-registry-qualification-20261106-r1'
QUAL='/Users/qianqi/heptabao-authbus-auth-wal-qualification-20261106-r2'
PINS={'mac_guarded_current_capture_r3.py':'606b5df58909ebedc035ebbff6a4aa5e754d19c6a7e0f5e4e88c9ddfc57c2693',
 'mac_registry_readonly_wal_r1.py':'60d5e5874c281af2e19fee55bc4b2242627f69b500f1af1d6b5b22e16120bfed',
 'authbus_current_auth_wal.py':'ad443869e259da06de2be71131e5d1854680477d1cf77248e05a3c1704160f8c'}
local=(HERE/'qualify_poststop_registry_local_r1.py').read_text()
start=local.index('CASES = []\n')
end=local.index('\nreport = {',start)
cases=local[start:end]
cases=cases.replace("fixture_root = Path(tempfile.mkdtemp(prefix='registry-composition-local-', dir=HERE))",
                    "fixture_root = ROOT / 'output'")
cases=cases.replace("live = fixture_root / name / 'live'",
                    "remaining();live = fixture_root / 'cases' / ('A%02d' % (len(CASES)+1)) / 'live'")
cases=cases.replace('writer = sqlite3.connect(path, isolation_level=None)',
                    "writer = sqlite3.connect(path, isolation_level=None)\n    writer_row={'db':writer,'closeAttempted':False,'closed':False}\n    fixture_connections.append(writer_row)")
cases=cases.replace('writer.execute(', 'fixture_execute(writer, ')
cases=cases.replace(').close()', ')')
cases=cases.replace('writer.close()', 'close_fixture(writer_row)')
cases=cases.replace('writer.rollback()', "fixture_execute(writer, 'ROLLBACK')")
header='''#!/usr/bin/env python3
"""One actual Mac synthetic registry reader composition; no live data reads."""
from __future__ import annotations
import contextlib,errno,hashlib,json,os,sqlite3,stat,sys,time,types
from pathlib import Path
START=time.monotonic();UNTIL=float(sys.argv[1])
ROOT=Path(@ROOT@);QUAL=Path(@QUAL@)
PINS=@PINS@
source_fds=[];fixture_connections=[];fixture_cursors=[];probes=[];sock=None
def remaining():
 if time.monotonic()>=UNTIL:raise RuntimeError('original_registry_worker_deadline')
def read_source(path,expected):
 remaining();fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC);row={'closed':False};source_fds.append(row)
 try:
  before=os.fstat(fd)
  assert stat.S_ISREG(before.st_mode) and before.st_nlink==1 and before.st_uid in (0,501) and not stat.S_IMODE(before.st_mode)&0o022 and 0<before.st_size<=65536
  data=bytearray()
  while len(data)<=before.st_size:
   remaining();part=os.read(fd,min(65536,before.st_size+1-len(data)))
   if not part:break
   data.extend(part)
  def ident(s):return tuple(getattr(s,k) for k in ('st_dev','st_ino','st_uid','st_gid','st_mode','st_nlink','st_size','st_mtime_ns','st_ctime_ns'))
  assert len(data)==before.st_size and ident(before)==ident(os.fstat(fd))==ident(path.lstat()) and hashlib.sha256(data).hexdigest()==expected
  return bytes(data)
 finally:os.close(fd);row['closed']=True
def fixture_execute(db,sql,args=()):
 remaining();cursor=db.cursor();row={'closed':False};fixture_cursors.append(row)
 try:cursor.execute(sql,args)
 finally:cursor.close();row['closed']=True
def close_fixture(row):
 if row['closeAttempted']:return
 row['closeAttempted']=True;row['db'].close();row['closed']=True
assert sys.platform=='darwin' and os.getuid()==501 and START<UNTIL<=START+30
assert sqlite3.sqlite_version=='3.53.4'
os.umask(0o077);sys.dont_write_bytecode=True
for code,path,flags in [('own-protected-read',ROOT/'protected-read',os.O_RDONLY),
 ('own-protected-write',ROOT/'protected-write',os.O_WRONLY),
 ('live-configuration-read',Path('/Users/qianqi/.openclaw/openclaw.json'),os.O_RDONLY)]:
 try:fd=os.open(path,flags)
 except OSError as error:assert error.errno in (errno.EPERM,errno.EACCES);probes.append({'name':code,'denied':True})
 else:os.close(fd);raise RuntimeError('synthetic_kernel_path_not_refused')
import socket
try:
 sock=socket.socket(socket.AF_INET,socket.SOCK_STREAM);sock.settimeout(.1);sock.connect(('127.0.0.1',9))
except OSError as error:assert error.errno in (errno.EPERM,errno.EACCES);probes.append({'name':'network','denied':True})
else:raise RuntimeError('synthetic_kernel_network_not_refused')
finally:
 if sock is not None:sock.close()
source={name:read_source(QUAL/'qa'/name,pin) for name,pin in PINS.items()}
sys.path.insert(0,str(QUAL/'qa'))
import mac_guarded_current_capture_r3 as base
import mac_registry_readonly_wal_r1 as wal
auth_raw=source['authbus_current_auth_wal.py'].decode()
old='SYNTHETIC_ROOT = Path("/Users/qianqi/heptabao-authbus-auth-wal-qualification-20261106-r2")'
assert auth_raw.count(old)==1
derived=auth_raw.replace(old,'SYNTHETIC_ROOT = Path('+repr(str(ROOT/'output'))+')')
auth=types.ModuleType('fixture_original_auth_reader');auth.__file__=str(ROOT/'code/fixture_original_auth_reader.py')
exec(compile(derived,auth.__file__,'exec'),auth.__dict__)
sys.path.insert(0,str(ROOT/'code'))
import mac_poststop_registry_read_r1 as bridge
Refused,need=base.CaptureRefused,base.need
def inputs(live):
 return auth.AuthInputs(until=min(UNTIL,time.monotonic()+20),critical=contextlib.nullcontext,cancelled=lambda:False,live=live,synthetic=True)
'''.replace('@ROOT@',repr(ROOT)).replace('@QUAL@',repr(QUAL)).replace('@PINS@',repr(PINS))
footer='''
for name,pin in PINS.items():read_source(QUAL/'qa'/name,pin)
remaining()
report={'schema':'heptabao.actual-mac-poststop-registry-composition.r1',
 'ok':len(CASES)==11 and all(row['passed'] for row in CASES),
 'cases':CASES,'passed':sum(row['passed'] for row in CASES),'expected':11,
 'actualMacSQLite':True,'sqliteVersion':sqlite3.sqlite_version,
 'actualOriginalHeldFdAndReadonlyWalRoutes':True,
 'fixedProductionNamespaceQualifiedBySyntheticFixture':False,
 'fixtureRootDerivationOnly':True,'fixtureOwnerGroupLiteralChanged':False,
 'originalAuthSyntheticRootOnlyDerivation':True,'productionSourcesRead':False,
 'productionQuiescenceQualified':False,'providerDispatched':False,'serviceChanged':False,
 'kernelDenials':probes,'probeSocketClosed':sock is not None and sock.fileno()==-1,
 'sourcePins':PINS,'resourceCounts':TOTAL,
 'allSourceCodeDescriptorsClosedOnce':all(row['closed'] for row in source_fds),
 'allFixtureWriterConnectionsClosedOnce':all(row['closeAttempted'] and row['closed'] for row in fixture_connections),
 'allFixtureCursorsClosedOnce':all(row['closed'] for row in fixture_cursors),
 'fixtureWriterConnectionCount':len(fixture_connections),'fixtureCursorCount':len(fixture_cursors),
 'elapsedSeconds':time.monotonic()-START}
report['ok']=report['ok'] and report['probeSocketClosed'] and all(report[k] for k in (
 'allSourceCodeDescriptorsClosedOnce','allFixtureWriterConnectionsClosedOnce','allFixtureCursorsClosedOnce'))
print(json.dumps(report,sort_keys=True,separators=(',',':')),flush=True)
raise SystemExit(0 if report['ok'] else 1)
'''
worker=header+cases+footer
compile(worker,'qualify_poststop_registry_mac_r1.py','exec')
(HERE/'qualify_poststop_registry_mac_r1.py').write_text(worker)

template=(HERE.parent/'mac-whole-sqlite-streaming-r1-work/launch_mac_whole_sqlite_streaming_small_r1.template.py').read_text()
template=template.replace('One new Mac synthetic whole-database fixture; no production source read.',
 'One new Mac fixed-registry composition fixture; no production source read.')
template=template.replace('/Users/qianqi/heptabao-authbus-whole-database-streaming-small-20261106-r1',ROOT)
template=template.replace('heptabao.actual-mac-whole-database-qualification-launch.streaming.r1',
 'heptabao.actual-mac-poststop-registry-qualification-launch.r1')
template=template.replace("for relative,pin in PAYLOAD['installedSchemaSourcePins'].items():need(sha(read(SDK/relative))==pin,'same_installed_whole_schema_sources')",
 "for name,pin in PAYLOAD['originalReaderSourcePins'].items():need(sha(read(QUAL/'qa'/name))==pin,'same_original_registry_reader_sources')")
template=template.replace(" for name,pin in PAYLOAD['schemaPins'].items():need(sha(read(ROOT/'code'/(name+'-schema.sql')))==pin,'same_staged_whole_schema')\n",'')
first=template.index(" need(set(PAYLOAD['sources'])==")
last=template.index('\n home=ROOT.parent.lstat()',first)
template=template[:first]+" need(set(PAYLOAD['sources'])=={'mac_poststop_registry_read_r1.py','qualify_poststop_registry_mac_r1.py'},'two_exact_registry_modules')"+template[last:]
first=template.index(" for kind,sql in PAYLOAD['schemas'].items():")
last=template.index("\n private(ROOT/'code/plan.public.json'",first)
template=template[:first]+" plan={'schema':'heptabao.synthetic-poststop-registry-plan.r1',\n  'sourcePins':PAYLOAD['sourcePins'],'originalReaderSourcePins':PAYLOAD['originalReaderSourcePins'],\n  'originalChildren':1,'sharedSeconds':45,'workerSeconds':30,'productionReadAuthorized':False,'productionWriteAuthorized':False}"+template[last:]
anchor=" for name in (ROOT/'code',ROOT/'output'):lines.append('(allow file-read* (subpath '+json.dumps(str(name))+'))')"
assert template.count(anchor)==1
template=template.replace(anchor,anchor+"\n for name in PAYLOAD['originalReaderSourcePins']:lines.append('(allow file-read* (literal '+json.dumps(str(QUAL/'qa'/name))+'))')\n for name in (QUAL,QUAL/'qa'):lines.append('(allow file-read* (literal '+json.dumps(str(name))+'))')")
template=template.replace('mac_whole_sqlite_streaming_worker_r1.py','qualify_poststop_registry_mac_r1.py')
first=template.index("  need(value['ok'] and value['kernelReadWriteNetworkRefusalsObserved']")
last=template.index('\n public_fence();own_fence();remaining()',first)
template=template[:first]+"""  need(value['ok'] and value['actualMacSQLite'] and value['sqliteVersion']=='3.53.4'
   and value['passed']==value['expected']==len(value['cases'])==11
   and len(value['kernelDenials'])==4 and all(row['denied'] for row in value['kernelDenials'])
   and value['probeSocketClosed'] and value['productionSourcesRead'] is False
   and value['providerDispatched'] is False and value['serviceChanged'] is False
   and all(row['originalResourcesClosed'] for row in value['cases'])
   and all(value[key] for key in ('allSourceCodeDescriptorsClosedOnce',
    'allFixtureWriterConnectionsClosedOnce','allFixtureCursorsClosedOnce')),
   'whole_actual_poststop_registry_composition_closed')"""+template[last:]
template=template.replace("'maximumDatabaseBytes':4294967296,\n 'largeDatabaseCapacityQualified':False,",
 "'fixtureCases':11,'productionQuiescenceQualified':False,")
compile(template.replace('# PAYLOAD_PLACEHOLDER','PAYLOAD = {}'),'template','exec')
(HERE/'launch_poststop_registry_qualification_r1.template.py').write_text(template)
sources={'mac_poststop_registry_read_r1.py':(HERE/'mac_poststop_registry_read_r1.py').read_text(),
         'qualify_poststop_registry_mac_r1.py':worker}
payload={'sources':sources,'sourcePins':{name:hashlib.sha256(raw.encode()).hexdigest() for name,raw in sources.items()},
 'originalReaderSourcePins':PINS,
 'custodyQualificationAuthority':json.loads((HERE/'poststop-registry-original-custody-authority.public.json').read_text())}
assembled=template.replace('# PAYLOAD_PLACEHOLDER','PAYLOAD = '+repr(payload))
compile(assembled,'assembled','exec')
(HERE/'launch_poststop_registry_qualification_r1.py').write_text(assembled)
manifest={'schema':'heptabao.poststop-registry-prepared.r1','actualExecuted':False,
 'files':{name:{'bytes':len(raw.encode()),'sha256':hashlib.sha256(raw.encode()).hexdigest()}
          for name,raw in {**sources,'launch_poststop_registry_qualification_r1.template.py':template,
                          'launch_poststop_registry_qualification_r1.py':assembled}.items()},
 'originalReaderSourcePins':PINS,'originalSmallParentSourceSha256':hashlib.sha256(
 (HERE.parent/'mac-whole-sqlite-streaming-r1-work/launch_mac_whole_sqlite_streaming_small_r1.template.py').read_bytes()).hexdigest(),
 'localLinuxCompositionResult':'known_failed_5_of_11_Mac_VFS_and_fd_path_semantics_not_available',
 'productionSourceReads':0,'providerCalls':0,'serviceActions':0}
(HERE/'poststop-registry-prepared-r1.manifest.public.json').write_text(json.dumps(manifest,indent=2,sort_keys=True)+'\n')
print(json.dumps(manifest,sort_keys=True))
