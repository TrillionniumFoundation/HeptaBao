#!/usr/bin/env python3
"""Project bounded numeric metadata from the closed, failed r2 QA artifact.

No production source, credential row, new SQL or helper is opened. Original
failure stays failed; this projection cannot reconstruct its final gates.
"""
import hashlib,json,os,re,stat,sys,time
from pathlib import Path
START=time.monotonic();UNTIL=START+10
ROOT=Path('/Users/qianqi/heptabao-authbus-production-source-inventory-20261106-r2')
PY='/opt/homebrew/Cellar/python@3.14/3.14.3_1/Frameworks/Python.framework/Versions/3.14/bin/python3.14'
COUNTS=('connectionAttemptCount','returnedConnectionCount','cursorCount','queryCount')
fds=[];codes=set();report={'schema':'heptabao.original-failed-inventory-private-metadata-projection.r1','ok':False,
 'originalJobId':'1a1b323521f-fc05-80bc','originalJobRemainsFailed':True,
 'originalSourceFenceOrCloseSuccessReconstructed':False,'newSqliteConnections':0,
 'newChildren':0,'productionSourceReads':0,'providerCalls':0,'serviceActions':0,
 'configurationPathsIdsMessagesOrPrivateDigestsPublished':False}
def need(v,c):
 if not v:codes.add(c);raise RuntimeError(c)
def ident(s):return tuple(getattr(s,k) for k in ('st_dev','st_ino','st_uid','st_gid','st_mode','st_nlink','st_size','st_mtime_ns','st_ctime_ns'))
def read(path,maximum,*,exact=None,private=False,optional=False):
 need(time.monotonic()<UNTIL,'original_metadata_projection_deadline')
 try:fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
 except FileNotFoundError:
  need(optional,'fixed_original_metadata_required');return None
 row={'closeAttempts':0,'closed':False};fds.append(row)
 try:
  before=os.fstat(fd);need(stat.S_ISREG(before.st_mode) and before.st_nlink==1 and 0<=before.st_size<=maximum
   and before.st_uid in (0,501) and not stat.S_IMODE(before.st_mode)&0o022,'fixed_metadata_projection_input_custody')
  if exact is not None:need(before.st_size==exact,'exact_original_projection_input_size')
  if private:need(before.st_uid==501 and before.st_gid==20 and stat.S_IMODE(before.st_mode)==0o600,'fixed_private_metadata_custody')
  value=bytearray()
  while len(value)<=before.st_size:
   need(time.monotonic()<UNTIL,'original_metadata_projection_deadline');part=os.read(fd,min(65536,before.st_size+1-len(value)))
   if not part:break
   value.extend(part)
  need(len(value)==before.st_size and ident(before)==ident(os.fstat(fd))==ident(Path(path).lstat()),'complete_original_metadata_unchanged')
  return bytes(value)
 finally:
  row['closeAttempts']=1;os.close(fd);row['closed']=True
def unique_pairs(items):
 result={}
 for key,value in items:
  need(key not in result,'unique_original_private_metadata_keys');result[key]=value
 return result
def reject_constant(_value):raise RuntimeError('nonfinite_original_private_metadata')
def size(full):
 need(isinstance(full,list) and len(full)==9 and all(isinstance(x,str) and re.fullmatch(r'[0-9]{1,24}',x) for x in full),'original_private_full9_shape')
 return int(full[6])
try:
 need(sys.platform=='darwin' and os.getuid()==501 and os.path.realpath(sys.executable)==PY,'actual_original_projection_runtime')
 need(hashlib.sha256(read(PY,34640,exact=34640)).hexdigest()=='cebfcc4ac431ff7a2179bc6eff7e5c6bdae48b564eeab2d504bef6173a2cfc13','same_original_projection_python')
 source=read(ROOT/'code/capture_current_database_inventory_r2.py',65536,private=True)
 need(hashlib.sha256(source).hexdigest()=='00bab7c4ec400d30d8829230887f35389ec39db26cd660a1551fa3b186bdc3e3','original_failed_inventory_source_pin')
 error=read(ROOT/'output/inventory.stderr.private',308,exact=308,private=True).decode('utf-8','strict').splitlines()
 report['originalErrorIsKeyError']=any(line.startswith('KeyError:') for line in error)
 report['missingKnownResourceCountField']=next((key for key in COUNTS if "KeyError: '"+key+"'" in error),None)
 raw=read(ROOT/'output/inventory.private.json',4*1048576,private=True,optional=True)
 report['originalPrivateMetadataArtifactPresent']=raw is not None
 if raw is not None:
  packet=json.loads(raw,object_pairs_hook=unique_pairs,parse_constant=reject_constant)
  need(isinstance(packet,dict) and packet.get('schema')=='heptabao.current-production-source-inventory.private.r1','same_original_private_metadata_schema')
  physical=packet['initialDatabaseNamespaceMetadata'];databases=packet['databases']
  need(isinstance(physical,list) and isinstance(databases,list) and len(physical)==len(databases)==6,'six_original_metadata_slots')
  rows=[]
  for ordinal,(namespace,database) in enumerate(zip(physical,databases),1):
   need(namespace['ordinal']==ordinal and database['slot']==ordinal-1 and set(namespace['files'])=={'','-wal','-shm','-journal'},'exact_original_metadata_slot_order')
   sizes={('main' if suffix=='' else suffix[1:]):None if value is None else size(value) for suffix,value in namespace['files'].items()}
   observation=database['inventory'];need(observation['schema']=='heptabao.current-database-inventory.private.r1','original_metadata_query_schema')
   pages=observation['pragmas']['page_count'];page_size=observation['pragmas']['page_size']
   need(type(pages) is int and 0<=pages<=0x7fffffff and type(page_size) is int and page_size in (512,1024,2048,4096,8192,16384,32768,65536),'bounded_original_database_capacity')
   objects=observation['sqliteObjects'];need(isinstance(objects,list) and 0<len(objects)<=1024,'bounded_original_schema_objects')
   counts={name:0 for name in ('table','index','view','trigger')}
   for item in objects:need(item['type'] in counts,'fixed_original_schema_object_category');counts[item['type']]+=1
   mappings=observation['registeredAgentDatabases'];need(isinstance(mappings,list) and len(mappings)<=256,'bounded_original_registry_mapping_count')
   rows.append({'ordinal':ordinal,'physicalFileBytes':sizes,'pageCount':pages,'pageSize':page_size,
    'logicalDatabaseBytes':pages*page_size,'schemaObjectCounts':counts,'registeredDatabaseMappingCount':len(mappings)})
  report['originalDatabaseMetadata']=rows
 report['ok']=True
except BaseException as error:
 report['projectionErrorType']=type(error).__name__;report['projectionErrorCode']=str(error) if str(error) in codes else 'original_private_metadata_projection_refused'
finally:
 report['descriptors']=fds;report['allOriginalDescriptorsClosedOnce']=all(r['closed'] and r['closeAttempts']==1 for r in fds)
 report['elapsedSeconds']=time.monotonic()-START
 if not report['allOriginalDescriptorsClosedOnce'] or time.monotonic()>=UNTIL:report['ok']=False
 print(json.dumps(report,sort_keys=True,separators=(',',':')),flush=True)
raise SystemExit(0 if report['ok'] else 1)
