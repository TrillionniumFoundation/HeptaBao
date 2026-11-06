
const d=load('authbus_return_home_source_draft'),base=load('authbus_return_publisher_raw');
const encode=s=>encodeBase64Bytes(utf8Bytes(s));
const originalPayload=JSON.parse(load('authbus_return_stdin_raw'));
const candidateRaw=JSON.stringify(d.candidate,null,2)+'\n';
const documents={...load('authbus_return_original_documents8'),'candidate-current-manager-wal-r1.public.json':candidateRaw};
const payload={schema:'heptabao.mac-current-home-launch-inert-public-inputs.r1',files:{},documents:{},anchorBase64:originalPayload.anchorBase64};
for(const n of Object.keys(originalPayload.files))payload.files[n]=encode(d.sources[n]);
for(const n of Object.keys(originalPayload.documents))payload.documents[n]=encode(documents[n]);
const payloadRaw=JSON.stringify(payload,null,2)+'\n';
const pins=Object.fromEntries(Object.entries(d.sources).map(([n,t])=>[n,[gitBlobMeta(t).bytes,gitBlobMeta(t).sha256]]));
const documentPins=Object.fromEntries(Object.entries(documents).map(([n,t])=>[n,[gitBlobMeta(t).bytes,gitBlobMeta(t).sha256]]));
const edits=[];
function one(src,old,neu,label){if(src.split(old).length!==2)throw Error('publisher_one:'+label);edits.push({label,old,new:neu});return src.replace(old,neu);}
let source=base.split(d.OLD_ROOT).join(d.NEW_ROOT);
source=one(source,'import ast, base64, hashlib, json, os, select, signal, sys, time, types',
    'import ast, base64, hashlib, json, os, re, select, signal, stat, sys, time, types','HomeControl standard library only');
const p0=source.indexOf('PINS='),p1=source.indexOf('\nDOCUMENT_PINS=',p0);
source=one(source,source.slice(p0,p1),'PINS='+JSON.stringify(pins,null,4),'22 exact pins');
const d0=source.indexOf('DOCUMENT_PINS='),d1=source.indexOf('\nPAYLOAD_BYTES=',d0);
source=one(source,source.slice(d0,d1),'DOCUMENT_PINS='+JSON.stringify(documentPins,null,4),'8 exact document pins');
source=one(source,'PAYLOAD_BYTES=801859','PAYLOAD_BYTES='+gitBlobMeta(payloadRaw).bytes,'exact input length');
source=one(source,'PAYLOAD_SHA="c84a7e6ba807f90c98f5a8a9e375aff86b9a287281d8e2d001e8566315a3b7d9"','PAYLOAD_SHA='+JSON.stringify(gitBlobMeta(payloadRaw).sha256),'exact input whole');
source=one(source,"class Refused(RuntimeError):pass\n","class Refused(RuntimeError):pass\nManagerRefused=Refused\n",'only own inert refusal alias');
const identity="def file_identity(s):\n    return tuple(str(x) for x in (s.st_dev,s.st_ino,s.st_uid,s.st_gid,s.st_mode,\n        s.st_nlink,s.st_size,s.st_mtime_ns,s.st_ctime_ns))\n";
source=one(source,'def stdin_once():\n',identity+'\n'+load('authbus_return_home_control_source_draft')+'\ndef stdin_once():\n','exact same HomeControl class/constants');
source=one(source,"'schema':'heptabao.mac-current-registry-wal-4e808-inert.r1','ok':False,'files':[],",
    "'schema':'heptabao.mac-current-home-launch-inert.r1','ok':False,'files':[],'homeCopies':[],",'fresh inert schema');
source=one(source,'    guard=None;commands=None;candidate=None;prepared=False\n',
    '    guard=None;commands=None;candidate=None;prepared=False\n    home=None;home_init_started=False;home_init_complete=False\n','retained new HOME init ownership');
source=one(source,"payload['schema']=='heptabao.mac-current-registry-wal-4e808-inert-public-inputs.r1'",
    "payload['schema']=='heptabao.mac-current-home-launch-inert-public-inputs.r1'",'fresh payload schema');
source=one(source,"        report['freshRootAbsence']=fresh_root_absent(guard)\n",
"        report['freshRootAbsence']=fresh_root_absent(guard)\n        home_init_started=True;home=HomeControl.__new__(HomeControl)\n        home.__init__(remaining=remaining,critical=critical,\n            copy_pins={name:PINS[name] for name in HOME_COPY_NAMES},binding=None,create=True)\n        home_init_complete=True\n        for name in HOME_COPY_NAMES:\n            content=decoded[name]\n            written=home.write_new(HOME_CONTROL/name,content,copy=True)\n            need(home.read(HOME_CONTROL/name,1048576)==content\n                 and written['bytes']==PINS[name][0] and written['sha256']==PINS[name][1],\n                 'home_staged_copy_separate_held_whole_readback')\n            report['homeCopies'].append({'name':name,**written,\n                'wholeReadbackVerified':True,'readbackUsesSeparateHeldFd':True})\n        report['homeControlBinding']=home.actual_binding()\n        report['homePublicOnly']=True;report['privatePlansAndBusinessDataRemainOnT5']=True\n",'create-only HOME with two exact public copies');
source=one(source,"        if guard is not None:\n            guard.close();report['heldT5Final']=guard.public_state()\n",
"        if home is not None:\n            try:home.close();report['homeControlFinal']=home.public()\n            except BaseException as error:\n                report['homeControlClosureErrorType']=type(error).__name__\n        home_closed=bool(home_init_complete\n            and report.get('homeControlFinal',{}).get('allReturnedDescriptorsClosed') is True\n            and report['homeControlFinal'].get('allFiniteLeavesClosed') is True\n            and report['homeControlFinal'].get('effectUnknown') is False)\n        report['homeControlInitializationStarted']=home_init_started\n        report['homeControlInitializationComplete']=home_init_complete\n        report['allReturnedHomeControlDescriptorsClosed']=home_closed\n        if guard is not None:\n            guard.close();report['heldT5Final']=guard.public_state()\n",'close entire HOME ledger before final inert report');
source=one(source,"        closed=guard is not None and report['heldT5Final']['allDescriptorsClosed']",
    "        closed=bool(guard is not None and report['heldT5Final']['allDescriptorsClosed'] and home_closed)",'combined inert descriptor predicate');
source=one(source,"report['ok']=bool(prepared and candidate is not None and len(report['files'])==30",
    "report['ok']=bool(prepared and candidate is not None and len(report['files'])==30\n            and len(report['homeCopies'])==2 and report.get('homePublicOnly') is True",'two public copies final conjunction');
source=one(source,'"""Create only a fresh Mac WAL-current ROOT, 22 sources and eight public documents.',
    '"""Create fresh T5 ROOT plus HOME public controls, 22 sources and eight public documents.','inert truthful header');
source=one(source,'already verified stdin bytes to guard diskutil and descriptor-relative writes.',
    'already verified stdin bytes to guard diskutil and descriptor-relative writes.\nThe finite HomeControl definition creates two public wrapper copies only. No\nwrapper, manager, SDK or candidate entrypoint executes during this publisher.','inert exact new helper scope');
const sourcePin=gitBlobMeta(source);
const request={host:'mac',executable:'/opt/homebrew/Cellar/python@3.14/3.14.3_1/Frameworks/Python.framework/Versions/3.14/bin/python3.14',
    args:['-I','-S','-B','-c',source],cwd:'/Users/qianqi',stdin:payloadRaw,timeout_seconds:60,
    idempotency_key:'heptabao-mac-current-home-launch-inert-'+sourcePin.sha256.slice(0,8)+'-20261106-r1'};
const requestRaw=JSON.stringify(request,null,2)+'\n';
store('authbus_return_home_dispatch_draft',{source,sourcePin,payloadRaw,payloadPin:gitBlobMeta(payloadRaw),documents,candidateRaw,pins,documentPins,edits,request,requestRaw,requestPin:gitBlobMeta(requestRaw),runtimeExactRequest:null,actualHomeBinding:null,readyForRuntime:false,NativeCalls:0});
text({publisher:sourcePin,payload:gitBlobMeta(payloadRaw),candidate:gitBlobMeta(candidateRaw),request:gitBlobMeta(requestRaw),key:request.idempotency_key,edits:edits.length});
