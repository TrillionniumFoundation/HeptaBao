#!/usr/bin/env python3
"""Private selected-owner capsule admission; no credential output or public digest.

Each fence is one bounded before/after observation, never a continuous lock.
The source producer has a known succeeded terminal. Current namespace identities
must still match its private generation before any canonical value is written.
"""
from __future__ import annotations
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import time
from main3_source_authority import validate_authority,SOURCE_SELECTION_AUTHORITY,SDK_SOURCE_PINS
from main3_inline_capture import AUTHORITY,OPERATION_KEY,CAPTURE_WORKER_SHA,validate_authority as validate_inline_authority

LIVE=Path('/Users/qianqi/.openclaw')
CAPSULE_ROOT=Path('/Users/qianqi/heptabao-authbus-main3-api-inline-capsule-20261106-r5')
CAPSULE=CAPSULE_ROOT/'output/selected-owner-credentials.private.json'
PREP=Path('/Users/qianqi/heptabao-mac-authbus-main3-api-preparation-20261106-r5')
BINDING=PREP/'capsule-admission-binding.private.json'
AGENTS=('main','trnm','hepta-ui','hepta','hepta-backend')


class Refused(RuntimeError):pass
def need(value,code):
    if not value:raise Refused(code)
def ident(s):return tuple(str(getattr(s,k)) for k in ('st_dev','st_ino','st_uid','st_gid','st_mode','st_nlink','st_size','st_mtime_ns','st_ctime_ns'))
def typed_identity(value):
    need(isinstance(value,(list,tuple)) and len(value)==9 and all(isinstance(x,str) and re.fullmatch(r'[0-9]{1,30}',x) for x in value),'private_full9_identity_shape')
    return tuple(value)
def within(path,root):
    try:relative=Path(path).relative_to(root)
    except ValueError:return False
    return str(relative)!='.' and '..' not in relative.parts

class CapsuleFence:
    def __init__(self,phase_until,*,capsule_path=CAPSULE,clock=time.monotonic,admit_mode="run"):
        self.clock=clock;self.phase_until=phase_until;self.until=min(phase_until,clock()+45.0)
        self.opened=0;self.closed=0;self.bytes=0;self.file_reads=0;self.observations=[]
        self.capsule_path=Path(capsule_path)
        need(self.capsule_path==CAPSULE,'fixed_authoritative_capsule_path')
        self.remaining()
        authority_raw,_=self.read(AUTHORITY,131072,private=True)
        validate_inline_authority(json.loads(authority_raw),parent_pid=os.getpid())
        self.capture_authority_sha=hashlib.sha256(authority_raw).hexdigest()
        for p in (CAPSULE_ROOT,CAPSULE_ROOT/'output'):
            s=p.lstat();need(stat.S_ISDIR(s.st_mode) and s.st_uid==501 and stat.S_IMODE(s.st_mode)==0o700,'private_capsule_parent_custody')
        raw,self.capsule_identity=self.read(self.capsule_path,1048576,private=True)
        self.doc=json.loads(raw)
        self.validate(self.doc)
        self.bind_admission(admit_mode)
        self.remaining()
    def remaining(self):
        left=min(self.phase_until,self.until)-self.clock()
        need(left>0,'source_fence_original_absolute_deadline');return left
    def read(self,path,maximum,*,private=False,expected=None):
        self.remaining();need(self.file_reads<4096,'source_fence_finite_file_reads');self.file_reads+=1
        fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC);self.opened+=1
        try:
            s=os.fstat(fd)
            need(stat.S_ISREG(s.st_mode) and s.st_uid in (0,501) and s.st_nlink==1
                 and not stat.S_IMODE(s.st_mode)&0o022 and 0<=s.st_size<=maximum,'source_fence_regular_custody')
            if private:need(s.st_uid==501 and stat.S_IMODE(s.st_mode)==0o600,'source_fence_private_mode')
            current=ident(s)
            if expected is not None:need(current==typed_identity(expected),'source_fence_exact_expected_generation')
            raw=bytearray()
            while len(raw)<=maximum:
                self.remaining();part=os.read(fd,min(65536,maximum+1-len(raw)))
                if not part:break
                raw.extend(part)
            self.bytes+=len(raw);need(self.bytes<=512*1048576,'source_fence_total_read_bound')
            need(len(raw)==s.st_size and current==ident(os.fstat(fd))==ident(Path(path).lstat()),'source_fence_stable_whole_file')
            self.remaining();return bytes(raw),current
        finally:os.close(fd);self.closed+=1
    @staticmethod
    def validate(doc):
        need(isinstance(doc,dict) and doc.get('schema')=='heptabao.actual-sdk-selected-owner-credentials.private.r1'
             and doc.get('host')=='mac','exact_selected_owner_capsule_schema')
        c=doc.get('constraints',{})
        need(c.get('containsCredentialValues') is True and c.get('containsCredentialDigests') is False
             and c.get('selectedOwnerCount')==3 and c.get('containsUnselectedCredentials') is False
             and all(c.get(k) is False for k in ('productionChanged','providerLivenessVerified','oauthRefreshAttempted','productionCutover')),
             'selected_capsule_scope_and_provider_unqualified')
        rows=doc.get('ownerEntries');need(isinstance(rows,list) and len(rows)==3,'exact_three_selected_owners')
        ids=[]
        for entry in rows:
            need(isinstance(entry,dict) and entry.get('ownerAgent')=='main'
                 and entry.get('ownerAgentDir')==str(LIVE/'agents/main/agent') and entry.get('actualProvider')=='openai',
                 'actual_main_owner_and_provider')
            profile=entry.get('profileId');cred=entry.get('credential')
            need(isinstance(profile,str) and 0<len(profile)<=240 and profile not in ids,'three_unique_private_profile_ids');ids.append(profile)
            need(isinstance(cred,dict) and cred.get('provider')=='openai' and cred.get('type')=='oauth'
                 and all(isinstance(cred.get(k),str) and 8<=len(cred[k])<=131072 for k in ('access','refresh'))
                 and type(cred.get('expires')) in (int,float) and cred['expires']>0
                 and not any(k in cred for k in ('keyRef','tokenRef','accessRef','refreshRef','oauthRef'))
                 and len(json.dumps(cred,ensure_ascii=False).encode())<=131072,'exact_real_oauth_shape_no_secret_references')
        consumers=doc.get('consumerBindings')
        need(isinstance(consumers,list) and len(consumers)==15,'exact_fifteen_private_consumer_bindings')
        seen=set()
        for row in consumers:
            need(isinstance(row,dict) and row.get('scopeAgent') in AGENTS
                 and row.get('scopeAgentDir')==str(LIVE/'agents'/row['scopeAgent']/'agent')
                 and row.get('profileId') in ids and row.get('ownerAgent')=='main'
                 and row.get('ownerAgentDir')==str(LIVE/'agents/main/agent')
                 and row.get('persistedOwnerMatchesEffective') is True
                 and row.get('selectedByActualSdkOrder') is True
                 and type(row.get('actualSdkOrderRank')) is int and 0<=row['actualSdkOrderRank']<3
                 and row.get('configuredProfileId') is False,'current_sdk_five_by_three_owner_binding')
            key=(row['scopeAgent'],row['profileId'])
            need(key not in seen,'unique_consumer_owner_reference');seen.add(key)
        for agent in AGENTS:
            need({r['actualSdkOrderRank'] for r in consumers if r['scopeAgent']==agent}=={0,1,2},'exact_three_sdk_order_ranks_per_agent')
        generations=doc.get('sourceGenerations')
        need(isinstance(generations,list) and len(generations)==5 and set(x.get('agent') for x in generations)==set(AGENTS),
             'exact_five_source_agent_generations')
        typed_identity(doc.get('configurationIdentity'))
        need(isinstance(doc.get('configurationSha256'),str) and re.fullmatch(r'[0-9a-f]{64}',doc['configurationSha256']),
             'private_configuration_pin_shape')
        validate_authority(doc,need)
        metadata=doc.get('registeredMetadataFileBindings')
        need(isinstance(metadata,list) and len(metadata)==145,'exact_observed_registered_metadata_count')
    @staticmethod
    def expected_binding(identity,authority_sha):
        need(isinstance(authority_sha,str) and re.fullmatch(r'[0-9a-f]{64}',authority_sha),'public_inline_authority_pin_shape')
        return {'schema':'heptabao.main3-capsule-admission-binding.private.r5',
            'capsulePath':str(CAPSULE),'capsuleIdentity':list(typed_identity(identity)),
            'sourceCaptureOperationKey':OPERATION_KEY,'sourceCaptureWorkerSha256':CAPTURE_WORKER_SHA,
            'publicCaptureAuthoritySha256':authority_sha}
    @classmethod
    def validate_binding(cls,value,identity,authority_sha):
        need(value==cls.expected_binding(identity,authority_sha),'same_authoritatively_qualified_capsule_generation')
    def bind_admission(self,mode):
        self.remaining();need(mode in ('qualify','run'),'fixed_private_capsule_admission_mode')
        parent=os.open(PREP,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC);self.opened+=1
        try:
            p=os.fstat(parent)
            need(stat.S_ISDIR(p.st_mode) and p.st_uid==501 and stat.S_IMODE(p.st_mode)==0o700,
                 'admission_fixed_private_parent')
            if mode=='qualify':
                raw=(json.dumps(self.expected_binding(self.capsule_identity,self.capture_authority_sha),sort_keys=True,separators=(',',':'))+'\n').encode()
                fd=os.open(BINDING.name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o600,dir_fd=parent);self.opened+=1
                try:
                    before=os.fstat(fd)
                    need(stat.S_ISREG(before.st_mode) and before.st_uid==501 and before.st_nlink==1
                         and stat.S_IMODE(before.st_mode)==0o600,'new_private_capsule_binding')
                    offset=0
                    while offset<len(raw):
                        self.remaining();count=os.write(fd,raw[offset:]);need(count>0,'private_admission_write_progress');offset+=count
                    os.fsync(fd);os.fsync(parent);after=os.fstat(fd)
                    need(ident(before)[:6]==ident(after)[:6] and after.st_size==len(raw)
                         and ident(after)==ident(os.stat(BINDING.name,dir_fd=parent,follow_symlinks=False)),
                         'private_admission_binding_durable_identity')
                finally:os.close(fd);self.closed+=1
            else:
                raw,_=self.read(BINDING,8192,private=True)
                self.validate_binding(json.loads(raw),self.capsule_identity,self.capture_authority_sha)
        finally:os.close(parent);self.closed+=1
        need(self.opened==self.closed,'capsule_admission_all_descriptors_closed')
        self.remaining()
    def namespace(self,bundle,scope):
        need(isinstance(bundle,dict) and isinstance(bundle.get('sourceIdentities'),dict)
             and isinstance(bundle.get('sourceAbsences'),list),'private_namespace_bundle_shape')
        identities=bundle['sourceIdentities'];absences=bundle['sourceAbsences']
        need(1<=len(identities)<=8 and len(absences)<=16 and len(set(absences))==len(absences)
             and not set(identities).intersection(absences),'finite_disjoint_source_namespace')
        for name,expected in identities.items():
            self.remaining();need(scope(name),'fixed_source_namespace_scope')
            s=Path(name).lstat()
            need(stat.S_ISREG(s.st_mode) and s.st_uid==501 and s.st_nlink==1
                 and not stat.S_IMODE(s.st_mode)&0o077 and ident(s)==typed_identity(expected),
                 'current_source_full_generation_exact')
        for name in absences:
            self.remaining();need(isinstance(name,str) and scope(name),'fixed_absence_namespace_scope')
            try:Path(name).lstat()
            except FileNotFoundError:continue
            raise Refused('current_source_expected_absence_changed')
        return len(identities),len(absences)
    @staticmethod
    def exact_database_bundle(bundle,base):
        need(isinstance(bundle,dict) and isinstance(bundle.get('sourceIdentities'),dict)
             and isinstance(bundle.get('sourceAbsences'),list),'database_bundle_shape')
        present=bundle['sourceIdentities'];absent=bundle['sourceAbsences'];base=str(base)
        allowed={base,base+'-wal',base+'-shm',base+'-journal'}
        need(set(present)|set(absent)==allowed and not set(present)&set(absent)
             and base in present and base+'-journal' in absent,'exact_database_namespace_and_journal_absence')
        if base+'-wal' in absent:need(base+'-shm' in absent,'absent_wal_requires_absent_shm')
        elif int(typed_identity(present[base+'-wal'])[6])>0:
            need(base+'-shm' in present and int(typed_identity(present[base+'-shm'])[6])>0,'nonempty_wal_requires_actual_nonempty_shm')
        return allowed
    def observe(self,label):
        # Each explicit observation is <=45s AND the original phase deadline.
        # This does not reset or extend phase_until.
        need(label in ('preflight','before-phase','before-canonical-write','after-phase'),'fixed_source_fence_observation')
        need(len(self.observations)<16,'source_fence_finite_observations')
        self.until=min(self.phase_until,self.clock()+45.0);self.remaining()
        before_reads=self.file_reads;before_bytes=self.bytes;started=self.clock()
        raw,identity=self.read(CAPSULE,1048576,private=True,expected=self.capsule_identity)
        need(json.loads(raw)==self.doc and identity==self.capsule_identity,'same_private_capsule_full_values')
        d=self.doc;identities=0;absences=0
        for source in d['sourceGenerations']:
            prefix=LIVE/'agents'/source['agent']/'agent'
            allowed=self.exact_database_bundle(source,prefix/'openclaw-agent.sqlite')
            a,b=self.namespace(source,lambda name:name in allowed);identities+=a;absences+=b
        allowed=self.exact_database_bundle(d['registryGeneration'],LIVE/'state/openclaw.sqlite')
        a,b=self.namespace(d['registryGeneration'],lambda name:name in allowed)
        identities+=a;absences+=b
        config,_=self.read(LIVE/'openclaw.json',1048576,private=True,expected=d['configurationIdentity'])
        need(hashlib.sha256(config).hexdigest()==d['configurationSha256'],'private_configuration_whole_bytes_exact')
        for item in d['registeredMetadataFileBindings']:
            self.remaining();need(isinstance(item,dict) and set(item)=={'nominal','path','identity','sha256'},'metadata_binding_shape')
            nominal=Path(item['nominal']);actual=Path(item['path'])
            need(nominal.is_absolute() and actual.is_absolute() and nominal.resolve(strict=True)==actual,'metadata_same_actual_namespace')
            need(isinstance(item['sha256'],str) and re.fullmatch(r'[0-9a-f]{64}',item['sha256']),'private_metadata_pin_shape')
            code,_=self.read(actual,2*1048576,expected=item['identity'])
            need(hashlib.sha256(code).hexdigest()==item['sha256'] and nominal.resolve(strict=True)==actual,'private_metadata_whole_bytes_exact')
        need(ident(CAPSULE.lstat())==self.capsule_identity and self.opened==self.closed,'source_fence_capsule_and_descriptor_closure')
        self.remaining()
        row={'observation':label,'beforeAfterObservationOnly':True,'continuousLockClaimed':False,
             'currentFiveAgentGenerationsExact':True,'currentRegistryGenerationExact':True,
             'currentConfigurationWholeBytesExact':True,'currentMetadataWholeFilesExact':145,
             'namespacePresentCount':identities,'namespaceAbsentCount':absences,
             'wholeFileReadCount':self.file_reads-before_reads,'wholeFileBytesRead':self.bytes-before_bytes,
             'descriptorsClosed':True,'withinOriginalPhaseDeadline':True,'observationMaximumSeconds':45,
             'elapsedSeconds':self.clock()-started}
        self.observations.append(row);return row
    def public(self):
        return {'captureOperationKey':OPERATION_KEY,'captureWorkerSourceSha256':CAPTURE_WORKER_SHA,
                'publicCaptureAuthoritySha256':self.capture_authority_sha,
                'sourceSelectionAuthority':SOURCE_SELECTION_AUTHORITY,
                'publicSdkCodePinCount':len(SDK_SOURCE_PINS),'qualificationCapsuleIdentityBound':True,
                'selectedOwnerCount':3,'consumerReferenceCount':15,'sourceAgentCount':5,
                'providerValid':False,'providerRefreshAttempted':False,'productionCutover':False,
                'credentialValuesOrDigestsPublished':False,'capsuleDigestsPublished':False,
                'fileDescriptorsOpened':self.opened,'fileDescriptorsClosed':self.closed,
                'allReturnedDescriptorsClosed':self.opened==self.closed,'observations':self.observations}
