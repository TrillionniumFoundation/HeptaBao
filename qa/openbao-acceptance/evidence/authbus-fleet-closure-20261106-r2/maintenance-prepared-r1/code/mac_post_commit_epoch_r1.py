#!/usr/bin/env python3
"""One fresh post-COMMITTED epoch, from the original selected main three.

Reuses the actual qualified readonly auth projection inside the same original
maintenance parent. It neither repeats a provider operation nor re-labels the
pre-refresh capsule. A separately qualified full-state baseline and actual cold
gateway consumption are still required before restoring production traffic.
"""
from __future__ import annotations
import copy
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import time

from mac_owned_refresh_parent_r1 import OwnedRefreshParent, strict_json
from mac_maintenance_private_files_r1 import MaintenancePrivateFiles

ROOT=Path('/Users/qianqi/heptabao-authbus-writer-maintenance-20261106-r1')
LIVE=Path('/Users/qianqi/.openclaw')
MAIN=LIVE/'agents/main/agent/openclaw-agent.sqlite'
CAPSULE=ROOT/'captures/owner-03/output/selected-owner-credentials.private.json'
QUAL=Path('/Users/qianqi/heptabao-authbus-auth-wal-qualification-20261106-r2/qa')
PINS={'authbus_current_auth_wal.py':'ad443869e259da06de2be71131e5d1854680477d1cf77248e05a3c1704160f8c',
      'mac_registry_readonly_wal_r1.py':'60d5e5874c281af2e19fee55bc4b2242627f69b500f1af1d6b5b22e16120bfed',
      'mac_guarded_current_capture_r3.py':'606b5df58909ebedc035ebbff6a4aa5e754d19c6a7e0f5e4e88c9ddfc57c2693'}
AGENTS=('main','trnm','hepta-ui','hepta','hepta-backend')
FIELDS=('st_dev','st_ino','st_uid','st_gid','st_mode','st_nlink','st_size','st_mtime_ns','st_ctime_ns')

class EpochRefused(RuntimeError):pass
def need(value,code):
    if not value:raise EpochRefused(code)
def identity(value):return tuple(str(getattr(value,key)) for key in FIELDS)
def typed(value):
    need(type(value) in (tuple,list) and len(value)==9
         and all(type(item) is str and re.fullmatch('[0-9]{1,30}',item) for item in value),
         'epoch_full9_private_identity_shape')
    return tuple(value)
def encoded(value):return json.dumps(value,sort_keys=True,separators=(',',':'),allow_nan=False).encode()

class PostCommitEpoch:
    def __init__(self,*,parent,private_files,auth,read_public,source_fence,
                 capsule_bytes,capsule_identity,critical,cancelled,clock=time.monotonic):
        need(isinstance(parent,OwnedRefreshParent) and isinstance(private_files,MaintenancePrivateFiles)
             and parent.until==private_files.until and all(callable(f) for f in
             (read_public,source_fence,critical,cancelled)), 'epoch_original_parent_and_private_io')
        self.parent,self.maintenance,self.private=parent,parent.maintenance,private_files
        self.auth,self.read_public,self.source_fence=auth,read_public,source_fence
        self.critical,self.cancelled,self.clock=critical,cancelled,clock
        self.until=parent.until;self.observation_until=min(self.until,clock()+45)
        self.original_bytes=capsule_bytes;self.original_identity=typed(capsule_identity)
        need(type(capsule_bytes) is bytes and 0<len(capsule_bytes)<=1048576,
             'epoch_original_third_capsule_bounded')
        self.doc=strict_json(capsule_bytes,1048576)
        need(self.doc.get('schema')=='heptabao.actual-sdk-selected-owner-credentials.private.r1'
             and self.doc.get('host')=='mac' and len(self.doc.get('sourceGenerations',[]))==5
             and [row.get('agent') for row in self.doc['sourceGenerations']]==list(AGENTS)
             and len(self.doc.get('registeredMetadataFileBindings',[]))==145,
             'epoch_original_third_capture_finite_scope')
        self.rows=[];self.attempted=False;self.failed=False;self.closed=False;self.document=None
        self.report={'schema':'heptabao.post-three-committed-current-epoch.public.r1','ok':False,
            'originalParentMaximumSeconds':600,'observationMaximumSeconds':45,
            'providerOperationsAdded':0,'nodeChildrenAdded':0,'wholeDatabaseCopiesAdded':0,
            'oldCapsuleRebound':False,'credentialValuesIdsOrDigestsPublished':False,
            'actualGatewayConsumptionQualified':False,'productionRollbackQualified':False,
            'fullPostRefreshSixDatabaseBaselineStillRequired':True,'observations':[]}

    def within(self):
        need(not self.failed and not self.closed and not self.cancelled()
             and self.clock()<min(self.until,self.observation_until), 'epoch_original_deadline_or_closed')

    def _code(self):
        self.within();self.source_fence()
        for name,pin in PINS.items():
            raw=self.read_public(QUAL/name,65536)
            need(type(raw) is bytes and hashlib.sha256(raw).hexdigest()==pin,
                 'epoch_exact_qualified_reader_public_source')
        need(Path(self.auth.__file__)==QUAL/'authbus_current_auth_wal.py'
             and Path(self.auth.readonly_auth_query.__code__.co_filename)==QUAL/'authbus_current_auth_wal.py'
             and Path(self.auth.wal.__file__)==QUAL/'mac_registry_readonly_wal_r1.py'
             and Path(self.auth.base.__file__)==QUAL/'mac_guarded_current_capture_r3.py',
             'epoch_original_reader_modules_loaded_from_bound_files')

    def _read(self,path,maximum,expected,private=False):
        self.within();path=Path(path)
        fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC)
        row={'closeAttempts':0,'closed':False};self.rows.append(row)
        try:
            before=os.fstat(fd);full=identity(before)
            need(stat.S_ISREG(before.st_mode) and before.st_uid in (0,501) and before.st_nlink==1
                 and not stat.S_IMODE(before.st_mode)&0o022 and 0<=before.st_size<=maximum
                 and full==typed(expected)==identity(path.lstat()), 'epoch_whole_bound_file_admission')
            if private:need(before.st_uid==501 and before.st_gid==20 and stat.S_IMODE(before.st_mode)==0o600,
                            'epoch_private_source_custody')
            data=bytearray()
            while len(data)<=before.st_size:
                self.within();part=os.read(fd,min(65536,before.st_size+1-len(data)))
                if not part:break
                data.extend(part)
            need(len(data)==before.st_size and identity(os.fstat(fd))==full==identity(path.lstat()),
                 'epoch_original_whole_file_unchanged')
            self.within();return bytes(data)
        finally:
            row['closeAttempts']=1
            try:os.close(fd);row['closed']=True
            except BaseException:self.failed=True;raise

    def _namespace(self,bundle,base):
        self.within();base=str(base)
        present,absent=bundle.get('sourceIdentities'),bundle.get('sourceAbsences')
        need(type(present) is dict and type(absent) is list and len(absent)==len(set(absent))
             and not set(present)&set(absent)
             and set(present)|set(absent)=={base+s for s in ('','-wal','-shm','-journal')}
             and base in present and base+'-journal' in absent, 'epoch_exact_database_namespace')
        if base+'-wal' in absent:need(base+'-shm' in absent,'epoch_absent_wal_no_shm')
        elif int(typed(present[base+'-wal'])[6])>0:
            need(base+'-shm' in present and int(typed(present[base+'-shm'])[6])>0,
                 'epoch_nonempty_wal_existing_shm')
        for path,expected in present.items():
            self.within();s=Path(path).lstat()
            need(stat.S_ISREG(s.st_mode) and s.st_uid==501 and s.st_gid==20 and s.st_nlink==1
                 and stat.S_IMODE(s.st_mode)==0o600 and identity(s)==typed(expected),
                 'epoch_current_database_full9_exact')
        for path in absent:
            try:Path(path).lstat()
            except FileNotFoundError:continue
            raise EpochRefused('epoch_current_sidecar_expected_absence_changed')

    def _other_sources(self):
        need(self.private.read(CAPSULE,1048576,expected=self.original_identity)==self.original_bytes,
             'epoch_third_capsule_itself_unchanged_not_relabelled')
        for bundle in self.doc['sourceGenerations'][1:]:
            self._namespace(bundle,LIVE/'agents'/bundle['agent']/'agent/openclaw-agent.sqlite')
        self._namespace(self.doc['registryGeneration'],LIVE/'state/openclaw.sqlite')
        raw=self._read(LIVE/'openclaw.json',1048576,self.doc['configurationIdentity'],True)
        need(hashlib.sha256(raw).hexdigest()==self.doc['configurationSha256'],
             'epoch_actual_original_configuration_whole_bytes')
        for entry in self.doc['registeredMetadataFileBindings']:
            self.within()
            need(type(entry) is dict and set(entry)=={'nominal','path','identity','sha256'},
                 'epoch_original_metadata_shape')
            nominal,actual=Path(entry['nominal']),Path(entry['path'])
            need(nominal.is_absolute() and actual.is_absolute() and nominal.resolve(strict=True)==actual,
                 'epoch_same_registered_metadata_alias')
            raw=self._read(actual,2*1048576,entry['identity'])
            need(hashlib.sha256(raw).hexdigest()==entry['sha256'] and nominal.resolve(strict=True)==actual,
                 'epoch_registered_metadata_whole_bytes')

    def capture(self,committed):
        need(not self.attempted and self.document is None and not self.parent.blocked
             and len(committed)==len(self.parent.committed)==len(self.parent.attempts)==3
             and committed==tuple(self.parent.committed) and self.maintenance.owned_refresh_child is None
             and all(row['ok'] for row in self.parent.report['children']),
             'epoch_three_original_known_committed_and_retired')
        self.attempted=True;self.observation_until=min(self.until,self.clock()+45)
        inputs=None
        try:
            self._code();self.maintenance.verify_quiesced('post-three-committed-before-read')
            self._other_sources()
            identifiers=tuple(self.parent.profile_ids)
            need(len(identifiers)==len(set(identifiers))==3
                 and tuple(row['profileId'] for row in self.doc['ownerEntries'])==identifiers,
                 'epoch_same_actual_selected_three_owner_order')
            requested=self.auth.validate_profiles('main',identifiers,identifiers)
            inputs=self.auth.AuthInputs(until=self.observation_until,critical=self.critical,
                                        cancelled=self.cancelled)
            bundle=self.auth.auth_wal_database(inputs,'main')
            old_main=self.doc['sourceGenerations'][0]['sourceIdentities'][str(MAIN)]
            need(tuple(bundle['main']['expected'][:6])==typed(old_main)[:6],
                 'epoch_original_main_inode_preserved_across_known_cas')
            value=self.auth.readonly_auth_query(inputs,bundle,requested)
            need(value['storeRowPresent'] is True and value['registeredMissingCount']==0
                 and set(value['profiles'])==set(identifiers), 'epoch_all_three_current_selected_values')
            for ordinal,profile in enumerate(identifiers):
                original=committed[ordinal]
                need(type(original['ordinal']) is int and original['ordinal']==ordinal
                     and original['outcome']['state']=='COMMITTED'
                     and encoded(value['profiles'][profile])==encoded(original['normalizedCredential']),
                     'epoch_current_values_equal_original_committed_normalized_responses')
            inputs.verify();self.auth.verify_auth_bundle(inputs,bundle,until=self.observation_until)
            current={'agent':'main','sourceIdentities':{name:list(row['expected']) for name,row in inputs.files.items()},
                     'sourceAbsences':list(inputs.absent)}
            inputs.close();closure=inputs.public()
            need(closure['allOwnedDescriptorsClosed'] and not closure['closeErrors'],
                 'epoch_actual_readonly_projection_resources_all_closed')
            self._namespace(current,MAIN);self._other_sources();self._code()
            self.maintenance.verify_quiesced('post-three-committed-after-close')
            self._namespace(current,MAIN)
            # This is a new private post-refresh generation. Only source
            # metadata and original once provenance need durable publication;
            # credential bytes remain in the original three normalized records.
            document={'schema':'heptabao.post-three-committed-current-epoch.private.r1',
                'createdWallNs':time.time_ns(),'originalParentPid':os.getpid(),
                'sourceGenerations':[current,*copy.deepcopy(self.doc['sourceGenerations'][1:])],
                'registryGeneration':copy.deepcopy(self.doc['registryGeneration']),
                'configurationIdentity':copy.deepcopy(self.doc['configurationIdentity']),
                'configurationSha256':self.doc['configurationSha256'],
                'registeredMetadataFileBindings':copy.deepcopy(self.doc['registeredMetadataFileBindings']),
                'originalOnceRecords':[{'ordinal':row['ordinal'],'attemptId':row['attemptId'],
                    'responseSha256':row['privateResponseSha256']} for row in committed],
                'actualSelectedProfileIds':list(identifiers),'allSelectedValuesCompared':True,
                'oldCapsuleRebound':False,'actualGatewayConsumptionQualified':False}
            document['epochId']=hashlib.sha256(encoded(document)).hexdigest()  # private only
            self.private.write('post-three-committed-epoch.private.json',encoded(document))
            self.document=document
            self.report.update(ok=True,currentThreeValuesEqualOriginalCommittedResponses=True,
                currentMainGenerationCapturedAfterSqlClosure=True,allOtherFourAgentGenerationsExact=True,
                currentRegistryGenerationExact=True,currentConfigurationAnd145MetadataExact=True,
                originalSqliteProjectionCount=1,readonlyResourceClosure={key:closure[key] for key in
                ('allOwnedDescriptorsClosed','allHeldDescriptorsClosed','allReturnedConnectionsClosed',
                 'allExplicitCursorsClosed','connectionAttemptCount','returnedConnectionCount','cursorCount')})
            self.verify('after-private-epoch-publication')
            return copy.deepcopy(self.report)
        except BaseException:
            self.failed=True;self.parent.blocked=True;self.report['ok']=False;raise
        finally:
            if inputs is not None:
                inputs.close()
                if not inputs.public()['allOwnedDescriptorsClosed']:
                    self.failed=True;self.parent.blocked=True;self.report['ok']=False

    def verify(self,label):
        need(self.document is not None and type(label) is str and len(self.report['observations'])<16,
             'epoch_finite_original_new_generation_observation')
        self.observation_until=min(self.until,self.clock()+45)
        try:
            self.within();self._code();self.maintenance.verify_quiesced('post-refresh-epoch-'+label)
            self._namespace(self.document['sourceGenerations'][0],MAIN);self._other_sources()
            self._namespace(self.document['sourceGenerations'][0],MAIN);self._code()
            need(all(row['closeAttempts']==1 and row['closed'] for row in self.rows),
                 'epoch_original_observation_file_handles_closed')
            self.report['observations'].append({'label':label,'sameNewPostCommitEpoch':True,
                'fullSixDatabaseGenerationsExact':True,'descriptorClosureKnown':True,
                'continuousLockClaimed':False})
            return True
        except BaseException:self.failed=True;self.parent.blocked=True;self.report['ok']=False;raise

    def close(self):
        self.closed=True
        self.report.update(fileDescriptorsOpened=len(self.rows),
            allFileDescriptorsClosedOnce=all(row['closeAttempts']==1 and row['closed'] for row in self.rows),
            failed=self.failed)
        return copy.deepcopy(self.report)
