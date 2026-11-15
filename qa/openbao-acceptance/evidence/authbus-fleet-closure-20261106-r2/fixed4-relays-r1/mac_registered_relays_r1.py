#!/usr/bin/env python3
"""Fresh private registration/restore inputs for exactly four existing relays.

This observer does not stop services, read credential databases, or infer that
an absent file descriptor means a process has no cached credential. Arguments
are the actual launchd registration arguments, not claimed process memory.
"""
from __future__ import annotations
import base64
import copy
import hashlib
import os
from pathlib import Path
import plistlib
import re
import stat
import time

HOME=Path('/Users/qianqi')
BIN=HOME/'.openclaw/authbus-relay/bin'
DOMAIN='gui/501'
LABELS=tuple('ai.openclaw.authbus-relay.'+name for name in ('proxy','bridge','egressguard','front'))
FIELDS=('st_dev','st_ino','st_uid','st_gid','st_mode','st_nlink','st_size','st_mtime_ns','st_ctime_ns')
STABLE_PRINT=('path','program','arguments','pid','runs','state','last exit code')

class RelayRefused(RuntimeError):pass
def need(value,code):
    if not value:raise RelayRefused(code)
def identity(value):return tuple(getattr(value,key) for key in FIELDS)

class RegisteredRelayInputs:
    def __init__(self,*,commands,reader,parse_print,parse_disabled,plist_factory,
                 parent_until,source_fence,private_write,clock=time.monotonic):
        now=clock()
        need(os.getuid()==501 and now<parent_until<=now+600
             and all(callable(f) for f in (parse_print,parse_disabled,plist_factory,source_fence,private_write)),
             'relay_fixed_original_parent_bindings')
        self.commands,self.reader=commands,reader
        self.parse_print,self.parse_disabled,self.plist_factory=parse_print,parse_disabled,plist_factory
        self.parent_until,self.until,self.started,self.clock=parent_until,min(parent_until,now+45),now,clock
        self.source_fence,self.private_write=source_fence,private_write
        self.rows=[];self.plists=[];self.files=[];self.slots=[];self.failed=self.closed=False
        self.captured=self.transferred=False;self.packet=None
        self.report={'schema':'heptabao.fixed-four-relay-registration.public.r1','ok':False,
            'fixedRegistrationCount':4,'captureMaximumSeconds':45,'originalParentMaximumSeconds':600,
            'serviceActions':0,'providerCalls':0,'credentialDatabaseReads':0,
            'argumentsOrigin':'actual_launchctl_registration',
            'processMemoryEnvironmentOrCredentialsInspected':False,
            'allConsumersQuiesced':False,'wholeGatewayRollbackQualified':False,
            'rawArgumentsEnvironmentPlistOrDigestsPublished':False,'registrations':[],
            'commands':self.rows,'sourceHandlesTransferredToOriginalMaintenance':False}

    def remaining(self):
        need(not self.failed and not self.closed and self.clock()<self.until,
             'relay_original_readonly_or_transferred_lifetime')
        return self.until-self.clock()

    def _command(self,name,argv):
        self.remaining();self.source_fence()
        need(name not in self.slots and len(self.slots)<10,'relay_ten_original_readonly_slots_once')
        self.slots.append(name)
        row,out,err=self.commands.run(name,argv,until=min(self.until,self.clock()+8),maximum=262144)
        self.rows.append({key:value for key,value in row.items()
                          if key not in ('stdoutSha256','stderrSha256')})
        self.private_write(name+'.record.private.json',row)
        self.private_write(name+'.stdout.private',out)
        self.private_write(name+'.stderr.private',err)
        need(row.get('outcomeUnknown') is False and row.get('completeBeforeDeadline') is True
             and type(row.get('exitCode')) is int and row['exitCode']==0 and not err,
             'relay_original_readonly_command_complete_known_zero')
        self.remaining();return out

    def _disabled(self,phase):
        raw=self._command('relay-disabled-'+phase,['/bin/launchctl','print-disabled',DOMAIN])
        result={}
        for label in LABELS:
            value=self.parse_disabled(raw,label)
            need(value is None or type(value) is bool,'relay_exact_selected_disabled_override_type')
            result[label]=value
        return result

    def _query(self,slot,phase):
        target=DOMAIN+'/'+LABELS[slot]
        raw=self._command('relay-%02d-print-%s'%(slot+1,phase),['/bin/launchctl','print',target])
        return self.parse_print(raw,target)

    def _family(self,pid):
        root=self.reader.read(pid)
        need(root['uid']==501 and root['ppid']==1 and type(root['pid']) is int
             and root['pid']==pid and isinstance(root['executable'],str)
             and Path(root['executable']).parent==BIN,
             'relay_original_registered_home_binary_birth')
        rows,relations={pid:root},{};queue=[(pid,0)]
        while queue:
            self.remaining();parent,depth=queue.pop(0)
            children=sorted(self.reader.children(parent))
            need(len(children)==len(set(children)) and len(rows)+len(children)<=64,
                 'relay_bounded_original_family')
            relations[parent]=children
            for child in children:
                need(child not in rows and depth<8,'relay_acyclic_original_family')
                row=self.reader.read(child)
                need(row['ppid']==parent and row['uid']==501,'relay_original_descendant_owner')
                rows[child]=row;queue.append((child,depth+1))
        self._verify_family(rows,relations)
        return rows,relations

    def _verify_family(self,rows,relations):
        for pid,row in rows.items():
            self.remaining()
            need(self.reader.read(pid)==row and sorted(self.reader.children(pid))==relations[pid],
                 'relay_complete_original_birth_and_children_exact')

    def _binary(self,path):
        self.remaining();path=Path(path)
        need(path.parent==BIN and path.name not in ('','.','..') and path.resolve(strict=True)==path,
             'relay_only_actual_fixed_binary_directory')
        parents=[];parent_fd=None;leaf=None
        try:
            for item in [Path('/'),*list(reversed(path.parent.parents))[1:],path.parent]:
                fd=(os.open('/',os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW) if parent_fd is None else
                    os.open(item.name,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=parent_fd))
                row={'fd':fd,'path':item,'closed':False,'closeAttempts':0};self.files.append(row);parents.append(row)
                value=os.fstat(fd);row['identity']=identity(value)
                need(stat.S_ISDIR(value.st_mode) and value.st_uid==(501 if item.is_relative_to(HOME) else 0)
                     and not stat.S_IMODE(value.st_mode)&0o022 and identity(item.lstat())==row['identity'],
                     'relay_complete_nonalias_binary_ancestor_custody')
                parent_fd=fd
            fd=os.open(path.name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=parent_fd)
            leaf={'fd':fd,'path':path,'closed':False,'closeAttempts':0};self.files.append(leaf)
            value=os.fstat(fd);leaf['identity']=identity(value)
            need(stat.S_ISREG(value.st_mode) and value.st_uid==501 and value.st_gid==20 and value.st_nlink==1
                 and not stat.S_IMODE(value.st_mode)&0o022 and value.st_mode&0o100
                 and 0<value.st_size<=64*1048576,'relay_bounded_original_executable_custody')
            count=0;digest=hashlib.sha256()
            while count<=value.st_size:
                self.remaining();part=os.read(fd,min(1048576,value.st_size+1-count))
                if not part:break
                count+=len(part);digest.update(part)
            need(count==value.st_size and identity(os.fstat(fd))==leaf['identity']==identity(path.lstat()),
                 'relay_whole_executable_named_generation_exact')
            for row in parents:
                need(identity(os.fstat(row['fd']))==row['identity']==identity(row['path'].lstat()),
                     'relay_binary_parent_unchanged_during_read')
            return {'path':str(path),'full9':list(leaf['identity']),'bytes':count,
                    'sha256':digest.hexdigest(),'parentGenerations':{str(row['path']):list(row['identity']) for row in parents}}
        finally:
            close_unknown=False
            for row in reversed([*parents,*([leaf] if leaf is not None else [])]):
                if row['closeAttempts']:continue
                row['closeAttempts']=1
                try:os.close(row['fd']);row['closed']=True
                except BaseException:self.failed=True;close_unknown=True
            need(not close_unknown,'relay_original_binary_descriptor_close_unknown')

    def _binary_metadata(self,value):
        self.remaining()
        need(identity(Path(value['path']).lstat())==tuple(value['full9']),
             'relay_same_bound_executable_generation')
        for path,expected in value['parentGenerations'].items():
            need(identity(Path(path).lstat())==tuple(expected),'relay_same_executable_ancestor_generation')

    def capture(self):
        need(not self.captured and self.packet is None,'relay_four_registration_capture_once')
        self.captured=True;private=[]
        try:
            self.source_fence();disabled=self._disabled('before');seen=set()
            for slot,label in enumerate(LABELS):
                self.remaining();plist=self.plist_factory(label,self.remaining);self.plists.append(plist)
                raw,full=plist.open();value=plistlib.loads(raw)
                path=HOME/'Library/LaunchAgents'/(label+'.plist')
                need(type(value) is dict and value.get('Label')==label,'relay_exact_original_plist_label')
                args=value.get('ProgramArguments');environment=value.get('EnvironmentVariables',{})
                plist_disabled=value.get('Disabled',False)
                need(type(plist_disabled) is bool,'relay_boolean_original_plist_disabled')
                need(type(args) is list and 1<=len(args)<=32 and all(type(s) is str and '\0' not in s
                     and len(s.encode())<=16384 for s in args),'relay_bounded_private_plist_arguments')
                need(type(environment) is dict and len(environment)<=256 and all(type(k) is str and type(v) is str
                     and len(k)<=256 and '\0' not in k+v and len(v.encode())<=16384 for k,v in environment.items()),
                     'relay_bounded_private_plist_environment')
                first=self._query(slot,'before')
                need(first.get('path')==str(path) and first.get('state')=='running'
                     and type(first.get('pid')) is int and first.get('arguments')==args
                     and first.get('program')==value.get('Program',args[0]),
                     'relay_exact_current_loaded_registration_and_plist')
                family,relations=self._family(first['pid'])
                need(not seen.intersection(family),'relay_four_distinct_original_families');seen.update(family)
                binary=self._binary(family[first['pid']]['executable'])
                direct=Path(first['program']).is_absolute() and str(Path(first['program']).resolve(strict=True))==binary['path']
                record={'ordinal':slot,'label':label,'target':DOMAIN+'/'+label,'plistPath':str(path),
                    'plistBytesBase64':base64.b64encode(raw).decode(),'plistFull9':list(full),'plist':value,
                    'loadedFirst':first,'arguments':args,'environment':environment,
                    'originalDisabledOverride':disabled[label],
                    'originalPlistDisabled':plist_disabled,
                    'originalEffectiveDisabled':plist_disabled if disabled[label] is None else disabled[label],
                    'originalFamilies':family,
                    'originalChildRelations':relations,'originalExecutable':binary,
                    'registeredProgramResolvesToKernelImage':direct,
                    'sourceMemoryOrProviderEquivalenceClaimed':False}
                private.append(record)
            after=self._disabled('after')
            need(after==disabled,'relay_four_original_disabled_effects_and_absence_stable')
            for slot,record in enumerate(private):
                second=self._query(slot,'after');record['loadedSecond']=second
                need(all(second.get(key)==record['loadedFirst'].get(key) for key in STABLE_PRINT),
                     'relay_same_registration_after_all_four_captures')
                self._verify_family(record['originalFamilies'],record['originalChildRelations'])
                self.plists[slot].verify();self._binary_metadata(record['originalExecutable'])
                keep=record['plist'].get('KeepAlive',False)
                keep_kind='true' if keep is True else 'false' if keep is False else 'dictionary' if type(keep) is dict else 'other'
                override=record['originalDisabledOverride']
                self.report['registrations'].append({'ordinal':slot,'registeredRunning':True,
                    'programArgumentsEqualActualLaunchdRegistration':True,
                    'registeredProgramResolvesToKernelImage':record['registeredProgramResolvesToKernelImage'],
                    'keepAliveKind':keep_kind,'abandonProcessGroupEnabled':record['plist'].get('AbandonProcessGroup') is True,
                    'originalDisabledOverride':'absent' if override is None else 'disabled' if override else 'enabled',
                    'originalPlistDisabled':record['originalPlistDisabled'],
                    'originalRegisteredDisabledConfiguration':record['originalEffectiveDisabled'],
                    'descendantCount':len(record['originalFamilies'])-1,'originalExecutableBytePinBoundPrivately':True,
                    'sameFullBirthAndPlistWholeBytesTwice':True,
                    'productionRestartOrRollbackQualified':False})
            self.source_fence();self.remaining()
            packet={'schema':'heptabao.fixed-four-relay-restore-inputs.private.r1',
                'createdWallNs':time.time_ns(),'originalParentPid':os.getpid(),'registrations':private,
                'argumentsOrigin':'actual_launchctl_registration','processMemoryEnvironmentClaimed':False,
                'notAuthorityFromHistoricalReceipt':True,'restorationRequiresKnownProviderEpoch':True}
            self.private_write('four-relay-restore-inputs.private.json',packet)
            self.packet=packet;self.verify()
            self.report.update(ok=True,allFourRegistrationSourcesBoundTwice=True,
                privateRestoreInputsDurablyPublished=True,allFourSourceHandlesStillHeld=True)
            return copy.deepcopy(self.report)
        except BaseException:self.failed=True;self.report['ok']=False;raise

    def verify(self):
        need(self.packet is not None,'relay_original_private_packet_required')
        self.verify_sources()
        for slot,record in enumerate(self.packet['registrations']):
            self._verify_family(record['originalFamilies'],record['originalChildRelations'])
        return True

    def verify_sources(self):
        need(self.packet is not None,'relay_original_private_packet_required')
        self.remaining();self.source_fence()
        for slot,record in enumerate(self.packet['registrations']):
            self.plists[slot].verify();self._binary_metadata(record['originalExecutable'])
        return True

    def transfer_to_original_maintenance(self):
        need(self.captured and self.packet is not None and self.report['ok'] is True and not self.transferred,
             'relay_single_existing_handle_handoff')
        self.verify();need(self.clock()<self.until<=self.parent_until,'relay_handoff_before_original_capture_deadline')
        self.transferred=True;self.until=self.parent_until
        self.report['sourceHandlesTransferredToOriginalMaintenance']=True
        # No source FD is closed and reopened, and no child/HTTP budget changes.
        return self

    def close(self):
        if not self.closed:
            for plist in reversed(self.plists):plist.close()
            self.closed=True
        closure=[item.public() for item in self.plists]
        self.report.update(allPlistSourceDescriptorsClosedOnce=all(item['allOwnedDescriptorsClosedOnce'] for item in closure),
            plistSourceDescriptorCount=sum(item['ownedDescriptorCount'] for item in closure),
            binaryDescriptorCount=len(self.files),allBinaryDescriptorsClosedOnce=all(
                row['closed'] and row['closeAttempts']==1 for row in self.files),
            allFourSourceHandlesStillHeld=False)
        if not self.report['allPlistSourceDescriptorsClosedOnce'] or not self.report['allBinaryDescriptorsClosedOnce']:
            self.report['ok']=False
        return copy.deepcopy(self.report)
