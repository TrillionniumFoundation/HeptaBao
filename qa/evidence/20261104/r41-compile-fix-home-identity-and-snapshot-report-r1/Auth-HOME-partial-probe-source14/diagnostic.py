#!/usr/bin/env python3
"""Read only one already-created public HOME root and its fixed server copy.
Fresh observation only. The original failed write's metadata was not retained.
No directory scan, mkdir, writes, child, launchd, T5, private inputs or SDK.
"""
from __future__ import annotations
import hashlib,json,os,re,signal,stat,sys,time
from contextlib import contextmanager
from pathlib import Path
EXPECTED=json.loads("{\"schema\":\"heptabao.home-partial-readonly-fixed-inputs.v1\",\"root\":\"/Users/qianqi/heptabao-mac-authbus-4e808-home-launch-20261106-r1\",\"originalFailedJob\":\"1a1b0702e84-fc05-708a\",\"originalStdout\":{\"blob\":\"905b50d39c980b7c9c4041825dd815131490f344\",\"bytes\":6966,\"sha256\":\"acf89e2a45e1efe26a7b0a3b9b51123b36832a3e113821dc4cec86c631314874\"},\"parents\":[{\"path\":\"/\",\"identity\":[\"16777233\",\"2\",\"0\",\"0\",\"16877\",\"22\",\"704\",\"1786589515000000000\",\"1786589515000000000\"]},{\"path\":\"/Users\",\"identity\":[\"16777233\",\"18326\",\"0\",\"80\",\"16877\",\"6\",\"192\",\"1790904461743063380\",\"1790904461743063380\"]},{\"path\":\"/Users/qianqi\",\"identity\":[\"16777233\",\"6929812\",\"501\",\"20\",\"16877\",\"298\",\"9536\",\"1793960981148958120\",\"1793960981148958120\"]}],\"rootOriginalFull9\":[\"16777233\",\"593068531\",\"501\",\"20\",\"16832\",\"2\",\"64\",\"1793961504844318705\",\"1793961504844318705\"],\"serverCopy\":{\"name\":\"mac_current_server_owner_r1.py\",\"path\":\"/Users/qianqi/heptabao-mac-authbus-4e808-home-launch-20261106-r1/mac_current_server_owner_r1.py\",\"bytes\":14052,\"sha256\":\"6e0fd6f2aee1bc72b931824846cc26e90053939c995620f9e14ed009d3207e27\"},\"absenceNames\":[\"mac_current_phase_owner_r2.py\",\"server-initial.plist\",\"server-initial.stdout.private\",\"server-initial.stderr.private\",\"server-cold-new-process.plist\",\"server-cold-new-process.stdout.private\",\"server-cold-new-process.stderr.private\",\"initial.plist\",\"initial.stdout.private\",\"initial.stderr.private\",\"cold-new-process.plist\",\"cold-new-process.stdout.private\",\"cold-new-process.stderr.private\",\"initial-inverse.plist\",\"initial-inverse.stdout.private\",\"initial-inverse.stderr.private\",\"cold-new-process-inverse.plist\",\"cold-new-process-inverse.stdout.private\",\"cold-new-process-inverse.stderr.private\"]}")
START=time.monotonic()
UNTIL=START+5.0
MAX_FDS=5
MAX_METADATA=128
MAX_READ_CALLS=8
MAX_RETURNED_BYTES=14053
MAX_OUTPUT=16384
protected=0
pending=None

class Refused(RuntimeError):pass
def need(value,code):
    if not value:raise Refused(code)
def remaining():
    need(pending is None,'pending_signal')
    need(time.monotonic()<UNTIL,'original_shared_5_seconds')
def identity(value):
    return tuple(str(x) for x in (value.st_dev,value.st_ino,value.st_uid,value.st_gid,
        value.st_mode,value.st_nlink,value.st_size,value.st_mtime_ns,value.st_ctime_ns))
def encoded(value):
    return (json.dumps(value,sort_keys=True,separators=(',',':'))+'\n').encode('ascii')
def receive(signum,_frame):
    global pending
    pending=signum
    if not protected:raise KeyboardInterrupt()
@contextmanager
def critical():
    global protected
    protected+=1
    try:yield
    finally:protected-=1

class FixedRead:
    def __init__(self):
        self.rows=[];self.directories=[];self.open_attempts=0;self.open_pending=0
        self.registration_unknown=False;self.close_errors=[];self.closed=False
        self.counts={'metadata':0,'readCalls':0,'returnedBytes':0}
        self.root_observations=[];self.absence_observations=[]
        self.copy_observation=None;self.complete=False
    def metadata(self):
        need(self.counts['metadata']<MAX_METADATA,'metadata_cap')
        self.counts['metadata']+=1
    def fstat(self,fd):
        self.metadata();return os.fstat(fd)
    def named(self,name,parent=None):
        self.metadata();return os.stat(name,dir_fd=parent,follow_symlinks=False)
    def open_fd(self,name,flags,*,parent,path,kind):
        remaining()
        with critical():
            need(self.open_attempts<MAX_FDS,'returned_fd_attempt_cap')
            self.open_attempts+=1;self.open_pending+=1
            try:fd=os.open(name,flags,dir_fd=parent)
            except OSError:
                self.open_pending-=1
                raise
            try:
                row={'fd':fd,'path':str(path),'kind':kind,'closeAttempted':False,'closed':False}
                self.rows.append(row);self.open_pending-=1
            except BaseException:
                self.registration_unknown=True
                raise
        return row
    def close_one(self,row):
        if row['closeAttempted']:return
        with critical():
            row['closeAttempted']=True
            try:os.close(row['fd']);row['closed']=True
            except BaseException as error:
                self.close_errors.append({'path':row['path'],'type':type(error).__name__,
                                          'errno':getattr(error,'errno',None)})
    def close(self):
        with critical():
            if not self.closed:
                for row in reversed(self.rows):self.close_one(row)
                self.closed=True
    def acquire_directories(self):
        paths=[x['path'] for x in EXPECTED['parents']]+[EXPECTED['root']]
        bindings=[x['identity'] for x in EXPECTED['parents']]+[EXPECTED['rootOriginalFull9']]
        need(paths==['/','/Users','/Users/qianqi',EXPECTED['root']]
             and len(bindings)==4,'four_fixed_directory_chain')
        for index,(path,old) in enumerate(zip(paths,bindings)):
            remaining();p=Path(path)
            parent=None if index==0 else self.directories[-1]['fd']
            row=self.open_fd(str(p) if index==0 else p.name,
                os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC,
                parent=parent,path=p,kind='directory')
            held=self.fstat(row['fd']);named=self.named(p if index==0 else p.name,parent)
            current=identity(held);named_identity=identity(named)
            row['identity']=current;row['namedIdentity']=named_identity
            row['fixedFirst5Matched']=current[:5]==tuple(old[:5])
            need(current==named_identity and row['fixedFirst5Matched']
                 and stat.S_ISDIR(held.st_mode),'directory_fd_name_fixed_first5')
            self.directories.append(row)
        self.check_directories('after_acquire')
    def check_directories(self,label):
        remaining()
        for index,row in enumerate(self.directories):
            path=Path(row['path'])
            parent=None if index==0 else self.directories[index-1]['fd']
            held=identity(self.fstat(row['fd']))
            named=identity(self.named(path if index==0 else path.name,parent))
            same_object=held[:5]==row['identity'][:5]
            if index==3:
                projection={'stage':label,'heldFull9':list(held),'namedFull9':list(named),
                    'heldNamedFull9Equal':held==named,'sameObservedFirst5':same_object,
                    'sameFull9AsCurrentOpen':held==row['identity'],
                    'sameFirst5AsOriginalFailure':held[:5]==tuple(EXPECTED['rootOriginalFull9'][:5]),
                    'fieldEqualToOriginalPrewrite':[x==y for x,y in zip(held,EXPECTED['rootOriginalFull9'])]}
                self.root_observations.append(projection)
                need(projection['sameFull9AsCurrentOpen'],'owned_root_full9_drift_during_observation')
            need(held==named and same_object,'directory_held_named_current_fence')
        remaining()
    def observe_absence(self,stage):
        parent=self.directories[-1]['fd']
        names=EXPECTED['absenceNames']
        need(len(names)==19 and len(set(names))==19,'exact_nineteen_absence_names')
        for name in names:
            remaining()
            need('/' not in name and name not in ('.','..'),'fixed_flat_absence_name')
            try:self.named(name,parent)
            except FileNotFoundError:
                self.absence_observations.append({'stage':stage,'name':name,'enoentObserved':True})
            else:
                self.absence_observations.append({'stage':stage,'name':name,'enoentObserved':False})
                raise Refused('known_absence_leaf_present')
    def read_piece(self,fd,count):
        remaining()
        need(type(count) is int and 0<count<=14052
             and self.counts['readCalls']<MAX_READ_CALLS
             and self.counts['returnedBytes']+count<=MAX_RETURNED_BYTES,'bounded_read_request')
        self.counts['readCalls']+=1
        raw=os.read(fd,count)
        self.counts['returnedBytes']+=len(raw)
        need(len(raw)<=count,'returned_read_bound')
        remaining();return raw
    def read_server_copy(self):
        expected=EXPECTED['serverCopy'];root=self.directories[-1]['fd']
        need(expected['path']==str(Path(EXPECTED['root'])/expected['name'])
             and expected['name']=='mac_current_server_owner_r1.py'
             and expected['bytes']==14052
             and re.fullmatch(r'[0-9a-f]{64}',expected['sha256']) is not None,
             'exact_public_server_copy_binding')
        row=self.open_fd(expected['name'],
            os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC,
            parent=root,path=expected['path'],kind='public_copy')
        try:
            info=self.fstat(row['fd']);before=identity(info)
            named_before=identity(self.named(expected['name'],root))
            self.copy_observation={'path':expected['path'],'beforeFull9':list(before),
                'beforeNamedFull9':list(named_before),'expectedBytes':expected['bytes'],
                'wholeExpectedHashMatched':False,'afterFull9':None,'afterNamedFull9':None,
                'boundedEOFObserved':False,'rawContentPublished':False}
            need(before==named_before and stat.S_ISREG(info.st_mode)
                 and info.st_uid==501 and info.st_gid==20
                 and info.st_nlink==1 and stat.S_IMODE(info.st_mode)==0o600
                 and info.st_size==expected['bytes'],'public_copy_regular_full9_size_owner')
            parts=[];size=0
            while size<expected['bytes']:
                raw=self.read_piece(row['fd'],expected['bytes']-size)
                need(bool(raw),'public_copy_nonempty_progress')
                size+=len(raw);parts.append(raw)
            tail=self.read_piece(row['fd'],1)
            self.copy_observation['boundedEOFObserved']=tail==b''
            need(tail==b'','public_copy_exact_eof')
            body=b''.join(parts)
            after=identity(self.fstat(row['fd']))
            named_after=identity(self.named(expected['name'],root))
            self.copy_observation['afterFull9']=list(after)
            self.copy_observation['afterNamedFull9']=list(named_after)
            need(before==after==named_after,'public_copy_same_interval_full9')
            matched=hashlib.sha256(body).hexdigest()==expected['sha256']
            self.copy_observation['wholeExpectedHashMatched']=matched
            need(len(body)==expected['bytes'] and matched,'public_copy_exact_expected_whole_sha')
            self.copy_observation['verifiedSha256']=expected['sha256']
            self.copy_observation['verifiedBytes']=len(body)
        finally:
            self.close_one(row)
            need(row['closed'],'public_copy_fd_close_known')
    def public(self):
        return {'schema':'heptabao.home-partial-readonly-fd-ledger.v1',
            'rows':[dict(x) for x in self.rows],'openAttempts':self.open_attempts,
            'openPending':self.open_pending,'registrationUnknown':self.registration_unknown,
            'closeErrors':list(self.close_errors),'counts':dict(self.counts),
            'allReturnedDescriptorsClosed':bool(self.closed and self.open_pending==0
                and not self.registration_unknown and not self.close_errors
                and all(x['closeAttempted'] and x['closed'] for x in self.rows)),
            'interpreterInternalDescriptorsEnumerated':False}

def main():
    report={'schema':'heptabao.home-partial-readonly-observation.r1','ok':False,
        'observationComplete':False,'outcomeUnknown':False,
        'freshObservationOnly':True,'originalFailedPredicateValuesRecovered':False,
        'originalPartialEffectUnknownPreserved':True,
        'originalFailedJob':EXPECTED['originalFailedJob'],
        'originalStdoutPin':EXPECTED['originalStdout'],
        'sharedDeadlineSeconds':5,
        'directoryScanPerformed':False,'writesPerformed':False,
        'childrenStarted':False,'servicesOrSDKExecuted':False,'privateInputsRead':False,
        't5Read':False,'publicCopyBodyMaximum':14052,'returnedBytesIncludingEOFMaximum':14053,
        'maximumFds':5,'maximumMetadata':128,'metadataWorstCaseForCompletePath':82,
        'maximumReadCalls':8,'outputMaximum':16384}
    io=None;io_init_started=False;io_init_complete=False
    old_handlers=[];restore_errors=[]
    try:
        with critical():
            for signum in (signal.SIGTERM,signal.SIGINT):
                old_handlers.append((signum,signal.getsignal(signum)))
                signal.signal(signum,receive)
        need(sys.platform=='darwin' and os.getuid()==501,'fixed_mac_owner')
        remaining()
        io_init_started=True;io=FixedRead.__new__(FixedRead);io.__init__();io_init_complete=True
        io.acquire_directories()
        io.observe_absence('before_copy')
        io.check_directories('before_copy')
        io.read_server_copy()
        io.check_directories('after_copy')
        io.observe_absence('after_copy')
        io.check_directories('after_absence')
        remaining();io.complete=True
    except BaseException as error:
        report['errorType']=type(error).__name__
        report['errorCode']=str(error) if isinstance(error,Refused) else None
        report['errno']=getattr(error,'errno',None)
    finally:
        if io is not None:
            try:io.close()
            except BaseException as error:
                report['closeErrorType']=type(error).__name__
        with critical():
            for signum,handler in reversed(old_handlers):
                try:signal.signal(signum,handler)
                except BaseException as error:
                    restore_errors.append({'signal':signum,'errorType':type(error).__name__})
        report['signalRestoreErrors']=restore_errors
        report['pendingSignal']=pending
        report['ioInitializationStarted']=io_init_started
        report['ioInitializationComplete']=io_init_complete
        if io_init_complete:
            report['descriptorClosure']=io.public()
            report['rootObservations']=io.root_observations
            report['absenceObservations']=io.absence_observations
            report['serverCopy']=io.copy_observation
        closed=bool(io_init_complete and report.get('descriptorClosure',{}).get('allReturnedDescriptorsClosed'))
        report['outcomeUnknown']=bool(not closed or pending is not None or restore_errors)
        completed_at=time.monotonic()
        report['elapsedSeconds']=completed_at-START
        report['deadlineMetAfterClosure']=completed_at<UNTIL
        report['observationComplete']=bool(io_init_complete and io.complete and closed
            and not report['outcomeUnknown'] and completed_at<UNTIL)
        report['ok']=report['observationComplete']
        raw=encoded(report)
        if len(raw)>MAX_OUTPUT:
            raw=encoded({'schema':report['schema'],'ok':False,'observationComplete':False,
                'outcomeUnknown':True,'errorCode':'public_report_size_bound',
                'originalPartialEffectUnknownPreserved':True})
            report['ok']=False
        sys.stdout.buffer.write(raw);sys.stdout.buffer.flush()
    return 0 if report['ok'] and pending is None and time.monotonic()<UNTIL else 1

if __name__=='__main__':sys.exit(main())
