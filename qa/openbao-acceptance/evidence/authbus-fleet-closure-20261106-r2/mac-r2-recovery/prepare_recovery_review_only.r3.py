
import ast,hashlib,json,os,stat,sys,time
from pathlib import Path
ROOT=Path('/Users/qianqi/heptabao-mac-authbus-r2-recovery-preparation-20261106-r3')
def need(value):
    if not value:raise RuntimeError('preparation_refused')
need(sys.platform=='darwin' and os.geteuid()==501)
payload=sys.stdin.buffer.read(131073);need(len(payload)<=131072)
data=json.loads(payload);source=data['source'];raw=source.encode();need(len(raw)<=65536)
ast.parse(source);source_sha=hashlib.sha256(raw).hexdigest()
os.mkdir(ROOT,0o700)
fd_root=os.open(ROOT,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
info=os.fstat(fd_root);need(info.st_uid==501 and stat.S_IMODE(info.st_mode)==0o700)
written={}
def save(name,text):
    body=text.encode()
    fd=os.open(name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600,dir_fd=fd_root)
    try:
        offset=0
        while offset<len(body):
            n=os.write(fd,body[offset:]);need(n>0);offset+=n
        os.fsync(fd)
    finally:os.close(fd)
    os.fsync(fd_root)
    written[name]={'bytes':len(body),'sha256':hashlib.sha256(body).hexdigest()}
save('recover_r2_qa_once.py',source)
save('prior-terminal.public.json',data['priorTerminal'])
save('prior-stdout.original',data['priorStdout'])
ns={'__name__':'prepared_definitions_only','__source_sha256__':source_sha}
exec(compile(source,str(ROOT/'recover_r2_qa_once.py'),'exec'),ns)
Recovery=ns['Recovery'];Refused=ns['Refused'];real_time=ns['time']
need(written['prior-terminal.public.json']['sha256']==ns['PRIOR_TERMINAL_SHA']
     and written['prior-stdout.original']['sha256']==ns['PRIOR_STDOUT_SHA'])
results=[]
def case(name,fn):
    fn();results.append({'name':name,'passed':True})
def refuses(fn):
    try:fn()
    except Refused:return
    raise AssertionError('refusal_required')
class Clock:
    def __init__(self):self.now=1000.0
    def monotonic(self):return self.now
    def sleep(self,seconds):self.now+=seconds
class FakeJournal:
    def __init__(self):self.rows=[]
    def check(self):pass
    def write_new(self,name,value):
        need(name not in [n for n,v in self.rows])
        self.rows.append((name,json.loads(json.dumps(value))))
        return 'a'*64
def fake(initial='live',kill_signal='9'):
    clock=Clock();ns['time']=clock
    r=Recovery();r.clock=clock;r.journal=FakeJournal();r.fake_state=initial
    r.fake_signal='15';r.fake_calls=[];r.prior_term_verified=True
    r.report['publicInputSha256']={};r.report['durableInitialIntentSha256']='b'*64
    r.report['priorKnownTerm']={'complete':True,'exitCode':0,'termDispatchCount':1}
    def observe(allow_missing=False):
        r.remaining()
        row={'state':r.fake_state,'relatedProcessRows':[]}
        if r.fake_state=='retired':
            row['launchctlTerminal']={'runs':1,'state':'not running',
                'last exit code':None,'last terminating signal':r.fake_signal}
        return row
    def call(label,argv,cap=10):
        operation=label.removeprefix('launchctl-')
        need(operation in ('kill','bootout'))
        need(any(n.endswith(operation+'-intent.public.json') for n,v in r.journal.rows))
        r.fake_calls.append(label)
        if operation=='kill':r.fake_state='retired';r.fake_signal=kill_signal
        else:r.fake_state='absent'
        return {'complete':True,'outcomeUnknown':False,'exitCode':0},b'',b''
    r.observe=observe;r.call=call;r.guard=lambda:None
    r.preflight=lambda:r.report.update(initialObservation=observe())
    return r
def allow_kill(r):
    r.report['newObservationGraceCompleted']=True
    r.report['newObservationGraceElapsedSeconds']=20
def full_grace():
    r=fake();r.run()
    need(r.report['ok'] and r.fake_calls==['launchctl-kill','launchctl-bootout']
         and r.report['newObservationGraceElapsedSeconds']>=20
         and r.clock.now-r.started>=20 and 'term' not in r.attempts)
case('new-full-twenty-second-observation-before-single-kill',full_grace)
def retired():
    r=fake('retired');r.run()
    need(r.report['ok'] and r.fake_calls==['launchctl-bootout']
         and 'newObservationGraceCompleted' not in r.report)
case('already-retired-known-term-needs-only-bootout',retired)
def term_disabled():
    r=fake();refuses(lambda:r.dispatch_once('term'))
    need(not r.fake_calls and not r.journal.rows)
case('term-has-no-callable-dispatch-branch',term_disabled)
def no_new_grace():
    r=fake();refuses(lambda:r.dispatch_once('kill'));need(not r.fake_calls)
case('prior-term-does-not-substitute-new-twenty-second-observation',no_new_grace)
def no_prior():
    r=fake();allow_kill(r);r.prior_term_verified=False
    refuses(lambda:r.dispatch_once('kill'));need(not r.fake_calls)
case('new-kill-requires-pinned-prior-known-term',no_prior)
def duplicate():
    r=fake();allow_kill(r);r.dispatch_once('kill')
    refuses(lambda:r.dispatch_once('kill'));need(r.fake_calls==['launchctl-kill'])
case('kill-cannot-repeat',duplicate)
def unknown():
    r=fake();allow_kill(r)
    def call(*a,**k):
        r.fake_calls.append('unknown-kill');raise Refused('unknown')
    r.call=call;refuses(lambda:r.dispatch_once('kill'))
    need(r.attempts['kill']['attempted'] and not r.attempts['kill']['complete'])
    r.fake_state='retired';r.report['retirementTerminalVerified']=True
    refuses(lambda:r.dispatch_once('kill'));refuses(lambda:r.dispatch_once('bootout'))
    need(r.fake_calls==['unknown-kill'])
case('unknown-kill-stops-repeat-and-bootout-even-if-process-gone',unknown)
def nonzero():
    r=fake();allow_kill(r)
    def call(*a,**k):
        r.fake_calls.append('failed-kill');return {'complete':True,'exitCode':1},b'',b'failure'
    r.call=call;refuses(lambda:r.dispatch_once('kill'))
    r.fake_state='retired';r.report['retirementTerminalVerified']=True
    refuses(lambda:r.dispatch_once('bootout'));need(r.fake_calls==['failed-kill'])
case('known-nonzero-kill-stops-bootout',nonzero)
def identity_change():
    r=fake();allow_kill(r);n=[0]
    def observe(allow_missing=False):
        n[0]+=1
        if n[0]==2:raise Refused('identity_changed')
        return {'state':'live'}
    r.observe=observe;refuses(lambda:r.dispatch_once('kill'))
    need(not r.fake_calls and len(r.journal.rows)==1)
case('identity-change-after-fsynced-intent-stops-dispatch',identity_change)
def expired():
    r=fake();allow_kill(r);r.until=r.started-1
    refuses(lambda:r.dispatch_once('kill'));need(not r.fake_calls)
case('expired-total-budget-blocks-dispatch',expired)
def insufficient():
    r=fake();r.until=r.started+19
    refuses(r.run);need(not r.fake_calls)
case('insufficient-new-budget-cannot-shorten-grace',insufficient)
def unknown_terminal():
    r=fake(kill_signal=None);refuses(r.run)
    need(r.fake_calls==['launchctl-kill']
         and r.report['retirementLaunchctlTerminal']['last terminating signal'] is None)
case('missing-post-kill-signal-never-implies-success',unknown_terminal)
for value in ('9','SIGKILL','Killed: 9','9 (Killed: 9)'):
    def known_terminal(value=value):
        r=fake(kill_signal=value);r.run()
        need(r.report['retirementTerminalVerified'] and r.fake_calls==['launchctl-kill','launchctl-bootout'])
    case('known-post-kill-terminal-'+value,known_terminal)
ns['time']=real_time
def fixture(raw):
    r=Recovery();r.call=lambda *a,**k:({'exitCode':0},raw,b'');return r
def foreign_metadata():
    r=fixture(b'97472 1 97472 -2 Ss\n97473 1 97473 -3 ?X\n97474 1 97474\n32527 1 32527 501 S\n')
    need(r.related_rows()==[{'pid':32527,'ppid':1,'pgid':32527,'uid':501,'stat':'S'}])
case('unrelated-uid-stat-are-not-identity-gates',foreign_metadata)
def related_uid():
    for uid in ('-2','-3','0','502','+501'):
        r=fixture(('32527 1 32527 '+uid+' S\n').encode());refuses(r.related_rows)
        need(r.report['rejectedProcessMetadataRow']['fields'][3]==uid)
case('all-related-uids-remain-exact-501-with-offending-row',related_uid)
def selector():
    for column in range(3):
        f=['97472','1','97472','501','S'];f[column]='-2'
        r=fixture((' '.join(f)+'\n').encode());refuses(r.related_rows)
        need(r.report['rejectedProcessMetadataRow']['fields']==f)
case('all-selector-columns-remain-strict-with-offending-row',selector)
def malformed_selector():
    r=fixture(b'not-a-pid 1 97472 501 S\n');refuses(r.related_rows)
    need(r.report['rejectedProcessMetadataRow']['fields'][0]=='not-a-pid')
case('unrelated-malformed-selector-still-fails-closed',malformed_selector)
def related_stat():
    r=fixture(b'32527 1 32527 501 ?X\n');refuses(r.related_rows)
    need(r.report['rejectedProcessMetadataRow']['fields'][4]=='?X')
case('unknown-related-stat-refused-and-preserved',related_stat)
def related_columns():
    r=fixture(b'32527 1 32527 501\n');refuses(r.related_rows)
    need(r.report['rejectedProcessMetadataRow']['fieldCount']==4)
case('related-record-still-requires-complete-five-columns',related_columns)
def prior_exit_unknown():
    r=Recovery()
    refuses(lambda:r.verify_retirement_terminal({'state':'retired','launchctlTerminal':{'last exit code':None,'last terminating signal':None}}))
    need(not r.report.get('retirementTerminalVerified',False))
case('never-exited-null-cannot-qualify-prior-retirement',prior_exit_unknown)
def journal_once():
    old=ns['RECOVERY_ROOT'];ns['RECOVERY_ROOT']=ROOT/'synthetic-journal'
    try:
        j=ns['Journal']();j.write_new('001-intent.public.json',{'synthetic':True})
        refuses(lambda:j.write_new('001-intent.public.json',{'synthetic':False}))
        j.close_once();need(j.closed)
        try:ns['Journal']()
        except FileExistsError:return
        raise AssertionError('journal_reused')
    finally:ns['RECOVERY_ROOT']=old
case('actual-private-journal-fsync-create-only-no-reuse',journal_once)
real_journal=ns['Journal']
try:
    ns['Journal']=FakeJournal
    native=Recovery();native.preflight()
    need(native.attempts=={} and native.prior_term_verified
         and native.report['initialObservation']['state'] in ('live','retired')
         and len(native.journal.rows)==1
         and all(r['complete'] and not r['outcomeUnknown'] and r['exitCode']==0
                 and r['label'] in ('launchctl-print','ps-fixed-metadata') for r in native.commands))
    native_report={'ok':True,'actualMac':True,'sourceSha256':source_sha,
        'realQaServiceActions':0,'journalWritesInMemoryOnly':True,
        'initialObservation':native.report['initialObservation'],
        'priorKnownTerm':native.report['priorKnownTerm'],
        'helperCommandReceipts':native.commands}
finally:ns['Journal']=real_journal
loader="""import hashlib,os,stat
from pathlib import Path
p=Path(%r)
fd=os.open(p,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
try:
    s=os.fstat(fd)
    assert stat.S_ISREG(s.st_mode) and s.st_uid==501 and s.st_nlink==1 and stat.S_IMODE(s.st_mode)==0o600
    assert 0<s.st_size<=65536
    raw=os.read(fd,65537)
    ident=lambda x:(x.st_dev,x.st_ino,x.st_uid,x.st_gid,x.st_mode,x.st_nlink,x.st_size,x.st_mtime_ns,x.st_ctime_ns)
    assert len(raw)==s.st_size and not os.read(fd,1) and ident(s)==ident(os.fstat(fd))==ident(p.lstat())
finally:os.close(fd)
assert hashlib.sha256(raw).hexdigest()==%r
exec(compile(raw,str(p),'exec'),{'__name__':'__main__','__source_sha256__':%r})
"""%(str(ROOT/'recover_r2_qa_once.py'),source_sha,source_sha)
ast.parse(loader);save('pinned_loader.py',loader)
plan={'schema':'heptabao.mac-authbus-r2-recovery-preparation.r3',
 'sourcePath':str(ROOT/'recover_r2_qa_once.py'),'sourceSha256':source_sha,
 'loaderPath':str(ROOT/'pinned_loader.py'),
 'executionKey':'heptabao-mac-authbus-r2-owned-cleanup-20261106-r3','timeoutSeconds':60,
 'newIndependentCleanupSeconds':60,'newOwnObservationBeforeKillSeconds':20,'killGraceSeconds':10,
 'noTermDispatchBranch':True,'oldR2RemainsFailed':True,'priorRuntimeJob':'1a1b11e72f9-fc05-75ee',
 'priorKnownTerm':native_report['priorKnownTerm'],'expectedIdentity':ns['EXPECTED_IDENTITY'],
 'newCleanupJournalRoot':str(ns['RECOVERY_ROOT']),'oldFilesNeverModified':True,
 'businessExecution':False,'productionMutation':False,'dataFileDeletion':False,
 'syntheticGateCount':len(results),'actualReadOnlyPreflightPassed':True,
 'realQaServiceActionsExecutedByPreparation':0,'rootReviewRequiredBeforeExecution':True}
save('plan.public.json',json.dumps(plan,indent=2,sort_keys=True)+'\n')
save('synthetic-gates.public.json',json.dumps({'schema':'heptabao.mac-authbus-r2-recovery-synthetic-gates.r3',
 'sourceSha256':source_sha,'cases':results,'passCount':len(results),'failCount':0,'skipCount':0,
 'syntheticOnly':True,'realQaServiceActions':0,'actualReadOnlyPreflight':native_report},indent=2,sort_keys=True)+'\n')
os.close(fd_root)
print(json.dumps({'ok':True,'preparationRoot':str(ROOT),'files':written,
 'syntheticPassCount':len(results),'actualReadOnlyPreflightPassed':True,'realQaServiceActions':0,
 'rootReviewPending':True},sort_keys=True),flush=True)
