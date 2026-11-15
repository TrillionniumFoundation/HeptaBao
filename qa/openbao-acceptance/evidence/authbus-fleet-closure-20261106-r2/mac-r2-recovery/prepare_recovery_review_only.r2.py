
import ast, hashlib, json, os, stat, sys
from pathlib import Path
from types import SimpleNamespace
ROOT = Path('/Users/qianqi/heptabao-mac-authbus-r2-recovery-preparation-20261106-r2')
need = lambda value: None if value else (_ for _ in ()).throw(RuntimeError('preparation_refused'))
need(sys.platform == 'darwin' and os.geteuid() == 501)
payload = sys.stdin.buffer.read(131073)
need(len(payload) <= 131072)
source = json.loads(payload)['source']
raw = source.encode()
need(len(raw) <= 65536)
ast.parse(source)
source_sha = hashlib.sha256(raw).hexdigest()
os.mkdir(ROOT, 0o700)
root_fd = os.open(ROOT, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
info = os.fstat(root_fd)
need(info.st_uid == 501 and stat.S_IMODE(info.st_mode) == 0o700)
written = {}
def save(name, body):
    data = body.encode()
    fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=root_fd)
    try:
        offset=0
        while offset < len(data):
            count=os.write(fd,data[offset:]);need(count>0);offset+=count
        os.fsync(fd)
    finally:
        os.close(fd)
    os.fsync(root_fd)
    written[name]={'bytes':len(data),'sha256':hashlib.sha256(data).hexdigest()}
save('recover_r2_qa_once.py',source)
namespace={'__name__':'prepared_recovery_definitions_only','__source_sha256__':source_sha}
exec(compile(source,str(ROOT/'recover_r2_qa_once.py'),'exec'),namespace)
Refused=namespace['Refused'];Recovery=namespace['Recovery']
results=[]
def record(name,fn):
    fn();results.append({'name':name,'passed':True})
class FakeJournal:
    def __init__(self): self.rows=[]
    def check(self): pass
    def write_new(self,name,value):
        need(name not in [row[0] for row in self.rows])
        self.rows.append((name,json.loads(json.dumps(value))))
        return 'f'*64
def fake(term_retires=True):
    r=Recovery();r.journal=FakeJournal();r.fake_state='live';r.fake_calls=[];r.fake_events=[]
    r.report['publicInputSha256']={};r.report['durableInitialIntentSha256']='e'*64
    def observe(allow_missing=False):
        r.remaining()
        r.fake_events.append('observe:'+r.fake_state)
        return {'state':r.fake_state,'relatedProcessRows':[]}
    def call(label,argv,cap=10):
        need(any(name.endswith(label.removeprefix('launchctl-')+'-intent.public.json')
                 for name,_ in r.journal.rows))
        r.fake_events.append(label);r.fake_calls.append(label)
        if label=='launchctl-term' and term_retires:r.fake_state='retired'
        elif label=='launchctl-kill':r.fake_state='retired'
        elif label=='launchctl-bootout':r.fake_state='absent'
        return {'exitCode':0,'complete':True,'outcomeUnknown':False},b'',b''
    r.observe=observe;r.call=call;r.guard=lambda:None;r.preflight=lambda:None
    return r
def refuses(fn):
    try:fn()
    except Refused:return
    raise AssertionError('expected refusal')
def term_then_bootout():
    r=fake();r.run()
    need(r.report['ok'] and r.fake_calls==['launchctl-term','launchctl-bootout'])
record('known-term-exit-then-single-bootout',term_then_bootout)
def escalation():
    r=fake(False);r.wait_retired=lambda seconds:{'state':'live'}
    r.run()
    need(r.report['ok'] and r.fake_calls==['launchctl-term','launchctl-kill','launchctl-bootout'])
record('same-birth-grace-gated-single-kill',escalation)
def duplicate():
    r=fake(False);r.dispatch_once('term');refuses(lambda:r.dispatch_once('term'))
    need(r.fake_calls==['launchctl-term'])
record('term-cannot-repeat',duplicate)
def active_bootout():
    r=fake();refuses(lambda:r.dispatch_once('bootout'));need(not r.fake_calls and not r.journal.rows)
record('live-process-blocks-bootout',active_bootout)
def early_kill():
    r=fake();refuses(lambda:r.dispatch_once('kill'));need(not r.fake_calls and not r.journal.rows)
record('kill-blocked-without-known-term-and-grace',early_kill)
def changed_after_intent():
    r=fake();calls=[0]
    def observe(allow_missing=False):
        calls[0]+=1
        if calls[0]==2:raise Refused('changed_identity_or_child')
        return {'state':'live'}
    r.observe=observe
    refuses(lambda:r.dispatch_once('term'))
    need(not r.fake_calls and len(r.journal.rows)==1 and r.journal.rows[0][0]=='010-term-intent.public.json')
record('identity-or-child-change-after-durable-intent-blocks-dispatch',changed_after_intent)
def unknown_dispatch():
    r=fake()
    def call(*args,**kwargs):
        r.fake_calls.append('unknown-term')
        raise Refused('helper_outcome_unknown')
    r.call=call
    refuses(lambda:r.dispatch_once('term'))
    need(r.attempts['term']['attempted'] and not r.attempts['term']['complete'])
    refuses(lambda:r.dispatch_once('term'))
    need(r.fake_calls==['unknown-term'])
record('unknown-attempt-is-never-replayed',unknown_dispatch)
def known_error():
    r=fake()
    def call(*args,**kwargs):
        r.fake_calls.append('failed-term')
        return {'exitCode':1,'complete':True,'outcomeUnknown':False},b'',b'failure'
    r.call=call;refuses(lambda:r.dispatch_once('term'))
    need(r.fake_calls==['failed-term'] and r.attempts['term']['exitCode']==1)
record('known-nonzero-command-stops-before-next-action',known_error)
def expired():
    r=fake();r.until=r.started-1
    refuses(lambda:r.dispatch_once('term'))
    need(not r.fake_calls and not r.journal.rows)
record('expired-total-budget-blocks-mutation',expired)
def journal_create_only():
    old=namespace['RECOVERY_ROOT'];namespace['RECOVERY_ROOT']=ROOT/'synthetic-journal'
    try:
        j=namespace['Journal']();j.write_new('001-intent.public.json',{'synthetic':True})
        refuses(lambda:j.write_new('001-intent.public.json',{'synthetic':False}))
        j.close_once();need(j.closed)
        try:namespace['Journal']()
        except FileExistsError:return
        raise AssertionError('journal directory reused')
    finally:namespace['RECOVERY_ROOT']=old
record('actual-private-create-only-fsynced-journal-no-reuse',journal_create_only)

def ps_fixture(raw):
    r=Recovery()
    r.call=lambda *args,**kwargs:({'exitCode':0},raw,b'')
    return r
def signed_uid_unrelated():
    r=ps_fixture(b'97472 1 97472 -2 Ss\n32527 1 32527 501 S\n')
    rows=r.related_rows()
    need(rows==[{'pid':32527,'ppid':1,'pgid':32527,'uid':501,'stat':'S'}])
record('actual-observed-unrelated-uid-minus2-is-accepted',signed_uid_unrelated)
def other_negative_uid_rejected():
    r=ps_fixture(b'97472 1 97472 -3 Ss\n')
    refuses(r.related_rows)
record('unobserved-negative-uid-minus3-remains-rejected',other_negative_uid_rejected)
def target_signed_uid_rejected():
    r=ps_fixture(b'32527 1 32527 -2 S\n')
    r.guard=lambda:None
    r.query=lambda:{'pid':32527}
    refuses(r.observe)
    need(not r.attempts)
record('owned-target-uid-minus2-cannot-pass-501-identity-gate',target_signed_uid_rejected)
def negative_pid_columns_rejected():
    for column in range(3):
        fields=['97472','1','97472','501','Ss'];fields[column]='-2'
        r=ps_fixture((' '.join(fields)+'\n').encode());refuses(r.related_rows)
record('pid-ppid-pgid-still-reject-negative-literals',negative_pid_columns_rejected)
def plus_uid_rejected():
    r=ps_fixture(b'97472 1 97472 +501 Ss\n');refuses(r.related_rows)
record('uid-plus501-remains-rejected',plus_uid_rejected)
real_journal=namespace['Journal']
try:
    namespace['Journal']=FakeJournal
    native=Recovery()
    native.preflight()
    need(native.attempts=={} and native.report['initialObservation']['state']=='live'
         and native.report['initialObservation']['processIdentity']==namespace['EXPECTED_IDENTITY']
         and len(native.journal.rows)==1
         and all(row['complete'] and not row['outcomeUnknown'] and row['exitCode']==0
                 for row in native.commands)
         and all(row['label'] in ('launchctl-print','ps-fixed-metadata') for row in native.commands))
    native_preflight={
        'ok':True,'actualMac':True,'realQaServiceActions':0,'journalWritesInMemoryOnly':True,
        'sourceSha256':source_sha,'initialObservation':native.report['initialObservation'],
        'originalLedgerVerified':native.report['originalLedgerVerified'],
        'immutableOriginalBindingsVerified':native.report['originalPlistPlanAndSourceBindingsVerified'],
        'helperCommandReceipts':native.commands,'singlePreflightSeconds':60,
    }
finally:
    namespace['Journal']=real_journal

loader = """import hashlib,os,stat
from pathlib import Path
p=Path(%r)
fd=os.open(p,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
try:
    first=os.fstat(fd)
    assert stat.S_ISREG(first.st_mode) and first.st_uid==501 and first.st_nlink==1 and stat.S_IMODE(first.st_mode)==0o600
    assert 0 < first.st_size <= 65536
    raw=os.read(fd,65537)
    ident=lambda s:(s.st_dev,s.st_ino,s.st_uid,s.st_gid,s.st_mode,s.st_nlink,s.st_size,s.st_mtime_ns,s.st_ctime_ns)
    assert len(raw)==first.st_size and not os.read(fd,1) and ident(first)==ident(os.fstat(fd))==ident(p.lstat())
finally:
    os.close(fd)
assert hashlib.sha256(raw).hexdigest()==%r
exec(compile(raw,str(p),'exec'),{'__name__':'__main__','__source_sha256__':%r})
""" % (str(ROOT/'recover_r2_qa_once.py'),source_sha,source_sha)
ast.parse(loader)
save('pinned_loader.py',loader)
plan={
 'schema':'heptabao.mac-authbus-r2-recovery-preparation.r1','sourceSha256':source_sha,
 'sourcePath':str(ROOT/'recover_r2_qa_once.py'),
 'loaderPath':str(ROOT/'pinned_loader.py'),
 'executionKey':'heptabao-mac-authbus-r2-owned-cleanup-20261106-r2',
 'timeoutSeconds':60,'cleanupSeconds':60,'termGraceSeconds':20,'killGraceSeconds':10,
 'target':'gui/501/org.heptabao.qa.mac-authbus-4e808-home-r2.server',
 'expectedIdentity':namespace['EXPECTED_IDENTITY'],
 'newCleanupJournalRoot':str(namespace['RECOVERY_ROOT']),
 'originalRunNeverReplayed':True,'originalFilesNeverModified':True,'dataFilesNeverDeleted':True,
 'productionMutation':False,'realServiceMutationExecutedByPreparation':False,
 'rootReviewRequiredBeforeExecution':True,'syntheticGateCount':len(results),
 'actualReadOnlyPreflightPassed':native_preflight['ok'],
}
save('plan.public.json',json.dumps(plan,indent=2,sort_keys=True)+'\n')
save('synthetic-gates.public.json',json.dumps({'schema':'heptabao.mac-authbus-r2-recovery-synthetic-gates.r1',
 'sourceSha256':source_sha,'actualMac':True,'cases':results,
 'passCount':len(results),'failCount':0,'skipCount':0,'syntheticOnly':True,
 'actualJournalCreatedUnderPreparationRootOnly':True,'realQaServiceActions':0,
 'actualReadOnlyPreflight':native_preflight},indent=2,sort_keys=True)+'\n')
os.close(root_fd)
print(json.dumps({'ok':True,'preparationRoot':str(ROOT),'files':written,
 'syntheticPassCount':len(results),'actualReadOnlyPreflightPassed':True,
 'realQaServiceActions':0,'rootReviewPending':True},sort_keys=True),flush=True)
