import json,hashlib,sys
from pathlib import Path
not_run=[]
def need(value):
    if not value:raise AssertionError('gate_failed')
source=Path(sys.argv[1]).read_text()
source_sha=hashlib.sha256(source.encode()).hexdigest()
need(source_sha=='74c1c25ea9a747946b18b4a4e70e2a48037e3ca8892af63230e1e1980fcfad8a')
ROOT=Path(sys.argv[2])
ns={'__name__':'source_definitions_only','__source_sha256__':source_sha}
exec(compile(source,str(Path(sys.argv[1])),'exec'),ns)
Recovery=ns['Recovery'];Refused=ns['Refused'];real_time=ns['time']
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
    r.fake_signal=None;r.fake_calls=[];r.prior_failure_verified=True
    r.report['publicInputSha256']={};r.report['durableInitialIntentSha256']='b'*64
    r.report['priorKnownTerm']={'complete':True,'exitCode':0,'termDispatchCount':1}
    def observe(allow_missing=False):
        r.remaining()
        row={'state':r.fake_state,'relatedProcessRows':[]}
        if r.fake_state=='retired':
            row['launchctlTerminal']={'runs':1,'state':'not running',
                'last exit code':1 if r.fake_signal is None else None,'last terminating signal':r.fake_signal}
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
case('already-retired-known-numeric-exit-needs-only-bootout',retired)
def term_disabled():
    r=fake();refuses(lambda:r.dispatch_once('term'))
    need(not r.fake_calls and not r.journal.rows)
case('term-has-no-callable-dispatch-branch',term_disabled)
def no_new_grace():
    r=fake();refuses(lambda:r.dispatch_once('kill'));need(not r.fake_calls)
case('prior-failure-does-not-substitute-new-twenty-second-observation',no_new_grace)
def no_prior():
    r=fake();allow_kill(r);r.prior_failure_verified=False
    refuses(lambda:r.dispatch_once('kill'));need(not r.fake_calls)
case('new-kill-requires-pinned-failed-campaign-reconciliation',no_prior)
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
    r=fixture(b'97472 1 97472 -2 Ss\n97473 1 97473 -3 ?X\n97474 1 97474\n19545 1 19545 501 S\n')
    need(r.related_rows()==[{'pid':19545,'ppid':1,'pgid':19545,'uid':501,'stat':'S'}])
case('unrelated-uid-stat-are-not-identity-gates',foreign_metadata)
def related_uid():
    for uid in ('-2','-3','0','502','+501'):
        r=fixture(('19545 1 19545 '+uid+' S\n').encode());refuses(r.related_rows)
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
    r=fixture(b'19545 1 19545 501 ?X\n');refuses(r.related_rows)
    need(r.report['rejectedProcessMetadataRow']['fields'][4]=='?X')
case('unknown-related-stat-refused-and-preserved',related_stat)
def related_columns():
    r=fixture(b'19545 1 19545 501\n');refuses(r.related_rows)
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
if sys.platform=='darwin':case('actual-private-journal-fsync-create-only-no-reuse',journal_once)
else:not_run.append('actual-private-journal-fsync-create-only-no-reuse')

def unknown_helper():
    r=fake();allow_kill(r);r.commands=[{'complete':False,'outcomeUnknown':True}]
    refuses(lambda:r.dispatch_once('kill'));need(not r.fake_calls)
case('new-unknown-helper-blocks-all-service-mutations',unknown_helper)
def unannounced_signal():
    r=fake('retired');r.fake_signal='15'
    refuses(r.run);need(not r.fake_calls)
case('unannounced-external-signal-does-not-prove-owned-retirement',unannounced_signal)
ns['time']=real_time
print(json.dumps({'ok':True,'passedCount':len(results),'results':results,'notRun':not_run,'serviceMutations':0,'sourceSha256':source_sha},sort_keys=True))
