#!/usr/bin/env python3
"""Independently validate exact original runtime bytes; no remote action."""
import collections,hashlib,json,sys
from pathlib import Path
root=Path(sys.argv[1]) if len(sys.argv)>1 else Path(__file__).parent/'primitive6-r4-retained'
raw=(root/'stdout.original.json').read_bytes()
assert len(raw)==117007
assert hashlib.sha256(raw).hexdigest()=='6e9b34c61d1b90c98b8d279f7066df7420153289c8b7169622738349d88e0f05'
assert hashlib.sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest()=='ece1ce458b89b19c421d074a332de78eb5407d33'
authority=json.loads((root/'terminal.original.json').read_bytes())
assert authority['job_id']=='1a1b2e87896-fc05-802a' and authority['state']=='succeeded' and authority['exit_code']==0
assert all(authority[k] is True for k in ('output_complete','output_durable','terminal_publication_confirmed'))
assert all(authority[k] is False for k in ('automatic_retry','cancelled','timed_out'))
assert authority['log_bytes']['stdout']=={'seen':117007,'stored':117007}
assert authority['log_bytes']['stderr']=={'seen':0,'stored':0}
v=json.loads(raw);q=v['qualification'];commands=v['originalCommandHelpers']
assert v['ok'] is True and q['ok'] is True and v['businessCompletedWithinOriginal45Seconds'] is True
assert v['sharedSeconds']==45 and v['supervisorSeconds']==70 and v['elapsedSeconds']<45
assert v['actualProductionGatewayChanged'] is False and v['productionKeepAliveRollbackQualified'] is False
assert v['providerCalls']==0 and v['credentialOrConfigurationReads']==0
assert v['automaticRetry'] is False and v['automaticFailureServiceMutationAttempted'] is False
assert q['allOwnedServiceGenerationsAbsent'] is True and q['allSixOriginalMutationsKnown'] is True
assert q['unknown'] is False and q['registeredServiceMayRemain'] is False
assert q['productionGatewayOrRollbackQualified'] is False and q['productionServiceChanged'] is False
assert q['restoredEffectiveDisabledFalse'] is True and q['originalOverrideAbsenceRestored'] is False
assert q['persistedFalseOverrideEntryCreatedForNewQaLabel'] is True
order=['bootstrap-first','disable','bootout-first','enable','bootstrap-recovery','bootout-recovery']
assert set(q['mutations'])==set(order)
for row in q['mutations'].values():
 assert row=={'dispatched':True,'exitCode':0,'intentPersisted':True,'outcome':'complete'}
intents=[e['operation'] for e in q['events'] if e['kind']=='mutation-intent']
completed=[e['operation'] for e in q['events'] if e['kind']=='mutation-complete']
assert intents==completed==order
assert [e['index'] for e in q['events']]==list(range(len(q['events'])))
live=q['serviceIdentities'];assert len(live)==2
assert [r['generation'] for r in live]==['first','recovery']
assert [(r['pid'],r['birthSec'],r['birthUsec']) for r in live]==[(6054,1794002942,562423),(6310,1794002944,274470)]
assert all(r['pid']==r['pgid'] and r['ppid']==1 and r['uid']==501 and r['executable']=='/bin/sleep' for r in live)
absences=[e for e in q['events'] if e['kind']=='absence']
assert [e['generation'] for e in absences]==['first','recovery']
for event in absences:
 assert len(event['rounds'])==2
 for i,row in enumerate(event['rounds']):
  assert row=={'labelAbsent':True,'originalPidEsrch':True,'relatedRowsEmpty':True,'round':i}
assert [e['sameOriginalBirth'] for e in q['events'] if e['kind']=='disable-keeps-running']==[True]
assert commands['allOwnedCommandsStopped'] is True and commands['unknownCommandCount']==0
rows=commands['commands'];assert len(rows)==43
assert q['commands']==rows
for row in rows:
 assert row['completeBeforeDeadline'] is True and row['outcomeUnknown'] is False and row['streamsClosed'] is True
 assert row['exitCode'] in (0,113) and row['errorCode'] is None and row['errorType'] is None
 if row['exitCode']==113:assert row['label']=='read-owned-label'
 c=row['cleanup'];assert c['ok'] is True and c['outcomeUnknown'] is False
 assert c['directChildReaped'] is True and c['allGroupRowsEmptyAfterReap'] is True and c['remainingGroupRows']==[]
 assert c['postReapSignalSent'] is False and c['pid']==row['pid'] and c['exitCode']==row['exitCode']
 if row['label']=='read-disabled':
  assert row['fullDisabledDomainOutputAndDigestsWithheld'] is True
  assert 'stdoutSha256' not in row and 'stderrSha256' not in row
fds=v['recordedFileDescriptors'];assert len(fds)==105
assert all(r['closeAttempts']==1 and r['closed'] is True for r in fds)
report={'schema':'heptabao.root-retained-primitive-six-r4.r1','ok':True,
 'originalHost':'mac','originalJob':authority['job_id'],'rawBytePinsVerified':True,
 'originalActionsKnownOnce':6,'originalHelperCommandsClosed':43,
 'helperExitCodes':dict(collections.Counter(str(r['exitCode']) for r in rows)),
 'launcherDescriptorsClosedOnce':105,'serviceGenerations':2,'absenceRoundsPerGeneration':2,
 'originalDisabledOverrideAbsenceRestored':False,'newQaExplicitFalseOverrideRemains':True,
 'productionGatewayOrRollbackQualified':False,'providerCalls':0,'newRemoteExecution':False}
print(json.dumps(report,sort_keys=True,separators=(',',':')))
