#!/usr/bin/env python3
"""Narrow pure checks of whole-five accounting and temporary child custody.

No actual Mac process, source inventory, service, database, provider or credential
is accessed. The fake process reader is explicitly a harness; real admission is
still delegated to the fixed original process reader in the prepared parent.
"""
import copy
import json
import os
from pathlib import Path
import sys
import time
import types
sys.path.insert(0,str(Path(__file__).resolve().parent))
import mac_refresh_capture_sequence_r1 as sequence
import mac_gateway_writer_maintenance_r1 as maintenance

cases=[]
def case(name,action):
    try:action();cases.append({'name':name,'passed':True})
    except BaseException as error:cases.append({'name':name,'passed':False,'errorType':type(error).__name__})
def refused(action):
    try:action()
    except (sequence.SequenceRefused,maintenance.MaintenanceRefused):return
    raise AssertionError('expected refusal')

def packet():
    rows=[]
    sizes=[2469126144,151576576,151576576,151572480,151576576,202899456]
    for slot,size in enumerate(sizes):
        base=str(sequence.LIVE/('state/openclaw.sqlite' if slot==5 else
            'agents/%s/agent/openclaw-agent.sqlite'%sequence.AGENTS[slot]))
        record={'slot':slot,'inventory':{'pragmas':{'page_count':size//4096,'page_size':4096}},
            'generation':{'sourceIdentities':{base:['1',str(slot+10),'501','20','33152','1',str(size),'1','1']},
                          'sourceAbsences':[base+'-wal',base+'-shm',base+'-journal']}}
        record['kind' if slot==5 else 'agentId']='shared-state' if slot==5 else sequence.AGENTS[slot]
        rows.append(record)
    return {'schema':'heptabao.current-production-source-inventory.private.r1',
            'unopenedAdditionalRegisteredPaths':[],'databases':rows}

def all_five():
    p=packet();v=sequence.capacity_requirements(p)
    five=sum(int(next(iter(row['generation']['sourceIdentities'].values()))[6]) for row in p['databases'][:5])
    six=five+int(next(iter(p['databases'][5]['generation']['sourceIdentities'].values()))[6])
    assert v['components']['threeOwnersTwoWholeFiveDatabaseCopiesBytes']==6*five
    assert v['components']['postThreeCommittedTwoWholeSixBaselineCopiesBytes']==2*six
    assert v['components']['oneWholeSixRestoreStagingBytes']==six
    assert v['requiredAdditionalBytes']==sum(v['components'].values())
    assert not v['productionCapacityAdmitted'] and not v['observationIsSpaceReservation']
case('all_five_each_round_and_full_six_baseline_restore_are_counted',all_five)

def wal_growth():
    p=packet();before=sequence.capacity_requirements(p)
    source=p['databases'][0]['generation'];base=next(iter(source['sourceIdentities']))
    source['sourceIdentities'][base+'-wal']=['1','99','501','20','33152','1','8388608','1','1']
    source['sourceAbsences'].remove(base+'-wal')
    after=sequence.capacity_requirements(p)
    assert after['requiredAdditionalBytes']-before['requiredAdditionalBytes']==9*8388608
case('additional_main_wal_counts_in_all_clone_baseline_restore_outputs',wal_growth)
def logical_larger():
    p=packet();before=sequence.capacity_requirements(p)
    p['databases'][1]['inventory']['pragmas']['page_count']+=256
    after=sequence.capacity_requirements(p)
    assert after['requiredAdditionalBytes']-before['requiredAdditionalBytes']==9*1048576
case('logical_backup_pages_cannot_be_underestimated_by_smaller_file',logical_larger)
for name,change in (
 ('boolean_page_count_not_capacity',lambda p:p['databases'][0]['inventory']['pragmas'].__setitem__('page_count',True)),
 ('extra_registered_database_not_silently_omitted',lambda p:p.__setitem__('unopenedAdditionalRegisteredPaths',['synthetic-extra'])),
 ('reordered_or_missing_original_slot_refused',lambda p:p['databases'][1].__setitem__('slot',2)),
 ('oversize_source_not_hidden_in_global_sum',lambda p:p['databases'][0]['inventory']['pragmas'].__setitem__('page_count',1048577))):
    def action(change=change):
        p=packet();change(p);refused(lambda:sequence.capacity_requirements(p))
    case(name,action)

def subject():
    obj=object.__new__(maintenance.GatewayWriterMaintenance)
    obj.until=time.monotonic()+10;obj.clock=time.monotonic;obj.closed=obj.unknown=False
    obj.phase='safe-plist-published';obj.owned_refresh_child=None;obj.retired_refresh_children=[]
    identity={'pid':12345,'ppid':os.getpid(),'pgid':12345,'uid':501,
        'executable':maintenance.NODE,'birthSeconds':1,'birthMicroseconds':2}
    obj.reader=types.SimpleNamespace(read=lambda pid:copy.deepcopy(identity),children=lambda pid:[])
    custody={'ps':{key:identity[key] for key in ('pid','ppid','pgid','uid')},'sid_observed_while_live':12345}
    cleanup={'ok':True,'directChildReaped':True,'allGroupRowsEmptyAfterReap':True,
        'ownedLiveGroupEmptyBeforeReap':True,'pid':12345,'pgid':12345,'postReapSignalSent':False}
    return obj,identity,custody,cleanup

def original_only():
    obj,identity,custody,cleanup=subject()
    obj.bind_owned_refresh_child(identity,custody)
    assert obj.owned_refresh_child==identity
    obj.retire_owned_refresh_child(identity,cleanup)
    assert obj.owned_refresh_child is None and obj.retired_refresh_children==[identity]
case('one_full_birth_original_handle_only_then_known_retained_wait',original_only)
for name,change in (
 ('unrelated_parent_never_temporarily_allowed',lambda o,i,c:i.__setitem__('ppid',1)),
 ('other_executable_never_temporarily_allowed',lambda o,i,c:i.__setitem__('executable','/synthetic/other')),
 ('same_pid_other_birth_never_allowed',lambda o,i,c:setattr(o.reader,'read',lambda pid:{**i,'birthMicroseconds':3})),
 ('child_descendant_cannot_enter_allowance',lambda o,i,c:setattr(o.reader,'children',lambda pid:[999])),
 ('missing_live_session_custody_never_allowed',lambda o,i,c:c.__setitem__('sid_observed_while_live',None))):
    def action(change=change):
        o,i,c,_=subject();change(o,i,c);refused(lambda:o.bind_owned_refresh_child(i,c))
        assert o.owned_refresh_child is None
    case(name,action)
def unknown_retirement():
    o,i,c,end=subject();o.bind_owned_refresh_child(i,c);end['ownedLiveGroupEmptyBeforeReap']=False
    refused(lambda:o.retire_owned_refresh_child(i,end));assert o.owned_refresh_child==i
case('unconfirmed_original_group_retirement_keeps_allowance_owned',unknown_retirement)
report={'schema':'heptabao.maintenance-sequence-local-specific.r1','ok':all(row['passed'] for row in cases),
 'checks':len(cases),'passed':sum(row['passed'] for row in cases),'cases':cases,
 'actualMacQualified':False,'actualConsumerFenceQualified':False,'processReaderSynthetic':True,
 'productionSourceReads':0,'providerDispatches':0,'serviceActions':0}
print(json.dumps(report,sort_keys=True,separators=(',',':')))
raise SystemExit(0 if report['ok'] else 1)
