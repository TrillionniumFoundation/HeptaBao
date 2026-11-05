#!/usr/bin/env python3
"""Fixed owned QA metadata only; no regular-file body or runtime action."""
import hashlib, json, os, signal, stat, sys, time
from contextlib import contextmanager
from pathlib import Path
START=time.monotonic();UNTIL=START+5.0
TARGET=Path('/Volumes/T5/hepta-vnext-recovery-20261013/mac-authbus-r10-current-consumer-r1/qa')
ANCHORS=[
  {
    "path": "/",
    "identity": [
      "16777233",
      "2",
      "0",
      "0",
      "16877",
      "22",
      "704",
      "1786589515000000000",
      "1786589515000000000"
    ]
  },
  {
    "path": "/Volumes",
    "identity": [
      "16777233",
      "18336",
      "0",
      "0",
      "16877",
      "5",
      "160",
      "1793100597756515591",
      "1793100597756515591"
    ]
  },
  {
    "path": "/Volumes/T5",
    "identity": [
      "16777244",
      "2",
      "0",
      "0",
      "16893",
      "12",
      "384",
      "1793152973144260495",
      "1793152973144260495"
    ]
  }
]
OLD_NAMES=[
  "mac_current_outer_r3.py",
  "mac_current_outer_inputs_r1.py",
  "mac_current_fixture_materializer_r1.py",
  "mac_current_capture_entry_r1.py",
  "mac_owned_launchd_r3.py",
  "mac_current_server_owner_r1.py",
  "mac_current_phase_owner_r2.py",
  "mac_native_process_observer_r1.py",
  "mac_guarded_current_capture_r3.py",
  "mac_owned_commands_r1.py",
  "mac_t5_volume_guard_r1.py",
  "mac_owned_unreaped_r1.py",
  "mac_capture_sqlite_synthetic_r1.py",
  "mac_capture_sqlite_synthetic_r2.py",
  "mac_current_cycle_r2.mjs",
  "mac_single_native_r2.mjs",
  "mac_auth_rows_cas_r1.mjs",
  "mac_authbus_cache_cas_r1.mjs"
]
KNOWN_NAMES=[
  "mac_current_outer_r3.py",
  "mac_current_outer_inputs_r1.py",
  "mac_current_fixture_materializer_r1.py",
  "mac_current_capture_entry_r1.py",
  "mac_owned_launchd_r3.py",
  "mac_current_server_owner_r1.py",
  "mac_current_phase_owner_r2.py",
  "mac_native_process_observer_r1.py",
  "mac_guarded_current_capture_r3.py",
  "mac_owned_commands_r1.py",
  "mac_t5_volume_guard_r1.py",
  "mac_owned_unreaped_r1.py",
  "mac_capture_sqlite_synthetic_r1.py",
  "mac_capture_sqlite_synthetic_r2.py",
  "mac_current_cycle_r2.mjs",
  "mac_single_native_r2.mjs",
  "mac_auth_rows_cas_r1.mjs",
  "mac_authbus_cache_cas_r1.mjs",
  "mac_current_outer_inputs_r2.py",
  "mac_current_outer_r4.py"
]
MAX_MEMBERS=32
MAX_METADATA=64
metadata=0;protected=0;pending=None
rows=[];iterator=None;iterator_close_attempted=False;iterator_close_returned=False
report={'schema':'heptabao.mac-owned-qa-members-metadata.r1','status':'failed',
 'target':str(TARGET),'inner_seconds':5,'outer_seconds':60,
 'prior_refused_job':'1a1a98ec7b8-fc05-35fb',
 'scope':'new finite metadata observation, not reconstruction of the prior failed predicate',
 'max_members':MAX_MEMBERS,'max_metadata_calls':MAX_METADATA,
 'regular_file_bodies_opened_by_probe':False,'files_written':False,
 'private_inputs_read':False,'children_started':False,'network_used':False,
 'permissions_changed':False,'guard_changed':False,'business_replayed':False,
 'uuid_requeried':False,'source_or_runtime_qualified':False}
class Refused(RuntimeError):pass
def need(value,code):
    if not value:raise Refused(code)
def remaining():
    need(pending is None,'observation_cancelled')
    need(time.monotonic()<UNTIL,'original_observation_deadline')
def count():
    global metadata
    remaining();metadata+=1;need(metadata<=MAX_METADATA,'finite_metadata_bound')
def ident(value):
    return [str(x) for x in (value.st_dev,value.st_ino,value.st_uid,value.st_gid,
         value.st_mode,value.st_nlink,value.st_size,value.st_mtime_ns,value.st_ctime_ns)]
def on_signal(signum,_):
    global pending
    pending=signum
    if not protected:raise KeyboardInterrupt()
@contextmanager
def critical():
    global protected
    protected+=1
    try:yield
    finally:protected-=1
def close_row(row):
    if row['close_attempted']:return
    with critical():
        row['close_attempted']=True
        try:os.close(row['fd']);row['closed']=True
        except BaseException as error:row['close_error_type']=type(error).__name__
def close_iterator():
    global iterator_close_attempted,iterator_close_returned
    if iterator is None or iterator_close_attempted:return
    with critical():
        iterator_close_attempted=True
        try:iterator.close();iterator_close_returned=True
        except BaseException as error:report['iterator_close_error_type']=type(error).__name__
try:
    need(sys.platform=='darwin' and os.getuid()==501,'fixed_mac_owner')
    need(len(OLD_NAMES)==18 and len(set(OLD_NAMES))==18
         and len(KNOWN_NAMES)==20 and set(OLD_NAMES)<set(KNOWN_NAMES),'fixed_public_names')
    for signum in (signal.SIGTERM,signal.SIGINT):signal.signal(signum,on_signal)
    parts=TARGET.parts;current=Path('/');parent=None
    expected={item['path']:item['identity'] for item in ANCHORS}
    for index,component in enumerate(parts):
        remaining();current=Path('/') if index==0 else current/component
        count()
        named=os.lstat('/') if parent is None else os.stat(
            component,dir_fd=parent['fd'],follow_symlinks=False)
        value=ident(named)
        need(stat.S_ISDIR(named.st_mode),'fixed_chain_directory_not_symlink')
        if str(current) in expected:need(value==expected[str(current)],'fixed_t5_anchor_identity')
        else:need(named.st_uid==501 and named.st_dev==int(ANCHORS[2]['identity'][0])
                  and not (stat.S_IMODE(named.st_mode)&0o022),'owned_qa_chain_custody')
        with critical():
            fd=os.open('/' if parent is None else component,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,
                       **({} if parent is None else {'dir_fd':parent['fd']}))
            row={'fd':fd,'path':str(current),'component':component,'parent':parent,
                 'identity':value,'close_attempted':False,'closed':False}
            rows.append(row)
        count();need(ident(os.fstat(fd))==value,'held_chain_fd_full_identity')
        parent=row
    report['chain_before']=[{'path':r['path'],'identity':r['identity']} for r in rows]
    report['qa_identity_before']=list(rows[-1]['identity'])
    remaining()
    with critical():iterator=os.scandir(rows[-1]['fd'])
    members=[];actual_names=set();eof=False
    while len(members)<MAX_MEMBERS:
        remaining()
        try:entry=next(iterator)
        except StopIteration:eof=True;break
        name=entry.name
        need(name not in ('.','..') and '/' not in name and '\0' not in name,'directory_member_name')
        need(name not in actual_names,'duplicate_directory_member')
        actual_names.add(name)
        count();info=os.stat(name,dir_fd=rows[-1]['fd'],follow_symlinks=False)
        kind=('regular' if stat.S_ISREG(info.st_mode) else 'directory' if stat.S_ISDIR(info.st_mode)
              else 'symlink' if stat.S_ISLNK(info.st_mode) else 'other')
        item={'name_sha256':hashlib.sha256(os.fsencode(name)).hexdigest(),
              'type':kind,'identity':ident(info),'known_public_name':name in KNOWN_NAMES}
        if name in KNOWN_NAMES:item['name']=name
        members.append(item)
    close_iterator()
    need(iterator_close_returned,'iterator_close_unconfirmed')
    report['members']=members;report['members_enumeration_eof']=eof
    report['observed_member_count']=len(members)
    report['expected_member_count']=len(OLD_NAMES)
    report['member_count_matches_expected']=len(members)==len(OLD_NAMES)
    report['member_set_matches_expected']=actual_names==set(OLD_NAMES) and eof
    report['missing_expected_public_names']=sorted(set(OLD_NAMES)-actual_names)
    report['unexpected_known_public_names']=sorted((actual_names-set(OLD_NAMES))&set(KNOWN_NAMES))
    report['unknown_member_name_sha256']=[x['name_sha256'] for x in members if not x['known_public_name']]
    need(eof,'member_bound_reached_before_eof')
    after=[]
    for row in rows:
        count();named=os.lstat('/') if row['parent'] is None else os.stat(
            row['component'],dir_fd=row['parent']['fd'],follow_symlinks=False)
        count();held=os.fstat(row['fd'])
        after.append({'path':row['path'],'identity':ident(named),'held_identity':ident(held)})
    report['chain_after']=after
    report['qa_identity_after']=after[-1]['identity']
    report['qa_full_identity_stable']=report['qa_identity_before']==report['qa_identity_after']==after[-1]['held_identity']
    report['all_chain_named_fd_identity_stable']=all(
        row['identity']==observed['identity']==observed['held_identity']
        for row,observed in zip(rows,after))
    report['original_membership_guard_would_pass_on_this_observation']=bool(
        report['qa_full_identity_stable'] and report['member_count_matches_expected']
        and report['member_set_matches_expected'])
    need(report['all_chain_named_fd_identity_stable'],'observed_chain_identity_drift')
    remaining();report['status']='complete_finite_metadata_observation'
except BaseException as error:
    report['error_type']=type(error).__name__
    report['error_code']=str(error) if type(error) is Refused else None
finally:
    signal.signal(signal.SIGTERM,signal.SIG_IGN);signal.signal(signal.SIGINT,signal.SIG_IGN)
    close_iterator()
    for row in reversed(rows):close_row(row)
    report['explicit_directory_fd_closure']=[{'path':r['path'],'attempted':r['close_attempted'],
       'closed':r['closed'],'error_type':r.get('close_error_type')} for r in rows]
    report['all_explicit_directory_fds_closed']=all(r['closed'] for r in rows)
    report['iterator_close_attempted']=iterator_close_attempted
    report['iterator_close_returned']=iterator_close_returned
    report['metadata_calls']=metadata
    completed=time.monotonic();report['elapsed_seconds']=completed-START
    report['original_deadline_after_closure']=completed<UNTIL
    report['outcome_unknown']=bool(pending is not None or not report['all_explicit_directory_fds_closed']
       or (iterator is not None and not iterator_close_returned))
    if report['outcome_unknown'] or completed>=UNTIL:report['status']='failed'
    raw=(json.dumps(report,sort_keys=True,separators=(',',':'))+'\n').encode()
    need(len(raw)<=32768,'bounded_public_report')
    sys.stdout.buffer.write(raw);sys.stdout.buffer.flush()
raise SystemExit(0 if report['status']=='complete_finite_metadata_observation' and time.monotonic()<UNTIL else 1)
