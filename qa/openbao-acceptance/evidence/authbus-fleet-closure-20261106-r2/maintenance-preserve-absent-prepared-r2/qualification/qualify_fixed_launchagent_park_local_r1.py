#!/usr/bin/env python3
"""Real local filesystem fault cases; injected service/epoch bindings only.

No launchctl, provider, production data or Mac qualification. Path/uid constants
are rebound to a fresh local synthetic directory. Actual link/unlink/fsync and
descriptor operations use the unchanged parking implementation.
"""
import contextlib
import hashlib
import json
import os
from pathlib import Path
import plistlib
import shutil
import sys
import tempfile
import time
from types import SimpleNamespace
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import mac_fixed_launchagent_park_r1 as core
from mac_gateway_writer_maintenance_r2 import GatewayWriterMaintenance
from mac_registered_relay_retirement_r2 import RegisteredRelayRetirement
from mac_refresh_capture_sequence_r2 import FreshOwnerRefreshSequence
from mac_owned_refresh_parent_r2 import OwnedRefreshParent
import mac_owned_refresh_parent_r2 as parent_core
from mac_maintenance_private_files_r1 import MaintenancePrivateFiles

cases = []
SOURCE_NAMES = ('mac_fixed_launchagent_park_r1.py', 'mac_gateway_writer_maintenance_r2.py',
    'mac_registered_relay_retirement_r2.py', 'mac_owned_refresh_parent_r2.py',
    'mac_refresh_capture_sequence_r2.py', 'mac_post_commit_epoch_r2.py')
source_pins = {name: hashlib.sha256((HERE/name).read_bytes()).hexdigest() for name in SOURCE_NAMES}


def need(value):
    if not value:
        raise AssertionError('synthetic_fixture_case_failed')


def refuses(fn):
    try:
        fn()
    except (core.ParkRefused, RuntimeError, OSError, AssertionError):
        return
    raise AssertionError('expected_refusal')


@contextlib.contextmanager
def fixture():
    # /workspace itself is 0777 on this executor. Use the owned 0755 home
    # ancestor so the production !022 chain rule stays unchanged.
    base = Path(tempfile.mkdtemp(prefix='heptabao-park-local-', dir=Path.home()))
    home = base / 'home'
    root = home / 'maintenance'
    la = home / 'Library/LaunchAgents'
    for directory in (home, root, root / 'output', home / 'Library', la):
        directory.mkdir(mode=0o700)
    for name in core.NAMES:
        (la / name).write_bytes(plistlib.dumps({'Label': name[:-6], 'KeepAlive': True,
            'RunAtLoad': True, 'ProgramArguments': ['/synthetic/private-program']}))
        (la / name).chmod(0o600)
    (la / 'unrelated.fixture.plist').write_bytes(b'unrelated synthetic bytes')
    (la / 'unrelated.fixture.plist').chmod(0o600)
    original = {name: ((la / name).read_bytes(), core.full((la / name).lstat())) for name in core.NAMES}
    events = []
    def private_write(name, raw):
        file = root / 'output' / name
        fd = os.open(file, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        try:
            view = memoryview(raw)
            while view:
                n = os.write(fd, view);need(n > 0);view = view[n:]
            os.fsync(fd)
        finally:
            os.close(fd)
        d = os.open(file.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.fsync(d)
        finally:
            os.close(d)
        events.append(name)
    with patch.multiple(core, HOME=home, ROOT=root, LA=la, PARK=root/'parked-launchagents',
                        SAFE=root/'safe-gateway.plist.pending', UID=os.getuid(), GID=os.getgid()):
        p = core.FixedLaunchAgentParking(until=time.monotonic()+30,
            source_fence=lambda: None, private_write=private_write)
        p.prepare_directory()
        shared_commands, shared_reader = object(), object()
        g = GatewayWriterMaintenance.__new__(GatewayWriterMaintenance)
        g.phase='original-bound';g.commands=shared_commands;g.reader=shared_reader;g.until=p.until
        g.unknown=False;g.parking=None;g.original_disabled=None;g.report={}
        g.plist_bytes=original[core.NAMES[4]][0]
        g.binding={'plistFull9': original[core.NAMES[4]][1]}
        g.original_parent=p._directory(la)
        g.wrapper_inputs=SimpleNamespace(verify=lambda: True)
        g._verify_directories=lambda: True
        g.same_original_running=lambda _: True
        g.verify_quiesced=lambda _: p.verify()
        g.safe={'plistBytes': plistlib.dumps({'Label':core.LABELS[4], 'KeepAlive':True,
            'EnvironmentVariables': {'SYNTHETIC_SAFE':'true'},
            'ProgramArguments':['/synthetic/safe-private-program']})}
        g._verify_fallback_files=lambda: True
        g.selector_fence=lambda *_: True
        g.accept_known_safe_autoload=lambda obj: need(obj is p and obj.phase=='safe-published')
        r=RegisteredRelayRetirement.__new__(RegisteredRelayRetirement)
        r.phase='bound';r.commands=shared_commands;r.reader=shared_reader;r.until=p.until
        r.unknown=r.blocked=False;r.parking=None;r.retired=[]
        bindings=[];plists=[]
        for ordinal,name in enumerate(core.NAMES[:4]):
            raw,full=original[name]
            bindings.append({'label':core.LABELS[ordinal], 'originalDisabledOverride':None,
                'plist':plistlib.loads(raw), 'originalPlistDisabled':False, 'plistFull9':full,
                'originalExecutable':{}})
            plists.append(SimpleNamespace(raw=raw, rows=[]))
        r.inputs=SimpleNamespace(packet={'registrations':bindings}, plists=plists,
            _binary_metadata=lambda _: True)
        r._sources=lambda: True;r._same_running=lambda _: True
        r.verify_retired=lambda: need(r.phase=='retired' and r.retired==list(range(4))) or p.verify()
        try:
            p.bind(gateway=g,relays=r)
            g.phase='quiesced';r.phase='retired';r.retired=list(range(4))
            yield p,g,r,original,events
        finally:
            result=p.close()
            need(result['allOriginalDescriptorsClosedOnce'] and not result['closeErrorTypes'])
    shutil.rmtree(base)


def test(name,fn):
    fn();cases.append({'case':name,'passed':True})


def park_all(p):
    for expected in range(5):need(p.park_next()==expected)
    need(p.phase=='parked' and p.verify_parked())


def roundtrip():
    with fixture() as (p,g,r,original,events):
        unrelated=p.la_entries['unrelated.fixture.plist']
        park_all(p)
        need(len(p.actions)==22 and all(row['outcome']=='COMPLETE' for row in p.actions))
        for ordinal,name in enumerate(core.NAMES):
            f=core.PARK/core.PARK_NAMES[ordinal]
            need(not (core.LA/name).exists() and f.read_bytes()==original[name][0]
                 and core.full(f.lstat())[:5]==original[name][1][:5] and f.stat().st_nlink==1)
        need(p.la_entries['unrelated.fixture.plist']==unrelated and g.phase=='parked-for-refresh')
        parent=OwnedRefreshParent.__new__(OwnedRefreshParent)
        parent.maintenance=g;parent.until=p.until
        parent.assert_no_provider_dispatch=lambda: True
        p.restore_originals_before_any_provider(parent)
        need(p.phase=='restored' and len(p.actions)==42 and len(p.restored)==5)
        for name in core.NAMES:
            f=core.LA/name
            need(f.read_bytes()==original[name][0] and core.full(f.lstat())[:5]==original[name][1][:5]
                 and f.stat().st_nlink==1)
        need(os.listdir(core.PARK)==[] and p.la_entries['unrelated.fixture.plist']==unrelated)
test('P01_real_five_original_inodes_park_and_explicit_pre_provider_restore',roundtrip)


def completion_unknown():
    with fixture() as (p,*_):
        native=p.private_write
        def inject(name,raw):
            native(name,raw)
            if name=='park-02-complete.private.json':raise OSError('synthetic_complete_fsync_unknown')
        p.private_write=inject
        refuses(lambda:p.park_next())
        need(p.unknown and p.actions[-1]['outcome']=='UNKNOWN'
             and (core.LA/core.NAMES[0]).stat().st_nlink==2
             and (core.PARK/core.PARK_NAMES[0]).exists())
        count=len(p.actions);refuses(lambda:p.park_next());need(len(p.actions)==count)
test('P02_link_completed_but_completion_unknown_never_unlinks_or_retries',completion_unknown)


def link_directory_sync_unknown():
    with fixture() as (p,*_):
        native=os.fsync;target=os.fstat(p.parents[core.PARK]['fd'])
        def inject(fd):
            value=os.fstat(fd)
            if (value.st_dev,value.st_ino)==(target.st_dev,target.st_ino):raise OSError('synthetic_park_fsync_unknown')
            return native(fd)
        with patch.object(core.os,'fsync',inject):refuses(lambda:p.park_next())
        need(p.unknown and p.actions[-1]['operation']=='park-link-directory-sync'
             and (core.LA/core.NAMES[0]).stat().st_nlink==2)
        count=len(p.actions);refuses(lambda:p.park_next());need(len(p.actions)==count)
test('P03_park_fsync_unknown_keeps_both_original_inode_names',link_directory_sync_unknown)


def unlink_unknown():
    with fixture() as (p,*_):
        native=os.unlink
        def inject(path,*args,**kwargs):
            result=native(path,*args,**kwargs)
            if path==core.NAMES[0] and kwargs.get('dir_fd')==p.parents[core.LA]['fd']:
                raise OSError('synthetic_unlink_completed_but_unknown')
            return result
        with patch.object(core.os,'unlink',inject):refuses(lambda:p.park_next())
        need(p.unknown and not (core.LA/core.NAMES[0]).exists()
             and (core.PARK/core.PARK_NAMES[0]).stat().st_nlink==1
             and p.actions[-1]['operation']=='park-unlink-autoload')
        count=len(p.actions);refuses(lambda:p.park_next());need(len(p.actions)==count)
test('P04_original_unlink_effect_unknown_is_preserved_without_compensation',unlink_unknown)


def source_sync_unknown():
    with fixture() as (p,*_):
        native=os.fsync;target=os.fstat(p.parents[core.LA]['fd'])
        def inject(fd):
            value=os.fstat(fd)
            if (value.st_dev,value.st_ino)==(target.st_dev,target.st_ino):raise OSError('synthetic_la_fsync_unknown')
            return native(fd)
        with patch.object(core.os,'fsync',inject):refuses(lambda:p.park_next())
        need(p.unknown and not (core.LA/core.NAMES[0]).exists()
             and p.actions[-1]['operation']=='park-autoload-directory-sync'
             and not p.parked)
        count=len(p.actions);refuses(lambda:p.park_next());need(len(p.actions)==count)
test('P05_autoload_directory_sync_unknown_does_not_admit_next_ordinal',source_sync_unknown)


def intent_unknown():
    with fixture() as (p,*_):
        native=p.private_write
        def inject(name,raw):
            if name=='park-02-intent.private.json':raise OSError('synthetic_intent_unknown')
            native(name,raw)
        p.private_write=inject
        refuses(lambda:p.park_next())
        need(p.unknown and p.actions[-1]['syscallAttempted'] is False
             and (core.LA/core.NAMES[0]).stat().st_nlink==1 and os.listdir(core.PARK)==[])
        refuses(lambda:p.park_next())
test('P06_intent_unknown_consumes_once_slot_without_link',intent_unknown)


def unrelated_change():
    with fixture() as (p,*_):
        before=len(p.actions)
        (core.LA/'unrelated.fixture.plist').write_bytes(b'changed synthetic bytes')
        refuses(lambda:p.park_next())
        need(p.blocked and not p.unknown and len(p.actions)==before and os.listdir(core.PARK)==[])
        refuses(lambda:p.park_next());need(len(p.actions)==before)
test('P07_nonselected_directory_entry_full9_change_refused_before_action',unrelated_change)


def replacement():
    with fixture() as (p,*_):
        name=core.LA/core.NAMES[0];raw=name.read_bytes()
        name.unlink();name.write_bytes(raw);name.chmod(0o600)
        before=len(p.actions);refuses(lambda:p.park_next())
        need(len(p.actions)==before and os.listdir(core.PARK)==[])
test('P08_same_bytes_different_original_inode_refused',replacement)


def destination_collision():
    with fixture() as (p,*_):
        target=core.PARK/core.PARK_NAMES[0]
        target.write_bytes(b'unrelated collision');target.chmod(0o600)
        before=len(p.actions);refuses(lambda:p.park_next())
        need(len(p.actions)==before and target.read_bytes()==b'unrelated collision'
             and (core.LA/core.NAMES[0]).stat().st_nlink==1)
test('P09_existing_private_park_target_never_overwritten',destination_collision)


def outside_hardlink():
    with fixture() as (p,*_):
        extra=core.ROOT/'unexpected-hardlink'
        os.link(core.LA/core.NAMES[0],extra)
        before=len(p.actions);refuses(lambda:p.park_next());need(len(p.actions)==before and extra.exists())
test('P10_unexplained_original_nlink_change_refused',outside_hardlink)


def no_service_authority():
    with fixture() as (p,g,r,*_):
        r.phase='bound';r.retired=[]
        before=len(p.actions);refuses(lambda:p.park_next());need(len(p.actions)==before)
test('P11_no_park_before_actual_controller_retirement_phase',no_service_authority)


def no_known_provider_epoch():
    with fixture() as (p,g,r,*_):
        park_all(p);before=len(p.actions)
        sequence=FreshOwnerRefreshSequence.__new__(FreshOwnerRefreshSequence)
        sequence.maintenance=g;sequence.until=p.until;sequence.current_epoch=None;sequence.report={'ok':False}
        refuses(lambda:p.publish_safe_gateway(sequence=sequence))
        need(len(p.actions)==before and not (core.LA/core.NAMES[4]).exists())
test('P12_no_safe_autoload_before_three_known_committed_epoch',no_known_provider_epoch)


def rejected_pre_provider_restore():
    with fixture() as (p,g,r,*_):
        park_all(p);before=len(p.actions)
        parent=OwnedRefreshParent.__new__(OwnedRefreshParent);parent.maintenance=g;parent.until=p.until
        parent.assert_no_provider_dispatch=lambda: (_ for _ in ()).throw(RuntimeError('synthetic_attempt_consumed'))
        refuses(lambda:p.restore_originals_before_any_provider(parent))
        need(len(p.actions)==before and all(not (core.LA/name).exists() for name in core.NAMES))
test('P13_provider_attempt_or_unknown_blocks_old_autoload_restore',rejected_pre_provider_restore)


def safe_publication():
    with fixture() as (p,g,r,original,events):
        park_all(p);g.phase='committed'
        sequence=FreshOwnerRefreshSequence.__new__(FreshOwnerRefreshSequence)
        sequence.maintenance=g;sequence.until=p.until;sequence.current_epoch=object();sequence.report={'ok':True}
        count=[]
        sequence.verify_current_epoch=lambda label: count.append(label) or p.verify()
        p.publish_safe_gateway(sequence=sequence)
        need(p.phase=='safe-published' and p.verify_parked() and len(p.actions)==28
             and len(count)==7 and not core.SAFE.exists()
             and (core.LA/core.NAMES[4]).read_bytes()==g.safe['plistBytes']
             and (core.LA/core.NAMES[4]).stat().st_nlink==1
             and (core.LA/core.NAMES[4]).stat().st_ino!=original[core.NAMES[4]][1][1])
        need(all(not (core.LA/name).exists() for name in core.NAMES[:4]))
        need(all((core.PARK/core.PARK_NAMES[n]).read_bytes()==original[core.NAMES[n]][0] for n in range(5)))
test('P14_only_safe_new_gateway_published_all_five_originals_still_parked',safe_publication)


def actual_parent_gate():
    with fixture() as (p,g,r,*_):
        ledger=core.ROOT/'synthetic-once-ledger';ledger.mkdir(mode=0o700)
        fd=os.open(ledger,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
        try:
            private=MaintenancePrivateFiles.__new__(MaintenancePrivateFiles)
            private.until=p.until;private.closed=private.failed=False
            private.directory=lambda path: {'fd':fd} if path==ledger else (_ for _ in ()).throw(AssertionError('scope'))
            private.verify_parents=lambda: True
            parent=OwnedRefreshParent.__new__(OwnedRefreshParent)
            parent.maintenance=g;parent.until=p.until;parent.read_private=private.read
            parent.closed=False;parent.attempts=[];parent.committed=[];parent.clock=time.monotonic
            parent.signals=SimpleNamespace(pending=None);parent.source_fence=lambda: None
            g.owned_refresh_child=None
            with patch.object(parent_core,'LEDGER',ledger):
                need(parent.assert_no_provider_dispatch())
                parent.attempts=[{'ordinal':0}];refuses(parent.assert_no_provider_dispatch)
                parent.attempts=[];parent.committed=[{'ordinal':0}];refuses(parent.assert_no_provider_dispatch)
                parent.committed=[];(ledger/'intent.private.json').write_bytes(b'synthetic-consumed')
                refuses(parent.assert_no_provider_dispatch)
        finally:os.close(fd)
test('P15_actual_parent_gate_rejects_attempt_commit_or_nonempty_original_ledger',actual_parent_gate)


def actual_gateway_graph():
    def make():
        g=GatewayWriterMaintenance.__new__(GatewayWriterMaintenance)
        g.actions={};g.unknown=g.closed=False;g.clock=time.monotonic;g.until=time.monotonic()+5
        g.phase='original-bound';g.source_fence=lambda: None;g._write=lambda *_: None
        return g
    g=make();refuses(lambda:g._intent('disable'));refuses(lambda:g._intent('enable-safe-local'))
    need(g.actions=={})
    g.actions={'bootout':{'outcome':'COMPLETE'}};g.phase='restoring-original-before-provider'
    g._intent('bootstrap-original-before-provider')
    refuses(lambda:g._intent('bootstrap-original-before-provider'))
    g=make();g.actions={'bootout':{'outcome':'COMPLETE'},'publish-safe-plist':{'outcome':'COMPLETE'}}
    g.phase='restoring-original-before-provider';refuses(lambda:g._intent('bootstrap-original-before-provider'))
    g=make();g.unknown=True;refuses(lambda:g._intent('bootout'));need(g.actions=={})
test('P16_actual_gateway_graph_never_mutates_override_or_restores_old_after_publication',actual_gateway_graph)


need(source_pins == {name:hashlib.sha256((HERE/name).read_bytes()).hexdigest() for name in SOURCE_NAMES})
result={'schema':'heptabao.fixed-five-parking-local-filesystem-qualification.r1',
 'ok':True,'passed':len(cases),'expected':16,'cases':cases,
 'actualLocalFilesystemLinkUnlinkFsyncUsed':True,'serviceAndEpochBindingsInjected':True,
 'productionUidAndPathsReboundOnlyInsideSyntheticFixture':True,
 'actualMacServiceActions':0,'providerCalls':0,'productionQualification':False,
 'sourcePinsBeforeAndAfterExact':source_pins,
 'sourceSha256':hashlib.sha256((HERE/'mac_fixed_launchagent_park_r1.py').read_bytes()).hexdigest()}
(HERE/'fixed-five-parking-local-r1.result.public.json').write_text(json.dumps(result,sort_keys=True,indent=2)+'\n')
print(json.dumps(result,sort_keys=True))
