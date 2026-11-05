"""Selected artifact-reader components; every OS/signal operation is synthetic."""
import ast
import copy
import hashlib
import json
from pathlib import Path
import os as real_os
import stat
import time
import types

source=Path(__file__).with_name('build_native_h2_client_r3.draft.py').read_text()
parsed=ast.parse(source)
compile(parsed,'<builder-r3-compile-only>','exec')
ns={'__name__':'selected_qa_builder_definitions'}
exec(compile(ast.Module(body=[x for x in parsed.body if not isinstance(x,ast.If)],
                        type_ignores=[]),'<selected-builder-definitions>','exec'),ns)
TARGET=Path('/home/qian-qi/heptabao-cold-h2-normal-20261105-r1/target-normal-r3')
PRIMARY=TARGET/'release/heptabao-native-h2-qa'
ALIAS='heptabao_native_h2_qa-0123456789abcdef'
BindingError=ns['BindingError'];Cancelled=ns['Cancelled']
rows=[]

def info(ino,mode,size=0,links=1,uid=1000):
    return types.SimpleNamespace(st_dev=77,st_ino=ino,st_uid=uid,st_gid=uid,
        st_mode=mode,st_nlink=links,st_size=size,st_mtime_ns=123456789012345,
        st_ctime_ns=123456789012678)

class Entries:
    def __init__(self,names):self.names=names;self.close_calls=0
    def __iter__(self):return iter([types.SimpleNamespace(name=x) for x in self.names])
    def close(self):self.close_calls+=1

class FakeSignal:
    SIGTERM=15;SIGINT=2
    def __init__(self):
        self.prior={15:object(),2:object()};self.handlers=dict(self.prior)
        self.installs=[]
    def getsignal(self,number):return self.handlers[number]
    def signal(self,number,handler):self.installs.append(number);self.handlers[number]=handler
    def send(self,number):self.handlers[number](number,None)

class FakeOS:
    O_RDONLY=real_os.O_RDONLY;O_NOFOLLOW=real_os.O_NOFOLLOW
    O_CLOEXEC=real_os.O_CLOEXEC;O_DIRECTORY=real_os.O_DIRECTORY
    fsencode=staticmethod(real_os.fsencode)
    def __init__(self,signals):
        self.signals=signals;self.fd_to_path={};self.offsets={};self.serial=100
        self.closed=[];self.open_calls=[];self.read_calls=[];self.iterators=[]
        self.extra_alias=False;self.alias_drift=False;self.cancel_open=False
        self.tail=False;self.fail_close=False;self.close_failure_used=False
        self.metadata={Path('/'):info(1,stat.S_IFDIR|0o755,uid=0)}
        path=Path('/')
        for count,part in enumerate((TARGET/'release/deps').parts[1:],2):
            path=path/part;self.metadata[path]=info(count,stat.S_IFDIR|0o700)
        self.binary=info(800,stat.S_IFREG|0o700,size=2,links=2)
        self.metadata[PRIMARY]=self.binary
        self.metadata[TARGET/'release/deps'/ALIAS]=self.binary
    @staticmethod
    def geteuid():return 1000
    @staticmethod
    def getuid():return 1000
    def named(self,path,parent=None):
        path=Path(path)
        return path if path.is_absolute() else self.fd_to_path[parent]/path
    def stat(self,path,*,dir_fd=None,follow_symlinks=False):
        assert follow_symlinks is False
        named=self.named(path,dir_fd)
        if self.alias_drift and named==TARGET/'release/deps'/ALIAS:
            changed=copy.copy(self.binary);changed.st_ctime_ns+=1;return changed
        if self.extra_alias and named==TARGET/'release/deps'/'heptabao_native_h2_qa-fedcba9876543210':
            return self.binary
        return self.metadata[named]
    def open(self,path,flags,*,dir_fd=None):
        named=self.named(path,dir_fd)
        assert named in self.metadata
        self.serial+=1;fd=self.serial
        self.fd_to_path[fd]=named;self.offsets[fd]=0;self.open_calls.append(named)
        if self.cancel_open:
            self.cancel_open=False;self.signals.send(15)
        return fd
    def fstat(self,fd):return self.metadata[self.fd_to_path[fd]]
    def close(self,fd):
        self.closed.append(fd)
        if self.fail_close and not self.close_failure_used:
            self.close_failure_used=True;raise OSError(5,'synthetic-close')
        del self.fd_to_path[fd]
    def scandir(self,fd):
        assert self.fd_to_path[fd]==TARGET/'release/deps'
        names=[ALIAS,'unrelated-private-file']
        if self.extra_alias:names.append('heptabao_native_h2_qa-fedcba9876543210')
        value=Entries(names);self.iterators.append(value);return value
    def read(self,fd,count):
        path=self.fd_to_path[fd]
        assert path in (PRIMARY,TARGET/'release/deps'/ALIAS)
        raw=b'ok'+(b'x' if self.tail else b'')
        offset=self.offsets[fd];value=raw[offset:offset+count]
        self.offsets[fd]+=len(value);self.read_calls.append((str(path),count,len(value)))
        return value

def setup():
    signals=FakeSignal();fake=FakeOS(signals)
    ns['os']=fake;ns['signal']=signals;ns['FD_CLOSE_FAILED']=False
    target_id={k:ns['identity'](fake.metadata[TARGET])[k]
               for k in ('device','inode','uid','gid','mode')}
    return signals,fake,target_id,{}

def run_reader(fake,pin,report):
    return ns['read_cargo_binary'](PRIMARY,TARGET,pin,128*1024*1024,
                                   time.monotonic_ns()+5_000_000_000,report)

def case(name,operation):
    operation();rows.append({'name':name,'passed':True})

def closed_known(fake,signals,report):
    assert report['all_registered_resources_closed'] is True
    assert report['resource_outcome_unknown'] is False
    assert report['fds_opened']==report['fds_closed_once']==len(fake.closed)
    assert len(fake.closed)==len(set(fake.closed)) and not fake.fd_to_path
    assert signals.handlers==signals.prior
    assert all(x.close_calls==1 for x in fake.iterators)

def success():
    signals,fake,pin,report=setup()
    body,metadata=run_reader(fake,pin,report)
    assert body==b'ok' and metadata['links']==2
    assert metadata['sha256']==hashlib.sha256(b'ok').hexdigest()
    assert report['status']=='observed_two_aliases'
    assert report['body_bytes_read']==4 and report['eof_probe_bytes_read']==0
    assert report['eof_probe_calls']==2 and report['total_bytes_read']==4
    assert report['body_bytes_limit']==4 and report['total_returned_bytes_limit']==6
    assert len(report['aliases'])==2 and not ns['FD_CLOSE_FAILED']
    assert all('unrelated-private-file' not in str(p) for p in fake.open_calls)
    closed_known(fake,signals,report)
case('exact-two-alias-body-return-with-once-closure-and-restored-handlers',success)

def refuse_extra_alias():
    signals,fake,pin,report=setup();fake.extra_alias=True
    try:run_reader(fake,pin,report)
    except BindingError as exc:assert str(exc)=='link_count_not_fully_accounted_for'
    else:raise AssertionError('extra alias accepted')
    assert report['status']=='failed' and fake.read_calls==[]
    closed_known(fake,signals,report)
case('third-same-inode-name-refused-before-body-read',refuse_extra_alias)

def refuse_alias_drift():
    signals,fake,pin,report=setup();fake.alias_drift=True
    try:run_reader(fake,pin,report)
    except BindingError as exc:assert str(exc)=='alias_census_identity'
    else:raise AssertionError('identity drift accepted')
    assert report['status']=='failed' and fake.read_calls==[]
    closed_known(fake,signals,report)
case('same-inode-full9-drift-refused-before-body-read',refuse_alias_drift)

def one_link_refused():
    signals,fake,pin,report=setup();fake.binary.st_nlink=1
    try:run_reader(fake,pin,report)
    except BindingError as exc:assert str(exc)=='cargo_binary_two_link_metadata'
    else:raise AssertionError('unexpected nlink accepted')
    assert report['status']=='failed' and fake.read_calls==[]
    closed_known(fake,signals,report)
case('normal-binary-reader-does-not-generalize-link-count',one_link_refused)

def tail_refused():
    signals,fake,pin,report=setup();fake.tail=True
    try:run_reader(fake,pin,report)
    except BindingError as exc:assert str(exc)=='cargo_binary_trailing_bytes'
    else:raise AssertionError('tail accepted')
    assert report['status']=='failed' and report['total_bytes_read']==3
    assert report['body_bytes_read']==2 and report['eof_probe_bytes_read']==1
    closed_known(fake,signals,report)
case('unexpected-tail-byte-is-counted-and-refused',tail_refused)

def cancellation():
    signals,fake,pin,report=setup();fake.cancel_open=True
    try:run_reader(fake,pin,report)
    except Cancelled:pass
    else:raise AssertionError('cancellation accepted')
    assert report['status']=='failed' and report['cancel_signal']==15
    assert fake.read_calls==[]
    closed_known(fake,signals,report)
case('cancel-after-open-registers-and-closes-before-original-handlers-restored',cancellation)

def close_unknown():
    signals,fake,pin,report=setup();fake.fail_close=True
    try:run_reader(fake,pin,report)
    except BindingError as exc:assert str(exc)=='cargo_binary_observation_incomplete'
    else:raise AssertionError('close uncertainty accepted')
    assert report['status']=='failed' and report['fd_close_failures']==1
    assert not report['all_registered_resources_closed'] and report['resource_outcome_unknown']
    assert ns['FD_CLOSE_FAILED'] and len(fake.fd_to_path)==1
    assert len(fake.closed)==len(set(fake.closed))
    assert signals.handlers==signals.prior
    assert all(x.close_calls==1 for x in fake.iterators)
case('one-close-failure-is-not-retried-and-blocks-global-fd-success',close_unknown)

def cleanup_entry_failure():
    signals,fake,pin,report=setup()
    original_close=ns['CargoBinaryRead'].close_all_once
    def failed_close(_self):raise MemoryError('synthetic-cleanup-entry')
    ns['CargoBinaryRead'].close_all_once=failed_close
    try:
        try:run_reader(fake,pin,report)
        except MemoryError:pass
        else:raise AssertionError('cleanup failure accepted')
    finally:ns['CargoBinaryRead'].close_all_once=original_close
    assert ns['FD_CLOSE_FAILED'] and report['resource_outcome_unknown']
    assert report['status']=='failed' and report['failure_code']=='cargo_binary_cleanup_unconfirmed'
    assert not report['all_registered_resources_closed'] and fake.fd_to_path
    assert signals.handlers==signals.prior
case('unexpected-cleanup-error-preserves-unknown-and-blocks-fd-success',cleanup_entry_failure)

print(json.dumps({'schema':'heptabao.qa-cargo-alias-copy.selected-components.v1',
    'source_sha256':hashlib.sha256(source.encode()).hexdigest(),'source_bytes':len(source.encode()),
    'status':'passed-selected-source-components-only','case_count':len(rows),'cases':rows,
    'builder_main_calls':0,'real_signal_install_or_delivery':0,'real_alias_or_target_reads':0,
    'child_or_cargo_or_product_calls':0,'retained_file_write_executed':False,
    'scope':'Artifact reader only, synthetic OS metadata/data/signals. Generic copy/read path proven separately byte-identical.'},
    indent=2,sort_keys=True))
