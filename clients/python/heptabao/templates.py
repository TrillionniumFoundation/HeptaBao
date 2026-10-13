"""Actual full-Go template process bridge and descriptor-bound private sinks.

The evaluator asks the Agent's trusted subscription owner for secrets through
private pipes. It never receives a bearer token or arbitrary network authority.
"""
from __future__ import annotations
import hashlib
import fcntl
import os
from pathlib import Path
import selectors
import stat
import subprocess
import threading
import time

from .private_state import StateDirectory
from .transport import BaoError, canonical, decode_json, private_read

MAX_FRAME=1_048_576


def configuration(value,agent):
    if not isinstance(value,dict) or set(value)-{'renderer','renderer_sha256','jobs','timeout_seconds','poll_interval_seconds','clean_on_stop'}:
        raise BaoError('invalid_template_configuration')
    result=dict(value)
    try:
        if not isinstance(result['renderer'],str) or not Path(result['renderer']).is_absolute():raise BaoError('template_renderer_absolute_path_required')
        digest=result['renderer_sha256']
        if not isinstance(digest,str) or len(digest)!=64 or any(c not in '0123456789abcdef' for c in digest):raise BaoError('template_renderer_digest_required')
        result.setdefault('timeout_seconds',10);result.setdefault('poll_interval_seconds',1);result.setdefault('clean_on_stop',True)
        if type(result['clean_on_stop']) is not bool:raise BaoError('template_cleanup_flag')
        for name,low,high in [('timeout_seconds',1,60),('poll_interval_seconds',.1,60)]:
            if type(result[name]) not in (int,float) or not low<=result[name]<=high:raise BaoError('template_timing_bound')
        jobs=result['jobs']
        if not isinstance(jobs,list) or not 1<=len(jobs)<=16:raise BaoError('template_job_bound')
        destinations=set()
        for row in jobs:
            if not isinstance(row,dict) or set(row)!={'source_file','destination_dir','destination_name'}:raise BaoError('invalid_template_job')
            if any(not isinstance(row[name],str) or not Path(row[name]).is_absolute() for name in ('source_file','destination_dir')):raise BaoError('template_absolute_paths_required')
            name=row['destination_name']
            if not name or len(name)>128 or name in ('.','..','.agent.lock','state.json','token') or not all(c.isascii() and (c.isalnum() or c in '._-') for c in name):raise BaoError('template_destination_name_blocked')
            target=(row['destination_dir'],name)
            if target in destinations:raise BaoError('template_duplicate_destination')
            destinations.add(target)
        return result
    except (KeyError,ValueError,TypeError):raise BaoError('invalid_template_configuration') from None


class Templates:
    def __init__(self,config,agent,secrets,stop):
        self.config=configuration(config,agent);self.agent=agent;self.secrets=secrets;self.stop=stop
        self.directories={};self.next_poll=0;self.written=set();self.events={'rendered':0,'changed':0,'blocked':0,'secret_calls':0}
        self.published={};self.publication_lock=threading.RLock();self.cleaner_stop=threading.Event();self.cleaner=None
        try:
            for job in self.config['jobs']:
                directory=job['destination_dir']
                if Path(directory).samefile(agent.state_dir) or Path(directory).samefile(secrets.config['state_dir']):raise BaoError('template_destination_conflicts_with_owner_state')
                if directory not in self.directories:self.directories[directory]=StateDirectory(directory,writer=True)
                source=Path(job['source_file'])
                if source.parent.samefile(directory) and source.name==job['destination_name']:
                    raise BaoError('template_source_destination_collision')
                # A previous process's sink is never admitted by its existence.
                self.directories[directory].remove(job['destination_name'])
            descriptor,_=self._renderer();os.close(descriptor)
            self.cleaner=threading.Thread(target=self._clean_expired,name='heptabao-template-expiry',daemon=True)
            self.cleaner.start()
        except BaseException:
            for directory in self.directories.values():directory.close()
            raise

    def _renderer(self):
        # A path hash followed by Popen(path) does not pin the executed bytes.
        # Linux seals the admitted image before it is handed to the kernel.
        if not hasattr(os,'memfd_create') or not all(hasattr(fcntl,name) for name in ('F_ADD_SEALS','F_SEAL_WRITE','F_SEAL_SHRINK','F_SEAL_GROW','F_SEAL_SEAL')):
            raise BaoError('template_immutable_renderer_platform_unsupported')
        descriptor=None
        try:
            source=os.open(self.config['renderer'],os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC)
            with os.fdopen(source,'rb') as stream:
                info=os.fstat(stream.fileno())
                if not stat.S_ISREG(info.st_mode) or info.st_uid not in (0,os.geteuid()) or info.st_mode&0o022 or not info.st_mode&0o111 or not 0<info.st_size<=134217728:
                    raise BaoError('template_renderer_requires_trusted_executable')
                descriptor=os.memfd_create('heptabao-admitted-renderer',os.MFD_CLOEXEC|os.MFD_ALLOW_SEALING)
                digest=hashlib.sha256();count=0
                while True:
                    chunk=stream.read(1048576)
                    if not chunk:break
                    count+=len(chunk)
                    if count>info.st_size:raise BaoError('template_renderer_changed')
                    digest.update(chunk);offset=0
                    while offset<len(chunk):offset+=os.write(descriptor,chunk[offset:])
                if count!=info.st_size or digest.hexdigest()!=self.config['renderer_sha256']:
                    raise BaoError('template_renderer_changed')
            os.fchmod(descriptor,0o500)
            fcntl.fcntl(descriptor,fcntl.F_ADD_SEALS,fcntl.F_SEAL_WRITE|fcntl.F_SEAL_SHRINK|fcntl.F_SEAL_GROW|fcntl.F_SEAL_SEAL)
            return descriptor,'/proc/self/fd/'+str(descriptor)
        except BaseException:
            if descriptor is not None:os.close(descriptor)
            raise

    def _frame(self,process,value,deadline):
        data=canonical(value)+b'\n'
        if len(data)>MAX_FRAME:raise BaoError('template_rpc_frame_bound')
        descriptor=process.stdin.fileno();os.set_blocking(descriptor,False)
        selector=selectors.DefaultSelector();selector.register(descriptor,selectors.EVENT_WRITE)
        try:
            offset=0
            while offset<len(data):
                remaining=deadline-time.monotonic()
                if self.stop.is_set():raise BaoError('template_owner_stopped')
                if remaining<=0:raise BaoError('template_deadline')
                if not selector.select(min(.1,remaining)):continue
                try:count=os.write(descriptor,data[offset:offset+65536])
                except BlockingIOError:continue
                if count<=0:raise BaoError('template_evaluator_stopped')
                offset+=count
        finally:selector.close()

    def _render(self,job):
        source=private_read(job['source_file'],65536).decode('utf-8')
        deadline=time.monotonic()+self.config['timeout_seconds']
        if self.secrets.owner_deadline is not None:deadline=min(deadline,self.secrets.owner_deadline)
        token_hash=self.secrets.token_generation(end=deadline);paths=set()
        descriptor,executable=self._renderer()
        try:
            process=subprocess.Popen([executable],stdin=subprocess.PIPE,stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,env={'PATH':'/usr/bin:/bin','LANG':'C.UTF-8'},bufsize=0,pass_fds=(descriptor,))
        finally:os.close(descriptor)
        selector=selectors.DefaultSelector();selector.register(process.stdout,selectors.EVENT_READ)
        os.set_blocking(process.stdout.fileno(),False);buffer=bytearray()
        try:
            self._frame(process,{'template':source,'timeout_ms':int(self.config['timeout_seconds']*1000)},deadline)
            while True:
                if self.stop.is_set():raise BaoError('template_owner_stopped')
                remaining=deadline-time.monotonic()
                if remaining<=0:raise BaoError('template_deadline')
                if not selector.select(min(.1,remaining)):
                    if process.poll() is not None:raise BaoError('template_evaluator_stopped')
                    continue
                chunk=os.read(process.stdout.fileno(),65536)
                if not chunk:raise BaoError('template_evaluator_stopped')
                buffer.extend(chunk)
                if len(buffer)>MAX_FRAME:raise BaoError('template_rpc_frame_bound')
                while b'\n' in buffer:
                    line,_,tail=buffer.partition(b'\n');buffer=bytearray(tail)
                    frame=decode_json(line)
                    if not isinstance(frame,dict):raise BaoError('template_rpc_shape')
                    if frame.get('op')=='secret' and set(frame)=={'op','path'} and isinstance(frame['path'],str):
                        self.events['secret_calls']+=1
                        secret=self.secrets.secret(frame['path'],end=deadline)
                        paths.add(frame['path'])
                        self._frame(process,{'ok':True,'secret':secret},deadline)
                    elif frame.get('op')=='result' and frame.get('ok') is True and isinstance(frame.get('output'),str):
                        output=frame['output'].encode('utf-8')
                        if len(output)>65536:raise BaoError('template_output_bound')
                        process.stdin.close()
                        if process.wait(timeout=max(.01,deadline-time.monotonic()))!=0:raise BaoError('template_evaluator_stopped')
                        self.secrets.delivery(paths,token_hash,end=deadline)
                        return output,paths,token_hash,deadline
                    else:raise BaoError('template_render_blocked')
        finally:
            selector.close()
            if process.poll() is None:process.terminate()
            try:process.wait(timeout=1)
            except subprocess.TimeoutExpired:process.kill();process.wait(timeout=1)
            for stream in (process.stdin,process.stdout):
                if stream is not None and not stream.closed:stream.close()

    def step(self):
        if time.monotonic()<self.next_poll:return
        self.next_poll=time.monotonic()+self.config['poll_interval_seconds']
        for job in self.config['jobs']:
            try:
                output,paths,token_hash,deadline=self._render(job)
                directory=self.directories[job['destination_dir']];name=job['destination_name']
                with self.publication_lock:
                    expires,wall_expires,observed_wall=self.secrets.delivery(paths,token_hash,end=deadline,include_wall=True)
                    if self.stop.is_set():raise BaoError('template_owner_stopped')
                    before=directory.read(name,optional=True)
                    if before!=output:
                        directory.write(name,output)
                        expires,wall_expires,observed_wall=self.secrets.delivery(paths,token_hash,end=deadline,include_wall=True)
                        self.written.add((job['destination_dir'],name));self.events['changed']+=1
                    self.published[(job['destination_dir'],name)]=(expires,paths,token_hash,wall_expires,observed_wall)
                self.events['rendered']+=1
            except (BaoError,OSError,ValueError,TypeError,UnicodeError,subprocess.SubprocessError):
                self.events['blocked']+=1
                # A stale secret file must not outlive the subscription's known
                # authority after expiry, revoke, unknown renewal or token stop.
                directory=self.directories[job['destination_dir']]
                with self.publication_lock:
                    directory.remove(job['destination_name'])
                    self.published.pop((job['destination_dir'],job['destination_name']),None)

    def _clean_expired(self):
        while not self.cleaner_stop.wait(.05):
            with self.publication_lock:
                for target,(expires,paths,token_hash,wall_expires,observed_wall) in list(self.published.items()):
                    try:
                        wall,mono=time.time(),time.monotonic()
                        if self.stop.is_set() or mono>=expires or wall>=wall_expires or wall<observed_wall or self.secrets.storage_failed:
                            raise BaoError('template_sink_expired')
                        # Never wait for a network operation holding the
                        # subscription lock. Its durable pending marker itself
                        # withdraws permission for a previously published sink.
                        for path in paths:
                            row=self.secrets.rows.get(path)
                            if row is None or row.get('phase')!='ready' or row.get('token_hash')!=token_hash:
                                raise BaoError('template_sink_subscription_fenced')
                            if wall<row['observed_wall'] or row.get('lease_id') and (wall>=row['wall_deadline'] or mono>=row['deadline']):
                                raise BaoError('template_sink_subscription_expired')
                    except (BaoError,OSError,ValueError,TypeError):
                        try:self.directories[target[0]].remove(target[1])
                        except (BaoError,OSError,ValueError,TypeError):self.stop.set()
                        self.published.pop(target,None)

    def metadata(self):return {'events':dict(self.events),'destinations':len(self.written)}

    def close(self):
        self.cleaner_stop.set()
        if self.cleaner is not None:self.cleaner.join(timeout=2)
        if self.cleaner is not None and self.cleaner.is_alive():raise BaoError('template_expiry_owner_not_stopped')
        try:
            if self.config['clean_on_stop']:
                for job in self.config['jobs']:self.directories[job['destination_dir']].remove(job['destination_name'])
        finally:
            for directory in self.directories.values():directory.close()
