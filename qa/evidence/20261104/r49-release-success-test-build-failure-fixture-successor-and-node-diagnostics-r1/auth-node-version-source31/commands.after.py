#!/usr/bin/env python3
"""Bounded foreground commands with retained direct-child custody.

No import-time I/O. The caller supplies exact reviewed argv and an absolute
command deadline. Pipe reads, exit observation and metadata capture share it.
Cleanup uses the separate once-only TERM1/wait5/group3 custody contract.
"""
from __future__ import annotations
from contextlib import contextmanager
import hashlib, os, select, signal, subprocess, time
from mac_owned_unreaped_r1 import require_waitid, capture_child, exit_observation, observed_returncode, stop_once_unreaped


# Fixed public comparison only; no inherited environment and no script argument.
VERSION_CWD="/Users/qianqi/heptabao-public-node-version-20261106-r1-empty"
VERSION_ENV={"PATH":"/opt/homebrew/bin:/usr/bin:/bin:/usr/sbin:/sbin","LANG":"C","LC_ALL":"C","HOME":"/Users/qianqi/heptabao-public-node-version-20261106-r1-empty","TMPDIR":"/Users/qianqi/heptabao-public-node-version-20261106-r1-empty"}
VERSION_ARGV={"restricted-version":["/usr/bin/sandbox-exec","-f","/Users/qianqi/heptabao-public-node-version-20261106-r1-control/consumer.sb","/opt/homebrew/Cellar/node/25.9.0_1/bin/node","--version"],"baseline-version":["/opt/homebrew/Cellar/node/25.9.0_1/bin/node","--version"]}

class CommandRefused(RuntimeError):pass
def need(value,code):
    if not value:raise CommandRefused(code)
def sha(raw):return hashlib.sha256(raw).hexdigest()

class Signals:
    def __init__(self):
        self.protected=0;self.pending=None
    def receive(self,signum,_frame):
        self.pending=signum
        if not self.protected:raise KeyboardInterrupt()
    def install(self):
        signal.signal(signal.SIGTERM,self.receive);signal.signal(signal.SIGINT,self.receive)
    @contextmanager
    def critical(self):
        self.protected+=1
        try:yield
        finally:self.protected-=1

class Commands:
    def __init__(self,signals):
        self.signals=signals;self.rows=[]
    def run(self,label,argv,*,until,allow_cancelled_cleanup=False,maximum=2*1024*1024):
        need(isinstance(label,str) and label.replace('-','').replace('_','').isalnum(),'safe_command_label')
        need(type(maximum) is int and 0<maximum<=2*1024*1024,'fixed_command_output_bound')
        need(isinstance(argv,list) and argv and all(isinstance(x,str) for x in argv),'explicit_argv')
        def remaining():
            if not allow_cancelled_cleanup:need(self.signals.pending is None,'command_cancelled')
            n=until-time.monotonic();need(n>0,'original_command_deadline_exhausted');return n
        need(label in VERSION_ARGV and argv==VERSION_ARGV[label]
             and len(self.rows)<2 and not any(r['label']==label for r in self.rows),
             'fixed_two_version_argv_once')
        need(maximum==4096,'fixed_version_output_limit')
        require_waitid();remaining()
        started=time.monotonic();row=None;out=bytearray();err=bytearray()
        try:
            with self.signals.critical():
                remaining()
                p=subprocess.Popen(argv,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,
                    env=VERSION_ENV,cwd=VERSION_CWD,
                    start_new_session=True,close_fds=True)
                row={'label':label,'argv':list(argv),'process':p,'custody':None,
                     'stopAttempted':False,'streamsCloseAttempted':False,'streamsClosed':False,
                     'completeBeforeDeadline':False,'errorType':None,'errorCode':None}
                self.rows.append(row)
            row['custody']=capture_child(p,until=until)
            streams={p.stdout.fileno():out,p.stderr.fileno():err}
            for fd in streams:os.set_blocking(fd,False)
            event=None
            while streams or event is None:
                left=remaining()
                ready,_,_=select.select(list(streams),[],[],min(left,0.025))
                for fd in ready:
                    data=os.read(fd,65536)
                    if not data:del streams[fd]
                    else:
                        target=streams[fd];target.extend(data)
                        need(len(target)<=maximum,'command_output_bound')
                event=exit_observation(p)
            remaining()
            row['completeBeforeDeadline']=True
            row['observedExit']=event
            row['observedExitCode']=observed_returncode(event)
        except BaseException as error:
            if row is None:raise
            row['errorType']=type(error).__name__
            row['errorCode']=str(error) if isinstance(error,CommandRefused) else None
        finally:
            if row is not None:
                with self.signals.critical():
                    row['stopAttempted']=True
                    try:row['cleanup']=stop_once_unreaped(row['process'],row['custody'])
                    except BaseException as error:
                        row['cleanup']={'ok':False,'outcomeUnknown':True,
                            'errorType':type(error).__name__,'directChildReaped':row['process'].returncode is not None,
                            'allGroupRowsEmptyAfterReap':False}
                    row['streamsCloseAttempted']=True
                    errors=[]
                    for stream in (row['process'].stdout,row['process'].stderr):
                        try:stream.close()
                        except BaseException as error:errors.append(type(error).__name__)
                    row['streamsClosed']=not errors
                    row['streamCloseErrors']=errors
        p=row['process'];cleanup=row['cleanup']
        public={'label':label,'argv':list(argv),'pid':p.pid,'exitCode':p.returncode,
            'completeBeforeDeadline':row['completeBeforeDeadline'],
            'commandDeadlineMonotonic':until,'elapsedSeconds':time.monotonic()-started,
            'errorType':row['errorType'],'errorCode':row['errorCode'],'cleanup':cleanup,
            'stdoutBytes':len(out),'stdoutSha256':sha(out),'stderrBytes':len(err),'stderrSha256':sha(err),
            'streamsClosed':row['streamsClosed'],
            'outcomeUnknown':not(row['completeBeforeDeadline'] and cleanup.get('ok') is True
                and cleanup.get('directChildReaped') is True and cleanup.get('allGroupRowsEmptyAfterReap') is True
                and row['streamsClosed'] and row['errorType'] is None)}
        row['public']=public
        return public,bytes(out),bytes(err)
    def public(self):
        values=[r.get('public') for r in self.rows]
        return {'commands':values,'allOwnedCommandsStopped':all(v is not None
            and v['cleanup'].get('directChildReaped') is True
            and v['cleanup'].get('allGroupRowsEmptyAfterReap') is True
            and v['streamsClosed'] for v in values),
            'unknownCommandCount':sum(v is None or v['outcomeUnknown'] for v in values)}
