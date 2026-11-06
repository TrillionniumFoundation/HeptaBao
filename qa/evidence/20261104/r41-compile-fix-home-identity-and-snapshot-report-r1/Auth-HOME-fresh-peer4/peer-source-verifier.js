function verifyHomeControlPeer(input) {
 const checks=[];
 function ck(name,value){if(!value)throw new Error(name);checks.push({name,pass:true});}
 function body(raw,start,end){const a=raw.indexOf(start),b=raw.indexOf(end,a+start.length);ck("unique selected section "+start,a>=0&&b>a);return raw.slice(a,b);}
 function ordered(name,s,parts){let at=-1;for(const p of parts){at=s.indexOf(p,at+1);ck(name+" :: "+p,at>=0);}}
 for(const [name,x] of Object.entries(input.files)){ck("whole "+name,JSON.stringify(gitBlobMeta(x.raw))===JSON.stringify(x.pin));}
 const home=input.files["home-control.py"].raw,mgr=input.files["mac_owned_launchd_r3.py"].raw;
 const outer=input.files["mac_current_outer_wal_r1.py.diff"].raw;
 const phase=input.files["mac_current_phase_owner_r2.py"].raw,server=input.files["mac_current_server_owner_r1.py"].raw;
 const diff=input.files["mac_owned_launchd_r3.py.diff"].raw;
 ck("HomeControl exact one inline instance",mgr.split(home).length===2);
 ck("manager strict forward",snapshotApply(input.oldManager.raw,diff)===mgr);
 ck("manager strict reverse",snapshotApply(mgr,diff,true)===input.oldManager.raw);
 const op=body(home,"    def _open(","    def _close_one(");
 ordered("open protected registration",op,["with self.critical():","self.open_attempts+=1;self.open_pending+=1","try:fd=os.open","except OSError:","self.open_pending-=1","row={'fd':fd","self.rows.append(row);self.open_pending-=1","except BaseException:","self.registration_unknown=True"]);
 ck("close whole loop critical",home.includes("with self.critical():\n            for row in reversed(self.rows):self._close_one(row)\n            self.closed=True"));
 ck("once close marker precedes syscall",home.includes("row['closeAttempted']=True\n            try:os.close(row['fd']);row['closed']=True"));
 ck("finite exact flat paths",home.includes("path.parent==HOME_CONTROL")&&home.includes("path==Path(os.path.normpath(str(path)))")&&home.includes("for s in ('.plist','.stdout.private','.stderr.private')"));
 ck("no symlink acquire",home.split("self._open(").length===6&&home.split("os.O_NOFOLLOW").length===6);
 ck("held named parent plus first5",home.includes("actual==file_identity(named) and actual[:5]==row['identity'][:5]"));
 ck("owned root full9",home.includes("file_identity(info)==file_identity(named)==self.root_identity"));
 ck("exclusive role split",home.includes("(self.create and copy and name in HOME_COPY_NAMES)")&&home.includes("(not self.create and not copy and name not in HOME_COPY_NAMES)"));
 ck("stdio created empty",home.includes("need(kind!='stdio' or raw==b''"));
 ck("new regular singleton 0600",home.includes("before.st_nlink==1 and stat.S_IMODE(before.st_mode)==0o600"));
 ck("finite counts unchanged",home.includes("HOME_FD_ATTEMPTS=64\nHOME_METADATA_CALLS=4096\nHOME_READ_CALLS=256\nHOME_READ_BYTES=2*1024*1024\nHOME_WRITE_CALLS=64\nHOME_WRITE_BYTES=131072"));
 ck("write ceiling and progress",home.includes("self.counts['writeBytes']+len(raw)<=HOME_WRITE_BYTES")&&home.includes("0<amount<=len(raw)-offset"));
 ck("read byte count before bounds gate",home.includes("self.counts['readBytes']+=len(raw)\n        need(len(raw)<=count"));
 ck("whole read plus real EOF",home.includes("info.st_size+1<=HOME_READ_BYTES")&&home.includes("need(self._read(row['fd'],1)==b''"));
 ck("read full9 interval",home.includes("before==after==named"));
 ck("stderr body rejected",home.includes("not name.endswith('.stderr.private')"));
 ck("prefix two reads same FD",home.includes("self._read(row['fd'],len(raw),0)==raw"));
 ck("unknown forbids closure",home.includes("self.open_pending==0 and not self.registration_unknown")&&home.includes("and not self.effect_unknown and not self.close_errors"));
 ck("outer incomplete construction conservative",outer.includes("home_init_started=True;home_control=HomeControl.__new__(HomeControl)")&&outer.includes("home_init_complete=True")&&outer.includes("home_closed=(not home_init_started or (home_init_complete"));
 ck("outer finally closes home and aggregates",outer.includes("home_control.close();report['homeControlFinal']=home_control.public()")&&outer.includes("or not manager_closed or not helpers_closed or not input_closed or not home_closed"));
 ck("manager compares original and HOME public wrapper",mgr.includes("self.home.read(home_wrapper,1048576)==raw")&&mgr.includes("return [PYTHON_LAUNCHER,'-I','-S','-B',str(home_wrapper),*common]"));
 ck("HOME plist WorkingDirectory",mgr.includes("'WorkingDirectory':str(HOME_CONTROL),'StandardOutPath':str(stdout)"));
 ck("private plan stays T5",mgr.includes("path=ROOT/'launchd'/(generation+'.private.json')")&&mgr.includes("raw=self.guard.read(path)"));
 ck("private result stays T5",mgr.includes("raw=self.guard.read(ROOT/'launchd'/(generation+'.result.public.json'))"));
 ck("outer HomeControl deadline inherited",outer.includes("home_control.__init__(remaining=ctx.remaining,critical=ctx.critical,"));
 ck("manager original deadline and cleanup separate",mgr.includes("NEW_MANAGER_SECONDS=600.0")&&mgr.includes("NEW_CLEANUP_SECONDS=60.0")&&mgr.includes("left=bound-time.monotonic();need(left>0,'original_manager_or_cleanup_deadline')"));
 ordered("phase held cwd before private plan",phase,["report['volumeGuard']=volume_before_private_state()","with volume_guard.parent(ROOT/'launchd')","os.fchdir(work_fd)","identity(os.stat('.'))==identity(os.fstat(work_fd))","volume_guard.check();report['ownedBusinessWorkingDirectoryHeldT5']=True","raw=private_read(args.plan)"]);
 ordered("server held cwd before private plan",server,["guard.accept_diskutil(out)","with guard.parent(ROOT/'launchd')","os.fchdir(work_fd)","identity(os.stat('.'))==identity(os.fstat(work_fd))","guard.check();report['ownedBusinessWorkingDirectoryHeldT5']=True","raw=guard.read(args.plan)"]);
 ck("manager requires held business cwd",mgr.split("get('ownedBusinessWorkingDirectoryHeldT5') is True").length===3);
 ck("kernel launcher split both wrappers",phase.includes("self_identity['executable']==PYTHON_KERNEL_IMAGE")&&server.includes("self_identity['executable']==PYTHON_KERNEL_IMAGE")&&phase.includes("str(Path(sys.executable).resolve())==PYTHON_LAUNCHER")&&server.includes("str(Path(sys.executable).resolve())==PYTHON_LAUNCHER"));
 const candidate=JSON.parse(input.files["candidate.public.json"].raw),scope=JSON.parse(input.files["SOURCE-ONLY.public.json"].raw);
 for(const name of ["mac_owned_launchd_r3.py","mac_current_phase_owner_r2.py","mac_current_server_owner_r1.py"]){ck("candidate pin "+name,candidate.sourcePins[name]===input.files[name].pin.sha256);}
 ck("runtime binding not fabricated",scope.actualHomeBinding===null&&scope.runtimeRequest===null&&scope.NativeCalls===0);
 return {schema:"heptabao.home-t5-core-source-peer.actual.v1",scope:"pure source/hash/strict diff, no Python or Native",checks,passed:checks.length};
}
