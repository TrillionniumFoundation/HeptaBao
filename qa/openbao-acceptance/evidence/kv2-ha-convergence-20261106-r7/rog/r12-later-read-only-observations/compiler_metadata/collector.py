import errno,json,os,pathlib,re,signal,time
started=time.monotonic()
deadline=started+52
def stop(_signum,_frame):
    raise TimeoutError("bounded_metadata_deadline")
previous=signal.signal(signal.SIGALRM,stop)
signal.setitimer(signal.ITIMER_REAL,52)
PID=1419419
def read_bound(path,cap=65536):
    if time.monotonic()>=deadline:
        raise TimeoutError("bounded_metadata_deadline")
    with open(path,"rb") as stream:
        value=stream.read(cap+1)
    if len(value)>cap:
        raise ValueError("metadata_bound")
    return value.decode("utf-8","strict")
def stat_row(pid):
    value=read_bound("/proc/"+str(pid)+"/stat",4096)
    close=value.rfind(")")
    if close<0:
        raise ValueError("stat_shape")
    prefix=value[:close+1]
    actual=int(prefix.split("(",1)[0].strip())
    fields=value[close+1:].split()
    if actual!=pid or len(fields)<20:
        raise ValueError("stat_identity_shape")
    return {"pid":pid,"state":fields[0],"ppid":int(fields[1]),"pgid":int(fields[2]),"sid":int(fields[3]),"start_ticks":int(fields[19])}
def identity(row):
    return [row[k] for k in ("pid","ppid","pgid","sid","start_ticks")]
def observe(pid):
    try:
        first=stat_row(pid)
        comm=read_bound("/proc/"+str(pid)+"/comm",128).rstrip("\n")
        if not re.fullmatch(r"[A-Za-z0-9_.+:/() -]{1,64}",comm):
            raise ValueError("comm_shape")
        uidrow=next((line for line in read_bound("/proc/"+str(pid)+"/status").splitlines() if line.startswith("Uid:")),None)
        if uidrow is None:
            raise ValueError("uid_missing")
        uids=[int(v) for v in uidrow.split()[1:]]
        if len(uids)!=4:
            raise ValueError("uid_shape")
        cgroup_raw=read_bound("/proc/"+str(pid)+"/cgroup",16384)
        runtime_ids=sorted(set(re.findall(r"(?:^|/)hepta-runtime-job-([0-9a-f]+-[0-9a-f]+-[0-9a-f]+)(?:[.]service)?(?:/|$)",cgroup_raw,re.M)))
        kernel_sid=os.getsid(pid)
        kernel_pgid=os.getpgid(pid)
        last=stat_row(pid)
        stable=identity(first)==identity(last)
        return {**last,"present":True,"comm":comm,"uids":uids,"stable_identity_within_observation":stable,"kernel_sid_matches":kernel_sid==last["sid"],"kernel_pgid_matches":kernel_pgid==last["pgid"],"runtime_unit_job_ids":runtime_ids,"unmatched_cgroup_paths_withheld":not bool(runtime_ids)}
    except (ProcessLookupError,FileNotFoundError):
        return {"pid":pid,"present":False,"observation":"gone_or_raced","original_preflight_identity_not_proven":True}
    except OSError as error:
        return {"pid":pid,"present":None,"error_type":type(error).__name__,"errno":error.errno}
out={"schema":"heptabao.readonly-compiler-metadata-observation.v1","requested_pid":PID,"original_preflight_birth_unknown":True,"no_attribution_inferred":True,"read_cmdline":False,"read_environ":False,"signals_sent":False,"subprocesses_started":0,"product_files_opened":False,"process_chain":[]}
try:
    boot=read_bound("/proc/sys/kernel/random/boot_id",128).strip()
    if re.fullmatch("[0-9a-f-]{36}",boot) is None:
        raise ValueError("boot_id_shape")
    out["boot_id"]=boot
    out["clock_ticks_per_second"]=os.sysconf("SC_CLK_TCK")
    pid=PID
    seen=set()
    for _ in range(5):
        if pid<=0 or pid in seen:
            break
        seen.add(pid)
        row=observe(pid)
        out["process_chain"].append(row)
        if row.get("present") is not True or not row.get("stable_identity_within_observation") or pid==1:
            break
        pid=row["ppid"]
    out["bounded_parent_chain_complete"]=not (len(out["process_chain"])==5 and out["process_chain"][-1].get("ppid",0)>0)
    out["status"]="observed"
except BaseException as error:
    out["status"]="failed"
    out["error_type"]=type(error).__name__
finally:
    out["elapsed_seconds"]=time.monotonic()-started
    signal.setitimer(signal.ITIMER_REAL,0)
    signal.signal(signal.SIGALRM,previous)
    print(json.dumps(out,sort_keys=True),flush=True)
if out["status"]!="observed":
    raise SystemExit(1)
