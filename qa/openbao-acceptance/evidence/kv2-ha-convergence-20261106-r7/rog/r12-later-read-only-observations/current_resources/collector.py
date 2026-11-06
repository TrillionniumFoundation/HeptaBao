import json,os,pathlib,shutil,signal,time
started=time.monotonic()
def stop(_signum,_frame):
    raise TimeoutError("resource_observation_deadline")
prior=signal.signal(signal.SIGALRM,stop)
signal.setitimer(signal.ITIMER_REAL,52)
root=pathlib.Path("/home/qian-qi/heptabao-kv2-ha-convergence-20261106-r1")
out={"schema":"heptabao.ci-diagnostic-current-resource-observation.v1","read_only":True,"read_cmdline":False,"read_environ":False,"signals_sent":False,"subprocesses_started":0,"product_files_opened":False,"snapshot_not_host_reservation":True,"original_r12_failed_attempt_unchanged":True}
try:
    mem={line.split(":")[0]:int(line.split()[1]) for line in pathlib.Path("/proc/meminfo").read_text().splitlines() if line.startswith(("MemAvailable:","SwapFree:"))}
    compilers=[]; vanished=[]; denied=[]; malformed=[]
    for p in pathlib.Path("/proc").iterdir():
        if not p.name.isdigit():
            continue
        try:
            name=(p/"comm").read_text().rstrip("\n")
            if name not in {"cargo","rustc","rustfmt","rust-lld"}:
                continue
            value=(p/"stat").read_text()
            fields=value.rsplit(")",1)[1].split()
            uid_line=next(line for line in (p/"status").read_text().splitlines() if line.startswith("Uid:"))
            compilers.append({"pid":int(p.name),"comm":name,"state":fields[0],"ppid":int(fields[1]),"pgid":int(fields[2]),"sid":int(fields[3]),"start_ticks":int(fields[19]),"uids":[int(v) for v in uid_line.split()[1:]]})
        except (FileNotFoundError,ProcessLookupError):
            vanished.append(int(p.name))
        except PermissionError:
            denied.append(int(p.name))
        except (IndexError,ValueError,StopIteration):
            malformed.append(int(p.name))
    out.update(status="observed",disk_free_bytes=shutil.disk_usage(root).free,mem_available_kib=mem["MemAvailable"],swap_free_kib=mem["SwapFree"],load_average=list(os.getloadavg()),compiler_processes=compilers,vanished_during_scan=vanished,permission_denied=denied,malformed_metadata=malformed,euid=os.geteuid())
    out["original_resource_thresholds"]={"disk_free_minimum_bytes":8*1024**3,"mem_available_minimum_kib":12*1024**2,"compiler_processes_required":0}
    out["resource_gate_currently_matches_original"]=(not compilers and not denied and not malformed and out["disk_free_bytes"]>=8*1024**3 and out["mem_available_kib"]>=12*1024**2)
except BaseException as error:
    out.update(status="failed",error_type=type(error).__name__)
finally:
    out["elapsed_seconds"]=time.monotonic()-started
    signal.setitimer(signal.ITIMER_REAL,0)
    signal.signal(signal.SIGALRM,prior)
    print(json.dumps(out,sort_keys=True),flush=True)
if out["status"]!="observed":
    raise SystemExit(1)
