import json, os, stat, sys, time
root = "/Volumes/T5/hepta-vnext-recovery-20261013/continuation-20261103-ha-closure-r1/r10-pocket3-mac1-direct98-node1-r2"
started = time.monotonic()
until = started + 15.0
out = {"schema":"heptabao.stopped-raft-three-file-lstat.v1","file_writes":0,"payload_reads":0,"child_processes":0,"product_requests":0,"new_inner_seconds":15,"paths":[],"status":"failed"}
rc = 1
try:
    for path in (root + "/native-ha-fixture.json", root + "/raft/log/raft-log.bin", root + "/raft/log/raft-log.journal"):
        if time.monotonic() >= until: raise TimeoutError()
        s = os.lstat(path)
        out["paths"].append({"path":path,"uid":s.st_uid,"type":"regular" if stat.S_ISREG(s.st_mode) else "directory" if stat.S_ISDIR(s.st_mode) else "symlink" if stat.S_ISLNK(s.st_mode) else "other","mode":stat.S_IMODE(s.st_mode),"mode_octal":oct(stat.S_IMODE(s.st_mode)),"device":s.st_dev,"inode":s.st_ino,"nlink":s.st_nlink,"size":s.st_size,"mtime_ns":s.st_mtime_ns,"ctime_ns":s.st_ctime_ns})
    if time.monotonic() >= until: raise TimeoutError()
    out["status"] = "completed"
    rc = 0
except BaseException as e:
    out["failure_type"] = type(e).__name__
out["elapsed_seconds"] = time.monotonic() - started
out["publication_within_original_observer_deadline"] = time.monotonic() < until
if not out["publication_within_original_observer_deadline"]:
    out["status"] = "failed"; rc = 1
raw = json.dumps(out, sort_keys=True, separators=(",",":")) + "\n"
if len(raw.encode()) > 4096: raise RuntimeError("bounded_output")
sys.stdout.write(raw); sys.stdout.flush()
raise SystemExit(rc if time.monotonic() < until else 1)
