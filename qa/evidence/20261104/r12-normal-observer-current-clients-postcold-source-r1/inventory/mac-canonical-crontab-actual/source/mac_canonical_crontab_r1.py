#!/usr/bin/env python3
"""One canonical system-crontab observation after exact /etc alias evidence.

No general symlink following, no directory scan, no command, no file writes.
"""
import hashlib, json, os, re, stat, sys, time
START=time.monotonic()
UNTIL=START+5.0
EXPECTED_ALIAS=["16777233","1152921500312571429","0","0","41453","1","11","1786589515000000000","1786589515000000000"]
EXPECTED_ROOT=["16777233","2","0","0","16877","22","704","1786589515000000000","1786589515000000000"]
report={'schema':'heptabao.mac-canonical-system-crontab.r1','status':'failed',
 'source_alias_result_sha256':'61ad3e1dcd69c43f20010869225d0bd8ed6654b4e88570ecc03a239689157254',
 'path':'/private/etc/crontab','new_inner_seconds':5,'new_outer_seconds':60,
 'read_limit_bytes':65536,'explicit_metadata_operations':0,'readlink_operations':0,
 'bytes_read':0,'files_written':False,'children_started':False,'network_used':False,
 'directory_scanned':False,'general_symlink_following':False,
 'previous_inventory_result_rewritten':False,'repeated_completed_entries':0}
fds=[];parents=[];file_fd=None
def need(ok,code):
    if not ok:raise RuntimeError(code)
def remaining():
    need(time.monotonic()<UNTIL,'canonical_read_deadline')
def identity(s):
    return [str(x) for x in (s.st_dev,s.st_ino,s.st_uid,s.st_gid,s.st_mode,s.st_nlink,
                            s.st_size,s.st_mtime_ns,s.st_ctime_ns)]
def metadata(fn,*args,**kwargs):
    remaining();report['explicit_metadata_operations']+=1
    return fn(*args,**kwargs)
def sha(raw):return hashlib.sha256(raw).hexdigest()
def cron_projection(raw):
    rows = []
    for number, line in enumerate(raw.decode("utf-8").splitlines(), 1):
        value = line.strip()
        if not value or value.startswith("#"):
            continue
        if re.search(r"openbao|heptabao|authbus|openclaw", value, re.I):
            rows.append({"line": number, "sha256": sha(value.encode()),
                         "literal_match_only": True})
    need(len(rows) <= 32, "selected_cron_line_bound")
    return {"selected_application_lines": rows, "unmatched_lines_not_published": True,
            "manual_or_unregistered_paths_excluded_by_absence": False}
def hold_directory(name,parent_fd=None):
    before=metadata(os.lstat,name) if parent_fd is None else metadata(
        os.stat,name,dir_fd=parent_fd,follow_symlinks=False)
    need(stat.S_ISDIR(before.st_mode) and before.st_uid==0
      and not before.st_mode&0o022 and str(before.st_dev)==EXPECTED_ROOT[0],
      'plain_root_owned_canonical_parent')
    fd=os.open(name,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,
               **({} if parent_fd is None else {'dir_fd':parent_fd}))
    fds.append(fd)
    held=metadata(os.fstat,fd)
    need(identity(before)==identity(held),'same_named_parent_fd')
    parents.append({'name':name,'parent_fd':parent_fd,'fd':fd,'identity':identity(before)})
    return fd
def prove_parent_closure():
    rows=[]
    for row in parents:
        named=metadata(os.lstat,row['name']) if row['parent_fd'] is None else metadata(
            os.stat,row['name'],dir_fd=row['parent_fd'],follow_symlinks=False)
        held=metadata(os.fstat,row['fd'])
        need(identity(named)==identity(held)==row['identity'],'canonical_parent_changed')
        rows.append({'component':row['name'],'identity':row['identity']})
    return rows
try:
    need(os.getuid()==501 and os.uname().sysname=='Darwin'
      and os.uname().machine=='arm64','expected_mac_owner_os')
    root=hold_directory('/')
    need(parents[0]['identity']==EXPECTED_ROOT,'original_system_root_unchanged')
    alias_before=metadata(os.stat,'etc',dir_fd=root,follow_symlinks=False)
    need(identity(alias_before)==EXPECTED_ALIAS and stat.S_ISLNK(alias_before.st_mode),
         'original_etc_alias_unchanged')
    target=os.readlink('etc',dir_fd=root);report['readlink_operations']+=1
    need(target=='private/etc','same_observed_literal_alias_target')
    private=hold_directory('private',root)
    canonical=hold_directory('etc',private)
    try:
        before=metadata(os.stat,'crontab',dir_fd=canonical,follow_symlinks=False)
    except FileNotFoundError:
        before=None
    if before is None:
        try:
            metadata(os.stat,'crontab',dir_fd=canonical,follow_symlinks=False)
        except FileNotFoundError:
            report['absence_observations']=2
        else:raise RuntimeError('crontab_appeared_during_absence_observation')
        report['leaf_status']='absent_two_named_enoent'
    else:
        need(stat.S_ISREG(before.st_mode) and before.st_uid==0 and before.st_nlink==1
          and not before.st_mode&0o022 and 0<=before.st_size<=65536,
          'bounded_root_owned_plain_crontab')
        file_fd=os.open('crontab',os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=canonical)
        opened=metadata(os.fstat,file_fd)
        need(identity(before)==identity(opened),'same_crontab_fd')
        chunks=[];size=0
        while True:
            remaining()
            block=os.read(file_fd,min(8192,65537-size))
            if not block:break
            chunks.append(block);size+=len(block)
            need(size<=65536,'crontab_read_byte_bound')
        raw=b''.join(chunks);report['bytes_read']=size
        held=metadata(os.fstat,file_fd)
        named=metadata(os.stat,'crontab',dir_fd=canonical,follow_symlinks=False)
        need(size==before.st_size and identity(before)==identity(held)==identity(named),
             'crontab_bytes_and_named_identity_stable')
        report['leaf_status']='read_verified'
        report['file']={'identity':identity(named),'bytes':size,'sha256':sha(raw),
                        'projection':cron_projection(raw)}
    report['parents']=prove_parent_closure()
    alias_after=metadata(os.stat,'etc',dir_fd=root,follow_symlinks=False)
    need(identity(alias_after)==identity(alias_before)==EXPECTED_ALIAS,'alias_stable_through_canonical_read')
    report['alias_identity']=EXPECTED_ALIAS
    need(report['explicit_metadata_operations']==(16 if before is None else 18)
      and report['readlink_operations']==1,'fixed_single_leaf_operation_denominator')
    remaining();report['status']='complete_single_canonical_observation'
except BaseException as error:
    report['error_type']=type(error).__name__
    report['error_code']=str(error) if type(error) is RuntimeError else None
finally:
    closed=True
    for fd in ([file_fd] if file_fd is not None else [])+list(reversed(fds)):
        try:os.close(fd)
        except BaseException as error:
            closed=False;report['close_error_type']=type(error).__name__
    report['all_owned_fds_closed']=closed
    if not closed or time.monotonic()>=UNTIL:report['status']='failed'
    report['elapsed_seconds']=time.monotonic()-START
    report['authoritative_exit_zero_within_new_inner_required']=True
    raw=(json.dumps(report,sort_keys=True,separators=(',',':'))+'\n').encode()
    need(len(raw)<=16384,'bounded_public_canonical_observation')
    sys.stdout.buffer.write(raw);sys.stdout.buffer.flush()
sys.exit(0 if report['status']=='complete_single_canonical_observation' and time.monotonic()<UNTIL else 1)
