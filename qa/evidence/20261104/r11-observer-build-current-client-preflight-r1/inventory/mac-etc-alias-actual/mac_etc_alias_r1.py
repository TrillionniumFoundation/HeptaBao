#!/usr/bin/env python3
"""One named /etc alias observation; no target open, directory scan or follow."""
import hashlib, json, os, re, stat, sys, time
START=time.monotonic()
UNTIL=START+5.0
EXPECTED=["16777233","1152921500312571429","0","0","41453","1","11","1786589515000000000","1786589515000000000"]
report={'schema':'heptabao.mac-finite-inventory-etc-alias.r1','host':'mac',
 'status':'failed','new_inner_seconds':5,'new_outer_seconds':60,
 'source_readonly_result_sha256':'001d9d3384f1b8c00fa3cba8af7f3020bedc54f26678611ab3cd3a524ce23902',
 'link_path':'/etc','target_opened':False,'symlink_followed':False,
 'directory_scanned':False,'files_written':False,'children_started':False,
 'network_used':False,'system_crontab_read':False,'system_crontab_absence_claimed':False}
fd=None
def need(ok,code):
    if not ok:raise RuntimeError(code)
def remaining():
    need(time.monotonic()<UNTIL,'new_alias_observation_deadline')
def identity(s):
    return [str(x) for x in (s.st_dev,s.st_ino,s.st_uid,s.st_gid,s.st_mode,s.st_nlink,
      s.st_size,s.st_mtime_ns,s.st_ctime_ns)]
try:
    need(os.getuid()==501 and os.uname().sysname=='Darwin'
      and os.uname().machine=='arm64','expected_mac_owner_os')
    remaining()
    root_before=os.lstat('/')
    need(stat.S_ISDIR(root_before.st_mode) and root_before.st_uid==0
      and str(root_before.st_dev)==EXPECTED[0],'existing_system_root_identity')
    fd=os.open('/',os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    root_open=os.fstat(fd)
    need(identity(root_open)==identity(root_before),'same_root_fd')
    remaining()
    before=os.stat('etc',dir_fd=fd,follow_symlinks=False)
    need(identity(before)==EXPECTED and stat.S_ISLNK(before.st_mode)
      and before.st_uid==0 and before.st_nlink==1 and 0<before.st_size<=4096,
      'exact_previously_observed_named_alias')
    target=os.readlink('etc',dir_fd=fd)
    raw=target.encode('utf-8')
    need(len(raw)==before.st_size and len(raw)<=4096,'exact_link_text_length')
    need(re.fullmatch(r'/?[A-Za-z0-9_.+-]+(?:/[A-Za-z0-9_.+-]+)*',target) is not None
      and all(x not in ('.','..') for x in target.split('/')),'simple_literal_link_target')
    remaining()
    after=os.stat('etc',dir_fd=fd,follow_symlinks=False)
    root_after=os.lstat('/')
    need(identity(before)==identity(after)==EXPECTED
      and identity(root_before)==identity(root_open)==identity(root_after),
      'named_alias_and_root_stable_through_readlink')
    report.update(status='observed_named_alias_only',expected_previous_identity=EXPECTED,
      observed_identity=identity(after),root_identity=identity(root_after),
      readlink_target=target,target_sha256=hashlib.sha256(raw).hexdigest(),target_bytes=len(raw),
      lexical_absolute_candidate=target if target.startswith('/') else '/'+target,
      lexical_candidate_not_opened_or_resolved=True,
      explicit_lstat_fstat_count=5,readlink_count=1)
except BaseException as error:
    report['error_type']=type(error).__name__
    report['error_code']=str(error) if type(error) is RuntimeError else None
finally:
    if fd is not None:
        try:os.close(fd);report['owned_root_fd_closed']=True
        except BaseException as error:
            report['status']='failed';report['close_error_type']=type(error).__name__
    else:report['owned_root_fd_closed']=True
    if time.monotonic()>=UNTIL:report['status']='failed'
    report['elapsed_seconds']=time.monotonic()-START
    report['authoritative_exit_zero_within_new_inner_required']=True
    raw=(json.dumps(report,sort_keys=True,separators=(',',':'))+'\n').encode()
    need(len(raw)<=8192,'bounded_public_alias_observation')
    sys.stdout.buffer.write(raw);sys.stdout.buffer.flush()
sys.exit(0 if report['status']=='observed_named_alias_only' and time.monotonic()<UNTIL else 1)
