"""Fixed public formatter-output collector. SOURCE proposal; separate root GO required.
Reads exactly 10 public files, then writes one new observation report. No child/network.
The report proves input observations; final stdout plus authoritative exit proves cleanup.
"""
import difflib,hashlib,json,os,re,signal,stat,sys,time

START=time.monotonic()
LIMIT=50.0
INPUT_ROOT="/home/qian-qi/heptabao-native-pki-lease400-format-20261106-r1"
OUTPUT_NAME="heptabao-native-pki-lease400-format-observe-20261106-r1"
OUTPUT_ROOT="/home/qian-qi/"+OUTPUT_NAME
REPORT_NAME="observation.public.json"
SOURCE_COMMIT="e3afc157447d35c861f275a761b29da3e42aff8e"
SOURCE_TREE="5497775d9d473541e13e1603be8c893a3e27681b"
FORMATTER_JOB="1a1af6d62a1-fc05-686a"
FORMATTER_SOURCE_BLOB="4bea36c9c2c80c280429a90d2f22523fd80e95d5"
RECEIPT_BLOB="6638b8f22581832b5451d8b79e275feccec54959"
CANDIDATE_SOURCE_PACKET="6e4bf23de8f7fdac6dd9b152232a905bedb87744"
INPUT_CARRIER_SHA256="b04208ff4a3787e229b8cd7a86316ef6b0d90fdb941ebd5ef166b14cb06e1489"
INPUT_ORIGINAL_AND_CANDIDATE_PINS=json.loads("{\"pki.rs\":[\"c7f86b2eccaa4756dbffc1ed30c6f6e00f2f3874c35b76d46705e64cb87302e9\",\"3236b3a297bda793f756be4f95aa2dc5bb1202eb6a846164ce38ee01597850ba\"],\"service_native_pki_tests.rs\":[\"b5dbe7c3b75182f44213495e764c4ebfa6760b9c915219720cee0b711cc8931b\",\"3dfea1dccd78187517f3cb9ca04ed036073eb7ed6b7c604815aa745f4402f208\"]}")
READ_CAP=1424736
READ_CHUNK=65536
READ_CALL_CAP=256
META_CAP=320
FD_CAP=18
PEAK_FD_CAP=16
DIFF_CAP=131072
REPORT_CAP=262144
STDOUT_CAP=16384
CONFIG_BYTES=b'edition = "2024"\n'
ROWS=json.loads("[{\"index\":0,\"role\":\"candidate\",\"name\":\"pki.rs\",\"relative\":\"candidate/pki.rs\",\"path\":\"/home/qian-qi/heptabao-native-pki-lease400-format-20261106-r1/candidate/pki.rs\",\"bytes\":136672,\"sha256\":\"3236b3a297bda793f756be4f95aa2dc5bb1202eb6a846164ce38ee01597850ba\",\"cap\":136672,\"expected_full9\":null,\"immutable_blob\":\"3c6fd86dcd641eb16af64b835d2252163dd1488e\"},{\"index\":1,\"role\":\"formatted\",\"name\":\"pki.rs\",\"relative\":\"formatted/pki.rs\",\"path\":\"/home/qian-qi/heptabao-native-pki-lease400-format-20261106-r1/formatted/pki.rs\",\"bytes\":136672,\"sha256\":\"3236b3a297bda793f756be4f95aa2dc5bb1202eb6a846164ce38ee01597850ba\",\"cap\":262144,\"expected_full9\":null,\"immutable_blob\":null},{\"index\":2,\"role\":\"stdout\",\"name\":\"pki.rs\",\"relative\":\"pki.rs.rustfmt.stdout\",\"path\":\"/home/qian-qi/heptabao-native-pki-lease400-format-20261106-r1/pki.rs.rustfmt.stdout\",\"bytes\":136672,\"sha256\":\"3236b3a297bda793f756be4f95aa2dc5bb1202eb6a846164ce38ee01597850ba\",\"cap\":262144,\"expected_full9\":null,\"immutable_blob\":null},{\"index\":3,\"role\":\"stderr\",\"name\":\"pki.rs\",\"relative\":\"pki.rs.rustfmt.stderr\",\"path\":\"/home/qian-qi/heptabao-native-pki-lease400-format-20261106-r1/pki.rs.rustfmt.stderr\",\"bytes\":0,\"sha256\":\"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855\",\"cap\":65536,\"expected_full9\":null,\"immutable_blob\":null},{\"index\":4,\"role\":\"candidate\",\"name\":\"service_native_pki_tests.rs\",\"relative\":\"candidate/service_native_pki_tests.rs\",\"path\":\"/home/qian-qi/heptabao-native-pki-lease400-format-20261106-r1/candidate/service_native_pki_tests.rs\",\"bytes\":42863,\"sha256\":\"3dfea1dccd78187517f3cb9ca04ed036073eb7ed6b7c604815aa745f4402f208\",\"cap\":42863,\"expected_full9\":null,\"immutable_blob\":\"352e581f5a901f21ee7c7af4c9bc5b3bed1a1439\"},{\"index\":5,\"role\":\"formatted\",\"name\":\"service_native_pki_tests.rs\",\"relative\":\"formatted/service_native_pki_tests.rs\",\"path\":\"/home/qian-qi/heptabao-native-pki-lease400-format-20261106-r1/formatted/service_native_pki_tests.rs\",\"bytes\":42909,\"sha256\":\"6a1fd1fbaf6caa1c206844e8d97414ea231a1cba663ebb704d26cdff42417d56\",\"cap\":262144,\"expected_full9\":null,\"immutable_blob\":null},{\"index\":6,\"role\":\"stdout\",\"name\":\"service_native_pki_tests.rs\",\"relative\":\"service_native_pki_tests.rs.rustfmt.stdout\",\"path\":\"/home/qian-qi/heptabao-native-pki-lease400-format-20261106-r1/service_native_pki_tests.rs.rustfmt.stdout\",\"bytes\":42909,\"sha256\":\"6a1fd1fbaf6caa1c206844e8d97414ea231a1cba663ebb704d26cdff42417d56\",\"cap\":262144,\"expected_full9\":null,\"immutable_blob\":null},{\"index\":7,\"role\":\"stderr\",\"name\":\"service_native_pki_tests.rs\",\"relative\":\"service_native_pki_tests.rs.rustfmt.stderr\",\"path\":\"/home/qian-qi/heptabao-native-pki-lease400-format-20261106-r1/service_native_pki_tests.rs.rustfmt.stderr\",\"bytes\":0,\"sha256\":\"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855\",\"cap\":65536,\"expected_full9\":null,\"immutable_blob\":null},{\"index\":8,\"role\":\"config\",\"name\":\"rustfmt.toml\",\"relative\":\"rustfmt.toml\",\"path\":\"/home/qian-qi/heptabao-native-pki-lease400-format-20261106-r1/rustfmt.toml\",\"bytes\":17,\"sha256\":\"f32d2f03b3f4b1e295c79ed49d543f1205c7dac7c3dc74f05a5a27af4fea0584\",\"cap\":17,\"expected_full9\":[\"66306\",\"28071611\",\"1000\",\"1000\",\"33152\",\"1\",\"17\",\"1793944550719366866\",\"1793944550719366866\"],\"immutable_blob\":null},{\"index\":9,\"role\":\"receipt\",\"name\":\"result.public.json\",\"relative\":\"result.public.json\",\"path\":\"/home/qian-qi/heptabao-native-pki-lease400-format-20261106-r1/result.public.json\",\"bytes\":4907,\"sha256\":\"7b2560af593a62c7de4b8ca3a8cb7c2fffaed1408b2f1b356a302a38a7617776\",\"cap\":65536,\"expected_full9\":[\"66306\",\"28071628\",\"1000\",\"1000\",\"33152\",\"1\",\"4907\",\"1793944550782366173\",\"1793944550782366173\"],\"immutable_blob\":\"6638b8f22581832b5451d8b79e275feccec54959\"}]")
DIRECTORY_SPECS=(
 ("root",None,"/",0,0,None,True),
 ("home","root","home",0,0,None,True),
 ("user","home","qian-qi",1000,1000,None,True),
 ("input","user","heptabao-native-pki-lease400-format-20261106-r1",1000,1000,0o700,False),
 ("candidate","input","candidate",1000,1000,0o700,False),
 ("formatted","input","formatted",1000,1000,0o700,False),
)
IDENTITY_FIELDS=("dev","ino","uid","gid","full_mode","nlink","size","mtime_ns","ctime_ns")
PATCH_HEADER=re.compile(r"@@ -([0-9]+)(?:,([0-9]+))? \+([0-9]+)(?:,([0-9]+))? @@\n")

class Refused(Exception):
 pass

def must(value,code):
 if not value:
  raise Refused(code)

def sha(data):
 return hashlib.sha256(data).hexdigest()

def identity(s):
 return [str(x) for x in (s.st_dev,s.st_ino,s.st_uid,s.st_gid,s.st_mode,
                          s.st_nlink,s.st_size,s.st_mtime_ns,s.st_ctime_ns)]

def version(v):
 return ":".join((v[0],v[1],v[6],v[7],v[8]))

def require_invocation():
 a=sys.orig_argv
 must(len(a)==7 and a[0]=="/usr/bin/python3" and a[1:5]==["-I","-S","-B","-c"],
      "inline_invocation")
 must(sys.argv==["-c",a[6]] and re.fullmatch(r"[0-9a-f]{64}",a[6]) is not None,
      "inline_self_hash_argument")
 must(sha(a[5].encode("utf-8"))==a[6],"inline_self_hash")
 must(sys.flags.isolated==1 and sys.flags.no_site==1 and sys.dont_write_bytecode,
      "inline_isolation_flags")
 return a[6]

class Custody:
 def __init__(self):
  self.ledger=[]
  self.directories={}
  self.files=[]
  self.pending_signal=None
  self.handlers=[]
  self.handler_restore_errors=[]
  self.old_umask=None
  self.umask_restored=False
  self.metadata_calls=0
  self.read_calls=0
  self.read_bytes=0
  self.input_read_bytes=0
  self.report_read_bytes=0
  self.write_bytes=0
  self.fsync_calls=0
  self.peak_fds=0
  self.phase="entry"
  self.output_created=False
  self.report_created=False
  self.report_pin=None
  self.final_namespace=None

 def check(self):
  must(self.pending_signal is None,"signal_pending")
  must(time.monotonic()-START<LIMIT,"shared_deadline")

 def mark_signal(self,signum,frame):
  self.pending_signal=signum

 def install(self):
  for signum in (signal.SIGINT,signal.SIGTERM,signal.SIGHUP):
   record={"signal":signum,"before":signal.getsignal(signum),"installed":False,"restored":False}
   self.handlers.append(record)
   signal.signal(signum,self.mark_signal)
   record["installed"]=True
  self.old_umask=os.umask(0o077)

 def restore(self):
  if self.old_umask is not None:
   try:
    os.umask(self.old_umask)
    self.umask_restored=True
   except BaseException as e:
    self.handler_restore_errors.append({"resource":"umask","type":type(e).__name__})
  for record in reversed(self.handlers):
   if record["installed"]:
    try:
     signal.signal(record["signal"],record["before"])
     record["restored"]=True
    except BaseException as e:
     self.handler_restore_errors.append({"resource":"signal","signal":record["signal"],"type":type(e).__name__})

 def metadata(self,fn,*args,**kwargs):
  self.check()
  must(self.metadata_calls<META_CAP,"metadata_cap")
  self.metadata_calls+=1
  value=fn(*args,**kwargs)
  self.check()
  return value

 def acquire(self,label,kind,parent,name,flags,mode=None):
  self.check()
  must(len(self.ledger)<FD_CAP,"fd_acquisition_cap")
  must(sum(1 for x in self.ledger if x["fd"] is not None and not x["close_attempted"])<PEAK_FD_CAP,
       "peak_fd_cap")
  record={"label":label,"kind":kind,"fd":None,"close_attempted":False,
          "closed":False,"close_error":None}
  self.ledger.append(record)
  kwargs={} if parent is None else {"dir_fd":parent}
  if mode is None:
   record["fd"]=os.open(name,flags,**kwargs)
  else:
   record["fd"]=os.open(name,flags,mode,**kwargs)
  self.peak_fds=max(self.peak_fds,sum(1 for x in self.ledger
                         if x["fd"] is not None and not x["close_attempted"]))
  self.check()
  return record

 def close_once(self,record):
  if record["fd"] is None or record["close_attempted"]:
   return
  record["close_attempted"]=True
  try:
   os.close(record["fd"])
   record["closed"]=True
  except BaseException as e:
   record["close_error"]=type(e).__name__

 def close_all(self):
  for record in reversed(self.ledger):
   self.close_once(record)

 def all_closed(self):
  return all(x["fd"] is None or (x["close_attempted"] and x["closed"]
                                 and x["close_error"] is None) for x in self.ledger)

 def read(self,fd,count,kind):
  self.check()
  must(0<count<=READ_CHUNK and self.read_calls<READ_CALL_CAP,"read_call_bound")
  must(count<=READ_CAP-self.read_bytes,"shared_read_byte_cap")
  self.read_calls+=1
  data=os.read(fd,count)
  self.read_bytes+=len(data)
  if kind=="input":
   self.input_read_bytes+=len(data)
  else:
   must(kind=="report","read_kind")
   self.report_read_bytes+=len(data)
  self.check()
  return data

 def write_report(self,fd,data):
  must(len(data)<=REPORT_CAP,"report_write_cap")
  offset=0
  while offset<len(data):
   self.check()
   count=os.write(fd,data[offset:offset+READ_CHUNK])
   must(count>0,"report_short_write")
   offset+=count
   self.write_bytes+=count
   must(self.write_bytes<=REPORT_CAP,"report_write_cap")
   self.check()

 def sync(self,fd):
  self.check()
  must(self.fsync_calls<4,"fsync_cap")
  self.fsync_calls+=1
  os.fsync(fd)
  self.check()

 def ledger_public(self):
  return [{"label":x["label"],"kind":x["kind"],"acquired":x["fd"] is not None,
           "close_attempted":x["close_attempted"],"closed":x["closed"],
           "close_error":x["close_error"]} for x in self.ledger]

 def counters(self):
  return {"metadata_calls":self.metadata_calls,"read_calls":self.read_calls,
          "read_bytes":self.read_bytes,"input_read_bytes":self.input_read_bytes,
          "report_read_bytes":self.report_read_bytes,"write_bytes":self.write_bytes,
          "fsync_calls":self.fsync_calls,"fd_acquisition_attempts":len(self.ledger),
          "fd_acquisitions":sum(x["fd"] is not None for x in self.ledger),
          "peak_owned_fds":self.peak_fds}

def named_stat(c,parent,name):
 if parent is None:
  return c.metadata(os.stat,name,follow_symlinks=False)
 return c.metadata(os.stat,name,dir_fd=parent,follow_symlinks=False)

def directory_pair(c,record):
 held=c.metadata(os.fstat,record["entry"]["fd"])
 named=named_stat(c,record["parent_fd"],record["name"])
 a,b=identity(held),identity(named)
 if record["shared"]:
  must(a[:5]==b[:5]==record["before"][:5],"shared_directory_identity_changed")
 else:
  must(a==b==record["before"],"owned_input_directory_identity_changed")
 return {"held":a,"named":b}

def open_directories(c):
 for label,parent_label,name,uid,gid,mode,shared in DIRECTORY_SPECS:
  parent=None if parent_label is None else c.directories[parent_label]["entry"]["fd"]
  entry=c.acquire("dir-"+label,"input-directory",parent,name,
       os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC|os.O_NONBLOCK)
  held=c.metadata(os.fstat,entry["fd"])
  named=named_stat(c,parent,name)
  a,b=identity(held),identity(named)
  must(stat.S_ISDIR(held.st_mode) and stat.S_ISDIR(named.st_mode),"directory_type")
  must(held.st_uid==uid and held.st_gid==gid and held.st_mode & 0o022==0,
       "directory_owner_or_write_mode")
  if mode is not None:
   must(stat.S_IMODE(held.st_mode)==mode,"owned_directory_mode")
  must(a[:5]==b[:5] if shared else a==b,"directory_named_held_mismatch")
  c.directories[label]={"label":label,"parent_fd":parent,"name":name,"entry":entry,
                        "shared":shared,"before":a,"named_before":b}

def file_parent(c,row):
 relative=row["relative"]
 if row["role"] in ("candidate","formatted"):
  expected=row["role"]+"/"+row["name"]
  must(relative==expected,"file_relative_role")
  return c.directories[row["role"]]["entry"]["fd"],row["name"]
 must("/" not in relative,"flat_input_name")
 return c.directories["input"]["entry"]["fd"],relative

def open_inputs(c):
 must(len(ROWS)==10 and [r["index"] for r in ROWS]==list(range(10)),"fixed_rows")
 must(len({r["path"] for r in ROWS})==10,"unique_fixed_paths")
 must(sum(r["cap"] for r in ROWS)==READ_CAP and sum(r["bytes"] for r in ROWS)==543621,
      "original_fixed_read_caps")
 for row in ROWS:
  must(row["path"]==INPUT_ROOT+"/"+row["relative"] and ".." not in row["relative"].split("/"),
       "fixed_input_root")
  must(0<=row["bytes"]<=row["cap"] and re.fullmatch("[0-9a-f]{64}",row["sha256"]),
       "fixed_size_hash")
  parent,name=file_parent(c,row)
  entry=c.acquire("input-"+str(row["index"]).zfill(2),"input-file",parent,name,
         os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC|os.O_NONBLOCK)
  held=c.metadata(os.fstat,entry["fd"])
  named=named_stat(c,parent,name)
  a,b=identity(held),identity(named)
  must(stat.S_ISREG(held.st_mode) and held.st_uid==1000 and held.st_gid==1000
       and held.st_nlink==1 and held.st_mode==(stat.S_IFREG|0o600),"input_file_custody")
  must(a==b and held.st_size==row["bytes"],"input_size_or_named_identity")
  if row["expected_full9"] is not None:
   must(a==row["expected_full9"],"prior_full9_mismatch")
  c.files.append({"row":row,"entry":entry,"parent_fd":parent,"name":name,
                  "before":a,"named_before":b,"read_after":None,"final_after":None,
                  "eof":False,"read_bytes":0,"read_calls":0})

def input_pair(c,record):
 held=c.metadata(os.fstat,record["entry"]["fd"])
 named=named_stat(c,record["parent_fd"],record["name"])
 a,b=identity(held),identity(named)
 must(a==b==record["before"],"input_full9_changed")
 return {"held":a,"named":b}

def read_exact(c,fd,expected,kind):
 data=bytearray()
 while True:
  remaining=expected-len(data)
  part=c.read(fd,min(READ_CHUNK,remaining+1),kind)
  if not part:
   break
  data.extend(part)
  must(len(data)<=expected,"read_grew_beyond_expected")
 must(len(data)==expected,"read_short")
 return bytes(data)

def read_inputs(c):
 data={}
 for record in c.files:
  row=record["row"]
  before_calls=c.read_calls
  before_bytes=c.read_bytes
  value=read_exact(c,record["entry"]["fd"],row["bytes"],"input")
  record["read_calls"]=c.read_calls-before_calls
  record["read_bytes"]=c.read_bytes-before_bytes
  record["eof"]=True
  record["read_after"]=input_pair(c,record)
  c.check()
  must(sha(value)==row["sha256"],"input_whole_sha256")
  data[row["relative"]]=value
  c.check()
 must(len(data)==10 and c.input_read_bytes==543621,"whole_input_accounting")
 return data

def lf_lines(text):
 must(text=="" or text.endswith("\n"),"strict_diff_requires_final_lf")
 if not text:
  return []
 return [x+"\n" for x in text[:-1].split("\n")]

def strict_apply(c,base,patch,name,reverse=False):
 original=lf_lines(base)
 if patch=="":
  return base
 lines=lf_lines(patch)
 must(len(lines)>=3 and lines[0]=="--- a/"+name+"\n" and lines[1]=="+++ b/"+name+"\n",
      "strict_diff_file_headers")
 out=[]
 cursor=0
 pos=2
 hunks=0
 while pos<len(lines):
  c.check()
  match=PATCH_HEADER.fullmatch(lines[pos])
  must(match is not None,"strict_diff_hunk_header")
  must(all(x is None or len(x)<=9 for x in match.groups()),"strict_diff_hunk_integer")
  old_start=int(match.group(1));old_count=1 if match.group(2) is None else int(match.group(2))
  new_start=int(match.group(3));new_count=1 if match.group(4) is None else int(match.group(4))
  if reverse:
   old_start,new_start=new_start,old_start
   old_count,new_count=new_count,old_count
  must((old_count==0 or old_start>=1) and (new_count==0 or new_start>=1),
       "strict_diff_hunk_start")
  old_at=old_start if old_count==0 else old_start-1
  new_at=new_start if new_count==0 else new_start-1
  must(cursor<=old_at<=len(original) and old_count<=len(original)-old_at,
       "strict_diff_order_or_range")
  out.extend(original[cursor:old_at])
  cursor=old_at
  must(len(out)==new_at,"strict_diff_new_offset")
  pos+=1
  used_old=0
  used_new=0
  while pos<len(lines) and not lines[pos].startswith("@@ "):
   c.check()
   line=lines[pos]
   must(line[0] in (" ","+","-"),"strict_diff_line_kind")
   tag=line[0];body=line[1:]
   if reverse:
    tag="+" if tag=="-" else "-" if tag=="+" else tag
   if tag in (" ","-"):
    must(cursor<len(original) and original[cursor]==body,"strict_diff_context")
    cursor+=1
    used_old+=1
   if tag in (" ","+"):
    out.append(body)
    used_new+=1
   must(used_old<=old_count and used_new<=new_count,"strict_diff_hunk_overflow")
   pos+=1
  must(used_old==old_count and used_new==new_count,"strict_diff_hunk_count")
  hunks+=1
 must(hunks>0,"strict_diff_empty_hunk_set")
 out.extend(original[cursor:])
 c.check()
 return "".join(out)

def validate_receipt(data):
 receipt=json.loads(data["result.public.json"].decode("utf-8"))
 must(receipt["schema"]=="heptabao.native-pki-lease-status-input-rustfmt.v1"
      and receipt["sourceCommit"]==SOURCE_COMMIT and receipt["sourceTree"]==SOURCE_TREE,
      "formatter_receipt_source")
 must(receipt["status"]=="passed" and receipt["allOwnedStopped"] is True
      and receipt["withinDeadline"] is True,
      "formatter_receipt_known_terminal")
 must(receipt["sourceIdentityIsBaseOnly"] is True
      and receipt["uncommittedCandidateInputs"] is True
      and receipt["inputCarrierSha256"]==INPUT_CARRIER_SHA256
      and receipt["inputOriginalAndCandidatePins"]==INPUT_ORIGINAL_AND_CANDIDATE_PINS,
      "formatter_exact_supplied_candidate_provenance")
 must(receipt["compileExecuted"] is False and receipt["productExecuted"] is False
      and receipt["productionChanged"] is False,"formatter_receipt_scope")
 must(receipt["internalSeconds"]==50 and receipt["newRemoteSupervisorSeconds"]==60,
      "formatter_receipt_deadlines")
 must(len(receipt["children"])==2 and all(
      x["exitCode"]==0 and x["reaped"] is True and x["stopped"] is True
      and x["newProcessGroupCreated"] is False and x["pgid"]==x["supervisorGroup"]
      for x in receipt["children"]),"formatter_direct_children")
 expected=[]
 for i in range(2):
  a,b,o,e=ROWS[4*i:4*i+4]
  expected.append({"name":a["name"],"beforeSha256":a["sha256"],"beforeBytes":a["bytes"],
                   "afterSha256":b["sha256"],"afterBytes":b["bytes"],
                   "stderrBytes":e["bytes"],"stderrSha256":e["sha256"]})
 must(receipt["files"]==expected,"formatter_receipt_exact_files")
 return {"source_commit":SOURCE_COMMIT,"source_tree":SOURCE_TREE,"job_id":FORMATTER_JOB,
         "source_identity_is_base_only":True,"uncommitted_candidate_inputs":True,
         "candidate_source_packet":CANDIDATE_SOURCE_PACKET,
         "receipt_blob":RECEIPT_BLOB,"receipt_sha256":sha(data["result.public.json"]),
         "direct_children_reaped":2,"same_supervisor_pgid":True,
         "independent_group_empty_observed":False,"compile_executed":False}

def make_diffs(c,data):
 result=[]
 total=0
 changed=0
 for i in range(2):
  a,b,o,e=ROWS[4*i:4*i+4]
  c.check()
  must([x["role"] for x in (a,b,o,e)]==["candidate","formatted","stdout","stderr"]
       and len({x["name"] for x in (a,b,o,e)})==1,"fixed_quartet")
  before=data[a["relative"]]
  after=data[b["relative"]]
  must(data[o["relative"]]==after and data[e["relative"]]==b"","stdout_or_stderr")
  before_text=before.decode("utf-8");after_text=after.decode("utf-8")
  patch_parts=[]
  patch_bytes=0
  for line in difflib.unified_diff(lf_lines(before_text),lf_lines(after_text),
          fromfile="a/"+a["name"],tofile="b/"+a["name"],n=3,lineterm="\n"):
   c.check()
   patch_bytes+=len(line.encode("utf-8"))
   must(total+patch_bytes<=DIFF_CAP,"strict_diff_byte_cap")
   patch_parts.append(line)
  patch="".join(patch_parts)
  total+=patch_bytes
  rebuilt=strict_apply(c,before_text,patch,a["name"]).encode("utf-8")
  restored=strict_apply(c,after_text,patch,a["name"],reverse=True).encode("utf-8")
  must(rebuilt==after and restored==before,"strict_diff_bidirectional_bytes")
  must(sha(rebuilt)==b["sha256"] and sha(restored)==a["sha256"],
       "strict_diff_bidirectional_hashes")
  is_changed=before!=after
  must(bool(patch)==is_changed,"strict_diff_changed_flag")
  changed+=is_changed
  result.append({"name":a["name"],"immutable_candidate_blob":a["immutable_blob"],
      "before_bytes":len(before),"before_sha256":sha(before),
      "after_bytes":len(after),"after_sha256":sha(after),
      "stdout_byte_equal":True,"stderr_empty":True,"changed":is_changed,
      "unified_diff":patch,"diff_bytes":patch_bytes,"diff_sha256":sha(patch.encode("utf-8")),
      "strict_forward_equal":True,"strict_reverse_equal":True})
 must(changed==1 and len(result)-changed==1,"formatter_changed_count")
 must(data["rustfmt.toml"]==CONFIG_BYTES,"fixed_configuration_bytes")
 return result,total

def recheck_inputs_and_close(c):
 for record in c.files:
  record["final_after"]=input_pair(c,record)
 directory_after={label:directory_pair(c,r) for label,r in c.directories.items()}
 for record in reversed(c.files):
  c.close_once(record["entry"])
 must(len(c.files)==10 and all(r["entry"]["closed"] and r["entry"]["close_error"] is None
                               for r in c.files),"input_once_close")
 c.check()
 return directory_after

def public_input_records(c):
 return [{"index":r["row"]["index"],"role":r["row"]["role"],"name":r["row"]["name"],
          "path":r["row"]["path"],"bytes":r["row"]["bytes"],"sha256":r["row"]["sha256"],
          "original_file_cap":r["row"]["cap"],"prior_full9":r["row"]["expected_full9"],
          "immutable_blob":r["row"]["immutable_blob"],"before_full9":r["before"],
          "named_before_full9":r["named_before"],"read_after":r["read_after"],
          "final_after":r["final_after"],"version":version(r["before"]),
          "eof":r["eof"],"read_calls":r["read_calls"],"read_bytes":r["read_bytes"],
          "once_close_attempted":r["entry"]["close_attempted"],
          "once_close_completed":r["entry"]["closed"],
          "close_error":r["entry"]["close_error"]} for r in c.files]

def publish_report(c,report):
 c.phase="publish_report"
 c.check()
 raw=(json.dumps(report,sort_keys=True,indent=2,ensure_ascii=False)+"\n").encode("utf-8")
 must(len(raw)<=REPORT_CAP,"serialized_report_cap")
 parent=c.directories["user"]["entry"]["fd"]
 try:
  named_stat(c,parent,OUTPUT_NAME)
 except FileNotFoundError:
  pass
 else:
  raise Refused("output_root_already_exists")
 c.check()
 os.mkdir(OUTPUT_NAME,0o700,dir_fd=parent)
 c.output_created=True
 c.check()
 c.sync(parent)
 outdir=c.acquire("output-directory","output-directory",parent,OUTPUT_NAME,
        os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC|os.O_NONBLOCK)
 held=c.metadata(os.fstat,outdir["fd"]);named=named_stat(c,parent,OUTPUT_NAME)
 before=identity(held)
 must(before==identity(named) and stat.S_ISDIR(held.st_mode)
      and held.st_uid==1000 and held.st_gid==1000 and stat.S_IMODE(held.st_mode)==0o700,
      "output_directory_custody")
 out=c.acquire("output-report","output-file",outdir["fd"],REPORT_NAME,
        os.O_RDWR|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC|os.O_NONBLOCK,0o600)
 c.report_created=True
 c.write_report(out["fd"],raw)
 c.sync(out["fd"])
 held=c.metadata(os.fstat,out["fd"]);named=named_stat(c,outdir["fd"],REPORT_NAME)
 file_before=identity(held)
 must(file_before==identity(named) and stat.S_ISREG(held.st_mode)
      and held.st_mode==(stat.S_IFREG|0o600) and held.st_uid==1000 and held.st_gid==1000
      and held.st_nlink==1 and held.st_size==len(raw),"report_written_identity")
 c.check()
 must(os.lseek(out["fd"],0,os.SEEK_SET)==0,"report_seek")
 observed=read_exact(c,out["fd"],len(raw),"report")
 must(observed==raw and sha(observed)==sha(raw),"report_same_fd_readback")
 file_after=identity(c.metadata(os.fstat,out["fd"]))
 named_after=identity(named_stat(c,outdir["fd"],REPORT_NAME))
 must(file_after==named_after==file_before,"report_readback_full9")
 c.sync(outdir["fd"])
 out_after=identity(c.metadata(os.fstat,outdir["fd"]))
 out_named_after=identity(named_stat(c,parent,OUTPUT_NAME))
 must(out_after==out_named_after and out_after[:5]==before[:5],
      "output_directory_final_identity")
 c.final_namespace={label:directory_pair(c,r) for label,r in c.directories.items()}
 c.report_pin={"path":OUTPUT_ROOT+"/"+REPORT_NAME,"bytes":len(raw),"sha256":sha(raw),
               "full9":file_after,"version":version(file_after),
               "same_fd_readback":True,"eof":True,
               "directory_full9_after":out_after}
 c.check()

def main():
 c=Custody()
 error=None
 success=False
 self_sha=None
 try:
  self_sha=require_invocation()
  c.install()
  c.check()
  c.phase="open_fixed_directories"
  open_directories(c)
  c.phase="open_fixed_inputs"
  open_inputs(c)
  c.phase="read_fixed_inputs"
  data=read_inputs(c)
  receipt=validate_receipt(data)
  c.phase="strict_bidirectional_diffs"
  diffs,diff_bytes=make_diffs(c,data)
  c.phase="recheck_and_close_inputs"
  directory_after=recheck_inputs_and_close(c)
  report={"schema":"heptabao.native-pki-formatter10-observation.v1",
    "input_observation_complete":True,"collector_source_sha256":self_sha,
    "source_commit":SOURCE_COMMIT,"source_tree":SOURCE_TREE,
    "source_identity_is_base_only":True,"uncommitted_candidate_inputs":True,
    "candidate_source_packet":CANDIDATE_SOURCE_PACKET,
    "formatter_source_blob":FORMATTER_SOURCE_BLOB,"formatter_receipt":receipt,
    "input_root":INPUT_ROOT,"output_root":OUTPUT_ROOT,
    "identity_fields":IDENTITY_FIELDS,"identity_numbers":"decimal strings",
    "input_count":10,"input_bytes":543621,"original_read_cap":READ_CAP,
    "input_files":public_input_records(c),
    "directories_before":{k:{"full9":r["before"],"shared_identity_only":r["shared"]}
                           for k,r in c.directories.items()},
    "directories_after_inputs":directory_after,
    "diffs":diffs,"diff_total_bytes":diff_bytes,
    "source_bytes":179535,"formatted_bytes":179581,"changed_files":1,"unchanged_files":1,
    "configuration_utf8":CONFIG_BYTES.decode("utf-8"),
    "reconstruction":{"candidates":"two exact immutable PKI candidate blobs supplied in candidate_source_packet; not base-tree leaves",
       "formatted":"strict bidirectional unified diffs against those candidate bytes",
       "stdout":"byte equal to corresponding actual formatted file",
       "stderr":"two empty byte strings",
       "config":"configuration_utf8 encoded as UTF-8",
       "receipt":"exact already archived receipt blob "+RECEIPT_BLOB},
    "counters_before_publication":c.counters(),
    "limits":{"shared_seconds":50,"outer_seconds":60,"read_bytes":READ_CAP,
       "per_read_bytes":READ_CHUNK,"read_calls":READ_CALL_CAP,"metadata_calls":META_CAP,
       "fd_acquisitions":FD_CAP,"peak_owned_fds":PEAK_FD_CAP,"diff_bytes":DIFF_CAP,
       "report_bytes":REPORT_CAP,"stdout_bytes":STDOUT_CAP},
    "all_10_input_fds_once_closed":True,
    "input_observations_are_sequential":True,
    "input_fds_closed_before_report_publication":True,
    "output_and_directory_fd_closure_requires_final_stdout_and_authority":True,
    "elapsed_seconds_before_publication":time.monotonic()-START,
    "child_count":0,"network_calls":0,"directory_listings":0,
    "original_input_writes":0,"product_executed":False,"cargo_executed":False}
  publish_report(c,report)
  success=True
 except BaseException as e:
  error={"type":type(e).__name__,"code":str(e) if isinstance(e,Refused) else None,
         "errno":e.errno if isinstance(e,OSError) else None,"phase":c.phase}
 finally:
  c.close_all()
  c.restore()
 elapsed=time.monotonic()-START
 all_closed=c.all_closed()
 handlers_restored=all(not x["installed"] or x["restored"] for x in c.handlers) and not c.handler_restore_errors
 success=(success and error is None and c.pending_signal is None and elapsed<LIMIT
          and all_closed and handlers_restored and c.umask_restored
          and len(c.ledger)==18 and all(x["fd"] is not None for x in c.ledger)
          and c.report_pin is not None and c.input_read_bytes==543621)
 summary={"schema":"heptabao.native-pki-formatter10-terminal.v1",
   "status":"passed" if success else "failed","error":error,
   "collector_source_sha256":self_sha,"input_count":len(c.files),
   "report":c.report_pin,"output_root_created":c.output_created,"report_created":c.report_created,
   "all_owned_fds_once_closed":all_closed,"handlers_restored":handlers_restored,
   "umask_restored":c.umask_restored,"handler_restore_errors":c.handler_restore_errors,
   "fd_ledger":c.ledger_public(),"counters":c.counters(),
   "pending_signal":c.pending_signal,"elapsed_seconds":elapsed,"within_deadline":elapsed<LIMIT,
   "child_count":0,"network_calls":0,"directory_listings":0,"original_input_writes":0,
   "product_executed":False,"cargo_executed":False,
   "input_namespace_final":c.final_namespace}
 output=json.dumps(summary,sort_keys=True,separators=(",",":"))+"\n"
 must(len(output.encode("utf-8"))<=STDOUT_CAP,"terminal_stdout_cap")
 sys.stdout.write(output)
 sys.stdout.flush()
 return 0 if success and time.monotonic()-START<LIMIT else 1

if __name__=="__main__":
 sys.exit(main())
