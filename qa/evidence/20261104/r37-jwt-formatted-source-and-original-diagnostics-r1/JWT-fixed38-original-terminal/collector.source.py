"""Fixed public formatter-output collector. SOURCE proposal; separate root GO required.
Reads exactly 38 public files, then writes one new observation report. No child/network.
The report proves input observations; final stdout plus authoritative exit proves cleanup.
"""
import difflib,hashlib,json,os,re,signal,stat,sys,time

START=time.monotonic()
LIMIT=50.0
INPUT_ROOT="/home/qian-qi/heptabao-native-jwt-e3afc157-format-20261106-r1"
OUTPUT_NAME="heptabao-native-jwt-e3afc157-format-observe-20261106-r1"
OUTPUT_ROOT="/home/qian-qi/"+OUTPUT_NAME
REPORT_NAME="observation.public.json"
SOURCE_COMMIT="e3afc157447d35c861f275a761b29da3e42aff8e"
SOURCE_TREE="5497775d9d473541e13e1603be8c893a3e27681b"
FORMATTER_JOB="1a1af017fae-fc05-64f1"
FORMATTER_SOURCE_BLOB="1266e75033bee0962b0d77d3c35ee19ec53086db"
RECEIPT_BLOB="58827993343d76b96fc92b0bae47432710ffbedd"
READ_CAP=7906155
READ_CHUNK=65536
READ_CALL_CAP=256
META_CAP=320
FD_CAP=46
PEAK_FD_CAP=44
DIFF_CAP=786432
REPORT_CAP=1048576
STDOUT_CAP=16384
CONFIG_BYTES=b'edition = "2024"\n'
ROWS=json.loads("[{\"index\":0,\"role\":\"candidate\",\"name\":\"auth.rs\",\"relative\":\"candidate/auth.rs\",\"path\":\"/home/qian-qi/heptabao-native-jwt-e3afc157-format-20261106-r1/candidate/auth.rs\",\"bytes\":397709,\"sha256\":\"6fe0c3a8af3af126be3217143c85519e9b6d9abf7fcbc33f08e6b553ba5a7c97\",\"cap\":397709,\"expected_full9\":null,\"canonical_blob\":\"19646b7848e5588d72f5514400d607696549611d\"},{\"index\":1,\"role\":\"formatted\",\"name\":\"auth.rs\",\"relative\":\"formatted/auth.rs\",\"path\":\"/home/qian-qi/heptabao-native-jwt-e3afc157-format-20261106-r1/formatted/auth.rs\",\"bytes\":398266,\"sha256\":\"9f366e631019e55aca61717a324bf13c1995797ed088b5b9d8b80c4a11914f7f\",\"cap\":524288,\"expected_full9\":null,\"canonical_blob\":null},{\"index\":2,\"role\":\"stdout\",\"name\":\"auth.rs\",\"relative\":\"auth.rs.rustfmt.stdout\",\"path\":\"/home/qian-qi/heptabao-native-jwt-e3afc157-format-20261106-r1/auth.rs.rustfmt.stdout\",\"bytes\":398266,\"sha256\":\"9f366e631019e55aca61717a324bf13c1995797ed088b5b9d8b80c4a11914f7f\",\"cap\":524288,\"expected_full9\":null,\"canonical_blob\":null},{\"index\":3,\"role\":\"stderr\",\"name\":\"auth.rs\",\"relative\":\"auth.rs.rustfmt.stderr\",\"path\":\"/home/qian-qi/heptabao-native-jwt-e3afc157-format-20261106-r1/auth.rs.rustfmt.stderr\",\"bytes\":0,\"sha256\":\"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855\",\"cap\":65536,\"expected_full9\":null,\"canonical_blob\":null},{\"index\":4,\"role\":\"candidate\",\"name\":\"auth_native_jwt.rs\",\"relative\":\"candidate/auth_native_jwt.rs\",\"path\":\"/home/qian-qi/heptabao-native-jwt-e3afc157-format-20261106-r1/candidate/auth_native_jwt.rs\",\"bytes\":17391,\"sha256\":\"d28cc6af7a1ef30fecb704ac9d3917a2c54ad8d6f8ac1cb77e6f75eca9de5042\",\"cap\":17391,\"expected_full9\":null,\"canonical_blob\":\"2e76f906edefb92406328459fd6c5711dfa7ad2b\"},{\"index\":5,\"role\":\"formatted\",\"name\":\"auth_native_jwt.rs\",\"relative\":\"formatted/auth_native_jwt.rs\",\"path\":\"/home/qian-qi/heptabao-native-jwt-e3afc157-format-20261106-r1/formatted/auth_native_jwt.rs\",\"bytes\":18771,\"sha256\":\"ca4325e8c853816855a332b85e1ae87fe24ccecdea375c3422cd25451fc49641\",\"cap\":262144,\"expected_full9\":null,\"canonical_blob\":null},{\"index\":6,\"role\":\"stdout\",\"name\":\"auth_native_jwt.rs\",\"relative\":\"auth_native_jwt.rs.rustfmt.stdout\",\"path\":\"/home/qian-qi/heptabao-native-jwt-e3afc157-format-20261106-r1/auth_native_jwt.rs.rustfmt.stdout\",\"bytes\":18771,\"sha256\":\"ca4325e8c853816855a332b85e1ae87fe24ccecdea375c3422cd25451fc49641\",\"cap\":262144,\"expected_full9\":null,\"canonical_blob\":null},{\"index\":7,\"role\":\"stderr\",\"name\":\"auth_native_jwt.rs\",\"relative\":\"auth_native_jwt.rs.rustfmt.stderr\",\"path\":\"/home/qian-qi/heptabao-native-jwt-e3afc157-format-20261106-r1/auth_native_jwt.rs.rustfmt.stderr\",\"bytes\":0,\"sha256\":\"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855\",\"cap\":65536,\"expected_full9\":null,\"canonical_blob\":null},{\"index\":8,\"role\":\"candidate\",\"name\":\"auth_native_v6_routes.rs\",\"relative\":\"candidate/auth_native_v6_routes.rs\",\"path\":\"/home/qian-qi/heptabao-native-jwt-e3afc157-format-20261106-r1/candidate/auth_native_v6_routes.rs\",\"bytes\":21959,\"sha256\":\"9114c08a472dfde56837f6bbccf565e471ee2b5286980efb906c3121c71d1761\",\"cap\":21959,\"expected_full9\":null,\"canonical_blob\":\"6bb16ad15f43d0ca908438b4fb26d44d625f476b\"},{\"index\":9,\"role\":\"formatted\",\"name\":\"auth_native_v6_routes.rs\",\"relative\":\"formatted/auth_native_v6_routes.rs\",\"path\":\"/home/qian-qi/heptabao-native-jwt-e3afc157-format-20261106-r1/formatted/auth_native_v6_routes.rs\",\"bytes\":21959,\"sha256\":\"9114c08a472dfde56837f6bbccf565e471ee2b5286980efb906c3121c71d1761\",\"cap\":262144,\"expected_full9\":null,\"canonical_blob\":null},{\"index\":10,\"role\":\"stdout\",\"name\":\"auth_native_v6_routes.rs\",\"relative\":\"auth_native_v6_routes.rs.rustfmt.stdout\",\"path\":\"/home/qian-qi/heptabao-native-jwt-e3afc157-format-20261106-r1/auth_native_v6_routes.rs.rustfmt.stdout\",\"bytes\":21959,\"sha256\":\"9114c08a472dfde56837f6bbccf565e471ee2b5286980efb906c3121c71d1761\",\"cap\":262144,\"expected_full9\":null,\"canonical_blob\":null},{\"index\":11,\"role\":\"stderr\",\"name\":\"auth_native_v6_routes.rs\",\"relative\":\"auth_native_v6_routes.rs.rustfmt.stderr\",\"path\":\"/home/qian-qi/heptabao-native-jwt-e3afc157-format-20261106-r1/auth_native_v6_routes.rs.rustfmt.stderr\",\"bytes\":0,\"sha256\":\"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855\",\"cap\":65536,\"expected_full9\":null,\"canonical_blob\":null},{\"index\":12,\"role\":\"candidate\",\"name\":\"federated_auth.rs\",\"relative\":\"candidate/federated_auth.rs\",\"path\":\"/home/qian-qi/heptabao-native-jwt-e3afc157-format-20261106-r1/candidate/federated_auth.rs\",\"bytes\":56677,\"sha256\":\"8ac92cf16e18ceccb479322103228142fea413f6ce7ecbcfd9e908ed07bd1cdb\",\"cap\":56677,\"expected_full9\":null,\"canonical_blob\":\"21c48f7d50d30076d1aae82d51ce2b782a9739dc\"},{\"index\":13,\"role\":\"formatted\",\"name\":\"federated_auth.rs\",\"relative\":\"formatted/federated_auth.rs\",\"path\":\"/home/qian-qi/heptabao-native-jwt-e3afc157-format-20261106-r1/formatted/federated_auth.rs\",\"bytes\":56677,\"sha256\":\"8ac92cf16e18ceccb479322103228142fea413f6ce7ecbcfd9e908ed07bd1cdb\",\"cap\":262144,\"expected_full9\":null,\"canonical_blob\":null},{\"index\":14,\"role\":\"stdout\",\"name\":\"federated_auth.rs\",\"relative\":\"federated_auth.rs.rustfmt.stdout\",\"path\":\"/home/qian-qi/heptabao-native-jwt-e3afc157-format-20261106-r1/federated_auth.rs.rustfmt.stdout\",\"bytes\":56677,\"sha256\":\"8ac92cf16e18ceccb479322103228142fea413f6ce7ecbcfd9e908ed07bd1cdb\",\"cap\":262144,\"expected_full9\":null,\"canonical_blob\":null},{\"index\":15,\"role\":\"stderr\",\"name\":\"federated_auth.rs\",\"relative\":\"federated_auth.rs.rustfmt.stderr\",\"path\":\"/home/qian-qi/heptabao-native-jwt-e3afc157-format-20261106-r1/federated_auth.rs.rustfmt.stderr\",\"bytes\":0,\"sha256\":\"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855\",\"cap\":65536,\"expected_full9\":null,\"canonical_blob\":null},{\"index\":16,\"role\":\"candidate\",\"name\":\"federated_native_jwt.rs\",\"relative\":\"candidate/federated_native_jwt.rs\",\"path\":\"/home/qian-qi/heptabao-native-jwt-e3afc157-format-20261106-r1/candidate/federated_native_jwt.rs\",\"bytes\":7709,\"sha256\":\"255ec883fbb055fdfaea3d8f771fb723a4bb5b524d87f846dcc197dd5e46e92e\",\"cap\":7709,\"expected_full9\":null,\"canonical_blob\":\"0b4f4b18be19951e6744e1202f2fb1561351add2\"},{\"index\":17,\"role\":\"formatted\",\"name\":\"federated_native_jwt.rs\",\"relative\":\"formatted/federated_native_jwt.rs\",\"path\":\"/home/qian-qi/heptabao-native-jwt-e3afc157-format-20261106-r1/formatted/federated_native_jwt.rs\",\"bytes\":7772,\"sha256\":\"beed7767f9d0784fc023af725e38b4390fe9df7a68c5639e087f6f493dfe9547\",\"cap\":262144,\"expected_full9\":null,\"canonical_blob\":null},{\"index\":18,\"role\":\"stdout\",\"name\":\"federated_native_jwt.rs\",\"relative\":\"federated_native_jwt.rs.rustfmt.stdout\",\"path\":\"/home/qian-qi/heptabao-native-jwt-e3afc157-format-20261106-r1/federated_native_jwt.rs.rustfmt.stdout\",\"bytes\":7772,\"sha256\":\"beed7767f9d0784fc023af725e38b4390fe9df7a68c5639e087f6f493dfe9547\",\"cap\":262144,\"expected_full9\":null,\"canonical_blob\":null},{\"index\":19,\"role\":\"stderr\",\"name\":\"federated_native_jwt.rs\",\"relative\":\"federated_native_jwt.rs.rustfmt.stderr\",\"path\":\"/home/qian-qi/heptabao-native-jwt-e3afc157-format-20261106-r1/federated_native_jwt.rs.rustfmt.stderr\",\"bytes\":0,\"sha256\":\"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855\",\"cap\":65536,\"expected_full9\":null,\"canonical_blob\":null},{\"index\":20,\"role\":\"candidate\",\"name\":\"service.rs\",\"relative\":\"candidate/service.rs\",\"path\":\"/home/qian-qi/heptabao-native-jwt-e3afc157-format-20261106-r1/candidate/service.rs\",\"bytes\":519054,\"sha256\":\"5953adcb817a2210cc2b5266ec145632e7a263d39b7c61b2811e4c9d1ece289a\",\"cap\":519054,\"expected_full9\":null,\"canonical_blob\":\"c75adfe47637c5b2b559e515a754521e93238445\"},{\"index\":21,\"role\":\"formatted\",\"name\":\"service.rs\",\"relative\":\"formatted/service.rs\",\"path\":\"/home/qian-qi/heptabao-native-jwt-e3afc157-format-20261106-r1/formatted/service.rs\",\"bytes\":519132,\"sha256\":\"6df7278a7b90363fe25a563e10e29db35f47868a2d1d1ea225c91c1b9b6add7d\",\"cap\":655360,\"expected_full9\":null,\"canonical_blob\":null},{\"index\":22,\"role\":\"stdout\",\"name\":\"service.rs\",\"relative\":\"service.rs.rustfmt.stdout\",\"path\":\"/home/qian-qi/heptabao-native-jwt-e3afc157-format-20261106-r1/service.rs.rustfmt.stdout\",\"bytes\":519132,\"sha256\":\"6df7278a7b90363fe25a563e10e29db35f47868a2d1d1ea225c91c1b9b6add7d\",\"cap\":655360,\"expected_full9\":null,\"canonical_blob\":null},{\"index\":23,\"role\":\"stderr\",\"name\":\"service.rs\",\"relative\":\"service.rs.rustfmt.stderr\",\"path\":\"/home/qian-qi/heptabao-native-jwt-e3afc157-format-20261106-r1/service.rs.rustfmt.stderr\",\"bytes\":0,\"sha256\":\"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855\",\"cap\":65536,\"expected_full9\":null,\"canonical_blob\":null},{\"index\":24,\"role\":\"candidate\",\"name\":\"service_native_auth.rs\",\"relative\":\"candidate/service_native_auth.rs\",\"path\":\"/home/qian-qi/heptabao-native-jwt-e3afc157-format-20261106-r1/candidate/service_native_auth.rs\",\"bytes\":142316,\"sha256\":\"877d158852e1e47dea0f65e3207592db1226fd92ba50d51f698f2f31d657c1a2\",\"cap\":142316,\"expected_full9\":null,\"canonical_blob\":\"c4b356de7c082b396e7e26024f567fb5337a55bb\"},{\"index\":25,\"role\":\"formatted\",\"name\":\"service_native_auth.rs\",\"relative\":\"formatted/service_native_auth.rs\",\"path\":\"/home/qian-qi/heptabao-native-jwt-e3afc157-format-20261106-r1/formatted/service_native_auth.rs\",\"bytes\":143153,\"sha256\":\"42a3080d030e6bc22318bf574e47209666f47aa7f336d91fef2c81f0c6b7e165\",\"cap\":262144,\"expected_full9\":null,\"canonical_blob\":null},{\"index\":26,\"role\":\"stdout\",\"name\":\"service_native_auth.rs\",\"relative\":\"service_native_auth.rs.rustfmt.stdout\",\"path\":\"/home/qian-qi/heptabao-native-jwt-e3afc157-format-20261106-r1/service_native_auth.rs.rustfmt.stdout\",\"bytes\":143153,\"sha256\":\"42a3080d030e6bc22318bf574e47209666f47aa7f336d91fef2c81f0c6b7e165\",\"cap\":262144,\"expected_full9\":null,\"canonical_blob\":null},{\"index\":27,\"role\":\"stderr\",\"name\":\"service_native_auth.rs\",\"relative\":\"service_native_auth.rs.rustfmt.stderr\",\"path\":\"/home/qian-qi/heptabao-native-jwt-e3afc157-format-20261106-r1/service_native_auth.rs.rustfmt.stderr\",\"bytes\":0,\"sha256\":\"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855\",\"cap\":65536,\"expected_full9\":null,\"canonical_blob\":null},{\"index\":28,\"role\":\"candidate\",\"name\":\"service_native_jwt_tests.rs\",\"relative\":\"candidate/service_native_jwt_tests.rs\",\"path\":\"/home/qian-qi/heptabao-native-jwt-e3afc157-format-20261106-r1/candidate/service_native_jwt_tests.rs\",\"bytes\":33059,\"sha256\":\"f7ca5c2c6e67717287887d31d5d8d40459f5ed6fb40524e5d026c95ee07fa48b\",\"cap\":33059,\"expected_full9\":null,\"canonical_blob\":\"89f3ce081c94e08446a15b11fdc76a1d724ab09e\"},{\"index\":29,\"role\":\"formatted\",\"name\":\"service_native_jwt_tests.rs\",\"relative\":\"formatted/service_native_jwt_tests.rs\",\"path\":\"/home/qian-qi/heptabao-native-jwt-e3afc157-format-20261106-r1/formatted/service_native_jwt_tests.rs\",\"bytes\":37377,\"sha256\":\"d16659cdb309644e8cf2ee2dcc6384671f034f49325152573f9d384076ab6feb\",\"cap\":262144,\"expected_full9\":null,\"canonical_blob\":null},{\"index\":30,\"role\":\"stdout\",\"name\":\"service_native_jwt_tests.rs\",\"relative\":\"service_native_jwt_tests.rs.rustfmt.stdout\",\"path\":\"/home/qian-qi/heptabao-native-jwt-e3afc157-format-20261106-r1/service_native_jwt_tests.rs.rustfmt.stdout\",\"bytes\":37377,\"sha256\":\"d16659cdb309644e8cf2ee2dcc6384671f034f49325152573f9d384076ab6feb\",\"cap\":262144,\"expected_full9\":null,\"canonical_blob\":null},{\"index\":31,\"role\":\"stderr\",\"name\":\"service_native_jwt_tests.rs\",\"relative\":\"service_native_jwt_tests.rs.rustfmt.stderr\",\"path\":\"/home/qian-qi/heptabao-native-jwt-e3afc157-format-20261106-r1/service_native_jwt_tests.rs.rustfmt.stderr\",\"bytes\":0,\"sha256\":\"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855\",\"cap\":65536,\"expected_full9\":null,\"canonical_blob\":null},{\"index\":32,\"role\":\"candidate\",\"name\":\"service_native_userpass_tests.rs\",\"relative\":\"candidate/service_native_userpass_tests.rs\",\"path\":\"/home/qian-qi/heptabao-native-jwt-e3afc157-format-20261106-r1/candidate/service_native_userpass_tests.rs\",\"bytes\":25592,\"sha256\":\"750574f862d135829036f08badaaf2fdb55bbc2790a244599e6dd4533a827fea\",\"cap\":25592,\"expected_full9\":null,\"canonical_blob\":\"0aafabbd9af4d381808f73efd2cba76e6eef3558\"},{\"index\":33,\"role\":\"formatted\",\"name\":\"service_native_userpass_tests.rs\",\"relative\":\"formatted/service_native_userpass_tests.rs\",\"path\":\"/home/qian-qi/heptabao-native-jwt-e3afc157-format-20261106-r1/formatted/service_native_userpass_tests.rs\",\"bytes\":25592,\"sha256\":\"750574f862d135829036f08badaaf2fdb55bbc2790a244599e6dd4533a827fea\",\"cap\":262144,\"expected_full9\":null,\"canonical_blob\":null},{\"index\":34,\"role\":\"stdout\",\"name\":\"service_native_userpass_tests.rs\",\"relative\":\"service_native_userpass_tests.rs.rustfmt.stdout\",\"path\":\"/home/qian-qi/heptabao-native-jwt-e3afc157-format-20261106-r1/service_native_userpass_tests.rs.rustfmt.stdout\",\"bytes\":25592,\"sha256\":\"750574f862d135829036f08badaaf2fdb55bbc2790a244599e6dd4533a827fea\",\"cap\":262144,\"expected_full9\":null,\"canonical_blob\":null},{\"index\":35,\"role\":\"stderr\",\"name\":\"service_native_userpass_tests.rs\",\"relative\":\"service_native_userpass_tests.rs.rustfmt.stderr\",\"path\":\"/home/qian-qi/heptabao-native-jwt-e3afc157-format-20261106-r1/service_native_userpass_tests.rs.rustfmt.stderr\",\"bytes\":0,\"sha256\":\"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855\",\"cap\":65536,\"expected_full9\":null,\"canonical_blob\":null},{\"index\":36,\"role\":\"config\",\"name\":\"rustfmt.toml\",\"relative\":\"rustfmt.toml\",\"path\":\"/home/qian-qi/heptabao-native-jwt-e3afc157-format-20261106-r1/rustfmt.toml\",\"bytes\":17,\"sha256\":\"f32d2f03b3f4b1e295c79ed49d543f1205c7dac7c3dc74f05a5a27af4fea0584\",\"cap\":17,\"expected_full9\":[\"66306\",\"30539974\",\"1000\",\"1000\",\"33152\",\"1\",\"17\",\"1793937480154146135\",\"1793937480154146135\"],\"canonical_blob\":null},{\"index\":37,\"role\":\"receipt\",\"name\":\"result.public.json\",\"relative\":\"result.public.json\",\"path\":\"/home/qian-qi/heptabao-native-jwt-e3afc157-format-20261106-r1/result.public.json\",\"bytes\":22202,\"sha256\":\"60776056ee93fa1fdb557233626ee392385bfe69c8335cd9bc8d236fb0974874\",\"cap\":65536,\"expected_full9\":[\"66306\",\"30541013\",\"1000\",\"1000\",\"33152\",\"1\",\"22202\",\"1793937480615144693\",\"1793937480615144693\"],\"canonical_blob\":\"58827993343d76b96fc92b0bae47432710ffbedd\"}]")
DIRECTORY_SPECS=(
 ("root",None,"/",0,0,None,True),
 ("home","root","home",0,0,None,True),
 ("user","home","qian-qi",1000,1000,None,True),
 ("input","user","heptabao-native-jwt-e3afc157-format-20261106-r1",1000,1000,0o700,False),
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
 must(len(ROWS)==38 and [r["index"] for r in ROWS]==list(range(38)),"fixed_rows")
 must(len({r["path"] for r in ROWS})==38,"unique_fixed_paths")
 must(sum(r["cap"] for r in ROWS)==READ_CAP and sum(r["bytes"] for r in ROWS)==3701083,
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
 must(len(data)==38 and c.input_read_bytes==3701083,"whole_input_accounting")
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
 must(receipt["schema"]=="heptabao.native-jwt-input-rustfmt.v1"
      and receipt["sourceCommit"]==SOURCE_COMMIT and receipt["sourceTree"]==SOURCE_TREE,
      "formatter_receipt_source")
 must(receipt["status"]=="passed" and receipt["allOwnedStopped"] is True
      and receipt["withinDeadline"] is True and receipt["allFixedSourceInputsUnchanged"] is True,
      "formatter_receipt_known_terminal")
 must(receipt["compileExecuted"] is False and receipt["productExecuted"] is False
      and receipt["productionChanged"] is False,"formatter_receipt_scope")
 must(receipt["internalSeconds"]==50 and receipt["newRemoteSupervisorSeconds"]==60,
      "formatter_receipt_deadlines")
 must(len(receipt["children"])==9 and all(
      x["exitCode"]==0 and x["reaped"] is True and x["stopped"] is True
      and x["newProcessGroupCreated"] is False and x["pgid"]==x["supervisorGroup"]
      for x in receipt["children"]),"formatter_direct_children")
 expected=[]
 for i in range(9):
  a,b,o,e=ROWS[4*i:4*i+4]
  expected.append({"name":a["name"],"beforeSha256":a["sha256"],"beforeBytes":a["bytes"],
                   "afterSha256":b["sha256"],"afterBytes":b["bytes"],
                   "stderrBytes":e["bytes"],"stderrSha256":e["sha256"]})
 must(receipt["files"]==expected,"formatter_receipt_exact_files")
 return {"source_commit":SOURCE_COMMIT,"source_tree":SOURCE_TREE,"job_id":FORMATTER_JOB,
         "receipt_blob":RECEIPT_BLOB,"receipt_sha256":sha(data["result.public.json"]),
         "direct_children_reaped":9,"same_supervisor_pgid":True,
         "independent_group_empty_observed":False,"compile_executed":False}

def make_diffs(c,data):
 result=[]
 total=0
 changed=0
 for i in range(9):
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
  result.append({"name":a["name"],"canonical_candidate_blob":a["canonical_blob"],
      "before_bytes":len(before),"before_sha256":sha(before),
      "after_bytes":len(after),"after_sha256":sha(after),
      "stdout_byte_equal":True,"stderr_empty":True,"changed":is_changed,
      "unified_diff":patch,"diff_bytes":patch_bytes,"diff_sha256":sha(patch.encode("utf-8")),
      "strict_forward_equal":True,"strict_reverse_equal":True})
 must(changed==6 and len(result)-changed==3,"formatter_changed_count")
 must(data["rustfmt.toml"]==CONFIG_BYTES,"fixed_configuration_bytes")
 return result,total

def recheck_inputs_and_close(c):
 for record in c.files:
  record["final_after"]=input_pair(c,record)
 directory_after={label:directory_pair(c,r) for label,r in c.directories.items()}
 for record in reversed(c.files):
  c.close_once(record["entry"])
 must(len(c.files)==38 and all(r["entry"]["closed"] and r["entry"]["close_error"] is None
                               for r in c.files),"input_once_close")
 c.check()
 return directory_after

def public_input_records(c):
 return [{"index":r["row"]["index"],"role":r["row"]["role"],"name":r["row"]["name"],
          "path":r["row"]["path"],"bytes":r["row"]["bytes"],"sha256":r["row"]["sha256"],
          "original_file_cap":r["row"]["cap"],"prior_full9":r["row"]["expected_full9"],
          "canonical_blob":r["row"]["canonical_blob"],"before_full9":r["before"],
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
  report={"schema":"heptabao.native-jwt-formatter38-observation.v1",
    "input_observation_complete":True,"collector_source_sha256":self_sha,
    "source_commit":SOURCE_COMMIT,"source_tree":SOURCE_TREE,
    "formatter_source_blob":FORMATTER_SOURCE_BLOB,"formatter_receipt":receipt,
    "input_root":INPUT_ROOT,"output_root":OUTPUT_ROOT,
    "identity_fields":IDENTITY_FIELDS,"identity_numbers":"decimal strings",
    "input_count":38,"input_bytes":3701083,"original_read_cap":READ_CAP,
    "input_files":public_input_records(c),
    "directories_before":{k:{"full9":r["before"],"shared_identity_only":r["shared"]}
                           for k,r in c.directories.items()},
    "directories_after_inputs":directory_after,
    "diffs":diffs,"diff_total_bytes":diff_bytes,
    "source_bytes":1221466,"formatted_bytes":1228699,"changed_files":6,"unchanged_files":3,
    "configuration_utf8":CONFIG_BYTES.decode("utf-8"),
    "reconstruction":{"candidates":"nine exact canonical e3af blobs",
       "formatted":"strict bidirectional unified diffs against those candidate bytes",
       "stdout":"byte equal to corresponding actual formatted file",
       "stderr":"nine empty byte strings",
       "config":"configuration_utf8 encoded as UTF-8",
       "receipt":"exact already archived receipt blob "+RECEIPT_BLOB},
    "counters_before_publication":c.counters(),
    "limits":{"shared_seconds":50,"outer_seconds":60,"read_bytes":READ_CAP,
       "per_read_bytes":READ_CHUNK,"read_calls":READ_CALL_CAP,"metadata_calls":META_CAP,
       "fd_acquisitions":FD_CAP,"peak_owned_fds":PEAK_FD_CAP,"diff_bytes":DIFF_CAP,
       "report_bytes":REPORT_CAP,"stdout_bytes":STDOUT_CAP},
    "all_38_input_fds_once_closed":True,
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
          and len(c.ledger)==46 and all(x["fd"] is not None for x in c.ledger)
          and c.report_pin is not None and c.input_read_bytes==3701083)
 summary={"schema":"heptabao.native-jwt-formatter38-terminal.v1",
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
