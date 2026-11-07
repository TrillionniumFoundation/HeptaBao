import hashlib,json,os,stat,sys,time,types,unittest
from pathlib import Path
QA=Path("/Volumes/T5/hepta-vnext-recovery-20261013/mac-authbus-main3-sdk-20261106-r4/qa")
path=QA/'main3_sdk_controller.py'
def identity(s):return tuple(str(getattr(s,k)) for k in ('st_dev','st_ino','st_uid','st_gid','st_mode','st_nlink','st_size','st_mtime_ns','st_ctime_ns'))
fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC)
try:
 before=os.fstat(fd)
 assert stat.S_ISREG(before.st_mode) and before.st_uid==501 and before.st_nlink==1 and stat.S_IMODE(before.st_mode)==0o600
 raw=os.read(fd,1048576)
 assert len(raw)==33429 and hashlib.sha256(raw).hexdigest()=="eb253c69eaa6f1f480f5f6e0a095066eb5e7a53b00c1060c52223072701720f1"
 assert os.read(fd,1)==b'' and identity(before)==identity(os.fstat(fd))==identity(path.lstat())
finally:os.close(fd)
module=types.ModuleType('main3_sdk_controller');module.__file__=str(path)
sys.modules[module.__name__]=module
exec(compile(raw,str(path),'exec'),module.__dict__)
plan,pin=module.load_inputs()
assert pin=="5c74cac57c3f6f16ebb7bb4844e1b457de66b90fd4a7ecc84e43196798a9b487"
EXPECTED_ASSETS={"qa/main3_sdk_cycle_r2.mjs":{"bytes":31439,"sha256":"4a67ca8ec0effa91e35cde4d92eaaa28a18a58b8cab647e4e9ac4315b476b383"},"qa/main3_auth_rows_cas_r1.mjs":{"bytes":3040,"sha256":"4f3efdf344e61f5f1c95dadfd8b9c52f142f85ddc2794933f798142ab8324e9c"},"qa/main3_authbus_cache_cas_r1.mjs":{"bytes":6983,"sha256":"7fa83d69c5c9713d3be642434ad009e070e688890d0e0a23db11f7b46d702302"},"qa/main3_sdk_seed_r1.mjs":{"bytes":7715,"sha256":"6a156f3e8e0e51ad2492e76720a76e386a8020d991cfe66aa21131141f36e410"},"plugin/index.js":{"bytes":54455,"sha256":"b19b6a9e7c1d57ccef8d67994ed3421891788ac30a82ff6bad2eef2ef7e30f9b"},"plugin/package.json":{"bytes":980,"sha256":"e9a39d1880a285e76b5b09fb69c9614cfbecff0e1021eb29ce214a6340fd7334"},"plugin/order-policy.js":{"bytes":7376,"sha256":"16bddaa7d18600f9f09dac7b5fb4999a141c86aab1fb15d3e9d6abc24e1cf301"},"plugin/runtime-refresh-policy.js":{"bytes":956,"sha256":"8257a6d2ee04868f3a7de5ff8ffaa7fdd3b37bb12a07ac993a3e9c7480c83547"},"plugin/codex-client-recycler.js":{"bytes":2120,"sha256":"d3fffe4c401af1dd997017a22930da241d2a4a899c518ce6d25c7047f1b3a13d"},"plugin/provider-error-classifier.js":{"bytes":4670,"sha256":"3f9470edea686a0eb46400efecc4c12a284e7fdef018565c34185b0cff102d77"},"plugin/bad-refresh-quarantine.js":{"bytes":5438,"sha256":"916617f296bd2e4b97b240a13418ac6220bb6513a1a0b83f5ee21854edc62286"},"plugin/lease-assignments.js":{"bytes":6932,"sha256":"24192dc82ddd682e836ea2df717b065b76773c0a1f4b0905f6764e4d498d77e7"},"qa/main3_sdk_wire_r3.mjs":{"bytes":13346,"sha256":"e80c7eb22e2cd2fbc547eb085b8eb0b482e8e656baa8a59520e0cb93a4c0396c"}}
assert plan['assetPins']==EXPECTED_ASSETS
def verify_assets():
 for relative,p in EXPECTED_ASSETS.items():
  data=module.stable_read(QA.parent/relative,2097152)
  assert len(data)==p['bytes'] and hashlib.sha256(data).hexdigest()==p['sha256']
verify_assets()
sys.path.insert(0,str(QA))
sys.argv=[str(path),'--mode','run']
raise SystemExit(module.main())
