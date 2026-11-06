import hashlib,io,json,os,sys,time,unittest
from pathlib import Path
root=Path('/Volumes/T5/hepta-vnext-recovery-20261013/continuation-20261106-kv2-ha-convergence-r1/source-dr25-authbus-r2')
qa=root/'qa/openbao-acceptance'
pins={
 'kv2_native_fresh_directory_dr_live.py':('01993e6c367bf8b896b4832c7723b1f36900fefbc20fcc05394ce401ec6b4f67',72065),
 'tests/test_kv2_native_fresh_directory_dr_live.py':('26db39e8f63156ec10337bb436459794b95a104033ca1efeed08c4fdc3e30570',38607),
 'kv2_dr_process_custody.py':('669e2cd1d9ee597529c08b88f3fc21c813d4ff7b57f3792381baa44fbdbe7008',26131),
 'kv2_271_lossless_native_live.py':('383176647f0670837f40f3989496c6d1c902f8503dfa006d386b75877436b581',49393)}
def verify():
 for name,(digest,size) in pins.items():
  raw=(qa/name).read_bytes()
  assert len(raw)==size and hashlib.sha256(raw).hexdigest()==digest,name
assert sys.platform=='darwin' and os.geteuid()==501 and sys.dont_write_bytecode and sys.flags.isolated and sys.flags.no_site
assert sys.version_info[:3]==(3,14,3)
verify()
sys.path.insert(0,str(qa))
class Result(unittest.TextTestResult):
 def __init__(self,*a,**k):super().__init__(*a,**k);self.passed=[]
 def addSuccess(self,test):self.passed.append(test.id());super().addSuccess(test)
suite=unittest.TestLoader().discover(str(qa/'tests'),pattern='test_kv2_native_fresh_directory_dr_live.py')
assert suite.countTestCases()==34
stream=io.StringIO();started=time.monotonic()
result=unittest.TextTestRunner(stream=stream,verbosity=2,resultclass=Result).run(suite)
elapsed=time.monotonic()-started
verify()
ok=result.wasSuccessful() and result.testsRun==34 and len(result.passed)==34 and not result.skipped and not result.expectedFailures and not result.unexpectedSuccesses and elapsed<55
report={'schema':'heptabao.mac-dr25-5ded-controller-guards.v1','qa_commit':'5ded017e1c858b8602a73678acc29df75386a84d','source_pins':{n:{'sha256':v[0],'bytes':v[1]} for n,v in pins.items()},'actual_mac':True,'ok':ok,'required':34,'executed':result.testsRun,'passed':len(result.passed),'failed':len(result.failures),'errors':len(result.errors),'skipped':len(result.skipped),'test_names':result.passed,'elapsed_seconds':elapsed,'original_runtime_outer_seconds':60,'stdout':'','unittest_output':stream.getvalue(),'source_bytes_unchanged':True,'product_oracle_started':False,'actual_restore_qualified':False}
print(json.dumps(report,sort_keys=True))
raise SystemExit(0 if ok else 1)
