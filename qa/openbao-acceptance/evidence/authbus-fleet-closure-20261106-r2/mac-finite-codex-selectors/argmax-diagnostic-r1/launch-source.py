import ctypes,json,os,sys,time
from pathlib import Path
start=time.monotonic()
out={'schema':'heptabao.fixed-kern-argmax-diagnostic.r1','ok':False,'mib':[1,8],'processArgumentReads':0,'credentialFileReads':0,'keychainReads':0,'childProcesses':0,'productionWrites':0,'sysctlWrites':0}
try:
 if sys.platform!='darwin' or os.getuid()!=501 or os.geteuid()!=501 or Path(sys.executable).resolve()!=Path('/opt/homebrew/Cellar/python@3.14/3.14.3_1/Frameworks/Python.framework/Versions/3.14/bin/python3.14'):raise RuntimeError('exact_runtime')
 lib=ctypes.CDLL('/usr/lib/libSystem.B.dylib',use_errno=True)
 lib.sysctl.argtypes=[ctypes.POINTER(ctypes.c_int),ctypes.c_uint,ctypes.c_void_p,ctypes.POINTER(ctypes.c_size_t),ctypes.c_void_p,ctypes.c_size_t]
 lib.sysctl.restype=ctypes.c_int
 mib=(ctypes.c_int*2)(1,8)
 value=ctypes.c_int()
 size=ctypes.c_size_t(ctypes.sizeof(value))
 ctypes.set_errno(0)
 result=lib.sysctl(mib,2,ctypes.byref(value),ctypes.byref(size),None,0)
 out.update(returnCode=result,returnedBytes=size.value,kernelArgumentMaximum=value.value,errno=ctypes.get_errno(),intBytes=ctypes.sizeof(value))
 out['ok']=result==0 and size.value==4 and value.value>0 and time.monotonic()-start<10
except BaseException:out['errorCode']='fixed_argmax_diagnostic_refused'
out['elapsedSeconds']=time.monotonic()-start
print(json.dumps(out,sort_keys=True,separators=(',',':')),flush=True)
raise SystemExit(0 if out['ok'] else 1)
