import hashlib,sys
raw=sys.stdin.buffer.read(76659)
if len(raw)!=76658 or hashlib.sha256(raw).hexdigest()!="4dc7cc28869ff4cd78bd4d442619e79a44d82b0ae46c5040dcd9b59e0e17921d": raise SystemExit(2)
exec(compile(raw,'<mac-native-proc-sandbox-probe-r2>','exec'),{'__name__':'__main__','_ROOT_AUTHORED_SOURCE':raw})
