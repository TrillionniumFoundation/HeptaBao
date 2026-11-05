import hashlib,sys
raw=sys.stdin.buffer.read(39811)
if len(raw)!=39810 or hashlib.sha256(raw).hexdigest()!="c694655f3cf6835bdc8d507afef10764b0d2c41601f60de9466705c93efb39fe": raise SystemExit(2)
exec(compile(raw,'<mac-public-ps-sandbox-probe-r1>','exec'),{'__name__':'__main__','_ROOT_AUTHORED_SOURCE':raw})
