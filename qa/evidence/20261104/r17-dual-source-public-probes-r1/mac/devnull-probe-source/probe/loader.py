import hashlib,sys
raw=sys.stdin.buffer.read(28202)
if len(raw)!=28201 or hashlib.sha256(raw).hexdigest()!="5229fa7089b9164e853dec4628c31969e39a212253618573f38b8a26df3d29a5": raise SystemExit(2)
exec(compile(raw,'<mac-capture-devnull-sandbox-probe-r1>','exec'),{'__name__':'__main__','_ROOT_AUTHORED_SOURCE':raw})
