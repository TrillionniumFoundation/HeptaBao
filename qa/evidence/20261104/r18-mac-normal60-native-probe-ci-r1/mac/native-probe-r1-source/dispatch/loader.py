import hashlib,sys
raw=sys.stdin.buffer.read(75076)
if len(raw)!=75075 or hashlib.sha256(raw).hexdigest()!="a24d818266ffc2f791dab4c075a02cf26874cb50c84d2bd38d934caf3dfb8857": raise SystemExit(2)
exec(compile(raw,'<mac-native-proc-sandbox-probe-r1>','exec'),{'__name__':'__main__','_ROOT_AUTHORED_SOURCE':raw})
