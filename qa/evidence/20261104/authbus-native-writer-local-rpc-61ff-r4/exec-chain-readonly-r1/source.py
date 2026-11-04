import os,pathlib,hashlib,json,stat
env=pathlib.Path('/usr/bin/env').resolve(strict=True)
assert str(env)=='/usr/lib/cargo/bin/coreutils/env'
wrapper=pathlib.Path('/home/qian-qi/.openclaw/runtime/openai-codex-0.159.2/node_modules/@openai/codex/bin/codex.js')
def inspect(p,maximum):
 fd=os.open(p,os.O_RDONLY|os.O_NOFOLLOW)
 try:
  a=os.fstat(fd);assert stat.S_ISREG(a.st_mode)and a.st_size<=maximum
  h=hashlib.sha256();first=b''
  while True:
   b=os.read(fd,1048576)
   if not b:break
   if not first:first=b[:128]
   h.update(b)
  z=os.fstat(fd);assert(a.st_dev,a.st_ino,a.st_size,a.st_mtime_ns,a.st_ctime_ns)==(z.st_dev,z.st_ino,z.st_size,z.st_mtime_ns,z.st_ctime_ns)
  return {'realpath':str(p),'bytes':a.st_size,'sha256':h.hexdigest(),'uid':a.st_uid,'mode':oct(a.st_mode&0o7777)},first
e,_=inspect(env,67108864);w,first=inspect(wrapper,65536)
assert w['sha256']=='61b0194f3bb6534439c8d26a3ed57d0805f84b884588b761795323eeb92fcf70'
assert first.split(b'\n',1)[0]==b'#!/usr/bin/env node'
print(json.dumps({'schema':'heptabao.native-wrapper-shebang-exec-chain-readonly.v1','nativeStarted':False,'providerCalled':False,'productionChanged':False,'env':e,'wrapper':w,'wrapperShebangExact':True,'knownIntermediateExecutableFromOriginalSpawnReceipt':True},sort_keys=True))
