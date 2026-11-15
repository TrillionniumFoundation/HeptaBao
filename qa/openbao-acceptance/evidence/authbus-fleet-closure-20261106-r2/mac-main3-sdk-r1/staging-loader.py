import hashlib,io,json,os,sys
assert sys.platform=='darwin' and os.getuid()==501 and os.geteuid()==501
raw=sys.stdin.buffer.read(1048577)
assert len(raw)<=1048576
bundle=json.loads(raw)
assert set(bundle)=={'sources','assets','preparerSource'}
source=bundle['preparerSource'].encode('utf-8')
assert len(source)==19405 and hashlib.sha256(source).hexdigest()=="3d76972effb9c907be2b87f32d85877f6ef5e6e24619aee19ceedfe933cd9839"
sys.stdin=io.TextIOWrapper(io.BytesIO(raw),encoding='utf-8')
exec(compile(source,'<heptabao-main3-sdk-r1-pinned-preparation>','exec'),{'__name__':'__main__'})
