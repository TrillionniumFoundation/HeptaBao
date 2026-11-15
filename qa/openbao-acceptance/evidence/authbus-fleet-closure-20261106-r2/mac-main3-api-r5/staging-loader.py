import hashlib,io,json,os,sys
assert sys.platform=='darwin' and os.getuid()==501 and os.geteuid()==501
raw=sys.stdin.buffer.read(1048577)
assert len(raw)<=1048576
bundle=json.loads(raw)
assert set(bundle)=={'sources','preparerSource'}
source=bundle['preparerSource'].encode('utf-8')
assert len(source)==16199 and hashlib.sha256(source).hexdigest()=="d7341c8fa66a7cd33cf2e3c13360c7137e3fdfc69083fa9fb83f59dc16c8c5c0"
sys.stdin=io.TextIOWrapper(io.BytesIO(raw),encoding='utf-8')
exec(compile(source,'<heptabao-main3-api-r5-pinned-preparation>','exec'),{'__name__':'__main__'})
