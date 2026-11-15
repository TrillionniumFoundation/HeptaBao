import hashlib,io,json,os,sys
assert sys.platform=='darwin' and os.getuid()==501 and os.geteuid()==501
raw=sys.stdin.buffer.read(1048577)
assert len(raw)<=1048576
bundle=json.loads(raw)
assert set(bundle)=={'sources','assets','preparerSource'}
source=bundle['preparerSource'].encode('utf-8')
assert len(source)==19405 and hashlib.sha256(source).hexdigest()=="ca6cb48e1d74aafed1320ef7e29048b8d1f9b20d38247c3c64d7c717660aa774"
sys.stdin=io.TextIOWrapper(io.BytesIO(raw),encoding='utf-8')
exec(compile(source,'<heptabao-main3-sdk-r4-pinned-preparation>','exec'),{'__name__':'__main__'})
