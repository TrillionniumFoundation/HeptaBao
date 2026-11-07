import hashlib,io,json,os,sys
assert sys.platform=='darwin' and os.getuid()==501 and os.geteuid()==501
raw=sys.stdin.buffer.read(1048577)
assert len(raw)<=1048576
bundle=json.loads(raw)
assert set(bundle)=={'sources','assets','preparerSource'}
source=bundle['preparerSource'].encode('utf-8')
assert len(source)==19405 and hashlib.sha256(source).hexdigest()=="52c985a1b3911a8555f4281b904503f4f3ffbead666d6bf18b2724063af507f2"
sys.stdin=io.TextIOWrapper(io.BytesIO(raw),encoding='utf-8')
exec(compile(source,'<heptabao-main3-sdk-r3-pinned-preparation>','exec'),{'__name__':'__main__'})
