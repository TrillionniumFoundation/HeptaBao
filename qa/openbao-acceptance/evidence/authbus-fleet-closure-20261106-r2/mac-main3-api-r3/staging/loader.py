import io,json,sys
bundle=json.loads(sys.stdin.buffer.read(1048577))
source=bundle['preparerSource']
sys.stdin=io.TextIOWrapper(io.BytesIO(json.dumps(bundle,separators=(',',':')).encode()),encoding='utf-8')
exec(compile(source,'<main3-api-create-only-preparer-r3>','exec'),{'__name__':'__main__'})
