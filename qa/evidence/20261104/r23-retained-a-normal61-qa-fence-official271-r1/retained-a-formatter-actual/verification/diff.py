import difflib,hashlib,json,pathlib
p=pathlib.Path('/tmp/heptabao_retained_a_format_actual_r1/input.json')
data=json.loads(p.read_text())
def pin(t):
 b=t.encode()
 return {'bytes':len(b),'sha256':hashlib.sha256(b).hexdigest(),'blob':hashlib.sha1(b'blob '+str(len(b)).encode()+b'\0'+b).hexdigest()}
assert pin(data['after'])['sha256']=='973bb75ed4def7d7675f6cf38be77832b7c512d243c4569d12601dab1eec4372'
def delta(a,b):
 return ''.join(difflib.unified_diff(a.splitlines(True),b.splitlines(True),fromfile='a/'+data['path'],tofile='b/'+data['path']))
out={'schema':'heptabao.retained-a.actual-rustfmt-diff.v1','before':pin(data['before']),'after':pin(data['after']),'base':pin(data['base']),'formatter_diff':delta(data['before'],data['after']),'combined_diff':delta(data['base'],data['after']),'source_only_diff_generation':True,'remote_calls':0,'rust_execution_in_this_command':0}
print(json.dumps(out,indent=2))
