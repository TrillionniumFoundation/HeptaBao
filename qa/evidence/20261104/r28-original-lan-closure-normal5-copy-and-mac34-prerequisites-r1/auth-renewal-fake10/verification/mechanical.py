import ast,difflib,hashlib,json,pathlib,re
base=pathlib.Path("/tmp/heptabao_renewal_fake_r2_grf3_e7n")
old=(base/'selected-checks.original.py').read_text()
new=(base/'selected-checks.r2.py').read_text()
diff=''.join(difflib.unified_diff(old.splitlines(keepends=True),new.splitlines(keepends=True),fromfile='before/selected-checks.py',tofile='after/selected-checks.py'))
def apply_exact(source,patch):
    original=source.splitlines(keepends=True);lines=patch.splitlines(keepends=True);out=[];at=0;i=2;hunks=0
    while i<len(lines):
        match=re.fullmatch(r'@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@.*\n',lines[i])
        assert match
        start=int(match[1])-1;old_count=int(match[2] or 1);new_count=int(match[4] or 1)
        assert at<=start
        out.extend(original[at:start]);at=start;i+=1;old_seen=0;new_seen=0;hunks+=1
        while i<len(lines) and not lines[i].startswith('@@ '):
            row=lines[i];kind=row[0];body=row[1:];assert kind in ' +-'
            if kind in ' -':assert at<len(original) and original[at]==body;at+=1;old_seen+=1
            if kind in ' +':out.append(body);new_seen+=1
            i+=1
        assert old_seen==old_count and new_seen==new_count
    out.extend(original[at:]);return ''.join(out),hunks
rebuilt,hunks=apply_exact(old,diff);assert rebuilt==new
inverse=''.join(difflib.unified_diff(new.splitlines(keepends=True),old.splitlines(keepends=True),fromfile='after/selected-checks.py',tofile='before/selected-checks.py'))
assert apply_exact(new,inverse)[0]==old
before_ast=ast.parse(old);after_ast=ast.parse(new);compile(after_ast,'selected-checks.r2.py','exec')
def definitions(text,tree):return {n.name:ast.get_source_segment(text,n) for n in tree.body if isinstance(n,(ast.FunctionDef,ast.ClassDef))}
bd=definitions(old,before_ast);ad=definitions(new,after_ast)
modified=[name for name in bd if bd[name]!=ad.get(name)]
assert sorted(modified)==['FakeClient','run_chain']
pins={}
for name,expected in [('outer.proposed.py','72ecfcd586a4ab4c48fd95d2e15b4a44165a754570c699eae18dceaa02f3b262'),('outer.before.py','bce47fd194be7ec1d1ec340e24d8e759dbf7611ef3c75eca2adeb62e9b4ccf01'),('selected-checks.original.py','bd3e8ad155b9d219b992c091f124a61a1fc82470008629584ca423055a630f28'),('selected-checks.r2.py','be4f7012b28e5bbaf64e18da0d732d496ecbe37e57a4614a5bdd2ca50d3bf52b'),('result.public.json','3de6cccc370981dc1f084002b20deea4349854760f6a7e64ac4304a334785f16')]:
    data=(base/name).read_bytes();actual=hashlib.sha256(data).hexdigest();assert actual==expected
    pins[name]={'bytes':len(data),'sha256':actual}
with (base/'selected-checks.review.diff').open('x') as f:assert f.write(diff)==len(diff)
report={'schema':'heptabao.renewal-pure-fake-r2-mechanical-verification.v1','strict_forward_exact':True,'strict_inverse_exact':True,'hunks':hunks,'modified_existing_definitions':modified,'unchanged_existing_definitions':[n for n in bd if bd[n]==ad.get(n)],'pins_after_execution':pins,'candidate_product_and_guard_changed':False,'new_component_execution':False,'diff':diff}
print(json.dumps(report,sort_keys=True,indent=2))
