"""Use the actual read method to reject the XNU insufficient-buffer marker."""
import ast
import ctypes
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
source = (HERE / 'observe_finite_codex_selectors_r2.template.py').read_text()
tree = ast.parse(source)
reader = next(n for n in tree.body if isinstance(n, ast.ClassDef) and n.name == 'ArgsReader')
parse_calls = []
def need(value, code):
    if not value:
        raise RuntimeError(code)
ns = {'ctypes':ctypes,'need':need,'parse_procargs':lambda raw:parse_calls.append(raw) or {'parsed':True}}
exec(compile(ast.Module(body=[reader],type_ignores=[]),'actual-reader-def','exec'),ns)
results=[]
for returned, expected_ok in ((262148,False),(262149,False),(262147,True),(5,False)):
    obj=object.__new__(ns['ArgsReader']);obj.maximum=262148
    obj.call=lambda mib,out,length,n=returned:setattr(length,'value',n)
    count=len(parse_calls);ok=False
    try:
        result=obj.read(66414);ok=result=={'parsed':True}
    except RuntimeError as error:
        assert str(error)=='selector_complete_returned_procargs_strictly_below_cap'
    assert ok==expected_ok and len(parse_calls)==count+int(expected_ok)
    results.append({'returnedBytes':returned,'accepted':ok,'expectedAccepted':expected_ok,'passed':True})
report={'schema':'heptabao.procargs-returned-cap-actual-method.r2','ok':True,'cases':results,'actualMac':False,'processReads':0}
raw=json.dumps(report,sort_keys=True,separators=(',',':'))+'\n'
(HERE/'returned-bound-local4.original.json').write_text(raw)
print(raw,end='')
