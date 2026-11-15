#!/usr/bin/env python3
"""Pure boundary tests for the exact observed SDK warning admission."""
import ast,json
from pathlib import Path
p=Path(__file__).with_name('launch_gateway_registration_qualification_r3.template.py')
tree=ast.parse(p.read_text());node=next(x for x in tree.body if isinstance(x,ast.FunctionDef) and x.name=='admitted_child_stderr')
scope={};exec(compile(ast.Module(body=[node],type_ignores=[]),str(p),'exec'),scope)
admit=scope['admitted_child_stderr']
warning=b'Config warnings:\n- plugins.entries.openclaw-authbus: plugin disabled (disabled in config) but config is present\n'
good={'ok':True,'originalDisabledConfigWarningExact':True,'passed':15,'executed':15}
cases=[
 ('empty-syntax','syntax-0',0,b'',None,True),
 ('empty-unit','unit',0,b'',good,True),
 ('exact-unit-warning','unit',0,warning,good,True),
 ('syntax-warning','syntax-0',0,warning,good,False),
 ('nonzero-unit','unit',1,warning,good,False),
 ('boolean-exit','unit',False,warning,good,False),
 ('unit-failed','unit',0,warning,{**good,'ok':False},False),
 ('snapshot-not-exact','unit',0,warning,{**good,'originalDisabledConfigWarningExact':False},False),
 ('case-missing','unit',0,warning,{**good,'passed':14},False),
 ('extra-case','unit',0,warning,{**good,'executed':16},False),
 ('warning-prefix','unit',0,b'x'+warning,good,False),
 ('warning-trailer','unit',0,warning+b'x',good,False),
 ('duplicate-warning','unit',0,warning+warning,good,False),
 ('different-reason','unit',0,warning.replace(b'in config',b'by config'),good,False),
 ('different-plugin','unit',0,warning.replace(b'openclaw-authbus',b'unknown-plugin'),good,False),
 ('text-not-bytes','unit',0,warning.decode(),good,False),
]
rows=[]
for name,label,rc,err,unit,expected in cases:
 actual=admit(label,rc,err,unit);assert actual is expected,name
 rows.append({'id':name,'matched':True})
print(json.dumps({'schema':'heptabao.registration-exact-stderr.local.r3','passed':len(rows),'executed':len(rows),'actualMacRun':False,'rows':rows},sort_keys=True))
