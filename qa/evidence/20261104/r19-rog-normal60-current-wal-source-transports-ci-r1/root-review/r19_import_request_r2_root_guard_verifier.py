import ast,json,hashlib,re,sys,types
x=json.loads(sys.argv[1]);tree=ast.parse(x['source']);top=next(n for n in tree.body if isinstance(n,ast.Try) and n.lineno==518);nodes=top.body[:5]
assert [n.lineno for n in nodes]==[519,520,521,522,523]
assert [type(n).__name__ for n in nodes]==['Assert','Assert','Assert','Assign','Assert']
module=ast.Module(body=nodes,type_ignores=[]);code=compile(ast.fix_missing_locations(module),'exact-original-import-argv-guards','exec')
result={}
for name in ('old','corrected'):
 req=x[name];args=req['args'];fake=types.SimpleNamespace(argv=['-c',*args[5:]],orig_argv=[req['executable'],*args]);scope={'sys':fake,'re':re,'digest':lambda b:hashlib.sha256(b).hexdigest()}
 try:exec(code,scope);result[name]={'passed':True,'body_exact':scope['controller_raw']==x['source'].encode()}
 except AssertionError as e:
  tb=e.__traceback__
  while tb.tb_next:tb=tb.tb_next
  result[name]={'passed':False,'line':tb.tb_lineno}
assert result['old']=={'passed':False,'line':519}
assert result['corrected']=={'passed':True,'body_exact':True}
before=dict(x['old']);after=dict(x['corrected']);a=after.pop('args');b=before.pop('args');ak=after.pop('idempotency_key');bk=before.pop('idempotency_key')
assert before==after and a[:-1]==b and a[-1]==hashlib.sha256(x['source'].encode()).hexdigest()
assert bk=='heptabao-df026-standalone-import-fbbb2f85-20261105-r1' and ak=='heptabao-df026-standalone-import-fbbb2f85-20261105-r2'
print(json.dumps({'status':'passed','selected_exact_lines':[519,520,521,522,523],'old_result':result['old'],'corrected_result':result['corrected'],'executed_full_importer':False,'only_changes':['append_exact_self_SHA_argument','fresh_r2_idempotency_key']},sort_keys=True))
