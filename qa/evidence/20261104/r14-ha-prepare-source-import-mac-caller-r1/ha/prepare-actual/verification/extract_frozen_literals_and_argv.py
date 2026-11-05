import ast,json,sys
from pathlib import PurePosixPath
from types import SimpleNamespace
source=json.loads(sys.argv[1])
module=ast.parse(source)
wanted={'COMMIT','TREE','QA_PINS','BUILDS','COMPARISON_PINS','DEADLINE_QA_PINS','POSTCOLD_CHECKS','RUNNER_SHA256','NUMERIC_HELPER_SHA256','CIPHER_HELPER_SHA256'}
values={n.targets[0].id:ast.literal_eval(n.value) for n in module.body if isinstance(n,ast.Assign) and len(n.targets)==1 and isinstance(n.targets[0],ast.Name) and n.targets[0].id in wanted}
assert set(values)==wanted
pure={'ROOT','CONTROL','WORK','SOURCE','COMMIT','TREE','MAC','LINUX','RUNNER','BUILDS'}
nodes=[n for n in module.body if isinstance(n,ast.Assign) and len(n.targets)==1 and isinstance(n.targets[0],ast.Name) and n.targets[0].id in pure]
nodes.append(next(n for n in module.body if isinstance(n,ast.FunctionDef) and n.name=='args'))
env={'Path':PurePosixPath,'sys':SimpleNamespace(executable='/usr/bin/python3')}
exec(compile(ast.Module(body=nodes,type_ignores=[]),'<selected-pure-paths-and-argv>','exec'),env)
values['ACTUAL_ARGS_FROM_FROZEN_FUNCTION']=env['args']()
print(json.dumps(values,sort_keys=True))
