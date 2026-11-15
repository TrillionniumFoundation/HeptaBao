"""Local pure projection/privacy fixtures; no Mac or configuration reads."""
from pathlib import Path
import hashlib,json,shlex,time
START=time.monotonic();p=Path(__file__).with_name('current_gateway_argv_projection_r2.py');source=p.read_text()
a=source.index(" args=value['arguments'];");b=source.index(' ROOT.mkdir(',a)
program=compile('\n'.join(line[1:] for line in source[a:b].splitlines()),'<exact-projection-only>','exec')
def project(args):
 def need(v,c):
  if not v:raise ValueError(c)
 env={'value':{'arguments':args},'need':need,'Path':Path,'shlex':shlex,'SDK':Path('/opt/homebrew/lib/node_modules/openclaw'),'LIVE':Path('/Users/qianqi/.openclaw')}
 exec(program,env)
 return {k:env[k] for k in ('projected','transparent','script_index','safe_tokens')}
rows=[]
def case(name,fn):
 try:fn();rows.append({'id':name,'passed':True})
 except BaseException as e:rows.append({'id':name,'passed':False,'errorType':type(e).__name__})
def check(value):
 if not value:raise AssertionError()
base=['/bin/sh','-c','ulimit -n 65536; exec "$0" "$@"','/opt/homebrew/bin/node','/opt/homebrew/lib/node_modules/openclaw/dist/index.js','gateway','--port','18789']
case('G01_exact_c_wrapper',lambda:check(project(base)['transparent']))
case('G02_lc_wrapper_shape_observed_without_memory_claim',lambda:check(project([base[0],'-lc',*base[2:]])['transparent']))
case('G03_argv0_alias',lambda:check(project(['sh',*base[1:]])['transparent']))
case('G04_program_arguments_need_not_repeat_program',lambda:check(project(['-c',base[2],*base[3:],'--'])['script_index']==1))
case('G05_unrecognized_option_not_interpreted',lambda:check(project([base[0],'-x',*base[2:]])['script_index'] is None))
def no_private_text():
 secret='synthetic-private-value-never-public'
 x=project([base[0],base[1],'export TOKEN='+secret+'; exec "$0" "$@"',*base[3:]])
 check(secret not in json.dumps(x) and not x['transparent'] and '<private-or-unrecognized>' in x['safe_tokens'])
case('G06_shell_private_literal_redacted',no_private_text)
def no_private_argument():
 secret='synthetic-private-argument'
 x=project([*base[:6],'--token',secret]);check(secret not in json.dumps(x) and x['projected'][-1]['kind']=='private-or-unrecognized')
case('G07_unknown_argument_redacted',no_private_argument)
def duplicate():
 try:project([base[0],'-c','-lc',*base[3:]])
 except ValueError:return
 raise AssertionError()
case('G08_duplicate_shell_switch_refused',duplicate)
result={'schema':'heptabao.gateway-argv-projection-local.r2','ok':all(x['passed'] for x in rows),'cases':rows,'passed':sum(x['passed'] for x in rows),'executed':len(rows),'actualMacExecution':False,'credentialInputsRead':0,'sourceSha256':hashlib.sha256(source.encode()).hexdigest(),'elapsedSeconds':time.monotonic()-START}
print(json.dumps(result,sort_keys=True));raise SystemExit(0 if result['ok'] else 1)
