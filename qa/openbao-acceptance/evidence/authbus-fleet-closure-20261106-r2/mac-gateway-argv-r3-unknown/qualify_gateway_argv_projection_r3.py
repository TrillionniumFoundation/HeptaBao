"""Local pure projection/privacy fixtures; no Mac or configuration reads."""
from pathlib import Path
import ast,hashlib,json,shlex,time
START=time.monotonic();p=Path(__file__).with_name('current_gateway_argv_projection_r3.py');source=p.read_text()
function=[n for n in ast.parse(source).body if isinstance(n,ast.FunctionDef) and n.name=='shell_switch'][0]
function_program=compile(ast.Module(body=[function],type_ignores=[]),'<exact-shell-switch>','exec')
a=source.index(" args=value['arguments'];");b=source.index(' ROOT.mkdir(',a)
program=compile('\n'.join(line[1:] for line in source[a:b].splitlines()),'<exact-projection-only>','exec')
def project(args):
 def need(v,c):
  if not v:raise ValueError(c)
 env={'value':{'arguments':args},'need':need,'Path':Path,'shlex':shlex,'SDK':Path('/opt/homebrew/lib/node_modules/openclaw'),'LIVE':Path('/Users/qianqi/.openclaw')}
 exec(function_program,env)
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
 try:project(['-c','-lc',*base[2:]])
 except ValueError:return
 raise AssertionError()
case('G08_duplicate_shell_switch_refused',duplicate)
def combined(flag,errexit,login):
 x=project([base[0],flag,*base[2:]])
 check(x['transparent'] and x['projected'][1]['kind']=='known-shell-switches')
 f=x['projected'][1]['flags'];check(f['commandString'] and f['errexit']==errexit and f['login']==login)
case('G09_ec_combined_flags',lambda:combined('-ec',True,False))
case('G10_ce_combined_flags',lambda:combined('-ce',True,False))
case('G11_lec_combined_login_flags',lambda:combined('-lec',True,True))
def unknown_flag():
 private='-synthetic-secret-c'
 x=project([base[0],private,*base[2:]])
 check(x['script_index'] is None and private not in json.dumps(x))
case('G12_unrecognized_flag_text_never_public',unknown_flag)
def trace_flag():
 x=project([base[0],'-cx',*base[2:]])
 check(x['projected'][1]['flags']['xtrace'] is True and 'value' not in x['projected'][1])
case('G13_trace_is_observed_without_echoing_raw_flag',trace_flag)
def traversal():
 x=project([*base[:4],'/opt/homebrew/lib/node_modules/openclaw/dist/../../secret.js',*base[5:]])
 check(x['projected'][4]['kind']=='private-or-unrecognized')
case('G14_entry_path_traversal_not_published',traversal)
result={'schema':'heptabao.gateway-argv-projection-local.r3','ok':all(x['passed'] for x in rows),'cases':rows,'passed':sum(x['passed'] for x in rows),'executed':len(rows),'actualMacExecution':False,'credentialInputsRead':0,'sourceSha256':hashlib.sha256(source.encode()).hexdigest(),'elapsedSeconds':time.monotonic()-START}
print(json.dumps(result,sort_keys=True));raise SystemExit(0 if result['ok'] else 1)
