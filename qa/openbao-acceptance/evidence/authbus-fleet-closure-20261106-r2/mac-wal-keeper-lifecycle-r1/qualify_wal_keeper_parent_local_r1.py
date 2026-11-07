#!/usr/bin/env python3
"""Local real SQLite proof for exact parent functions; no actual Mac SDK claim."""
import ast,hashlib,json,os,sqlite3,tempfile,time
from pathlib import Path

BASE=Path(__file__).resolve().parent
SOURCE=BASE/'launch_wal_keeper_lifecycle_r1.template.py'
raw=SOURCE.read_bytes();tree=ast.parse(raw)
selected={'need','remaining','database','open_sql','query','begin_keeper','close_sql','credential','store','setup'}
nodes=[n for n in tree.body if isinstance(n,ast.FunctionDef) and n.name in selected]
assert {n.name for n in nodes}==selected
state=next(n for n in tree.body if isinstance(n,ast.Assign) and any(isinstance(t,ast.Name) and t.id=='STATE' for t in n.targets))
root=Path(tempfile.mkdtemp(prefix='wal-keeper-parent-local-',dir=BASE))
report={'schema':'heptabao.wal-keeper-parent-local.r1','ok':False,'actualMac':False,
 'actualInstalledSdk':False,'rawSdkWriterUsed':False,'syntheticPythonWriterStandIn':True,
 'sourceSha256':hashlib.sha256(raw).hexdigest(),'sqliteVersion':sqlite3.sqlite_version,'cases':[]}
original_mode=os.umask(0o077)
def namespace(p):return {x:Path(str(p)+x).exists() for x in ('','-wal','-shm','-journal')}
def exercise(name):
 case_root=root/name
 for which in ('cold','held'):(case_root/'output/fixtures'/which/'agents/main/agent').mkdir(parents=True,mode=0o700)
 env={'ROOT':case_root,'Path':Path,'time':time,'UNTIL':time.monotonic()+5,'sqlite3':sqlite3,'json':json,
  'connections':[],'error_codes':set(),'report':{},'IDS':['synthetic-main-one','synthetic-main-two','synthetic-main-three']}
 exec(compile(ast.Module(body=nodes+[state],type_ignores=[]),str(SOURCE),'exec'),env)
 return env
def close_all(env):
 for item in reversed(env['connections']):env['close_sql'](item)
 return all(x['row']['closed'] and x['row']['closeAttempts']==1 and not x['row']['transactionActive'] and
  not x['row']['unknown'] and x['row']['cursorOpened']==x['row']['cursorClosed'] for x in env['connections'])
environments=[]
try:
 e=exercise('cold');environments.append(e)
 rw=e['setup']('cold');e['close_sql'](rw);n=namespace(e['database']('cold'))
 assert n=={'':True,'-wal':False,'-shm':False,'-journal':False}
 report['cases'].append({'case':'cold_last_rw_close_removes_sidecars','passed':True})

 e=exercise('open-only');environments.append(e)
 rw=e['setup']('held');idle=e['open_sql']('held','unestablished-readonly-control',True)
 assert idle['row']['beginDispatches']==0
 e['close_sql'](rw);n=namespace(e['database']('held'))
 assert n=={'':True,'-wal':False,'-shm':False,'-journal':False}
 report['cases'].append({'case':'open_readonly_without_transaction_does_not_retain_sidecars','passed':True})
 e['close_sql'](idle)

 e=exercise('held');environments.append(e)
 rw=e['setup']('held',True);p=e['database']('held');n=namespace(p)
 assert n=={'':True,'-wal':True,'-shm':True,'-journal':False}
 control=e['open_sql']('held','checkpointed-main-control',True,True)
 value=e['query'](control,'SELECT store_json FROM auth_profile_store WHERE store_key=?',('primary',),'one')
 assert json.loads(value[0])['profiles'][e['IDS'][0]]['access']=='synthetic-access-checkpointed'
 e['close_sql'](control)
 report['cases'].append({'case':'uncheckpointed_committed_row_excluded_from_main_control','passed':True})
 keeper=e['open_sql']('held','readonly-keeper',True);original=e['begin_keeper'](keeper)
 e['close_sql'](rw)
 assert namespace(p)==n and keeper['row']['transactionActive']
 report['cases'].append({'case':'actual_read_transaction_retains_existing_wal_names','passed':True})
 fresh=e['open_sql']('held','standin-independent-before',True)
 assert e['query'](fresh,'SELECT store_json FROM auth_profile_store WHERE store_key=?',('primary',),'one')==(original,)
 e['close_sql'](fresh)
 report['cases'].append({'case':'independent_reader_sees_uncheckpointed_committed_before','passed':True})
 writer=e['open_sql']('held','standin-python-writer')
 updated=json.loads(original);updated['profiles'][e['IDS'][0]]['access']='synthetic-access-after'
 e['query'](writer,'UPDATE auth_profile_store SET store_json=? WHERE store_key=?',(json.dumps(updated),'primary'))
 e['close_sql'](writer)
 assert e['query'](keeper,'SELECT store_json FROM auth_profile_store WHERE store_key=?',('primary',),'one')==(original,)
 fresh=e['open_sql']('held','standin-independent-after',True)
 assert json.loads(e['query'](fresh,'SELECT store_json FROM auth_profile_store WHERE store_key=?',('primary',),'one')[0])==updated
 e['close_sql'](fresh)
 report['cases'].append({'case':'fresh_reader_sees_new_commit_while_keeper_snapshot_stays_old','passed':True})
 e['close_sql'](keeper)
 report['namespaceAfterKeeperClose']={'walPresent':namespace(p)['-wal'],'shmPresent':namespace(p)['-shm']}
 report['cases'].append({'case':'keeper_rollback_and_close_once','passed':keeper['row']['rollbackDispatches']==1 and keeper['row']['closeAttempts']==1 and keeper['row']['closed']})
 assert all(close_all(env) for env in environments)
 report['cases'].append({'case':'all_parent_connections_and_query_cursors_closed_once','passed':True})
 report['ok']=all(x['passed'] for x in report['cases']);report['executed']=len(report['cases']);report['passed']=sum(x['passed'] for x in report['cases'])
finally:
 for e in environments:close_all(e)
 os.umask(original_mode)
 report['connections']=[dict(x['row']) for e in environments for x in e['connections']]
 report['allOriginalLocalConnectionsClosed']=all(x['closed'] and x['closeAttempts']==1 and not x['unknown'] and
  not x['transactionActive'] and x['cursorOpened']==x['cursorClosed'] for x in report['connections'])
 if not report['allOriginalLocalConnectionsClosed']:report['ok']=False
 value=json.dumps(report,sort_keys=True)+'\n';(root/'result.public.json').write_text(value)
 (BASE/'wal-keeper-parent-local-r1.result.public.json').write_text(value)
 print(value,end='')
raise SystemExit(0 if report['ok'] else 1)
