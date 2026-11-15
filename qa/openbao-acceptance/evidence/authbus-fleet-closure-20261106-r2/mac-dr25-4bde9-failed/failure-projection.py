import json,time,os
from pathlib import Path
root=Path('/Volumes/T5/hepta-vnext-recovery-20261013/continuation-20261106-kv2-ha-convergence-r1/full34-dr25-r1')
p=root/'dr25-summary.json'
v=json.loads(p.read_text())
r={'schema':'heptabao.dr25-failure-projection.v1','read_only':True,'observed_unix':time.time(),'status':v.get('status'),'failure':v.get('failure'),'summary_bytes':p.stat().st_size,'check_count':len(v.get('checks',[])),'checks':[{'case':x.get('case'),'passed':x.get('passed')} for x in v.get('checks',[])],'cleanup_failures':v.get('cleanup_failures'),'process_custody':{k:v.get('process_custody',{}).get(k) for k in ['passed_process_custody','finished','failed','original_count']}}
for row in v.get('checks',[]):
 if row.get('case')=='complete_v6_archive_seal_binding':
  e=row.get('evidence',{});c=e.get('cli_archive',{});h=e.get('normal_http_archive',{})
  r['archive_comparison']={'cli':{k:c.get('metadata',{}).get(k) for k in ['format','state_format','generation','state_bytes']},'http':{k:h.get('metadata',{}).get(k) for k in ['format','state_format','generation','state_bytes']},'seal_identity_equal':c.get('metadata',{}).get('seal_identity')==h.get('metadata',{}).get('seal_identity'),'expected_min_state_bytes':34*1024*1024,'cli_members':[{'name':x.get('name'),'bytes':x.get('bytes')} for x in c.get('members',[])],'http_members':[{'name':x.get('name'),'bytes':x.get('bytes')} for x in h.get('members',[])],'cli_outer_checksums':c.get('outer_checksums_verified'),'http_outer_checksums':h.get('outer_checksums_verified')}
b=v.get('baseline',{});r['baseline_qualified']=b.get('qualified');r['baseline_required_count']=b.get('required_count')
if isinstance(b.get('summary'),str):
 q=Path(b['summary'])
 if q.is_relative_to(root) and q.is_file():
  z=json.loads(q.read_text());r['baseline']={k:z.get(k) for k in ['status','failure','source_profile','version_count','live_payload_bytes']}
  r['baseline']['checks']=[{'case':x.get('case'),'passed':x.get('passed')} for x in z.get('checks',[])]
  r['baseline']['cleanup_failures']=z.get('cleanup_failures')
print(json.dumps(r,sort_keys=True))
