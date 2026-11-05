import base64,hashlib,json,sys
x=json.loads(sys.argv[1]);checks=[]
def ok(name,value):
 assert value,name
 checks.append(name)
p=json.loads(x['carrier'])
ok('closed_carrier_keys',set(p)=={'schema','files'} and set(p['files'])=={'sender.py','receiver.py','relay.py'})
ok('carrier_schema',p['schema']=='heptabao.phaseb3cb-shared-artifact-inputs.v1')
for name,encoded in p['files'].items():
 raw=base64.b64decode(encoded,validate=True);pin=x['control_pins'][name[:-3]]
 ok('carrier_bytes_'+name,len(raw)==pin['bytes'])
 ok('carrier_sha_'+name,hashlib.sha256(raw).hexdigest()==pin['sha256'])
 ok('carrier_gitblob_'+name,hashlib.sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest()==pin['blob'])
for f in x['files']:
 i=x['fileinfo'][f['name']]
 ok('actual_fileinfo_'+f['name'],f['path']==i['path'] and f['version']==i['version'] and f['bytes']==i['size'] and f['sha256']==i['sha256'] and f['source_mode']==i['mode'])
 ok('actual_custody_'+f['name'],i['metadata']['uid']==1000 and i['metadata']['link_count']==1)
n=json.loads(x['native']);b=json.loads(x['release']);f=x['files']
ok('raw_native_bytes_sha',len(x['native'].encode())==f[1]['bytes'] and hashlib.sha256(x['native'].encode()).hexdigest()==f[1]['sha256'])
ok('raw_release_bytes_sha',len(x['release'].encode())==f[2]['bytes'] and hashlib.sha256(x['release'].encode()).hexdigest()==f[2]['sha256'])
ok('raw_receipt_commit_tree',n['source_commit']==b['source_commit']==x['commit'] and n['source_tree']==b['source_tree']==x['tree'])
ok('raw_receipt_binary',n['binary_sha256']==b['artifacts']['heptabao-server']['sha256']==f[0]['sha256'] and b['artifacts']['heptabao-server']['bytes']==f[0]['bytes'])
ok('native_provenance',n['provenance']['result_sha256']==f[2]['sha256'])
ok('default_normal_features',n['features']==b['artifacts']['heptabao-server']['features']==['default','native-v6-ha','native-v6-storage'])
ok('normal_completion',n['build_exit_code']==b['build_exit_code']==0 and n['source_freeze_verified'] and b['source_freeze_verified'] and b['normal_default_candidate'] and b['build_finished_success'] and not b['timed_out'] and not b['owned_group_survivors_after_wait'])
ok('abi',n['native_abi']==b['native_abi']=='x86_64-unknown-linux-gnu')
print(json.dumps({'schema':'heptabao.phaseb3cb.transport-carrier-provenance-check.v1','status':'passed','checks':checks,'candidate_modules_executed':False,'product_or_transport_started':False},sort_keys=True))
