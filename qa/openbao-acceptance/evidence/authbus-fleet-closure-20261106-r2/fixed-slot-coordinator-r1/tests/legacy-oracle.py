"""Original source-bound publisher as a synthetic transaction oracle only."""
from pathlib import Path
import hashlib, importlib.util, json, tempfile

path=Path(__file__).resolve().parents[1]/'reference/authbus_coordinator.py'
assert hashlib.sha256(path.read_bytes()).hexdigest()=='cc46822439dfd33c86d1068c886941a92c5581871474cef846d2aee14ce80fe0'
spec=importlib.util.spec_from_file_location('original_coordinator',path)
module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
owner='11111111-1111-4111-8111-111111111111'
credential={'provider':'openai','type':'oauth','access':'synthetic-access-1','refresh':'synthetic-refresh-1','expires':2000000000001,'accountId':'synthetic-account'}
event={'schemaVersion':1,'eventId':'33333333-3333-4333-8333-000000000001','sourceHost':'fixture-host','reason':'new-profile',
       'profileId':'synthetic-profile','credential':credential,'digest':module.digest(credential),'identity':module.identity(credential)}
grant={'authorizationId':'66666666-6666-4666-8666-666666666666','profileId':event['profileId'],'sourceHost':event['sourceHost'],
       'provider':'openai','identityDigest':event['identity'],'expectedCurrentDigest':None,'nextDigest':event['digest']}
class Remote:
    def __init__(self):self.records={}
    def read(self,key,version=None):return json.loads(json.dumps(self.records.get(key)))
    def write(self,key,value,cas):
        assert self.records.get(key,{}).get('version',0)==cas
        self.records[key]={'data':json.loads(json.dumps(value)),'version':cas+1}
        return cas+1
with tempfile.TemporaryDirectory(prefix='heptabao-original-oracle-') as directory:
    remote=Remote();worker=module.Coordinator(remote,Path(directory),owner,['fixture-host'])
    worker.initialize();worker.authorize(grant)
    before=remote.read('manifest')
    worker.commit_event(event['sourceHost'],event['eventId'],event,module.parse_event(event['sourceHost'],event['eventId'],event))
    print(json.dumps({'event':event,'grant':grant,'before':before,'after':remote.records,'syntheticOnly':True},sort_keys=True,separators=(',',':')))
