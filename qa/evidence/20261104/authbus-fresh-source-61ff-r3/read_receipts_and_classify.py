import os,stat,json,hashlib
from pathlib import Path
ROOT=Path('/home/qian-qi/heptabao-ha-closure-20261103-r1/authbus-fresh-source-61ff8bef-r3')
def sha(b): return hashlib.sha256(b).hexdigest()
def read_safe(path,max_bytes):
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW)
    try:
        before=os.fstat(fd)
        assert stat.S_ISREG(before.st_mode) and before.st_uid==os.getuid() and before.st_nlink==1 and before.st_mode & 0o077==0 and before.st_size<=max_bytes
        data=os.read(fd,max_bytes+1)
        assert len(data)==before.st_size
        after=os.fstat(fd);named=os.lstat(path)
        for v in [after,named]:assert (v.st_dev,v.st_ino,v.st_size,v.st_mtime_ns,v.st_ctime_ns)==(before.st_dev,before.st_ino,before.st_size,before.st_mtime_ns,before.st_ctime_ns)
        return data
    finally:os.close(fd)
files=[]
for name in ['result.public.json','outer-result.public.json','request-started.public.json']:
    b=read_safe(ROOT/'native4-r1'/name,32768)
    json.loads(b)
    if name=='outer-result.public.json':assert sha(b)=='32a3353dfb900d4cfc19f0084190f662900d03631f402ca6166563f872f9f6ef'
    files.append({'relative':'native4-r1/'+name,'bytes':len(b),'sha256':sha(b),'text':b.decode()})
body=read_safe(ROOT/'managed1-r1/response.private',4096)
assert len(body)==334 and sha(body)=='2dd8af6137cc2b1f408e76a00ccf6479db404b03f3d383befcb5bc67c3ba2cce'
o=json.loads(body)
allowed_codes={'token_invalidated','invalid_token','token_expired','authentication_error','invalid_authentication','unauthorized','account_deactivated','account_disabled','account_suspended','invalid_jwt','invalid_request_error','insufficient_permissions','permission_denied','session_expired','access_token_expired','invalid_api_key','invalid_authentication_token','token_revoked','invalid_session','expired_token','account_not_found','not_authenticated'}
nodes=[('$',o)]
for prefix in ['error','detail']:
    if isinstance(o,dict) and prefix in o:nodes.append((prefix,o[prefix]))
fields=[];messages=[]
for label,node in nodes:
    if isinstance(node,str):messages.append(node)
    elif isinstance(node,dict):
        for key in ['code','type','error','error_code']:
            if isinstance(node.get(key),str):
                v=node[key];fields.append({'path':label+'.'+key,'recognized':v in allowed_codes,'safeValue':v if v in allowed_codes else None,'valueSha256':sha(v.encode())})
        for key in ['message','detail','error_description']:
            if isinstance(node.get(key),str):messages.append(node[key])
message_text='\n'.join(messages).lower()
terms={
 'tokenExpired':('token' in message_text and ('expired' in message_text or 'expiration' in message_text)),
 'tokenInvalidated':('token' in message_text and 'invalidated' in message_text),
 'tokenRevoked':('token' in message_text and 'revoked' in message_text),
 'invalidToken':('invalid token' in message_text or 'token is invalid' in message_text),
 'accountDeactivated':('account' in message_text and 'deactivat' in message_text),
 'accountDisabled':('account' in message_text and 'disabled' in message_text),
 'accountSuspended':('account' in message_text and 'suspend' in message_text),
 'signInAgainRequested':('sign in again' in message_text or 'signing in again' in message_text or 'log in again' in message_text),
 'permissionMentioned':('permission' in message_text or 'privilege' in message_text),
 'geographyMentioned':any(s in message_text for s in ['country','region','geograph']),
}
classification={'schema':'heptabao.provider-401-safe-classification.v1','providerCalled':False,'sourceReadOnly':True,'responseSha256':sha(body),'responseBytes':len(body),'responseJsonType':type(o).__name__,'topKnownKeys':{k:isinstance(o,dict) and k in o for k in ['error','detail','message','code','type']},'safeErrorFields':fields,'messageCount':len(messages),'messageTermPredicates':terms,'messageDigests':[sha(m.encode()) for m in messages],'rawBodyPublished':False,'accountIdentitiesPublished':False,'freshCredentialUsed':False,'automaticRetry':False,'refreshAttempted':False}
print(json.dumps({'schema':'heptabao.fresh-source-r3-readonly-receipt-export.v1','nativeFiles':files,'managed401Classification':classification},sort_keys=True,separators=(',',':')))
