#!/usr/bin/env python3
"""Selected remote JWT-key behavior vs pinned official OpenBao 2.6.2.

The two servers use the SAME HTTPS issuer and signed claim scenarios. Candidate
CA/egress is enrolled at process startup; Oracle CA is configured on its auth
mount. These deployment differences are disclosed, not normalized away into
API-format parity. The test does not exercise browser OIDC code flow.
"""
from __future__ import annotations
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import socket
import tempfile
from bao_http import Client,private_read
from core_isolation import successful_comparison
from official_openbao_launcher import start_oracle,stop_oracle,BINARY_SHA256
from remote_jwks_live import Instance,JsonIssuer,signing_key,token


def scenarios(client,issuer,ca,is_oracle,results):
    def check(case,condition):
        results.append(dict(case=case,passed=condition is True))
        if condition is not True:raise RuntimeError(case)
    def call(method,path,body=None):return client.request(method,'/v1/'+path,body)
    origin=issuer.origin
    for mode in ('direct','discovery'):
        mount='keys-'+mode
        private,jwk=signing_key('RS256','rsa-a')
        issuer.documents['/keys']={'keys':[jwk]}
        issuer.documents['/.well-known/openid-configuration']={'issuer':origin,'jwks_uri':origin+'/keys','authorization_endpoint':origin+'/authorize','token_endpoint':origin+'/token','response_types_supported':['code'],'subject_types_supported':['public'],'id_token_signing_alg_values_supported':['RS256','ES256','EdDSA']}
        check(mode+'.mount',call('POST','sys/auth/'+mount,{'type':'jwt'}).status==204)
        config={'bound_issuer':origin,'jwt_supported_algs':['RS256','ES256','EdDSA']}
        if mode=='direct':config['jwks_url']=origin+'/keys'
        else:config['oidc_discovery_url']=origin
        if is_oracle:config['jwks_ca_pem' if mode=='direct' else 'oidc_discovery_ca_pem']=ca
        check(mode+'.configure',call('POST','auth/'+mount+'/config',config).status==204)
        check(mode+'.role',call('POST','auth/'+mount+'/role/test',{'role_type':'jwt','user_claim':'sub','bound_audiences':['heptabao-test'],'token_policies':['default'],'token_ttl':60}).status==204)
        def login(jwt):return call('POST','auth/'+mount+'/login',{'role':'test','jwt':jwt})
        response=login(token(private,jwk,origin));check(mode+'.rsa_login',response.status==200)
        entity=response.body.get('auth',{}).get('entity_id')
        check(mode+'.identity_bound',isinstance(entity,str) and bool(entity))
        check(mode+'.issuer_rejected',login(token(private,jwk,'https://wrong.invalid:443')).status>=400)
        check(mode+'.audience_rejected',login(token(private,jwk,origin,aud='wrong')).status>=400)
        check(mode+'.expired_rejected',login(token(private,jwk,origin,iat=1000,exp=1001)).status>=400)
        private2,jwk2=signing_key('ES256','p256-b');issuer.documents['/keys']={'keys':[jwk,jwk2]}
        response=login(token(private2,jwk2,origin));check(mode+'.new_p256_key_refresh',response.status==200)
        check(mode+'.stable_subject_identity',response.body.get('auth',{}).get('entity_id')==entity)
        # Do not assert Oracle immediately retires a removed cached key: it may
        # cache keys. Exact candidate no-stale tests are a separate profile.
        check(mode+'.config_source_exclusivity',call('POST','auth/'+mount+'/config',dict(config,jwks_url=origin+'/keys',oidc_discovery_url=origin)).status>=400)
        check(mode+'.rejected_config_preserves_predecessor',login(token(private2,jwk2,origin)).status==200)
    return results


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--binary',required=True);p.add_argument('--output',required=True);a=p.parse_args()
    out=Path(a.output).resolve();binary=Path(a.binary).resolve(strict=True)
    if out.exists():p.error('output must be new')
    root=Path(tempfile.mkdtemp(prefix='hb-jwks-compare-'));instance=Instance(binary,root/'candidate');issuer=JsonIssuer(instance.root/'tls.crt',instance.root/'tls.key');oracle=None
    digest=hashlib.sha256(binary.read_bytes()).hexdigest()
    report={'schema':'heptabao.remote-jwt-selected-comparison.v1','target_version':'2.6.2','candidate_binary_sha256':digest,'oracle_binary_sha256':BINARY_SHA256,'cases':{},'side_failures':{},'independent_qualification':False,'full_openbao_compatibility':False,'deployment_difference':'candidate startup-pinned egress/CA versus oracle per-mount CA; not configuration API equivalence','excluded':'browser code flow, immediate Oracle cache invalidation, jti replay parity, arbitrary claims mappings'}
    try:
        cpath=instance.root/'server.json';cfg=json.loads(cpath.read_text());ca=(instance.root/'ca.crt').read_text()
        cfg['outbound_endpoints']=[dict(origin=issuer.origin,address=f'127.0.0.1:{issuer.port}',server_name='localhost',ca_pem=ca)]
        cpath.write_text(json.dumps(cfg));cpath.chmod(0o600);instance.start()
        status,init=instance.call('POST','sys/init',{'secret_shares':1,'secret_threshold':1})
        if status!=200:raise RuntimeError('init')
        instance.token=init['root_token']
        if instance.call('POST','sys/unseal',{'key':init['keys_base64'][0]})[0]!=200:raise RuntimeError('unseal')
        with socket.socket() as s:s.bind(('127.0.0.1',0));port=s.getsockname()[1]
        oracle=start_oracle(port)
        clients=[('candidate',Client(instance.address,str(instance.root/'ca.crt'),instance.token),False),('oracle',Client(oracle['address'],oracle['ca_file'],private_read(oracle['token_file'],8192).decode().strip()),True)]
        for name,client,flag in clients:
            result=[];report['cases'][name]=result
            try:scenarios(client,issuer,ca,flag,result)
            except Exception as e:report['side_failures'][name]=str(e) if type(e) is RuntimeError else type(e).__name__
        report['cases_match']=report['cases']['candidate']==report['cases']['oracle']
        report['status']='passed' if successful_comparison(report['cases'],report['side_failures']) else 'mismatch'
    except Exception as e:report.update(status='failed',failure=str(e) if type(e) is RuntimeError else type(e).__name__)
    finally:
        instance.stop();issuer.close()
        if oracle is not None:stop_oracle(oracle);shutil.rmtree(oracle['root'])
        shutil.rmtree(root);report['candidate_binary_unchanged']=hashlib.sha256(binary.read_bytes()).hexdigest()==digest
        if not report['candidate_binary_unchanged']:report['status']='failed'
        report['case_count_per_side']=len(report['cases'].get('candidate',[]));out.write_text(json.dumps(report,indent=2)+'\n');out.chmod(0o600)
    print(json.dumps({k:report.get(k) for k in ('status','side_failures','case_count_per_side','failure')}))
    return 0 if report['status']=='passed' else 1
if __name__=='__main__':raise SystemExit(main())
