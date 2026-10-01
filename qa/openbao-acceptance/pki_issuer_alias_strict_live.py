#!/usr/bin/env python3
"""Finite 2.7 issuer alias comparison; original discovery receipts stay separate."""
import argparse
import base64
import hashlib
import json
import importlib.util
import os
from pathlib import Path
import socket
import ssl
import subprocess
import sys
import threading
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

ROUTES = ('json', 'der', 'pem', 'crl', 'crl/der', 'crl/pem',
          'crl/delta', 'crl/delta/der', 'crl/delta/pem')
REFERENCES = ('default', 'id', 'name')
MODES = ('absent', 'empty')
SETUP = ('provider_health', 'consumer_health', 'distinct_clusters', 'provider_mount',
         'provider_key', 'provider_public', 'configuration', 'mapping', 'mount',
         'grant', 'root', 'root_binding', 'full_cache', 'delta_cache')
EXPECTED = (SETUP + tuple(f'public.{m}.{r}.{route}' for m in MODES for r in REFERENCES for route in ROUTES)
            + tuple(f'unknown.{r}.{route}' for r in ('name', 'id') for route in ROUTES)
            + ('restart_health',) + tuple(f'restart.{r}.{route}' for r in REFERENCES for route in ROUTES)
            + ('owned_cleanup',))
BINARY_SHA = '9403c2b121e13fe79b3182051320d2096d10519b597ee587e322dab5e359c51e'
ARCHIVE_SHA = 'c3ab5de9e778223445487ccbfb16c291bf491642b688f3a3df5aeba23d9b3667'

def private_fields_absent(value):
    if isinstance(value, dict):
        return not any(k in ('private_key', 'token', 'external_key_ref') for k in value) and all(private_fields_absent(v) for v in value.values())
    if isinstance(value, list):
        return all(private_fields_absent(v) for v in value)
    return True

def trace_complete(rows):
    return (type(rows) is list and all(type(r) is dict for r in rows)
            and tuple(r.get('case') for r in rows) == EXPECTED
            and rows[-1].get('all_owned_stopped') is True)

def safe_unknown_response(status, media, body, signs):
    def material_absent(value):
        if isinstance(value,dict):
            return not any(k in ('certificate','ca_chain','crl','public_key','csr') for k in value) and all(material_absent(v) for v in value.values())
        if isinstance(value,list):return all(material_absent(v) for v in value)
        return True
    return (type(status) is int and status == 500 and media == 'application/json'
            and type(body) is dict and body.get('data') is None
            and type(body.get('errors')) is list and bool(body['errors'])
            and all(type(e) is str for e in body['errors']) and private_fields_absent(body) and material_absent(body)
            and type(signs) is int and signs == 0)

MEDIA = {'json':'application/json', 'der':'application/pkix-cert',
         'pem':'application/pem-certificate-chain', 'crl':'application/json',
         'crl/der':'application/pkix-crl', 'crl/pem':'application/x-pem-file',
         'crl/delta':'application/json', 'crl/delta/der':'application/pkix-crl',
         'crl/delta/pem':'application/x-pem-file'}

def exact_projection(row, suffix, negative=False):
    if (type(row) is not dict or type(row.get('status')) is not int
            or type(row.get('provider_sign_entries')) is not int
            or row['provider_sign_entries'] != 0
            or type(row.get('audit_request_delta')) is not int or row['audit_request_delta'] != 1
            or type(row.get('audit_response_delta')) is not int or row['audit_response_delta'] != 1
            or row.get('passed') is not True): return False
    if negative:
        return (row['status'] == 500 and row.get('content_type') == 'application/json'
            and row.get('data_fields') == [] and row.get('private_fields_absent') is True
            and row.get('no_material') is True and row.get('not_default_material') is True)
    if (suffix not in MEDIA or row['status'] != 200 or row.get('content_type') != MEDIA[suffix]
            or any(row.get(k) is not True for k in ('public_material_valid','exact_original_der','private_fields_absent'))): return False
    is_der = suffix == 'der' or suffix.endswith('/der')
    if row.get('pem_final_lf_count') != (None if is_der else 1): return False
    if suffix == 'json':
        return (row.get('data_fields') == ['ca_chain','certificate','issuer_id','issuer_name']
            and row.get('data_field_types') == {'ca_chain':'list','certificate':'str','issuer_id':'str','issuer_name':'str'}
            and row.get('issuer_id_exact') is True and row.get('issuer_name_exact') is True
            and row.get('chain_exact_original_certificate') is True)
    if suffix in ('crl','crl/delta'):
        return row.get('data_fields') == ['crl'] and row.get('data_field_types') == {'crl':'str'}
    return 'data_fields' not in row and 'data_field_types' not in row

def observation_contract_complete(rows):
    if not trace_complete(rows) or any(r.get('passed') is not True for r in rows): return False
    statuses={'provider_health':200,'consumer_health':200,'provider_mount':204,
        'provider_key':200,'provider_public':200,'configuration':204,'mapping':204,
        'mount':204,'grant':204,'root':200,'full_cache':200,'delta_cache':200,'restart_health':200}
    indexed={r['case']:r for r in rows}
    if any(type(indexed[k].get('status')) is not int or indexed[k]['status'] != v for k,v in statuses.items()):return False
    if not exact_projection(indexed['full_cache'],'crl/der') or not exact_projection(indexed['delta_cache'],'crl/delta/der'):return False
    if type(indexed['root'].get('provider_sign_entries')) is not int or indexed['root']['provider_sign_entries'] != 3:return False
    bound=indexed['root_binding']
    if (bound.get('public_key_bound') is not True or bound.get('private_fields_absent') is not True
        or type(bound.get('root_sign_entries')) is not int or bound['root_sign_entries'] != 3):return False
    for row in rows:
        case=row['case']
        if case.startswith(('public.','restart.','unknown.')):
            suffix=case.split('.',3)[3] if case.startswith('public.') else case.split('.',2)[2]
            if not exact_projection(row,suffix,case.startswith('unknown.')):return False
    return True

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', required=True); parser.add_argument('--root', required=True)
    parser.add_argument('--mode',choices=('oracle','paired'),required=True)
    parser.add_argument('--binary');parser.add_argument('--expected-binary-sha256')
    parser.add_argument('--expected-source-commit', required=True); parser.add_argument('--expected-source-tree', required=True)
    a = parser.parse_args(); os.umask(0o077)
    root = Path(a.root); root.mkdir(mode=0o700, exist_ok=False); source = Path(a.source).resolve(strict=True)
    def identity():
        return {'commit': subprocess.check_output(['git','rev-parse','HEAD'],cwd=source,text=True).strip(),
                'tree': subprocess.check_output(['git','rev-parse','HEAD^{tree}'],cwd=source,text=True).strip(),
                'dirty': bool(subprocess.check_output(['git','status','--porcelain','--untracked-files=all'],cwd=source))}
    candidate=None; binary_before=None
    if a.mode=='paired':
        if not a.binary or not a.expected_binary_sha256: raise RuntimeError('candidate_identity_required')
        candidate=Path(a.binary).resolve(strict=True)
        with candidate.open('rb') as stream:binary_before=hashlib.file_digest(stream,'sha256').hexdigest()
        if binary_before!=a.expected_binary_sha256:raise RuntimeError('candidate_identity_mismatch')
    before = identity()
    if before != {'commit':a.expected_source_commit,'tree':a.expected_source_tree,'dirty':False}: raise RuntimeError('source_identity_mismatch')
    sys.path.insert(0, str(source/'qa/openbao-acceptance'))
    import official_openbao_launcher as launcher
    from bao_http import Client as OriginalClient, NoRedirect, private_read
    from cryptography import x509
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ed25519
    class Client(OriginalClient):
        def __init__(self,*args,**kwargs): kwargs['timeout']=2; super().__init__(*args,**kwargs)
    launcher.Client = Client
    os.environ.update(HB_ORACLE_WORK_ROOT=str(root), TMPDIR=str(root),
        HB_ORACLE_BINARY='/home/qian/work/heptabao-linux-a40fe653-20260930/oracle270/bao',
        HB_ORACLE_ARCHIVE='/home/qian/work/heptabao-linux-a40fe653-20260930/oracle270/official-verified-2.7.0-linux-amd64.tar.gz')
    def pins(): return {k:launcher.file_digest(os.environ[v]) for k,v in
        (('binary_sha256','HB_ORACLE_BINARY'),('archive_sha256','HB_ORACLE_ARCHIVE'))}
    original_pins=pins()
    if original_pins != {'binary_sha256':BINARY_SHA,'archive_sha256':ARCHIVE_SHA}: raise RuntimeError('oracle_identity_mismatch')
    rows=[]; instances=[]; handles=[]; proxy=None; thread=None; sign_entries=[]; failure=None; native=None; unseal=None
    def note(case, **v):
        rows.append({'case':case,**v})
        (root/'partial-observations.json').write_text(json.dumps({'observations':rows},indent=2)+'\n')
    def port():
        with socket.socket() as s: s.bind(('127.0.0.1',0)); return s.getsockname()[1]
    def request(client, method, path, case, body=None, expected=200):
        n=len(sign_entries); response=client.request(method,'/v1/'+path,body)
        note(case,status=response.status,provider_sign_entries=len(sign_entries)-n,passed=response.status==expected)
        if response.status!=expected: raise RuntimeError('setup_status_mismatch')
        return response.body.get('data',{})
    def verify(public,obj,crl=False):
        try: public.verify(obj.signature,obj.tbs_certlist_bytes if crl else obj.tbs_certificate_bytes); return True
        except Exception: return False
    try:
        provider=launcher.start_oracle(port(),version='2.7.0',audit_file=True); instances.append(provider);handles.append(provider['process'])
        p=Client(provider['address'],provider['ca_file'],private_read(provider['token_file'],8192).decode().strip())
        tls=root/'proxy'; tls.mkdir(mode=0o700); launcher.certificates(tls)
        provider_opener=urllib.request.build_opener(NoRedirect(),urllib.request.ProxyHandler({}),urllib.request.HTTPSHandler(context=ssl.create_default_context(cafile=provider['ca_file'])))
        class Proxy(BaseHTTPRequestHandler):
            def log_message(self,*args): pass
            def dispatch(self):
                try:
                    n=int(self.headers.get('Content-Length','0'))
                    if not 0<=n<=2**20: raise ValueError('request_bounds')
                    payload=self.rfile.read(n)
                    if self.path=='/v1/transit/sign/remote': sign_entries.append(self.command)
                    headers={k:self.headers[k] for k in ('X-Vault-Token','X-Vault-Namespace','Content-Type') if k in self.headers}
                    req=urllib.request.Request(provider['address']+self.path,data=payload if self.command!='GET' else None,headers=headers,method=self.command)
                    try: response=provider_opener.open(req,timeout=2)
                    except urllib.error.HTTPError as e: response=e
                    with response: raw=response.read(2**20+1); status=response.status; media=response.headers.get('Content-Type','application/json')
                    if len(raw)>2**20: raise ValueError('response_bounds')
                    self.send_response(status); self.send_header('Content-Type',media); self.send_header('Content-Length',str(len(raw))); self.end_headers(); self.wfile.write(raw)
                except Exception:
                    try: self.send_response(502); self.send_header('Content-Length','0'); self.end_headers()
                    except Exception: pass
            do_GET=dispatch; do_POST=dispatch; do_PUT=dispatch
        proxy=ThreadingHTTPServer(('127.0.0.1',port()),Proxy); proxy.daemon_threads=True
        context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER); context.load_cert_chain(str(tls/'tls.crt'),str(tls/'tls.key'))
        proxy.socket=context.wrap_socket(proxy.socket,server_side=True)
        thread=threading.Thread(target=proxy.serve_forever,daemon=True); thread.start()
        if a.mode=='oracle':
            consumer=launcher.start_oracle(port(),version='2.7.0',audit_file=True); instances.append(consumer);handles.append(consumer['process'])
        else:
            spec=importlib.util.spec_from_file_location('pki_alias_smoke',source/'qa/single-node/smoke.py')
            smoke=importlib.util.module_from_spec(spec);spec.loader.exec_module(smoke)
            import external_pki_public_live as public_profile
            native=public_profile.bounded_native_instance(smoke,candidate,root/'candidate')
            public_profile.shared.native_configuration(native,{'address':'https://127.0.0.1:'+str(proxy.server_port)},(tls/'ca.crt').read_text())
            native.start();handles.append(native.process)
            status,initialized=native.call('POST','sys/init',{'secret_shares':1,'secret_threshold':1})
            if status!=200:raise RuntimeError('candidate_init_failed')
            native.token=initialized['root_token'];unseal=initialized['keys_base64'][0]
            if native.call('POST','sys/unseal',{'key':unseal})[0]!=200:raise RuntimeError('candidate_unseal_failed')
            token_file=native.root/'probe-token';token_file.write_text(native.token);token_file.chmod(0o600)
            consumer={'address':native.address,'ca_file':str(native.root/'ca.crt'),'token_file':str(token_file),'root':str(native.root)}
        c=Client(consumer['address'],consumer['ca_file'],private_read(consumer['token_file'],8192).decode().strip())
        for name,instance,client in (('provider_health',provider,p),('consumer_health',consumer,c)):
            response=client.request('GET','/v1/sys/health')
            if name=='provider_health' or a.mode=='oracle':launcher.verify_selected_oracle(instance,response.body,version='2.7.0')
            elif response.status!=200 or response.body.get('initialized') is not True or response.body.get('sealed') is not False:raise RuntimeError('candidate_health_failed')
            note(name,status=response.status,passed=response.status==200);instance['cluster_id']=response.body['cluster_id']
        distinct=provider['cluster_id']!=consumer['cluster_id']; note('distinct_clusters',passed=distinct)
        if not distinct:raise RuntimeError('clusters_not_distinct')
        request(p,'POST','sys/mounts/transit','provider_mount',{'type':'transit'},204)
        request(p,'POST','transit/keys/remote','provider_key',{'type':'ed25519'})
        desc=request(p,'GET','transit/keys/remote','provider_public')
        public=ed25519.Ed25519PublicKey.from_public_bytes(base64.b64decode(desc['keys']['1']['public_key'],validate=True))
        cfg='sys/external-keys/configs/remote'
        request(c,'POST',cfg,'configuration',{'plugin':'transit','address':'https://127.0.0.1:'+str(proxy.server_port),'token':private_read(provider['token_file'],8192).decode().strip(),'mount_path':'transit','tls_ca_cert_bytes':(tls/'ca.crt').read_text(),'verify':True},204)
        request(c,'POST',cfg+'/keys/fixed','mapping',{'name':'remote','version':1,'verify':True},204)
        request(c,'POST','sys/mounts/pki','mount',{'type':'pki'},204)
        request(c,'POST',cfg+'/keys/fixed/grants/pki','grant',{},204)
        authority=request(c,'POST','pki/root/generate/kms','root',{'external_key_ref':'remote:fixed','common_name':'aliases.example.test','issuer_name':'primary','ttl':'1h'})
        certificate=x509.load_pem_x509_certificate(authority['certificate'].encode()); expected_der=certificate.public_bytes(serialization.Encoding.DER)
        bound=verify(public,certificate) and certificate.public_key().public_bytes(serialization.Encoding.Raw,serialization.PublicFormat.Raw)==public.public_bytes(serialization.Encoding.Raw,serialization.PublicFormat.Raw)
        note('root_binding',passed=bound,public_key_bound=bound,private_fields_absent=private_fields_absent(authority),root_sign_entries=rows[-1]['provider_sign_entries'])
        if not bound or rows[-1]['private_fields_absent'] is not True or rows[-1]['root_sign_entries']!=3: raise RuntimeError('root_binding_failed')
        references={'default':'default','id':authority['issuer_id'],'name':'primary'}
        opener=urllib.request.build_opener(NoRedirect(),urllib.request.ProxyHandler({}),urllib.request.HTTPSHandler(context=ssl.create_default_context(cafile=consumer['ca_file'])))
        caches={}
        def audit_count():
            counts={'request':0,'response':0}
            for line in (Path(consumer['root'])/'audit.jsonl').read_text().splitlines():
                kind=json.loads(line).get('type')
                if kind in counts: counts[kind]+=1
            return counts
        def read(path,case,mode='absent',kind=None,negative=False):
            headers={} if mode=='absent' else {'X-Vault-Token':''}; n=len(sign_entries); audit=audit_count()
            req=urllib.request.Request(consumer['address']+'/v1/'+path,headers=headers,method='GET')
            try: response=opener.open(req,timeout=2)
            except urllib.error.HTTPError as e: response=e
            with response: raw=response.read(2**20+1); status=response.status; media=response.headers.get('Content-Type','').split(';')[0]
            if len(raw)>2**20: raise RuntimeError('bounded_response_failed')
            after=audit_count(); row={'status':status,'provider_sign_entries':len(sign_entries)-n,'content_type':media,
                'audit_request_delta':after['request']-audit['request'],'audit_response_delta':after['response']-audit['response']}
            data=None; body=None
            if media=='application/json':
                body=json.loads(raw); data=body.get('data'); row['data_fields']=sorted(data) if isinstance(data,dict) else []; row['private_fields_absent']=private_fields_absent(body)
            if negative:
                safe=safe_unknown_response(status,media,body,row['provider_sign_entries'])
                row.update(no_material=safe,not_default_material=safe,passed=safe)
                row['passed']=exact_projection(row,kind,True)
            elif status==200:
                is_crl=kind.startswith('crl') if kind else path.endswith('crl') or 'delta' in path
                material=raw
                if data is not None:
                    field='crl' if is_crl else 'certificate'; material=data[field].encode()
                    row['data_field_types']={k:type(v).__name__ for k,v in data.items()}
                obj=(x509.load_pem_x509_crl(material) if material.startswith(b'-----') else x509.load_der_x509_crl(material)) if is_crl else (x509.load_pem_x509_certificate(material) if material.startswith(b'-----') else x509.load_der_x509_certificate(material))
                der=obj.public_bytes(serialization.Encoding.DER); valid=verify(public,obj,is_crl)
                selected='delta' if (kind and 'delta' in kind) or 'delta' in path else 'full'
                same=der==(caches[selected] if is_crl and selected in caches else expected_der) if not is_crl or selected in caches else True
                row.update(public_material_valid=valid,exact_original_der=same,private_fields_absent=row.get('private_fields_absent',True),pem_final_lf_count=len(material)-len(material.rstrip(b'\n')) if material.startswith(b'-----') else None,
                    passed=valid and same and row.get('private_fields_absent',True) and row['provider_sign_entries']==0)
                if not is_crl and kind=='json':
                    row.update(issuer_id_exact=data.get('issuer_id')==authority['issuer_id'],
                        issuer_name_exact=data.get('issuer_name')=='primary',
                        chain_exact_original_certificate=data.get('ca_chain')==[certificate.public_bytes(serialization.Encoding.PEM).decode()])
                if kind is not None:
                    row['passed']=exact_projection(row,kind)
                if is_crl:caches.setdefault(selected,der)
            else: row['passed']=False
            note(case,**row)
        read('pki/crl','full_cache'); read('pki/crl/delta','delta_cache')
        for mode in MODES:
            for ref in REFERENCES:
                for route in ROUTES: read('pki/issuer/'+references[ref]+'/'+route,f'public.{mode}.{ref}.{route}',mode,route)
        for ref,value in (('name','unknown-issuer'),('id','00000000-0000-4000-8000-000000000000')):
            for route in ROUTES: read('pki/issuer/'+value+'/'+route,f'unknown.{ref}.{route}',kind=route,negative=True)
        if a.mode=='oracle':launcher.stop_oracle(consumer);launcher.restart_oracle(consumer);handles.append(consumer['process'])
        else:
            native.stop();native.start();handles.append(native.process)
            if native.call('POST','sys/unseal',{'key':unseal})[0]!=200:raise RuntimeError('candidate_restart_unseal_failed')
        health=c.request('GET','/v1/sys/health')
        if a.mode=='oracle':launcher.verify_selected_oracle(consumer,health.body,version='2.7.0')
        elif health.status!=200 or health.body.get('initialized') is not True or health.body.get('sealed') is not False:raise RuntimeError('candidate_restart_health_failed')
        note('restart_health',status=health.status,passed=health.status==200)
        for ref in REFERENCES:
            for route in ROUTES: read('pki/issuer/'+references[ref]+'/'+route,f'restart.{ref}.{route}',kind=route)
    except Exception as e: failure=type(e).__name__
    finally:
        if proxy is not None: proxy.shutdown(); proxy.server_close()
        if thread is not None: thread.join(timeout=2)
        if native is not None:native.stop()
        for instance in reversed(instances): launcher.stop_oracle(instance)
        cleared=bool(handles) and all(handle.poll() is not None for handle in handles) and (thread is None or not thread.is_alive())
        note('owned_cleanup',all_owned_stopped=cleared,passed=cleared)
        after=identity(); final_pins=pins(); complete=observation_contract_complete(rows)
        binary_after=None
        if candidate is not None:
            with candidate.open('rb') as stream:binary_after=hashlib.file_digest(stream,'sha256').hexdigest()
        report={'schema':'heptabao.pki270-issuer-alias-strict.v2','oracle_only':a.mode=='oracle','candidate_evidence':a.mode=='paired',
            'candidate_binary_sha256_before':binary_before,'candidate_binary_sha256_after':binary_after,'candidate_binary_identity_same':binary_before==binary_after,
            'full_openbao_compatibility':False,'production_authority':False,'independent_qualification':False,
            'source_before':before,'source_after':after,'oracle_before':original_pins,'oracle_after':final_pins,
            'source_identity_same':after==before,'oracle_identity_same':original_pins==final_pins,'runner_sha256':launcher.file_digest(__file__),
            'fixed_case_count':len(EXPECTED),'actual_case_count':len(rows),'fixed_trace_complete':complete,'observations':rows,
            'http_timeout_seconds':2,'outer_timeout_seconds':360,'business_mutation_retry':False,'failure_type':failure,
            'all_observed_predicates_true':all(r.get('passed') is True for r in rows),'owned_processes_stopped':cleared}
        (root/'summary.json').write_text(json.dumps(report,indent=2)+'\n')
    return 0 if failure is None and complete and cleared and before==after and original_pins==final_pins and binary_before==binary_after and report['all_observed_predicates_true'] else 1

if __name__=='__main__': raise SystemExit(main())
