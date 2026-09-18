#!/usr/bin/env python3
"""Synthetic, actual Kubernetes API/etcd/RBAC acceptance in a new local KIND node.

Never connects to an existing kubeconfig or cluster. A missing actual binary or
local Docker daemon is exit 77, not success. No runtime credentials are uploaded.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import secrets
import shutil
import ssl
import stat
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request

import yaml

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'clients/python'))
sys.path.insert(0, str(ROOT / 'qa/single-node'))
from smoke import Instance
from bao_http import SafeArgumentParser
from online_evidence import admit_output, source_identity, publish

KIND_VERSION = '0.31.0'
KIND_SHA256 = 'eb244cbafcc157dff60cf68693c14c9a75c4e6e6fedaf9cd71c58117cb93e3fa'
NODE_IMAGE = 'kindest/node:v1.35.0@sha256:452d707d4862f52530247495d180205e029056831160e22870e37e3f6c1ac31f'
DOCKER_SOCKET = 'unix:///var/run/docker.sock'
AUDIENCE = 'heptabao-real-kubernetes'
EXPECTED_CHECKS = 45


class PrerequisiteMissing(Exception):
    pass


class FixtureFailure(Exception):
    pass


def private(path: Path, data: bytes) -> None:
    fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'wb') as f:
        f.write(data)


def local_environment(environment: dict[str, str]) -> dict[str, str]:
    """Do not let ambient Docker/Kubernetes routing reach an operator's cluster."""
    if environment.get('DOCKER_HOST') not in (None, '', DOCKER_SOCKET):
        raise FixtureFailure('nonlocal_docker_routing_rejected')
    if environment.get('DOCKER_CONTEXT') not in (None, '', 'default'):
        raise FixtureFailure('nondefault_docker_context_rejected')
    result = {k: v for k, v in environment.items()
              if not k.startswith(('DOCKER_', 'KUBE', 'KIND_'))}
    result['DOCKER_HOST'] = DOCKER_SOCKET
    result['KIND_EXPERIMENTAL_PROVIDER'] = 'docker'
    return result


def validate_binary(binary: Path, expected: str) -> Path:
    original = binary.absolute()
    info = original.lstat()
    if not stat.S_ISREG(info.st_mode) or original.is_symlink() or not os.access(original, os.X_OK):
        raise FixtureFailure('prerequisite_binary_not_regular_executable')
    if not re.fullmatch(r'[0-9a-f]{64}', expected):
        raise FixtureFailure('invalid_prerequisite_digest')
    with original.open('rb') as f:
        actual = hashlib.file_digest(f, 'sha256').hexdigest()
    if actual != expected:
        raise FixtureFailure('prerequisite_binary_digest_mismatch')
    return original


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        raise FixtureFailure('api_redirect_rejected')


def kubeconfig_material(document: dict, cluster_name: str) -> tuple[str, bytes, bytes, bytes]:
    """Admit only the single newly generated, embedded-certificate KIND config."""
    expected = 'kind-' + cluster_name
    if not isinstance(document, dict) or document.get('current-context') != expected:
        raise FixtureFailure('unexpected_kube_context')
    try:
        clusters, users, contexts = document['clusters'], document['users'], document['contexts']
        if len(clusters) != 1 or len(users) != 1 or len(contexts) != 1:
            raise ValueError('multiple contexts')
        c, u, x = clusters[0], users[0], contexts[0]
        if c['name'] != expected or u['name'] != expected or x['name'] != expected:
            raise ValueError('wrong names')
        if x['context']['cluster'] != expected or x['context']['user'] != expected:
            raise ValueError('wrong binding')
        c, u = c['cluster'], u['user']
        if set(c) != {'server', 'certificate-authority-data'}:
            raise ValueError('non-embedded server trust')
        if set(u) != {'client-certificate-data', 'client-key-data'}:
            raise ValueError('external or exec credential')
        url = urllib.parse.urlsplit(c['server'])
        if (url.scheme != 'https' or url.hostname != '127.0.0.1' or url.username or url.password
                or url.path or url.query or url.fragment or not url.port or not 1024 <= url.port <= 65535):
            raise ValueError('nonlocal origin')
        material = [base64.b64decode(v, validate=True) for v in
                    (c['certificate-authority-data'], u['client-certificate-data'], u['client-key-data'])]
        if any(not 32 <= len(v) <= 32768 for v in material):
            raise ValueError('credential bounds')
        return c['server'], *material
    except (KeyError, TypeError, ValueError) as error:
        raise FixtureFailure('unsafe_generated_kubeconfig') from error


class Cluster:
    def __init__(self, kind: Path, root: Path):
        self.kind, self.root = kind, root
        self.name = 'hb-accept-' + secrets.token_hex(8)
        self.env = local_environment(dict(os.environ))
        self.attempted = False
        self.opener = None

    def command(self, args: list[str], timeout: int = 180) -> None:
        with (self.root / 'kind-private.log').open('ab') as log:
            result = subprocess.run([str(self.kind), *args], env=self.env, stdin=subprocess.DEVNULL,
                                    stdout=log, stderr=log, timeout=timeout, check=False)
        if result.returncode:
            raise FixtureFailure('kind_command_failed')

    def start(self) -> None:
        self.root.mkdir(mode=0o700)
        self.root.chmod(0o700)
        config = {'kind':'Cluster', 'apiVersion':'kind.x-k8s.io/v1alpha4',
                  'networking':{'apiServerAddress':'127.0.0.1'},
                  'nodes':[{'role':'control-plane'}]}
        private(self.root/'kind.json', json.dumps(config).encode())
        self.attempted = True
        self.command(['create', 'cluster', '--name', self.name, '--image', NODE_IMAGE,
                      '--config', str(self.root/'kind.json'), '--kubeconfig', str(self.root/'kubeconfig'),
                      '--wait', '120s'], 240)
        cfg = self.root/'kubeconfig'
        if cfg.is_symlink() or not stat.S_ISREG(cfg.lstat().st_mode):
            raise FixtureFailure('generated_kubeconfig_not_regular')
        cfg.chmod(0o600)
        self.origin, ca, cert, key = kubeconfig_material(yaml.safe_load(cfg.read_text()), self.name)
        self.ca = ca
        private(self.root/'ca.pem', ca)
        private(self.root/'client.pem', cert)
        private(self.root/'client.key', key)
        context = ssl.create_default_context(cadata=ca.decode())
        context.load_cert_chain(self.root/'client.pem', self.root/'client.key')
        self.opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect(),
                                                 urllib.request.HTTPSHandler(context=context))

    def call(self, method: str, path: str, body=None):
        if (method not in ('GET','POST','DELETE') or not path.startswith('/')
                or path.startswith('//') or '..' in path or '?' in path or '#' in path):
            raise FixtureFailure('api_path_rejected')
        data = None if body is None else json.dumps(body).encode()
        request = urllib.request.Request(self.origin+path, data=data, method=method,
                                         headers={'Content-Type':'application/json'})
        try:
            response = self.opener.open(request, timeout=10)
        except urllib.error.HTTPError as error:
            response = error
        with response:
            raw = response.read(256*1024+1)
            if len(raw) > 256*1024:
                raise FixtureFailure('api_response_oversized')
            return response.code, json.loads(raw)

    def post(self, path: str, value: dict):
        status, body = self.call('POST', path, value)
        if status not in (200,201):
            raise FixtureFailure('api_mutation_failed')
        return body

    def service_account(self, namespace: str, name: str):
        return self.post(f'/api/v1/namespaces/{namespace}/serviceaccounts',
                         {'apiVersion':'v1','kind':'ServiceAccount','metadata':{'name':name}})

    def token(self, namespace: str, name: str, audience: str):
        result = self.post(f'/api/v1/namespaces/{namespace}/serviceaccounts/{name}/token',
                           {'apiVersion':'authentication.k8s.io/v1','kind':'TokenRequest',
                            'spec':{'audiences':[audience],'expirationSeconds':600}})
        token = result.get('status',{}).get('token')
        if not isinstance(token,str) or not 32 <= len(token) <= 32768:
            raise FixtureFailure('invalid_actual_tokenrequest')
        return token

    def await_review_permission(self, allowed: bool) -> None:
        # Poll read-only authorization observations, never repeat a login/credential effect.
        until = time.monotonic()+20
        while time.monotonic() < until:
            review = self.post('/apis/authorization.k8s.io/v1/subjectaccessreviews',
                {'apiVersion':'authorization.k8s.io/v1','kind':'SubjectAccessReview',
                 'spec':{'user':'system:serviceaccount:hb-review:reviewer',
                         'groups':['system:serviceaccounts','system:serviceaccounts:hb-review','system:authenticated'],
                         'resourceAttributes':{'group':'authentication.k8s.io','resource':'tokenreviews','verb':'create'}}})
            if review.get('status',{}).get('allowed') is allowed:
                return
            time.sleep(0.2)
        raise FixtureFailure('rbac_observation_timeout')

    def await_token_review(self, token: str, authenticated: bool) -> None:
        until = time.monotonic()+20
        while time.monotonic() < until:
            result = self.post('/apis/authentication.k8s.io/v1/tokenreviews',
                {'apiVersion':'authentication.k8s.io/v1','kind':'TokenReview',
                 'spec':{'token':token,'audiences':[AUDIENCE]}})
            if result.get('status',{}).get('authenticated',False) is authenticated:
                return
            time.sleep(0.2)
        raise FixtureFailure('tokenreview_observation_timeout')

    def close(self):
        if self.attempted:
            self.command(['delete','cluster','--name',self.name], 120)
            self.attempted = False


def run(binary: Path, kind: Path, root: Path, checks: list[dict]):
    def check(name, condition):
        checks.append({'case':name,'passed':condition is True})
        if condition is not True:
            raise FixtureFailure(name)
    cluster = Cluster(kind, root/'cluster')
    service = None
    try:
        cluster.start()
        status, version = cluster.call('GET','/version')
        check('actual_apiserver_version', status == 200 and version.get('gitVersion') == 'v1.35.0')
        for ns in ('hb-review','hb-work','hb-other'):
            value = cluster.post('/api/v1/namespaces',{'apiVersion':'v1','kind':'Namespace','metadata':{'name':ns}})
            check('actual_namespace_'+ns.replace('-','_'), bool(value.get('metadata',{}).get('uid')))
        reviewer = cluster.service_account('hb-review','reviewer')
        worker = cluster.service_account('hb-work','worker')
        other = cluster.service_account('hb-other','worker')
        check('actual_serviceaccount_uids_distinct', len({v['metadata']['uid'] for v in (reviewer,worker,other)}) == 3)
        cluster.post('/apis/rbac.authorization.k8s.io/v1/clusterroles',
            {'apiVersion':'rbac.authorization.k8s.io/v1','kind':'ClusterRole','metadata':{'name':'hb-review-only'},
             'rules':[
                 {'apiGroups':['authentication.k8s.io'],'resources':['tokenreviews'],'verbs':['create']},
                 {'apiGroups':[''],'resources':['serviceaccounts/token'],'verbs':['create']}
             ]})
        binding = {'apiVersion':'rbac.authorization.k8s.io/v1','kind':'ClusterRoleBinding',
                   'metadata':{'name':'hb-review-only'},
                   'roleRef':{'apiGroup':'rbac.authorization.k8s.io','kind':'ClusterRole','name':'hb-review-only'},
                   'subjects':[{'kind':'ServiceAccount','namespace':'hb-review','name':'reviewer'}]}
        cluster.post('/apis/rbac.authorization.k8s.io/v1/clusterrolebindings',binding)
        cluster.await_review_permission(True)
        check('actual_reviewer_rbac_admitted', True)
        status, discovery = cluster.call('GET','/.well-known/openid-configuration')
        issuer = discovery.get('issuer')
        check('actual_serviceaccount_issuer', status == 200 and issuer == 'https://kubernetes.default.svc.cluster.local')
        reviewer_jwt = cluster.token('hb-review','reviewer',issuer)
        worker_jwt = cluster.token('hb-work','worker',AUDIENCE)
        other_jwt = cluster.token('hb-other','worker',AUDIENCE)
        wrong_aud = cluster.token('hb-work','worker','not-heptabao')
        check('actual_tokenrequests', all(t.count('.') == 2 for t in (reviewer_jwt,worker_jwt,other_jwt,wrong_aud)))
        cluster.await_token_review(worker_jwt, True)
        service = Instance(binary, root/'candidate')
        cfg_path = service.root/'server.json'
        cfg = json.loads(cfg_path.read_text())
        address = urllib.parse.urlsplit(cluster.origin).netloc
        cfg['outbound_endpoints'] = [{'origin':cluster.origin,'address':address,'server_name':'127.0.0.1',
                                     'ca_pem':cluster.ca.decode(),'path_prefix':'/'}]
        cfg_path.write_text(json.dumps(cfg));cfg_path.chmod(0o600)
        service.start()
        status, init = service.call('POST','sys/init',{'secret_shares':1,'secret_threshold':1})
        check('candidate_initialized',status == 200)
        key = init['keys_base64'][0];service.token = init['root_token']
        check('candidate_unsealed',service.call('POST','sys/unseal',{'key':key})[0] == 200)
        secrets_mount='platform-kubernetes-secrets'
        check('real_kubernetes_secrets_mount',
              service.call('POST','sys/mounts/'+secrets_mount,{'type':'kubernetes'})[0] == 204)
        check('real_kubernetes_secrets_config',
              service.call('POST',f'{secrets_mount}/config',
                           {'kubernetes_host':cluster.origin,'service_account_token':reviewer_jwt})[0] == 204)
        check('real_kubernetes_secrets_role',
              service.call('POST',f'{secrets_mount}/roles/worker',
                           {'allowed_kubernetes_namespaces':['hb-work'],
                            'service_account_name':'worker',
                            'token_default_ttl':600,'token_max_ttl':600,
                            'token_default_audiences':[AUDIENCE]})[0] == 204)
        status, secret_credential = service.call(
            'POST',f'{secrets_mount}/creds/worker',
            {'kubernetes_namespace':'hb-work','ttl':600,'audiences':[AUDIENCE]})
        secret_token = secret_credential.get('data',{}).get('service_account_token')
        check('real_kubernetes_tokenrequest_issues_secret',
              status == 200 and isinstance(secret_token,str) and secret_token.count('.') == 2)
        check('kubernetes_secret_lease_is_bounded_nonrenewable',
              secret_credential.get('renewable') is False
              and 0 < secret_credential.get('lease_duration',0) <= 720
              and secret_credential.get('lease_id','').startswith(secrets_mount+'/creds/worker/'))
        cluster.await_token_review(secret_token, True)
        check('issued_kubernetes_secret_token_is_real', True)
        status, secret_role_read = service.call('GET',f'{secrets_mount}/roles/worker')
        check('kubernetes_secret_role_readback_redacts_manager',
              status == 200 and reviewer_jwt not in json.dumps(secret_role_read))
        mount='platform/kubernetes'
        check('real_kubernetes_mount',service.call('POST','sys/auth/'+mount,{'type':'kubernetes'})[0] == 204)
        config={'kubernetes_host':cluster.origin,'token_reviewer_jwt':reviewer_jwt,'disable_local_ca_jwt':True}
        check('reviewer_enrolled',service.call('POST',f'auth/{mount}/config',config)[0] == 204)
        role={'bound_service_account_names':['worker'],'bound_service_account_namespaces':['hb-work'],
              'audience':AUDIENCE,'token_policies':['default'],'token_ttl':300}
        check('bounded_role_enrolled',service.call('POST',f'auth/{mount}/role/worker',role)[0] == 204)
        def login(token):
            return service.call('POST',f'auth/{mount}/login',{'role':'worker','jwt':token},token='')
        status, result = login(worker_jwt)
        check('real_tokenreview_issues_local_token',status == 200 and bool(result.get('auth',{}).get('client_token')))
        old_token=result['auth']['client_token'];old_entity=result['auth']['entity_id']
        check('local_token_bounded_nonrenewable',result['auth'].get('renewable') is False and 0 < result['auth']['lease_duration'] <= 300)
        check('live_identity_bound',bool(old_entity))
        check('wrong_actual_audience_denied',login(wrong_aud)[0] == 403)
        check('foreign_actual_namespace_denied',login(other_jwt)[0] == 403)
        check('invalid_signature_denied',login(worker_jwt[:-8]+'AAAAAAAA')[0] == 403)
        status, readable = service.call('GET',f'auth/{mount}/config')
        check('reviewer_credential_not_read_back',status == 200 and reviewer_jwt not in json.dumps(readable))
        check('issued_token_usable',service.call('GET','auth/token/lookup-self',token=old_token)[0] == 200)
        service.stop();service.start()
        check('restart_requires_unseal',service.call('GET','sys/seal-status')[1].get('sealed') is True)
        check('restart_unseal',service.call('POST','sys/unseal',{'key':key})[0] == 200)
        status, secret_after_restart = service.call(
            'POST',f'{secrets_mount}/creds/worker',{'kubernetes_namespace':'hb-work'})
        restart_secret_token = secret_after_restart.get('data',{}).get('service_account_token')
        check('kubernetes_secret_config_role_survive_restart',
              status == 200 and isinstance(restart_secret_token,str))
        cluster.await_token_review(restart_secret_token, True)
        check('restart_issued_kubernetes_token_is_real', True)
        status, again=login(worker_jwt)
        check('real_review_after_restart_same_uid',status == 200 and again['auth']['entity_id'] == old_entity)
        check('delete_old_serviceaccount',cluster.call('DELETE','/api/v1/namespaces/hb-work/serviceaccounts/worker',{})[0] == 200)
        cluster.await_token_review(worker_jwt, False)
        cluster.await_token_review(secret_token, False)
        cluster.await_token_review(restart_secret_token, False)
        check('deleted_serviceaccount_invalidates_secret_tokens', True)
        check('deleted_uid_token_denied',login(worker_jwt)[0] == 403)
        recreated=cluster.service_account('hb-work','worker')
        check('same_name_has_new_actual_uid',recreated['metadata']['uid'] != worker['metadata']['uid'])
        new_jwt=cluster.token('hb-work','worker',AUDIENCE)
        cluster.await_token_review(new_jwt, True)
        status, new_secret = service.call(
            'POST',f'{secrets_mount}/creds/worker',{'kubernetes_namespace':'hb-work'})
        new_secret_token = new_secret.get('data',{}).get('service_account_token')
        check('recreated_serviceaccount_gets_new_secret_token',
              status == 200 and isinstance(new_secret_token,str)
              and new_secret_token not in (secret_token,restart_secret_token))
        cluster.await_token_review(new_secret_token, True)
        status, replacement=login(new_jwt)
        check('replacement_uid_has_distinct_identity',status == 200 and replacement['auth']['entity_id'] != old_entity)
        check('old_jwt_not_revived_by_recreation',login(worker_jwt)[0] == 403)
        check('remove_reviewer_permission',cluster.call('DELETE','/apis/rbac.authorization.k8s.io/v1/clusterrolebindings/hb-review-only',{})[0] == 200)
        cluster.await_review_permission(False)
        denied_status, denied=login(new_jwt)
        check('real_rbac_denial_releases_no_local_token',denied_status >= 400 and not denied.get('auth'))
        cluster.post('/apis/rbac.authorization.k8s.io/v1/clusterrolebindings',binding)
        cluster.await_review_permission(True)
        status, restored=login(new_jwt)
        check('explicit_rbac_restore_allows_new_login',status == 200)
        token=restored['auth']['client_token']
        check('auth_unmount',service.call('DELETE','sys/auth/'+mount)[0] == 204)
        check('unmount_revokes_local_token',service.call('GET','auth/token/lookup-self',token=token)[0] == 403)
        return {'kubernetes_version':version['gitVersion'],'kind_version':KIND_VERSION,'node_image':NODE_IMAGE,
                'actual_kube_apiserver':True,'actual_etcd':True,'actual_rbac':True,
                'scope':'new_single_host_kind_cluster_not_distribution_or_production_qualification'}
    finally:
        try:
            if service is not None:
                service.stop()
        finally:
            cluster.close()


def main(argv=None):
    parser=SafeArgumentParser(description=__doc__)
    parser.add_argument('--binary',required=True,type=Path)
    parser.add_argument('--kind',required=True,type=Path)
    parser.add_argument('--output',required=True,type=Path)
    parser.add_argument('--allow-disposable-cluster',action='store_true')
    args=parser.parse_args(argv)
    if not args.allow_disposable_cluster:
        parser.error('explicit disposable cluster permission required')
    admitted=admit_output(args.output)
    if platform.system() != 'Linux' or platform.machine() not in ('x86_64','amd64'):
        raise PrerequisiteMissing('linux_amd64_kind_fixture_required')
    if not args.kind.is_file() or shutil.which('docker') is None:
        raise PrerequisiteMissing('actual_kind_and_docker_required')
    kind=validate_binary(args.kind,KIND_SHA256)
    env=local_environment(dict(os.environ))
    ready=subprocess.run(['docker','--host',DOCKER_SOCKET,'info'],env=env,stdin=subprocess.DEVNULL,
                         stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=15,check=False)
    if ready.returncode:
        raise PrerequisiteMissing('local_docker_daemon_required')
    before=source_identity(ROOT,args.binary)
    report={'schema':'heptabao.actual-kubernetes.v1','checks':[],'failure':None}
    root=Path(tempfile.mkdtemp(prefix='hb-actual-kubernetes-'));root.chmod(0o700)
    try:
        report.update(run(args.binary.absolute(),kind,root,report['checks']))
    except Exception as error:
        report['failure']=str(error) if isinstance(error,FixtureFailure) else type(error).__name__
    finally:
        try:
            shutil.rmtree(root)
        except OSError:
            report['failure']='private_fixture_cleanup_failed'
    publish(args.output,admitted,report,before,source_identity(ROOT,args.binary),EXPECTED_CHECKS)
    print(json.dumps({'status':report['status'],'count':len(report['checks']),'failure':report.get('failure')}))
    return 0 if report['status']=='passed' else 1


if __name__=='__main__':
    try:
        raise SystemExit(main())
    except PrerequisiteMissing as error:
        print(json.dumps({'status':'blocked_prerequisite','reason':str(error),'qualification':False}))
        raise SystemExit(77) from None
