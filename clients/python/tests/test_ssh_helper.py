import copy
import tempfile
import os
from pathlib import Path
import sys
import unittest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from heptabao.ssh_helper import read_otp, verify, config_file
from heptabao.transport import BaoError,Response,private_write


class HelperTests(unittest.TestCase):
    def setUp(self):
        self.config={'address':'https://localhost:8200','ca_file':'/synthetic-ca','namespace':'team',
                     'mount':'ssh','host_ips':['127.0.0.1','::1'],'allowed_users':['deploy'],
                     'allowed_roles':['limited'],'timeout':1}
        self.calls=[];self.response=Response(200,{'data':{'ip':'127.0.0.1','username':'deploy','role_name':'limited'}})
    def factory(self,*args,**kwargs):self.calls.append(('client',args));return self
    def request(self,*args,**kwargs):
        self.calls.append((args,kwargs))
        if isinstance(self.response,Exception):raise self.response
        return self.response
    def test_exact_binding_accepts_only_selected_host_user_role_and_namespace(self):
        verify(self.config,'deploy','synthetic-otp',client_factory=self.factory)
        self.assertEqual(self.calls[0][1][3],'team')
        self.assertEqual(self.calls[1],(('POST','/v1/ssh/verify',{'otp':'synthetic-otp'}),{'token':''}))
    def test_wrong_local_user_rejects_before_any_network_request(self):
        with self.assertRaises(BaoError):verify(self.config,'root','secret',client_factory=self.factory)
        self.assertEqual(self.calls,[])
    def test_wrong_host_role_or_username_denies_after_at_most_one_consumption(self):
        for field,value in [('ip','127.0.0.2'),('ip','::ffff:127.0.0.1'),('username','root'),('role_name','wide')]:
            with self.subTest(field=field,value=value):
                self.calls=[];data={'ip':'127.0.0.1','username':'deploy','role_name':'limited'};data[field]=value
                self.response=Response(200,{'data':data})
                with self.assertRaises(BaoError):verify(self.config,'deploy','secret',client_factory=self.factory)
                self.assertEqual(len(self.calls),2)
    def test_invalid_and_unknown_outcome_never_retry(self):
        for response in [Response(403,{'errors':['private-response']}),BaoError('transport_outcome_unknown')]:
            self.calls=[];self.response=response
            with self.assertRaises(BaoError):verify(self.config,'deploy','secret',client_factory=self.factory)
            self.assertEqual(len(self.calls),2)
    def test_pipe_requires_one_bounded_ascii_value(self):
        for value in [b'secret\n',b'secret',b'one\ntwo\n',b'\n',b'x'*257,b'\xff']:
            a,b=os.pipe();os.write(b,value);os.close(b)
            try:
                if value in (b'secret\n',b'secret'):self.assertEqual(read_otp(a,1),'secret')
                else:
                    with self.assertRaises(BaoError):read_otp(a,1)
            finally:os.close(a)
    def test_stalled_pipe_has_a_deadline_without_credential_echo(self):
        a,b=os.pipe()
        try:
            with self.assertRaisesRegex(BaoError,'deadline'):read_otp(a,0.01)
        finally:os.close(a);os.close(b)



    def test_private_config_accepts_safe_role_user_syntax_and_freezes_ca_bytes(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            ca = root / 'ca.pem'
            ca.write_bytes(b'synthetic-certificate')
            ca.chmod(0o644)
            config = {**self.config, 'ca_file': str(ca),
                      'allowed_users': ['deploy-user', 'service$'],
                      'allowed_roles': ['ssh-role_1']}
            private_write(root / 'config.json', config)
            parsed = config_file(str(root / 'config.json'))
            self.assertEqual(parsed['_trusted_ca'], b'synthetic-certificate')
            from unittest.mock import Mock
            factory = Mock()
            factory.return_value.request.return_value = Response(200, {'data': {
                'ip': '127.0.0.1', 'username': 'deploy-user', 'role_name': 'ssh-role_1'}})
            ca.write_bytes(b'replaced-after-configuration')
            verify(parsed, 'deploy-user', 'synthetic-otp', client_factory=factory)
            self.assertEqual(factory.call_args.kwargs['trusted_ca_pem'], b'synthetic-certificate')

    def test_public_configuration_writable_trust_and_symlink_trust_reject(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            ca = root / 'ca.pem'
            ca.write_bytes(b'synthetic-certificate')
            path = root / 'config.json'
            private_write(path, {**self.config, 'ca_file': str(ca)})
            ca.chmod(0o666)
            with self.assertRaises(BaoError):
                config_file(str(path))
            ca.chmod(0o644)
            ca.rename(root / 'real-ca')
            ca.symlink_to(root / 'real-ca')
            with self.assertRaises(BaoError):
                config_file(str(path))
            ca.unlink()
            ca.write_bytes(b'synthetic-certificate')
            path.chmod(0o644)
            with self.assertRaises(BaoError):
                config_file(str(path))


if __name__=='__main__':unittest.main()
