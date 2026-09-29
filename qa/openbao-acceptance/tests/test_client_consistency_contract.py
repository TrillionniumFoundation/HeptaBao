from pathlib import Path
import sys
import unittest
import os
import socket
import tempfile
import threading
from unittest.mock import patch
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import client_consistency_live as profile
from online_evidence import complete_checks

class ClientConsistencyContractTests(unittest.TestCase):
    def test_fixed_denominators_reject_prefixes_duplicates_and_failures(self):
        for required,count in ((profile.COMMON,35),(profile.HA_REQUIRED,28),(profile.PROXY_REQUIRED,14)):
            self.assertEqual(len(required),count)
            rows=[{'case':name,'passed':True} for name in sorted(required)]
            self.assertTrue(complete_checks(rows,count,required_cases=required))
            self.assertFalse(complete_checks(rows[:-1],count,required_cases=required))
            self.assertFalse(complete_checks(rows+rows[:1],count,required_cases=required))
            rows[0]['passed']=False
            self.assertFalse(complete_checks(rows,count,required_cases=required))

    def test_duplicate_index_refused_before_constructing_transport(self):
        t=profile.ClientTrace(Path('/unused/ca'))
        with patch.object(profile,'Client') as client:
            with self.assertRaises(profile.BaoError):
                t.invoke(None,'GET','unused',headers=[('X-Vault-Index',''),('X-Vault-Index','')])
            client.assert_not_called()

    def test_native_client_profile_is_required_alongside_native_server(self):
        root=Path(__file__).resolve().parents[3]
        rows=(root/'.github/workflows/codex-openbao-replacement-ci.yml').read_text().splitlines()
        line=next(row for row in rows if 'for profile in core_isolation' in row and 'consistency_headers_live' in row)
        self.assertIn('client_consistency_live',line.split())
        self.assertIn('consistency_headers_live',line.split())

class UnixFixtureDirectoryTests(unittest.TestCase):
    def test_world_accessible_socket_directory_is_rejected_before_transport(self):
        with tempfile.TemporaryDirectory() as raw:
            directory=Path(raw).resolve()
            directory.chmod(0o755)
            with patch.object(profile.socket,'socket',side_effect=AssertionError('transport before directory admission')) as transport:
                with self.assertRaises(profile.BaoError):
                    profile.unix_request(directory,'GET','synthetic')
                transport.assert_not_called()

    def test_symlink_socket_directory_is_rejected_before_transport(self):
        with tempfile.TemporaryDirectory() as raw:
            directory=Path(raw).resolve(); target=directory/'target';target.mkdir(mode=0o700)
            alias=directory/'alias';alias.symlink_to(target,target_is_directory=True)
            with patch.object(profile.socket,'socket',side_effect=AssertionError('transport before directory admission')) as transport:
                with self.assertRaises(profile.BaoError):
                    profile.unix_request(alias,'GET','synthetic')
                transport.assert_not_called()

    @unittest.skipUnless(sys.platform.startswith('linux'),'Linux descriptor-bound Unix socket transport')
    def test_long_private_directory_uses_same_fd_binding_as_real_proxy(self):
        with tempfile.TemporaryDirectory() as raw:
            directory=Path(raw).resolve()/('nested-'+'x'*100)
            directory.mkdir(mode=0o700)
            self.assertGreater(len(str(directory/'api.sock').encode()),107)
            failures=[]
            with profile.StateDirectory(directory) as anchor, socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as listener:
                listener.bind(f'/proc/self/fd/{anchor.fd}/api.sock')
                os.chmod('api.sock',0o600,dir_fd=anchor.fd)
                listener.listen(1);listener.settimeout(2)
                def respond():
                    try:
                        peer,_=listener.accept()
                        with peer:
                            peer.settimeout(2);request=b''
                            while b'\r\n\r\n' not in request:
                                part=peer.recv(4096)
                                if not part or len(request)+len(part)>8192:
                                    raise AssertionError('bounded synthetic request expected')
                                request+=part
                            body=b'{"data":{"fixture":"long-private-path"}}'
                            peer.sendall(b'HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: '
                                         +str(len(body)).encode()+b'\r\nConnection: close\r\n\r\n'+body)
                    except Exception as error:
                        failures.append(type(error).__name__)
                thread=threading.Thread(target=respond,daemon=True);thread.start()
                try:
                    status,value,_=profile.unix_request(directory,'GET','synthetic')
                finally:
                    thread.join(3)
                self.assertFalse(thread.is_alive())
                self.assertEqual(failures,[])
                self.assertEqual(status,200)
                self.assertEqual(value,{'data':{'fixture':'long-private-path'}})

if __name__=='__main__':unittest.main()
