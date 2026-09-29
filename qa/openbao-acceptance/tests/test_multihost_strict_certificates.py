from pathlib import Path
import socket
import ssl
import sys
import tempfile
import threading
import unittest
from cryptography import x509

sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
import ha_multihost_live as profile


class StrictMultihostCertificates(unittest.TestCase):
    def setUp(self):
        self.temporary=tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root=Path(self.temporary.name)
        self.ca_key=self.root/"ca.key"; self.ca=self.root/"ca.crt"
        profile.create_fixture_ca(self.ca_key,self.ca)
        self.node=profile.Node(1,"synthetic","100.64.0.1","/home/synthetic/private",49001,49002)
        directory=self.root/"node";directory.mkdir(mode=0o700)
        self.key,self.cert=profile.create_fixture_node_certificate(self.node,directory,self.ca_key,self.ca)

    def handshake(self,name):
        server=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        server.minimum_version=ssl.TLSVersion.TLSv1_2
        server.load_cert_chain(str(self.cert),str(self.key))
        client=ssl.create_default_context(cafile=str(self.ca))
        client.verify_flags |= ssl.VERIFY_X509_STRICT
        self.assertTrue(client.check_hostname)
        self.assertEqual(client.verify_mode,ssl.CERT_REQUIRED)
        left,right=socket.socketpair();left.settimeout(5);right.settimeout(5)
        def serve():
            try:
                with server.wrap_socket(left,server_side=True) as channel:
                    channel.sendall(b"ok")
            except ssl.SSLError:
                # A wrong-host client deliberately aborts during verification.
                pass
            finally:left.close()
        thread=threading.Thread(target=serve,daemon=True);thread.start()
        try:
            with client.wrap_socket(right,server_hostname=name) as channel:
                self.assertEqual(channel.recv(2),b"ok")
        finally:
            right.close();thread.join(timeout=6)
            self.assertFalse(thread.is_alive())

    def test_real_handshake_accepts_the_named_leaf_with_strict_verification(self):
        self.handshake(self.node.server_name)

    def test_real_handshake_preserves_wrong_hostname_rejection(self):
        with self.assertRaises(ssl.SSLCertVerificationError):
            self.handshake("wrong.synthetic.invalid")

    def test_leaf_authority_and_ca_subject_key_identifiers_match(self):
        ca=x509.load_pem_x509_certificate(self.ca.read_bytes())
        leaf=x509.load_pem_x509_certificate(self.cert.read_bytes())
        subject=ca.extensions.get_extension_for_class(x509.SubjectKeyIdentifier).value.digest
        authority=leaf.extensions.get_extension_for_class(x509.AuthorityKeyIdentifier).value.key_identifier
        self.assertEqual(authority,subject)
        self.assertEqual(ca.extensions.get_extension_for_class(x509.AuthorityKeyIdentifier).value.key_identifier,subject)
        self.assertIsNotNone(leaf.extensions.get_extension_for_class(x509.SubjectKeyIdentifier).value.digest)
        self.assertEqual(self.key.stat().st_mode & 0o777,0o600)
        self.assertEqual(self.ca_key.stat().st_mode & 0o777,0o600)
