from __future__ import annotations
import argparse
import hashlib
import json
import os
from pathlib import Path
import secrets
import socket
import sys
import tempfile
import threading
import time
import unittest
import urllib.parse
from unittest import mock
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from heptabao.oidc_login import Loopback, PrivateOutput, authorization_url, callback_code, opaque, run
from heptabao.transport import BaoError


class OidcNativeTests(unittest.TestCase):
    def head(self,state=None,code="authorization-code"):
        state=state or self.state
        query=urllib.parse.urlencode({"state":state,"code":code})
        return f"GET /oidc/callback?{query} HTTP/1.1\r\nHost: 127.0.0.1:8259\r\n\r\n".encode()
    def setUp(self):
        self.state=secrets.token_urlsafe(32)
    def test_opaque_proofs_are_canonical_32_bytes(self):
        self.assertTrue(opaque(self.state))
        for value in ["",self.state+"=","x"*43,"+"*43,None,"a"*42]:self.assertFalse(opaque(value))
    def test_valid_callback_never_returns_state(self):
        self.assertEqual(callback_code(self.head(),8259,self.state),"authorization-code")
    def test_callback_rejects_wrong_state_host_and_origin(self):
        original=self.head()
        for value in [self.head(secrets.token_urlsafe(32)),original.replace(b"127.0.0.1",b"attacker.example"),
            original.replace(b"\r\n\r\n",b"\r\nOrigin: https://attacker.example\r\n\r\n")]:
            with self.assertRaises(BaoError):callback_code(value,8259,self.state)
    def test_smuggling_body_duplicate_and_percent_path_reject(self):
        original=self.head()
        additions=[b"Transfer-Encoding: chunked",b"Content-Length: 1",b"Host: 127.0.0.1:8259",b" folded: value"]
        values=[original+b"extra",original.replace(b"/oidc/callback",b"/oidc/%63allback"),
            original.replace(b"GET ",b"POST "),original.replace(b" HTTP/1.1",b" HTTP/1.0")]
        values += [original.replace(b"\r\n\r\n",b"\r\n"+v+b"\r\n\r\n") for v in additions]
        for value in values:
            with self.assertRaises(BaoError):callback_code(value,8259,self.state)
    def test_extra_query_parameters_and_duplicate_codes_reject(self):
        for extra in ["&code=again","&access_token=must-not-be-accepted","&error=denied"]:
            with self.assertRaises(BaoError):callback_code(self.head().replace(b" HTTP/1.1",extra.encode()+b" HTTP/1.1"),8259,self.state)
    def test_callback_codes_cannot_carry_controls_or_non_ascii(self):
        for code in ["","line\nseparator","é","a"*4097]:
            with self.assertRaises(BaoError):callback_code(self.head(code=code),8259,self.state)
    def url(self):
        values={"response_type":"code","scope":"openid","client_id":"confidential-client",
            "redirect_uri":"http://127.0.0.1:8259/oidc/callback","state":self.state,
            "nonce":secrets.token_urlsafe(32),"code_challenge":secrets.token_urlsafe(32),"code_challenge_method":"S256"}
        return "https://issuer.example:443/authorize?"+urllib.parse.urlencode(values)
    def test_authorization_url_has_exact_trusted_origin_redirect_and_s256(self):
        original=self.url();redirect="http://127.0.0.1:8259/oidc/callback"
        self.assertEqual(authorization_url(original,"https://issuer.example:443",redirect),(original,self.state))
        for value in [original.replace("https://","http://",1),original.replace("issuer.example","attacker.example"),
            original.replace("S256","plain"),original+"&state=duplicate",original+"#fragment",original.replace("8259","8260")]:
            with self.assertRaises(BaoError):authorization_url(value,"https://issuer.example:443",redirect)
    def test_private_output_reservation_precedes_any_network(self):
        args=argparse.Namespace(allow_write=False)
        with mock.patch("heptabao.oidc_login.Client") as client:
            with self.assertRaises(BaoError):run(args)
            client.assert_not_called()
    def test_private_output_refuses_existing_symlink_and_public_parent(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);original=root/"output";original.write_text("existing")
            with self.assertRaises(BaoError):PrivateOutput(original)
            self.assertEqual(original.read_text(),"existing")
            (root/"link").symlink_to(original)
            with self.assertRaises(BaoError):PrivateOutput(root/"link")
            root.chmod(0o755)
            with self.assertRaises(BaoError):PrivateOutput(root/"new")
    def test_publication_is_private_and_keeps_reserved_inode(self):
        with tempfile.TemporaryDirectory() as tmp:
            output=Path(tmp)/"result";destination=PrivateOutput(output)
            inode=output.stat().st_ino
            try:destination.publish({"auth":{"client_token":"private-value"}})
            finally:destination.close()
            self.assertEqual(output.stat().st_ino,inode)
            self.assertEqual(output.stat().st_mode&0o777,0o600)
            self.assertEqual(json.loads(output.read_text())["auth"]["client_token"],"private-value")
    def test_replaced_output_does_not_receive_token(self):
        with tempfile.TemporaryDirectory() as tmp:
            path=Path(tmp)/"result";destination=PrivateOutput(path)
            try:
                path.unlink();path.write_text("other")
                with self.assertRaises(BaoError):destination.publish({"token":"private"})
                self.assertEqual(path.read_text(),"other")
            finally:destination.close()
    def test_renamed_parent_does_not_redirect_secret_output(self):
        with tempfile.TemporaryDirectory() as tmp:
            base=Path(tmp);directory=base/"private";directory.mkdir(mode=0o700)
            destination=PrivateOutput(directory/"result")
            try:
                directory.rename(base/"original");directory.mkdir(mode=0o700)
                destination.publish({"value":"private"})
                self.assertFalse((directory/"result").exists())
                self.assertTrue((base/"original/result").is_file())
            finally:destination.close()
    def test_real_loopback_success_and_absolute_timeout(self):
        with socket.socket() as sock:sock.bind(("127.0.0.1",0));port=sock.getsockname()[1]
        receiver=Loopback(port,3)
        def send():
            with socket.create_connection(("127.0.0.1",port)) as client:
                client.sendall(self.head().replace(b"8259",str(port).encode()))
                self.reply=client.recv(4096)
        worker=threading.Thread(target=send);worker.start()
        try:self.assertEqual(receiver.wait(self.state),"authorization-code")
        finally:receiver.close();worker.join(timeout=5)
        self.assertFalse(worker.is_alive());self.assertNotIn(self.state.encode(),self.reply)
        with socket.socket() as sock:sock.bind(("127.0.0.1",0));port=sock.getsockname()[1]
        receiver=Loopback(port,0.05);start=time.monotonic()
        try:
            with self.assertRaises(BaoError):receiver.wait(self.state)
        finally:receiver.close()
        self.assertLess(time.monotonic()-start,1)
    def test_unbounded_time_and_privileged_port_reject_before_bind(self):
        for port,timeout in [(80,1),(8259,float("inf")),(8259,241),(True,1)]:
            with self.assertRaises(BaoError):Loopback(port,timeout)

if __name__=="__main__":unittest.main()
