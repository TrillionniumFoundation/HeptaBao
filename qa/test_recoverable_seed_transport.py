#!/usr/bin/env python3
"""Local TLS component checks; never initialize or contact a HeptaBao instance."""
from pathlib import Path
import hashlib
import importlib.util
import json
import os
import signal
import socket
import ssl
import stat
import subprocess
import sys
import tempfile
import threading
import time

SOURCE=Path(__file__).resolve().parents[1]/'tools/production/prepare_recoverable_seed.py'
spec=importlib.util.spec_from_file_location('owned_seed_transport_under_test',SOURCE)
seed=importlib.util.module_from_spec(spec)
spec.loader.exec_module(seed)


class Peer:
    def __init__(self, context, action):
        self.socket=socket.socket()
        self.socket.bind(('127.0.0.1',0));self.socket.listen(1)
        self.port=self.socket.getsockname()[1]
        self.requests=0;self.errors=[]
        self.context=context;self.action=action
        self.thread=threading.Thread(target=self.serve,daemon=True)
        self.thread.start()

    def serve(self):
        try:
            raw,_=self.socket.accept()
            with self.context.wrap_socket(raw,server_side=True) as channel:
                channel.settimeout(3)
                data=b''
                while b'\r\n\r\n' not in data:
                    part=channel.recv(1024)
                    if not part:
                        return
                    data+=part
                    if len(data)>16384:
                        raise RuntimeError('component_request_header_bound')
                header,body=data.split(b'\r\n\r\n',1)
                fields={line.split(b':',1)[0].lower():line.split(b':',1)[1].strip()
                        for line in header.split(b'\r\n')[1:]}
                length=int(fields.get(b'content-length',b'0'))
                while len(body)<length:
                    part=channel.recv(min(4096,length-len(body)))
                    if not part:
                        raise RuntimeError('component_request_body_incomplete')
                    body+=part
                assert len(body)==length
                self.requests+=1
                self.action(channel)
        except (OSError,ssl.SSLError):
            # The deliberate deadline closes the client's own socket.
            pass
        except BaseException as exc:
            self.errors.append(type(exc).__name__)
        finally:
            self.socket.close()

    def finish(self):
        self.thread.join(4)
        assert not self.thread.is_alive() and not self.errors


def send(raw):
    def action(channel):
        channel.sendall(b'HTTP/1.1 200 OK\r\nContent-Length: '+str(len(raw)).encode()
                        +b'\r\nConnection: close\r\n\r\n'+raw)
    return action


def main():
    os.umask(0o077)
    original_budget=seed.HTTP_SECONDS
    assert original_budget==12
    records=[]
    with tempfile.TemporaryDirectory(prefix='heptabao-seed-transport-') as directory:
        root=Path(directory);(root/'tls').mkdir(mode=0o700)
        key=root/'tls/key.pem';cert=root/'tls/ca.crt'
        subprocess.run(['openssl','req','-x509','-newkey','rsa:2048','-nodes',
                        '-keyout',str(key),'-out',str(cert),'-days','1',
                        '-subj','/CN=owned-loopback-component',
                        '-addext','subjectAltName=IP:127.0.0.1'],
                       check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=15)
        seed.ROOT=root
        seed.LEAF_SHA=hashlib.sha256(ssl.PEM_cert_to_DER_cert(cert.read_text())).hexdigest()
        context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);context.load_cert_chain(cert,key)
        for label,payload in [('complete-json',b'{"keys_base64":[],"root_token":"component-only"}'),
                              ('invalid-json',b'{not-json')]:
            work=root/label;work.mkdir(mode=0o700);(work/'journal').mkdir(mode=0o700)
            run=seed.SeedRun(work);peer=Peer(context,send(payload));run.port=peer.port
            error=None;response=None
            try:
                response=run.request(label,'POST','sys/init',{'component_only':True},persist_init=True)
            except BaseException as exc:
                error=type(exc).__name__
            finally:
                peer.finish()
            retained=work/'initialization-response.private.json'
            assert retained.read_bytes()==payload and stat.S_IMODE(retained.stat().st_mode)==0o600
            assert peer.requests==1 and len(run.report['requests'])==1
            assert run.report['requests'][0]['outcome']=='response_received'
            assert not list((work/'journal').glob('*-unresolved.public.json'))
            if label=='complete-json':
                assert error is None and response[0]==200
            else:
                assert error=='JSONDecodeError' and response is None
            records.append({'case':label,'passed':True,'one_request_only':True,
                            'exact_response_durable_before_decode':True,'error_type':error})
        chunked_payload=json.dumps({'value':'c'*3000}).encode()
        for label,wire,expected in [
            ('complete204-no-length',b'HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n',(204,None)),
            ('complete-canonical-chunked',b'HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n'
             +format(len(chunked_payload),'x').encode()+b'\r\n'+chunked_payload+b'\r\n0\r\n\r\n',
             (200,json.loads(chunked_payload)))]:
            work=root/label;work.mkdir(mode=0o700);(work/'journal').mkdir(mode=0o700)
            run=seed.SeedRun(work);peer=Peer(context,lambda ch,payload=wire:ch.sendall(payload));run.port=peer.port
            try: response=run.request(label,'POST','sys/seal',{})
            finally: peer.finish()
            assert response==expected and peer.requests==1
            assert len(run.report['requests'])==1 and run.report['requests'][0]['outcome']=='response_received'
            records.append({'case':label,'passed':True,'one_request_only':True,
                            'framing':run.report['requests'][0]['framing']})
        for label,raw in [
            ('truncated204-header',b'HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n'),
            ('truncated-declared-body',b'HTTP/1.1 200 OK\r\nContent-Length: 20\r\nConnection: close\r\n\r\n{}'),
            ('forbidden204-content-length',b'HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n'),
            ('chunked-short-data',b'HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n20\r\n{}'),
            ('chunked-wrong-data-terminator',b'HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2\r\n{}XX0\r\n\r\n'),
            ('chunked-missing-terminal-crlf',b'HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2\r\n{}\r\n0\r\n'),
            ('chunked-with-content-length',b'HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nContent-Length: 2\r\n\r\n2\r\n{}\r\n0\r\n\r\n')]:
            work=root/label;work.mkdir(mode=0o700);(work/'journal').mkdir(mode=0o700)
            run=seed.SeedRun(work)
            peer=Peer(context,lambda channel,payload=raw:channel.sendall(payload));run.port=peer.port
            error=None
            try:
                run.request(label,'POST','sys/seal',{})
            except seed.Refused as exc:
                error=str(exc)
            finally:
                peer.finish()
            assert error is not None and peer.requests==1
            assert len(run.report['requests'])==1 and run.report['requests'][0]['outcome']=='unknown'
            records.append({'case':label,'passed':True,'one_request_only':True,'outcome':'unknown','error':error})
        # A separate accelerated component budget exercises a trickle attack.
        # The production script remains unchanged with its12-second constant.
        seed.HTTP_SECONDS=.4
        def trickle(channel):
            for byte in b'HTTP/1.1 200 OK\r\nContent-Length: 999\r\n\r\n':
                channel.sendall(bytes([byte]));time.sleep(.08)
        work=root/'trickled-header';work.mkdir(mode=0o700);(work/'journal').mkdir(mode=0o700)
        run=seed.SeedRun(work);peer=Peer(context,trickle);run.port=peer.port
        started=time.monotonic();error=None
        try:
            run.request('trickled-header','POST','sys/init',{'component_only':True},persist_init=True)
        except BaseException as exc:
            error=type(exc).__name__
        elapsed=time.monotonic()-started
        peer.finish()
        assert error is not None and .2<=elapsed<1.2 and peer.requests==1
        assert len(run.report['requests'])==1 and run.report['requests'][0]['outcome']=='unknown'
        assert not (work/'initialization-response.private.json').exists()
        records.append({'case':'absolute-deadline-with-trickled-tls-header','passed':True,
                        'one_request_only':True,'outcome':'unknown','error_type':error,
                        'component_budget_seconds':.4,'elapsed_seconds':elapsed})
        seed.HTTP_SECONDS=original_budget
        # Deliver an actual SIGTERM after a real child is spawned, before the
        # Popen factory returns to SeedRun.start. Cleanup must retain that child.
        (root/'release').mkdir(mode=0o700)
        dummy=root/'release/heptabao-server'
        dummy.write_text('#!'+sys.executable+'\nimport time\ntime.sleep(15)\n')
        dummy.chmod(0o700)
        work=root/'spawn-signal';work.mkdir(mode=0o700);(work/'journal').mkdir(mode=0o700)
        run=seed.SeedRun(work);spawned=[];original_popen=subprocess.Popen
        def spawn_then_interrupt(*args,**kwargs):
            child=original_popen(*args,**kwargs);spawned.append(child)
            signal.raise_signal(signal.SIGTERM)
            return child
        previous=signal.signal(signal.SIGTERM,lambda signum,frame:run.handle_signal(signum))
        seed.subprocess.Popen=spawn_then_interrupt
        error=None
        try:
            run.start('owned-dummy')
        except seed.Refused as exc:
            error=str(exc)
        finally:
            seed.subprocess.Popen=original_popen
            signal.signal(signal.SIGTERM,previous)
            assert len(spawned)==1 and run.child is spawned[0]
            assert len(run.report['processes'])==1 and run.report['processes'][0]['pid']==spawned[0].pid
            assert os.getpgid(spawned[0].pid)==os.getpgrp()
            run.stop()
        assert error=='owned_seed_controller_interrupted'
        assert run.child is None and spawned[0].poll() is not None
        assert run.report['processes'][0]['stopped'] and not run.report['processes'][0]['forced_kill']
        records.append({'case':'sigterm-after-spawn-before-popen-return','passed':True,
                        'actual_signal_delivered':True,'actual_child_retained_and_reaped':True,
                        'controller_process_group_retained':True,'unowned_process_signalled':False})
    return {'schema':'heptabao.recoverable-seed-local-transport-component.v1','ok':True,
            'source_sha256':hashlib.sha256(SOURCE.read_bytes()).hexdigest(),
            'production_http_budget_seconds':original_budget,'cases':records,
            'real_heptabao_executed':False,'remote_hosts_contacted':False,
            'production_files_read_or_changed':False,'production_initialized':False,
            'new_self_signed_component_ca_only':True,'temporary_fixture_removed':True}


if __name__=='__main__':
    print(json.dumps(main(),sort_keys=True,indent=2))
