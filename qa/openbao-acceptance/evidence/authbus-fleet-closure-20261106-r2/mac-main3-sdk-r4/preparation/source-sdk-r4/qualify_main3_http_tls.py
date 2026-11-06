#!/usr/bin/env python3
"""One-shot synthetic TLS peers qualify the real Api reader and socket closure.

Accepts an already-created synthetic certificate/key pair, never runs a child,
never contacts a provider, and never loads a production configuration/capsule.
"""
import hashlib
import json
from pathlib import Path
import socket
import ssl
import threading
import time
import types
import main3_api_cycle as a


def run(certificate, key):
    started = time.monotonic()
    until = started + 30
    cert = Path(certificate).read_text()
    leaf = hashlib.sha256(ssl.PEM_cert_to_DER_cert(cert)).hexdigest()
    server_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server_context.minimum_version = ssl.TLSVersion.TLSv1_2
    server_context.load_cert_chain(str(certificate), str(key))
    client_context = ssl.create_default_context(cafile=str(certificate))
    checks = []
    peers = []
    body = json.dumps({'synthetic': True, 'padding': 'x' * 4096}, separators=(',', ':')).encode()
    large = (b'HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n' +
             b'89;synthetic=one\r\n' + body[:137] + b'\r\n' +
             format(len(body) - 137, 'x').encode() + b'\r\n' + body[137:] +
             b'\r\n0\r\nX-Synthetic: complete\r\n\r\n')
    header = b'HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n'
    fixtures = [
        ('content_length', b'HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}', True, 200),
        ('large_fragmented_chunked', large, True, 200),
        ('empty_204_no_length', b'HTTP/1.1 204 No Content\r\n\r\n', True, 204),
        ('truncated_content_length', b'HTTP/1.1 200 OK\r\nContent-Length: 1000\r\n\r\n{}', False, 200),
        ('invalid_chunk_size', header + b'z\r\n{}\r\n0\r\n\r\n', False, 200),
        ('missing_terminal_chunk', header + b'2\r\n{}\r\n', False, 200),
        ('missing_trailer_completion', header + b'2\r\n{}\r\n0\r\n', False, 200),
        ('bad_chunk_terminator', header + b'2\r\n{}XX0\r\n\r\n', False, 200),
        ('oversize_decoded_chunk', header + b'100001\r\n', False, 200),
        ('ambiguous_transfer_and_length', b'HTTP/1.1 200 OK\r\nContent-Length: 2\r\nTransfer-Encoding: chunked\r\n\r\n2\r\n{}\r\n0\r\n\r\n', False, 200),
        ('duplicate_transfer', b'HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n', False, 200),
        ('forbidden_trailer', header + b'0\r\nContent-Length: 0\r\n\r\n', False, 200),
        ('wrong_leaf_before_dispatch', b'', False, 200),
        ('original_absolute_deadline_stall', b'', False, 200),
        ('original_absolute_deadline_slow_header', b'HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}', False, 200),
    ]
    for name, wire, success, status in fixtures:
        if time.monotonic() >= until:
            raise RuntimeError('synthetic_tls_qualification_30_seconds')
        observed = {'case': name, 'connections': 0, 'requests': 0,
                    'listenerClosed': False, 'acceptedSocketClosed': False,
                    'peerThreadJoined': False}
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.settimeout(2)
        listener.bind(('127.0.0.1', 0))
        listener.listen(1)
        port = listener.getsockname()[1]
        release = threading.Event()

        def serve():
            raw = tls = None
            try:
                raw, _ = listener.accept()
                observed['connections'] += 1
                raw.settimeout(2)
                tls = server_context.wrap_socket(raw, server_side=True)
                request = b''
                while b'\r\n\r\n' not in request:
                    part = tls.recv(8192)
                    if not part:
                        return
                    request += part
                    if len(request) > 65536:
                        raise RuntimeError('bounded_synthetic_peer_request')
                observed['requests'] += 1
                if name == 'original_absolute_deadline_stall':
                    release.wait(1)
                elif name == 'original_absolute_deadline_slow_header':
                    for byte in wire:
                        tls.sendall(bytes([byte]))
                        if release.wait(.025):
                            break
                else:
                    for offset in range(0, len(wire), 137):
                        tls.sendall(wire[offset:offset + 137])
            except (BrokenPipeError, ConnectionResetError, ssl.SSLError):
                observed['peerSawClientClosure'] = True
            except BaseException as error:
                observed['peerErrorType'] = type(error).__name__
            finally:
                if tls is not None:
                    tls.close()
                elif raw is not None:
                    raw.close()
                observed['acceptedSocketClosed'] = raw is not None
                listener.close()
                observed['listenerClosed'] = True

        peer = threading.Thread(target=serve, name='synthetic-main3-http-peer', daemon=False)
        peer.start()
        api = object.__new__(a.Api)
        api.plan = {'port': port, 'certificateLeafSha256': leaf if name != 'wrong_leaf_before_dispatch' else '0' * 64}
        api.phase = 'initial'
        api.until = min(until, time.monotonic() + (.18 if name.startswith('original_absolute_deadline') else 2))
        api.rows, api.checks, api.sensitive = [], [], []
        api.unknown, api.root_token = False, None
        api.context = client_context
        events = []
        api.journal = types.SimpleNamespace(append=lambda event, row: events.append((event, row)))
        api.guard = types.SimpleNamespace(check=lambda: None)
        returned = False
        try:
            value = api.call('synthetic.' + name, 'GET', '/v1/sys/health', expected=status,
                             token='', category='health')
            returned = True
            if name == 'large_fragmented_chunked':
                assert value == json.loads(body)
            if not success:
                raise RuntimeError('malformed_synthetic_response_accepted')
        except a.Refused:
            if success:
                raise
        finally:
            release.set()
            peer.join(timeout=min(3, max(.01, until - time.monotonic())))
            observed['peerThreadJoined'] = not peer.is_alive()
            peers.append(observed)
        assert returned == success
        assert observed['connections'] == 1 and observed['requests'] == (0 if name == 'wrong_leaf_before_dispatch' else 1)
        assert observed['listenerClosed'] and observed['acceptedSocketClosed'] and observed['peerThreadJoined']
        assert 'peerErrorType' not in observed
        assert len(api.rows) == 1 and api.rows[0]['socketsClosed'] and api.rows[0]['responseReaderClosed']
        if success:
            assert api.rows[0]['responseComplete'] and not api.rows[0]['outcomeUnknown']
        else:
            assert api.unknown and not api.rows[0]['responseComplete']
            assert api.rows[0]['outcomeUnknown'] == (name != 'wrong_leaf_before_dispatch')
            try:
                api.call('synthetic.replay_refused', 'GET', '/v1/sys/health', token='', category='health')
                raise RuntimeError('unknown_synthetic_replay_permitted')
            except a.Refused:
                pass
            assert len(api.rows) == 1
        public = json.dumps({'rows': api.rows, 'events': events})
        assert 'padding' not in public and 'sha256' not in public.lower()
        checks.append({'case': name, 'passed': True, 'requests': api.rows})
    return {'schema': 'heptabao.main3-http-complete-real-tls-qualification.r1',
            'ok': True, 'checks': checks, 'checkCount': len(checks), 'peers': peers,
            'allPeerThreadsJoined': all(x['peerThreadJoined'] for x in peers),
            'allPeerSocketsClosed': all(x['listenerClosed'] and x['acceptedSocketClosed'] for x in peers),
            'elapsedSeconds': time.monotonic() - started,
            'providerCalled': False, 'productionCredentialInputsRead': False,
            'productServiceStarted': False, 'productionChanged': False}
