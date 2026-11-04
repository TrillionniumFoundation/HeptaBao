#!/usr/bin/env python3
"""One bounded TCP observation; no product, TLS, credentials or external peer."""
import ctypes, hashlib, json, os, select, socket, sys, threading, time
from pathlib import Path

os.umask(0o077)
root = Path('/Volumes/T5/hepta-vnext-recovery-20261013/continuation-20261104-native-ssh-http-r8/mac-tcp-pending-bytes-r1')
assert os.uname().sysname == 'Darwin' and os.getuid() == 501
assert root.parent.resolve(strict=True) == root.parent and not root.exists() and not root.is_symlink()
root.mkdir(mode=0o700)
code = sys.orig_argv[sys.orig_argv.index('-c') + 1].encode()
with (root/'controller.py').open('xb') as f:
    f.write(code); f.flush(); os.fsync(f.fileno())
deadline = time.monotonic() + 5.0
def remaining():
    value = deadline - time.monotonic()
    if value <= 0: raise TimeoutError('original_five_second_deadline')
    return value
class Timeval(ctypes.Structure):
    _fields_ = [('tv_sec', ctypes.c_long), ('tv_usec', ctypes.c_int)]
libc = ctypes.CDLL(None, use_errno=True)
setopt = libc.setsockopt
setopt.argtypes = [ctypes.c_int, ctypes.c_int, ctypes.c_int, ctypes.c_void_p, ctypes.c_uint]
setopt.restype = ctypes.c_int
def timeout_option(sock, option):
    seconds = remaining(); whole = int(seconds); usec = max(1, int((seconds-whole)*1_000_000))
    tv = Timeval(whole, usec)
    ctypes.set_errno(0)
    result = setopt(sock.fileno(), socket.SOL_SOCKET, option, ctypes.byref(tv), ctypes.sizeof(tv))
    return {'returncode': result, 'errno': ctypes.get_errno() if result < 0 else 0,
            'level': socket.SOL_SOCKET, 'option': option, 'optlen': ctypes.sizeof(tv),
            'seconds': whole, 'microseconds': usec}
header = b'owned-header'
body = b'owned-unread-upload-22'
response = b'HTTP/1.1 307 Temporary Redirect\r\nLocation: https://localhost/owned\r\nContent-Length: 0\r\nConnection: close\r\n\r\n'
assert len(body) == 22
sockets = []; worker = None; peer_result = {}; client = None
report = {'schema':'heptabao.mac-tcp-pending-bytes-observation.v1','diagnostic_only':True,
          'source_sha256':hashlib.sha256(code).hexdigest(),'status':'failed',
          'product_executed':False,'tls_executed':False,'credentials_used':False,
          'external_network':False,'production_changed':False,'original_deadline_seconds':5,
          'server_body_read_bytes':0,'new_connections_planned':1,'qualification':False}
def serve(listener):
    conn = None
    try:
        listener.settimeout(remaining())
        conn, addr = listener.accept(); sockets.append(conn)
        assert addr[0] == '127.0.0.1'
        conn.setblocking(True)
        conn.settimeout(remaining())
        received = bytearray()
        while len(received) < len(header):
            part = conn.recv(len(header)-len(received))
            if not part: raise RuntimeError('early_header_eof')
            received.extend(part)
        assert bytes(received) == header
        peer_result['header_bytes_read'] = len(received)
        peer_result['body_read_bytes'] = 0
        conn.settimeout(remaining())
        conn.sendall(response)
        peer_result['response_bytes_sent'] = len(response)
    except BaseException as error:
        peer_result['error_type'] = type(error).__name__
        peer_result['errno'] = getattr(error,'errno',None)
    finally:
        if conn is not None: conn.close()
        peer_result['socket_closed'] = conn is None or conn.fileno() == -1
try:
    listener = socket.socket(); sockets.append(listener)
    listener.bind(('127.0.0.1',0)); listener.listen(1)
    worker = threading.Thread(target=serve,args=(listener,),daemon=False); worker.start()
    client = socket.create_connection(listener.getsockname(),timeout=remaining()); sockets.append(client)
    client.setblocking(True)
    report['connected_receive_timeout'] = timeout_option(client,socket.SO_RCVTIMEO)
    report['connected_send_timeout'] = timeout_option(client,socket.SO_SNDTIMEO)
    assert report['connected_receive_timeout']['returncode'] == report['connected_send_timeout']['returncode'] == 0
    client.sendall(header+body)
    worker.join(remaining())
    assert not worker.is_alive() and not peer_result.get('error_type') and peer_result['socket_closed']
    report['after_peer_close_receive_timeout'] = timeout_option(client,socket.SO_RCVTIMEO)
    try:
        peer = client.getpeername()
        report['peer_name_available'] = peer[0] == '127.0.0.1'
    except OSError as error:
        report['peer_name_errno'] = error.errno
    # Do not read SO_ERROR: that would consume a pending socket error.
    ready, _, _ = select.select([client],[],[],remaining())
    assert ready == [client]
    remaining()
    try:
        data = client.recv(4096, socket.MSG_DONTWAIT)
        report['direct_read_after_ready'] = {'bytes':len(data),'sha256':hashlib.sha256(data).hexdigest(),
             'exact_complete_response':data==response,'errno':0}
    except OSError as error:
        report['direct_read_after_ready'] = {'errno':error.errno,'error_type':type(error).__name__}
    report['status'] = 'observed'
except BaseException as error:
    report['error_type'] = type(error).__name__
    report['errno'] = getattr(error,'errno',None)
finally:
    for s in list(sockets):
        try: s.close()
        except OSError: pass
    if worker is not None: worker.join(1.0)
    report['server'] = peer_result
    report['worker_joined'] = worker is None or not worker.is_alive()
    report['all_owned_sockets_closed'] = all(s.fileno()==-1 for s in sockets)
    report['observed_socket_count'] = len(sockets)
    report['elapsed_seconds'] = time.monotonic()-(deadline-5.0)
    if not report['worker_joined'] or not report['all_owned_sockets_closed']: report['status']='failed'
    raw=(json.dumps(report,sort_keys=True,indent=2)+'\n').encode()
    with (root/'result.public.json').open('xb') as f:
        f.write(raw);f.flush();os.fsync(f.fileno())
    fd=os.open(root,os.O_RDONLY)
    try:os.fsync(fd)
    finally:os.close(fd)
    print(json.dumps({'status':report['status'],'path':str(root/'result.public.json'),
          'sha256':hashlib.sha256(raw).hexdigest(),'all_owned_stopped':report['worker_joined'] and report['all_owned_sockets_closed']}),flush=True)
raise SystemExit(0 if report['status']=='observed' else 1)
