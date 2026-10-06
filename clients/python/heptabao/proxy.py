"""Linux/macOS same-UID Unix-socket proxy for an explicit, finite route allowlist.

The upstream HTTPS origin and namespace are fixed by an admitted AppRole agent.
No incoming credentials, redirects, arbitrary URLs, caches, retry, auth/system
management routes or TCP listener. This is not a general OpenBao Proxy replacement.
"""
from __future__ import annotations
import json
import os
from pathlib import Path
import signal
import socket
import stat
import struct
import sys
import threading
import time

from .consistency import Metadata, InvalidConsistency, validate_index
from .agent import AgentConfig
from .private_state import StateDirectory, token_snapshot, read_trusted_ca
from .transport import BaoError, Client, SafeArgumentParser, canonical, decode_json, key_path, private_json

MAX_HEADERS=16384
MAX_BODY=262144
MAX_RESPONSE=16*1024*1024


def configuration(path):
    value=private_json(path)
    allowed={'agent_config','socket_dir','routes','allow_effects','timeout','max_runtime_seconds','max_requests'}
    if not isinstance(value,dict) or set(value)-allowed:
        raise BaoError('invalid_proxy_configuration')
    try:
        if any(not isinstance(value[k],str) or not Path(value[k]).is_absolute() for k in ('agent_config','socket_dir')):
            raise BaoError('proxy_absolute_paths_required')
        value.setdefault('allow_effects',False)
        if type(value['allow_effects']) is not bool:raise BaoError('proxy_effect_flag_invalid')
        routes=value['routes']
        if not isinstance(routes,list) or not 1<=len(routes)<=64:raise BaoError('proxy_route_bound')
        seen=set()
        for row in routes:
            if not isinstance(row,dict) or set(row)!={'method','path','effectful'} or type(row['effectful']) is not bool:
                raise BaoError('invalid_proxy_route')
            if row['method'] not in ('GET','LIST','HEAD','POST','PUT','PATCH','DELETE'):
                raise BaoError('invalid_proxy_method')
            if key_path(row['path'])!=row['path'] or row['path'].startswith(('auth/','sys/')):
                raise BaoError('proxy_route_is_not_an_admissible_product_route')
            if (row['method'] not in ('GET','LIST','HEAD') and not row['effectful']) or (row['effectful'] and not value['allow_effects']):
                raise BaoError('proxy_effect_requires_explicit_admission')
            pair=(row['method'],row['path'])
            if pair in seen:raise BaoError('duplicate_proxy_route')
            seen.add(pair)
        for name,default,low,high in [('timeout',5,1,30),('max_runtime_seconds',3600,1,86400),('max_requests',10000,1,100000)]:
            value.setdefault(name,default)
            if type(value[name]) is not int or not low<=value[name]<=high:raise BaoError('invalid_proxy_resource_bound')
        agent=AgentConfig.load(value['agent_config'])
        if Path(value['socket_dir'])==Path(agent.state_dir):raise BaoError('proxy_and_agent_directories_must_differ')
        return value,agent
    except (KeyError,TypeError,ValueError):
        raise BaoError('invalid_proxy_configuration') from None


def _remaining(end):
    remaining=end-time.monotonic()
    if remaining<=0:raise BaoError('proxy_request_deadline')
    return remaining


def read_request(stream,end,*,with_consistency=False):
    raw=bytearray()
    while b'\r\n\r\n' not in raw:
        stream.settimeout(_remaining(end))
        part=stream.recv(4096)
        if not part:raise BaoError('proxy_incomplete_headers')
        raw.extend(part)
        if len(raw)>MAX_HEADERS+4096:raise BaoError('proxy_header_limit')
    head,body=bytes(raw).split(b'\r\n\r\n',1)
    if len(head)>MAX_HEADERS:raise BaoError('proxy_header_limit')
    try:lines=head.decode('ascii').split('\r\n')
    except UnicodeError:raise BaoError('proxy_ascii_headers_required') from None
    first=lines[0].split(' ')
    if len(first)!=3 or first[2]!='HTTP/1.1' or len(lines)>101:raise BaoError('proxy_request_line')
    method,target,_=first
    if not target.startswith('/v1/') or key_path(target[4:])!=target[4:]:raise BaoError('proxy_canonical_path_required')
    headers={}
    indices=[]; behaviors=[]
    allowed={'host','content-length','content-type','accept','connection','user-agent'}
    for line in lines[1:]:
        if ':' not in line or line.startswith((' ','\t')):raise BaoError('proxy_header_framing')
        name,val=line.split(':',1);name=name.lower()
        if name in ('x-vault-index','x-vault-inconsistent'):
            if any(ord(c)<32 or ord(c)==127 for c in val):
                raise BaoError('proxy_header_rejected')
            target_values = indices if name == 'x-vault-index' else behaviors
            target_values.append(val.strip())
            if len(indices)>1 or len(behaviors)>2:
                raise BaoError('proxy_consistency_header_count')
            continue
        if name not in allowed or name in headers or any(ord(c)<32 or ord(c)==127 for c in val):
            raise BaoError('proxy_header_rejected')
        headers[name]=val.strip()
    try:
        metadata = Metadata(indices[0] if indices else None, tuple(behaviors))
    except InvalidConsistency as error:
        raise BaoError(str(error)) from None
    if not headers.get('host') or headers.get('connection','close').lower()!='close':
        raise BaoError('proxy_host_and_close_required')
    length=headers.get('content-length','0')
    if not length.isascii() or not length.isdigit() or len(length)>9:raise BaoError('proxy_content_length')
    length=int(length)
    if length>MAX_BODY or (method in ('GET','LIST','HEAD') and length):raise BaoError('proxy_body_limit')
    if len(body)>length:raise BaoError('proxy_pipelining_rejected')
    while len(body)<length:
        stream.settimeout(_remaining(end));part=stream.recv(min(65536,length-len(body)))
        if not part:raise BaoError('proxy_incomplete_body')
        body+=part
    if body and headers.get('content-type','').lower()!='application/json':raise BaoError('proxy_json_body_required')
    data=decode_json(body) if body else None
    if data is not None and not isinstance(data,dict):raise BaoError('proxy_json_object_required')
    if with_consistency:
        return method,target[4:],data,metadata
    if metadata.headers():
        raise BaoError('proxy_consistency_context_required')
    return method,target[4:],data


def forward(config,agent_config,method,path,payload,*,client_factory=Client,deadline=None,consistency=None):
    if not any(row['method']==method and row['path']==path for row in config['routes']):
        raise BaoError('proxy_route_not_admitted')
    if consistency is not None and not isinstance(consistency, Metadata):
        raise BaoError('invalid_consistency_metadata')
    if deadline is not None:
        _remaining(deadline)
    # No persisted session cache; every request observes the current sink generation.
    trusted_ca = read_trusted_ca(agent_config.ca_file)
    binding=agent_config.binding()
    if read_trusted_ca(agent_config.ca_file) != trusted_ca:
        raise BaoError('proxy_trust_configuration_changed')
    with StateDirectory(agent_config.state_dir) as directory:
        token,_=token_snapshot(directory,time.time(),binding)
    timeout = config['timeout'] if deadline is None else min(config['timeout'], _remaining(deadline))
    client=client_factory(agent_config.address,agent_config.ca_file,token,agent_config.namespace,timeout,trusted_ca_pem=trusted_ca)
    if consistency is not None:
        return client.request(method,'/v1/'+path,payload,consistency_index=consistency.index,
                              inconsistent=consistency.behavior)
    return client.request(method,'/v1/'+path,payload)


def send_response(stream,status,body,end,head=False,*,consistency_index=None,retry_after_seconds=None):
    raw=canonical(body) if body else b''
    if len(raw)>MAX_RESPONSE:raise BaoError('proxy_response_limit')
    if not 100<=status<=599:raise BaoError('proxy_response_status')
    try:
        validate_index(consistency_index)
    except InvalidConsistency as error:
        raise BaoError(str(error)) from None
    index_header = '' if consistency_index is None else f'X-Vault-Index: {consistency_index}\r\n'
    retry_header = ''
    if retry_after_seconds is not None:
        if type(retry_after_seconds) is not int or not 0<=retry_after_seconds<=86400:
            raise BaoError('proxy_invalid_retry_after')
        retry_header = f'Retry-After: {retry_after_seconds}\r\n'
    header=(f'HTTP/1.1 {status} Response\r\nContent-Type: application/json\r\nContent-Length: {len(raw)}\r\n'
            f'{index_header}{retry_header}Connection: close\r\nCache-Control: no-store\r\n\r\n').encode('ascii')
    stream.settimeout(_remaining(end));stream.sendall(header+(b'' if head else raw))



def _peer_uid(stream):
    if sys.platform == 'linux' and hasattr(socket, 'SO_PEERCRED'):
        return struct.unpack('3i', stream.getsockopt(
            socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize('3i')))[1]
    if sys.platform == 'darwin':
        # Darwin's libc reports the effective credentials at connect/listen.
        # https://developer.apple.com/library/archive/documentation/System/Conceptual/ManPages_iPhoneOS/man3/getpeereid.3.html
        import ctypes
        libc = ctypes.CDLL(None, use_errno=True)
        query = libc.getpeereid
        query.argtypes = [ctypes.c_int, ctypes.POINTER(ctypes.c_uint),
                         ctypes.POINTER(ctypes.c_uint)]
        query.restype = ctypes.c_int
        uid, gid = ctypes.c_uint(), ctypes.c_uint()
        if query(stream.fileno(), ctypes.byref(uid), ctypes.byref(gid)) != 0:
            raise OSError(ctypes.get_errno(), 'proxy peer credentials unavailable')
        return uid.value
    raise BaoError('proxy_requires_kernel_peer_credentials')


def _bind_listener(listener, directory):
    directory.check()
    if sys.platform == 'linux':
        listener.bind(f'/proc/self/fd/{directory.fd}/api.sock')
        return
    if sys.platform != 'darwin':
        raise BaoError('proxy_requires_descriptor_bound_socket')
    # The CLI has one serial worker. A process-wide cwd change is permitted only
    # before any additional threads exist; both directories remain open by fd.
    if (threading.current_thread() is not threading.main_thread()
            or threading.active_count() != 1):
        raise BaoError('proxy_macos_binding_requires_single_thread')
    previous = os.open('.', os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        os.fchdir(directory.fd)
        listener.bind('api.sock')
    finally:
        try:
            os.fchdir(previous)
        finally:
            os.close(previous)


def serve(config,agent_config,stop):
    if sys.platform not in ('linux', 'darwin'):
        raise BaoError('proxy_requires_kernel_peer_credentials')
    with StateDirectory(config['socket_dir'],writer=True) as directory:
        # A stale socket requires explicit operator cleanup; never delete an
        # unknown listener/file to "recover" automatically.
        try:os.stat('api.sock',dir_fd=directory.fd,follow_symlinks=False)
        except FileNotFoundError:pass
        else:raise BaoError('proxy_socket_already_exists')
        listener=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM)
        bound=False
        try:
            _bind_listener(listener, directory);bound=True
            os.chmod('api.sock',0o600,dir_fd=directory.fd,follow_symlinks=False)
            owned=os.stat('api.sock',dir_fd=directory.fd,follow_symlinks=False)
            directory.check()
            listener.listen(16);listener.settimeout(0.2)
            deadline=time.monotonic()+config['max_runtime_seconds']
            requests=0
            # One serial worker; at most 16 pending accepts and one upstream effect.
            while not stop.is_set() and requests<config['max_requests'] and time.monotonic()<deadline:
                directory.check()
                current=os.stat('api.sock',dir_fd=directory.fd,follow_symlinks=False)
                if (current.st_dev,current.st_ino)!=(owned.st_dev,owned.st_ino):raise BaoError('proxy_socket_replaced')
                try:stream,_=listener.accept()
                except socket.timeout:continue
                requests+=1
                with stream:
                    uid = _peer_uid(stream)
                    if uid!=os.geteuid():continue
                    end=time.monotonic()+config['timeout']
                    try:
                        method,path,body,metadata=read_request(stream,end,with_consistency=True)
                        response=forward(config,agent_config,method,path,body,deadline=end,consistency=metadata)
                        send_response(stream,response.status,response.body,end,method=='HEAD',
                                      consistency_index=response.consistency_index if response.consistency_valid else None,
                                      retry_after_seconds=response.retry_after_seconds)
                    except (BaoError,OSError,ValueError,TypeError):
                        try:send_response(stream,503,{'errors':['request rejected or outcome unknown; do not retry effects blindly']},end)
                        except (BaoError,OSError):pass
        finally:
            listener.close()
            if bound:
                # Remove only the socket inode created by this process.
                try:
                    current=os.stat('api.sock',dir_fd=directory.fd,follow_symlinks=False)
                    if stat.S_ISSOCK(current.st_mode) and 'owned' in locals() and (current.st_dev,current.st_ino)==(owned.st_dev,owned.st_ino):
                        os.unlink('api.sock',dir_fd=directory.fd);os.fsync(directory.fd)
                except FileNotFoundError:pass


def main(argv=None):
    parser=SafeArgumentParser(description=__doc__);parser.add_argument('--config',required=True)
    args=parser.parse_args(argv);stop=threading.Event();handlers={}
    try:
        config,agent=configuration(args.config)
        for sig in (signal.SIGINT,signal.SIGTERM):handlers[sig]=signal.signal(sig,lambda *_:stop.set())
        serve(config,agent,stop);return 0
    except (BaoError,OSError,ValueError,TypeError):
        print('heptabao-proxy: stopped or blocked; no automatic effect retry',file=sys.stderr);return 2
    finally:
        for sig,handler in handlers.items():signal.signal(sig,handler)


if __name__=='__main__':raise SystemExit(main())
