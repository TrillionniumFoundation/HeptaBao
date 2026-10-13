"""Linux/macOS same-UID Unix-socket proxy for an explicit, finite route allowlist.

The upstream HTTPS origin and namespace are fixed by an admitted AppRole agent.
No incoming credentials, redirects, arbitrary URLs, retry or auth/system
management routes. Optional owned mTLS loopback and online leased-response cache
are bounded features, not a general OpenBao Proxy replacement.
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
from .local_api import CacheClearValueMissing, LeaseCache, LocalAPI, validate_listener
from .deadline_transport import DeadlineClient

MAX_HEADERS=16384
MAX_BODY=262144
MAX_RESPONSE=16*1024*1024


def configuration(path):
    value=private_json(path)
    allowed={'agent_config','socket_dir','routes','allow_effects','timeout','max_runtime_seconds','max_requests',
             'listener','require_request_header','enable_quit','cache_enabled','cache_max_entries','cache_max_bytes'}
    if not isinstance(value,dict) or set(value)-allowed:
        raise BaoError('invalid_proxy_configuration')
    try:
        if any(not isinstance(value[k],str) or not Path(value[k]).is_absolute() for k in ('agent_config','socket_dir')):
            raise BaoError('proxy_absolute_paths_required')
        value.setdefault('allow_effects',False)
        if type(value['allow_effects']) is not bool:raise BaoError('proxy_effect_flag_invalid')
        validate_routes(value)
        for name,default in [('require_request_header',False),('enable_quit',False),('cache_enabled',False)]:
            value.setdefault(name,default)
            if type(value[name]) is not bool:raise BaoError('invalid_proxy_flag')
        for name,default,low,high in [('cache_max_entries',64,1,1024),('cache_max_bytes',1048576,1024,16777216)]:
            value.setdefault(name,default)
            if type(value[name]) is not int or not low<=value[name]<=high:raise BaoError('invalid_proxy_cache_bound')
        if value.get('listener') is not None:
            value['listener']=validate_listener({**value['listener'],'routes':value['routes'],
                'allow_effects':value['allow_effects'], 'timeout':value.get('timeout',5),
                'max_runtime_seconds':value.get('max_runtime_seconds',3600),
                'max_requests':value.get('max_requests',10000),
                'cache_enabled':value['cache_enabled'], 'cache_max_entries':value['cache_max_entries'],
                'cache_max_bytes':value['cache_max_bytes']})
        for name,default,low,high in [('timeout',5,1,30),('max_runtime_seconds',3600,1,86400),('max_requests',10000,1,100000)]:
            value.setdefault(name,default)
            if type(value[name]) is not int or not low<=value[name]<=high:raise BaoError('invalid_proxy_resource_bound')
        agent=AgentConfig.load(value['agent_config'])
        if Path(value['socket_dir'])==Path(agent.state_dir):raise BaoError('proxy_and_agent_directories_must_differ')
        return value,agent
    except (KeyError,TypeError,ValueError):
        raise BaoError('invalid_proxy_configuration') from None


def validate_routes(value):
    try:
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
    except (KeyError,TypeError,ValueError):
        raise BaoError('invalid_proxy_routes') from None


def _remaining(end):
    remaining=end-time.monotonic()
    if remaining<=0:raise BaoError('proxy_request_deadline')
    return remaining


class RequestHeaderRequired(BaoError):
    pass


def read_request(stream,end,*,with_consistency=False,with_controls=False,require_request_header=False):
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
    headers={}
    request_headers=[]
    rejected_headers=False
    indices=[]; behaviors=[]
    allowed={'host','content-length','content-type','accept','connection','user-agent'}
    for line in lines[1:]:
        if ':' not in line or line.startswith((' ','\t')):raise BaoError('proxy_header_framing')
        name,val=line.split(':',1);name=name.lower()
        if name=='x-vault-request':
            if any((ord(c)<32 and c!='\t') or ord(c)==127 for c in val):raise BaoError('proxy_header_rejected')
            request_headers.append(val.strip())
            continue
        if name in ('x-vault-index','x-vault-inconsistent'):
            if any(ord(c)<32 or ord(c)==127 for c in val):
                raise BaoError('proxy_header_rejected')
            target_values = indices if name == 'x-vault-index' else behaviors
            target_values.append(val.strip())
            if len(indices)>1 or len(behaviors)>2:
                raise BaoError('proxy_consistency_header_count')
            continue
        if any((ord(c)<32 and c!='\t') or ord(c)==127 for c in val):raise BaoError('proxy_header_rejected')
        if name not in allowed or name in headers:rejected_headers=True
        headers[name]=val.strip()
    if require_request_header and request_headers!=['true']:
        raise RequestHeaderRequired('request_header_required')
    if rejected_headers:raise BaoError('proxy_header_rejected')
    control=with_controls and target in ('/agent/v1/quit','/proxy/v1/quit',
                                         '/agent/v1/cache-clear','/proxy/v1/cache-clear')
    if not control and (not target.startswith('/v1/') or key_path(target[4:])!=target[4:]):
        raise BaoError('proxy_canonical_path_required')
    try:
        metadata = Metadata(indices[0] if indices else None, tuple(behaviors))
    except InvalidConsistency as error:
        raise BaoError(str(error)) from None
    if not headers.get('host') or headers.get('connection','close').lower()!='close':
        raise BaoError('proxy_host_and_close_required')
    length=headers.get('content-length','0')
    if not length.isascii() or not length.isdigit() or len(length)>9:raise BaoError('proxy_content_length')
    length=int(length)
    if length>MAX_BODY or (not control and method in ('GET','LIST','HEAD') and length):raise BaoError('proxy_body_limit')
    if len(body)>length:raise BaoError('proxy_pipelining_rejected')
    while len(body)<length:
        stream.settimeout(_remaining(end));part=stream.recv(min(65536,length-len(body)))
        if not part:raise BaoError('proxy_incomplete_body')
        body+=part
    if body and not control and headers.get('content-type','').lower()!='application/json':raise BaoError('proxy_json_body_required')
    data=body if control else decode_json(body) if body else None
    if not control and data is not None and not isinstance(data,dict):raise BaoError('proxy_json_object_required')
    if control:
        return method,target,data,metadata,True
    if with_controls:
        return method,target[4:],data,metadata,False
    if with_consistency:
        return method,target[4:],data,metadata
    if metadata.headers():
        raise BaoError('proxy_consistency_context_required')
    return method,target[4:],data


def forward(config,agent_config,method,path,payload,*,client_factory=Client,deadline=None,consistency=None,cache=None):
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
        token,state=token_snapshot(directory,time.time(),binding)
    timeout = config['timeout'] if deadline is None else min(config['timeout'], _remaining(deadline))
    if client_factory is Client:
        client=DeadlineClient(agent_config.address,agent_config.ca_file,token,agent_config.namespace,timeout,
                              trusted_ca_pem=trusted_ca,deadline=deadline)
    else:client=client_factory(agent_config.address,agent_config.ca_file,token,agent_config.namespace,timeout,trusted_ca_pem=trusted_ca)
    metadata=consistency if consistency is not None else Metadata()
    key=None
    accessor=None
    # Check actual Agent admission before an extra lookup could consume a use.
    # Finite and legacy snapshots skip caching and make one upstream request.
    if cache is not None and cache.enabled and type(state.get('token_num_uses')) is int and state['token_num_uses']==0:
        # Do not serve a cached response for a remotely revoked token or during
        # an upstream outage. Cached secrets never introduce an offline bypass.
        lookup=client.request('GET','/v1/auth/token/lookup-self')
        if lookup.status!=200:
            cache.records.clear()
            return lookup
        accessor=lookup.data().get('accessor')
        if not isinstance(accessor,str) or not accessor:raise BaoError('proxy_token_accessor_missing')
        key=cache.key(token,agent_config.namespace,method,path,payload,metadata)
        hit=cache.get(key)
        if hit is not None:return hit
    start_wall,start_mono=time.time(),time.monotonic()
    if deadline is not None:client.timeout=min(config['timeout'],_remaining(deadline))
    if consistency is not None:
        response=client.request(method,'/v1/'+path,payload,consistency_index=consistency.index,
                                inconsistent=consistency.behavior)
    else:response=client.request(method,'/v1/'+path,payload)
    if key is not None:cache.put(key,response,state,accessor,start_wall,start_mono)
    return response


def handle_request(stream,config,agent_config,stop,kind,cache,*,end=None):
    end=time.monotonic()+config['timeout'] if end is None else end
    try:
        method,path,body,metadata,control=read_request(stream,end,with_controls=True,
            require_request_header=config.get('require_request_header',False))
        if control:
            if not path.startswith('/'+kind+'/v1/'):
                send_response(stream,404,{},end);return
            if path.endswith('/quit'):
                if not config.get('enable_quit',False):send_response(stream,404,{},end);return
                if method!='POST':send_response(stream,405,{},end);return
                send_response(stream,200,{},end)
                stop.set();return
            if cache.enabled and method in ('POST','PUT'):
                try:cache.clear(decode_json(body))
                except CacheClearValueMissing:send_response(stream,500,{'errors':['cache value required']},end);return
                except (BaoError,ValueError,TypeError):send_response(stream,400,{'errors':['invalid cache clear request']},end);return
            send_response(stream,200,{},end);return
        response=forward(config,agent_config,method,path,body,deadline=end,consistency=metadata,cache=cache)
        send_response(stream,response.status,response.body,end,method=='HEAD',
            consistency_index=response.consistency_index if response.consistency_valid else None,
            retry_after_seconds=response.retry_after_seconds)
    except RequestHeaderRequired:
        send_response(stream,412,{'errors':['missing required X-Vault-Request header']},end)
    except (BaoError,OSError,ValueError,TypeError):
        # A fixed write-only cleanup budget can report an expired upstream
        # deadline. It never admits another upstream operation or retry.
        try:send_response(stream,503,{'errors':['request rejected or outcome unknown; do not retry effects blindly']},max(end,time.monotonic()+.25))
        except (BaoError,OSError):pass


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
    owned = None
    try:
        os.fchdir(directory.fd)
        listener.bind('api.sock')
        owned = os.stat('api.sock', dir_fd=directory.fd, follow_symlinks=False)
    finally:
        try:
            os.fchdir(previous)
        except OSError:
            # The CLI stops on a failed cwd restoration. Capture the created
            # inode before restoration so failure cannot strand our listener.
            listener.close()
            if owned is not None:
                try:
                    current = os.stat('api.sock', dir_fd=directory.fd,
                                      follow_symlinks=False)
                    if (stat.S_ISSOCK(current.st_mode)
                            and (current.st_dev, current.st_ino)
                            == (owned.st_dev, owned.st_ino)):
                        os.unlink('api.sock', dir_fd=directory.fd)
                        os.fsync(directory.fd)
                except FileNotFoundError:
                    pass
            raise
        finally:
            os.close(previous)


def serve(config,agent_config,stop):
    if sys.platform not in ('linux', 'darwin'):
        raise BaoError('proxy_requires_kernel_peer_credentials')
    with StateDirectory(config['socket_dir'],writer=True) as directory:
        cache=LeaseCache(config)
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
                        handle_request(stream,config,agent_config,stop,'proxy',cache)
                    except (BaoError,OSError,ValueError,TypeError):
                        try:send_response(stream,503,{'errors':['request rejected or outcome unknown; do not retry effects blindly']},end)
                        except (BaoError,OSError):pass
        finally:
            cache.records.clear()
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
    args=parser.parse_args(argv);stop=threading.Event();handlers={};local_api=None
    try:
        config,agent=configuration(args.config)
        for sig in (signal.SIGINT,signal.SIGTERM):handlers[sig]=signal.signal(sig,lambda *_:stop.set())
        if config.get('listener') is not None:
            local_api=LocalAPI(config['listener'],agent,stop,'proxy')
            local_api.start()
            while not stop.is_set():stop.wait(0.2)
            local_api.close();local_api=None
        else:serve(config,agent,stop)
        return 0
    except (BaoError,OSError,ValueError,TypeError):
        print('heptabao-proxy: stopped or blocked; no automatic effect retry',file=sys.stderr);return 2
    finally:
        if local_api is not None:
            try:local_api.close()
            except (BaoError,OSError):pass
        for sig,handler in handlers.items():signal.signal(sig,handler)


if __name__=='__main__':raise SystemExit(main())
