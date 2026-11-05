#!/usr/bin/env python3
"""New R4 outer caller for the isolated Mac five-agent launchd fixture.

This is executable source for review, not a runtime grant. Production input
reads occur only inside the separately admitted kernel-sandboxed capture entry.
Only new ROOT files, two exact owned launchd labels, and one new loopback TLS
server may change. Any unknown operation stops the finite graph; it is never
replayed. Completed synthetic proof does not by itself authorize this caller.
"""
from __future__ import annotations
import argparse, base64, copy, errno, hashlib, json, math, os, re, select, signal
import socket, ssl, stat, sys, time, traceback
from pathlib import Path

ROOT=Path('/Volumes/T5/hepta-vnext-recovery-20261013/mac-authbus-r10-current-consumer-r1')
QA=ROOT/'qa'
COMMIT='49503322c7f446e5eb41e7744f1fdbd7f1192ecc'
TREE='1d4211f91e1b34a2ed087a3bbef2e2884bac88e9'
BINARY=Path('/Volumes/T5/hepta-vnext-recovery-20261013/continuation-20261104-native-http-r10/normal-release-tests-r1/artifacts/heptabao-server')
BINARY_SHA='bc1fc6b8ded5a43a60ab4c562cd5e092e63ae9df77afd654c9af8c096c128c98'
BINARY_BYTES=93038816
NAMES=('mac_guarded_current_capture_r3.py','mac_capture_sqlite_synthetic_r1.py',
 'mac_capture_sqlite_synthetic_r2.py','mac_owned_commands_r1.py','mac_t5_volume_guard_r1.py',
 'mac_owned_unreaped_r1.py','mac_native_process_observer_r1.py','mac_current_phase_owner_r2.py',
 'mac_current_server_owner_r1.py','mac_owned_launchd_r3.py','mac_current_fixture_materializer_r1.py',
 'mac_current_capture_entry_r1.py','mac_current_outer_inputs_r2.py','mac_current_outer_r4.py',
 'mac_current_cycle_r2.mjs','mac_single_native_r2.mjs','mac_auth_rows_cas_r1.mjs',
 'mac_authbus_cache_cas_r1.mjs')
ENTRY_NAMES=('mac_current_capture_entry_r1.py','mac_guarded_current_capture_r3.py',
 'mac_t5_volume_guard_r1.py','mac_owned_commands_r1.py','mac_owned_unreaped_r1.py')
SYNTHETIC={
 'schema':'heptabao.mac-capture-synthetic-input-binding.r1',
 'jobId':'1a1a918c6cf-fc05-3143',
 'stdoutSha256':'6c14a7f95e4f059090da2e88a3fff80eac79c1d83ef58a29df3cc67a610cd8f5',
 'stdoutBytes':16228,'authoritySha256':'1b33a9144712ac2bc3d16d87bb2a9ea1c2e4c0be236dfd08d8b599f7518942dd',
 'authorityBytes':733,'controllerSha256':'f3c6bb336814411aa4a24490f0904cdbd0fac2bb89dbcc36d6151ada13a51ba2'}
AGENTS=('main','trnm','hepta-ui','hepta','hepta-backend')
NEW_OUTER_SECONDS=900.0
NEW_OUTER_FAILURE_CLEANUP_SECONDS=60.0
NEW_LISTENER_READY_SECONDS=30.0
HTTP_SECONDS=10.0
CAPTURE_SECONDS=45.0
MAX_HTTP_BODY=2*1024*1024
MAX_PUBLIC_REPORT=2*1024*1024
FIXED_UTILITIES={
  "/usr/bin/openssl": {
    "bytes": 1130832,
    "sha256": "f81b4fcec5048ea1eceb40fc08f4e06f1668181f0b5bacfa8be27d0da181dcb7",
    "identity": [
      "16777233",
      "1152921500312572476",
      "0",
      "0",
      "33261",
      "1",
      "1130832",
      "1786589515000000000",
      "1786589515000000000"
    ]
  },
  "/usr/bin/sandbox-exec": {
    "bytes": 102368,
    "sha256": "abc5bb136d6b5cce8fa85d789f78e3326c51ca60cae637b2064adfb67a1dcd9a",
    "identity": [
      "16777233",
      "1152921500312572700",
      "0",
      "0",
      "33261",
      "1",
      "102368",
      "1786589515000000000",
      "1786589515000000000"
    ]
  },
  "/bin/launchctl": {
    "bytes": 363488,
    "sha256": "b4dbf509754d8e1117f7851baa93ede75bc75218c48d6ddf19fbb1505d261be7",
    "identity": [
      "16777233",
      "1152921500312571385",
      "0",
      "0",
      "33261",
      "1",
      "363488",
      "1786589515000000000",
      "1786589515000000000"
    ]
  },
  "/usr/sbin/diskutil": {
    "bytes": 1937776,
    "sha256": "624a8601b97ddfaa4b18dd2854c299e084cd45eb18fc152011c97615c3b9da1f",
    "identity": [
      "16777233",
      "1152921500312575979",
      "0",
      "0",
      "33261",
      "1",
      "1937776",
      "1786589515000000000",
      "1786589515000000000"
    ]
  },
  "/bin/ps": {
    "bytes": 170432,
    "sha256": "3bbba882e30d91fc4ff6e6844ca7c59fef4351b9a3fea35dca55708d6d487d1c",
    "identity": [
      "16777233",
      "1152921500312571399",
      "0",
      "0",
      "35309",
      "1",
      "170432",
      "1786589515000000000",
      "1786589515000000000"
    ]
  },
  "/sbin/mount": {
    "bytes": 174016,
    "sha256": "e0368cc89f48770e30dcbc639ae4d99d3ee478516b0186baf3e030ce9828e5dd",
    "identity": [
      "16777233",
      "1152921500312571481",
      "0",
      "0",
      "33133",
      "1",
      "174016",
      "1786589515000000000",
      "1786589515000000000"
    ]
  }
}
START=time.monotonic()

class Refused(RuntimeError):pass
def need(value,code):
    if not value:raise Refused(code)
def sha(raw):return hashlib.sha256(raw).hexdigest()
def encoded(value):
    return (json.dumps(value,sort_keys=True,separators=(',',':'),ensure_ascii=False,allow_nan=False)+'\n').encode()
def canonical(value):
    return json.dumps(value,sort_keys=True,separators=(',',':'),ensure_ascii=False,allow_nan=False).encode()
def digest(value):return sha(canonical(value))
def ident(s):
    return tuple(str(v) for v in (s.st_dev,s.st_ino,s.st_uid,s.st_gid,s.st_mode,
        s.st_nlink,s.st_size,s.st_mtime_ns,s.st_ctime_ns))
def valid_pin(value):return isinstance(value,str) and re.fullmatch('[0-9a-f]{64}',value) is not None
def exact_json(raw):
    def pairs(items):
        result={}
        for key,value in items:
            need(key not in result,'duplicate_json_member');result[key]=value
        return result
    return json.loads(raw,object_pairs_hook=pairs,parse_constant=lambda _:(_ for _ in ()).throw(Refused('nonfinite_json')))

class Context:
    def __init__(self):
        self.until=START+NEW_OUTER_SECONDS
        self.signals=None;self.cleanup_mode=False;self.cleanup_until=None
        self.rows=[];self.close_errors=[];self.unknown=False
        self.port_reservation=None
    def remaining(self,until=None):
        if self.cleanup_mode:
            bound=self.cleanup_until
        else:
            need(self.signals is None or self.signals.pending is None,'outer_cancelled')
            bound=self.until
        if until is not None:bound=min(bound,until)
        left=bound-time.monotonic();need(left>0,'original_outer_or_exact_step_deadline');return left
    def critical(self):
        from contextlib import nullcontext
        return self.signals.critical() if self.signals is not None else nullcontext()
    def fd(self,fd,label):
        row={'fd':fd,'label':label,'attempted':False,'closed':False};self.rows.append(row);return row
    def close(self,row):
        if row['attempted']:return
        with self.critical():
            row['attempted']=True
            try:os.close(row['fd']);row['closed']=True
            except BaseException as error:
                row['errorType']=type(error).__name__;self.close_errors.append(type(error).__name__);self.unknown=True
    def close_all(self):
        for row in reversed(self.rows):self.close(row)
    def public(self):
        reservation=self.port_reservation
        return {'allOuterReadDescriptorsClosed':all(x['closed'] for x in self.rows),
            'descriptorCount':len(self.rows),'closeErrors':list(self.close_errors),
            'portReservation':None if reservation is None else dict(reservation),
            'allEphemeralPortReservationSocketsClosed':bool(reservation is None or not reservation['created']
                or (reservation['closeAttempted'] and reservation['closed'])),
            'newOuterSeconds':NEW_OUTER_SECONDS,'newFailureCleanupSeconds':NEW_OUTER_FAILURE_CLEANUP_SECONDS}

def read_public_source(ctx,path,pin):
    need(Path(path).parent==QA and Path(path).name in NAMES and valid_pin(pin),'fixed_outer_public_source')
    row=None
    try:
        with ctx.critical():row=ctx.fd(os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK),'public-qa')
        first=os.fstat(row['fd'])
        need(stat.S_ISREG(first.st_mode) and first.st_uid==501 and first.st_nlink==1
             and stat.S_IMODE(first.st_mode)==0o600 and 0<first.st_size<=1024*1024,
             'public_qa_custody')
        out=bytearray()
        while len(out)<=first.st_size:
            ctx.remaining();part=os.read(row['fd'],min(65536,first.st_size+1-len(out)))
            if not part:break
            out.extend(part)
        need(len(out)==first.st_size and sha(out)==pin and ident(first)==ident(os.fstat(row['fd']))
             ==ident(Path(path).lstat()),'public_qa_whole_pin_and_named_fd')
        return list(ident(first))
    finally:
        if row is not None:ctx.close(row)
        need(row is None or row['closed'],'public_qa_close')

def read_system_tool(ctx,path,expected):
    need(str(path) in FIXED_UTILITIES and expected==FIXED_UTILITIES[str(path)],
         'six_actual_system_tool_inputs_only')
    path=Path(path);need(path.resolve(strict=True)==path,'observed_system_tool_has_no_alias')
    row=None
    try:
        before=path.lstat()
        need(ident(before)==tuple(expected['identity']) and stat.S_ISREG(before.st_mode),
             'actual_system_tool_full_stat_identity')
        with ctx.critical():
            row=ctx.fd(os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK),'actual-public-system-tool')
        need(ident(os.fstat(row['fd']))==tuple(expected['identity']),'same_actual_tool_open_fd')
        h=hashlib.sha256();count=0
        while count<=expected['bytes']:
            ctx.remaining();part=os.read(row['fd'],min(65536,expected['bytes']+1-count))
            if not part:break
            count+=len(part);h.update(part)
        need(count==expected['bytes'] and h.hexdigest()==expected['sha256']
             and ident(os.fstat(row['fd']))==ident(path.lstat())==tuple(expected['identity'])
             and path.resolve(strict=True)==path,'actual_system_tool_full_sha_name_and_fd')
        return list(expected['identity'])
    finally:
        if row is not None:ctx.close(row)
        need(row is None or row['closed'],'system_tool_read_descriptor_closed')

class LoopbackHTTP:
    """One TLS connection per explicit request, no redirect or retry.

    Nonblocking socket/SSL operations and all framing share one original ten
    second absolute deadline. A full, typed response and actual socket closure
    must precede clearing the operation record.
    """
    def __init__(self,ctx,port,ca_pem,peer_sha):
        need(type(port) is int and 1024<=port<=65535 and valid_pin(peer_sha),'fixed_loopback_tls')
        self.ctx=ctx;self.port=port;self.peer_sha=peer_sha
        self.ssl=ssl.create_default_context(cadata=ca_pem.decode('ascii'))
        self.ssl.check_hostname=True;self.ssl.verify_mode=ssl.CERT_REQUIRED
        self.ssl.set_alpn_protocols(['http/1.1'])
        self.rows=[];self.sockets=[];self.inflight=None;self.unknown=False
        self.root_token=None;self.secrets=[]
    def left(self,until):return self.ctx.remaining(until)
    def wait(self,sock,until,reading):
        left=self.left(until)
        r,w,e=select.select([sock] if reading else [],[] if reading else [sock],[sock],left)
        self.left(until);need(not e and bool(r or w),'loopback_socket_readiness')
    def close(self,row):
        if row['attempted']:return
        with self.ctx.critical():
            row['attempted']=True
            try:row['socket'].close();row['closed']=row['socket'].fileno()==-1
            except BaseException as error:row['errorType']=type(error).__name__
        if not row['closed']:self.unknown=True
    def recv(self,sock,until):
        while True:
            self.left(until)
            try:return sock.recv(65536)
            except ssl.SSLWantReadError:self.wait(sock,until,True)
            except ssl.SSLWantWriteError:self.wait(sock,until,False)
    def send(self,sock,raw,until):
        offset=0
        while offset<len(raw):
            self.left(until)
            try:
                n=sock.send(memoryview(raw)[offset:]);need(n>0,'tls_write_progress');offset+=n
            except ssl.SSLWantReadError:self.wait(sock,until,True)
            except ssl.SSLWantWriteError:self.wait(sock,until,False)
    def response(self,sock,until):
        buffer=bytearray()
        while b'\r\n\r\n' not in buffer:
            need(len(buffer)<=65536,'http_head_bound')
            part=self.recv(sock,until);need(bool(part),'http_head_complete');buffer.extend(part)
        boundary=buffer.index(b'\r\n\r\n')
        need(boundary<=65536,'http_head_bound')
        head=bytes(buffer[:boundary]);buffer=buffer[boundary+4:]
        lines=head.split(b'\r\n')
        match=re.fullmatch(rb'HTTP/1[.]1 ([0-9]{3}) [\x20-\x7e]*',lines[0])
        need(match is not None,'one_http11_response')
        status=int(match.group(1));need(200<=status<=599,'no_interim_or_upgrade_profile')
        headers={}
        for line in lines[1:]:
            name,separator,value=line.partition(b':')
            need(separator and re.fullmatch(rb"[!#$%&'*+.^_\x60|~0-9A-Za-z-]+",name)
                 and b'\x00' not in value,'unfolded_http_header')
            headers.setdefault(name.lower(),[]).append(value.strip())
        lengths=headers.get(b'content-length',[]);transfer=headers.get(b'transfer-encoding',[])
        need(len(lengths)<=1 and len(transfer)<=1 and not(lengths and transfer),'unambiguous_http_framing')
        need(headers.get(b'content-encoding',[]) in ([],[b'identity']),'uncompressed_json_response')
        def append_more():
            part=self.recv(sock,until);need(bool(part),'http_body_complete')
            buffer.extend(part);need(len(buffer)<=MAX_HTTP_BODY+65536,'bounded_http_buffer')
        if status in (204,304):
            need(not transfer and lengths in ([],[b'0']) and not buffer,'empty_status_frame')
            return status,b'','no-body'
        if lengths:
            need(re.fullmatch(rb'[0-9]{1,10}',lengths[0]) is not None,'decimal_content_length')
            length=int(lengths[0]);need(length<=MAX_HTTP_BODY,'http_body_bound')
            while len(buffer)<length:append_more()
            need(len(buffer)==length,'one_content_length_response_no_surplus')
            return status,bytes(buffer),'content-length'
        if transfer:
            need(transfer==[b'chunked'],'only_explicit_chunked_transfer')
            body=bytearray();chunks=0
            while True:
                while b'\r\n' not in buffer:
                    need(len(buffer)<=128,'chunk_size_line_bound');append_more()
                end=buffer.index(b'\r\n');line=bytes(buffer[:end]);del buffer[:end+2]
                need(len(line)<=128 and re.fullmatch(rb'[0-9a-fA-F]{1,8}(?:;[\x20-\x7e]*)?',line),
                     'typed_chunk_size')
                size=int(line.split(b';')[0],16);chunks+=1
                need(chunks<=32768 and len(body)+size<=MAX_HTTP_BODY,'bounded_chunked_body')
                if size==0:
                    # No trailers are needed by this API. Reject unreviewed
                    # trailing metadata rather than infer successful framing.
                    while len(buffer)<2:append_more()
                    need(bytes(buffer)==b'\r\n','empty_exact_chunk_trailer')
                    return status,bytes(body),'chunked'
                while len(buffer)<size+2:append_more()
                need(buffer[size:size+2]==b'\r\n','chunk_data_crlf')
                body.extend(buffer[:size]);del buffer[:size+2]
        need(headers.get(b'connection',[])==[b'close'],'explicit_close_delimited_response')
        while True:
            part=self.recv(sock,until)
            if not part:break
            buffer.extend(part);need(len(buffer)<=MAX_HTTP_BODY,'http_body_bound')
        return status,bytes(buffer),'tls-close-notify'
    def call(self,label,method,route,body=None,*,token=None,expected=200,validate=None,until=None):
        need(self.inflight is None and not self.unknown,'no_http_after_unknown')
        need(re.fullmatch('[a-zA-Z0-9_.-]{1,100}',label) and method in ('GET','POST','PUT','LIST')
             and re.fullmatch('[a-zA-Z0-9_./:-]{1,512}',route) and not route.startswith('/'),
             'explicit_safe_control_method_route')
        allowed_prefix=('sys/','auth/','openclaw-auth/')
        need(route.startswith(allowed_prefix),'owned_api_control_scope')
        started=time.monotonic();deadline=min(self.ctx.until,started+HTTP_SECONDS,
            until if until is not None else self.ctx.until)
        self.left(deadline);socks=[];result=None
        row={'name':label,'method':method,'route':route,'dispatched':False,
             'responseComplete':False,'responseValidated':False,'socketClosuresComplete':False,
             'originalRequestSeconds':10,'outcomeUnknown':False}
        self.rows.append(row);self.inflight=row
        try:
            with self.ctx.critical():
                raw=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
                raw_row={'socket':raw,'attempted':False,'closed':False,'transferred':False}
                self.sockets.append(raw_row);socks.append(raw_row)
            raw.setblocking(False)
            code=raw.connect_ex(('127.0.0.1',self.port))
            if code not in (0,errno.EINPROGRESS,errno.EWOULDBLOCK,errno.EALREADY):
                raise OSError(code,os.strerror(code))
            if code:
                self.wait(raw,deadline,False)
                error=raw.getsockopt(socket.SOL_SOCKET,socket.SO_ERROR)
                if error:raise OSError(error,os.strerror(error))
            self.left(deadline)
            with self.ctx.critical():
                tls=self.ssl.wrap_socket(raw,server_hostname='localhost',
                    do_handshake_on_connect=False,suppress_ragged_eofs=False)
                tls_row={'socket':tls,'attempted':False,'closed':False,'transferred':False}
                self.sockets.append(tls_row);socks.append(tls_row)
                need(raw.fileno()==-1,'raw_socket_transferred_to_registered_tls')
                raw_row['transferred']=True
            while True:
                self.left(deadline)
                try:tls.do_handshake();break
                except ssl.SSLWantReadError:self.wait(tls,deadline,True)
                except ssl.SSLWantWriteError:self.wait(tls,deadline,False)
            self.left(deadline)
            need(tls.selected_alpn_protocol() in (None,'http/1.1')
                 and sha(tls.getpeercert(binary_form=True))==self.peer_sha,'actual_trusted_tls_peer')
            row['tlsVerified']=True;row['peerSha256']=self.peer_sha
            payload=b'' if body is None else canonical(body)
            need(len(payload)<=MAX_HTTP_BODY,'control_request_body_bound')
            actual_token=self.root_token if token is None else token
            headers=[method+' /v1/'+route+' HTTP/1.1','Host: 127.0.0.1:'+str(self.port),
                     'Connection: close','Content-Length: '+str(len(payload))]
            if body is not None:headers.append('Content-Type: application/json')
            if actual_token:
                need(isinstance(actual_token,str) and len(actual_token)<=8192
                     and re.fullmatch('[\x21-\x7e]+',actual_token),'private_token_header_shape')
                headers.append('X-Vault-Token: '+actual_token)
            request=('\r\n'.join(headers)+'\r\n\r\n').encode('ascii')+payload
            row['dispatched']=True
            self.send(tls,request,deadline)
            status,reply,framing=self.response(tls,deadline)
            self.left(deadline)
            row.update(status=status,responseBytes=len(reply),responseSha256=sha(reply),
                       framing=framing,responseComplete=True)
            result={} if not reply else exact_json(reply)
            need(isinstance(result,dict),'typed_json_response_object')
            need(status==expected,'exact_expected_http_status')
            if validate is not None:validate(result)
            self.left(deadline);row['responseValidated']=True
        except BaseException as error:
            row['errorType']=type(error).__name__
            row['errorCode']=str(error) if isinstance(error,Refused) else None
            if row['dispatched']:self.unknown=True
            raise
        finally:
            for sock in reversed(socks):self.close(sock)
            row['socketClosuresComplete']=all(s['closed'] for s in socks)
            completed_at=time.monotonic()
            row['elapsedSeconds']=completed_at-started
            row['completedWithinOriginalDeadline']=completed_at<deadline
            row['outcomeUnknown']=bool((row['dispatched'] and (not row['responseValidated']
                or not row['completedWithinOriginalDeadline'])) or not row['socketClosuresComplete'])
            self.unknown=bool(self.unknown or row['outcomeUnknown'])
            if row['responseValidated'] and row['socketClosuresComplete'] and row['completedWithinOriginalDeadline']:
                self.inflight=None
            elif not row['dispatched'] and row['socketClosuresComplete']:
                # A known refused TCP connection before sending is only usable
                # by the explicit bounded readiness loop, not a mutation retry.
                self.inflight=None
            else:self.unknown=True
        need(not self.unknown and row['completedWithinOriginalDeadline'],'complete_http_terminal_deadline')
        return result
    def ready(self,status):
        deadline=min(self.ctx.until,time.monotonic()+NEW_LISTENER_READY_SECONDS)
        for attempt in range(120):
            self.left(deadline)
            try:return self.call('listener-ready-'+str(attempt),'GET','sys/health',
                                 token='',expected=status,until=deadline)
            except ConnectionRefusedError:
                need(not self.unknown and self.inflight is None,'known_not_sent_ready_refusal')
                time.sleep(min(0.05,self.left(deadline)))
        raise Refused('finite_listener_readiness_exhausted')
    def close_all(self):
        for row in reversed(self.sockets):self.close(row)
    def public(self):
        return {'requests':list(self.rows),'requestCount':len(self.rows),
            'inflight':None if self.inflight is None else {
                k:self.inflight[k] for k in ('name','method','route','dispatched')},
            'outcomeUnknown':self.unknown,
            'allOwnedSocketsClosed':all(row['closed'] for row in self.sockets),
            'onlyEndpoint':'127.0.0.1:'+str(self.port),'originalPerRequestSeconds':10,
            'newListenerReadySeconds':NEW_LISTENER_READY_SECONDS,'redirectsFollowed':0,
            'businessRequestsReplayed':0}

def add_secrets(values,value):
    if isinstance(value,dict):
        for key,item in value.items():
            if isinstance(item,str) and len(item)>=8 and key not in ('provider','type','chatgptPlanType'):
                values.add(item)
            elif isinstance(item,(dict,list)):add_secrets(values,item)
    elif isinstance(value,list):
        for item in value:add_secrets(values,item)

def reserve_port(ctx):
    need(ctx.port_reservation is None,'one_owned_ephemeral_port_reservation')
    row={'created':False,'closeAttempted':False,'closed':False};sock=None
    ctx.port_reservation=row
    try:
        with ctx.critical():
            sock=socket.socket(socket.AF_INET,socket.SOCK_STREAM);row['created']=True
        sock.bind(('127.0.0.1',0));port=sock.getsockname()[1]
        need(1024<=port<=65535,'one_owned_ephemeral_port');ctx.remaining();return port
    finally:
        if sock is not None:
            with ctx.critical():
                row['closeAttempted']=True
                try:
                    sock.close();row['closed']=sock.fileno()==-1
                except BaseException as error:
                    row['closeErrorType']=type(error).__name__
                if not row['closed']:ctx.unknown=True
            need(row['closed'],'ephemeral_port_reservation_closed')

def generated_read_fsync(ctx,guard,path,maximum):
    row=None
    with guard.parent(path) as (parent,name):
        try:
            with ctx.critical():
                row=ctx.fd(os.open(name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=parent),'owned-generated')
            first=os.fstat(row['fd'])
            need(stat.S_ISREG(first.st_mode) and first.st_uid==501 and first.st_nlink==1
                 and stat.S_IMODE(first.st_mode)==0o600 and 0<first.st_size<=maximum,
                 'owned_generated_file_custody')
            raw=bytearray()
            while len(raw)<=first.st_size:
                ctx.remaining();part=os.read(row['fd'],min(65536,first.st_size+1-len(raw)))
                if not part:break
                raw.extend(part)
            os.fsync(row['fd']);os.fsync(parent)
            need(len(raw)==first.st_size and ident(first)==ident(os.fstat(row['fd']))
                 ==ident(os.stat(name,dir_fd=parent,follow_symlinks=False)),'owned_generated_whole_read_and_fsync')
            return bytes(raw)
        finally:
            if row is not None:ctx.close(row)
            need(row is None or row['closed'],'owned_generated_close')

def tls_material(ctx,guard,commands):
    tls=ROOT/'server/tls'
    extension=b'basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\nsubjectAltName=DNS:localhost,IP:127.0.0.1\nsubjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid:always\n'
    guard.write_new(tls/'leaf.ext',extension)
    calls=(
      ('owned-ca',['/usr/bin/openssl','req','-x509','-newkey','rsa:2048','-nodes',
        '-keyout',str(tls/'ca.key'),'-out',str(tls/'ca.crt'),'-days','2','-subj','/CN=heptabao-mac-owned-ca',
        '-addext','basicConstraints=critical,CA:TRUE','-addext','keyUsage=critical,keyCertSign,cRLSign',
        '-addext','subjectKeyIdentifier=hash','-addext','authorityKeyIdentifier=keyid:always']),
      ('owned-leaf-request',['/usr/bin/openssl','req','-new','-newkey','rsa:2048','-nodes',
        '-keyout',str(tls/'server.key'),'-out',str(tls/'server.csr'),'-subj','/CN=localhost']),
      ('owned-leaf-sign',['/usr/bin/openssl','x509','-req','-in',str(tls/'server.csr'),
        '-CA',str(tls/'ca.crt'),'-CAkey',str(tls/'ca.key'),'-CAcreateserial',
        '-out',str(tls/'server.crt'),'-days','2','-extfile',str(tls/'leaf.ext')]))
    for label,argv in calls:
        row,out,err=commands.run(label,argv,until=min(ctx.until,time.monotonic()+30),maximum=262144)
        need(row['exitCode']==0 and row['completeBeforeDeadline'] and not row['outcomeUnknown'],
             'owned_tls_material_command')
        ctx.remaining()
    files={}
    for name in ('ca.key','ca.crt','server.key','server.csr','server.crt','ca.srl'):
        files[name]=generated_read_fsync(ctx,guard,tls/name,65536)
    ca=files['ca.crt'];certificate=files['server.crt']
    peer=sha(ssl.PEM_cert_to_DER_cert(certificate.decode('ascii')))
    need(all(b'PRIVATE KEY' not in value for name,value in files.items() if name in ('ca.crt','server.crt')),
         'public_certificates_not_keys')
    return ca,peer,{name:sha(value) for name,value in files.items()}

def capture_once(ctx,guard,commands,stage,pins,anchor_raw,anchor_sha):
    from mac_current_capture_entry_r1 import capture_profile
    need(stage in ('before','after'),'two_named_capture_stages')
    base=ROOT/'captures'/stage
    for path in (base,base/'probe',base/'output'):guard.mkdir_new(path)
    guard.write_new(base/'probe/writable-owned-main',b'owned capture kernel-write fence r1\n')
    policy=capture_profile(stage);guard.write_new(base/'capture.sb',policy)
    source_raw=encoded({name:pins[name] for name in ENTRY_NAMES})
    synthetic_raw=encoded(SYNTHETIC)
    deadline=min(ctx.until,time.monotonic()+CAPTURE_SECONDS)
    argv=['/usr/bin/sandbox-exec','-f',str(base/'capture.sb'),'/opt/homebrew/bin/python3','-I','-S','-B',
        str(QA/'mac_current_capture_entry_r1.py'),'--stage',stage,'--absolute-until',repr(deadline),
        '--public-volume-anchor-base64',base64.b64encode(anchor_raw).decode(),
        '--public-volume-anchor-sha256',anchor_sha,'--source-pins-base64',base64.b64encode(source_raw).decode(),
        '--source-pins-sha256',sha(source_raw),'--synthetic-binding-base64',base64.b64encode(synthetic_raw).decode(),
        '--synthetic-binding-sha256',sha(synthetic_raw),'--sandbox-profile-sha256',sha(policy)]
    row,out,err=commands.run('current-capture-'+stage,argv,until=deadline,maximum=262144)
    guard.write_new(base/'stdout.public.json',out);guard.write_new(base/'stderr.private',err)
    try:
        value=exact_json(out)
        need(isinstance(value,dict) and type(value.get('ok')) is bool
             and type(value.get('outcomeUnknown')) is bool,'typed_capture_terminal_report')
    except BaseException:
        ctx.unknown=True
        raise
    if value['outcomeUnknown']:ctx.unknown=True
    need(row['exitCode']==0 and row['completeBeforeDeadline'] and not row['outcomeUnknown']
         and not err,'actual_sandbox_capture_child_terminal')
    need(isinstance(value,dict) and value.get('schema')=='heptabao.mac-guarded-current-capture-entry.r1'
         and value.get('stage')==stage and value.get('ok') is True
         and value.get('outcomeUnknown') is False and value.get('productionWriteAttempted') is False
         and value.get('captureLibraryReturned') is True and value.get('allOwnedDescriptorsClosed') is True
         and value.get('originalDeadlineMetAfterPrivatePublicationAndClosure') is True
         and value.get('originalAbsoluteDeadlineMonotonic')==deadline
         and value.get('syntheticProofSha256')==SYNTHETIC['stdoutSha256'],'whole_successful_sandbox_capture_report')
    held=value.get('heldT5Final',{});owned=value.get('ownedCommands',{})
    need(held.get('allDescriptorsClosed') is True and held.get('closeErrors')==[]
         and held.get('lastAnchorCheckPassed') is True and owned.get('allOwnedCommandsStopped') is True
         and owned.get('unknownCommandCount')==0 and value.get('kernelSandboxProof',{}).get('allFourDenied') is True,
         'capture_held_volume_kernel_and_command_closure')
    capsule=guard.read(base/'output/capsule.private.json',4*1024*1024)
    need(value.get('capsule',{}).get('path')==str(base/'output/capsule.private.json')
         and value['capsule'].get('bytes')==len(capsule) and value['capsule'].get('sha256')==sha(capsule),
         'whole_private_capture_capsule')
    ctx.remaining(deadline)
    return exact_json(capsule),{'stage':stage,'stdoutSha256':sha(out),'stdoutBytes':len(out),
        'privateCapsuleSha256':sha(capsule),'privateCapsuleBytes':len(capsule),'child':row,'report':value}

def seed_documents(packet):
    ids=packet['targetProfileIds'];credentials=packet['credentials'];profiles={};entries=[];managed=[]
    for pid in ids:
        credential=credentials[pid];pin=digest(credential);key='sha256-'+pin
        identity=digest({name:credential.get(name) for name in ('provider','type','email','accountId','projectId')})
        payload={'schemaVersion':1,'profileId':pid,'credential':copy.deepcopy(credential),'digest':pin,'identity':identity}
        entry={k:v for k,v in payload.items() if k not in ('credential','schemaVersion')}
        entry.update(key=key,provider=credential['provider'],type=credential['type'],
                     expires=credential['expires'],quarantined=False,status='active')
        profiles['profiles/'+key]=payload;entries.append(entry)
        managed.append({'profileId':pid,'key':key,'credentialSha256':pin,
            'identityDigest':digest({name:credential[name] for name in ('provider','type','accountId','email')
                                     if name in credential})})
    now=int(time.time()*1000)
    order={'schemaVersion':1,'generation':1,'providers':{'openai':{'candidates':[
        {'profileId':pid,'digest':digest(credentials[pid]),'enrolledAt':now} for pid in reversed(ids)],
        'activeProfile':None,'enforceManagedOrder':False}}}
    docs={**profiles,'order-policy':order,'scheduler-assignments':{
        'schemaVersion':1,'generation':1,'assignments':[]},'manifest':{'schemaVersion':1,'generation':1,'profiles':entries}}
    return docs,managed

def exact_data(value):
    need(isinstance(value.get('data'),dict),'response_data_object')
    return value['data']

def bootstrap_api(client,guard,docs,secrets):
    def initialization(value):
        need(isinstance(value.get('root_token'),str) and value['root_token']
             and isinstance(value.get('keys_base64'),list) and len(value['keys_base64'])==1
             and isinstance(value['keys_base64'][0],str),'actual_init_credentials')
    init=client.call('initialize','POST','sys/init',{'secret_shares':1,'secret_threshold':1},
                     token='',validate=initialization)
    root=init['root_token'];unseal=init['keys_base64'][0];secrets.update((root,unseal));client.root_token=root
    guard.write_new(ROOT/'outer-r4/recovery.private.json',encoded({'rootToken':root,'unsealKey':unseal}))
    client.call('unseal','POST','sys/unseal',{'key':unseal},token='',
                validate=lambda v:need(v.get('sealed') is False,'actual_unsealed'))
    client.call('kv2-mount','POST','sys/mounts/openclaw-auth',{'type':'kv','options':{'version':'2'}},expected=204)
    client.call('approle-mount','POST','sys/auth/approle',{'type':'approle'},expected=204)
    client.call('formal-native-activation','POST','sys/storage/native-v6/activate',{},expected=204)
    client.call('formal-format-two','GET','sys/internal/capacity',
        validate=lambda v:need(exact_data(v).get('native_kv2_reader_format')==2,'actual_native_format_two'))
    for index,(name,data) in enumerate(docs.items()):
        client.call('canonical-seed-'+str(index),'POST','openclaw-auth/data/'+name,
            {'data':data,'options':{'cas':0}},
            validate=lambda v:need(exact_data(v).get('version')==1,'actual_cas_zero_created_once'))
    policy='\n'.join('path "openclaw-auth/data/'+name+'" { capabilities=["read"] }' for name in docs)
    policy+='\npath "openclaw-auth/data/inbox/mac/*" { capabilities=["create","update"] }\n'
    policy+='\n'.join('path "auth/token/'+name+'" { capabilities=["'+verb+'"] }'
        for name,verb in (('lookup-self','read'),('renew-self','update'),('revoke-self','update')))
    client.call('consumer-policy','PUT','sys/policies/acl/mac-five-current',{'policy':policy},expected=204)
    route='auth/approle/role/mac-five-current'
    client.call('consumer-role','POST',route,{'token_policies':['mac-five-current'],
        'token_ttl':'180s','token_max_ttl':'600s','secret_id_ttl':'1200s','secret_id_num_uses':0},expected=204)
    role=client.call('consumer-role-id','GET',route+'/role-id',
        validate=lambda v:need(isinstance(exact_data(v).get('role_id'),str) and v['data']['role_id'],
                                'actual_role_id'))['data']['role_id']
    secret=client.call('consumer-secret-id','POST',route+'/secret-id',{},
        validate=lambda v:need(isinstance(exact_data(v).get('secret_id'),str) and v['data']['secret_id'],
                                'actual_secret_id'))['data']['secret_id']
    secrets.update((role,secret))
    guard.write_new(ROOT/'credentials-consumer/role_id',role.encode())
    guard.write_new(ROOT/'credentials-consumer/secret_id',secret.encode())
    return unseal

def canonical_and_inbox(client,docs,phases):
    for index,(name,data) in enumerate(docs.items()):
        client.call('canonical-readback-'+str(len(phases))+'-'+str(index),'GET','openclaw-auth/data/'+name,
            validate=lambda v,data=data:need(exact_data(v).get('data')==data
                and v['data'].get('metadata',{}).get('version')==1,'canonical_scope_and_original_cas_exact'))
    paths=[]
    for phase in phases:
        cycle=phase['records'][0]['report']
        need(cycle.get('publishNewFlagPreserved') is True and cycle.get('workerManifestWriteRouteAllowed') is False,
             'original_publish_flag_and_canonical_scope')
        for item in cycle['wire']:
            if item['method']=='POST' and item['path'].startswith('/v1/openclaw-auth/data/inbox/mac/'):
                suffix=item['path'].split('/inbox/mac/',1)[1]
                need(re.fullmatch('[A-Za-z0-9_-]{1,128}',suffix) and item.get('complete') is True
                     and item.get('status')==200,'actual_complete_inbox_post')
                paths.append(suffix)
    need(len(paths)==len(set(paths))<=256,'finite_distinct_observed_inbox_events')
    if paths:
        listed=client.call('inbox-list-'+str(len(phases)),'LIST','openclaw-auth/metadata/inbox/mac',
            validate=lambda v:need(isinstance(exact_data(v).get('keys'),list)
                and sorted(v['data']['keys'])==sorted(paths),'exact_observed_inbox_keyset'))
        for index,key in enumerate(sorted(paths)):
            client.call('inbox-read-'+str(len(phases))+'-'+str(index),'GET','openclaw-auth/data/inbox/mac/'+key,
                validate=lambda v:need(isinstance(exact_data(v).get('data'),dict),'actual_proposal_document'))
    else:
        client.call('inbox-absent-'+str(len(phases)),'LIST','openclaw-auth/metadata/inbox/mac',expected=404)
    return {'observedInboxPosts':len(paths),'canonicalDocumentCount':len(docs),
        'canonicalAllVersionOneAndWholePayloadExact':True,'publishNewUnchanged':True,
        'canonicalGrantAddedByConsumer':False,'coordinatorExecuted':False,
        'proposalPresenceNotInterpretedAsCanonicalGrant':True}

def token_lifecycle(client,guard,phase,secrets):
    raw=guard.read(ROOT/phase/'workers/authbus-five-agent-cycle.auth.private.json',65536)
    value=exact_json(raw)
    need(isinstance(value,dict) and set(value)=={'tokens'} and isinstance(value['tokens'],list)
         and len(value['tokens'])==1 and isinstance(value['tokens'][0],str),'actual_cycle_token_custody')
    token=value['tokens'][0];secrets.add(token)
    client.call('unassigned-denied-'+phase,'GET','openclaw-auth/data/profiles/unassigned',token=token,expected=403)
    client.call('renew-self-'+phase,'POST','auth/token/renew-self',{},token=token)
    client.call('revoke-self-'+phase,'POST','auth/token/revoke-self',{},token=token,expected=204)
    client.call('revoked-denied-'+phase,'GET','openclaw-auth/data/manifest',token=token,expected=403)
    return {'phase':phase,'actualTokenCaptured':True,'renewed':True,'revoked':True,
            'unassignedAndRevokedRequestsRejected':True}

def scan_owned_plaintext(ctx,guard,packet):
    literals=[v.encode() for c in packet['credentials'].values() for key,v in c.items()
              if key in ('access','refresh') and isinstance(v,str) and v]
    roots=[ROOT/'server/data',*[ROOT/phase/'state/agents'/agent/'agent/codex-home'
           for phase in ('initial','cold-new-process') for agent in AGENTS]]
    seen=0;total=0;directories=0;server_files=0
    def fail(error):raise error
    for root in roots:
        if root!=ROOT/'server/data':
            try:(root/'auth.json').lstat()
            except FileNotFoundError:pass
            else:raise Refused('native_auth_json_must_remain_absent')
        for directory,subdirs,files in os.walk(root,followlinks=False,onerror=fail):
            ctx.remaining();directories+=1;need(directories<=512,'finite_owned_plaintext_directories')
            for name in subdirs:
                need(stat.S_ISDIR((Path(directory)/name).lstat().st_mode),'no_owned_scan_symlink_directories')
            for name in files:
                seen+=1;need(seen<=512,'finite_owned_plaintext_files')
                if root==ROOT/'server/data':server_files+=1
                path=Path(directory)/name;info=path.lstat()
                need(stat.S_ISREG(info.st_mode) and not path.is_symlink() and info.st_size<=16*1024*1024,
                     'bounded_owned_plaintext_file')
                raw=guard.read(path,16*1024*1024);total+=len(raw)
                need(total<=64*1024*1024 and all(value not in raw for value in literals),
                     'no_managed_provider_plaintext_in_server_or_native_homes')
    need(seen>0 and server_files>0,'actual_owned_server_disk_files_observed')
    return {'files':seen,'serverFiles':server_files,'directories':directories,'bytesRead':total,
            'providerAccessRefreshAbsent':True,'allTenNativeAuthFilesAbsent':True,
            'wholeProductionBackupClaimed':False}

def main():
    os.umask(0o077);ctx=Context()
    parser=argparse.ArgumentParser()
    parser.add_argument('--candidate',type=Path,required=True)
    parser.add_argument('--candidate-sha256',required=True)
    parser.add_argument('--public-source-pins-base64',required=True)
    parser.add_argument('--public-source-pins-sha256',required=True)
    parser.add_argument('--public-volume-anchor-base64',required=True)
    parser.add_argument('--public-volume-anchor-sha256',required=True)
    args=parser.parse_args()
    guard=None;commands=None;inputs=None;materializer=None;manager=None;client=None
    manager_terminal=None;candidate_result=None;completed=False;capsule_before=None;output_created=False
    secrets=set();qa_identities={};proof=None;packet=None;capture_reports=[];phase_results=[]
    report={'schema':'heptabao.mac-current-five-agent-owned-launchd-outer.r4','ok':False,
        'outcomeUnknown':False,'sourceCommit':COMMIT,'sourceTree':TREE,'checks':[],
        'productionCaptureAttempted':False,'productionChangedByController':False,
        'productionServiceOperationDispatched':False,'providerRequested':False,'j3160Contacted':False,
        'currentProviderAvailabilityQualified':False,'allAccountsQualified':False,
        'productionManagerQualification':False,'fullReplacementQualified':False,
        'automaticBusinessRetry':False,'credentialValuesPublished':False,
        'sourceGeneration':'new_r4_public_input_admission_successor',
        'newOuterSeconds':900,'newManagerSeconds':600,'newManagerCleanupSeconds':60,
        'originalPhaseSeconds':120,'originalNativeSeconds':[15,8,3],
        'originalHttpSeconds':10,'originalCaptureSeconds':45}
    def check(name,value):
        need(isinstance(value,bool),'boolean_outer_check')
        report['checks'].append({'case':name,'passed':value});need(value,name)
    try:
        need(sys.platform=='darwin' and os.getuid()==501 and os.getgid()==20,'actual_mac_owner')
        pins_raw=base64.b64decode(args.public_source_pins_base64,validate=True)
        need(len(pins_raw)<=8192 and sha(pins_raw)==args.public_source_pins_sha256,'exact_public_qa_pin_input')
        pins=exact_json(pins_raw)
        need(isinstance(pins,dict) and set(pins)==set(NAMES) and all(valid_pin(v) for v in pins.values()),
             'complete_exact_qa_source_inventory')
        for name,pin in pins.items():qa_identities[name]=read_public_source(ctx,QA/name,pin)
        sys.path.insert(0,str(QA))
        from mac_owned_commands_r1 import Signals,Commands
        from mac_t5_volume_guard_r1 import HeldT5
        from mac_guarded_current_capture_r3 import validate_synthetic_proof
        from mac_current_capture_entry_r1 import admitted_synthetic
        from mac_current_outer_inputs_r2 import Inputs,PLUGIN_FILES
        from mac_current_fixture_materializer_r1 import Materializer
        from mac_owned_launchd_r3 import OwnedLaunchd
        ctx.signals=Signals();ctx.signals.install();commands=Commands(ctx.signals)
        for path,value in FIXED_UTILITIES.items():read_system_tool(ctx,Path(path),value)
        anchor_raw=base64.b64decode(args.public_volume_anchor_base64,validate=True)
        guard=HeldT5(anchor_raw,args.public_volume_anchor_sha256,ctx.remaining,ctx.critical)
        row,out,err=commands.run('outer-t5-volume',['/usr/sbin/diskutil','info','-plist','/Volumes/T5'],
            until=min(ctx.until,time.monotonic()+30),maximum=262144)
        need(row['exitCode']==0 and row['completeBeforeDeadline'] and not row['outcomeUnknown'],
             'actual_t5_before_private_outer_io');guard.accept_diskutil(out)
        need(args.candidate==ROOT/'candidate-current-manager-r4.public.json' and valid_pin(args.candidate_sha256),
             'fixed_public_manager_candidate')
        candidate_raw=guard.read(args.candidate,65536);need(sha(candidate_raw)==args.candidate_sha256,'whole_public_candidate')
        candidate=exact_json(candidate_raw)
        need(isinstance(candidate,dict) and set(candidate)=={'schema','sourceCommit','sourceTree','sourcePins',
            'syntheticBinding','publicVolumeAnchorSha256','utilityPins','budgets'}
            and candidate['schema']=='heptabao.mac-current-manager-candidate.r4'
            and candidate['sourceCommit']==COMMIT and candidate['sourceTree']==TREE
            and candidate['sourcePins']==pins and candidate['syntheticBinding']==SYNTHETIC
            and candidate['utilityPins']=={path:value['sha256'] for path,value in FIXED_UTILITIES.items()}
            and candidate['publicVolumeAnchorSha256']==args.public_volume_anchor_sha256
            and candidate['budgets']=={'outer':900,'manager':600,'managerFailureCleanup':60,
                'phase':120,'native':[15,8,3],'http':10,'capture':45,'listenerReady':30,'tlsCommand':30},
            'entire_reviewed_public_candidate_contract')
        proof_raw,proof=admitted_synthetic(guard,SYNTHETIC)
        validate_synthetic_proof(proof_raw,SYNTHETIC['stdoutSha256'],remaining=ctx.remaining,critical=ctx.critical)
        inputs=Inputs(guard,ctx.signals,ctx.until)
        report['utilityPins']=inputs.admit_utilities(candidate['utilityPins'])
        runtime,report['normalSourceBinding']=inputs.normal_and_base_sources()
        packet,report['frozenSourceProjection']=inputs.project_frozen()
        add_secrets(secrets,packet);secrets.update(packet['targetProfileIds'])
        guard.mkdir_new(ROOT/'outer-r4');output_created=True
        for path in (ROOT/'captures',ROOT/'launchd',ROOT/'server',
                     ROOT/'server/data',ROOT/'server/tls',ROOT/'installed-plugin-copy',
                     ROOT/'installed-plugin-copy/node_modules',ROOT/'credentials-consumer'):
            guard.mkdir_new(path)
        guard.write_new(ROOT/'outer-r4/intent.public.json',encoded({
            'schema':report['schema'],'candidateSha256':args.candidate_sha256,'sourcePins':pins,
            'syntheticBinding':SYNTHETIC,'budgets':candidate['budgets'],'twoOwnedLaunchdLabelsOnly':True,
            'productionWriteAuthorized':False,'providerAuthorized':False,'businessReplaysAuthorized':False}))
        guard.write_new(ROOT/'outer-r4/managed12.private.json',encoded(packet))
        report['productionCaptureAttempted']=True
        capsule_before,before_public=capture_once(ctx,guard,commands,'before',pins,
            anchor_raw,args.public_volume_anchor_sha256);capture_reports.append(before_public)
        for document in capsule_before['authDocuments']:
            for values in document['rows'].values():
                for raw_row in values:
                    decoded=exact_json(raw_row[1]);add_secrets(secrets,decoded)
                    if isinstance(decoded.get('profiles'),dict):secrets.update(decoded['profiles'])
        runtime=inputs.admit_actual_harnesses(capsule_before['registry'],runtime)
        source_pins=inputs.public_pins()
        for name in PLUGIN_FILES:
            data=inputs.pin_code(Path('/Users/qianqi/.openclaw/extensions/openclaw-authbus')/name,collect=True)
            path=ROOT/'installed-plugin-copy'/name;guard.write_new(path,data);source_pins[str(path)]=sha(data)
        link=ROOT/'installed-plugin-copy/node_modules/openclaw'
        with guard.parent(link) as (parent,name):
            os.symlink(runtime['sdkRoot'],name,dir_fd=parent);os.fsync(parent)
            info=os.stat(name,dir_fd=parent,follow_symlinks=False)
            need(stat.S_ISLNK(info.st_mode) and info.st_uid==501 and info.st_nlink==1
                 and os.readlink(name,dir_fd=parent)==runtime['sdkRoot'],'single_explicit_owned_sdk_symlink')
            link_identity=list(ident(info))
        report['ownedSdkLink']={'path':str(link),'target':runtime['sdkRoot'],'identity':link_identity}
        port=reserve_port(ctx);ca,peer_sha,report['ownedTlsPins']=tls_material(ctx,guard,commands)
        guard.write_new(ROOT/'credentials-consumer/ca.crt',ca)
        config={'listen':'127.0.0.1:'+str(port),'data_dir':str(ROOT/'server/data'),
            'audit_file':str(ROOT/'server/audit.jsonl'),'tls_cert_file':str(ROOT/'server/tls/server.crt'),
            'tls_key_file':str(ROOT/'server/tls/server.key'),
            'storage':{'native_v6_file':{'path':str(ROOT/'server/data')}}}
        config_raw=encoded(config);guard.write_new(ROOT/'server/server.json',config_raw)
        for generation in ('server-initial','server-cold-new-process'):
            guard.write_new(ROOT/'launchd'/(generation+'.private.json'),encoded({
                'schema':'heptabao.mac-owned-launchd-server-plan.private.r1','generation':generation,
                'binaryPath':str(BINARY),'binarySha256':BINARY_SHA,'binaryBytes':BINARY_BYTES,
                'configPath':str(ROOT/'server/server.json'),'configSha256':sha(config_raw),
                'port':port,'workRoot':str(ROOT)}))
        manager=OwnedLaunchd(guard=guard,commands=commands,signals=ctx.signals,
            until=min(ctx.until,time.monotonic()+600),anchor_raw=anchor_raw,
            anchor_sha256=args.public_volume_anchor_sha256,qa_pins=pins,
            python_runtime=proof['runtime']['pythonExecutable'])
        manager.start_server('server-initial')
        client=LoopbackHTTP(ctx,port,ca,peer_sha);client.ready(501)
        docs,managed=seed_documents(packet)
        unseal=bootstrap_api(client,guard,docs,secrets)
        original_cfg=exact_json(base64.b64decode(capsule_before['configBase64'],validate=True))
        original_plugin=original_cfg['plugins']['entries']['openclaw-authbus']['config']
        plugin=copy.deepcopy(original_plugin)
        plugin.update(address='https://127.0.0.1:'+str(port),
            caFile=str(ROOT/'credentials-consumer/ca.crt'),roleIdFile=str(ROOT/'credentials-consumer/role_id'),
            secretIdFile=str(ROOT/'credentials-consumer/secret_id'))
        materializer=Materializer(guard,ctx.signals,ctx.until)
        report['materialization']=materializer.materialize(capsule_before,plugin_config=plugin,
            managed_profiles=managed,runtime=runtime,source_pins=source_pins,qa_pins=pins,
            port=port,server_certificate_sha256=peer_sha)
        first=manager.run_phase('initial');phase_results.append(first)
        report['initialCanonicalAndInbox']=canonical_and_inbox(client,docs,phase_results)
        report['initialTokenLifecycle']=token_lifecycle(client,guard,'initial',secrets)
        manager.kill_server_for_cold_or_inverse('server-initial')
        manager.start_server('server-cold-new-process')
        client.ready(503)
        client.call('cold-unseal','POST','sys/unseal',{'key':unseal},token='',
            validate=lambda v:need(v.get('sealed') is False,'actual_cold_unsealed'))
        second=manager.run_phase('cold-new-process');phase_results.append(second)
        report['coldCanonicalAndInbox']=canonical_and_inbox(client,docs,phase_results)
        report['coldTokenLifecycle']=token_lifecycle(client,guard,'cold-new-process',secrets)
        manager.kill_server_for_cold_or_inverse('server-cold-new-process')
        phase_results.append(manager.run_phase('initial-inverse'))
        phase_results.append(manager.run_phase('cold-new-process-inverse'))
        manager_terminal=manager.finish()
        check('four_independent_phase_generations',
              [p['generation'] for p in phase_results]==[
                'initial','cold-new-process','initial-inverse','cold-new-process-inverse'])
        check('two_independent_baselines_and_complete_five_agent_inverse',
              all(phase_results[i]['records'][0]['report'].get('inverseCompleted') is True
                  and phase_results[i]['records'][0]['report'].get('rollbackAttemptedOnce') is True
                  and phase_results[i]['records'][0]['report'].get('effectiveStoresOnlyRecomputedAndVerified') is True
                  for i in (2,3)))
        report['ownedDiskPlaintextScan']=scan_owned_plaintext(ctx,guard,packet)
        after,after_public=capture_once(ctx,guard,commands,'after',pins,
            anchor_raw,args.public_volume_anchor_sha256);capture_reports.append(after_public)
        check('two_complete_bounded_current_observations_exact',canonical(after)==canonical(capsule_before))
        check('all_frozen_and_selected_public_sources_after',inputs.verify())
        check('six_actual_system_tools_whole_identity_after',all(
            read_system_tool(ctx,Path(path),value)==value['identity']
            for path,value in FIXED_UTILITIES.items()))
        check('owned_sdk_symlink_exact_after',list(ident(link.lstat()))==link_identity
              and os.readlink(link)==runtime['sdkRoot'])
        check('all_public_qa_sources_same_identity_after',
            all(read_public_source(ctx,QA/name,pin)==qa_identities[name] for name,pin in pins.items()))
        report['ownedPhases']=phase_results
        report['manager']=manager_terminal
        report['currentObservationScope']='two_bounded_nonatomic_observations_primary_rows_and_fixed_files_only'
        report['wholeDatabaseBackupQualified']=False;report['crossAgentAtomicSnapshotClaimed']=False
        report['nativeFactoryCountObserved']=sum(p['nativeWorkerCount'] for p in phase_results)
        check('ten_actual_separate_native_lineages',report['nativeFactoryCountObserved']==10)
        ctx.remaining();guard.check();completed=True
    except BaseException as error:
        report['errorType']=type(error).__name__
        report['errorCode']=str(error) if isinstance(error,Refused) else None
        report['errorFrames']=[{'file':Path(f.filename).name,'line':f.lineno}
            for f in traceback.extract_tb(error.__traceback__)[-6:]]
        report['outcomeUnknown']=bool(ctx.unknown or isinstance(error,KeyboardInterrupt)
            or (client is not None and (client.unknown or client.inflight is not None))
            or (manager is not None and manager.unknown))
    finally:
        if ctx.signals is not None:
            signal.signal(signal.SIGTERM,signal.SIG_IGN);signal.signal(signal.SIGINT,signal.SIG_IGN)
        if manager is not None and not manager.finished:
            ctx.cleanup_mode=True;ctx.cleanup_until=time.monotonic()+NEW_OUTER_FAILURE_CLEANUP_SECONDS
            try:manager_terminal=manager.abort_cleanup_once()
            except BaseException as error:
                report['managerCleanupErrorType']=type(error).__name__;report['outcomeUnknown']=True
            finally:ctx.cleanup_mode=False
        if client is not None:client.close_all();report['controlHttp']=client.public()
        if materializer is not None:materializer.close();report['materializerClosure']=materializer.public()
        if inputs is not None:inputs.close();report['finiteInputClosure']=inputs.public()
        if manager_terminal is not None:report['manager']=manager_terminal
        report['captureReports']=capture_reports
        if not report.get('ownedPhases'):report['ownedPhases']=phase_results
        report['ownedCommands']=commands.public() if commands is not None else None
        manager_closed=(manager is None or (manager_terminal is not None
            and manager_terminal.get('allRegistrationsClosed') is True
            and manager_terminal.get('allKnownLineagesClosed') is True
            and manager_terminal.get('allManagerReadDescriptorsClosed') is True))
        helpers_closed=(commands is not None and report['ownedCommands']['allOwnedCommandsStopped']
                        and report['ownedCommands']['unknownCommandCount']==0)
        input_closed=(inputs is None or (report['finiteInputClosure']['allOwnedInputDescriptorsClosed']
                       and not report['finiteInputClosure']['closeErrors']))
        materializer_closed=(materializer is None or (report['materializerClosure']['allOwnedDescriptorsClosed']
                             and not report['materializerClosure']['closeErrors']))
        socket_closed=(ctx.public()['allEphemeralPortReservationSocketsClosed']
            and (client is None or report['controlHttp']['allOwnedSocketsClosed']))
        report['outcomeUnknown']=bool(report['outcomeUnknown'] or ctx.unknown
            or not manager_closed or not helpers_closed or not input_closed
            or not materializer_closed or not socket_closed
            or (client is not None and client.unknown)
            or (manager_terminal is not None and manager_terminal.get('outcomeUnknown') is True))
        report['allOwnedRegistrationsLineagesHelpersClosed']=bool(
            manager_closed and helpers_closed and input_closed and materializer_closed and socket_closed)
        report['ok']=bool(completed and not report['outcomeUnknown'] and time.monotonic()<ctx.until)
        try:
            raw=encoded(report)
            need(len(raw)<=MAX_PUBLIC_REPORT and all(value.encode() not in raw for value in secrets),
                 'public_outer_report_contains_no_secret_values')
            if guard is not None and output_created and time.monotonic()<ctx.until and not ctx.signals.pending:
                candidate_result=guard.write_new(ROOT/'outer-r4/result.public.json',raw)
        except BaseException as error:
            report={'schema':'heptabao.mac-current-five-agent-owned-launchd-outer.r4','ok':False,
                'outcomeUnknown':True,'errorType':type(error).__name__,
                'errorCode':'public_report_or_candidate_publication_refused',
                'productionManagerQualification':False,'automaticBusinessRetry':False,
                'allOwnedRegistrationsLineagesHelpersClosed':bool(
                    manager_closed and helpers_closed and input_closed and materializer_closed and socket_closed)}
        ctx.close_all()
        if guard is not None:guard.close();report['heldT5Final']=guard.public_state()
        report['outerDescriptorClosure']=ctx.public()
        final_closed=(guard is not None and report['heldT5Final']['allDescriptorsClosed']
            and report['heldT5Final']['lastAnchorCheckPassed'] and report['heldT5Final']['closeErrors']==[]
            and report['outerDescriptorClosure']['allOuterReadDescriptorsClosed']
            and report['outerDescriptorClosure']['closeErrors']==[])
        report['outcomeUnknown']=bool(report['outcomeUnknown'] or not final_closed or ctx.unknown)
        completed_at=time.monotonic()
        report['elapsedSeconds']=completed_at-START
        report['originalOuterDeadlineMetAfterAllClosure']=completed_at<ctx.until
        report['candidateResultSha256']=None if candidate_result is None else candidate_result['sha256']
        report['candidateFileAloneIsNotQualification']=True
        report['authoritativeExitZeroAndCompleteFinalStdoutRequired']=True
        report['ok']=bool(report.get('ok') and final_closed and not report['outcomeUnknown']
            and candidate_result is not None and completed_at<ctx.until)
        raw=encoded(report)
        if len(raw)>MAX_PUBLIC_REPORT or any(value.encode() in raw for value in secrets):
            raw=encoded({'schema':report['schema'],'ok':False,'outcomeUnknown':True,
                'errorCode':'final_public_projection_refused','authoritativeExitZeroAndCompleteFinalStdoutRequired':True})
            report['ok']=False
        sys.stdout.buffer.write(raw);sys.stdout.buffer.flush()
    return 0 if report.get('ok') is True and time.monotonic()<ctx.until else 1

if __name__=='__main__':sys.exit(main())
