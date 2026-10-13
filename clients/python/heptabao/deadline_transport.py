"""Finite, cancellable ownership around the existing HTTPS Client codec.

urllib's socket timeout measures inactivity, so a trickling response can exceed
the caller's total budget. Each request uses one daemon worker and an absolute
deadline; cancellation shuts down its owned sockets. A connect finishing after
cancellation cannot send credentials or an application request. At most two
uncompleted workers exist per process, including uninterruptible OS DNS work.
"""
from __future__ import annotations
import copy
from functools import partial
import http.client
import socket
import ssl
import threading
import time
import urllib.request

from .consistency import Metadata
from .transport import BaoError, Client, NoRedirect

_WORKERS=threading.BoundedSemaphore(2)


class _RequestOwner:
    def __init__(self, deadline):
        self.deadline=deadline
        self.cancelled=threading.Event()
        self.lock=threading.Lock()
        self.connections=[]

    def check(self):
        if self.cancelled.is_set() or time.monotonic()>=self.deadline:
            raise TimeoutError('owned request deadline')

    def add(self,connection):
        with self.lock:self.connections.append(connection)
        self.check()

    def cancel(self):
        self.cancelled.set()
        with self.lock:connections=list(self.connections)
        for connection in connections:
            for stream in (connection.sock,connection.admitted_socket):
                if stream is not None:
                    try:stream.shutdown(socket.SHUT_RDWR)
                    except OSError:pass
                    try:stream.close()
                    except OSError:pass


class _Connection(http.client.HTTPSConnection):
    def __init__(self,*args,owner,consistency,**kwargs):
        self.owner,self.consistency=owner,consistency
        self.admitted_socket=None
        super().__init__(*args,**kwargs)
        owner.add(self)

    def connect(self):
        self.owner.check()
        super().connect()
        self.admitted_socket=self.sock
        try:self.owner.check()
        except BaseException:
            self.owner.cancel()
            raise

    def send(self,data):
        self.owner.check()
        return super().send(data)

    def endheaders(self,message_body=None,*,encode_chunked=False):
        self.owner.check()
        for name,value in self.consistency.headers():self.putheader(name,value)
        return super().endheaders(message_body,encode_chunked=encode_chunked)


class _HTTPSHandler(urllib.request.HTTPSHandler):
    def __init__(self,owner,**kwargs):
        self.owner=owner
        super().__init__(**kwargs)

    def do_open(self,http_class,req,**http_conn_args):
        metadata=getattr(req,'heptabao_consistency',Metadata())
        if not isinstance(metadata,Metadata):raise BaoError('invalid_consistency_metadata')
        factory=partial(_Connection,owner=self.owner,consistency=metadata)
        return super().do_open(factory,req,**http_conn_args)


class DeadlineClient(Client):
    def __init__(self,address,ca_file,token,namespace='',timeout=15,*,deadline=None,trusted_ca_pem=None):
        super().__init__(address,ca_file,token,namespace,timeout,trusted_ca_pem=trusted_ca_pem)
        self.deadline=deadline
        if trusted_ca_pem is not None:
            self.context=ssl.create_default_context(cadata=trusted_ca_pem.decode('ascii'))
        else:
            self.context=ssl.create_default_context(cafile=ca_file)
        self.context.minimum_version=ssl.TLSVersion.TLSv1_2

    def request(self,method,path,payload=None,**kwargs):
        deadline=self.deadline if self.deadline is not None else time.monotonic()+self.timeout
        remaining=deadline-time.monotonic()
        # GET can issue credentials or consume a finite token. The verb never
        # proves that an entered operation can be retried safely.
        code='transport_outcome_unknown'
        if remaining<=0 or not _WORKERS.acquire(blocking=False):raise BaoError(code)
        owner=_RequestOwner(deadline)
        worker_client=copy.copy(self)
        worker_client.timeout=min(self.timeout,remaining)
        worker_client._opener=urllib.request.build_opener(urllib.request.ProxyHandler({}),
            NoRedirect(),_HTTPSHandler(owner,context=self.context))
        completed=threading.Event();result=[]
        def execute():
            try:result.append((True,Client.request(worker_client,method,path,payload,**kwargs)))
            except BaoError as error:
                result.append((False,BaoError(code) if error.code=='transport_read_failed' else error))
            except Exception:result.append((False,BaoError(code)))
            finally:
                _WORKERS.release()
                completed.set()
        worker=threading.Thread(target=execute,name='heptabao-owned-https-request',daemon=True)
        try:worker.start()
        except BaseException:
            _WORKERS.release()
            raise
        if not completed.wait(max(0,deadline-time.monotonic())):
            owner.cancel()
            raise BaoError(code)
        owner.cancel()
        if not result:raise BaoError(code)
        successful,value=result[0]
        if successful:return value
        raise value
