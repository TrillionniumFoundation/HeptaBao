import errno,hashlib,http.client,json,re,socket,ssl,time
from pathlib import Path
from main3_http_complete import DeadlineSocket,CompleteHTTPResponse,read_complete_body,safe_failure_code
ROOT=Path('/Users/qianqi/heptabao-fixed-slot-coordinator-normal-20261107-r1')
MAX_HTTP=192
MAX_BODY=1048576
class Refused(RuntimeError):pass
def need(value,code):
    if not value:raise Refused(code)
class Api:
    def __init__(self,plan,phase,phase_until,journal,guard):
        need(phase in ('initial','cold-new-process'),'fixed_api_phase')
        need(type(plan['port']) is int and 1024<=plan['port']<=65535
             and re.fullmatch(r'[0-9a-f]{64}',plan['certificateLeafSha256']),'fixed_owned_tls_endpoint')
        self.plan=plan;self.phase=phase;self.until=phase_until;self.journal=journal;self.guard=guard
        self.context=ssl.create_default_context(cafile=str(ROOT/'pki/ca.crt'))
        self.rows=[];self.checks=[];self.unknown=False;self.root_token=None;self.sensitive=[]
    def remaining(self,cap):
        left=self.until-time.monotonic();need(left>0,'original_api_phase_120_seconds');return min(left,cap)
    def check(self,case,value):
        need(re.fullmatch(r'[a-z0-9._-]{1,100}',case),'fixed_public_api_case')
        self.checks.append({'case':case,'passed':value is True});need(value is True,case)
    def call(self,case,method,route,body=None,*,expected=200,token=None,category,slot=0,readiness=False):
        self.remaining(1)
        self.guard.check()
        need(not self.unknown and len(self.rows)<MAX_HTTP,'no_http_after_unknown_and_finite_requests')
        need(re.fullmatch(r'[a-z0-9._-]{1,100}',case) and category in ('health','init','unseal','mount','activate','capacity','policy','role','role-id','secret-id','login','kv-read','kv-write','lookup','renew','revoke','secret-destroy','admin-denied'),
             'fixed_public_route_category')
        need(method in ('GET','POST','PUT') and isinstance(route,str) and route.startswith('/v1/')
             and re.fullmatch(r'/[A-Za-z0-9/._-]+',route) and 0<=slot<=3,'fixed_owned_api_route')
        if category=='activate':need(method=='POST' and route=='/v1/sys/storage/native-v6/activate','normal_configured_storage_activation_only')
        need(not readiness or (method=='GET' and route=='/v1/sys/health' and body is None and token==''),'health_only_tcp_refusal_wait')
        bearer=self.root_token if token is None else token
        need(bearer is None or isinstance(bearer,str) and len(bearer)<=16384 and '\r' not in bearer and '\n' not in bearer,'private_single_line_bearer')
        payload=b'' if body is None else json.dumps(body,separators=(',',':'),ensure_ascii=False).encode()
        need(len(payload)<=MAX_BODY,'bounded_private_request_body')
        row={'phase':self.phase,'ordinal':len(self.rows)+1,'case':case,'routeCategory':category,'slotOrdinal':slot,
             'method':method,'dispatched':False,'responseComplete':False,'outcomeUnknown':False,
             'responsePrivatelyDurable':False,'httpRequestCount':0,'connectionAttempts':0,'connectionRefusals':0,'tlsVerified':False,'socketsClosed':False}
        self.rows.append(row)
        self.journal.append('api-request-intent',dict(row))
        deadline=time.monotonic()+self.remaining(15 if readiness else 10)
        raw=tls=response=stream=None
        def left():
            remaining=min(self.until,deadline)-time.monotonic();need(remaining>0,'one_http_original_absolute_deadline');return remaining
        try:
            for _ in range(256 if readiness else 1):
                row['connectionAttempts']+=1
                try:raw=socket.create_connection(('127.0.0.1',self.plan['port']),timeout=min(5,left()));break
                except ConnectionRefusedError as error:
                    if not readiness or error.errno!=errno.ECONNREFUSED:raise
                    row['connectionRefusals']+=1;time.sleep(min(0.1,left()))
            need(raw is not None,'bounded_health_connection_attempts')
            raw.settimeout(left());tls=self.context.wrap_socket(raw,server_hostname='localhost')
            need(hashlib.sha256(tls.getpeercert(binary_form=True)).hexdigest()==self.plan['certificateLeafSha256'],'actual_tls_leaf_pin')
            row.update(tlsVerified=True,tlsVersion=tls.version())
            headers=[method+' '+route+' HTTP/1.1','Host: localhost:'+str(self.plan['port']),'Accept: application/json','Connection: close']
            if bearer:headers.append('X-Vault-Token: '+bearer)
            if body is not None:headers+=['Content-Type: application/json','Content-Length: '+str(len(payload))]
            request=('\r\n'.join(headers)+'\r\n\r\n').encode('ascii')+payload
            tls.settimeout(left());row['dispatched']=True;row['httpRequestCount']=1
            tls.sendall(request)
            stream=DeadlineSocket(tls,left,row)
            response=CompleteHTTPResponse(stream,left,row);response.begin()
            row['status']=response.status
            data=read_complete_body(response,left,row)
            left();row.update(responseComplete=True,responseBytes=len(data))
            self.journal.response_bytes(self.phase,row['ordinal'],data)
            row['responsePrivatelyDurable']=True
            left();value=json.loads(data) if data else {}
        except BaseException as error:
            row['outcomeUnknown']=bool(row['dispatched'] and not (row['responseComplete'] and row['responsePrivatelyDurable']))
            self.unknown=True;row['errorType']=type(error).__name__
            row['failureCode']=safe_failure_code(error)
            if isinstance(error,Refused) and error.args==('one_http_original_absolute_deadline',):row['failureCode']='http_original_deadline'
            if isinstance(error,json.JSONDecodeError):row['failureCode']='complete_body_json_invalid'
            # Exception messages, response bodies and their hashes stay private.
            raise Refused('api_transport_or_complete_response_failed') from None
        finally:
            if response is not None:response.close()
            if stream is not None:stream.close_reader()
            row['responseReaderClosed']=stream is None or stream.raw.closed
            if tls is not None:tls.close()
            elif raw is not None:raw.close()
            row['socketsClosed']=True
            self.journal.append('api-request-result',dict(row))
        self.guard.check();self.remaining(1)
        self.check(case,row['status']==expected)
        return value
    def public(self):
        return {'phase':self.phase,'checks':self.checks,'requests':self.rows,'requestCount':len(self.rows),
                'unknownHttpOutcomeCount':sum(r['outcomeUnknown'] for r in self.rows),
                'allDispatchedResponsesComplete':all(not r['dispatched'] or r['responseComplete'] for r in self.rows),
                'allReturnedSocketsClosed':all(r['socketsClosed'] for r in self.rows),
                'allCompleteResponsesPrivatelyDurable':all(not r['responseComplete'] or r['responsePrivatelyDurable'] for r in self.rows),
                'credentialValuesOrDigestsPublished':False,'providerValid':False,'providerCalled':False,
                'providerRefreshAttempted':False,'productionCutover':False}
