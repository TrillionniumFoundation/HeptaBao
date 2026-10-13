"""Actual managed secret subscriptions with private durable outcome fences.

All credentials stay in owner-only state. An ambiguous issuance cannot be
retried; an ambiguous renewal is reconciled by authoritative lease lookup.
This owner intentionally requires independently admitted unlimited-use tokens.
"""
from __future__ import annotations
import hashlib
import math
from pathlib import Path
import threading
import time

from .deadline_transport import DeadlineClient
from .private_state import StateDirectory, read_trusted_ca, token_snapshot
from .transport import BaoError, canonical, key_path


def configuration(value,agent):
    if not isinstance(value,dict) or set(value)-{'state_dir','routes','renew_increment_seconds','static_interval_seconds'}:
        raise BaoError('invalid_managed_secret_configuration')
    result=dict(value)
    try:
        if not isinstance(result['state_dir'],str) or not Path(result['state_dir']).is_absolute() or Path(result['state_dir'])==Path(agent.state_dir):
            raise BaoError('managed_secret_private_directory_required')
        result.setdefault('renew_increment_seconds',30)
        result.setdefault('static_interval_seconds',5)
        if type(result['renew_increment_seconds']) is not int or not 1<=result['renew_increment_seconds']<=3600:
            raise BaoError('invalid_managed_secret_renewal')
        if type(result['static_interval_seconds']) not in (int,float) or not math.isfinite(result['static_interval_seconds']) or not .1<=result['static_interval_seconds']<=3600:
            raise BaoError('invalid_managed_secret_static_interval')
        routes=result['routes']
        if not isinstance(routes,list) or not 1<=len(routes)<=16:raise BaoError('invalid_managed_secret_route_bound')
        paths=set()
        for row in routes:
            if not isinstance(row,dict) or set(row)!={'path','effectful'} or type(row['effectful']) is not bool:
                raise BaoError('invalid_managed_secret_route')
            if key_path(row['path'])!=row['path'] or row['path'].startswith(('auth/','sys/')) or row['path'] in paths:
                raise BaoError('invalid_managed_secret_route')
            paths.add(row['path'])
        return result
    except (KeyError,ValueError,TypeError):raise BaoError('invalid_managed_secret_configuration') from None


class ManagedSecrets:
    def __init__(self,config,agent,stop,*,client_factory=DeadlineClient,owner_deadline=None):
        self.config=configuration(config,agent);self.agent=agent;self.stop=stop
        self.client_factory=client_factory;self.lock=threading.RLock()
        self.owner_deadline=owner_deadline
        self.storage_failed=False
        self.directory=StateDirectory(self.config['state_dir'],writer=True)
        try:
            self.trust=read_trusted_ca(agent.ca_file)
            self.agent_binding=agent.binding()
            self.binding=hashlib.sha256(canonical({'agent':self.agent_binding,'managed':self.config})).hexdigest()
            self.rows={};self.events={'issued':0,'renewed':0,'reconciled':0,'fenced':0,'invalidated':0}
            saved=self.directory.json('subscriptions.json',optional=True)
            if saved is not None:
                if not isinstance(saved,dict) or saved.get('schema')!=1 or saved.get('binding')!=self.binding or not isinstance(saved.get('rows'),dict):
                    raise BaoError('managed_secret_restart_binding_mismatch')
                self.rows=saved['rows']
                if len(self.rows)>16:raise BaoError('managed_secret_restart_bound')
                # A persisted monotonic clock is never reused. Ready leases must be
                # authoritatively looked up before the stored data can be rendered.
                for path,row in self.rows.items():
                    self._route(path)
                    if not isinstance(row,dict) or row.get('phase') not in ('ready','issue_pending','renew_pending','lookup_pending','static_stale'):
                        raise BaoError('managed_secret_restart_shape')
                    token_hash=row.get('token_hash')
                    if not isinstance(token_hash,str) or len(token_hash)!=64 or any(c not in '0123456789abcdef' for c in token_hash):
                        raise BaoError('managed_secret_restart_shape')
                    if row['phase']!='issue_pending':
                        if not isinstance(row.get('body'),dict) or not isinstance(row.get('lease_id'),str):
                            raise BaoError('managed_secret_restart_shape')
                        if row['lease_id'] and type(row.get('renewable')) is not bool:
                            raise BaoError('managed_secret_restart_shape')
                    if row.get('phase')=='ready' and row.get('lease_id'):row['phase']='lookup_pending'
                    elif row.get('phase')=='ready':row['phase']='static_stale'
            self._save()
        except BaseException:
            self.directory.close()
            raise

    def _save(self):
        try:self.directory.publish('subscriptions.json',{'schema':1,'binding':self.binding,'rows':self.rows})
        except BaseException:
            self.storage_failed=True
            raise

    def _context(self,end=None):
        if self.storage_failed:raise BaoError('managed_secret_durable_publication_unknown')
        if self.stop.is_set():raise BaoError('managed_secret_owner_stopped')
        if self.agent.binding()!=self.agent_binding or read_trusted_ca(self.agent.ca_file)!=self.trust:
            raise BaoError('managed_secret_trust_changed')
        with StateDirectory(self.agent.state_dir) as directory:
            token,state=token_snapshot(directory,time.time(),self.agent.binding())
        if type(state.get('token_num_uses')) is not int or state['token_num_uses']!=0:
            raise BaoError('managed_secret_requires_admitted_unlimited_token')
        deadline=time.monotonic()+self.agent.timeout
        if self.owner_deadline is not None:deadline=min(deadline,self.owner_deadline)
        if end is not None:deadline=min(deadline,end)
        if deadline<=time.monotonic():raise BaoError('managed_secret_deadline')
        client=self.client_factory(self.agent.address,self.agent.ca_file,token,self.agent.namespace,
            self.agent.timeout,trusted_ca_pem=self.trust,deadline=deadline,cancellation=self.stop)
        return client,state,hashlib.sha256(token.encode('ascii')).hexdigest()

    def delivery(self,paths,token_hash,*,end=None,include_wall=False):
        """Recheck the same token and every subscription at the release boundary."""
        with self.lock:
            _,state,current=self._context(end)
            if current!=token_hash:raise BaoError('managed_secret_token_generation_changed')
            wall,mono=time.time(),time.monotonic()
            deadline=mono+max(0,state['expires_at']-wall)
            wall_deadline=state['expires_at'];observed_wall=state['observed_wall']
            for path in paths:
                row=self.rows.get(path)
                if row is None or row.get('phase')!='ready' or row.get('token_hash')!=token_hash:
                    raise BaoError('managed_secret_subscription_not_ready')
                if wall<row['observed_wall']:raise BaoError('managed_secret_clock_regression')
                observed_wall=max(observed_wall,row['observed_wall'])
                if row.get('lease_id'):
                    remaining=min(row['wall_deadline']-wall,row['deadline']-mono)
                    if remaining<=0:raise BaoError('managed_secret_lease_expired_before_delivery')
                    deadline=min(deadline,mono+remaining)
                    wall_deadline=min(wall_deadline,row['wall_deadline'])
            if self.stop.is_set() or deadline<=time.monotonic() or end is not None and time.monotonic()>=end:
                raise BaoError('managed_secret_deadline')
            return (deadline,wall_deadline,observed_wall) if include_wall else deadline

    def token_generation(self,*,end=None):
        with self.lock:return self._context(end)[2]

    def _route(self,path):
        for row in self.config['routes']:
            if row['path']==path:return row
        raise BaoError('managed_secret_path_not_admitted')

    @staticmethod
    def _envelope(body):
        data=body.get('data')
        if not isinstance(data,dict):raise BaoError('managed_secret_data_required')
        return {'Data':data,'LeaseID':body.get('lease_id',''),'LeaseDuration':body.get('lease_duration',0),
                'Renewable':body.get('renewable',False),'Warnings':body.get('warnings') or []}

    def secret(self,path,*,end=None):
        self._route(path)
        with self.lock:
            client,state,token_hash=self._context(end)
            row=self.rows.get(path)
            if row is not None and row.get('token_hash')!=token_hash:
                if row.get('phase') in ('issue_pending','renew_pending','lookup_pending'):
                    raise BaoError('managed_secret_unknown_outcome_for_previous_token')
                del self.rows[path];row=None;self.events['invalidated']+=1;self._save()
            if row is not None:
                if row.get('phase') in ('issue_pending','renew_pending','lookup_pending'):
                    raise BaoError('managed_secret_outcome_requires_reconciliation')
                if row.get('phase')=='ready' and row.get('lease_id'):
                    if time.time()<row['wall_deadline'] and time.monotonic()<row['deadline']:
                        # Online authorization is required even for a stored
                        # secret. No finite-use token reaches this extra lookup.
                        lookup=client.request('GET','/v1/auth/token/lookup-self')
                        if lookup.status!=200:
                            del self.rows[path];self._save();raise BaoError('managed_secret_token_denied')
                        self.delivery([path],token_hash,end=end)
                        result=self._envelope(row['body'])
                        remaining=min(row['wall_deadline']-time.time(),row['deadline']-time.monotonic())
                        if remaining<=0:raise BaoError('managed_secret_lease_expired_before_delivery')
                        # Integer metadata may floor a still-positive original
                        # grant to zero. It never grants a new or extended TTL.
                        result['LeaseDuration']=max(0,math.floor(remaining))
                        return result
                    del self.rows[path];row=None;self.events['invalidated']+=1;self._save()
                elif row.get('phase')=='ready' and time.time()<row['refresh_wall']:
                    lookup=client.request('GET','/v1/auth/token/lookup-self')
                    if lookup.status!=200:
                        del self.rows[path];self._save();raise BaoError('managed_secret_token_denied')
                    self.delivery([path],token_hash,end=end)
                    return self._envelope(row['body'])
            route=self._route(path);start_wall,start_mono=time.time(),time.monotonic()
            # A configured label cannot prove that an entered GET had no
            # effect. Every fetch has a durable intent before transport entry.
            self.rows[path]={'phase':'issue_pending','token_hash':token_hash,'observed_wall':start_wall}
            self._save()
            try:response=client.request('GET','/v1/'+path)
            except BaoError:
                self.events['fenced']+=1
                raise
            if response.status!=200 or response.body.get('wrap_info') is not None:
                self.events['fenced']+=1
                raise BaoError('managed_secret_request_denied')
            envelope=self._envelope(response.body)
            lease=envelope['LeaseID'];ttl=envelope['LeaseDuration'];renewable=envelope['Renewable']
            row={'phase':'ready','token_hash':token_hash,'body':response.body,'observed_wall':start_wall,
                 'lease_id':lease,'renewable':renewable,'refresh_wall':start_wall+self.config['static_interval_seconds']}
            if lease:
                if not isinstance(lease,str) or type(ttl) is not int or ttl<=0:
                    raise BaoError('managed_secret_lease_shape')
                duration=min(ttl,state['expires_at']-start_wall)
                if duration<=0:raise BaoError('managed_secret_lease_expired_during_admission')
                row.update(wall_deadline=start_wall+duration,deadline=start_mono+duration,
                           renew_at=start_mono+max(.1,duration/2))
            self.rows[path]=row;self._save();self.events['issued']+=1
            self.delivery([path],token_hash,end=end)
            return envelope

    def maintain(self):
        with self.lock:
            _,_,token_hash=self._context()
            for path,row in list(self.rows.items()):
                if row.get('token_hash')!=token_hash:continue
                if row.get('phase')=='issue_pending':continue
                lease=row.get('lease_id')
                if not lease:continue
                phase=row.get('phase')
                pending=phase in ('renew_pending','lookup_pending')
                if not pending and time.monotonic()<row.get('renew_at',0):continue
                if not pending and row.get('renewable') is not True:continue
                client,state,current_hash=self._context()
                if current_hash!=token_hash:raise BaoError('managed_secret_token_generation_changed')
                # Durable intent is published before entry. A transport error
                # leaves a lookup-only fence; maintenance never blindly renews.
                row['phase']='lookup_pending' if pending else 'renew_pending';self._save()
                start_wall,start_mono=time.time(),time.monotonic()
                endpoint='sys/leases/lookup' if pending else 'sys/leases/renew'
                payload={'lease_id':lease}
                if not pending:payload['increment']=self.config['renew_increment_seconds']
                try:response=client.request('POST','/v1/'+endpoint,payload)
                except BaoError:
                    self.events['fenced']+=1;continue
                if response.status!=200:
                    # A denial of lookup/renewal is not proof that an earlier
                    # issuance or renewal had no effect or that its lease died.
                    self.events['fenced']+=1;continue
                if pending:
                    data=response.body.get('data')
                    if not isinstance(data,dict) or data.get('id')!=lease or type(data.get('renewable')) is not bool:continue
                    ttl=data.get('ttl');renewable=data['renewable']
                else:
                    if response.body.get('lease_id')!=lease or type(response.body.get('renewable')) is not bool:continue
                    ttl=response.body.get('lease_duration');renewable=response.body['renewable']
                if type(ttl) is not int or ttl<=0:continue
                duration=min(ttl,state['expires_at']-start_wall)
                if duration<=0:continue
                row['body']['lease_duration']=ttl
                row['body']['renewable']=renewable
                row.update(phase='ready',observed_wall=start_wall,wall_deadline=start_wall+duration,
                    deadline=start_mono+duration,renew_at=start_mono+max(.1,duration/2),renewable=renewable)
                try:self.delivery([path],token_hash)
                except BaoError:
                    row['phase']='lookup_pending';self.events['fenced']+=1;self._save();continue
                self.events['reconciled' if pending else 'renewed']+=1;self._save()

    def metadata(self):
        with self.lock:return {'subscriptions':len(self.rows),'phases':{path:row['phase'] for path,row in self.rows.items()},'events':dict(self.events)}

    def close(self):
        with self.lock:
            try:
                if not self.storage_failed:self._save()
            finally:self.rows.clear();self.directory.close()
