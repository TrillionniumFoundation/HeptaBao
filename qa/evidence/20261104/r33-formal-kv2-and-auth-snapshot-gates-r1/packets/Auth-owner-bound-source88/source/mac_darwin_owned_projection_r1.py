#!/usr/bin/env python3
"""Closed Darwin numeric projection for a new public custody probe.

Apple exact source is a reference ABI, never a pin of the installed kernel.
No library is loaded at import time. Runtime uses two fixed install names and
records dladdr image names, the actual kernel/build, structure layout and an
own-process behavioral cross-check. It never lists all host PIDs or names.
"""
from __future__ import annotations
import ctypes, errno, os, re, sys, time

REFERENCE_XNU='f6217f891ac0bb64f3d375211650a4c1ff8ca1ea'
REFERENCE_DYLD='fd8d0c4d52320ebf64db34f3cb280310d905c5ae'
KERNEL_INSTALL_NAME='/usr/lib/system/libsystem_kernel.dylib'
SYSTEM_INSTALL_NAME='/usr/lib/libSystem.B.dylib'
PROJECTION_SCHEMA='heptabao.darwin-proc-bsdinfo-numeric.r1'
PROC_PGRP_ONLY=2
PROC_PIDTBSDINFO=3
INCLUDE_RETAINED_ZOMBIES=1
MAX_GROUP_MEMBERS=64
GROUP_CAPACITY=MAX_GROUP_MEMBERS+1
MAX_CALLS=4096
QUERY_SECONDS=4.0
BSD_SIZE=136
STATE_CODES={1:'SIDL',2:'SRUN',3:'SSLEEP',4:'SSTOP',5:'SZOMB'}

class NativeProjectionRefused(RuntimeError):
    def __init__(self,code,errno_value=None):
        super().__init__(code)
        self.code=code
        self.public_errno=(errno_value if type(errno_value) is int and 0<errno_value<=4095 else None)

def need(condition,code,errno_value=None):
    if not condition:raise NativeProjectionRefused(code,errno_value)

class ProcBSDInfo(ctypes.Structure):
    _fields_=[
        ('pbi_flags',ctypes.c_uint32),('pbi_status',ctypes.c_uint32),
        ('pbi_xstatus',ctypes.c_uint32),('pbi_pid',ctypes.c_uint32),
        ('pbi_ppid',ctypes.c_uint32),('pbi_uid',ctypes.c_uint32),
        ('pbi_gid',ctypes.c_uint32),('pbi_ruid',ctypes.c_uint32),
        ('pbi_rgid',ctypes.c_uint32),('pbi_svuid',ctypes.c_uint32),
        ('pbi_svgid',ctypes.c_uint32),('rfu_1',ctypes.c_uint32),
        ('pbi_comm',ctypes.c_char*16),('pbi_name',ctypes.c_char*32),
        ('pbi_nfiles',ctypes.c_uint32),('pbi_pgid',ctypes.c_uint32),
        ('pbi_pjobc',ctypes.c_uint32),('e_tdev',ctypes.c_uint32),
        ('e_tpgid',ctypes.c_uint32),('pbi_nice',ctypes.c_int32),
        ('pbi_start_tvsec',ctypes.c_uint64),('pbi_start_tvusec',ctypes.c_uint64)]

class DlInfo(ctypes.Structure):
    _fields_=[('dli_fname',ctypes.c_char_p),('dli_fbase',ctypes.c_void_p),
              ('dli_sname',ctypes.c_char_p),('dli_saddr',ctypes.c_void_p)]

EXPECTED_OFFSETS={
    'pbi_flags':0,'pbi_status':4,'pbi_xstatus':8,'pbi_pid':12,'pbi_ppid':16,
    'pbi_uid':20,'pbi_gid':24,'pbi_ruid':28,'pbi_rgid':32,'pbi_svuid':36,
    'pbi_svgid':40,'rfu_1':44,'pbi_comm':48,'pbi_name':64,'pbi_nfiles':96,
    'pbi_pgid':100,'pbi_pjobc':104,'e_tdev':108,'e_tpgid':112,'pbi_nice':116,
    'pbi_start_tvsec':120,'pbi_start_tvusec':128}

def abi_layout():
    sizes={'int':ctypes.sizeof(ctypes.c_int),'int32':ctypes.sizeof(ctypes.c_int32),
           'uint32':ctypes.sizeof(ctypes.c_uint32),'uint64':ctypes.sizeof(ctypes.c_uint64),
           'pointer':ctypes.sizeof(ctypes.c_void_p),'size_t':ctypes.sizeof(ctypes.c_size_t),
           'proc_bsdinfo':ctypes.sizeof(ProcBSDInfo),'Dl_info':ctypes.sizeof(DlInfo)}
    offsets={name:getattr(ProcBSDInfo,name).offset for name,_ in ProcBSDInfo._fields_}
    need(sizes=={'int':4,'int32':4,'uint32':4,'uint64':8,'pointer':8,
                 'size_t':8,'proc_bsdinfo':136,'Dl_info':32},
         'reference_abi_size_mismatch')
    need(offsets==EXPECTED_OFFSETS and ctypes.alignment(ProcBSDInfo)==8
         and [getattr(DlInfo,name).offset for name,_ in DlInfo._fields_]==[0,8,16,24],
         'reference_abi_offset_mismatch')
    need(sys.byteorder=='little','reference_abi_endianness')
    return {'sizes':sizes,'offsets':offsets,'alignment':8,'endianness':'little'}

def stable(row):
    return {key:row[key] for key in ('pid','ppid','pgid','uid','birthSeconds','birthMicroseconds')}

def project_bsdinfo(value,expected_pid):
    pid=int(value.pbi_pid);ppid=int(value.pbi_ppid);pgid=int(value.pbi_pgid)
    state=int(value.pbi_status);sec=int(value.pbi_start_tvsec);usec=int(value.pbi_start_tvusec)
    need(type(expected_pid) is int and 0<expected_pid<=0x7fffffff and pid==expected_pid,
         'native_pid_identity_mismatch')
    need(0<ppid<=0x7fffffff and 0<pgid<=0x7fffffff,'native_parent_or_group_malformed')
    need(state in STATE_CODES,'native_process_state_unsupported')
    need(0<sec<2**63 and 0<=usec<1000000,'native_birth_malformed')
    # comm/name/exit details and all other struct bytes are never published.
    return {'pid':pid,'ppid':ppid,'pgid':pgid,'uid':int(value.pbi_uid),
            'stateCode':state,'stateName':STATE_CODES[state],'isZombie':state==5,
            'birthSeconds':str(sec),'birthMicroseconds':str(usec)}

class NativeProjection:
    def __init__(self,*,until):
        need(sys.platform=='darwin' and os.uname().machine=='arm64' and os.geteuid()==501,
             'fixed_darwin_arm64_operator')
        self.layout=abi_layout();self.calls=0;self.pid_calls=0;self.group_calls=0
        self.last_call=None;self.self_qualified=False;self.identity=None
        self._check_deadline(until)
        self.kernel=ctypes.CDLL(KERNEL_INSTALL_NAME,use_errno=True)
        self.system=ctypes.CDLL(SYSTEM_INSTALL_NAME,use_errno=True)
        self._check_deadline(until)
        self._list=self.kernel.proc_listpids
        self._list.argtypes=[ctypes.c_uint32,ctypes.c_uint32,ctypes.c_void_p,ctypes.c_int]
        self._list.restype=ctypes.c_int
        self._info=self.kernel.proc_pidinfo
        self._info.argtypes=[ctypes.c_int,ctypes.c_int,ctypes.c_uint64,ctypes.c_void_p,ctypes.c_int]
        self._info.restype=ctypes.c_int
        self._sysctl=self.system.sysctlbyname
        self._sysctl.argtypes=[ctypes.c_char_p,ctypes.c_void_p,ctypes.POINTER(ctypes.c_size_t),
                              ctypes.c_void_p,ctypes.c_size_t]
        self._sysctl.restype=ctypes.c_int
        self._dladdr=self.system.dladdr
        self._dladdr.argtypes=[ctypes.c_void_p,ctypes.POINTER(DlInfo)]
        self._dladdr.restype=ctypes.c_int
        images={}
        for name,function in (('proc_listpids',self._list),('proc_pidinfo',self._info),
                              ('sysctlbyname',self._sysctl),('dladdr',self._dladdr)):
            images[name]=self._symbol_image(name,function,until)
        build=self._os_build(until)
        uname=os.uname()
        self.identity={'referenceXnuCommit':REFERENCE_XNU,'referenceDyldCommit':REFERENCE_DYLD,
            'referenceIsInstalledWholePin':False,
            'requestedInstallNames':[KERNEL_INSTALL_NAME,SYSTEM_INSTALL_NAME],
            'loadedSymbolImages':images,'libraryWholeFileHashClaimed':False,
            'sharedCacheMaterializationAttempted':False,
            'dylibHandlesRetainedUntilProcessExit':True,
            'actualKernel':{'sysname':uname.sysname,'release':uname.release,
                            'version':uname.version,'machine':uname.machine},
            'actualOsBuild':build,'abi':self.layout}
        self._check_deadline(until)

    @staticmethod
    def _check_deadline(until):
        need(type(until) in (int,float) and time.monotonic()<until,
             'original_projection_deadline_expired')

    def _begin(self,kind,until):
        self._check_deadline(until)
        need(self.calls<MAX_CALLS,'native_projection_call_bound')
        self.calls+=1
        end=min(until,time.monotonic()+QUERY_SECONDS)
        self.last_call={'kind':kind,'call':self.calls,'returned':False,'errno':None}
        self._check_deadline(end)
        return end

    def _end(self,result,deadline):
        error=ctypes.get_errno()
        self.last_call.update({'returned':True,'result':int(result),
                              'errno':error if 0<error<=4095 else None})
        self._check_deadline(deadline)
        return error

    def _symbol_image(self,name,function,until):
        deadline=self._begin('fixed_symbol_dladdr',until);info=DlInfo()
        ctypes.set_errno(0)
        result=self._dladdr(ctypes.cast(function,ctypes.c_void_p),ctypes.byref(info))
        self._end(result,deadline)
        need(result!=0 and info.dli_fname is not None,'fixed_symbol_image_unavailable')
        image=bytes(info.dli_fname)
        symbol=bytes(info.dli_sname) if info.dli_sname is not None else b''
        need(0<len(image)<=512 and image.startswith(b'/usr/lib/')
             and b'\0' not in image and 0<len(symbol)<=128,'fixed_system_symbol_image_shape')
        need(symbol.lstrip(b'_')==name.encode('ascii'),'fixed_symbol_name_mismatch')
        return {'requestedSymbol':name,'observedImagePath':image.decode('ascii'),
                'observedSymbolName':symbol.decode('ascii'),
                'addressesPublished':False,'imageWholeBytesPinned':False}

    def _os_build(self,until):
        deadline=self._begin('kern.osversion',until)
        buf=ctypes.create_string_buffer(128);size=ctypes.c_size_t(128)
        ctypes.set_errno(0)
        result=self._sysctl(b'kern.osversion',buf,ctypes.byref(size),None,0)
        error=self._end(result,deadline)
        need(result==0 and error==0 and 2<=size.value<=128,'fixed_os_build_query',error)
        raw=bytes(buf.raw[:size.value])
        need(raw[-1:]==b'\0' and re.fullmatch(rb'[A-Za-z0-9.()-]{1,64}',raw[:-1]) is not None,
             'fixed_os_build_shape')
        return raw[:-1].decode('ascii')

    def pid_row(self,pid,*,until):
        need(type(pid) is int and 0<pid<=0x7fffffff,'closed_numeric_pid_argument')
        deadline=self._begin('owned_pid_tbsdinfo',until)
        info=ProcBSDInfo();self.pid_calls+=1;ctypes.set_errno(0)
        size=self._info(pid,PROC_PIDTBSDINFO,INCLUDE_RETAINED_ZOMBIES,ctypes.byref(info),BSD_SIZE)
        error=self._end(size,deadline)
        need(error==0 and size==BSD_SIZE,'native_pid_info_not_complete',error)
        row=project_bsdinfo(info,pid)
        self._check_deadline(deadline)
        return row

    def _group_ids(self,pgid,*,until):
        need(type(pgid) is int and 0<pgid<=0x7fffffff,'closed_numeric_group_argument')
        deadline=self._begin('retained_pgrp_only',until)
        self.group_calls+=1
        buffer=(ctypes.c_int32*GROUP_CAPACITY)(*([-1]*GROUP_CAPACITY))
        capacity=ctypes.sizeof(buffer);ctypes.set_errno(0)
        size=self._list(PROC_PGRP_ONLY,pgid,ctypes.byref(buffer),capacity)
        error=self._end(size,deadline)
        # A full buffer may be truncated. Never grow it, retry, or enumerate all PIDs.
        need(error==0 and 0<=size<capacity and size%4==0,
             'native_group_error_short_or_truncated',error)
        ids=[int(buffer[i]) for i in range(size//4)]
        need(len(ids)<=MAX_GROUP_MEMBERS and len(set(ids))==len(ids)
             and all(0<pid<=0x7fffffff for pid in ids),'native_group_pid_shape')
        self._check_deadline(deadline)
        return sorted(ids)

    def group_rows(self,pgid,*,until):
        deadline=min(until,time.monotonic()+QUERY_SECONDS)
        self._check_deadline(deadline)
        before=self._group_ids(pgid,until=deadline)
        rows=[self.pid_row(pid,until=deadline) for pid in before]
        need(all(row['pgid']==pgid and row['uid']==os.geteuid() for row in rows),
             'native_group_scope_or_uid_changed')
        after=self._group_ids(pgid,until=deadline)
        need(before==after,'native_group_members_changed')
        self._check_deadline(deadline)
        return rows

    def qualify_self(self,*,until):
        pid=os.getpid();pgid=os.getpgrp()
        need(pid==pgid,'sandbox_owner_must_be_group_leader')
        first=self.pid_row(pid,until=until)
        need(first['ppid']==os.getppid() and first['pgid']==pgid
             and first['uid']==os.geteuid() and not first['isZombie'],
             'native_self_behavioral_crosscheck')
        rows=self.group_rows(pgid,until=until)
        # No child has been started in this sandbox at qualification.
        need(len(rows)==1 and stable(rows[0])==stable(first),'native_self_group_crosscheck')
        last=self.pid_row(pid,until=until)
        need(stable(first)==stable(last) and not last['isZombie'],'native_self_birth_stable')
        self.self_qualified=True
        return {'projectionSchema':PROJECTION_SCHEMA,'first':first,'last':last,
                'groupRows':rows,'pidUidPpidPgidMatchedIndependentOsApis':True}

    def public(self):
        return {'schema':PROJECTION_SCHEMA,'identity':self.identity,
                'selfQualified':self.self_qualified,'nativeCalls':self.calls,
                'pidQueries':self.pid_calls,'groupQueries':self.group_calls,
                'lastCall':self.last_call,'maxGroupMembers':MAX_GROUP_MEMBERS,
                'pidListNullBufferUsed':False,'allHostEnumerationUsed':False,
                'commandNamesOrPathsProjected':False,'querySeconds':QUERY_SECONDS,
                'lateNativeReturnRejected':True,
                'synchronousKernelCallHasNoSeparateKillableWorker':True}
