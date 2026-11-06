#!/usr/bin/env python3
"""Read only one already observed crash-report file for one retained Node child.
Potentially private IPS bodies stay local; only the explicit typed projection is emitted.
No child, SDK, T5, launchd, signal to another process, filesystem write or fallback root.
"""
from __future__ import annotations
import datetime,json,os,re,signal,stat,sys,time
from pathlib import Path
from contextlib import contextmanager

PYTHON='/opt/homebrew/Cellar/python@3.14/3.14.3_1/Frameworks/Python.framework/Versions/3.14/bin/python3.14'
DIRECTORY=Path('/Users/qianqi/Library/Logs/DiagnosticReports')
OBSERVED_DIRECTORY_IDENTITY5=(16777233,565199774,501,250,16888)
FIXED_REPORT_NAME='node-2026-11-07-033552.ips'
OBSERVED_REPORT_FULL9=(16777233,593533598,501,250,33152,1,6809,
                       1793993752090245618,1793993752090848927)
DIRECTORIES=(Path('/'),Path('/Users'),Path('/Users/qianqi'),
             Path('/Users/qianqi/Library'),Path('/Users/qianqi/Library/Logs'),DIRECTORY)
NODE_REAL='/opt/homebrew/Cellar/node/25.9.0_1/bin/node'
NODE_ALIAS='/opt/homebrew/bin/node'
NODE_ROOT='/opt/homebrew/Cellar/node/25.9.0_1/'
TARGET_PID=51494
TARGET_PARENT=51483
START_MS=1793993751636
TERMINAL_MS=1793993752149
# Actual local ps start was Sat Nov 7 03:35:52 2026; actual UTC bounds are Nov 6.
# Filename time may be rendered in UTC or that observed local convention.
NAME_OFFSETS_SECONDS=(0,28800)
NAME_MARGIN_SECONDS=120
CORRELATION_MARGIN_MS=2000
NAME_RE=re.compile(r'^node[-_](2026-11-06|2026-11-07)[-_]([0-9]{6})(?:[-_][0-9]{1,6})?\.ips$')
MAX_BODIES=1
MAX_BODY_BYTES=6809
MAX_TOTAL_RETURNED_BYTES=6810
MAX_READ_CALLS=36
MAX_METADATA_CALLS=256
MAX_PUBLIC_BYTES=65536
START=time.monotonic()
UNTIL=START+5.0
FINAL_UNTIL=START+8.0
protected=0
pending_signal=None

class Refused(Exception):pass
class Cancelled(Exception):pass
def need(value,code):
    if not value:raise Refused(code)
@contextmanager
def critical():
    global protected
    protected+=1
    try:yield
    finally:protected-=1
def interrupt(signum,_frame):
    global pending_signal
    pending_signal=signum
    if protected==0:raise Cancelled()
def remaining():
    need(pending_signal is None,'interrupted')
    need(time.monotonic()<UNTIL,'readonly_deadline')
def identity(s):
    return (s.st_dev,s.st_ino,s.st_uid,s.st_gid,s.st_mode,s.st_nlink,s.st_size,s.st_mtime_ns,s.st_ctime_ns)
class SignalFacade:
    def critical(self):return critical()
def error_projection(error):
    code=str(error) if isinstance(error,Refused) and str(error) in ERROR_CODES else None
    kind=type(error).__name__
    return {'type':kind if kind in ('Refused','Cancelled','OSError','FileNotFoundError',
             'PermissionError','UnicodeDecodeError','JSONDecodeError','ValueError',
             'RecursionError','KeyboardInterrupt','MemoryError') else 'Other',
            'code':code,
            'errno':error.errno if isinstance(error,OSError) and type(error.errno) is int
                    and 0<=error.errno<=255 else None}

ERROR_CODES=frozenset(["interrupted","readonly_deadline","fd_ledger_cap","metadata_cap","fixed_directory_shape","fixed_final_directory_observed_identity","held_directory_full9","one_directory_enumeration","candidate_name_cap","enumeration_incomplete","directory_iterator_closed","directory_stable_after_enumeration","fixed_candidate_body_scope","fixed_candidate_original_full9","candidate_regular_single_link_owner","candidate_size_cap","candidate_full9_open","body_read_cap","positive_bounded_read","body_growth_or_total_cap","whole_body_extent","candidate_full9_after_read","final_held_named_full9","duplicate_json_key","nonfinite_json_number","bounded_termination_text_slots","typed_termination_text_slots","bounded_dyld_text_slots","bounded_text_bytes","bounded_text_lines","public_library_projection_cap","bounded_ips_body","ips_first_metadata_line","two_ips_objects","fixed_regular_python_operator","body_candidate_count_cap","multiple_matching_reports","public_report_cap"])

class CrashIO:
    def __init__(self,signals):
        self.signals=signals;self.remaining=remaining
        self.rows=[];self.close_errors=[];self.max_rows=8
        self.open_ledger={'attempts':0,'knownNoReturnErrors':0,'registered':0,
                          'pending':0,'registrationUnknown':False}
        self.metadata_calls=0;self.read_calls=0;self.read_bytes=0
        self.dirs=[];self.leaves=[];self.iterator=None
        self.candidate_metadata=[]
        self.scan={'attempted':False,'returned':False,'pending':False,'closed':False,
                   'closeAttempted':False,'knownNoReturnError':False,'registrationUnknown':False,
                   'entriesExamined':0,'coverageComplete':False}
    def meta(self,fn,*args,**kwargs):
        remaining();need(self.metadata_calls<MAX_METADATA_CALLS,'metadata_cap')
        self.metadata_calls+=1
        value=fn(*args,**kwargs);remaining();return value
    def open_fd(self, path, flags, mode=None, *, parent=None, role='file'):
        need(len(self.rows) < self.max_rows and self.open_ledger['attempts'] < self.max_rows,
             'fd_ledger_cap')
        with self.signals.critical():
            self.remaining()
            ledger = self.open_ledger
            ledger['attempts'] += 1
            ledger['pending'] += 1
            try:
                fd = os.open(str(path) if parent is None else path.name, flags,
                             *(() if mode is None else (mode,)),
                             **({} if parent is None else {'dir_fd':parent['fd']}))
            except OSError:
                # This handler covers the syscall expression only: no FD was returned.
                ledger['knownNoReturnErrors'] += 1
                ledger['pending'] -= 1
                raise
            try:
                row = {'fd':fd, 'path':str(path), 'role':role,
                       'created':bool(flags & os.O_CREAT), 'writeComplete':False,
                       'closeAttempted':False, 'closed':False}
                self.rows.append(row)
                ledger['registered'] += 1
                ledger['pending'] -= 1
            except BaseException:
                # Even a subsequently closed row cannot erase this incomplete transfer.
                # Do not guess a descriptor, blind-close, or retry registration.
                ledger['registrationUnknown'] = True
                raise
        return row
    def close_one(self, row):
        if row['closeAttempted']:
            return row['closed']
        with self.signals.critical():
            row['closeAttempted'] = True
            try:
                os.close(row['fd'])
                row['closed'] = True
            except BaseException as error:
                row['closeError'] = error_projection(error)
                self.close_errors.append(row['closeError'])
        return row['closed']
    def close(self):
        with self.signals.critical():
            for row in reversed(self.rows):
                self.close_one(row)

    def named(self,row):
        if row.get('parent') is None:return self.meta(os.lstat,Path(row['path']))
        return self.meta(os.stat,Path(row['path']).name,dir_fd=row['parent']['fd'],follow_symlinks=False)
    def open_chain(self):
        parent=None
        for path in DIRECTORIES:
            before=self.meta(os.lstat,path) if parent is None else self.meta(
                os.stat,path.name,dir_fd=parent['fd'],follow_symlinks=False)
            if path==DIRECTORY:
                need(identity(before)[:5]==OBSERVED_DIRECTORY_IDENTITY5,
                     'fixed_final_directory_observed_identity')
            else:
                need(stat.S_ISDIR(before.st_mode) and before.st_uid in (0,501)
                     and not (before.st_mode & 0o022),'fixed_directory_shape')
            row=self.open_fd(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_DIRECTORY,parent=parent,role='directory')
            row['parent']=parent;row['expected']=identity(before)
            need(identity(self.meta(os.fstat,row['fd']))==row['expected']
                 ==identity(self.named(row)),'held_directory_full9')
            self.dirs.append(row);parent=row
        return parent
    def close_scan(self):
        if not self.scan['returned'] or self.scan['closeAttempted']:return
        with self.signals.critical():
            self.scan['closeAttempted']=True
            try:
                self.iterator.close()
                self.scan['closed']=True
            except BaseException as error:
                self.scan['closeError']=error_projection(error)
    def read_one(self,root,name):
        need(name==FIXED_REPORT_NAME and name_allowed(name) and len(self.leaves)<MAX_BODIES,
             'fixed_candidate_body_scope')
        path=DIRECTORY/name
        before=self.meta(os.stat,name,dir_fd=root['fd'],follow_symlinks=False)
        self.candidate_metadata.append({'basename':name,
            'full9':[str(v) for v in identity(before)],
            'type':('regular' if stat.S_ISREG(before.st_mode) else
                    'directory' if stat.S_ISDIR(before.st_mode) else
                    'symlink' if stat.S_ISLNK(before.st_mode) else 'other'),
            'uid':before.st_uid,'gid':before.st_gid,'mode':before.st_mode,
            'modeOctal':oct(before.st_mode),'nlink':before.st_nlink,'size':before.st_size,
            'originalPredicates':{'regular':stat.S_ISREG(before.st_mode),
                'uidIs501':before.st_uid==501,'singleLink':before.st_nlink==1,
                'noSetIdOrGroupOtherWrite':not (before.st_mode & 0o6022),
                'regularSingleLinkOwner':bool(stat.S_ISREG(before.st_mode) and before.st_uid==501
                    and before.st_nlink==1 and not (before.st_mode & 0o6022)),
                'positiveSizeWithinOriginalCap':0<before.st_size<=MAX_BODY_BYTES}})
        need(identity(before)==OBSERVED_REPORT_FULL9,'fixed_candidate_original_full9')
        need(stat.S_ISREG(before.st_mode) and before.st_uid==501 and before.st_nlink==1
             and not(before.st_mode & 0o6022),'candidate_regular_single_link_owner')
        need(0<before.st_size<=MAX_BODY_BYTES,'candidate_size_cap')
        row=self.open_fd(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,parent=root,role='candidate')
        row['parent']=root;row['expected']=identity(before);self.leaves.append(row)
        need(row['expected']==identity(self.meta(os.fstat,row['fd']))
             ==identity(self.named(row)),'candidate_full9_open')
        parts=[];total=0
        while True:
            remaining()
            need(self.read_calls<MAX_READ_CALLS and self.read_bytes<MAX_TOTAL_RETURNED_BYTES,'body_read_cap')
            limit=min(65536,before.st_size+1-total,MAX_TOTAL_RETURNED_BYTES-self.read_bytes)
            need(limit>0,'positive_bounded_read')
            self.read_calls+=1
            block=os.pread(row['fd'],limit,total)
            self.read_bytes+=len(block);total+=len(block)
            need(total<=before.st_size and self.read_bytes<=MAX_TOTAL_RETURNED_BYTES,'body_growth_or_total_cap')
            if not block:break
            parts.append(block)
        need(total==before.st_size,'whole_body_extent')
        need(row['expected']==identity(self.meta(os.fstat,row['fd']))
             ==identity(self.named(row)),'candidate_full9_after_read')
        return b''.join(parts),{'basename':name,'identity':[str(v) for v in row['expected']],
                               'wholeBytesRead':total,'wholeBodyHashExported':False}
    def verify_all(self):
        for row in self.dirs+self.leaves:
            need(not row['closed'] and row['expected']==identity(self.meta(os.fstat,row['fd']))
                 ==identity(self.named(row)),'final_held_named_full9')
        return True
    def public(self):
        ledger=dict(self.open_ledger)
        scan=dict(self.scan)
        scan_closed=(not scan['pending'] and not scan['registrationUnknown']
                     and (not scan['returned'] or scan['closed']) and 'closeError' not in scan)
        all_closed=(not ledger['pending'] and not ledger['registrationUnknown']
                    and ledger['registered']==len(self.rows) and all(r['closed'] for r in self.rows)
                    and not self.close_errors and scan_closed)
        return {'candidateMetadataBeforeShapeCheck':list(self.candidate_metadata),
                'returnedFdLedger':ledger,'scan':scan,'metadataCalls':self.metadata_calls,
                'readCalls':self.read_calls,'returnedReadBytes':self.read_bytes,
                'allReturnedFdsAndIteratorClosed':all_closed,'closeErrors':list(self.close_errors),
                'writes':0,'childProcesses':0}


EPOCH=datetime.datetime(1970,1,1,tzinfo=datetime.timezone.utc)
def date_epoch_seconds(year,month,day,hour,minute,second,offset_seconds=0):
    value=datetime.datetime(year,month,day,hour,minute,second,
            tzinfo=datetime.timezone(datetime.timedelta(seconds=offset_seconds)))
    delta=value-EPOCH
    return delta.days*86400+delta.seconds
def name_allowed(name):
    if type(name) is not str or len(name)>96:return False
    match=NAME_RE.fullmatch(name)
    if match is None:return False
    try:
        year,month,day=(int(v) for v in match.group(1).split('-'))
        hhmmss=match.group(2)
        epoch=date_epoch_seconds(year,month,day,int(hhmmss[:2]),int(hhmmss[2:4]),int(hhmmss[4:6]))
    except (ValueError,OverflowError):return False
    return any(START_MS//1000-NAME_MARGIN_SECONDS<=epoch-offset
               <=(TERMINAL_MS+999)//1000+NAME_MARGIN_SECONDS
               for offset in NAME_OFFSETS_SECONDS)
def crash_time(value):
    if type(value) is not str or len(value)>40:return None
    match=re.fullmatch(r'([0-9]{4})-([0-9]{2})-([0-9]{2})[ T]([0-9]{2}):([0-9]{2}):([0-9]{2})(?:\.([0-9]{1,9}))? ?([+-])([0-9]{2}):?([0-9]{2})',value)
    if match is None:return None
    try:
        y,mo,d,h,mi,se=(int(match.group(i)) for i in range(1,7))
        oh,om=int(match.group(9)),int(match.group(10))
        if oh>14 or om>59 or (oh==14 and om):return None
        offset=(oh*3600+om*60)*(1 if match.group(8)=='+' else -1)
        seconds=date_epoch_seconds(y,mo,d,h,mi,se,offset)
        fraction=int((match.group(7) or '').ljust(9,'0'))
        return {'epochNs':seconds*1000000000+fraction,'fixedFormat':value}
    except (ValueError,OverflowError):return None
def exact_pairs(pairs):
    value={}
    for key,item in pairs:
        need(type(key) is str and key not in value,'duplicate_json_key')
        value[key]=item
    return value
def reject_constant(_value):
    raise Refused('nonfinite_json_number')
def bounded_integer(value,minimum=0,maximum=18446744073709551615):
    return str(value) if type(value) is int and minimum<=value<=maximum else None
def enum_field(value,allowed):
    return {'present':value is not None,'known':value in allowed if type(value) is str else False,
            'value':value if type(value) is str and value in allowed else None}
def fixed_os(value):
    obj=value if type(value) is dict else {}
    train=obj.get('train');build=obj.get('build');release=obj.get('releaseType')
    return {'present':type(value) is dict,
       'train':train if type(train) is str and re.fullmatch(r'macOS [0-9]{1,2}(?:\.[0-9]{1,3}){0,2}',train) else None,
       'build':build if type(build) is str and re.fullmatch(r'[0-9]{1,2}[A-Z][0-9]{1,5}[a-z]?',build) else None,
       'releaseType':release if release in ('User','Beta') else None}
def library_line(line):
    match=re.fullmatch(r'Library (?:not loaded|not found):[ \t]+(.{1,512})[ \t]*',line)
    if match is None:return None
    path=match.group(1).strip()
    if len(path)>=2 and path[0]==path[-1] and path[0] in ("'",'"'):path=path[1:-1]
    if not re.fullmatch(r'/(?:opt/homebrew|System|usr/lib)/[A-Za-z0-9_@.+/-]{1,480}',path):return None
    parts=path.split('/')
    if any(part in ('','.','..') for part in parts[1:]):return None
    basename=parts[-1]
    if re.fullmatch(r'[A-Za-z0-9_+.-]{1,120}\.dylib',basename):
        kind='dylib'
    elif re.fullmatch(r'[A-Za-z0-9_+.-]{1,100}',basename) and basename+'.framework' in parts:
        kind='framework-binary'
    else:return None
    category=('homebrew' if path.startswith('/opt/homebrew/') else
              'System' if path.startswith('/System/') else 'usr-lib')
    return {'kind':kind,'basename':basename,'allowedPublicPrefix':category,
            'underPinnedNodeInstall':path.startswith(NODE_ROOT),
            'equalsKnownNodeExecutable':path==NODE_REAL,'equalsKnownNodeAlias':path==NODE_ALIAS,
            'fullUnknownPathExported':False,'fileExistenceOrContentQualified':False}
def fixed_text_projection(crash,termination):
    # Only these fixed slots, never arbitrary keys, full dictionaries or stack frames.
    slots=[]
    indicator=termination.get('indicator')
    if type(indicator) is str:slots.append(indicator)
    for key in ('reasons','details'):
        value=termination.get(key)
        if value is not None:
            need(type(value) is list and len(value)<=16,'bounded_termination_text_slots')
            need(all(type(x) is str for x in value),'typed_termination_text_slots')
            slots.extend(value)
    asi=crash.get('asi')
    dyld=asi.get('dyld') if type(asi) is dict else None
    if dyld is not None:
        need(type(dyld) is list and len(dyld)<=16 and all(type(x) is str for x in dyld),
             'bounded_dyld_text_slots')
        slots.extend(dyld)
    need(len(slots)<=32 and all(len(x.encode('utf-8'))<=4096 for x in slots)
         and sum(len(x.encode('utf-8')) for x in slots)<=32768,'bounded_text_bytes')
    lines=[]
    for text in slots:lines.extend(text.splitlines())
    need(len(lines)<=64,'bounded_text_lines')
    lower='\n'.join(slots).lower()
    words={'libraryNotLoaded':'library not loaded:','libraryNotFound':'library not found:',
           'symbolNotFound':'symbol not found:','codeSignature':'code signature',
           'sandbox':'sandbox','operationNotPermitted':'operation not permitted',
           'permissionDenied':'permission denied','abortCalled':'abort() called',
           'dyld':'dyld'}
    libraries=[]
    for line in lines:
        item=library_line(line)
        if item is not None and item not in libraries:
            need(len(libraries)<8,'public_library_projection_cap')
            libraries.append(item)
    return {'fixedSlotStringCount':len(slots),'fixedSlotLineCount':len(lines),
            'lexicalOnly':{key:value in lower for key,value in words.items()},
            'publicMissingLibraries':libraries,'allTextClassified':False,
            'rawOrUnknownTextOrHashExported':False}
def proc_path_projection(value):
    # Exact string matches below are classification hypotheses, not wildcard expansion.
    typed=type(value) is str
    bounded_ascii=bool(typed and len(value)<=512 and re.fullmatch(r'[\x20-\x7e]{1,512}',value))
    absolute=bool(bounded_ascii and value.startswith('/'))
    canonical=bool(absolute and all(part not in ('','.','..') for part in value.split('/')[1:]))
    forms=((NODE_REAL,'known-node-real'),(NODE_ALIAS,'known-node-alias'),
           ('/opt/homebrew/*/node','literal-homebrew-star-node'),
           ('/opt/homebrew/*/bin/node','literal-homebrew-star-bin-node'),
           ('/opt/homebrew/Cellar/node/*/bin/node','literal-homebrew-cellar-node-star-bin-node'),
           ('/opt/homebrew/Cellar/*/bin/node','literal-homebrew-cellar-star-bin-node'))
    form=next((label for known,label in forms if typed and value==known),'unrecognized')
    kind=('string' if typed else 'null' if value is None else 'boolean' if type(value) is bool else
          'integer' if type(value) is int else 'number' if type(value) is float else
          'array' if type(value) is list else 'object' if type(value) is dict else 'other')
    return {'type':kind,'boundedPrintableAscii':bounded_ascii,'absolute':absolute,
            'canonicalComponents':canonical,
            'underHomebrewPrefix':bool(canonical and value.startswith('/opt/homebrew/')),
            'basenameIsNode':bool(canonical and value.rsplit('/',1)[-1]=='node'),
            'endsWithBinNode':bool(canonical and value.endswith('/bin/node')),
            'containsLiteralAsterisk':bool(bounded_ascii and '*' in value),
            'equalsKnownReal':bool(typed and value==NODE_REAL),
            'equalsKnownAlias':bool(typed and value==NODE_ALIAS),
            'closedLiteralForm':form,'literalAsteriskMeaningInferred':False,
            'unknownPathOrHashExported':False,'kernelImageOrFileContentQualified':False}
def crash_projection(raw,file_info):
    need(type(raw) is bytes and 0<len(raw)<=MAX_BODY_BYTES,'bounded_ips_body')
    split=raw.find(b'\n')
    need(0<split<=16384,'ips_first_metadata_line')
    header=json.loads(raw[:split].decode('utf-8'),object_pairs_hook=exact_pairs,parse_constant=reject_constant)
    crash=json.loads(raw[split+1:].decode('utf-8'),object_pairs_hook=exact_pairs,parse_constant=reject_constant)
    need(type(header) is dict and type(crash) is dict,'two_ips_objects')
    bug=header.get('bug_type')
    bug_match=bug=='309' or (type(bug) is int and bug==309)
    name_match=crash.get('procName')=='node'
    header_name=header.get('name')
    header_match=header_name is None or header_name=='node'
    pid_match=type(crash.get('pid')) is int and crash['pid']==TARGET_PID
    parent_match=type(crash.get('parentPid')) is int and crash['parentPid']==TARGET_PARENT
    launched=crash_time(crash.get('procLaunch'));captured=crash_time(crash.get('captureTime'))
    lower=(START_MS-CORRELATION_MARGIN_MS)*1000000
    upper=(TERMINAL_MS+CORRELATION_MARGIN_MS)*1000000
    time_typed=launched is not None and captured is not None
    time_match=(time_typed and lower<=launched['epochNs']<=captured['epochNs']<=upper)
    path=crash.get('procPath')
    path_known=path in (NODE_REAL,NODE_ALIAS) if type(path) is str else False
    predicates={'crashType309':bug_match,'metadataNameAbsentOrNode':header_match,
                'procNameNode':name_match,'pidIs51494':pid_match,'parentIs51483':parent_match,
                'launchAndCaptureTimesTyped':time_typed,'withinOriginalCorrelatedTimeWindow':bool(time_match),
                'procPathIsKnownNodePath':path_known}
    fixed_file_bound=(type(file_info) is dict and file_info.get('basename')==FIXED_REPORT_NAME
        and file_info.get('identity')==[str(v) for v in OBSERVED_REPORT_FULL9]
        and type(file_info.get('wholeBytesRead')) is int
        and file_info['wholeBytesRead']==OBSERVED_REPORT_FULL9[6])
    nonpath_matched=all(predicates[key] for key in ('crashType309','metadataNameAbsentOrNode',
        'procNameNode','pidIs51494','parentIs51483','launchAndCaptureTimesTyped',
        'withinOriginalCorrelatedTimeWindow'))
    matched=fixed_file_bound and all(predicates.values())
    safe_fields_admitted=bool(fixed_file_bound and nonpath_matched)
    result={'correlation':predicates,'matchesOriginalFreshChild':matched,
            'fixedObservedFileWholeReadBound':fixed_file_bound,
            'nonPathCorrelationSatisfied':nonpath_matched,
            'safeCrashFieldsAdmitted':safe_fields_admitted,
            'pathQualificationSatisfied':path_known,
            'metadataTimestampUsedAsCrashTime':False,'unknownFieldsExported':False,
            'privateBodyOrHashExported':False,'sameBytesAsPriorReadClaimed':False,
            'causalConclusionClaimed':False,'causeClaim':False}
    result['correlationFullyEvaluated']=(type(crash.get('pid')) is int
        and type(crash.get('parentPid')) is int and type(crash.get('procName')) is str
        and time_typed and type(path) is str)
    if not safe_fields_admitted:
        result['disposition']='not-qualified-for-safe-crash-field-projection'
        return result
    result['procPathClassification']=proc_path_projection(path)
    exception=crash.get('exception');exception=exception if type(exception) is dict else {}
    termination=crash.get('termination');termination=termination if type(termination) is dict else {}
    codes=exception.get('codes')
    code_safe=(codes if type(codes) is str and re.fullmatch(
         r'0x[0-9a-fA-F]{1,16}(?:, ?0x[0-9a-fA-F]{1,16}){0,3}',codes) else None)
    indicator=termination.get('indicator')
    result.update({'disposition':('matched-one-fresh-child' if matched else
            'fixed-file-nonpath-matched-path-unqualified'),
       'pid':TARGET_PID,'parentPid':TARGET_PARENT,'procName':'node',
       'procPath':path if path_known else None,
       'procLaunch':launched['fixedFormat'],'captureTime':captured['fixedFormat'],
       'launchEpochNs':str(launched['epochNs']),'captureEpochNs':str(captured['epochNs']),
       'osVersion':fixed_os(crash.get('osVersion')),
       'exception':{
          'type':enum_field(exception.get('type'),('EXC_CRASH','EXC_BAD_ACCESS','EXC_BAD_INSTRUCTION',
               'EXC_BREAKPOINT','EXC_RESOURCE','EXC_GUARD','EXC_SOFTWARE','EXC_ARITHMETIC')),
          'signal':enum_field(exception.get('signal'),('SIGABRT','SIGSEGV','SIGILL','SIGTRAP','SIGKILL',
               'SIGBUS','SIGFPE','SIGTERM','SIGSYS')),
          'numericHexCodes':code_safe},
       'termination':{
          'namespace':enum_field(termination.get('namespace'),('DYLD','SIGNAL','CODESIGNING',
             'SANDBOX','LIBSYSTEM','RUNNINGBOARD','WATCHDOG','ENDPOINTSECURITY','TCC')),
          'codeDecimal':bounded_integer(termination.get('code')),
          'flagsDecimal':bounded_integer(termination.get('flags')),
          'indicator':enum_field(indicator,('Abort trap: 6','Library missing','Symbol missing',
             'Code Signature Invalid','Invalid Page','Segmentation fault: 11')),
          'byProc':enum_field(termination.get('byProc'),('node','dyld','kernel','launchd','sandboxd','exc handler')),
          'byPidEqualsTarget':termination.get('byPid')==TARGET_PID,
          'byPidEqualsOriginalParent':termination.get('byPid')==TARGET_PARENT},
       'dyldAndTerminationText':fixed_text_projection(crash,termination),
       'fullCrashReportClassified':False,'causalConclusionClaimed':False,
       'threadsEnvironmentOrUsedImagesExported':False})
    return result


def main():
    report={'schema':'heptabao.mac-one-public-node-ips-fixed-file-projection.r3',
      'ok':False,'observationComplete':False,'outcomeUnknown':False,
      'directory':str(DIRECTORY),'targetPid':TARGET_PID,'targetParentPid':TARGET_PARENT,
      'sourceJob':'mac/1a1b25c3c54-fc05-7db1',
      'originalNativeCreatedMs':START_MS,'originalNativeTerminalMs':TERMINAL_MS,
      'actualLocalPsStart':'Sat Nov 7 03:35:52 2026',
      'filenameUTCAndObservedLocalOffsetsSeconds':list(NAME_OFFSETS_SECONDS),
      'filenameMarginSeconds':NAME_MARGIN_SECONDS,'correlationMarginMs':CORRELATION_MARGIN_MS,
      'fixedPathChainObserved':[],'candidates':[],
      'fixedReportBasename':FIXED_REPORT_NAME,'fixedObservedReportFull9':[str(v) for v in OBSERVED_REPORT_FULL9],
      'directoryEnumerationRequested':False,'directoryCoverageClaimed':False,
      'sameBytesAsPriorReadClaimed':False,'safeCrashProjectionCount':0,
      'matchedReportCount':0,'matchingFreshReportFound':False,
      'historicalManagedClosureClaimed':False,'originalRuntimeCauseProved':False,
      'originalRuntimeProgressReclassified':False,'newProbeCauseConclusionClaimed':False,
      'oldPrivateLogsOrCapsuleRequested':False,'potentiallyPrivateIpsBodyReadScope':True,
      'rawIpsOrUnknownTextOrHashExported':False,'SDKOrCredentialOrProviderCalled':False,
      'filesystemWrites':0,'childProcesses':0,'otherPidSignalOrWait':False,
      'launchdOperation':False,'T5ReadOrWrite':False,'fallbackDirectory':False}
    signals=SignalFacade();io=None;query_complete=False;final_fences=False
    saved={sig:signal.getsignal(sig) for sig in (signal.SIGTERM,signal.SIGINT)}
    handlers_restored=False
    try:
        for sig in saved:signal.signal(sig,interrupt)
        need(sys.platform=='darwin' and os.geteuid()==501 and sys.executable==PYTHON,
             'fixed_regular_python_operator')
        io=CrashIO(signals)
        directory=io.open_chain()
        report['fixedPathChainObserved']=[{'path':row['path'],
           'identity':[str(x) for x in row['expected']]} for row in io.dirs]
        names=[FIXED_REPORT_NAME]
        report['candidateNameCount']=len(names)
        need(len(names)<=MAX_BODIES,'body_candidate_count_cap')
        for name in names:
            raw,file_info=io.read_one(directory,name)
            projection=crash_projection(raw,file_info)
            report['candidates'].append({'file':file_info,'projection':projection})
        matches=[r for r in report['candidates'] if r['projection']['matchesOriginalFreshChild']]
        report['matchedReportCount']=len(matches)
        need(len(matches)<=1,'multiple_matching_reports')
        report['matchingFreshReportFound']=len(matches)==1
        report['safeCrashProjectionCount']=sum(1 for r in report['candidates']
            if r['projection']['safeCrashFieldsAdmitted'])
        query_complete=all(r['projection']['correlationFullyEvaluated'] for r in report['candidates'])
        report['allCandidateCorrelationsEvaluated']=query_complete
        report['noQualifiedMatchWithinThisExactScope']=(len(matches)==0 and query_complete)
        report['noGlobalAbsenceClaim']=True
    except BaseException as error:
        report['error']=error_projection(error)
    finally:
        if io is not None:
            try:
                final_fences=io.verify_all()
            except BaseException as error:
                report['finalFenceError']=error_projection(error)
            try:
                with critical():
                    io.close_scan()
                    io.close()
            except BaseException as error:
                report['closeLoopError']=error_projection(error)
            report['io']=io.public()
        else:
            report['io']={'allReturnedFdsAndIteratorClosed':True,'noIoObjectCreated':True}
        restored=True
        for sig,handler in saved.items():
            try:signal.signal(sig,handler)
            except BaseException:
                restored=False
        handlers_restored=restored
        report['finalHeldNamedFencesPassed']=final_fences
        report['handlersRestored']=handlers_restored
        report['pendingSignalObserved']=pending_signal is not None
        report['elapsedSeconds']=time.monotonic()-START
        report['afterClosureDeadlineMet']=time.monotonic()<=FINAL_UNTIL
        closed=report['io']['allReturnedFdsAndIteratorClosed'] and handlers_restored
        report['allOwnResourcesClosed']=closed
        report['outcomeUnknown']=(not closed or not final_fences or pending_signal is not None
                                 or not report['afterClosureDeadlineMet'])
        report['observationComplete']=(query_complete and 'error' not in report
            and final_fences and closed and not report['outcomeUnknown'])
        report['ok']=report['observationComplete']
    raw=json.dumps(report,sort_keys=True,separators=(',',':'),ensure_ascii=True)+'\n'
    if len(raw.encode('ascii'))>MAX_PUBLIC_BYTES:
        report={'schema':'heptabao.mac-one-public-node-ips-fixed-file-projection.r3','ok':False,
         'observationComplete':False,'outcomeUnknown':True,'error':{'type':'Refused','code':'public_report_cap'},
         'allOwnResourcesClosed':report['allOwnResourcesClosed'],
         'handlersRestored':handlers_restored,'rawIpsOrUnknownTextOrHashExported':False,
         'projectionDroppedForReportCap':True,'historicalManagedClosureClaimed':False}
        raw=json.dumps(report,sort_keys=True,separators=(',',':'))+'\n'
    sys.stdout.write(raw);sys.stdout.flush()
    return 0 if report['ok'] else 1

if __name__=='__main__':raise SystemExit(main())
