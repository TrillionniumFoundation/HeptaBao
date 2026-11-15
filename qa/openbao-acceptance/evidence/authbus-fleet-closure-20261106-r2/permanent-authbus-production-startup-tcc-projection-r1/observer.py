"""Project only four already retained TCC events for the closed original PID."""
import hashlib, json, os, re, stat, sys, time
from pathlib import Path

START = time.monotonic(); UNTIL = START + 20
HOME = Path('/Users/qianqi')
ROOT = HOME / 'heptabao-authbus-production-custody/service-startup-systemlog-r1'
PYTHON = Path('/opt/homebrew/Cellar/python@3.14/3.14.3_1/Frameworks/Python.framework/Versions/3.14/bin/python3.14')
BINARY = '/Volumes/T5/hepta-vnext-recovery-20261013/heptabao-authbus-production/releases/4bde9aee03fcd27c59e13607e529b1cee594b249/heptabao-server'
PREDICATE = '(process == "tccd" OR process == "syspolicyd" OR process == "amfid" OR process == "launchd") AND (eventMessage CONTAINS[c] "19077" OR eventMessage CONTAINS[c] "org.heptabao.authbus" OR eventMessage CONTAINS[c] "heptabao-server")'
ARGV = ['/usr/bin/log', 'show', '--style', 'json', '--start', '@1794021555', '--end', '@1794021590',
        '--info', '--debug', '--no-pager', '--predicate', PREDICATE]
ROWS, PARENTS, FILES = [], [], []
REPORT = {'schema':'heptabao.original-startup-tcc-events-projection.r1', 'ok':False,
    'originalServiceJob':'1a1b4048166-fc05-85db', 'originalServicePid':19077,
    'originalSystemLogJob':'1a1b411eb05-fc05-861b', 'selectedOriginalOrdinals':[22,23,24,29],
    'serviceActions':0, 'childrenStarted':0, 'httpRequests':0, 'originalLogQueryRepeated':False,
    'keyOrCredentialFilesRead':0, 'permissionSettingsChanged':False,
    'rawLogContentsOrHashesPublished':False, 'messagesHavePathsAndLongIdentifiersRedacted':True,
    'causalityInferredByScript':False}

class Refused(Exception): pass
def need(value, code):
    if not value: raise Refused(code)
def live(): need(time.monotonic() < UNTIL, 'original_projection_deadline')
def full(info): return tuple(getattr(info, field) for field in
    ('st_dev','st_ino','st_uid','st_gid','st_mode','st_nlink','st_size','st_mtime_ns','st_ctime_ns'))
def opened(name, flags, parent=None):
    live()
    fd = os.open(name, flags | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK,
                 **({} if parent is None else {'dir_fd':parent['fd']}))
    row = {'fd':fd,'attempts':0,'closed':False}; ROWS.append(row); return row
def check():
    live()
    for path, row, expected in PARENTS + FILES:
        need(full(os.fstat(row['fd'])) == full(path.lstat()) == expected,
             'original_retained_log_and_parents_unchanged')
def read(name, maximum, expected_size=None):
    check()
    need(name in ('request.public.json','command.original.private.json',
                  'stdout.original.private.bin','stderr.original.private.bin'), 'finite_original_log_file')
    row = opened(name, os.O_RDONLY, PARENTS[-1][1]); info = os.fstat(row['fd'])
    need(stat.S_ISREG(info.st_mode) and info.st_uid == 501 and info.st_gid == 20
         and info.st_nlink == 1 and stat.S_IMODE(info.st_mode) == 0o600
         and 0 <= info.st_size <= maximum
         and (expected_size is None or info.st_size == expected_size)
         and full(info) == full((ROOT/name).lstat()), 'original_private_log_custody')
    FILES.append((ROOT/name, row, full(info)))
    value = bytearray()
    while len(value) <= info.st_size:
        live(); part = os.read(row['fd'], min(65536, info.st_size + 1 - len(value)))
        if not part: break
        value.extend(part)
    need(len(value) == info.st_size, 'original_log_complete_read')
    check(); return bytes(value)
def project(ordinal, event):
    need(type(event) is dict and Path(event.get('processImagePath','')).name == 'tccd',
         'selected_original_tccd_actor')
    message = event.get('eventMessage')
    need(type(message) is str and message.isascii() and 0 < len(message) <= 8192
         and '19077' in message and (ordinal == 24 or BINARY in message),
         'selected_original_pid_and_binary_binding')
    service = 'kTCCServiceSystemPolicyAllFiles' if ordinal in (22,23) else 'kTCCServiceSystemPolicyRemovableVolumes'
    need(service in message, 'selected_original_exact_tcc_service')
    need(not re.search(r'(?i)(access_token|refresh_token|root_token|keys_base64|bearer |password|authorization:)', message),
         'unexpected_sensitive_message_refused')
    text = message.replace(BINARY, '<original-binary>')
    text = text.replace('kTCCServiceSystemPolicyAllFiles', '<all-files-service>')
    text = text.replace('kTCCServiceSystemPolicyRemovableVolumes', '<removable-volume-service>')
    text = re.sub(r'(?:/[A-Za-z0-9._@%+=~:-]+)+', '<redacted-path>', text)
    text = re.sub(r'(?i)\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b', '<redacted-id>', text)
    text = re.sub(r'(?i)\b0x[0-9a-f]+\b', '<redacted-address>', text)
    text = re.sub(r'\b[A-Za-z0-9_+./=-]{24,}', '<redacted-long-id>', text)
    need(BINARY not in text and '/Volumes/' not in text and '/Users/' not in text
         and not re.search(r'(?i)\b[0-9a-f]{32,}\b', text), 'bounded_redacted_message_only')
    return {'ordinal':ordinal, 'actor':'tccd', 'originalPidPresent':True,
        'exactOriginalBinaryPresent':BINARY in message, 'service':service,
        'messageRedacted':text,
        'observedAuthValueFields':[int(v) for v in re.findall(r'\bauthValue[=: ]+(\d{1,2})\b', message)],
        'observedAuthReasonFields':[int(v) for v in re.findall(r'\bauthReason[=: ]+(\d{1,2})\b', message)]}

try:
    sys.dont_write_bytecode = True
    need(sys.platform == 'darwin' and os.getuid() == os.geteuid() == 501 and os.getgid() == 20
         and Path(sys.executable).resolve(strict=True) == PYTHON, 'original_mac_projection_runtime')
    parent = None
    for path in (Path('/'), Path('/Users'), HOME, ROOT.parent, ROOT):
        row = opened(str(path) if parent is None else path.name, os.O_RDONLY | os.O_DIRECTORY, parent)
        info = os.fstat(row['fd'])
        need(stat.S_ISDIR(info.st_mode) and info.st_uid == (0 if path in (Path('/'),Path('/Users')) else 501)
             and not stat.S_IMODE(info.st_mode) & 0o022 and full(info) == full(path.lstat()),
             'same_protected_original_log_parent')
        if path in (ROOT.parent, ROOT): need(stat.S_IMODE(info.st_mode) == 0o700, 'original_private_log_directory')
        PARENTS.append((path,row,full(info))); parent = row
    request = json.loads(read('request.public.json',16384))
    need(request == {'argv':ARGV, 'originalPid':19077, 'fixedHistoricalWindowSeconds':35,
                     'commandCapSeconds':20, 'maximumOutputBytesPerStream':2097152}, 'exact_original_log_request')
    command = json.loads(read('command.original.private.json',16384))
    need(command.get('argv') == ARGV and command.get('pid') == 23670 and command.get('exitCode') == 0
         and command.get('completeBeforeDeadline') is True and command.get('outcomeUnknown') is False
         and command.get('streamsClosed') is True and command.get('stdoutBytes') == 44062
         and command.get('stderrBytes') == 0 and command.get('cleanup',{}).get('ok') is True
         and command['cleanup'].get('directChildReaped') is True
         and command['cleanup'].get('allGroupRowsEmptyAfterReap') is True, 'known_complete_original_log_command')
    raw = read('stdout.original.private.bin',44062,44062)
    err = read('stderr.original.private.bin',0,0)
    need(hashlib.sha256(raw).hexdigest() == command.get('stdoutSha256')
         and hashlib.sha256(err).hexdigest() == command.get('stderrSha256'), 'original_private_output_hash_binding')
    events = json.loads(raw); need(type(events) is list and len(events) == 32, 'original_complete_event_array')
    result = [project(i,events[i]) for i in REPORT['selectedOriginalOrdinals']]
    check()
    REPORT.update(ok=True, originalRawBytes=44062, originalEventCount=32,
                  originalPrivateHashBindingVerified=True, events=result)
except BaseException as error:
    REPORT['errorCode'] = str(error) if isinstance(error,Refused) else 'original_projection_refused'
finally:
    for row in reversed(ROWS):
        row['attempts'] = 1
        try: os.close(row['fd']); row['closed'] = True
        except BaseException: REPORT['ok'] = False
    REPORT['allDescriptorsClosedOnce'] = all(row['attempts']==1 and row['closed'] for row in ROWS)
    REPORT['descriptorCount'] = len(ROWS)
    try:
        for path,_row,expected in PARENTS+FILES:
            need(full(path.lstat()) == expected, 'closed_original_names_still_exact')
        live(); REPORT['closedOriginalNamesStillExact'] = True
    except BaseException: REPORT['ok'] = False
    REPORT['elapsedSeconds'] = time.monotonic()-START
    REPORT['ok'] = bool(REPORT['ok'] and REPORT['allDescriptorsClosedOnce'])
    print(json.dumps(REPORT,sort_keys=True),flush=True)
raise SystemExit(0 if REPORT['ok'] else 1)
