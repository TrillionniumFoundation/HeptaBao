PARENT_START_NS = time.monotonic_ns()
PARENT_UNTIL_NS = PARENT_START_NS + 45000000000
HELPER_ADMISSION_END_NS = PARENT_START_NS + 35000000000
signals = None
controller_cleanup_mode = False
direct_call_attempts = 0

def remaining(*, cleanup=False):
    if not cleanup and not controller_cleanup_mode:
        need(signals is not None and signals.pending is None, 'controller_cancelled')
    left = (PARENT_UNTIL_NS-time.monotonic_ns())/1000000000
    need(left > 0, 'shared_45_second_deadline')
    return left

def load_readonly_helpers():
    for row in MODULES:
        raw = base64.b64decode(row['base64'], validate=True)
        need(len(raw) == row['bytes'] and sha(raw) == row['sha256'],
             'embedded_original_helper_whole')
        need(row['name'] not in sys.modules, 'no_existing_helper_module')
        module = types.ModuleType(row['name'])
        module.__file__ = '<public-' + row['name'] + '>'
        sys.modules[row['name']] = module
        exec(compile(raw, module.__file__, 'exec'), module.__dict__)
    from mac_owned_commands_r1 import Signals, Commands
    return Signals, Commands

def fixed_field_projection(raw, expected_argv):
    need(isinstance(raw,bytes) and len(raw) <= 65536, 'diagnostic_print_byte_cap')
    result = {'bytes':len(raw), 'utf8':False, 'lineCount':None,
              'firstLineExactTarget':False, 'scanComplete':False,
              'parsed':False, 'parseError':None, 'fieldFacts':{},
              'arguments':None, 'registrationBinding':None}
    try:
        lines = raw.decode('utf-8','strict').splitlines()
    except UnicodeDecodeError as error:
        result['parseError'] = error_projection(error)
        return result, None
    result['utf8'] = True
    result['lineCount'] = len(lines)
    need(1 <= len(lines) <= 4096, 'diagnostic_print_line_cap')
    result['firstLineExactTarget'] = lines[0].strip() == TARGET + ' = {'
    names = ('path','program','pid','state','runs','last exit code','last terminating signal')
    values = {name:[] for name in names}
    arguments = []
    argument_blocks = 0
    depth = 1
    in_arguments = False
    structure = result['firstLineExactTarget']
    for ordinal,line in enumerate(lines[1:],1):
        text = line.strip()
        if in_arguments:
            if text == '}':
                in_arguments = False
                depth -= 1
                continue
            structure = structure and depth == 2 and bool(text) and '{' not in text and '}' not in text
            arguments.append(text)
            continue
        if depth == 1 and text == 'arguments = {':
            argument_blocks += 1
            in_arguments = True
            depth += 1
            continue
        if depth == 1 and ' = ' in text and not text.endswith('{'):
            name,value = text.split(' = ',1)
            if name in values:
                values[name].append(value)
        depth += text.count('{') - text.count('}')
        if depth < 0 or depth == 0 and (text != '}' or ordinal != len(lines)-1):
            structure = False
    result['scanComplete'] = bool(structure and depth == 0 and not in_arguments)
    for name in names:
        items = values[name]
        single = items[0] if len(items) == 1 else None
        fact = {'present':bool(items), 'count':len(items), 'unique':len(items) == 1,
                'numericDecimalSyntax':None, 'typedInteger':None,
                'matchesExpected':None, 'knownState':None,
                'exactExConfig78':None, 'exactNeverExitedLiteral':None}
        if name in ('pid','runs','last exit code','last terminating signal'):
            decimal = single is not None and re.fullmatch(r'-?[0-9]{1,10}',single) is not None
            fact['numericDecimalSyntax'] = decimal
            fact['typedInteger'] = int(single) if decimal else None
            if name == 'last exit code':
                fact['exactExConfig78'] = single == '78: EX_CONFIG'
                fact['exactNeverExitedLiteral'] = single == '(never exited)'
        elif name == 'state':
            fact['knownState'] = single if single in ('running','not running') else None
        else:
            fact['matchesExpected'] = single == (str(PLIST) if name == 'path' else PYTHON)
        result['fieldFacts'][name] = fact
    result['arguments'] = {'blocks':argument_blocks, 'count':len(arguments),
        'exactExpectedVector':argument_blocks == 1 and arguments == expected_argv,
        'expectedCount':len(expected_argv),
        'expectedPositionMatches':[i < len(arguments) and arguments[i] == v
                                   for i,v in enumerate(expected_argv)]}
    try:
        value = parse_print(raw,TARGET)
    except (ProbeRefused,UnicodeDecodeError) as error:
        result['parseError'] = error_projection(error)
        return result, None
    result['parsed'] = True
    result['registrationBinding'] = {
        'path':value.get('path') == str(PLIST),
        'program':value.get('program') == PYTHON,
        'arguments':value['arguments'] == expected_argv,
        'runsAllowed':value.get('runs') in (0,1),
        'stateAllowed':value.get('state') in ('running','not running')}
    return result, value

class ReadOnlyControl:
    def __init__(self, commands, expected_argv):
        self.commands = commands
        self.argv = list(expected_argv)
        self.calls = 0
        self.command_bytes = 0
        self.unknown = False

    def call(self, label, argv, *, seconds=10.0, maximum=65536):
        global direct_call_attempts
        remaining()
        need(self.calls < 4 and self.command_bytes < 1048576, 'diagnostic_helper_cap')
        need(time.monotonic_ns() < HELPER_ADMISSION_END_NS, 'helper_cleanup_reserve')
        self.calls += 1
        until = min(HELPER_ADMISSION_END_NS/1000000000,time.monotonic()+seconds)
        with signals.critical():
            remaining()
            direct_call_attempts += 1
        try:
            row,out,err = self.commands.run(label,list(argv),until=until,maximum=maximum)
        except BaseException:
            self.unknown = True
            raise
        self.command_bytes += len(out)+len(err)
        if row['outcomeUnknown'] or not row['completeBeforeDeadline']:
            self.unknown = True
            raise ProbeRefused('direct_helper_outcome_unknown')
        need(self.command_bytes <= 1048576, 'diagnostic_total_helper_bytes')
        remaining()
        return row,out,err

    def query(self, ordinal):
        row,out,err = self.call('readonly-print-%d' % ordinal,
            ['/bin/launchctl','print',TARGET])
        if missing_service(row['exitCode'],out,err):
            return {'ordinal':ordinal,'registrationAbsent':True,'knownCommand':True,
                    'projection':None}, None
        need(row['exitCode'] == 0 and not err, 'known_probe_print')
        projection,value = fixed_field_projection(out,self.argv)
        return {'ordinal':ordinal,'registrationAbsent':False,'knownCommand':True,
                'projection':projection}, value

    def pid_observation(self, ordinal, ready_identity, reader):
        pid = ready_identity['pid']
        row,out,err = self.call('readonly-ready-pid-%d' % ordinal,
            ['/bin/ps','-p',str(pid),'-o','pid=,ppid=,pgid=,uid=,stat='],
            seconds=4.0,maximum=4096)
        need(not err, 'exact_pid_projection_stderr_empty')
        if row['exitCode'] == 1 and not out.strip():
            return {'ordinal':ordinal,'originalReadyPid':pid,'kind':'absent',
                    'originalBirthPresent':False,'processNotOwnedOrSignalled':True}
        need(row['exitCode'] == 0, 'known_pid_projection')
        lines = out.decode('ascii','strict').splitlines()
        need(len(lines) == 1, 'one_observed_pid_row')
        fields = lines[0].split()
        need(len(fields) == 5 and all(re.fullmatch(r'[0-9]{1,10}',v) for v in fields[:4])
             and int(fields[0]) == pid and re.fullmatch(r'[A-Za-z+<>\-]{1,16}',fields[4]),
             'numeric_observed_pid_projection')
        snapshots = []
        for _ in range(2):
            remaining()
            info = BsdInfo()
            n = reader.lib.proc_pidinfo(pid,3,0,ctypes.byref(info),ctypes.sizeof(info))
            need(n == ctypes.sizeof(info) and info.pid == pid
                 and info.birth_sec > 0 and info.birth_usec < 1000000, 'complete_reuse_birth')
            snapshots.append((info.pid,info.ppid,info.pgid,info.uid,info.birth_sec,info.birth_usec))
            remaining()
        need(snapshots[0] == snapshots[1], 'diagnostic_stable_pid_birth')
        actual = snapshots[0]
        same_birth = actual[4:] == (ready_identity['birthSec'],ready_identity['birthUsec'])
        same_numeric_identity = actual[:4] == tuple(ready_identity[k] for k in ('pid','ppid','pgid','uid'))
        return {'ordinal':ordinal,'originalReadyPid':pid,
                'kind':'same_birth_present' if same_birth else 'reused_different_birth',
                'originalBirthPresent':same_birth,
                'sameNumericIdentity':same_numeric_identity,
                'processNotOwnedOrSignalled':True}

def check_leaf_metadata(io, path, expected):
    parent = io.open_dir(path.parent)
    io.check_dir(parent)
    info = io.meta(os.stat,path.name,dir_fd=parent['fd'],follow_symlinks=False)
    io.file_shape(info,path)
    need(identity(info) == tuple(expected), 'diagnostic_pinned_leaf_final_full9')
    io.check_dir(parent)

def read_pinned(io,path,result):
    pin = INPUT_PINS[str(path)]
    raw,held = io.read(path,expected=pin['identity'],maximum=pin['bytes'])
    need(len(raw) == pin['bytes'] and sha(raw) == pin['sha256'], 'diagnostic_pinned_whole')
    result['pinnedInputs'].append({'path':str(path),'identity':held,
                                  'bytes':len(raw),'sha256':pin['sha256']})
    return raw

def observe_ready(io,plan,result):
    marker = io.present_marker(READY_MARK)
    result['ready'] = {'markerPresent':marker is not None,'qualified':False}
    if marker is None:
        return None,None
    raw,held = io.read(READY)
    need(io.present_marker(READY_MARK) == marker, 'ready_marker_stable')
    value = json.loads(raw)
    need(isinstance(value,dict) and set(value) == {'schema','generation','planSha256',
        'sourceSha256','identity','homeObject','initialChildren','t5AccessAttempted'},
        'exact_ready_keys')
    need(value['schema'] == 'heptabao.public-launchd-home-t5-ready.r1'
         and value['generation'] == plan['generation']
         and value['planSha256'] == INPUT_PINS[str(PLAN)]['sha256']
         and value['sourceSha256'] == INPUT_PINS[str(CHILD)]['sha256']
         and value['homeObject'] == plan['homeObject']
         and value['initialChildren'] == [] and value['t5AccessAttempted'] is False,
         'ready_exact_public_bindings')
    actual = validate_process(value['identity'])
    need(actual['pid'] <= 2147483647 and actual['pid'] != plan['controllerIdentity']['pid']
         and actual['ppid'] != plan['controllerIdentity']['pid'],
         'diagnostic_ready_not_original_controller')
    result['ready'] = {'markerPresent':True,'qualified':True,'identity':actual,
        'full9':held,'bytes':len(raw),'sha256':sha(raw),'markerFull9':marker,
        'sameFixedPlanAndSource':True,'historicalReadyInodeNotPreviouslyPublished':True}
    return actual,held

def observe_terminal(io,ready_identity,result):
    raw,held = io.read(STDOUT)
    result['terminal'] = {'present':True,'empty':not raw,'bytes':len(raw),
                          'full9':held,'qualified':False}
    if raw and ready_identity is not None:
        need(raw.endswith(b'\n') and raw.count(b'\n') == 1, 'diagnostic_one_public_terminal')
        value = json.loads(raw)
        if isinstance(value,dict) and isinstance(value.get('error'),dict):
            code = value['error'].get('code')
            need(code is None or code in CHILD_PUBLIC_ERROR_CODES, 'diagnostic_original_child_error_set')
        projected = validate_child_terminal(raw,ready_identity)
        result['terminal'].update(qualified=True,public=projected,sha256=sha(raw))
    err,err_held = io.read(STDERR)
    result['managedStderr'] = {'bytes':len(err),'empty':not err,'full9':err_held,
        'rawOrUnknownHashExported':False}
    return held,err_held

def safe_commands_public(commands):
    value = commands.public()
    # Never forward hashes of unknown print, ps or stderr text. Only closed, typed
    # helper resource/exit facts and the already fixed argv survive this projection.
    rows = []
    for row in value['commands']:
        rows.append({key:row[key] for key in (
            'label','argv','pid','exitCode','stdoutBytes','stderrBytes',
            'elapsedSeconds','commandDeadlineMonotonic','completeBeforeDeadline',
            'streamsClosed','outcomeUnknown','errorType','errorCode','cleanup')})
    return {'commands':rows,'allOwnedCommandsStopped':value['allOwnedCommandsStopped'],
            'unknownCommandCount':value['unknownCommandCount']}

def main():
    global signals,controller_cleanup_mode
    io = None
    commands = None
    control = None
    saved = {}
    stage = 'entry'
    result = {'schema':'heptabao.public-home-t5-existing-label-readonly.r1',
        'ok':False,'observationComplete':False,'outcomeUnknown':False,
        'newLabel':LABEL,'target':TARGET,'pinnedInputs':[],'prints':[],
        'pidObservations':[],'historicalR4Rewritten':False,
        'historicalPrintRawRecovered':False,'oldWorkerLabelTouched':False,
        'bootstrapOrBootoutCalled':False,'managedProcessSignalledOrReaped':False,
        'newDirectoriesOrFilesCreated':False,'t5FileOrDirectoryRead':False,
        'sdkOrCredentialRead':False,'productServerOrConsumerStarted':False,
        'sharedSeconds':45,'helperAdmissionEndSeconds':35,'outerSeconds':60,
        'registrationClosureClaimed':False,'originalR4ManagedScopeStillUnknown':True,
        'currentReadyOrTerminalIsNotHistoricalFull9Proof':True}
    try:
        Signals,Commands = load_readonly_helpers()
        signals = Signals()
        saved = {s:signal.getsignal(s) for s in (signal.SIGTERM,signal.SIGINT)}
        signals.install()
        need(sys.platform == 'darwin' and os.getuid() == os.geteuid() == 501
             and sys.executable == PYTHON, 'controller_exact_platform_python')
        io = FixedIO(signals,remaining,read_cap=262144,write_cap=0)
        io.allowed_dirs = {Path('/'),Path('/Users'),HOME_PARENT,HOME}
        io.allowed_dirs.update(PYTHON_PATHS)
        io.allowed_files = {Path(PYTHON):34640,CHILD:INPUT_PINS[str(CHILD)]['bytes'],
            PLAN:INPUT_PINS[str(PLAN)]['bytes'],PLIST:INPUT_PINS[str(PLIST)]['bytes'],
            READY:8192,READY_MARK:0,STDOUT:32768,STDERR:4096}
        io.writable = set()
        io.max_writes = 0
        stage = 'pinned_inputs'
        for path in (Path(PYTHON),CHILD,PLAN,PLIST):
            raw = read_pinned(io,path,result)
            if path == PLAN:
                plan = json.loads(raw)
            elif path == PLIST:
                plist = plistlib.loads(raw)
        need(isinstance(plan,dict) and set(plan) == {'schema','label','home','work','sourceSha256',
            'homeObject','workFull9','sentinelFull9','sentinelSha256','childUntilNs',
            'controllerUntilNs','controllerIdentity','generation'}, 'child_public_plan_fields')
        need(plan['schema'] == 'heptabao.public-launchd-home-t5-plan.r1'
             and plan['label'] == LABEL and plan['home'] == str(HOME)
             and plan['work'] == str(WORK) and plan['sourceSha256'] == INPUT_PINS[str(CHILD)]['sha256']
             and isinstance(plan['generation'],str) and re.fullmatch(r'[0-9a-f]{64}',plan['generation']),
             'diagnostic_same_original_public_plan')
        validate_process(plan['controllerIdentity'])
        need(isinstance(plist,dict) and plist.get('Label') == LABEL
             and 'Program' not in plist and plist.get('ProgramArguments') == EXPECTED_ARGV
             and plist.get('WorkingDirectory') == str(HOME)
             and plist.get('StandardOutPath') == str(STDOUT)
             and plist.get('StandardErrorPath') == str(STDERR), 'diagnostic_same_original_plist')
        home = io.open_dir(HOME)
        need(tuple(plan['homeObject']) == home['initial'][:5], 'child_same_home_object')
        commands = Commands(signals)
        control = ReadOnlyControl(commands,EXPECTED_ARGV)
        stage = 'current_print_first'
        first,first_value = control.query(1)
        result['prints'].append(first)
        stage = 'current_ready'
        ready_identity,ready_held = observe_ready(io,plan,result)
        stage = 'current_terminal'
        stdout_held,stderr_held = observe_terminal(io,ready_identity,result)
        reader = ProcessReader() if ready_identity is not None else None
        stage = 'current_ready_pid_first'
        if ready_identity is not None:
            result['pidObservations'].append(control.pid_observation(1,ready_identity,reader))
        stage = 'current_print_second'
        second,second_value = control.query(2)
        result['prints'].append(second)
        stage = 'current_ready_pid_second'
        if ready_identity is not None:
            result['pidObservations'].append(control.pid_observation(2,ready_identity,reader))
        result['currentLabelAbsentBoth'] = first['registrationAbsent'] and second['registrationAbsent']
        result['originalReadyPidDepartureObservedTwice'] = (len(result['pidObservations']) == 2
            and all(row['kind'] in ('absent','reused_different_birth') for row in result['pidObservations']))
        result['currentParsedRegistrationBoth'] = (first_value is not None and second_value is not None
            and all(all(row['projection']['registrationBinding'].values()) for row in result['prints']))
        result['currentPidMatchesReady'] = (None if ready_identity is None else
            [None if v is None else v.get('pid') == ready_identity['pid']
             for v in (first_value,second_value)])
        result['currentTerminalExitMatchesPrint'] = None
        if result.get('terminal',{}).get('qualified') and first_value is not None and second_value is not None:
            expected_exit = 0 if result['terminal']['public']['ok'] else 1
            result['currentTerminalExitMatchesPrint'] = [
                v.get('pid') is None and v.get('state') == 'not running'
                and v.get('runs') == 1 and v.get('last exit code') == expected_exit
                for v in (first_value,second_value)]
        stage = 'final_readonly_fences'
        for path in (Path(PYTHON),CHILD,PLAN,PLIST):
            check_leaf_metadata(io,path,INPUT_PINS[str(path)]['identity'])
        if ready_held is not None:
            check_leaf_metadata(io,READY,ready_held)
            need(io.present_marker(READY_MARK) == result['ready']['markerFull9'], 'ready_marker_stable')
        check_leaf_metadata(io,STDOUT,stdout_held)
        check_leaf_metadata(io,STDERR,stderr_held)
        io.check_all()
        remaining()
        result['observationComplete'] = True
        stage = 'complete'
    except BaseException as error:
        result['error'] = error_projection(error)
    finally:
        controller_cleanup_mode = True
        result['stage'] = stage
        io_closed = io is None
        try:
            if io is not None:
                io.close()
                result['io'] = io.public()
                io_closed = result['io']['allClosed']
        except BaseException as error:
            result['ioCloseError'] = error_projection(error)
            io_closed = False
        helpers_closed = direct_call_attempts == 0 if commands is None else False
        try:
            if commands is not None:
                result['directHelpers'] = safe_commands_public(commands)
                helpers_closed = (direct_call_attempts == len(commands.rows)
                    and result['directHelpers']['allOwnedCommandsStopped']
                    and result['directHelpers']['unknownCommandCount'] == 0)
        except BaseException as error:
            result['helperLedgerError'] = error_projection(error)
            helpers_closed = False
        result['signalRestoreErrors'] = restore_handlers(saved)
        result['pendingSignalAfterRestore'] = None if signals is None else signals.pending
        final_ns = time.monotonic_ns()
        result['deadlineMetAfterClosure'] = final_ns < PARENT_UNTIL_NS
        result['elapsedSeconds'] = (final_ns-PARENT_START_NS)/1000000000
        result['allReturnedApplicationFdsClosed'] = io_closed
        result['allDirectHelpersClosed'] = helpers_closed
        result['directHelperAttempts'] = direct_call_attempts
        result['directHelpersReturnedIntoLedger'] = 0 if commands is None else len(commands.rows)
        result['outcomeUnknown'] = bool(not io_closed or not helpers_closed
            or control is not None and control.unknown
            or result['signalRestoreErrors'] or result['pendingSignalAfterRestore'] is not None)
        result['ok'] = bool(result['observationComplete'] and not result['outcomeUnknown']
                            and result['deadlineMetAfterClosure'])
        final_raw = encoded(result)
        if len(final_raw) > 65536:
            raise SystemExit(1)
        sys.stdout.buffer.write(final_raw)
        sys.stdout.buffer.flush()
    raise SystemExit(0 if result['ok'] and time.monotonic_ns() < PARENT_UNTIL_NS else 1)

if __name__ == '__main__':
    main()
