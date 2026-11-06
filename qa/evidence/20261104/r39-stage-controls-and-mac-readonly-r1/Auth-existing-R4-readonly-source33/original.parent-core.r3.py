
PARENT_START_NS = time.monotonic_ns()
PARENT_UNTIL_NS = PARENT_START_NS + 45000000000
CHILD_UNTIL_NS = PARENT_START_NS + 25000000000
HELPER_ADMISSION_END_NS = PARENT_START_NS + 35000000000
OUTPUT_CAP = 131072
signals = None
controller_cleanup_mode = False
direct_call_attempts = 0

def remaining(*, cleanup=False):
    if not cleanup and not controller_cleanup_mode:
        need(signals is not None and signals.pending is None, 'controller_cancelled')
    left = (PARENT_UNTIL_NS-time.monotonic_ns())/1000000000
    need(left > 0, 'shared_45_second_deadline')
    return left

def load_helpers():
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
    from mac_t5_volume_guard_r1 import HeldT5
    from mac_native_process_observer_r1 import ProcessReader, BsdInfo
    return Signals, Commands, HeldT5, ProcessReader, BsdInfo

class ProbeControl:
    def __init__(self, io, commands, reader, info_type, plan, argv, pins):
        self.io, self.commands, self.reader, self.info_type = io, commands, reader, info_type
        self.plan, self.argv, self.pins = plan, list(argv), pins
        self.calls = 0
        self.prints = 0
        self.command_bytes = 0
        self.attempts = {}
        self.identity = None
        self.ready = None
        self.ready_raw = None
        self.registration_closed = False
        self.process_departed = False
        self.cleanup_attempted = False
        self.unknown = False
        self.last_state = None
        self.dispositions = []
        self.report = {'label':LABEL,'target':TARGET,'controllerIsParentOfManagedProbe':False,
            'managedProbeWaitOrReapCalled':False,'numericPidOrGroupSignalSent':False,
            'oldLabelReadOrChanged':False,'oldHistoricalLineageClosed':False,
            'bootstrapAttempted':False,'bootoutAttempted':False,
            'actualReadyIdentity':None,'sameBirthHandshake':False}

    def call(self, label, argv, *, seconds=10.0, cleanup=False, maximum=65536):
        global direct_call_attempts
        remaining(cleanup=cleanup)
        need(self.calls < 24 and self.command_bytes < 1048576, 'finite_helper_call_and_bytes')
        need(time.monotonic_ns() < HELPER_ADMISSION_END_NS, 'helper_cleanup_reserve')
        self.calls += 1
        until = min(HELPER_ADMISSION_END_NS/1000000000, time.monotonic()+seconds)
        with signals.critical():
            remaining(cleanup=cleanup)
            direct_call_attempts += 1
        try:
            row, out, err = self.commands.run(label, list(argv), until=until,
                allow_cancelled_cleanup=cleanup, maximum=maximum)
        except BaseException:
            self.unknown = True
            raise
        self.command_bytes += len(out)+len(err)
        if row['outcomeUnknown'] or not row['completeBeforeDeadline']:
            self.unknown = True
            raise ProbeRefused('direct_helper_outcome_unknown')
        need(self.command_bytes <= 1048576, 'all_helper_returned_byte_cap')
        remaining(cleanup=cleanup)
        return row, out, err

    def query(self, *, cleanup=False, expect_binding=True):
        need(self.prints < 18, 'finite_print_observations')
        number = self.prints
        self.prints += 1
        row, out, err = self.call('probe-print-%02d' % number,
            ['/bin/launchctl','print',TARGET], cleanup=cleanup)
        if missing_service(row['exitCode'], out, err):
            return None
        need(row['exitCode'] == 0 and not err, 'known_probe_print')
        value = parse_print(out, TARGET)
        if expect_binding:
            need(value.get('path') == str(PLIST) and value.get('program') == PYTHON
                 and value['arguments'] == self.argv and value.get('runs') in (0,1),
                 'exact_fresh_probe_registration')
        need(value.get('state') in ('running','not running'), 'fixed_known_probe_state')
        self.last_state = {k:value.get(k) for k in ('pid','state','runs','last exit code')}
        return value

    def check_inputs(self):
        self.io.check_all()
        for path in (CHILD, PLAN, PLIST):
            raw, _ = self.io.read(path, expected=self.pins[str(path)]['identity'])
            need(sha(raw) == self.pins[str(path)]['sha256'], 'registered_public_input_unchanged')

    def dispatch(self, operation, *, cleanup=False):
        need(operation in ('bootstrap','bootout') and operation not in self.attempts,
             'once_fresh_launchd_operation')
        self.check_inputs()
        argv = (['/bin/launchctl','bootstrap','gui/501',str(PLIST)] if operation == 'bootstrap'
                else ['/bin/launchctl','bootout',TARGET])
        with signals.critical():
            remaining(cleanup=cleanup)
            self.attempts[operation] = {'attempted':True,'knownZero':False}
            self.report[operation+'Attempted'] = True
        row, out, err = self.call('probe-'+operation, argv, cleanup=cleanup)
        self.attempts[operation].update(exitCode=row['exitCode'], knownZero=row['exitCode']==0,
            stdoutBytes=len(out),stderrBytes=len(err))
        need(row['exitCode'] == 0 and not out and not err, 'known_empty_launchd_mutation')

    def bind_ready(self):
        marker = self.io.present_marker(READY_MARK)
        if marker is None:
            return False
        raw, _ = self.io.read(READY)
        need(self.io.present_marker(READY_MARK) == marker, 'ready_marker_stable')
        value = json.loads(raw)
        need(set(value) == {'schema','generation','planSha256','sourceSha256','identity',
            'homeObject','initialChildren','t5AccessAttempted'}, 'exact_ready_keys')
        need(value['schema'] == 'heptabao.public-launchd-home-t5-ready.r1'
             and value['generation'] == self.plan['generation']
             and value['planSha256'] == self.pins[str(PLAN)]['sha256']
             and value['sourceSha256'] == CHILD_SHA
             and value['homeObject'] == self.plan['homeObject']
             and value['initialChildren'] == [] and value['t5AccessAttempted'] is False,
             'ready_exact_public_bindings')
        actual = validate_process(value['identity'])
        state = self.query()
        need(state is not None and state.get('pid') == actual['pid']
             and state.get('runs') == 1 and state.get('state') == 'running',
             'ready_same_launchd_pid')
        need(self.reader.read(actual['pid']) == actual
             and actual['pid'] != self.plan['controllerIdentity']['pid']
             and actual['ppid'] != self.plan['controllerIdentity']['pid']
             and self.reader.children(actual['pid']) == [], 'ready_actual_same_birth')
        self.identity, self.ready, self.ready_raw = actual, value, raw
        self.report['actualReadyIdentity'] = dict(actual)
        return True

    def admit(self):
        need(self.identity is not None and 'bootstrap' in self.attempts,
             'observed_ready_before_admission')
        state = self.query()
        need(state is not None and state.get('pid') == self.identity['pid']
             and self.reader.read(self.identity['pid']) == self.identity,
             'second_same_birth_before_admission')
        value = {'schema':'heptabao.public-launchd-home-t5-admission.r1',
            'generation':self.plan['generation'],'planSha256':self.pins[str(PLAN)]['sha256'],
            'identity':self.identity,'target':TARGET,'readySha256':sha(self.ready_raw)}
        self.io.write(ADMISSION, encoded(value))
        self.io.write(ADMISSION_MARK, b'')
        self.report['sameBirthHandshake'] = True

    def wait_ready(self):
        for _ in range(120):
            remaining()
            need(time.monotonic_ns() < CHILD_UNTIL_NS, 'ready_inside_child_deadline')
            if self.bind_ready():
                return
            time.sleep(min(0.1, remaining()))
        raise ProbeRefused('ready_observation_count_exhausted')

    def wait_inactive(self):
        for _ in range(10):
            remaining()
            state = self.query()
            need(state is not None, 'no_unexplained_label_disappearance')
            if state.get('pid') is None:
                need(state.get('state') == 'not running' and state.get('runs') == 1
                     and state.get('last exit code') in (0,1,78), 'known_inactive_probe_exit')
                return
            need(self.identity is not None and state['pid'] == self.identity['pid'],
                 'same_label_pid_observation_until_exit')
            time.sleep(min(0.1,remaining()))
        raise ProbeRefused('inactive_observation_count_exhausted')

    def pid_disposition(self, ordinal):
        need(self.identity is not None, 'observed_identity_before_pid_check')
        pid = self.identity['pid']
        row, out, err = self.call('probe-departure-%d' % ordinal,
            ['/bin/ps','-p',str(pid),'-o','pid=,ppid=,pgid=,uid=,stat='],
            seconds=4.0, cleanup=True, maximum=4096)
        need(not err, 'exact_pid_projection_stderr_empty')
        if row['exitCode'] == 1 and not out.strip():
            result = {'observation':ordinal,'kind':'absent','originalPid':pid,
                      'reapedByController':False}
        else:
            need(row['exitCode'] == 0, 'known_pid_projection')
            lines = out.decode('ascii','strict').splitlines()
            need(len(lines) == 1, 'one_observed_pid_row')
            fields = lines[0].split()
            need(len(fields) == 5 and all(re.fullmatch(r'[0-9]{1,10}',v) for v in fields[:4])
                 and int(fields[0]) == pid, 'numeric_observed_pid_projection')
            snapshots = []
            for _ in range(2):
                remaining(cleanup=True)
                info = self.info_type()
                n = self.reader.lib.proc_pidinfo(pid,3,0,ctypes.byref(info),ctypes.sizeof(info))
                need(n == ctypes.sizeof(info) and info.pid == pid, 'complete_reuse_birth')
                snapshots.append((info.pid,info.ppid,info.pgid,info.uid,info.birth_sec,info.birth_usec))
                remaining(cleanup=True)
            need(snapshots[0] == snapshots[1]
                 and snapshots[0][4:] != (self.identity['birthSec'],self.identity['birthUsec']),
                 'original_birth_still_present_or_reuse_unproven')
            result = {'observation':ordinal,'kind':'reused_different_birth','originalPid':pid,
                'currentBirthSec':snapshots[0][4],'currentBirthUsec':snapshots[0][5],
                'reapedByController':False,'newProcessNotOwnedOrSignalled':True}
        self.dispositions.append(result)

    def cleanup_once(self):
        if self.cleanup_attempted:
            return
        self.cleanup_attempted = True
        if 'bootstrap' not in self.attempts:
            self.registration_closed = True
            return
        need(not self.unknown, 'no_cleanup_dispatch_after_helper_unknown')
        self.check_inputs()
        state = self.query(cleanup=True)
        need(state is not None, 'no_unexplained_registration_disappearance')
        pid = state.get('pid')
        if pid is not None:
            if self.identity is None:
                # No guess that an unobserved Python process is our probe.
                # Its original absolute 25s deadline is allowed to elapse; no new budget.
                while time.monotonic_ns() < CHILD_UNTIL_NS:
                    remaining(cleanup=True)
                    time.sleep(max(0,min(0.25, (CHILD_UNTIL_NS-time.monotonic_ns())/1000000000)))
                state = self.query(cleanup=True)
                need(state is not None and state.get('pid') is None,
                     'unobserved_active_managed_probe_no_bootout')
            else:
                need(pid == self.identity['pid'] and self.reader.read(pid) == self.identity,
                     'cleanup_first_actual_same_birth')
                again = self.query(cleanup=True)
                need(again is not None, 'cleanup_registration_still_present')
                if again.get('pid') is not None:
                    need(again['pid'] == pid and self.reader.read(pid) == self.identity,
                         'cleanup_second_actual_same_birth')
                state = again
        if state.get('pid') is None:
            need(state.get('runs') in (0,1) and state.get('state') == 'not running',
                 'cleanup_exact_inactive_registration')
        self.dispatch('bootout', cleanup=True)
        need(self.query(cleanup=True) is None, 'fresh_registration_absent_after_bootout')
        self.registration_closed = True
        if self.identity is not None:
            self.pid_disposition(1)
            need(self.query(cleanup=True) is None, 'label_still_absent_before_second_pid_check')
            self.pid_disposition(2)
            self.process_departed = True

    def public(self):
        return dict(self.report, attempts=dict(self.attempts), lastState=self.last_state,
            registrationClosed=self.registration_closed, managedProbeProcessDepartureObserved=self.process_departed,
            pidDispositions=list(self.dispositions), helperCalls=self.calls, printCalls=self.prints,
            helperReturnedBytes=self.command_bytes, cleanupAttempted=self.cleanup_attempted,
            controlOutcomeUnknown=self.unknown, descendantReapingNotClaimed=True)


def validate_child_io(value):
    need(isinstance(value,dict) and set(value) == {'fdRows','allClosed','openLedger','counts','caps',
        'createdDirectories','directoryAttempts','interpreterAndDynamicLoaderInternalFdsNotEnumerated'},
        'child_io_schema')
    need(value['createdDirectories'] == [] and value['directoryAttempts'] == []
         and value['interpreterAndDynamicLoaderInternalFdsNotEnumerated'] is True,
         'child_io_no_directory_creation')
    need(value['caps'] == {'fdRows':64,'metadata':4096,'readCalls':256,'writeCalls':64,
         'readBytes':131072,'writeBytes':16384}, 'child_exact_io_caps')
    limits = {'metadata':4096,'readCalls':256,'readBytes':131072,'writeCalls':64,'writeBytes':16384}
    need(isinstance(value['counts'],dict) and set(value['counts']) == set(limits)
         and all(type(v) is int and 0 <= v <= limits[k] for k,v in value['counts'].items()),
         'child_actual_io_counts')
    ledger = value['openLedger']
    need(isinstance(ledger,dict) and set(ledger) == {'attempts','knownNoReturnErrors',
         'registered','pending','registrationUnknown'}, 'child_open_ledger_schema')
    need(all(type(ledger[k]) is int and 0 <= ledger[k] <= 64 for k in
         ('attempts','knownNoReturnErrors','registered','pending'))
         and ledger['registrationUnknown'] is False and ledger['pending'] == 0
         and ledger['attempts'] == ledger['knownNoReturnErrors'] + ledger['registered']
         and ledger['registered'] == len(value['fdRows']) and value['allClosed'] is True,
         'child_open_ledger_complete')
    rows = value['fdRows']
    need(isinstance(rows,list) and 1 <= len(rows) <= 64, 'child_fd_row_count')
    file_paths = {str(p) for p in (CHILD,PLAN,READY,READY_MARK,ADMISSION,ADMISSION_MARK,
                                  PUBLIC_SENTINEL,Path(PYTHON))}
    dir_paths = {str(p) for p in (Path('/'),Path('/Users'),HOME_PARENT,HOME,
                                 Path('/Volumes'),Path('/Volumes/T5'),T5_PARENT,WORK)}
    dir_paths.update(str(p) for p in PYTHON_PATHS)
    for i,row in enumerate(rows):
        need(isinstance(row,dict) and set(row) == {'ordinal','path','role','closeAttempted',
             'closed','closeError','created','writeComplete'} and type(row['ordinal']) is int and row['ordinal'] == i
             and row['role'] in ('file','directory') and row['closeAttempted'] is True
             and row['closed'] is True and row['closeError'] is None, 'child_each_fd_closed')
        need(row['path'] in (file_paths if row['role'] == 'file' else dir_paths),
             'child_each_fd_fixed_path')
        need(type(row['created']) is bool and type(row['writeComplete']) is bool
             and (not row['created'] or row['path'] in (str(READY),str(READY_MARK))),
             'child_fixed_creations_only')
        need(not row['created'] or row['writeComplete'], 'child_created_file_completed')
    return value

def validate_child_terminal(raw, expected_identity):
    value = json.loads(raw)
    required = {'schema','ok','stage','identity','readyPublished','sameBirthAdmission',
        'enteredT5','sentinelMatched','explicitApplicationChildrenCreated','sdkOrCredentialRead',
        'launchdOwnsThisProcess','controllerDirectChild','parentReapedThisProcess','newFixedPathsOnly',
        'io','signalRestoreErrors','pendingSignalAfterRestore','deadlineMetAfterClosure','elapsedSeconds',
        'allReturnedApplicationFdsClosed','outcomeUnknown'}
    allowed = required | {'error','sentinelBytes','sentinelSha256','sentinelFull9'}
    need(isinstance(value,dict) and required <= set(value) <= allowed, 'child_terminal_closed_schema')
    need(value['schema'] == 'heptabao.public-launchd-home-t5-probe.child.r1'
         and value['identity'] == expected_identity and value['readyPublished'] is True
         and value['launchdOwnsThisProcess'] is True and value['controllerDirectChild'] is False
         and value['parentReapedThisProcess'] is False and value['newFixedPathsOnly'] is True
         and value['explicitApplicationChildrenCreated'] == 0 and value['sdkOrCredentialRead'] is False,
         'child_terminal_same_instance')
    need(value['stage'] in ('home_plan','home_identity','home_admission','t5_open_ancestors',
         't5_chdir','t5_sentinel_read','complete','entry'), 'child_terminal_fixed_stage')
    need(all(type(value[k]) is bool for k in ('ok','sameBirthAdmission','enteredT5',
         'sentinelMatched','deadlineMetAfterClosure','allReturnedApplicationFdsClosed','outcomeUnknown')),
         'child_terminal_boolean_types')
    validated_io = validate_child_io(value['io'])
    need(value['allReturnedApplicationFdsClosed'] and validated_io['allClosed']
         and value['signalRestoreErrors'] == [] and value['pendingSignalAfterRestore'] is None
         and value['outcomeUnknown'] is False, 'child_reported_known_closure')
    if 'error' in value:
        need(isinstance(value['error'],dict) and set(value['error']) == {'type','code','errno'}
             and value['error']['type'] in PUBLIC_ERROR_TYPES
             and (value['error']['code'] is None or value['error']['code'] in PUBLIC_ERROR_CODES)
             and (value['error']['errno'] is None or type(value['error']['errno']) is int
                  and 0 <= value['error']['errno'] <= 4096), 'child_fixed_error_projection')
    if value['ok']:
        need(value['stage'] == 'complete' and value['sameBirthAdmission']
             and value['enteredT5'] and value['sentinelMatched']
             and value['deadlineMetAfterClosure'] and value.get('sentinelBytes') == len(SENTINEL)
             and value.get('sentinelSha256') == sha(SENTINEL), 'child_actual_sentinel_success')
    # Do not export the child's arbitrary JSON subtree. Return only these typed fields.
    return {k:value[k] for k in ('ok','stage','identity','readyPublished','sameBirthAdmission',
        'enteredT5','sentinelMatched','deadlineMetAfterClosure','allReturnedApplicationFdsClosed',
        'outcomeUnknown')} | {'error':value.get('error'),'io':validated_io}

def main():
    global signals, controller_cleanup_mode, direct_call_attempts
    io = None
    guard = None
    guard_init_started = False
    guard_init_complete = False
    commands = None
    control = None
    saved = {}
    stage = 'entry'
    result = {'schema':'heptabao.public-launchd-home-t5-context.controller.r1',
        'ok':False,'observationComplete':False,'executionSucceeded':False,'outcomeUnknown':False,
        'oldWorkerRootOrLabelTouched':False,'oldHistoricalUnknownPreserved':True,
        'oldStartupCauseQualified':False,'sdkOrCredentialRead':False,
        'productServerOrConsumerStarted':False,'productionChanged':False,
        'sharedSeconds':45,'outerSeconds':60,'childAbsoluteWindowSeconds':25,
        'commandAdmissionEndsAtSecond':35,'originalDirectHelperStopCaps':{'term':1,'wait':5,'group':3,'ps':4},
        'homeRoot':str(HOME),'newT5WorkRoot':str(WORK),'newLabel':LABEL,
        'environmentContrastOnly':True,'noNumericPidOrGroupSignalsForManagedProbe':True,
        'interpreterAndLibraryInternalFdsNotEnumerated':True}
    try:
        need(sys.platform == 'darwin' and os.getuid() == os.geteuid() == 501
             and sys.executable == PYTHON, 'controller_exact_platform_python')
        Signals, Commands, HeldT5, ProcessReader, BsdInfo = load_helpers()
        signals = Signals()
        saved = {s:signal.getsignal(s) for s in (signal.SIGTERM,signal.SIGINT)}
        signals.install()
        io = FixedIO(signals, remaining, read_cap=262144, write_cap=131072)
        commands = Commands(signals)
        reader = ProcessReader()
        controller_identity = validate_process(reader.read(os.getpid()))
        stage = 'fixed_python'
        raw, _ = io.read(Path(PYTHON), expected=PYTHON_ID)
        need(sha(raw) == PYTHON_SHA, 'controller_actual_regular_python_whole')
        stage = 't5_anchor'
        guard_init_started = True
        guard = HeldT5.__new__(HeldT5)
        guard.__init__(base64.b64decode(ANCHOR_BASE64,validate=True), ANCHOR_SHA,
                       remaining, signals.critical)
        guard_init_complete = True
        # Use the unchanged guard only for its anchored volume/UUID checks.
        # All new paths use the explicit FixedIO allowlist, not a changed guard ROOT.
        with signals.critical():
            remaining()
            direct_call_attempts += 1
        row, out, err = commands.run('probe-t5-uuid',
            ['/usr/sbin/diskutil','info','-plist','/Volumes/T5'],
            until=min(CHILD_UNTIL_NS/1000000000,time.monotonic()+30.0),maximum=262144)
        need(not row['outcomeUnknown'] and row['completeBeforeDeadline']
             and row['exitCode'] == 0 and not err, 'known_actual_t5_uuid_command')
        guard.accept_diskutil(out)
        io.open_dir(Path('/Volumes/T5'),full9=ANCHOR_FULL9['/Volumes/T5'])
        io.open_dir(T5_PARENT)
        io.open_dir(HOME_PARENT)
        io.absent(HOME)
        io.absent(WORK)
        # Exact label absence is required before any new directory creation.
        temporary = ProbeControl(io,commands,reader,BsdInfo,{},[],{})
        need(temporary.query(expect_binding=False) is None, 'fresh_label_initially_absent')
        stage = 'create_public_roots'
        home = io.mkdir(HOME)
        work = io.mkdir(WORK)
        sentinel_pin = io.write(PUBLIC_SENTINEL,SENTINEL)
        sentinel, _ = io.read(PUBLIC_SENTINEL,expected=sentinel_pin['identity'])
        need(sentinel == SENTINEL, 'created_public_sentinel_exact')
        work_id = identity(io.meta(os.fstat,work['fd']))
        work['fullFence'] = work_id
        io.check_dir(work)
        need(work_id[0] == ANCHOR_FULL9['/Volumes/T5'][0], 'new_work_on_actual_t5')
        stage = 'create_public_control'
        child_raw = base64.b64decode(CHILD_BASE64,validate=True)
        need(len(child_raw) == CHILD_BYTES and sha(child_raw) == CHILD_SHA, 'child_source_payload')
        plan = {'schema':'heptabao.public-launchd-home-t5-plan.r1',
            'label':LABEL,'home':str(HOME),'work':str(WORK),'sourceSha256':CHILD_SHA,
            'homeObject':list(home['initial'][:5]),'workFull9':list(work_id),
            'sentinelFull9':sentinel_pin['identity'],'sentinelSha256':sha(SENTINEL),
            'childUntilNs':CHILD_UNTIL_NS,'controllerUntilNs':PARENT_UNTIL_NS,
            'controllerIdentity':controller_identity}
        plan['generation'] = sha(encoded(plan))
        plan_raw = encoded(plan)
        argv = [PYTHON,'-I','-S','-B',str(CHILD),'--plan',str(PLAN),'--plan-sha256',sha(plan_raw)]
        expected_plist = {'Label':LABEL,'ProgramArguments':argv,'RunAtLoad':True,'KeepAlive':False,
            'AbandonProcessGroup':False,'ProcessType':'Background','ExitTimeOut':10,'Umask':0o077,
            'WorkingDirectory':str(HOME),'StandardOutPath':str(STDOUT),'StandardErrorPath':str(STDERR),
            'EnvironmentVariables':{'PATH':'/opt/homebrew/bin:/usr/bin:/bin:/usr/sbin:/sbin',
                                    'LANG':'C','LC_ALL':'C'}}
        plist_raw = plistlib.dumps(expected_plist,fmt=plistlib.FMT_XML,sort_keys=True)
        pins = {str(path):io.write(path,data) for path,data in
                ((CHILD,child_raw),(PLAN,plan_raw),(PLIST,plist_raw),(STDOUT,b''),(STDERR,b''))}
        need(time.monotonic_ns() < CHILD_UNTIL_NS, 'source_ready_before_child_window')
        control = ProbeControl(io,commands,reader,BsdInfo,plan,argv,pins)
        control.calls = temporary.calls + 1  # Include the owned diskutil command.
        control.prints = temporary.prints
        control.command_bytes = temporary.command_bytes + len(out)+len(err)
        result['createdPublicFiles'] = list(pins.values()) + [sentinel_pin]
        result['newWorkFull9'] = list(work_id)
        result['exactProgramArguments'] = argv
        result['programArgumentsCount'] = len(argv)
        result['publicPlanSha256'] = sha(plan_raw)
        stage = 'bootstrap_new_probe'
        guard.check()
        control.dispatch('bootstrap')
        stage = 'home_ready'
        control.wait_ready()
        stage = 'same_birth_admission'
        control.admit()
        stage = 'await_managed_exit'
        control.wait_inactive()
    except BaseException as error:
        result['error'] = error_projection(error)
    finally:
        controller_cleanup_mode = True
        result['lastControllerStage'] = stage
        if control is not None:
            try:
                with signals.critical():
                    control.cleanup_once()
            except BaseException as error:
                result['cleanupError'] = error_projection(error)
            result['managedProbe'] = control.public()
            if control.registration_closed and control.process_departed and control.identity is not None:
                try:
                    raw, stdout_id = io.read(STDOUT)
                    stderr, stderr_id = io.read(STDERR)
                    result['managedStdoutBytes'] = len(raw)
                    result['managedStderrBytes'] = len(stderr)
                    result['managedStdoutFull9'] = stdout_id
                    result['managedStderrFull9'] = stderr_id
                    need(not stderr and raw.endswith(b'\n') and raw.count(b'\n') == 1,
                         'one_public_managed_terminal_empty_stderr')
                    terminal = validate_child_terminal(raw,control.identity)
                    need(control.last_state is not None and
                         control.last_state.get('last exit code') == (0 if terminal['ok'] else 1),
                         'launchd_exit_matches_public_terminal')
                    result['childObservation'] = terminal
                    result['observationComplete'] = True
                    result['executionSucceeded'] = terminal['ok']
                    control.check_inputs()
                except BaseException as error:
                    result['terminalObservationError'] = error_projection(error)
        if guard is not None and hasattr(guard,'rows'):
            try:
                with signals.critical():
                    guard.close()
            except BaseException as error:
                result['volumeCloseError'] = error_projection(error)
            result['volumeGuard'] = guard.public_state()
            result['volumeGuardFdRows'] = [
                {'ordinal':i,'closeAttempted':r['close_attempted'],'closed':r['closed']}
                for i,r in enumerate(guard.rows)]
        if io is not None:
            io.close()
            result['controllerIo'] = io.public()
        if commands is not None:
            result['directOwnedHelpers'] = commands.public()
        restore_errors = restore_handlers(saved)
        result['signalRestoreErrors'] = restore_errors
        result['pendingSignalAfterRestore'] = None if signals is None else signals.pending
        helpers = result.get('directOwnedHelpers')
        helpers_closed = (direct_call_attempts == 0 if commands is None else
            direct_call_attempts == len(commands.rows) and helpers['allOwnedCommandsStopped']
            and helpers['unknownCommandCount'] == 0)
        result['directHelperAttempts'] = direct_call_attempts
        result['directHelpersReturnedIntoLedger'] = 0 if commands is None else len(commands.rows)
        io_closed = io is None or io.public()['allClosed']
        volume_closed = (not guard_init_started or (guard_init_complete
            and guard is not None and hasattr(guard,'rows')
            and all(r['closed'] for r in guard.rows) and not guard.close_errors))
        registration_closed = control is None or control.registration_closed
        managed_closed = control is None or 'bootstrap' not in control.attempts or control.process_departed
        final_ns = time.monotonic_ns()
        result['volumeGuardInitStarted'] = guard_init_started
        result['volumeGuardInitComplete'] = guard_init_complete
        result['allDirectHelpersClosed'] = helpers_closed
        result['allReturnedControllerFdsClosed'] = io_closed and volume_closed
        volume_good = (guard_init_complete and guard is not None and hasattr(guard,'rows')
            and result.get('volumeGuard',{}).get('volumeUUIDVerified') is True
            and result.get('volumeGuard',{}).get('lastAnchorCheckPassed') is True)
        result['finalVolumeAnchorAndUuidVerified'] = volume_good
        result['newRegistrationAttempted'] = control is not None and 'bootstrap' in control.attempts
        result['newRegistrationClosed'] = registration_closed if result['newRegistrationAttempted'] else None
        result['managedProbeProcessClosed'] = (control.process_departed if control is not None
            and control.identity is not None else None)
        result['managedClosureSatisfiedForThisAttempt'] = managed_closed
        result['deadlineMetAfterClosure'] = final_ns < PARENT_UNTIL_NS
        result['elapsedSeconds'] = (final_ns-PARENT_START_NS)/1000000000
        result['outcomeUnknown'] = bool(not helpers_closed or not io_closed or not volume_closed
            or not registration_closed or not managed_closed or restore_errors
            or (result['newRegistrationAttempted'] and not result['observationComplete'])
            or (signals is not None and signals.pending is not None))
        result['ok'] = bool(result['observationComplete'] and not result['outcomeUnknown']
            and result['deadlineMetAfterClosure'] and volume_good and 'error' not in result
            and 'cleanupError' not in result and 'terminalObservationError' not in result)
        raw = encoded(result)
        if len(raw) > OUTPUT_CAP:
            raise SystemExit(1)
        sys.stdout.buffer.write(raw)
        sys.stdout.buffer.flush()
    raise SystemExit(0 if result['ok'] and time.monotonic_ns() < PARENT_UNTIL_NS else 1)

if __name__ == '__main__':
    main()
