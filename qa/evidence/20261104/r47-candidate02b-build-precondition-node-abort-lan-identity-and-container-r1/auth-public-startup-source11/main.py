
def public_command(value):
    if not isinstance(value,dict):return None
    return {key:value.get(key) for key in ('label','argv','pid','exitCode',
        'completeBeforeDeadline','commandDeadlineMonotonic','elapsedSeconds','cleanup',
        'streamsClosed','outcomeUnknown','stdoutBytes','stderrBytes')}

def marker_projection(raw):
    need(isinstance(raw,bytes) and len(raw)<=4096,'bounded_public_marker_stream')
    try:text=raw.decode('ascii')
    except UnicodeError:
        return {'protocolValid':False,'unknownOutputPresent':True,'markers':[],
                'entryMarkerObserved':False,'complete':False}
    if text and not text.endswith('\n'):
        return {'protocolValid':False,'unknownOutputPresent':True,'markers':[],
                'entryMarkerObserved':False,'complete':False}
    lines=[] if not text else text[:-1].split('\n')
    allowed_failed={'failed-'+stage for stage in MARKERS}
    prefix=[];failure=None;valid=True
    for line in lines:
        if len(prefix)<len(MARKERS) and line==MARKERS[len(prefix)] and failure is None:
            prefix.append(line)
        elif line in allowed_failed and failure is None and prefix and line=='failed-'+prefix[-1]:
            failure=line
        else:valid=False;break
    if not valid:
        return {'protocolValid':False,'unknownOutputPresent':True,'markers':prefix,
                'entryMarkerObserved':bool(prefix),'complete':False}
    return {'protocolValid':True,'unknownOutputPresent':False,'markers':prefix,
            'entryMarkerObserved':bool(prefix),'complete':prefix==MARKERS and failure is None,
            'reportedFailureMarker':failure}

def load_modules():
    for name,payload in MODULES.items():
        raw=base64.b64decode(payload['base64'],validate=True)
        need(len(raw)==payload['bytes'] and sha(raw)==payload['sha256'],'embedded_helper_whole')
        module=types.ModuleType(name);module.__file__='<fixed-public:'+name+'>'
        sys.modules[name]=module
        exec(compile(raw,module.__file__,'exec'),module.__dict__)

def main():
    global volume_guard
    report={'schema':'heptabao.mac-public-node-startup-import-diagnostic.r1',
      'ok':False,'observationComplete':False,'executionSucceeded':False,'outcomeUnknown':False,
      'scope':str(ROOT),'originalRuntimeJob':'mac/1a1b1d28dc2-fc05-7afe',
      'historicalFailureReclassified':False,'historicalManagedClosureClaimed':False,
      'oldPrivateFileReadRequested':False,'credentialFileReadRequested':False,'providerCalled':False,
      'sdkImported':False,'casFunctionCalled':False,'applicationDatabaseMethodCalled':False,
      'launchdOperation':False,'oldPidOperation':False,'applicationNetworkCallDispatched':False,
      'foregroundOwnerDiffersFromOriginalLaunchdParent':True,
      'originalAbortCauseProved':False,'kernelImageOfAbortedChildProved':False,
      'sandboxPermissionsBroadened':False,'nodeCompatibilityFlagsAdded':False,
      'portPermissionIsNotReservationOrAvailabilityEvidence':True}
    saved={sig:signal.getsignal(sig) for sig in (signal.SIGTERM,signal.SIGINT)}
    signals=SignalFacade();io=None;commands=None
    guard_started=False;guard_complete=False;guard_pending=False
    command_pending=False;worker_pending=False;handlers_restored=False
    operations=0;readback_bytes=0;life=None
    try:
        for sig in saved:signal.signal(sig,interrupt)
        need(sys.platform=='darwin' and os.geteuid()==501 and sys.executable==PYTHON,
             'fixed_mac_python_operator')
        os.umask(0o077);load_modules()
        from mac_owned_commands_r1 import Commands
        from mac_t5_volume_guard_r1 import HeldT5
        commands=Commands(signals);io=InputAudit(signals)
        for path,pin in INPUT_PINS.items():io.admit(path,pin)
        io.alias()
        anchor=base64.b64decode(ANCHOR_BASE64,validate=True)
        guard_started=True;volume_guard=HeldT5.__new__(HeldT5)
        with critical():volume_guard.__init__(anchor,ANCHOR_SHA,remaining,critical)
        guard_complete=True
        command_pending=True
        disk,out,err=commands.run('startup-t5-volume',
            ['/usr/sbin/diskutil','info','-plist','/Volumes/T5'],
            until=min(UNTIL,time.monotonic()+4.0),maximum=262144)
        command_pending=False;report['volumeCommand']=public_command(disk)
        need(disk['exitCode']==0 and not disk['outcomeUnknown'] and not err,
             'actual_t5_volume_command_known_success')
        guard_pending=True;volume_guard.accept_diskutil(out);guard_pending=False
        # mkdir_new is exclusive; the first existing root refuses with no fallback.
        created=[]
        for path in DIRECTORIES:
            guard_pending=True
            created.append({'path':str(path),'identity':volume_guard.mkdir_new(path)})
            guard_pending=False;operations+=1
            need(len(volume_guard.rows)<=80,'fixed_guard_fd_total')
        report['createdDirectories']=created
        profile=consumer_profile('initial',63611,PUBLIC_SOURCE_PINS,
            str(ROOT/'credentials-consumer/ca.crt'),HARNESS_ROOTS,HARNESS_BINDINGS)
        need(sha(profile)==EXPECTED_PROFILE_SHA and len(profile)==6909,
             'unchanged_profile_semantic_derivation')
        files={ROOT/'qa/startup-imports.mjs':base64.b64decode(PUBLIC_FILES['marker'],validate=True),
               ROOT/'qa/mac_auth_rows_cas_r1.mjs':base64.b64decode(PUBLIC_FILES['rows'],validate=True),
               ROOT/'qa/mac_authbus_cache_cas_r1.mjs':base64.b64decode(PUBLIC_FILES['cache'],validate=True),
               ROOT/'initial/consumer.sb':profile}
        written=[]
        for path,raw in files.items():
            guard_pending=True;pin=volume_guard.write_new(path,raw);guard_pending=False;operations+=1
            written.append({'path':str(path),**pin})
            need(len(volume_guard.rows)<=80,'fixed_guard_fd_total')
        for path,raw in files.items():
            guard_pending=True;actual=volume_guard.read(path,len(raw),private=False)
            guard_pending=False;operations+=1;readback_bytes+=len(actual)
            need(actual==raw,'created_public_input_exact_readback')
        report['createdPublicFiles']=written
        io.verify();volume_guard.check()
        child_env={'PATH':'/opt/homebrew/bin:/usr/bin:/bin:/usr/sbin:/sbin',
          'HOME':str(ROOT/'initial/state/home'),'TMPDIR':str(ROOT/'initial/tmp'),
          'OPENCLAW_STATE_DIR':str(ROOT/'initial/state'),
          'OPENCLAW_CONFIG_PATH':str(ROOT/'initial/state/openclaw.json'),
          'OPENCLAW_OAUTH_DIR':str(ROOT/'initial/state/oauth'),
          'OPENCLAW_HOME':str(ROOT/'initial/state/home')}
        argv=['/usr/bin/sandbox-exec','-f',str(ROOT/'initial/consumer.sb'),NODE,
              str(ROOT/'qa/startup-imports.mjs')]
        report['argv']=argv;report['environment']=child_env
        report['cwd']=str(ROOT/'initial');report['profileSha256']=sha(profile)
        worker_pending=True;guard_pending=True
        life=run_owned_capture(argv,child_env,ROOT/'initial',
          min(UNTIL,time.monotonic()+10.0),ROOT/'initial/workers/startup.stdout.public',
          ROOT/'initial/workers/startup.stderr.public')
        guard_pending=False;worker_pending=False;operations+=2
        report['workerLifecycle']=life
        need(len(volume_guard.rows)<=80,'fixed_guard_fd_total')
        guard_pending=True
        stdout=volume_guard.read(ROOT/'initial/workers/startup.stdout.public',4096,private=False)
        guard_pending=False;operations+=1;readback_bytes+=len(stdout)
        guard_pending=True
        stderr=volume_guard.read(ROOT/'initial/workers/startup.stderr.public',65536,private=False)
        guard_pending=False;operations+=1;readback_bytes+=len(stderr)
        report['markers']=marker_projection(stdout)
        report['stdoutBytes']=len(stdout);report['stderrBytes']=len(stderr)
        report['stderrEmpty']=not stderr
        report['stderrContentOrHashExported']=False
        need(readback_bytes<=87547 and operations==21 and len(volume_guard.rows)<=80,
             'finite_public_output_readset_and_fd_bound')
        io.verify();volume_guard.check()
        report['allFixedInputsAfter']=True
        report['executionSucceeded']=bool(life.get('exitCode')==0
            and life.get('finalReturnCode')==0 and not life.get('outcomeUnknown')
            and report['markers']['protocolValid'] and report['markers']['complete'])
        report['observationComplete']=bool(not life.get('outcomeUnknown')
            and life.get('primaryReaped') is True and life.get('noGroupSurvivors') is True
            and report['markers']['protocolValid'])
    except BaseException as error:
        report['error']=error_projection(error)
    finally:
        with critical():
            # run_owned_capture owns its one once-only cleanup; never retry it here.
            if commands is not None:report['commands']={
                'commands':[public_command(x.get('public')) for x in commands.rows],
                'allOwnedCommandsStopped':commands.public()['allOwnedCommandsStopped'],
                'unknownCommandCount':commands.public()['unknownCommandCount']}
            if volume_guard is not None:
                try:volume_guard.close()
                except BaseException as error:report['guardCloseError']=error_projection(error)
                try:report['volume']=volume_guard.public_state()
                except BaseException:report['volumePublicUnavailable']=True
            if io is not None:io.close();report['inputs']=io.public()
            handlers_restored=True
            for sig,old in saved.items():
                try:signal.signal(sig,old)
                except BaseException:handlers_restored=False
        guard_closed=(guard_complete and not guard_pending and volume_guard is not None
            and report.get('volume',{}).get('allDescriptorsClosed') is True
            and not report.get('volume',{}).get('closeErrors')
            and report.get('volume',{}).get('lastAnchorCheckPassed') is True)
        inputs_closed=io is not None and report.get('inputs',{}).get('allReturnedInputFdsClosed') is True
        commands_closed=(commands is not None and not command_pending
            and commands.public()['allOwnedCommandsStopped'] and commands.public()['unknownCommandCount']==0)
        workers_closed=all(row.get('stopAttempted') is True
            and row.get('lifecycle',{}).get('primaryReaped') is True
            and row.get('lifecycle',{}).get('noGroupSurvivors') is True
            and not row.get('lifecycle',{}).get('outcomeUnknown') for row in owned)
        report['guardInitializationStarted']=guard_started
        report['guardInitializationCompleted']=guard_complete
        report['guardOperationPendingOrFailed']=guard_pending
        report['originalWorkerCleanupRepeated']=False
        report['returnedGuardFdCount']=len(getattr(volume_guard,'rows',[]))
        report['operations']=operations;report['publicReadbackBytes']=readback_bytes
        report['handlersRestored']=handlers_restored
        report['allOwnDescriptorsAndChildrenClosed']=bool(guard_closed and inputs_closed
            and commands_closed and workers_closed and not worker_pending and handlers_restored)
        report['pendingSignalObserved']=pending_signal is not None
        report['outcomeUnknown']=bool(pending_signal is not None or command_pending or worker_pending or guard_pending
            or (guard_started and not guard_complete) or not report['allOwnDescriptorsAndChildrenClosed'])
        report['elapsedSeconds']=time.monotonic()-START
        report['original45SecondDeadlineMetAfterClosure']=time.monotonic()<=FINAL_UNTIL
        report['observationComplete']=bool(report['observationComplete']
            and not report['outcomeUnknown'] and report['original45SecondDeadlineMetAfterClosure'])
        report['ok']=report['observationComplete']
        report['executionSucceeded']=bool(report['executionSucceeded'] and report['ok'])
    public=encoded(report)
    need(len(public)<=65536,'public_report_size_cap')
    print(public.decode(),end='',flush=True)
    return 0 if report['ok'] else 1

if __name__=='__main__':raise SystemExit(main())
