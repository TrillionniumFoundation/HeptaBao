def run_owned_capture(argv, env, cwd, timeout, stdout_path, stderr_path, native_observer=None):
    from authbus_native_login_custody import group_members
    from authbus_native_process_observer import OwnedNativeObserver, ObservationRefused
    lifecycle = {'exitCode': None, 'timeout': False, 'interrupted': False, 'primaryReaped': False,
                 'noGroupSurvivors': False, 'outcomeUnknown': False}
    observer = OwnedNativeObserver(native_observer) if native_observer else None
    child_env = dict(env)
    if observer:
        need(not any(k in child_env for k in observer.child_env), 'fresh_observer_pipe_environment')
        child_env.update(observer.child_env)
    with stdout_path.open('xb') as stdout, stderr_path.open('xb') as stderr:
        try:
            proc = subprocess.Popen(argv, env=child_env, cwd=str(cwd), start_new_session=True,
                stdout=stdout, stderr=stderr, close_fds=True,
                pass_fds=observer.child_fds if observer else ())
        except Exception:
            if observer: observer.close()
            raise
        pgid = proc.pid; lifecycle['ownedProcessGroup'] = pgid
        try:
            if observer: observer.parent_after_spawn(proc)
            deadline = time.monotonic() + timeout
            while True:
                if time.monotonic() >= deadline:
                    lifecycle['timeout'] = True
                    break
                if observer: observer.poll(deadline)
                returncode = proc.poll()
                if returncode is not None:
                    lifecycle['exitCode'] = returncode
                    break
                if time.monotonic() >= deadline:
                    lifecycle['timeout'] = True
                    break
                time.sleep(0.025)
        except KeyboardInterrupt: lifecycle['interrupted'] = True
        except Exception as observer_error:
            lifecycle['observationError'] = str(observer_error) if isinstance(observer_error, ObservationRefused) else type(observer_error).__name__
        finally:
            if observer:
                observer.close()
                lifecycle['nativeProcessObserver'] = observer.report
            previous = signal.signal(signal.SIGINT, signal.SIG_IGN)
            try:
                if group_members(pgid):
                    try: os.killpg(pgid, signal.SIGTERM)
                    except ProcessLookupError: pass
                    deadline = time.monotonic() + 1
                    while group_members(pgid) and time.monotonic() < deadline:
                        proc.poll(); time.sleep(0.05)
                    if group_members(pgid):
                        try: os.killpg(pgid, signal.SIGKILL)
                        except ProcessLookupError: pass
                proc.wait(timeout=5); lifecycle['primaryReaped'] = True
                lifecycle['finalReturnCode'] = proc.returncode
                deadline = time.monotonic() + 3
                remaining = group_members(pgid)
                while remaining and time.monotonic() < deadline:
                    time.sleep(0.05); remaining = group_members(pgid)
                lifecycle['remainingGroupMembers'] = remaining
                lifecycle['noGroupSurvivors'] = not remaining
                lifecycle['outcomeUnknown'] = lifecycle['timeout'] or lifecycle['interrupted'] or bool(remaining) or bool(lifecycle.get('observationError'))
            finally: signal.signal(signal.SIGINT, previous)
    return lifecycle

