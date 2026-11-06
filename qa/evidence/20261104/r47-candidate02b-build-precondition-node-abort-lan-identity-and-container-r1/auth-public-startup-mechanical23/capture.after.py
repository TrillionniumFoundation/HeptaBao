def run_owned_capture(argv, env, cwd, until, stdout_path, stderr_path, native_observer=None):
    global protected
    from mac_owned_unreaped_r1 import (require_waitid, capture_child,
        exit_observation, observed_returncode, stop_once_unreaped)
    from mac_native_process_observer_r1 import OwnedNativeObserver, ObservationRefused
    lifecycle = {'exitCode':None,'timeout':False,'interrupted':False,'primaryReaped':False,
                 'noGroupSurvivors':False,'outcomeUnknown':False,
                 'directChildRetainedUntilGroupCleanup':True}
    remaining(until);require_waitid()
    observer=None;row=None
    with critical():
        observer=OwnedNativeObserver(native_observer,critical=critical) if native_observer else None
        if observer is not None:observers.append(observer)
    if pending_signal is not None:raise Cancelled()
    child_env=dict(env)
    if observer:
        need(not any(k in child_env for k in observer.child_env),'fresh_observer_pipe_environment')
        child_env.update(observer.child_env)
    need(volume_guard is not None,'held_volume_before_child_output')
    with volume_guard.capture_sink(stdout_path, maximum=4096) as stdout, volume_guard.capture_sink(stderr_path, maximum=65536) as stderr:
        with critical():
            remaining(until)
            proc=subprocess.Popen(argv,env=child_env,cwd=str(cwd),start_new_session=True,
                stdout=stdout,stderr=stderr,close_fds=True,
                pass_fds=observer.child_fds if observer else ())
            row={'process':proc,'stopAttempted':False,'lifecycle':lifecycle,'custody':None,
                 'worker':True,'deliveredReport':False}
            owned.append(row)
        lifecycle['ownedProcessGroup']=proc.pid
        try:
            if observer:
                with critical():observer.parent_after_spawn(proc)
            row['custody']=capture_child(proc,until=until)
            lifecycle['actualDirectChildCustody']=row['custody']
            if pending_signal is not None:raise Cancelled()
            while True:
                if time.monotonic()>=until:
                    lifecycle['timeout']=True;break
                if observer:observer.poll(until)
                event=exit_observation(proc)
                if time.monotonic()>=until:
                    lifecycle['timeout']=True;break
                if event is not None:
                    lifecycle['exitCode']=observed_returncode(event)
                    lifecycle['retainedExit']=event
                    break
                remaining(until)
                time.sleep(min(0.025,remaining(until)))
        except (KeyboardInterrupt,Cancelled):lifecycle['interrupted']=True
        except BaseException as error:
            lifecycle['observationError']=str(error) if isinstance(error,ObservationRefused) else type(error).__name__
        finally:
            previous=signal.signal(signal.SIGINT,signal.SIG_IGN)
            previous_term=signal.signal(signal.SIGTERM,signal.SIG_IGN)
            try:
                if observer:
                    if not close_observer_once(observer):lifecycle['observerCloseError']='ObserverCloseFailed'
                    lifecycle['nativeProcessObserver']=observer.report
                row['stopAttempted']=True
                cleanup=stop_once_unreaped(proc,row['custody'])
                lifecycle['retainedChildCleanup']=cleanup
                lifecycle['primaryReaped']=cleanup.get('directChildReaped') is True
                lifecycle['finalReturnCode']=cleanup.get('exitCode')
                lifecycle['remainingGroupMembers']=cleanup.get('remainingGroupRows')
                lifecycle['noGroupSurvivors']=cleanup.get('allGroupRowsEmptyAfterReap') is True
                lifecycle['outcomeUnknown']=bool(lifecycle['timeout'] or lifecycle['interrupted']
                    or lifecycle.get('observationError') or lifecycle.get('observerCloseError')
                    or cleanup.get('outcomeUnknown') or not lifecycle['primaryReaped']
                    or not lifecycle['noGroupSurvivors'])
            finally:
                signal.signal(signal.SIGINT,previous);signal.signal(signal.SIGTERM,previous_term)
    return lifecycle
