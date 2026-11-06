    errors={}
    for label,p in reversed(children):
        try:stop_active(p)
        except BaseException as error:errors[label]=type(error).__name__
    rows=None;snapshot_error=None
    try:rows=process_snapshot() if children else []
    except BaseException as error:snapshot_error=type(error).__name__
    cleanup=[]
    for label,p in children:
        row={'label':label,'pid':p.pid,'exit_code':p.returncode,
             'direct_child_reaped':p.returncode is not None,
             'remaining':None if rows is None else [x for x in rows if x['pgid']==p.pid]}
        if label in errors:row['cleanup_error_type']=errors[label]
        if snapshot_error is not None:row['snapshot_error_type']=snapshot_error
        cleanup.append(row)
    result['commands']=commands;result['cleanup']=cleanup
    result['all_owned_stopped']=not errors and snapshot_error is None and all(
        row['direct_child_reaped'] and row['remaining']==[] for row in cleanup)
    result['within_original_deadline']=time.monotonic()<UNTIL
    result['elapsed_seconds']=time.monotonic()-START
    if pending_signal is not None or not result['all_owned_stopped'] or not result['within_original_deadline']:
        result['status']='failed';result['transfer_passed']=False
    result['success_requires_authoritative_exit_zero']=True
    result['success_requires_terminal_publication_within_original_deadline']=True
