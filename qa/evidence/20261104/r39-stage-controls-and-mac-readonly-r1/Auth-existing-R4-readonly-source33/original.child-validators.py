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

