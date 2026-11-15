try:
    os.umask(0o077)
    need(platform.node()=='alex-G1628-04' and platform.system()=='Linux'
         and platform.machine()=='x86_64' and os.getuid()==1000,'exact_pocket4_account')
    dirs={p:directory(p,private=True) for p in (ROOT,OUT,BASE)}
    need(not os.path.lexists(WORK),'new_qualification_directory')
    WORK.mkdir(mode=0o700);dirs[WORK]=directory(WORK,private=True)
    _,raw=file_pin(OUT/'preparation.result.public.json',
        (39110,'2b7dec111acdb1af091484328bbcae936839ed30ef33133a1056e6030bc619e2'),
        contents=True,maximum=65536)
    prepared=json.loads(raw)
    need(prepared['status']=='passed' and prepared['source_commit']==REPORT['source_commit']
         and prepared['source_tree']==REPORT['source_tree'] and prepared['source_clean'] is True,
         'exact_prepared_current_source')
    modules={}
    for name,pin in HELPERS.items():
        path=BASE/'qa/openbao-acceptance'/(name+'.py')
        _,raw=file_pin(path,pin,contents=True,maximum=65536)
        need(name not in sys.modules,'helper_not_preloaded')
        module=types.ModuleType(name);module.__file__=str(path);sys.modules[name]=module
        exec(compile(raw,str(path),'exec'),module.__dict__);modules[name]=module
    need(set(PACKET)=={'normal107_custody_bridge.py','qualify_normal107_custody_bridge.py','controller.py'},
         'exact_three_public_payloads')
    for name,item in PACKET.items():
        raw=item['source'].encode()
        need(len(raw)==item['bytes'] and hashlib.sha256(raw).hexdigest()==item['sha256']
             and len(raw)<65536,'exact_payload_bytes')
        if name=='controller.py':
            continue
        modname=name[:-3];need(modname not in sys.modules,'payload_not_preloaded')
        module=types.ModuleType(modname);module.__file__=str(WORK/name);sys.modules[modname]=module
        exec(compile(raw,module.__file__,'exec'),module.__dict__);modules[modname]=module
    REPORT['payload_pins']={n:{k:v for k,v in p.items() if k!='source'} for n,p in PACKET.items()}
    REPORT['helper_pins']={n:{'bytes':p[0],'sha256':p[1]} for n,p in HELPERS.items()}
    progress=io.StringIO();invoked=True
    try:
        with contextlib.redirect_stdout(progress):
            observation=modules['qualify_normal107_custody_bridge'].qualify(
                modules['normal107_custody_bridge'],modules['kv2_dr_process_custody'],
                PACKET['controller.py']['source'],WORK,outcomes)
    finally:
        REPORT['fixture_controller_stdout']=progress.getvalue();progress.close()
    REPORT['qualification']=observation
    for path,(pin,full9) in list(PUBLIC.items()):
        file_pin(path,pin);need(identity(path.lstat())==full9,'public_input_generation_changed')
    need(all(directory(path,private=True)==pin for path,pin in dirs.items()),'original_parent_identity_changed')
    need(observation['status']=='passed' and len(outcomes)==5
         and all(x['passed'] and x['observation']['originals_closed'] for x in outcomes),
         'all_five_real_cases_required')
    REPORT.update(status='passed',all_public_inputs_unchanged=True)
except BaseException as error:
    REPORT['failure']=str(error) if isinstance(error,Refused) else type(error).__name__
finally:
    for row in reversed(FDS):
        if row['attempts']==0:
            row['attempts']=1
            try:os.close(row['fd']);row['closed']=True
            except BaseException:REPORT['status']='failed'
    REPORT['remoteClosureUnknown']=bool(invoked and (len(outcomes)!=5 or any(
        x['observation']['remote_closure_unknown'] for x in outcomes)))
    REPORT['allDescriptorsClosedOnce']=all(r['attempts']==1 and r['closed'] for r in FDS)
    REPORT['descriptorCount']=len(FDS);REPORT['elapsedSeconds']=time.monotonic()-START
    if REPORT['remoteClosureUnknown'] or not REPORT['allDescriptorsClosedOnce'] or time.monotonic()>=END:
        REPORT['status']='failed'
    print(json.dumps(REPORT,sort_keys=True),flush=True)
raise SystemExit(0 if REPORT['status']=='passed' else 1)
