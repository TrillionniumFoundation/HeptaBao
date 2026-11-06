
function verifyCurrentRegistrationReadonlySource(I) {
 const checks=[];
 const check=(name,value)=>{checks.push({name,passed:value===true});if(value!==true)throw new Error(name);};
 const old=I.before,source=I.after;
 function method(s,name){const a=s.indexOf('    def '+name+'(');if(a<0)throw Error('method '+name);const b=s.indexOf('\n    def ',a+1);return s.slice(a,b<0?s.length:b).trimEnd();}
 function block(s,a,b){const i=s.indexOf(a),j=s.indexOf(b,i+1);if(i<0||j<0)throw Error('block');return s.slice(i,j);}
 check('candidate exact pin',JSON.stringify(gitBlobMeta(source))===JSON.stringify(I.sourcePin));
 check('exact stdin request',I.request.stdin===source);
 check('exact regular interpreter',I.request.executable===I.constants.python);
 check('fixed Python stdin argv',JSON.stringify(I.request.args)===JSON.stringify(['-I','-S','-B','-']));
 check('fixed user cwd',I.request.cwd==='/Users/qianqi');
 check('outer60',I.request.timeout_seconds===60);
 check('host mac',I.request.host==='mac');
 check('source-key binding',I.request.idempotency_key==='heptabao-mac-current-home-registration-'+I.sourcePin.sha256.slice(0,8)+'-20261106-r1');
 check('current original parser byte exact',block(source,'def parse_print','def missing_service')===I.currentParser);
 const parserCodes=Array.from(I.currentParser.matchAll(/,\s*'([a-z][a-z0-9_]+)'\s*\)/g),m=>m[1]);
 for(const code of parserCodes)check('parser error allowlist '+code,source.includes('"'+code+'"'));
 check('only old EX_CONFIG normalization retained',I.currentParser.includes("typed_value=='78: EX_CONFIG'")&&!I.currentParser.includes('(never exited)'));
 check('diagnostic-only never-exited equality',source.includes("single == '(never exited)'"));
 check('numeric rejected-field projection',source.includes("result['rejectedFixedIntegerFields']"));
 check('fixed same registration before public prefix',source.includes("'diagnostic_same_current_registration_source'")&&source.indexOf("all(first['projection']['fixedRegistrationFieldsMatch'].values())")<source.indexOf("first_lf,details = io.first_public_lf()"));
 const oi=block(old,'class FixedIO:','def restore_handlers'),ni=block(source,'class FixedIO:','def restore_handlers');
 for(const n of ['meta','open_fd','close_one','check_dir','check_all','close','public'])
    check('unchanged IO method '+n,method(oi,n)===method(ni,n));
 check('pending before open',ni.indexOf("ledger['pending'] += 1")<ni.indexOf("fd = os.open"));
 check('returned registration exception unknown',ni.includes("ledger['registrationUnknown'] = True"));
 check('close loop critical',method(ni,'close').includes('with self.signals.critical():'));
 check('no IO write method',!ni.includes('    def write('));
 check('no IO mkdir method',!ni.includes('    def mkdir('));
 check('zero write cap and methods',ni.includes('self.max_writes = 0')&&source.includes('read_cap=262144,write_cap=0')&&!source.includes('os.write(')&&!source.includes('os.mkdir('));
 check('whole private stdio blocked',ni.includes("need(path not in (STDOUT,STDERR), 'whole_private_stdio_forbidden')"));
 check('prefix read same FD',ni.includes("os.pread(row['fd'],want,0)")&&ni.includes("read_at_zero(len(raw)) == raw"));
 check('prefix first LF bound',ni.includes("read_at_zero(min(65536,first.st_size))")&&ni.includes("block.find(b'\\n')"));
 check('prefix first6 custody fence',ni.includes("identity(first)[:6] == identity(after)[:6] == identity(named)[:6]"));
 check('prefix append limits',ni.includes('first.st_size <= after.st_size <= named.st_size <= 2097152'));
 check('prefix no raw hash in result',!method(ni,'first_public_lf').includes('sha('));
 check('no tail stability claim',ni.includes("'unreadTailUnchangedClaimed':False"));
 check('fixed T5 device',ni.includes("str(info.st_dev) == EXPECTED_VOLUME_DEVICE")&&ni.includes("str(before.st_dev) == EXPECTED_VOLUME_DEVICE"));
 check('original Signals/Commands loader byte exact',block(source,'def load_readonly_helpers','def fixed_field_projection')===block(old,'def load_readonly_helpers','def fixed_field_projection'));
 const modules=JSON.parse(source.match(/MODULES = json\.loads\(r'''([\s\S]*?)'''\)/)[1]);
 check('only original two owned-command modules',modules.length===2);
 for(const m of modules){const raw=utf8Text(unb64(m.base64));check('module whole '+m.name,gitBlobMeta(raw).bytes===m.bytes&&gitBlobMeta(raw).sha256===m.sha256&&gitBlobMeta(raw).blob===m.blob);check('module current byte equality '+m.name,raw===I.currentModules[m.name]);}
 check('45s shared deadline',source.includes('PARENT_UNTIL_NS = PARENT_START_NS + 45000000000'));
 check('35s helper admission',source.includes('HELPER_ADMISSION_END_NS = PARENT_START_NS + 35000000000'));
 check('two fixed print calls',source.includes('self.calls < 2')&&source.includes('control.query(1)')&&source.includes('control.query(2)'));
 check('no direct PID helper or libproc introduced',!source.includes('def pid_observation')&&!source.includes('proc_pidinfo')&&!source.includes('import ctypes'));
 check('only exact launchctl print',source.includes("['/bin/launchctl','print',TARGET]")&&!/\['\/bin\/launchctl',\s*'(?:bootout|bootstrap|kill)'/.test(source));
 check('no managed signal or spawn APIs',!source.includes('os.kill(')&&!source.includes('os.execve(')&&!source.includes('subprocess.Popen'));
 check('no private capsule path',!source.includes('capsule.private')&&!source.includes('current-capture.private'));
 check('private plan only in exact argv string',source.match(/server-initial\.private\.json/g).length===2);
 check('closed wrapper-error codes',source.includes('WRAPPER_ERROR_CODES = frozenset(')&&source.includes("'errorCodeRecognized'"));
 check('13 boolean field allowlist',I.booleans.length===13);
 check('unknown keys not enumerated into output',!source.includes('list(value.keys())')&&!source.includes("'raw':"));
 check('candidate digest only equality output',source.includes("value.get('candidateReceiptSha256') == sha(exec_raw)"));
 check('candidate not terminal',source.includes("'pre_finally_candidate' if kind == 'exec-ready'"));
 check('first LF post-finally tag source-derived',source.includes("else 'post_finally_first_lf'"));
 check('restored handlers before final pending',source.indexOf("result['signalRestoreErrors'] = restore_handlers(saved)")<source.indexOf("result['pendingSignalAfterRestore']"));
 check('final deadline after close',source.indexOf('io.close()')<source.indexOf("final_ns = time.monotonic_ns()"));
 check('always preserve managed unknown',source.includes("'currentManagedScopeStillUnknown':True")&&source.includes("'registrationClosureClaimed':False"));
 check('two roots exact',source.includes('HOME = Path('+JSON.stringify(I.constants.home)+')')&&source.includes('WORK = Path('+JSON.stringify(I.constants.root)+')'));
 const input=JSON.parse(source.match(/INPUT_PINS = json\.loads\(r'''([\s\S]*?)'''\)/)[1]);
 check('three pinned controls',Object.keys(input).length===3);
 check('server wrapper original full9',JSON.stringify(input[I.constants.home+'/mac_current_server_owner_r1.py'])===JSON.stringify(I.constants.inputPins[I.constants.home+'/mac_current_server_owner_r1.py']));
 check('plist fresh-only inode explicit',input[I.constants.home+'/server-initial.plist'].identity===null);
 check('public plist reconstruction matches actual SHA',gitBlobMeta(I.plistRaw).sha256===input[I.constants.home+'/server-initial.plist'].sha256&&gitBlobMeta(I.plistRaw).bytes===3970);
 check('17 original argv reconstructed',I.constants.expectedArgv.length===17);
 check('exact HOME current full9',source.includes('HOME_FULL9 = json.loads(r\'\'\''+JSON.stringify(I.constants.homeFull9)+'\'\'\')'));
 check('new journal slot',I.journal.includes('const GF_SLOT = "owner_authbus_home_r2_registration_readonly_gitfirst_r1";'));
 const rebound=I.journal.replace('"owner_authbus_home_r2_registration_readonly_gitfirst_r1"','"owner_authbus_current_home_runtime_gitfirst_r2"').replace('const GF_REQUEST = {blob:"'+I.requestPin.blob+'",\n bytes:'+I.requestPin.bytes+',sha256:"'+I.requestPin.sha256+'"};','const GF_REQUEST = {blob:"0b9abcf80bc8bd27ced95abfb66bee3ebf837b32",\n bytes:8207,sha256:"a4fc7391b4b280b97ba06a0e71fd4951b1e282d3e5d89ae42c7519ad6505bbea"};').replace('^heptabao-mac-current-home-registration-'+I.sourcePin.sha256.slice(0,8)+'-','^heptabao-mac-current-home-launch-runtime-c67d6fe6-');
 check('journal only three literal bindings',rebound===I.oldJournal);
 check('strict source forward',strictApplySource(old,I.sourceDiff).raw===source);
 check('strict journal forward',strictApplySource(I.oldJournal,I.journalDiff).raw===I.journal);
 return {schema:'heptabao.current-home-r2-registration-readonly-static-checks.v1',passed:true,checkCount:checks.length,checks,scope:'Pure V8 byte/source/input verification only; Python not parsed or executed, no Native calls, no observed launchctl integer value and no runtime qualification.',NativeCalls:0,PythonExecution:false,sourcePin:I.sourcePin,requestPin:I.requestPin};
}
