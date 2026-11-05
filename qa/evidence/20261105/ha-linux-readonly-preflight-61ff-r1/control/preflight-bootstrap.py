import hashlib,json,sys,time
began=time.monotonic()
started_unix_ns=time.time_ns()
try:
    raw=sys.stdin.buffer.read(262145)
    assert len(raw)<=262144,'preflight_packet_bound'
    assert hashlib.sha256(raw).hexdigest()=='4a9cf4612c3c5928d7c4ed6e47d5a46d40fe96db78a71d26683421d9487e2056','preflight_packet_hash'
    value=json.loads(raw)
    assert value['schema']=='heptabao.rog-readonly-preflight-input.v1','preflight_packet_schema'
    for key in ('preflight','guard','base_frozen'):
        assert hashlib.sha256(value[key+'_source'].encode()).hexdigest()==value[key+'_sha256'],'preflight_inner_hash'
    source=compile(value['preflight_source'],'<pinned-rog-readonly-preflight>','exec')
    compile(value['guard_source'],'<pinned-original-r6-guard>','exec')
    assert sys.argv[1:]==['observe'],'closed_readonly_operation'
    assert time.monotonic()<began+60,'preflight_input_deadline'
    scope={'__name__':'__main__','PREFLIGHT_INPUT':value,'PREFLIGHT_BEGAN':began,
           'PREFLIGHT_UNTIL':began+60,'PREFLIGHT_STARTED_UNIX_NS':started_unix_ns}
    exec(source,scope)
except Exception as error:
    print(json.dumps({'status':'readonly_preflight_refused','error_class':type(error).__name__,
        'error_code':str(error) if isinstance(error,AssertionError) else None,
        'execution_admitted':False,'product_started':False,'full_replacement_qualified':False},sort_keys=True),flush=True)
    raise SystemExit(2) from None
