def load_modules():
    for name,payload in MODULES.items():
        raw=base64.b64decode(payload['base64'],validate=True)
        need(len(raw)==payload['bytes'] and sha(raw)==payload['sha256'],'embedded_helper_whole')
        module=types.ModuleType(name);module.__file__='<fixed-public:'+name+'>'
        sys.modules[name]=module
        exec(compile(raw,module.__file__,'exec'),module.__dict__)
