def consumer_profile(phase,port,source_pins,ca_file,harness_roots,harness_bindings):
    need(phase in PHASES and type(port) is int and 1024<=port<=65535,'fixed_consumer_sandbox')
    root=ROOT/phase
    need(Path(ca_file)==ROOT/'credentials-consumer/ca.crt','only_owned_ca')
    # The exact installed code and the new phase are readable; production
    # current DB/config/auth/cache values and other phase/control roots are not.
    q=lambda value:json.dumps(str(value))
    lines=['(version 1)','(deny default)','(allow process*)',
        '(allow signal (target children))','(allow sysctl-read)','(allow mach-lookup)',
        '(allow file-read-metadata)']
    for path in ('/System','/usr','/bin','/sbin','/Library','/private/etc','/opt/homebrew','/dev/fd'):
        lines.append('(allow file-read* (subpath '+q(path)+'))')
    for path in (ROOT/'qa',ROOT/'installed-plugin-copy',root):
        lines.append('(allow file-read* (subpath '+q(path)+'))')
    # Installed immutable package roots are public code. Reading their package
    # modules is necessary for the real Node loader and its transitive imports.
    need(isinstance(harness_roots,list) and 1<=len(harness_roots)<=8
         and len(set(harness_roots))==len(harness_roots),'actual_finite_harness_root_set')
    need(isinstance(harness_bindings,list) and len(harness_bindings)==len(harness_roots)
         and all(isinstance(item,dict) for item in harness_bindings),
         'finite_admitted_harness_binding_list')
    by_root={item['rootDir']:item for item in harness_bindings}
    need(len(by_root)==len(harness_bindings) and set(by_root)==set(harness_roots),
         'exact_harness_roots_match_admitted_bindings')
    for value in sorted(set([str(CODEX),*harness_roots])):
        path=Path(value);binding=by_root.get(value)
        need(path.is_absolute() and path==Path(os.path.normpath(str(path))),
             'normalized_public_installed_harness_root')
        if path.is_relative_to(LIVE/'npm/projects'):
            need(binding is None if path==CODEX and value not in harness_roots
                 else binding is not None and binding.get('layout')=='npm',
                 'admitted_npm_harness_root')
        else:
            need(binding is not None and binding.get('layout')=='sdk-bundled'
                 and path.parent==SDK/'dist/extensions'
                 and path.name==binding.get('pluginId'),'exact_admitted_sdk_bundled_root')
            for field,name in (('manifest','openclaw.plugin.json'),('package','package.json')):
                metadata=binding.get(field)
                need(isinstance(metadata,dict) and metadata.get('path')==str(path/name)
                     and isinstance(metadata.get('sha256'),str)
                     and re.fullmatch('[0-9a-f]{64}',metadata['sha256'])
                     and source_pins.get(metadata['path'])==metadata['sha256'],
                     'bundled_root_has_whole_admitted_metadata')
            entries=binding.get('entries')
            need(isinstance(entries,list) and 1<=len(entries)<=8
                 and all(isinstance(item,dict) and isinstance(item.get('path'),str)
                         and Path(item['path']).is_absolute()
                         and Path(item['path'])==Path(os.path.normpath(item['path']))
                         and Path(item['path']).is_relative_to(path)
                         and isinstance(item.get('sha256'),str)
                         and re.fullmatch('[0-9a-f]{64}',item['sha256'])
                         and source_pins.get(item['path'])==item['sha256'] for item in entries),
                 'bundled_declared_entries_have_exact_source_pins')
        # SDK bundled code is already inside the original /opt/homebrew read
        # subtree; this does not add a new OS-readable private path.
        lines.append('(allow file-read* (subpath '+q(path)+'))')
    for path in sorted(source_pins):
        lines.append('(allow file-read* (literal '+q(path)+'))')
    for path in (ROOT/'credentials-consumer/ca.crt',
                 ROOT/'credentials-consumer/role_id',ROOT/'credentials-consumer/secret_id'):
        lines.append('(allow file-read* (literal '+q(path)+'))')
    lines.extend(['(allow file-read* (literal "/dev/urandom"))',
        '(allow file-read* (literal "/dev/random"))',
        '(allow file-write* (subpath '+q(root)+'))',
        '(allow file-write* (literal "/dev/null"))',
        '(allow network-outbound (remote ip '+q('localhost:'+str(port))+'))'])
    return ('\n'.join(lines)+'\n').encode()
