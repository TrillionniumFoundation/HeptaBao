function makeJwtBuildRunner(before, groups, retainedCurrent) {
 const replacements=[];
 const replace=(oldText,newText,label)=>{if(before.split(oldText).length!==2)throw Error("nonunique "+label);replacements.push({label,before:oldText,after:newText});before=before.replace(oldText,newText);};
 replace('"""Build exact same-root publication source; retain 44/7/9 and add one real A-B-A regression."""','"""Build the separately admitted native JWT source and run 147 unique names in 162 profile instances."""',"purpose");
 replace("os.umask(0o077)\n","BINDING_READY = False\nassert BINDING_READY, 'formatter, final source and control publication require separate admission'\nos.umask(0o077)\n","inactive admission");
 const start=before.indexOf("DIAGNOSTIC_COMMIT = "),end=before.indexOf("children = []",start);
 replace(before.slice(start,end),"DIAGNOSTIC_COMMIT = None\nDIAGNOSTIC_TREE = None\n","final formatted identity unresolved");
 const priorEnd=before.indexOf("\n}\n\n\ndef preserve_prior_df026");
 if(priorEnd<0)throw Error("retained map boundary");
 const extra=Object.entries(retainedCurrent).map(([path,v])=>"    "+JSON.stringify(path)+": "+JSON.stringify(v)).join(",\n");
 const priorStart=before.indexOf("PRIOR_DF026_FILES = {");
 const oldMap=before.slice(priorStart,priorEnd+3);
 replace(oldMap,oldMap.slice(0,-3)+",\n"+extra+"\n}\n","six current retained fences");
 const gateStart=before.indexOf("assert args.groups_sha256 == "),gateEnd=before.indexOf("assert not output.exists()",gateStart);
 const groupsRaw=JSON.stringify(groups,null,2)+"\n";
 const groupHash=new Function(load("ha-jwt-journal-r2-pure-text")+"\nreturn gitBlobMeta(arguments[0]).sha256;")(groupsRaw);
 const gate=`assert args.groups_sha256 == '${groupHash}'
assert sha(args.groups) == args.groups_sha256
groups = json.loads(Path(args.groups).read_text())
EXPECTED_GROUP_SHAPES = [('native-jwt-file15', 'file', 15), ('native-jwt-default15', 'default', 15),
                         ('legacy-jwt-default63', 'default', 63), ('native-auth-identity-default69', 'default', 69)]
assert [(g['label'], g['libtest_profile'], len(g['tests'])) for g in groups] == EXPECTED_GROUP_SHAPES
all_names = []
for group in groups:
    assert set(group) == {'label', 'libtest_profile', 'tests', 'runtime_seconds'}
    assert group['runtime_seconds'] == 600 and group['libtest_profile'] in ('file', 'default')
    assert group['tests'] and len(group['tests']) == len(set(group['tests']))
    assert all(isinstance(n, str) and n for n in group['tests'])
    assert group['label'].replace('-', '').replace('_', '').isalnum()
    all_names.extend(group['tests'])
assert groups[0]['tests'] == groups[1]['tests'], 'same fifteen source names in both feature profiles'
assert len(all_names) == 162 and len(set(all_names)) == 147
assert len(set(groups[1]['tests'] + groups[2]['tests'] + groups[3]['tests'])) == 147
`;
 replace(before.slice(gateStart,gateEnd),gate,"exact four family source gate");
 const intentStart=before.indexOf("intent = {'schema': "),intentEnd=before.indexOf("write('intent.public.json', intent)",intentStart);
 const intent=`intent = {'schema': 'heptabao.native-jwt-r2-build-regression.v1', 'source_commit': args.commit,
          'source_tree': args.tree, 'normal_default_features': True, 'fixture_features': [],
          'profile': profile, 'groups': groups, 'test_count': 147,
          'groups_sha256': args.groups_sha256, 'controller_sha256': sha(__file__),
          'production_changed': False, 'started_ns': time.time_ns(),
          'selected_unique_test_total': 147, 'selected_profile_instance_total': 162,
          'new_unique_test_total': 15, 'existing_unique_test_total': 132,
          'actual_fixture_backend_for_new_tests': 'FileV6',
          'distributed_native_jwt_ha_qualified': False,
          'old_normal61_full34_LAN98plus12_comparison69_rerun': False,
          'original_outer_seconds': ORIGINAL_OUTER_SECONDS,
          'launcher_started_monotonic': args.outer_started_monotonic,
          'same_pid_launcher': args.launcher_pid,
          'outer_phase_caps_seconds': {'normal_release_build': 1800,
                                       'all_compile_checks_shared': 3600,
                                       'each_listing': 30, 'each_runtime_family_shared': 600}}
`;
 replace(before.slice(intentStart,intentEnd),intent,"new independent denominators and bounds");
 replace("'--message-format=json-render-diagnostics'], 1800)","'--message-format=json-render-diagnostics'], 1800, deadline=OUTER_UNTIL)","release clipped original outer");
 const bodyStart=before.indexOf("    build = owned('build',"),bodyEnd=before.indexOf("except BaseException as error:\n    result['failure_type']",bodyStart);
 const body=`    # One original 3600-second compilation budget includes all three checks.
    compile_started = time.monotonic()
    compile_until = min(compile_started + 3600.0, OUTER_UNTIL)
    result['compile_shared'] = {'started_monotonic': compile_started, 'until_monotonic': compile_until,
                                'cap_seconds': 3600, 'deadline_reset': False, 'commands': []}
    ordinary = owned('ordinary-no-default-check', [str(Path(args.toolchain) / 'cargo'), 'check',
                     '--release', '--locked', '--offline', '-p', 'heptabao-server',
                     '--lib', '--no-default-features', '--message-format=json-render-diagnostics'],
                     bounded_remaining(compile_until), deadline=compile_until)
    result['compile_shared']['commands'].append(ordinary)
    assert ordinary['exit_code'] == 0 and not ordinary['timed_out'], 'ordinary feature compilation failed'
    ordinary_events = []
    for line in (output / 'ordinary-no-default-check.stdout').read_text().splitlines():
        try:
            ordinary_events.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    assert any(e.get('reason') == 'build-finished' and e.get('success') is True for e in ordinary_events)
    ordinary_artifacts = [e for e in ordinary_events if e.get('reason') == 'compiler-artifact'
                          and e.get('target', {}).get('name') == 'heptabao_server']
    assert len(ordinary_artifacts) == 1 and ordinary_artifacts[0]['features'] == []
    assert not ordinary_artifacts[0]['profile']['test']
    assert freeze() == before
    binaries = {}
    for profile_name, feature_arguments, expected_features in (
            ('file', ['--no-default-features', '--features', 'native-v6-storage'], ['native-v6-storage']),
            ('default', [], ['default', 'native-v6-ha', 'native-v6-storage'])):
        label = profile_name + '-libtest-build'
        build = owned(label, [str(Path(args.toolchain) / 'cargo'), 'test', '--release', '--locked',
                      '--offline', '-p', 'heptabao-server', '--lib', '--no-run',
                      *feature_arguments, '--message-format=json-render-diagnostics'],
                      bounded_remaining(compile_until), deadline=compile_until)
        result['compile_shared']['commands'].append(build)
        assert build['exit_code'] == 0 and not build['timed_out'], 'reviewed libtest profile compilation failed'
        events, artifacts = [], []
        for line in (output / (label + '.stdout')).read_text().splitlines():
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                continue
            events.append(event)
            if (event.get('reason') == 'compiler-artifact' and event.get('profile', {}).get('test')
                    and event.get('target', {}).get('name') == 'heptabao_server' and event.get('executable')):
                artifacts.append(event)
        assert any(e.get('reason') == 'build-finished' and e.get('success') is True for e in events)
        assert len(artifacts) == 1
        artifact = artifacts[0]
        assert sorted(artifact['features']) == expected_features
        assert artifact['profile'] == {'opt_level': '3', 'debuginfo': 0, 'debug_assertions': True,
                                       'overflow_checks': True, 'test': True}
        built = Path(artifact['executable'])
        assert built.is_file() and not built.is_symlink()
        assert built.resolve().is_relative_to(Path(args.target).resolve())
        binary_sha = sha(built)
        binary = output / ('retained-heptabao-server-libtest-' + profile_name)
        with built.open('rb') as original, binary.open('xb') as retained:
            shutil.copyfileobj(original, retained, 1024 * 1024)
            retained.flush()
            os.fsync(retained.fileno())
        binary.chmod(0o500)
        assert sha(binary) == binary_sha and sha(built) == binary_sha
        binaries[profile_name] = {'path': str(binary), 'sha256': binary_sha, 'bytes': binary.stat().st_size,
                                 'features': artifact['features'], 'profile': artifact['profile'],
                                 'compiler_executable': str(built), 'build': build}
        bounded_remaining(compile_until)
        assert freeze() == before
    result['binaries'] = binaries
    result['compile_shared']['elapsed_seconds'] = time.monotonic() - compile_started
    bounded_remaining(compile_until)
    for group in groups:
        family_started = time.monotonic()
        family_until = min(family_started + group['runtime_seconds'], OUTER_UNTIL)
        selected_binary = binaries[group['libtest_profile']]
        binary, binary_sha = Path(selected_binary['path']), selected_binary['sha256']
        assert sha(binary) == binary_sha and freeze() == before
        family = {'label': group['label'], 'libtest_profile': group['libtest_profile'],
                  'status': 'failed', 'test_count': len(group['tests']), 'actual_test_names': [],
                  'cap_seconds': 600, 'clamped_to_original_outer_deadline': True, 'tests': []}
        result['group_results'].append(family)
        for index, name in enumerate(group['tests']):
            label = group['label'] + '-' + str(index + 1)
            listing = owned(label + '-list', [str(binary), name, '--exact', '--list'],
                            min(30.0, bounded_remaining(family_until)), deadline=family_until)
            assert listing['exit_code'] == 0 and not listing['timed_out']
            selected = [line[:-6] for line in (output / (label + '-list.stdout')).read_text().splitlines()
                        if line.endswith(': test')]
            assert selected == [name], 'exact reviewed testcase missing from selected feature profile'
            bounded_remaining(family_until)
            result['runtime_tests_started'] = True
            tests = owned(label, [str(binary), name, '--exact', '--nocapture', '--test-threads=1'],
                          bounded_remaining(family_until), deadline=family_until)
            family['actual_test_names'].append(name)
            family['tests'].append({'name': name, 'listing': listing, 'tests': tests})
            assert tests['exit_code'] == 0 and not tests['timed_out']
            summary = (output / (label + '.stdout')).read_text()
            assert 'test result: ok. 1 passed; 0 failed; 0 ignored;' in summary, 'actual testcase not executed'
            bounded_remaining(family_until)
        assert sha(binary) == binary_sha and freeze() == before
        family['elapsed_seconds'] = time.monotonic() - family_started
        bounded_remaining(family_until)
        family['status'] = 'passed'
    result['binaries_unchanged'] = all(sha(v['path']) == v['sha256'] for v in binaries.values())
    result['release_artifacts_unchanged'] = all(sha(v['path']) == v['sha256'] for v in release_artifacts.values())
    result['source_unchanged'] = freeze() == before
    actual_names = [name for family in result['group_results'] for name in family['actual_test_names']]
    assert len(actual_names) == 162 and len(set(actual_names)) == 147
    assert result['binaries_unchanged'] and result['release_artifacts_unchanged'] and result['source_unchanged']
    assert len(result['group_results']) == 4 and all(g['status'] == 'passed' for g in result['group_results'])
    result['actual_unique_test_total'] = 147
    result['actual_profile_instance_total'] = 162
    result['status'] = 'passed'
`;
 replace(before.slice(bodyStart,bodyEnd),body,"shared compile gate and exact profile runs");
 return {source:before,replacements,groupsRaw,groupHash};
}