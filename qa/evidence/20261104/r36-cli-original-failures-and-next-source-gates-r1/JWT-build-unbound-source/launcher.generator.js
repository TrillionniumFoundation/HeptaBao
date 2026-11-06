function makeJwtLauncher(before,groupsSha){
 let s=before;const replacements=[];
 function one(label,old,next){const n=s.split(old).length-1;if(n!==1)throw Error(label+": "+n);s=s.replace(old,next);replacements.push({label,before:old,after:next,count:1});}
 one("purpose",'"""Preserve prior evidence and admit one exact same-root publication normal build."""','"""Preserve prior evidence and admit one frozen native JWT build and exact regression matrix."""');
 one("inactive source admission","OUTER_STARTED = time.monotonic()","BINDING_READY = False\nassert BINDING_READY, 'formatted source and published controls need separate exact admission'\nFINAL_COMMIT = None\nFINAL_TREE = None\nSOURCE_STAGE_ROOT = None\nSOURCE_STAGE_SCHEMA = 'heptabao.native-jwt-independent-source-stage.v1'\nGROUPS_SHA256 = '"+groupsSha+"'\nOUTER_STARTED = time.monotonic()");
 one("controls receipt argument","('commit', 'tree', 'stage-sha256', 'runner-sha256', 'groups-sha256')","('commit', 'tree', 'stage-sha256', 'runner-sha256', 'groups-sha256', 'controls-sha256')");
 one("final source identity unresolved","assert args.commit == '4e808d0ecb1bcded22870a7ec960dfb2491cf6ec'\nassert args.tree == 'eba5e650bd080b8ad41ea52a2bc68867f541d255'","assert args.commit == FINAL_COMMIT and args.tree == FINAL_TREE");
 one("new exact controls receipt hash argument","for name in ('stage_sha256', 'runner_sha256', 'groups_sha256'):","for name in ('stage_sha256', 'runner_sha256', 'groups_sha256', 'controls_sha256'):");
 one("fresh isolated build controls root","ROOT = Path('/home/qian-qi/heptabao-same-root-publication-normal-20261105-r2')","ROOT = Path('/home/qian-qi/heptabao-native-jwt-r2-controls-20261106-r1')");
 one("current runner name","RUNNER_NAME = 'normal_same_root_publication_build.py'","RUNNER_NAME = 'native_jwt_build.py'");
 one("separate exact final source and controls","SOURCE = ROOT / 'source'\nCONTROL = ROOT / 'control'","SOURCE = SOURCE_STAGE_ROOT / 'source'\nSOURCE_STAGE_CONTROL = SOURCE_STAGE_ROOT / 'control'\nCONTROL = ROOT");
 one("owned build output","OUTPUT = ROOT / 'normal-release-tests-r1'","OUTPUT = ROOT / 'build-tests-r1'");
 one("failed observer remains in original source controls","authority_path = CONTROL / FAILED_AUTHORITY_NAME","authority_path = SOURCE_STAGE_CONTROL / FAILED_AUTHORITY_NAME");
 one("current launcher exact name","assert Path(__file__).resolve(strict=True) == CONTROL / 'launch_normal_same_root_publication.py'","assert Path(__file__).resolve(strict=True) == CONTROL / 'launch_native_jwt_build.py'");
 one("source stage receipt separate path","stage_raw, stage_pin = read_bound(CONTROL / 'stage-result.public.json', args.stage_sha256, 150000)","stage_raw, stage_pin = read_bound(SOURCE_STAGE_CONTROL / 'stage-result.public.json', args.stage_sha256, 150000)");
 one("final independent source schema","assert stage['schema'] == 'heptabao.same-root-publication-independent-source-stage.v1'","assert stage['schema'] == SOURCE_STAGE_SCHEMA");
 one("source closure qualification","assert all(x['direct_child_reaped'] and not x['remaining'] for x in stage['cleanup'])","assert all(x['direct_child_reaped'] and not x['remaining'] for x in stage['cleanup'])\nassert stage['full_strict_fsck_passed'] and stage['no_alternates'] and stage['no_shared_object_links']\nassert stage['source'] == str(SOURCE) and stage['root'] == str(SOURCE_STAGE_ROOT)\nassert stage['within_new_stage_deadline'] and not stage['compiler_started'] and not stage['rust_tests_executed']\nassert not stage['formatter_executed'] and not stage['historical_controls_executed']");
 one("new exact groups filename","groups_raw, groups_pin = read_bound(CONTROL / 'normal-test-groups.public.json', args.groups_sha256, 20000)","groups_raw, groups_pin = read_bound(CONTROL / 'jwt-test-groups.public.json', args.groups_sha256, 20000)");
 const old=`assert stage['controls'][RUNNER_NAME]['sha256'] == args.runner_sha256
assert stage['controls']['normal-test-groups.public.json']['sha256'] == args.groups_sha256
assert stage['controls'][FAILED_AUTHORITY_NAME] == {'bytes': 726, 'sha256': FAILED_AUTHORITY_SHA}
assert stage['failed_observer_before'] == stage['failed_observer_after']
assert [[g['label'], len(g['tests'])] for g in groups] == stage['exact_groups']
assert sum(len(g['tests']) for g in groups) == stage['exact_test_count']
assert all(g['runtime_seconds'] == 600 for g in groups)`;
 const next=`assert stage['controls'][FAILED_AUTHORITY_NAME] == {'bytes': 726, 'sha256': FAILED_AUTHORITY_SHA}
assert stage['failed_observer_before'] == stage['failed_observer_after']
assert args.groups_sha256 == GROUPS_SHA256
assert [(g['label'], g['libtest_profile'], len(g['tests'])) for g in groups] == [
    ('native-jwt-file15', 'file', 15), ('native-jwt-default15', 'default', 15),
    ('legacy-jwt-default63', 'default', 63), ('native-auth-identity-default69', 'default', 69)]
assert all(set(g) == {'label', 'libtest_profile', 'tests', 'runtime_seconds'}
           and g['runtime_seconds'] == 600 and len(g['tests']) == len(set(g['tests'])) for g in groups)
assert groups[0]['tests'] == groups[1]['tests']
assert sum(len(g['tests']) for g in groups) == 162
assert len({name for g in groups for name in g['tests']}) == 147
controls_raw, controls_pin = read_bound(CONTROL / 'inert-stage.result.public.json',
                                      args.controls_sha256, 65536)
controls = json.loads(controls_raw)
assert controls['schema'] == 'heptabao.native-jwt-build-controls-inert.v1'
assert controls['status'] == 'prepared' and controls['python_compile_only'] is True
assert all(controls[name] is False for name in
           ('source_executed', 'git_started', 'compiler_started', 'service_started', 'artifact_transfer_started'))
assert len(controls['files']) == 3
control_rows = {Path(row['path']).name: row for row in controls['files']}
assert set(control_rows) == {'native_jwt_build.py', 'launch_native_jwt_build.py', 'jwt-test-groups.public.json'}
_, launcher_pin = read_bound(CONTROL / 'launch_native_jwt_build.py',
                            control_rows['launch_native_jwt_build.py']['sha256'], 40000)
for name, observed in [('native_jwt_build.py', runner_pin),
                       ('launch_native_jwt_build.py', launcher_pin),
                       ('jwt-test-groups.public.json', groups_pin)]:
    row = control_rows[name]
    assert row['path'] == str(CONTROL / name) and row['mode'] == '0600'
    assert row['publication'] in ('created', 'existing_exact', 'existing_after_race')
    assert row['bytes'] == observed['bytes'] and row['sha256'] == observed['sha256']
    assert row['identity'] == observed['identity']
    assert observed['identity'][2:6] == [expected_uid, expected_uid, 0o100600, 1]
assert time.monotonic() < OUTER_UNTIL, 'original outer deadline expired after current control admission'`;
 one("new independent controls and 147-162 denominators",old,next);
 one("new admission schema","'schema': 'heptabao.same-root-publication-normal-target-admission.v1'","'schema': 'heptabao.native-jwt-r2-target-admission.v1'");
 one("actual source and controls receipt in admission","'stage': stage_pin, 'runner': runner_pin, 'groups': groups_pin,","'stage': stage_pin, 'runner': runner_pin, 'groups': groups_pin,\n          'controls_receipt': controls_pin, 'launcher': launcher_pin,");
 one("groups same-PID argv","'--groups', str(CONTROL / 'normal-test-groups.public.json'),","'--groups', str(CONTROL / 'jwt-test-groups.public.json'),");
 one("independent admitted counts",`                  exact_test_count=stage['exact_test_count'],
                  additional_existing_ingress_tests=7, additional_cold_h2_tests=9,
                  additional_same_root_publication_tests=1, original_60_test_count=60,
                  each_additional_group_total_cap_seconds=600,`,`                  unique_test_count=147, profile_instance_test_count=162,
                  new_jwt_test_names=15, new_jwt_profile_instances=30,
                  existing_auth_identity_test_names=132, compile_profiles=['file', 'default'],
                  default_features_do_not_qualify_distributed_jwt_ha=True,
                  compile_gate_shared_cap_seconds=3600, compile_deadline_reset=False,`);
 one("independent stdout counts","'source_tree': args.tree, 'exact_test_count': stage['exact_test_count'],","'source_tree': args.tree, 'unique_test_count': 147, 'profile_instance_test_count': 162,");
 return{source:s,replacements};
}