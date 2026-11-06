function boundedLineDiff(before,after,name){
 if(!before.endsWith('\n')||!after.endsWith('\n'))throw new Error('final_newline_required');
 const a=before.slice(0,-1).split('\n'),b=after.slice(0,-1).split('\n'),m=a.length,n=b.length;
 if(m>1000||n>1000)throw new Error('bounded_source_lines');
 const dp=Array.from({length:m+1},()=>new Uint16Array(n+1));
 for(let i=m-1;i>=0;i--)for(let j=n-1;j>=0;j--)dp[i][j]=a[i]===b[j]?dp[i+1][j+1]+1:Math.max(dp[i+1][j],dp[i][j+1]);
 const ops=[];let i=0,j=0;
 while(i<m||j<n){if(i<m&&j<n&&a[i]===b[j]){ops.push({k:' ',s:a[i++]});j++;}
 else if(j<n&&(i===m||dp[i][j+1]>dp[i+1][j]))ops.push({k:'+',s:b[j++]});
 else ops.push({k:'-',s:a[i++]});}
 const cuts=[];for(let k=0;k<ops.length;k++)if(ops[k].k!==' '){
  const lo=Math.max(0,k-3),hi=Math.min(ops.length,k+4),last=cuts.at(-1);
  if(last&&lo<=last[1])last[1]=Math.max(last[1],hi);else cuts.push([lo,hi]);
 }
 let out='--- a/'+name+'\n+++ b/'+name+'\n';
 for(const [lo,hi]of cuts){let oa=1,nb=1;for(let k=0;k<lo;k++){if(ops[k].k!=='+')oa++;if(ops[k].k!=='-')nb++;}
 const z=ops.slice(lo,hi),oc=z.filter(x=>x.k!=='+').length,nc=z.filter(x=>x.k!=='-').length;
 out+='@@ -'+oa+','+oc+' +'+nb+','+nc+' @@\n'+z.map(x=>x.k+x.s).join('\n')+'\n';}
 return out;
}
function strictApplyUnified(original,diff){
 const src=original.slice(0,-1).split('\n'),ls=diff.slice(0,-1).split('\n');
 if(!original.endsWith('\n')||!ls[0].startsWith('--- ')||!ls[1].startsWith('+++ '))throw new Error('diff_header');
 let cursor=0,out=[],hunks=0,i=2;
 while(i<ls.length){const m=/^@@ -(\d+),(\d+) \+(\d+),(\d+) @@$/.exec(ls[i++]);if(!m)throw new Error('hunk_header');
 const oldAt=Number(m[1])-1,oldCount=Number(m[2]),newAt=Number(m[3])-1,newCount=Number(m[4]);
 if(oldAt<cursor)throw new Error('hunk_overlap');out.push(...src.slice(cursor,oldAt));cursor=oldAt;
 if(out.length!==newAt)throw new Error('new_offset');let oc=0,nc=0;
 while(i<ls.length&&!ls[i].startsWith('@@ ')){const k=ls[i][0],s=ls[i++].slice(1);
 if(k===' '||k==='-'){if(src[cursor++]!==s)throw new Error('whole_context');oc++;}
 if(k===' '||k==='+'){out.push(s);nc++;}
 if(![' ','-','+'].includes(k))throw new Error('line_kind');}
 if(oc!==oldCount||nc!==newCount)throw new Error('hunk_counts');hunks++;
 }out.push(...src.slice(cursor));return {text:out.join('\n')+'\n',hunks};
}
function verifyCombined237(f){
 const checks=[],check=(name,ok,detail=null)=>{checks.push({name,pass:!!ok,...(detail===null?{}:{detail})});};
 const same=(a,b)=>JSON.stringify(a)===JSON.stringify(b);
 function span(raw,a,b){const x=raw.indexOf(a);if(x<0)return null;const y=raw.indexOf(b,x+a.length);return y<0?null:raw.slice(x,y);}
 function defs(raw){const lines=raw.split('\n'),out={};for(let i=0;i<lines.length;i++){
  const m=/^(?:async )?def ([A-Za-z_]\w*)\(/.exec(lines[i]);if(!m)continue;
  let j=i+1;while(j<lines.length&&(lines[j]===''||/^[ \t]/.test(lines[j])))j++;
  out[m[1]]=lines.slice(i,j).join('\n').replace(/\n+$/,'');}return out;}
 const rb=f.runner.before,ra=f.runner.after,lb=f.launcher.before,la=f.launcher.after;
 for(const [label,x]of[['runner',f.runner],['launcher',f.launcher]]){
  check(label+'_before_pin',same(gitBlobMeta(x.before),x.beforePin));
  check(label+'_after_pin',same(gitBlobMeta(x.after),x.afterPin));
  let next=x.before,valid=true;for(const e of x.edits){if(next.split(e.before).length!==2){valid=false;break;}next=next.replace(e.before,e.after);}
  check(label+'_ordered_exact_replacements',valid&&next===x.after);
  let prior=x.after;for(const e of [...x.edits].reverse()){if(prior.split(e.after).length!==2){valid=false;break;}prior=prior.replace(e.after,e.before);}
  check(label+'_reverse_exact_replacements',valid&&prior===x.before);
  check(label+'_strict_forward_whole',strictApplyUnified(x.before,x.forward).text===x.after);
  check(label+'_strict_reverse_whole',strictApplyUnified(x.after,x.reverse).text===x.before);
  check(label+'_fixed40000_source_limit',gitBlobMeta(x.after).bytes<=40000,gitBlobMeta(x.after).bytes);
  check(label+'_ready_false',x.after.includes('BINDING_READY = False\nassert BINDING_READY'));
  const a=defs(x.before),b=defs(x.after);
  check(label+'_same_function_names',same(Object.keys(a),Object.keys(b)),Object.keys(a));
  for(const name of Object.keys(a))check(label+'_definition_whole_'+name,a[name]===b[name]);
 }
 check('runner_combined_identity_null',ra.includes('DIAGNOSTIC_COMMIT = None\nDIAGNOSTIC_TREE = None'));
 check('launcher_combined_identity_and_stage_null',la.includes('FINAL_COMMIT = None\nFINAL_TREE = None\nSOURCE_STAGE_ROOT = None'));
 check('launcher_control_root_null',la.includes('    ROOT = None\n'));
 const groups=JSON.parse(f.groupsRaw),oldGroups=JSON.parse(f.oldGroupsRaw);
 check('groups_whole_pin',same(gitBlobMeta(f.groupsRaw),f.groupsPin));
 check('groups_exact32163',gitBlobMeta(f.groupsRaw).bytes===32163);
 check('groups_original_first_four',same(groups.slice(0,4),oldGroups));
 check('groups18',groups.length===18);
 check('groups_labels_unique',new Set(groups.map(x=>x.label)).size===18);
 check('every_family_shared600',groups.every(g=>g.runtime_seconds===600));
 check('only_original_group_fields',groups.every(g=>same(Object.keys(g).sort(),['label','libtest_profile','runtime_seconds','tests'])));
 const crates={file:'heptabao-server',default:'heptabao-server','ha-native-v6-peer-ingress':'heptabao-ha-service'};
 const flat=groups.flatMap(g=>g.tests.map(name=>({crate:crates[g.libtest_profile],libtest_profile:g.libtest_profile,name})));
 const expected=f.originalInventory.map(x=>({crate:x.crate,libtest_profile:x.libtest_profile,name:x.name}));
 check('all254_entries_exact_frozen_inventory_order',same(flat,expected));
 check('entries254',flat.length===254);
 check('unique237_by_crate_and_name',new Set(flat.map(x=>x.crate+'\0'+x.name)).size===237);
 check('baseline166_entries',groups.slice(0,4).reduce((n,g)=>n+g.tests.length,0)===166);
 check('snapshot27_entries',groups.slice(4,9).reduce((n,g)=>n+g.tests.length,0)===27);
 check('normal61_all_exact_original_order',same(flat.slice(193),expected.slice(193))&&flat.slice(193).length===61);
 const prof={};for(const x of flat){const k=x.crate+'/'+x.libtest_profile;prof[k]=(prof[k]||0)+1;}
 check('profiles_exact',same(prof,{'heptabao-server/file':17,'heptabao-server/default':220,'heptabao-ha-service/ha-native-v6-peer-ingress':17}),prof);
 check('original17_dual_profile_names',same(groups[0].tests,groups[1].tests));
 check('both_pin_groups_sha',ra.includes("assert args.groups_sha256 == '"+f.groupsPin.sha256+"'")&&la.includes("GROUPS_SHA256 = '"+f.groupsPin.sha256+"'"));
 check('launcher_only_groups_cap_change',la.includes("groups_raw, groups_pin = read_bound(CONTROL / 'jwt-test-groups.public.json', args.groups_sha256, 32163)"));
 check('generic_read_bound_whole',defs(lb).read_bound===defs(la).read_bound);
 check('runner_release_block_whole',span(rb,"    release = owned('normal-release-build'","    # One original")===span(ra,"    release = owned('normal-release-build'","    # One original"));
 check('ordinary_compile_gate_whole',span(rb,"    ordinary = owned(","    binaries = {}")===span(ra,"    ordinary = owned(","    binaries = {}"));
 check('shared_compile_deadline_same_once',ra.split('compile_until = min(compile_started + 3600.0, OUTER_UNTIL)').length===2);
 check('ordinary_and_libtests_same_compile_deadline',ra.includes('bounded_remaining(compile_until), deadline=compile_until)')&&ra.includes("'cap_seconds': 3600, 'deadline_reset': False"));
 check('outer12000_both',ra.includes('ORIGINAL_OUTER_SECONDS = 12000')&&la.includes('ORIGINAL_OUTER_SECONDS = 12000'));
 check('samePID_outer_origin_whole',span(rb,'ORIGINAL_OUTER_SECONDS =','source, output =')===span(ra,'ORIGINAL_OUTER_SECONDS =','source, output ='));
 check('original_file_profile_exact',ra.includes("('file', 'heptabao-server', 'heptabao_server', ['--no-default-features', '--features', 'native-v6-storage'], ['native-v6-storage'])"));
 check('original_default_profile_exact',ra.includes("('default', 'heptabao-server', 'heptabao_server', [], ['default', 'native-v6-ha', 'native-v6-storage'])"));
 check('one_new_HA_profile_exact',ra.includes("('ha-native-v6-peer-ingress', 'heptabao-ha-service', 'heptabao_ha_service', ['--no-default-features', '--features', 'native-v6-peer-ingress'], ['native-v6-peer-ingress'])"));
 check('HA_feature_exact_canonical_source',f.haCargo.includes('native-v6-peer-ingress = ["dep:heptabao-raft-runtime", "dep:tokio", "dep:tokio-rustls", "heptabao-raft-runtime/native-v6-raft-objects"]'));
 check('separate_retained_binaries',ra.includes("binary = output / ('retained-' + package + '-libtest-' + profile_name)")&&ra.includes("selected_binary['crate'] == PROFILE_CRATES[group['libtest_profile']]"));
 check('target_and_profile_exact_guards',ra.includes("event.get('target', {}).get('name') == target_name")&&ra.includes("assert sorted(artifact['features']) == expected_features")&&ra.includes("'overflow_checks': True, 'test': True"));
 check('retained_copy_original_sha_full_sequence',span(rb,"        with built.open('rb')","        binaries[profile_name]")===span(ra,"        with built.open('rb')","        binaries[profile_name]"));
 check('all_families_share_original_outer_clip',ra.includes("family_until = min(family_started + group['runtime_seconds'], OUTER_UNTIL)"));
 check('exact_list_run_loop_whole',span(rb,"        for index, name in enumerate(group['tests']):","    result['binaries_unchanged']")===span(ra,"        for index, name in enumerate(group['tests']):","    result['binaries_unchanged']"));
 check('final_all18_pass_required',ra.includes("len(result['group_results']) == 18 and all(g['status'] == 'passed'"));
 check('final_actual237_254',ra.includes("len(actual_cases) == 254 and len(set(actual_cases)) == 237")&&ra.includes("result['actual_unique_test_total'] = 237")&&ra.includes("result['actual_profile_instance_total'] = 254"));
 check('runner_failure_cleanup_receipt_suffix_whole',rb.slice(rb.lastIndexOf('\nexcept BaseException as error:'))===ra.slice(ra.lastIndexOf('\nexcept BaseException as error:')));
 check('launcher_samePID_argv_whole',span(lb,'    argv = [PYTHON','    assert time.monotonic() < OUTER_UNTIL, \'original outer deadline expired before exec admission\'')===span(la,'    argv = [PYTHON','    assert time.monotonic() < OUTER_UNTIL, \'original outer deadline expired before exec admission\''));
 check('launcher_old_fences_and_lock_probe_whole',span(lb,'lock_fd = None\ntry:','    argv = [PYTHON')===span(la,'lock_fd = None\ntry:','    argv = [PYTHON'));
 check('launcher_finally_and_close_whole',span(lb,'except BaseException as error:\n    result.update(error_type=',"print(json.dumps({'status': 'preflight-admitted'")===span(la,'except BaseException as error:\n    result.update(error_type=',"print(json.dumps({'status': 'preflight-admitted'"));
 check('lock_closed_before_exec_fact_retained',la.indexOf('os.close(lock_fd)')<la.indexOf('os.execv(argv[0], argv)'));
 check('no_new_control_definition',Object.keys(defs(rb)).length===Object.keys(defs(ra)).length&&Object.keys(defs(lb)).length===Object.keys(defs(la)).length);
 check('source_plan_no_runtime_request',f.plan.runtime_request===null&&f.plan.native_authorized===false&&f.plan.combined_commit===null&&f.plan.combined_tree===null);
 check('old149_166_not_declared_current_qualification',f.plan.prior_c_qualification_inherited===false);
 check('required_future_actual_list',f.plan.actual_list_required===true);
 const failures=checks.filter(x=>!x.pass);
 return {schema:'heptabao.combined237-unbound-source-verification.v1',pass:failures.length===0,checks:checks.length,failures,results:checks,profiles:prof,unique:237,profile_entries:254,groups:18,
  original_runtime_functions_executed:false,Python_compile_executed:false,Native_calls:0,Cargo_calls:0,runtime_tests_executed:0,actual_list_observed:false};
}