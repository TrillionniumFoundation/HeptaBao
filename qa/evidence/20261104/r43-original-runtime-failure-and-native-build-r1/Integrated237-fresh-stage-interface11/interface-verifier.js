function verifyFreshCombinedStageInterface(f){
 const c=f.contract,checks=[],check=(name,value)=>checks.push({name,pass:!!value});
 const equal=(a,b)=>JSON.stringify(a)===JSON.stringify(b);
 function def(raw,name){const lines=raw.split('\n'),at=lines.findIndex(s=>s.startsWith('def '+name+'('));if(at<0)throw new Error(name);let end=at+1;while(end<lines.length&&(lines[end]===''||/^[ \t]/.test(lines[end])))end++;return lines.slice(at,end).join('\n');}
 function table(raw,name){const m=new RegExp('^'+name+' = \\{\\n([\\s\\S]*?)^\\}','m').exec(raw);if(!m)throw new Error(name);return m[0];}
 check('stage_whole_pin',equal(gitBlobMeta(f.stage),c.reference_stage));
 check('launcher_whole_pin',equal(gitBlobMeta(f.launcher),c.reference_launcher));
 check('carrier_whole_pin',equal(gitBlobMeta(f.carrier),c.historical_controls.carrier));
 for(const m of c.consumer_field_map){check('consumer:'+m.field,f.launcher.includes(m.launcher_exact));check('producer:'+m.field,f.stage.includes(m.stage_exact));}
 const [schema,purpose]=c.semantic_literal_adaptations;
 check('one_schema_occurrence',f.stage.split(schema.old_literal).length===2);
 check('same_launcher_schema_after_planned_literal',f.launcher.includes('SOURCE_STAGE_SCHEMA = '+schema.new_literal));
 check('one_purpose_occurrence',f.stage.split(purpose.old_literal).length===2);
 const sf=table(f.stage,'FAILED_FILES'),lf=table(f.launcher,'FAILED_FILES');
 check('failed12_tables_exact',sf===lf);
 check('failed12_count',[...sf.matchAll(/^\s*'[^']+': \(\d+, '[0-9a-f]{64}'\),$/gm)].length===12);
 const sfun=def(f.stage,'preserve_failed_observer'),lfun=def(f.launcher,'preserve_failed_observer');
 check('failed_return_object_same',sfun.slice(sfun.indexOf('    return {')).trim()===lfun.slice(lfun.indexOf('    return {')).trim());
 check('authority_paths_equal_after_required_root_binding',f.stage.includes("CONTROL = ROOT / 'control'")&&f.launcher.includes("SOURCE_STAGE_CONTROL = SOURCE_STAGE_ROOT / 'control'"));
 const controls=JSON.parse(f.carrier).controls;
 for(const m of f.stage.matchAll(/^\s*"([^"]+)": \((\d+), "([0-9a-f]{64})"\),$/gm)){
  const p=gitBlobMeta(controls[m[1]]);check('carrier_control:'+m[1],p.bytes===Number(m[2])&&p.sha256===m[3]);
 }
 check('carrier_unchanged_f916',gitBlobMeta(f.carrier).blob==='f9166bc801c5b10e12b77274f485d27d61cd499a'&&gitBlobMeta(f.carrier).bytes===79951);
 check('budget300',f.stage.includes('STAGE_SECONDS = 300.0'));
 check('budget90',f.stage.includes('def owned(label, argv, limit=90, cwd=None):'));
 check('budget180',f.stage.includes('str(OLD), str(SOURCE)], 180)'));
 check('shared_absolute_clip',f.stage.includes('return original_owned(label, argv, min(limit, stage_remaining()), cwd)'));
 check('carrier_cap',f.stage.includes('sys.stdin.buffer.read(262145)')&&f.stage.includes('assert len(carrier) <= 262144'));
 check('bundle_cap',f.stage.includes('assert 0 < len(canonical_raw) <= 4 * 1024 * 1024'));
 check('no_runtime_request',c.runtime_request===null&&c.Native_authorized===false&&c.final_commit===null&&c.final_tree===null&&c.fresh_root===null);
 return {schema:'heptabao.combined237-stage-interface-source-checks.v1',pass:checks.every(x=>x.pass),checks:checks.length,results:checks,Native_calls_added:0,candidate_code_executed:false,new_stager_created:false,actual_new_stage_qualification:false};
}