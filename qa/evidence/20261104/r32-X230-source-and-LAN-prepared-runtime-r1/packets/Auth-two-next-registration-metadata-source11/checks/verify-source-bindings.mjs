function verifySourceProposal(input, sha256, gitSha1) {
  const checks=[];
  function check(name, passed) { checks.push({name,passed:passed===true}); if(passed!==true)throw Object.assign(new Error(name),{checks}); }
  function utf8(raw) { return unescape(encodeURIComponent(raw)); }
  function equal(a,b) { return JSON.stringify(a)===JSON.stringify(b); }
  const expectedSources={
  "selector": {
    "blob": "41d3492a4965c62292eaa74a4d0b746b6bc4e4b2",
    "bytes": 673468,
    "sha256": "ccff13111aa60369ac9d88b526a58a7df1f733f1d99d205c01c6186036957e66"
  },
  "harness-policy": {
    "blob": "4c2a270a3a9e21ccf86032131700daf685157388",
    "bytes": 5718,
    "sha256": "fc4938132774953cb0337d1b9f5fd715e3f062a987eedb45b7c1bb582077db43"
  },
  "registry": {
    "blob": "9f5042ec5442239f12975e3680c0568b3c85bdf8",
    "bytes": 3135,
    "sha256": "a845875a1998c2a6bdd9fe4c824a0a7c3e7da0f3ee75ec56dc6163d4327f7ff0"
  },
  "runtime-loader": {
    "blob": "909ec9eab6932b1f9241fbb0969c772639f18cb3",
    "bytes": 6047,
    "sha256": "bd6a9f363bc7aac2fb0503640e339ffce52e0eab15336e6489b6f8129df748fb"
  },
  "support": {
    "blob": "f216481adbe96bcba9f138a95c2ced5d25b11d4b",
    "bytes": 4255,
    "sha256": "ac75c6ed8c7ff564a189b3ca43c40f3bdbdf9c7b607254bf49a63940859f89f6"
  },
  "codex": {
    "blob": "39b49d3be2df87cde0af1f592a049cb49013c57d",
    "bytes": 3596,
    "sha256": "8919eefce05b3127251724c8f8cad7f1ac1a0994c57b243361092ea4de096f72"
  },
  "worker": {
    "blob": "3614c27cb06f311870ceeeda3f01e806306ae0d1",
    "bytes": 28533,
    "sha256": "8c4a2cc09330cfda7a488e7e5caa811f4e190a10054a31f683b3466124210431"
  },
  "runtime-policy": {
    "blob": "d61f4e1e874441cd4683a5da8e3a13dafb120514",
    "bytes": 6918,
    "sha256": "58c0bac3584b6db4c73f2d6770b71ae742fbbec79981cbf2803c6c4b5bbc54d6"
  },
  "openai-routing": {
    "blob": "b7b0533dcde5a358096fc1f57a0b8e2cee75863d",
    "bytes": 3497,
    "sha256": "31d71606e25c68579061a8ec2998402ebe33fb8cba0b55d9cf3342f8bfa029d6"
  },
  "plugin-loader": {
    "blob": "d93477dd8c184405737907803455dd52b214038c",
    "bytes": 116680,
    "sha256": "3a10479bdcbb713692c3ded7dbd5baad27c1b17ae3566172c117d45916dabce7"
  }
};
  const expectedRequests=[
  {
    "idempotency_key": "heptabao-mac-harness-dependency-info-manifest-registry-20261105-r1",
    "operation": {
      "tool": "file_info",
      "arguments": {
        "host": "mac",
        "path": "/opt/homebrew/lib/node_modules/openclaw/dist/manifest-registry--UiRn6nq.js"
      }
    }
  },
  {
    "idempotency_key": "heptabao-mac-harness-dependency-info-plugin-registry-20261105-r1",
    "operation": {
      "tool": "file_info",
      "arguments": {
        "host": "mac",
        "path": "/opt/homebrew/lib/node_modules/openclaw/dist/registry-B8eQDFB4.js"
      }
    }
  }
];
  check("exact_source_names",equal(Object.keys(input.sources).sort(),Object.keys(expectedSources).sort()));
  for(const [name,expected] of Object.entries(expectedSources)){
    const value=input.sources[name], bytes=utf8(value.raw);
    check(name+".whole_bytes",bytes.length===expected.bytes);
    check(name+".whole_sha256",sha256(bytes)===expected.sha256);
    check(name+".whole_Git_blob",gitSha1("blob "+bytes.length+"\0"+bytes)===expected.blob);
    check(name+".basis_pin",equal(input.source_basis.sources[name],expected));
  }
  check("anchor_count31",input.anchors.anchors.length===31);
  for(const a of input.anchors.anchors) {
    const value=input.sources[a.source],expected=expectedSources[a.source];
    check("anchor."+a.id,Boolean(value)&&a.blob===expected.blob&&a.sha256===expected.sha256&&
      Number.isInteger(a.start_line)&&a.start_line>0&&Number.isInteger(a.end_line)&&a.end_line>=a.start_line&&
      value.raw.split("\n").slice(a.start_line-1,a.end_line).join("\n")===a.text);
  }
  const loaderLines=input.sources["plugin-loader"].raw.split("\n");
  const imports=[
    {line:15,relative:"./manifest-registry--UiRn6nq.js",path:"/opt/homebrew/lib/node_modules/openclaw/dist/manifest-registry--UiRn6nq.js"},
    {line:40,relative:"./registry-B8eQDFB4.js",path:"/opt/homebrew/lib/node_modules/openclaw/dist/registry-B8eQDFB4.js"}
  ];
  for(let i=0;i<2;i++) {
    const expected=expectedRequests[i],p=input.proposal.requests[i],e=imports[i];
    check("request"+(i+1)+".exact_shape",equal(input.request_values[i],expected)&&equal(p.value,expected));
    const requestBytes=utf8(JSON.stringify(expected,null,2)+"\n");
    check("request"+(i+1)+".published_pin",p.request.bytes===requestBytes.length&&
      p.request.sha256===sha256(requestBytes)&&p.request.blob===gitSha1("blob "+requestBytes.length+"\0"+requestBytes));
    check("request"+(i+1)+".literal_origin",p.origin.line===e.line&&p.origin.import===loaderLines[e.line-1]&&
      p.origin.relative_specifier===e.relative&&loaderLines[e.line-1].endsWith('from "'+e.relative+'";'));
    check("request"+(i+1)+".lexical_path_only",expected.operation.arguments.path===e.path&&
      e.path==="/opt/homebrew/lib/node_modules/openclaw/dist/"+e.relative.slice(2)&&p.origin.derivation.includes("lexical"));
    check("request"+(i+1)+".actual_unbound",p.submitted===false&&Object.values(p.actual).every(v=>v===null));
  }
  check("proposal.metadata_only",input.proposal.requests.length===2&&input.proposal.bounds.maximum_native_metadata_operations===2&&
    input.proposal.bounds.body_read_operations===0&&input.proposal.bounds.SDK_executions===0&&input.proposal.bounds.directory_enumerations===0);
  check("proposal.one_original",input.proposal.bounds.maximum_inflight_Runtime_calls===1&&
    input.proposal.bounds.maximum_original_native_futures===1&&input.proposal.bounds.immutable_result_page_limit===8192);
  const a=input.proposal.consumed_body_accounting;
  check("consumed.first_window",equal(a.first_completed_window,{files:3,chunks:3,bytes:13569,original_max_chunks:5,original_max_bytes:265740,unused_authorization_reused:0}));
  check("consumed.second_window",equal(a.second_completed_window,{files:3,chunks:4,bytes:127095}));
  check("consumed.cumulative",a.cumulative_completed.files===6&&a.cumulative_completed.chunks===7&&a.cumulative_completed.bytes===140664&&13569+127095===140664);
  check("proposed.body_zero",a.proposed_metadata_window.body_bytes===0&&a.proposed_metadata_window.body_chunks===0&&
    a.cumulative_if_metadata_completes.body_bytes===140664);
  const contract=input.contract,worker=input.sources.worker.raw;
  function compact(v){return v.replace(/\s+/g,"");}
  const call=contract.original_selection_call;
  check("worker.loader_call_exact",compact(worker).includes(compact(call.loader)));
  check("worker.selector_call_exact",compact(worker).includes(compact(call.selector)));
  check("worker.existing_codex_and_object_gates",compact(worker).includes(compact(call.existing_id_gate))&&
    compact(worker).includes(compact(call.existing_instance_gate)));
  check("worker.five_agents",equal(contract.agents,["main","trnm","hepta-ui","hepta","hepta-backend"]));
  check("contract.not_executable",contract.status==="UNBOUND_SOURCE_CONTRACT_NOT_EXECUTABLE_NO_SDK_GO"&&
    contract.important_scope_limits.new_diagnostic_request===null&&contract.important_scope_limits.new_diagnostic_runtime_budget===null&&
    contract.important_scope_limits.actual_gateway_instance_proven===false&&
    contract.call_order_for_later_bound_diagnostic.every(s=>s.ready===false));
  check("contract.original_guard_unchanged",contract.important_scope_limits.original_npm_composite_guard_modified===false&&
    contract.important_scope_limits.old_failures_and_UNKNOWN_preserved===true);
  check("contract.owner_and_manifest_unbound",contract.important_scope_limits.Google_manifest_path===null&&
    contract.important_scope_limits.Google_executed_entry===null&&contract.important_scope_limits.Google_owner_selected===null);
  check("selector.same_object_return",input.sources.selector.raw.includes("harness: params.harness,")&&
    input.sources.selector.raw.includes("return selectAgentHarnessDecision(params).harness;"));
  check("registry.owner_field_separate",input.sources.registry.raw.includes("pluginId: harness.pluginId ?? options?.ownerPluginId")&&
    input.sources.registry.raw.includes("ownerPluginId: options?.ownerPluginId"));
  check("loader.no_Google_manifest_literal",!input.sources["plugin-loader"].raw.includes("openclaw.plugin.json")&&
    !input.sources["plugin-loader"].raw.includes("manifestPath"));
  return {schema:"heptabao.mac-owner-next2.pure-source-bindings.result.v1",ok:true,checks,
    passed:checks.length,failed:0,scope:"Whole source/string anchors/request shape/accounting only",
    Runtime_calls:0,native_futures:0,source_functions_executed:0,SDK_imported:0,product_cases:0,
    actual_selected_owner:null,GO:false};
}
