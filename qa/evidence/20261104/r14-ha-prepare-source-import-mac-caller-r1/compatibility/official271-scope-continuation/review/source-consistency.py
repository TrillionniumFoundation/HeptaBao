import difflib,json,re,sys
p=json.loads(sys.argv[1]);old=json.loads(p["old"]);new=json.loads(p["new"]);bounded=json.loads(p["bounded"]);reg=json.loads(p["registry"]);err=json.loads(p["erratum"])
checks=[]
def need(name,value):
    assert value,name
    checks.append(name)
need("eight existing action rows retained",len(new["action_rows"])==len(old["action_rows"])==8)
need("seven non-snapshot rows exact",new["action_rows"][1:]==old["action_rows"][1:])
need("snapshot change only runtime status boundary",{k:v for k,v in new["action_rows"][0].items() if k!="current_boundary"}=={k:v for k,v in old["action_rows"][0].items() if k!="current_boundary"})
need("all other original factual sections exact",{k:v for k,v in new.items() if k not in ("schema","status_update","product_source","action_rows")}=={k:v for k,v in old.items() if k not in ("schema","product_source","action_rows")})
need("exact same audited source",new["product_source"]["commit"]==old["product_source"]["commit"]=="3cb873919170cc77101b27f6a3ab9e98f41f8d93" and new["product_source"]["tree"]==old["product_source"]["tree"])
need("bounded69 retained on actual 495033",bounded["case_count"]==len(bounded["case_rows"])==69 and sum(bounded["counts"].values())==69 and bounded["candidate_source"]=="49503322c7f446e5eb41e7744f1fdbd7f1192ecc" and bounded["full_replacement"] is False)
for field,marker in (("credential_plugin_names","credentialBackends: map[string]credentialBackend{"),("database_plugin_names","databasePlugins: map[string]databasePlugin{"),("secret_plugin_names","logicalBackends: map[string]logicalBackend{")):
    section=p["registry_source"].split(marker,1)[1].split("\n\t\t},",1)[0]
    names=re.findall(r'^\s*"([^"]+)"\s*:',section,re.M)
    need("exact actual registry "+field,names==reg[field])
need("extension hook truly empty","func addExtPluginsImpl(r *registry) {}" in p["registry_source"])
need("three known family corrections only",[(r["surface_id"],r["field"],r["after"]) for r in err["changes"]]==[("HB-SURFACE-MOUNT-REGISTRY","bounded69_families",["kv","transit"]),("HB-SURFACE-POLICY-ACL","bounded69_families",["token"]),("HB-SURFACE-LEASE-EXPIRATION","bounded69_families",["pki"])])
need("no whole compatibility admitted",new["limits"]["exhaustive_upstream_coverage"] is False and new["limits"]["full_replacement"] is False and new["limits"]["production_cutover"] is False)
need("new PhaseB not claimed",new["status_update"]["new_phaseb_product_run"] is False and new["status_update"]["bounded69_transferred_to_3cb"] is False)
print(json.dumps({"schema":"heptabao.official271.partial-audit-update-source-check.v1","status":"passed_source_only","checks":checks,"count":len(checks),"host_operations":0,"product_tests":0,"exhaustive_denominator_complete":False,"full_replacement":False,"diff":"".join(difflib.unified_diff(p["old"].splitlines(True),p["new"].splitlines(True),fromfile="original/current-native-gap-map.public.json",tofile="updated/current-native-gap-map.public.json"))},indent=2))
