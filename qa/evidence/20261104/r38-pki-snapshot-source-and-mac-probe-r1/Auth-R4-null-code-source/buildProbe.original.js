function buildProbe(){
 const H=eval(load("owner_pure_source")+";({pin:gitBlobMeta,b:utf8Bytes})");
 const b64=eval("("+load("owner_home_t5_probe_b64_helper")+")");
 const extractor=eval("("+load("owner_home_t5_probe_error_code_extractor")+")");
 const common=load("owner_home_t5_probe_common"),body=load("owner_home_t5_probe_parent_body");
 const parts=[common,load("owner_home_t5_probe_child_body"),body,...load("owner_environment_probe_modules").map(x=>x.raw),load("owner_environment_probe_reference:native-observer").raw];
 const codes=[...new Set(parts.flatMap(extractor).concat(["process_projection_deadline_expired"]))].sort();
 store("owner_home_t5_probe_error_codes",codes);
 const constants=load("owner_home_t5_probe_constants")+"PUBLIC_ERROR_TYPES = tuple("+JSON.stringify(load("owner_home_t5_probe_error_types"))+")\nPUBLIC_ERROR_CODES = frozenset("+JSON.stringify(codes)+")\n";
 const pre="#!/usr/bin/env python3\n\"\"\"Independent public launchd context probe; no SDK, credential or product execution.\"\"\"\nfrom contextlib import contextmanager\nimport base64, ctypes, errno, hashlib, json, os, plistlib, re, signal, stat, sys, time, types\nfrom pathlib import Path\n\n";
 const child=pre+constants+"\n"+load("owner_home_t5_probe_signal_extract")+"\n"+load("owner_home_t5_probe_reader_extract")+"\n"+common+load("owner_home_t5_probe_child_body"),chp=H.pin(child);
 const mods=load("owner_home_t5_probe_module_rows"),anchor=load("owner_environment_probe_reference:anchor");
 const embeds="MODULES = json.loads(r'''"+JSON.stringify(mods)+"''')\n"+"ANCHOR_BASE64 = '"+b64(H.b(anchor.raw))+"'\nANCHOR_SHA = '"+anchor.pin.sha256+"'\n"+"CHILD_BASE64 = '"+b64(H.b(child))+"'\nCHILD_BYTES = "+chp.bytes+"\nCHILD_SHA = '"+chp.sha256+"'\n";
 const parent=pre+constants+"\n"+embeds+"\n"+common+"\n"+load("owner_home_t5_probe_parse_print")+load("owner_home_t5_probe_missing")+body;
 const pp=H.pin(parent);
 store("owner_home_t5_probe_child_source",child);store("owner_home_t5_probe_child_pin",chp);
 store("owner_home_t5_probe_controller_source",parent);store("owner_home_t5_probe_controller_pin",pp);
 store("owner_home_t5_probe_expanded_constants",constants);
 return {child:chp,controller:pp,childLines:child.split("\n").length,controllerLines:parent.split("\n").length};
}