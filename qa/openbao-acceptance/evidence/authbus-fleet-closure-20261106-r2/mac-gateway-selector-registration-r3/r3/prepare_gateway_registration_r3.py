#!/usr/bin/env python3
"""Create-only successor admitting the exact observed disabled-config warning."""
from pathlib import Path
import hashlib
HERE=Path(__file__).resolve().parent
PINS={
 'mac_gateway_registration_cases_r2.mjs':'6ffc5279007c46e031af5757c91cdb7060f37f9f7bdb46f91d68dceae8e43260',
 'mac_gateway_registration_qualification_r2.mjs':'3fe3cb7f9f45a3f90fa9959b4e6dd996bf600a1dcb7be689e958ccbcb30e4cfd',
 'launch_gateway_registration_qualification_r2.template.py':'39c918e58c5f64c90a3a881182dcd48716fac66cc1629e84714b9a6610b11b3b',
 'assemble_gateway_registration_qualification_r2.py':'bb93e1f19cf1388c1622da8f820de24fadfce8f9142b13389f0e9494bf9d305e',
}
for name,pin in PINS.items():assert hashlib.sha256((HERE/name).read_bytes()).hexdigest()==pin
def successor(name):
 return (HERE/name).read_text().replace('registration-qualification-20261106-r2','registration-qualification-20261106-r3').replace('registration_cases_r2','registration_cases_r3').replace('registration_qualification_r2','registration_qualification_r3').replace('registration.r2','registration.r3').replace('synthetic-plan.r2','synthetic-plan.r3').replace('registration-owned.r2','registration-owned.r3').replace('gateway-registration-r2.assembly','gateway-registration-r3.assembly').replace('assembled-source.r2','assembled-source.r3')
def once(s,old,new):
 assert s.count(old)==1,(old,s.count(old));return s.replace(old,new)
def save(name,text):
 with (HERE/name).open('x') as f:f.write(text)
cases=successor('mac_gateway_registration_cases_r2.mjs')
cases=once(cases,"  snapshotExact(selectionSnapshot);\n  need(report.originalDotenvReads.state>0", """  snapshotExact(selectionSnapshot);
  need(isDeepStrictEqual(selectionSnapshot.warnings,[{path:'plugins.entries.'+AUTHBUS,
   message:'plugin disabled (disabled in config) but config is present'}]),
   'gateway_exact_original_disabled_config_warning');
  report.originalDisabledConfigWarningExact=true;
  need(report.originalDotenvReads.state>0""")
save('mac_gateway_registration_cases_r3.mjs',cases)
save('mac_gateway_registration_qualification_r3.mjs',successor('mac_gateway_registration_qualification_r2.mjs'))
template=successor('launch_gateway_registration_qualification_r2.template.py')
helper="""def admitted_child_stderr(label,returncode,err,unit):
 # The original validator and logConfigWarningsOnce emit this exact public
 # warning for a disabled plugin retaining its required config. No other
 # stderr, reason, prefix, repetition, or failed child is accepted.
 expected=b'Config warnings:\\n- plugins.entries.openclaw-authbus: plugin disabled (disabled in config) but config is present\\n'
 return (type(returncode) is int and returncode==0 and isinstance(err,bytes)
  and (err==b'' or (label=='unit' and err==expected and isinstance(unit,dict)
   and unit.get('ok') is True and unit.get('originalDisabledConfigWarningExact') is True
   and unit.get('passed')==15 and unit.get('executed')==15)))
"""
template=once(template,'def record(label,child,out,err):',helper+'def record(label,child,out,err):')
template=once(template," need(child.returncode==0 and not err,'actual_fallback_sdk_child_complete_zero')", " need(admitted_child_stderr(label,child.returncode,err,report.get('unitResult')),'actual_fallback_sdk_child_complete_zero')\n if label=='unit':report['originalDisabledWarningBytesAdmitted']=len(err)")
template=once(template,"    and value.get('actualStateAndGatewayDotenvReadsObserved') is True", "    and value.get('originalDisabledConfigWarningExact') is True\n    and value.get('actualStateAndGatewayDotenvReadsObserved') is True")
save('launch_gateway_registration_qualification_r3.template.py',template)
save('assemble_gateway_registration_qualification_r3.py',successor('assemble_gateway_registration_qualification_r2.py'))
print('Created r3 warning-only semantic delta; previous source pins preserved.')
