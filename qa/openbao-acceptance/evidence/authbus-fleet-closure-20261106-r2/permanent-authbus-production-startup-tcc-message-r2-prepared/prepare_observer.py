"""Derive an exact-message historical query from the closed original observer."""
from pathlib import Path
import ast, difflib, hashlib, json

HERE = Path(__file__).resolve().parent
original_template = (HERE / 'observe_permanent_startup_systemlog_r1.template.py').read_text()
old = (HERE / 'observe_permanent_startup_systemlog_r1.py').read_bytes()
assert len(old) == 34187 and hashlib.sha256(old).hexdigest() == 'b611efa5ea07a6438dab325511dd9a17db957de15761954509162179ac8fe134'
tree = ast.parse(old)
payloads = [ast.literal_eval(node.value) for node in tree.body if isinstance(node,ast.Assign)
    and len(node.targets)==1 and isinstance(node.targets[0],ast.Name) and node.targets[0].id=='PAYLOAD']
assert len(payloads)==1
payload = payloads[0]

text = original_template.replace('service-startup-systemlog-r1', 'service-startup-tcc-message-r2')
text = text.replace('heptabao.permanent-startup-fixed-systemlog-observation.r1',
                    'heptabao.permanent-startup-exact-tcc-message-observation.r2')
old_predicate = 'PREDICATE=\'(process == "tccd" OR process == "syspolicyd" OR process == "amfid" OR process == "launchd") AND (eventMessage CONTAINS[c] "19077" OR eventMessage CONTAINS[c] "org.heptabao.authbus" OR eventMessage CONTAINS[c] "heptabao-server")\''
assert text.count(old_predicate)==1
text = text.replace(old_predicate,
    'PREDICATE=\'process == "tccd" AND eventMessage CONTAINS "9253.2991"\'')
text = text.replace("'causalityEstablishedByMarkerAlone':False,'automaticRetry':False}",
    "'causalityEstablishedByMarkerAlone':False,'automaticRetry':False,\n"
    "    'exactMessageIdFromOriginalEvent24':'9253.2991',\n"
    "    'originalMessageIdProjectionJob':'1a1b41be710-fc05-864d',\n"
    "    'messagesHavePathsAndLongIdentifiersRedacted':True}")
start = text.index('    events=json.loads(out)')
end = text.index('    for path,pin in tools.items():',start)
replacement = r'''    events=json.loads(out)
    need(type(events)is list and 0<len(events)<=64,'bounded_exact_message_systemlog_array')
    projected=[]
    services={'all_files':'kTCCServiceSystemPolicyAllFiles',
              'removable_volume':'kTCCServiceSystemPolicyRemovableVolumes'}
    for ordinal,event in enumerate(events):
        need(type(event)is dict and type(event.get('eventMessage'))is str
             and Path(event.get('processImagePath','')).name=='tccd',
             'selected_original_tccd_event')
        message=event['eventMessage']
        need(message.isascii() and 0<len(message)<=8192 and '9253.2991' in message,
             'exact_original_message_id_and_bound')
        need(not re.search(r'(?i)(access_token|refresh_token|root_token|keys_base64|bearer |password|authorization:)',message),
             'unexpected_sensitive_message_refused')
        redacted=message.replace(BINARY,'<original-binary>')
        redacted=redacted.replace(services['all_files'],'<all-files>')
        redacted=redacted.replace(services['removable_volume'],'<removable-volume>')
        redacted=re.sub(r'(?:/[A-Za-z0-9._@%+=~:-]+)+','<redacted-path>',redacted)
        redacted=re.sub(r'(?i)\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b','<redacted-id>',redacted)
        redacted=re.sub(r'(?i)\b0x[0-9a-f]+\b','<redacted-address>',redacted)
        redacted=re.sub(r'\b[A-Za-z0-9_+./=-]{24,}','<redacted-long-id>',redacted)
        need('/Volumes/' not in redacted and '/Users/' not in redacted
             and not re.search(r'(?i)\b[0-9a-f]{32,}\b',redacted),'redacted_message_only')
        projected.append({'ordinal':ordinal,'actor':'tccd','exactOriginalMessageId':True,
            'originalPidTextPresent':'19077' in message,'exactBinaryPathPresent':BINARY in message,
            'servicesPresent':[key for key,value in services.items() if value in message],
            'messageRedacted':redacted,
            'observedAuthValueFields':[int(v) for v in re.findall(r'\bauthValue[=: ]+(\d{1,2})\b',message)],
            'observedAuthReasonFields':[int(v) for v in re.findall(r'\bauthReason[=: ]+(\d{1,2})\b',message)]})
'''
text = text[:start]+replacement+text[end:]
source = text.replace('# PAYLOAD_PLACEHOLDER','PAYLOAD='+repr(payload))
ast.parse(text);ast.parse(source)
for name,body in payload['sources'].items():
    b=body.encode();assert len(b)==payload['pins'][name]['bytes'] and hashlib.sha256(b).hexdigest()==payload['pins'][name]['sha256']
template_path = HERE/'observe_startup_tcc_message_r2.template.py'
source_path = HERE/'observe_startup_tcc_message_r2.py'
diff_path = HERE/'startup-systemlog-to-exact-tcc-message-r2.diff'
for path in (template_path,source_path,diff_path): assert not path.exists()
template_path.write_text(text)
source_path.write_text(source)
diff_path.write_text(''.join(difflib.unified_diff(original_template.splitlines(True),text.splitlines(True),
    fromfile='original-fixed-systemlog-r1.template.py',tofile='exact-observed-message-r2.template.py')))
raw=source.encode()
print(json.dumps({'path':str(source_path),'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest(),
    'parentSeconds':45,'logQuerySeconds':20,'supervisorSeconds':70,'sameClosedOriginalWindowSeconds':35,
    'exactOriginalMessageId':'9253.2991','serviceActions':0,'providerCalls':0,'permissionSettingsChanged':False,
    'sources':payload['pins'],'source':source},sort_keys=True))
