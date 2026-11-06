"""Offline byte/lexical SOURCE checks. This is not a Rust parser or test run."""
from pathlib import Path
import difflib
import functools
import hashlib
import json
import re

ROOT = Path(__file__).resolve().parent
checks = []
def check(name, ok, detail=None):
    checks.append({'name': name, 'passed': bool(ok), 'detail': detail})
    if not ok:
        raise AssertionError(name)
def meta(data):
    return {'bytes': len(data), 'sha256': hashlib.sha256(data).hexdigest(),
            'blob': hashlib.sha1(b'blob '+str(len(data)).encode()+b'\0'+data).hexdigest()}
def read(area, name):
    return (ROOT/area/name).read_text()
RAW = re.compile(r'(?:br|r)(#*)"')
CHAR = re.compile(r"'(?:\\u\{[0-9a-fA-F_]+\}|\\x[0-9a-fA-F]{2}|\\.|[^'\\\n])'")
@functools.lru_cache(maxsize=128)
def mask_rust(text):
    """Hide comments/string/char contents, preserving byte positions/newlines."""
    out = list(text); i = 0
    def hide(a, b):
        for k in range(a, b):
            if out[k] != '\n': out[k] = ' '
    while i < len(text):
        start = i
        if text.startswith('//', i):
            j = text.find('\n', i); i = len(text) if j < 0 else j
        elif text.startswith('/*', i):
            i += 2; depth = 1
            while depth and i < len(text):
                if text.startswith('/*', i): depth += 1; i += 2
                elif text.startswith('*/', i): depth -= 1; i += 2
                else: i += 1
            assert depth == 0
        else:
            raw = RAW.match(text, i)
            char = CHAR.match(text, i)
            if raw:
                end = '"' + raw[1]; j = text.find(end, i+len(raw[0])); assert j >= 0
                i = j+len(end)
            elif text[i] == '"':
                i += 1
                while i < len(text):
                    if text[i] == '\\': i += 2
                    elif text[i] == '"': i += 1; break
                    else: i += 1
            elif char: i += len(char[0])
            else: i += 1; continue
        hide(start, i)
    return ''.join(out)
def balanced(mask, opening):
    assert mask[opening] == '{'; level = 0
    for i in range(opening, len(mask)):
        if mask[i] == '{': level += 1
        elif mask[i] == '}':
            level -= 1
            if level == 0: return i+1
    raise AssertionError('unclosed lexical body')
@functools.lru_cache(maxsize=128)
def functions(text):
    mask = mask_rust(text); result = {}
    for match in re.finditer(r'\bfn\s+(\w+)\s*(?:<|\()', mask):
        opening = mask.find('{', match.end()); semi = mask.find(';', match.end())
        if opening < 0 or (semi >= 0 and semi < opening): continue
        end = balanced(mask, opening)
        result.setdefault(match[1], []).append(text[match.start():end])
    return result
def declaration(text, name):
    mask = mask_rust(text); m = re.search(r'\b(?:struct|enum)\s+'+name+r'\b', mask)
    assert m is not None; opening = mask.index('{', m.end())
    return text[m.start():balanced(mask, opening)]
def one(text, name):
    values = functions(text)[name]; assert len(values) == 1, name
    return values[0]

try:
    base = json.loads((ROOT/'BASE.public.json').read_text())
    trees = {p.stem: json.loads(p.read_text()) for p in (ROOT/'canonical-trees').glob('*.json')}
    for name, tree in trees.items():
        entries = sorted(tree['tree'], key=lambda e: (e['path']+('/' if e['type']=='tree' else '')).encode())
        raw = b''.join((('40000' if e['type']=='tree' else e['mode'])+' '+e['path']).encode()
                       + b'\0'+bytes.fromhex(e['sha']) for e in entries)
        actual = hashlib.sha1(b'tree '+str(len(raw)).encode()+b'\0'+raw).hexdigest()
        check('canonical-merkle:'+name, actual == tree['sha'])
    check('canonical-root', trees['root']['sha'] == base['base_tree'])
    for parent, member, child in [('root','crates','crates'),('crates','heptabao-server','heptabao-server'),('heptabao-server','src','src')]:
        check('canonical-link:'+member, next(e['sha'] for e in trees[parent]['tree'] if e['path']==member)==trees[child]['sha'])
    src = {e['path']: e for e in trees['src']['tree']}
    for row in base['files']:
        name = Path(row['path']).name; actual = meta((ROOT/'before'/name).read_bytes())
        check('pinned-before:'+name, actual == {k:row[k] for k in actual} and src[name]['sha']==row['blob'])
    expected = {'auth.rs','auth_native_v6_routes.rs','federated_auth.rs','federated_native_jwt.rs',
                'service.rs','service_native_auth.rs','service_native_userpass_tests.rs'}
    old = {p.name:p.read_text() for p in (ROOT/'before').glob('*.rs')}
    new = {p.name:p.read_text() for p in (ROOT/'candidate').glob('*.rs')}
    check('exact-modified-seven', {n for n in old if old[n]!=new[n]} == expected)
    check('exact-new-two', set(new)-set(old) == {'auth_native_jwt.rs','service_native_jwt_tests.rs'})
    allowed = {
        'auth.rs': {'handle_with_connection_clock_for_cluster','jwt_route'},
        'auth_native_v6_routes.rs': {'native_v6_storage_profile','native_v6_local_auth_route'},
        'federated_auth.rs': set(), 'federated_native_jwt.rs': {'verify_native_with_user_claim'},
        'service.rs': {'dispatch_authorized_subrequest','dispatch_native_authorized_subrequest','dispatch_authorized_subrequest_inner'},
        'service_native_auth.rs': {'requires_local_proof','tracks_terminal_checkpoint','check_source','check_owner','check_reply_auth',
            'dispatch_native_auth_request','dispatch_native_owner_request_with_pki','complete_native_auth_delivery'},
        'service_native_userpass_tests.rs': {'native_userpass_selector_keeps_other_providers_and_wrapped_login_closed'},
    }
    changed_functions = {}
    unchanged_count = 0
    for name in old:
        of, nf = functions(old[name]), functions(new[name]); changed = []
        for fn, bodies in of.items():
            check('existing-function-present:'+name+':'+fn, fn in nf and len(bodies)==len(nf[fn]))
            if bodies != nf[fn]: changed.append(fn)
            else: unchanged_count += len(bodies)
        changed_functions[name] = changed
        check('function-change-scope:'+name, set(changed) <= allowed.get(name,set()), changed)
    for name in ['AuthState','AuthResponse','Token']:
        check('unchanged-auth-declaration:'+name, declaration(old['auth.rs'],name)==declaration(new['auth.rs'],name))
    check('unchanged-login-identity-module', meta((ROOT/'reference/auth_identity.rs').read_bytes())['blob']==src['auth_identity.rs']['sha']
          and 'auth_identity.rs' not in new)
    for name in ['State','Response','Service']:
        check('unchanged-service-declaration:'+name, declaration(old['service.rs'],name)==declaration(new['service.rs'],name))
    check('userpass-only-provider-literal', new['service_native_userpass_tests.rs'] == old['service_native_userpass_tests.rs'].replace(
        '("sys/auth/other", json!({"type":"jwt"}))','("sys/auth/other", json!({"type":"oidc"}))'))
    vf = one(new['federated_native_jwt.rs'],'verify_native_with_user_claim_and_lifetime')
    check('one-actual-verifier-in-new-body', vf.count('self.verified_claims(token)?')==1)
    check('numericdate-parser-unchanged', one(old['federated_native_jwt.rs'],'numeric_date')==one(new['federated_native_jwt.rs'],'numeric_date'))
    check('lifetime-not-serialized', 'Serialize' not in declaration(new['federated_native_jwt.rs'],'NativeJwtLifetime'))
    check('ordinary-verifier-wrapper-one', one(new['federated_native_jwt.rs'],'verify_native_with_user_claim').count('verify_native_with_user_claim_and_lifetime(')==1)
    auth_inner = one(new['auth.rs'],'jwt_route_with_native_lifetime')
    check('exclusive-verifier-branches', auth_inner.count('verifier.verify_native_with_user_claim_and_lifetime(')==1
          and auth_inner.count('verifier.verify_native_with_user_claim(')==1 and 'if native_lifetime.is_some()' in auth_inner)
    check('lifetime-export-last-auth-success', auth_inner.index('*output = lifetime;') > auth_inner.index('.insert(identity_key, identity)'))
    check('ordinary-auth-wrapper-none', one(new['auth.rs'],'handle_with_connection_clock_for_cluster').count('cluster_id, None,')==1)
    check('ordinary-jwt-wrapper-none', 'now, None)' in one(new['auth.rs'],'jwt_route'))
    si = one(new['service.rs'],'dispatch_authorized_subrequest_inner')
    check('service-fresh-slot-guard', 'native_jwt_lifetime.as_deref().is_some_and(Option::is_some)' in si)
    check('service-local-slot-none', si.count('let mut authenticated_jwt_lifetime = None;')==1)
    check('export-after-identity-and-state-install', si.index('*output = authenticated_jwt_lifetime;') > si.index('Self::finish_identity_response_observed(')
          and si.index('*output = authenticated_jwt_lifetime;') > si.index('state.engines = engines;'))
    check('only-successful-slot-export', 'if response.status == 200 && let Some(output) = native_jwt_lifetime' in si)
    check('ordinary-service-wrapper-none', 'false,\n            None,' in one(new['service.rs'],'dispatch_authorized_subrequest'))
    native = new['service_native_auth.rs']; dispatch = one(native,'dispatch_native_owner_request_with_pki')
    check('native-local-slot-none', dispatch.count('let mut jwt_lifetime = None;')==1)
    check('slot-consumed-once', dispatch.count('jwt_lifetime.take()')==1)
    check('unexpected-slot-fails', 'if jwt_lifetime.is_some() {' in dispatch)
    check('response-bound-before-plan', dispatch.index('delivery.jwt_reply = Some(digest)') < dispatch.index('self.prepare_native_live_root_checked'))
    check('only-signed-lifetime-owner', 'verify_native' not in new['auth_native_jwt.rs'] and 'JwtVerifier' not in new['auth_native_jwt.rs'])
    check('no-new-external-owner', all(t not in new['auth_native_jwt.rs'] for t in ['std::process','TcpStream','Outbound','reqwest','spawn(']))
    owner = new['auth_native_jwt.rs']
    for phrase in ['namespace.is_empty()', 'config.remote.is_none()', '!self.jwt_uses_batch',
                   'token.namespace.is_empty()', 'source.tokens.contains_key(&digest)',
                   'token.parent.is_some()', 'token.entity_id.as_deref()', 'login_lifetime: None']:
        check('closed-jwt-boundary:'+phrase, phrase in owner)
    check('legacy-role-acl-mapping', '(true, "GET" | "LIST") => "list"' in owner
          and '(false, "POST" | "PUT" | "DELETE") => "update"' in owner
          and 'owner.sudo = !collection && method != "GET";' in owner)
    for fn in ['requires_local_proof','tracks_terminal_checkpoint','check_owner','check_source','check_reply_auth','complete_native_auth_delivery']:
        check('jwt-retains-existing-custody:'+fn, 'jwt_owner' in one(native,fn))
    # Original numeric-deadline definitions stay outside the nine changed files;
    # no retry loop, new production timer or publication order was introduced.
    check('original-native-clock-function', one(old['service_native_auth.rs'],'time')==one(native,'time'))
    check('original-postcommit-audit-function', one(old['service.rs'],'audit_completed_response_with_receipt')==one(new['service.rs'],'audit_completed_response_with_receipt'))
    check('actual-native-commit-still-used', 'self.commit_native_root_plan(&candidate, plan, false, purpose' in dispatch)
    check('private-test-hook-only', '#[cfg(test)]\n        if delivery.jwt_owner.as_ref()' in dispatch)
    tests = new['service_native_jwt_tests.rs']
    test_names = re.findall(r'#\[test\]\s*fn\s+(\w+)', tests)
    check('ten-independent-new-regressions', len(test_names)==10 and len(set(test_names))==10, test_names)
    check('actual-native-config-and-activation', 'NativeStorageProfile::File' in tests and 'native_storage::ACTIVATE_PATH' in tests)
    for phrase in ['no_credential', 'PublicationPause::once', 'opaque_owner_capacity', 'audit_capacity',
                   'pending_native_auth_delivery.take()', 'NativeProof::Single', 'f.restart()',
                   'recovery_required', 'before.as_slice() == f.snapshot()?.as_slice()']:
        check('regression-boundary:'+phrase, phrase in tests)
    diffs = {}; (ROOT/'diffs').mkdir(exist_ok=True)
    for name in sorted(set(old)|set(new)):
        if old.get(name,'') == new[name]: continue
        delta = ''.join(difflib.unified_diff(old.get(name,'').splitlines(True),new[name].splitlines(True),
                    fromfile='a/crates/heptabao-server/src/'+name,tofile='b/crates/heptabao-server/src/'+name))
        (ROOT/'diffs'/f'{name}.diff').write_text(delta)
        # Line-range splice proof includes exact old/deleted bytes. The
        # upload helper can reconstruct large candidates without truncated I/O.
        old_lines=old.get(name,'').splitlines(True);new_lines=new[name].splitlines(True)
        matcher=difflib.SequenceMatcher(a=old_lines,b=new_lines,autojunk=False)
        edits=[{'start_line':i,'end_line':j,'before':''.join(old_lines[i:j]),'after':''.join(new_lines[k:l])}
               for tag,i,j,k,l in matcher.get_opcodes() if tag!='equal']
        reconstructed=old_lines[:]
        for e in reversed(edits):
            check('splice-before:'+name+':'+str(e['start_line']), ''.join(reconstructed[e['start_line']:e['end_line']])==e['before'])
            reconstructed[e['start_line']:e['end_line']]=e['after'].splitlines(True)
        check('splice-whole:'+name, ''.join(reconstructed)==new[name])
        diffs[name]={'before':meta(old[name].encode()) if name in old else None,'after':meta(new[name].encode()),
                     'delta':delta,'edits':edits}
    (ROOT/'SOURCE.splice-inputs.json').write_text(json.dumps(diffs,ensure_ascii=False,indent=2)+'\n')
    result={'schema':'heptabao.native-jwt-source-review.v1','status':'PASS_SOURCE_CHECKS_ONLY',
        'base_commit':base['base_commit'],'runtime_calls':0,'rust_compile':False,'rust_tests_run':0,'rustfmt_run':False,
        'check_count':len(checks),'unchanged_existing_function_definitions':unchanged_count,
        'changed_functions':changed_functions,'new_test_names':test_names,'checks':checks}
except BaseException as e:
    result={'status':'FAIL_SOURCE_CHECKS','error':repr(e),'check_count':len(checks),'checks':checks}
    (ROOT/'VERIFY.failure.public.json').write_text(json.dumps(result,indent=2)+'\n')
    raise
else:
    (ROOT/'VERIFY.result.public.json').write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps({k:v for k,v in result.items() if k not in ['checks','changed_functions','new_test_names']}))
