#!/usr/bin/env python3
"""Finite read-only input admission for the new Mac five-agent outer driver.

No import-time I/O. Four frozen credential/provenance files are the only
pre-existing private input files this library reads. Current SQLite/auth/cache
state belongs to the separately sandboxed capture entry, never this library.
Installed public code is selected from one exact historical successful receipt,
then rehashed now; that does not inherit the receipt's old runtime qualification.
"""
from __future__ import annotations
import base64, copy, hashlib, json, math, os, re, stat, time
from pathlib import Path
from contextlib import contextmanager

BASE=Path('/Volumes/T5/hepta-vnext-recovery-20261013')
ROOT=BASE/'mac-authbus-r10-current-consumer-r1'
LIVE=Path('/Users/qianqi/.openclaw')
PLUGIN=LIVE/'extensions/openclaw-authbus'
SDK=Path('/opt/homebrew/lib/node_modules/openclaw')
CODEX=LIVE/'npm/projects/openclaw-codex-8902d781d4__openclaw-generation__g-49fd4dbfde2c5057/node_modules/@openclaw/codex'
CORE=BASE/'authbus-profile2-selector-c138-20261104-r1'
NORMAL_ROOT=BASE/'continuation-20261104-native-http-r10/normal-release-tests-r1'
BINARY=NORMAL_ROOT/'artifacts/heptabao-server'
BINARY_SHA='bc1fc6b8ded5a43a60ab4c562cd5e092e63ae9df77afd654c9af8c096c128c98'
BINARY_BYTES=93038816
COMMIT='49503322c7f446e5eb41e7744f1fdbd7f1192ecc'
TREE='1d4211f91e1b34a2ed087a3bbef2e2884bac88e9'
PRIVATE_INPUTS={
 'prepare':(CORE/'multisource-prepare-r2/prepare.public.json','bb4f2e2c421102f9a0a31c70db7c26457a97a8a5bfac8227a3e372a2f3923228'),
 'bundle':(CORE/'multisource-prepare-r2/source-bundle.private.json','b38233cb4e0c2838bd26d93afb623c93d984b97930ecc769b4450704343e4957'),
 'profile1_proof':(BASE/'authbus-profile1-source-36076-20261104-r1/source-private/provider-proof.public.json','3050622c35bacb53ac47f532d4d5230c7c5c68bd2db243376c3c27385744a878'),
 'profile2_core':(CORE/'final360-core-r2/result.public.json','3ac84a78cb6f6fb145508adbb6918cf7de40478ec92854eeb4427ec5c04242a7')}
PUBLIC_INPUTS={
 'historical_sources':(CORE/'final360-native-codex-live-r5/result.public.json','6caa9ebfc2a3bf3ae637676a8055022817ec0efa85b09c6ffc304ac854ca6236',2*1024*1024),
 'native_pin':(CORE/'runtime-contract-source-r1/native-pin.public.json','fce8536b33a83b920accd7264991759a13011057cac3502b0ce14fffc075339e',65536),
 'normal':(NORMAL_ROOT/'normal-release-result.public.json','f5746eaf7fd79c8001ac927c9738922297d6e5e575cbd12bc092aafa2c13f544',65536),
 'native_build':(NORMAL_ROOT/'native-build.public.json','16fa488ed8d7a9a46541b5aea5007e27b538e5c37f9246c14de0e5fe24b05ad1',65536)}
GENERATIONS=(
 ('bca88c7adde84057871fd63f202e6aba80d453a04f75151df1d29f269dfaa5f1','332c2cdd98cd0650de22a4506f7f67c3cbc69a9154e0cbafa4344f7a691640b9','c40f74bc2c0190ebb30259e25534f78f7048346814d1a02cd99274340add0606'),
 ('48e095587f180413f65274d6d25d88d4ee6f9f99d981575f54bc4fb3399c286e','899445c0e083199d67988e1db5bc7ac6d4d158bf913bb54669e5afc7714f2fb2','c6b074866138e3ed265414016ed7ba4a88bdbe062e3983269c61be8496f22caa'))
PLUGIN_FILES=('index.js','bad-refresh-quarantine.js','codex-client-recycler.js','lease-assignments.js',
 'order-policy.js','provider-error-classifier.js','runtime-refresh-policy.js','package.json')
SDK_FILES=('package.json','dist/plugin-sdk/agent-runtime.js','dist/store-DH33UrUj.js',
 'dist/source-check-ZSz5NzGW.js','dist/oauth-B4aOCsid.js','dist/order-CeBlX0NH.js',
 'dist/model-auth-CJEm9SNp.js','dist/sqlite-wal-Bhk2Ro-u.js',
 'dist/runtime-registry-loader-Duw3fvRO.js','dist/runtime-registry-loader-d7xui8oD.js',
 'dist/selection-JInn13lc.js','dist/registry-DtLZ3rba.js',
 'dist/windows-spawn-C5RDaB22.js','dist/plugin-sdk/windows-spawn.js')
CODEX_FILES=('dist/shared-client-4ICy3U6d.js','dist/config-CYEDnLJ2.js','dist/index.js',
 'dist/harness.js','openclaw.plugin.json','package.json')
UTILITY_PATHS=('/usr/bin/openssl','/usr/bin/sandbox-exec','/bin/launchctl',
               '/usr/sbin/diskutil','/bin/ps','/sbin/mount')
MAX_CODE=256*1024*1024
MAX_ALL_HASHED=1024*1024*1024
MAX_PUBLIC_CODE_FILES=96

class InputRefused(RuntimeError):pass
def need(value,code):
    if not value:raise InputRefused(code)
def sha(raw):return hashlib.sha256(raw).hexdigest()
def encoded(value):
    return json.dumps(value,sort_keys=True,separators=(',',':'),ensure_ascii=False,allow_nan=False).encode()
def digest(value):return sha(encoded(value))
def identity(s):
    return tuple(str(v) for v in (s.st_dev,s.st_ino,s.st_uid,s.st_gid,s.st_mode,
        s.st_nlink,s.st_size,s.st_mtime_ns,s.st_ctime_ns))
def inode(s):return identity(s)[:6]
def valid_pin(value):return isinstance(value,str) and re.fullmatch('[0-9a-f]{64}',value) is not None
def exact_json(raw):
    def pairs(items):
        value={}
        for key,item in items:
            need(key not in value,'duplicate_json_member');value[key]=item
        return value
    return json.loads(raw,object_pairs_hook=pairs,parse_constant=lambda _:(_ for _ in ()).throw(InputRefused('nonfinite_json')))

class Inputs:
    def __init__(self,guard,signals,until):
        need(guard.uuid_verified and not guard.closed,'t5_before_any_frozen_private_read')
        self.guard=guard;self.signals=signals;self.until=until
        self.rows=[];self.records={};self.code_allowed={};self.aliases={}
        self.total_hashed=0;self.close_errors=[];self.closed=False
        self.private_attempted=False;self.projected=False;self.old_sources=None;self.tools_allowed=set()

    def remaining(self):
        need(not self.closed and self.signals.pending is None,'input_reader_open_uncancelled')
        left=self.until-time.monotonic();need(left>0,'original_outer_input_deadline')
        self.guard.check();return left

    def _close(self,row):
        if row['attempted']:return
        with self.signals.critical():
            row['attempted']=True
            try:os.close(row['fd']);row['closed']=True
            except BaseException as error:
                row['errorType']=type(error).__name__;self.close_errors.append(type(error).__name__)

    @contextmanager
    def parents(self,path):
        self.remaining();path=Path(path)
        need(path.is_absolute() and path==Path(os.path.normpath(str(path))),'normalized_explicit_input_path')
        local=[];parent=None
        try:
            for component in path.parent.parts:
                self.remaining()
                named=os.lstat('/') if parent is None else os.stat(component,dir_fd=parent['fd'],follow_symlinks=False)
                current=Path(component) if parent is None else current/component
                anchor=next((x for x in self.guard.expected['anchors'] if x['path']==str(current)),None)
                need(stat.S_ISDIR(named.st_mode) and named.st_uid in (0,501)
                     and (identity(named)==tuple(anchor['identity']) if anchor is not None
                          else not (stat.S_IMODE(named.st_mode)&0o022)),
                     'readonly_input_parent_custody_or_exact_held_anchor')
                with self.signals.critical():
                    fd=os.open('/' if parent is None else component,
                        os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,
                        **({} if parent is None else {'dir_fd':parent['fd']}))
                    row={'fd':fd,'parent':parent,'name':component,'identity':inode(named),
                         'attempted':False,'closed':False};self.rows.append(row);local.append(row)
                need(inode(os.fstat(fd))==row['identity'],'readonly_input_parent_fd')
                parent=row
            yield parent['fd'],path.name
            self.remaining()
            for row in local:
                named=os.lstat('/') if row['parent'] is None else os.stat(
                    row['name'],dir_fd=row['parent']['fd'],follow_symlinks=False)
                need(inode(named)==inode(os.fstat(row['fd']))==row['identity'],'readonly_input_parent_changed')
        finally:
            for row in reversed(local):self._close(row)
            need(all(r['closed'] for r in local),'readonly_parent_close')

    def _file(self,path,pin,cap,*,private,collect,record=True):
        self.remaining();path=Path(path)
        need(valid_pin(pin) and type(cap) is int and 0<cap<=MAX_CODE,'bounded_pinned_read')
        fdrow=None
        with self.parents(path) as (parent,name):
            try:
                with self.signals.critical():
                    fd=os.open(name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=parent)
                    fdrow={'fd':fd,'attempted':False,'closed':False};self.rows.append(fdrow)
                before=os.fstat(fd)
                need(stat.S_ISREG(before.st_mode) and 0<before.st_size<=cap
                     and not stat.S_IMODE(before.st_mode)&0o022
                     and (before.st_uid==501 and before.st_nlink==1 and stat.S_IMODE(before.st_mode)==0o600
                          if private else before.st_uid in (0,501) and before.st_nlink>=1),
                     'finite_input_file_custody')
                if path.is_relative_to(BASE):
                    need(before.st_dev==int(self.guard.expected['expectedVolumeDevice']),'same_t5_input_device')
                h=hashlib.sha256();raw=bytearray();count=0
                while count<=before.st_size:
                    self.remaining();chunk=os.read(fd,min(1024*1024,before.st_size+1-count))
                    if not chunk:break
                    count+=len(chunk);self.total_hashed+=len(chunk)
                    need(self.total_hashed<=MAX_ALL_HASHED,'one_outer_aggregate_input_hash_bound')
                    h.update(chunk)
                    if collect:raw.extend(chunk)
                named=os.stat(name,dir_fd=parent,follow_symlinks=False)
                need(count==before.st_size and identity(before)==identity(os.fstat(fd))==identity(named)
                     and h.hexdigest()==pin,'finite_input_whole_sha_and_name_fd')
                value={'path':str(path),'bytes':count,'sha256':pin,'identity':list(identity(before)),
                       'private':private,'cap':cap}
                if str(path) in self.records:need(value==self.records[str(path)],'same_original_input_identity')
                elif record:self.records[str(path)]=value
                self.remaining()
                return bytes(raw) if collect else value
            finally:
                if fdrow is not None:self._close(fdrow)
                need(fdrow is None or fdrow['closed'],'finite_input_close')

    def read_private(self,name):
        need(name in PRIVATE_INPUTS,'only_four_frozen_credential_provenance_inputs')
        path,pin=PRIVATE_INPUTS[name];self.private_attempted=True
        return self._file(path,pin,1024*1024,private=True,collect=True)

    def read_public(self,name):
        need(name in PUBLIC_INPUTS,'only_fixed_public_receipt_inputs')
        path,pin,cap=PUBLIC_INPUTS[name]
        return self._file(path,pin,cap,private=False,collect=True)

    def _admit_code(self,path,pin):
        path=Path(path);need(valid_pin(pin) and path.is_absolute()
            and path==Path(os.path.normpath(str(path))),'public_code_pin_shape')
        allowed=(path==BINARY or str(path) in self.tools_allowed or path.is_relative_to(Path('/opt/homebrew'))
             or path.is_relative_to(PLUGIN) or path.is_relative_to(LIVE/'npm/projects'))
        need(allowed and (path==BINARY or path.suffix not in ('.sqlite','.db','.pem','.key'))
             and path.name not in ('auth.json','openclaw.json'),'finite_public_code_scope')
        if str(path) in self.code_allowed:need(self.code_allowed[str(path)]==pin,'one_code_pin')
        else:
            need(len(self.code_allowed)<MAX_PUBLIC_CODE_FILES,'finite_public_code_count')
            self.code_allowed[str(path)]=pin

    def pin_code(self,path,*,collect=False):
        path=Path(path);need(str(path) in self.code_allowed,'explicit_admitted_code_only')
        pin=self.code_allowed[str(path)]
        before=identity(path.lstat());resolved=path.resolve(strict=True)
        need(resolved==BINARY if path==BINARY else (
            resolved.is_relative_to(Path('/opt/homebrew')) or resolved.is_relative_to(PLUGIN)
            or resolved.is_relative_to(LIVE/'npm/projects') or (str(path) in self.tools_allowed
                and any(resolved.is_relative_to(Path(p)) for p in ('/System','/usr','/bin','/sbin')))),
             'resolved_public_code_scope')
        cap=8*1024*1024 if collect else MAX_CODE
        value=self._file(resolved,pin,cap,private=False,collect=collect)
        need(identity(path.lstat())==before and path.resolve(strict=True)==resolved,'fixed_code_alias_before_after')
        alias={'path':str(path),'resolved':str(resolved),'identity':list(before),'sha256':pin}
        if str(path) in self.aliases:need(alias==self.aliases[str(path)],'original_public_code_alias')
        else:self.aliases[str(path)]=alias
        self.remaining();return value

    def admit_utilities(self,pins):
        need(isinstance(pins,dict) and set(pins)==set(UTILITY_PATHS)
             and all(valid_pin(v) for v in pins.values()),'actual_exact_six_public_utility_pins_required')
        self.tools_allowed=set(UTILITY_PATHS)
        for path,pin in pins.items():self._admit_code(path,pin);self.pin_code(path)
        return dict(pins)

    def project_frozen(self):
        need(not self.projected,'frozen_projection_once')
        self.projected=True
        raw={name:self.read_private(name) for name in PRIVATE_INPUTS}
        values={name:exact_json(value) for name,value in raw.items()}
        p,bundle,proof1,proof2=(values[k] for k in ('prepare','bundle','profile1_proof','profile2_core'))
        need(isinstance(p,dict) and p.get('ok') is True and len(p.get('checks',[]))==16
             and all(x.get('passed') is True for x in p['checks'])
             and p.get('sourceBundleSha256')==PRIVATE_INPUTS['bundle'][1],'exact_successful_frozen_prepare')
        need(proof1.get('single_current_credential_provider_validated') is True
             and proof1.get('selected_source_sha256')==GENERATIONS[0][0]
             and proof1.get('jwt_account_matches_stored') is True and proof1.get('source_custody_verified') is True
             and proof1.get('source_unchanged') is True and proof1.get('provider_read',{}).get('httpStatus')==200
             and proof1.get('provider_read',{}).get('tlsVerified') is True,'frozen_profile1_proof')
        need(proof2.get('ok') is True and proof2.get('selectedCredentialSha256')==GENERATIONS[1][0]
             and proof2.get('priorProviderCredentialBindingQualified') is True
             and proof2.get('providerValidationLink',{}).get('credentialAndResolvedAccessByteIdentical') is True
             and proof2.get('providerValidationLink',{}).get('reused') is True,'frozen_profile2_proof')
        ids=bundle.get('targetProfileIds');credentials=bundle.get('credentials')
        need(isinstance(ids,list) and len(ids)==len(set(ids))==2 and isinstance(credentials,dict)
             and set(credentials)==set(ids),'two_original_target_ids')
        projected={};public=[];now=time.time()
        for ordinal,(pid,pins) in enumerate(zip(ids,GENERATIONS),1):
            c=credentials[pid]
            need(isinstance(pid,str) and 0<len(pid)<=240 and isinstance(c,dict)
                 and c.get('provider')=='openai' and c.get('type')=='oauth'
                 and digest(c)==pins[0] and sha(c['accountId'].encode())==pins[1]
                 and sha(c['access'].encode())==pins[2],'same_frozen_credential_generation')
            claims=exact_json(base64.urlsafe_b64decode(c['access'].split('.')[1]+'==='))
            need(claims['https://api.openai.com/auth']['chatgpt_account_id']==c['accountId']
                 and claims['exp']>now+900 and c['expires']>now*1000+900000
                 and isinstance(c.get('refresh'),str) and bool(c['refresh']),
                 'frozen_generation_identity_or_expiry_no_refresh_fallback')
            provenance=p['sources'][ordinal-1]
            need(provenance['destinationOrdinal']==ordinal and provenance['credentialSha256']==pins[0]
                 and provenance['accountIdSha256']==pins[1],'original_ordinal_provenance')
            projected[pid]=copy.deepcopy(c)
            public.append({'ordinal':ordinal,'profileIdSha256':sha(pid.encode()),
                'credentialSha256':pins[0],'accountIdSha256':pins[1],'accessSha256':pins[2],
                'expiresUnixMs':c['expires'],'identityClaimMatches':True,'expiryFuture':True})
        for name in PRIVATE_INPUTS:need(self.read_private(name)==raw[name],'four_original_frozen_after_fences')
        return {'targetProfileIds':list(ids),'credentials':projected}, {
            'schema':'heptabao.mac-current-frozen12-projection.r3','projectedProfiles':public,
            'sourceGeneration':'frozen_previously_verified_generation','latestActiveGenerationClaimed':False,
            'providerAvailabilityQualified':False,'providerCalled':False,'refreshCalled':False,
            'copiedUsageOrderOrExcludedProfiles':False}

    def normal_and_base_sources(self):
        normal_raw=self.read_public('normal');native_raw=self.read_public('native_build')
        normal=exact_json(normal_raw);native=exact_json(native_raw)
        need(normal.get('schema')=='heptabao.native-default-build-result.v1'
             and normal.get('source_commit')==COMMIT and normal.get('source_tree')==TREE
             and normal.get('normal_default_candidate') is True and normal.get('source_freeze_verified') is True
             and normal.get('build_exit_code')==0 and normal.get('build_finished_success') is True
             and normal.get('timed_out') is False and normal.get('native_abi')=='aarch64-apple-darwin',
             'actual_normal_mac_build')
        need(native.get('schema')=='heptabao.native-build.v1' and native.get('source_commit')==COMMIT
             and native.get('source_tree')==TREE and native.get('binary_sha256')==BINARY_SHA
             and native.get('build_exit_code')==0 and native.get('source_freeze_verified') is True
             and native.get('native_abi')=='aarch64-apple-darwin'
             and native.get('features')==['default','native-v6-ha','native-v6-storage']
             and native.get('provenance',{}).get('result_path')==str(PUBLIC_INPUTS['normal'][0])
             and native.get('provenance',{}).get('result_sha256')==sha(normal_raw),'actual_mac_native_build_provenance')
        artifact=normal['artifacts']['heptabao-server']
        need(artifact.get('path')==str(BINARY) and artifact.get('sha256')==BINARY_SHA
             and artifact.get('bytes')==BINARY_BYTES
             and artifact.get('features')==native['features']
             and artifact.get('profile',{}).get('opt_level')=='3'
             and artifact['profile'].get('test') is False and artifact['profile'].get('debug_assertions') is True
             and artifact['profile'].get('overflow_checks') is True,'exact_normal_mac_artifact')
        self._admit_code(BINARY,BINARY_SHA);binary=self.pin_code(BINARY)
        need(binary['bytes']==BINARY_BYTES,'normal_binary_actual_size')
        old=exact_json(self.read_public('historical_sources'))
        need(old.get('ok') is True and isinstance(old.get('sourcePins'),dict),'whole_historical_successful_source_inventory')
        self.old_sources=old['sourcePins']
        required=[*[PLUGIN/name for name in PLUGIN_FILES],*[SDK/name for name in SDK_FILES],
                  *[CODEX/name for name in CODEX_FILES]]
        for path in required:
            need(valid_pin(self.old_sources.get(str(path))),'historical_exact_installed_code_pin')
            self._admit_code(path,self.old_sources[str(path)])
        native_pin=exact_json(self.read_public('native_pin'))
        for kind in ('launcher','native','package','nativePackage'):
            item=native_pin[kind]
            need(isinstance(item,dict) and isinstance(item.get('path'),str)
                 and valid_pin(item.get('sha256')),'actual_native_contract_source')
            self._admit_code(item['path'],item['sha256'])
        node=Path('/opt/homebrew/bin/node');resolved=node.resolve(strict=True)
        need(valid_pin(self.old_sources.get(str(resolved))),'actual_node_from_exact_original_inventory')
        self._admit_code(node,self.old_sources[str(resolved)])
        for path in list(self.code_allowed):
            if Path(path)!=BINARY:self.pin_code(path)
        need(self.code_allowed[str(CODEX/'dist/shared-client-4ICy3U6d.js')]=='bff60f1bb2cb73ad44c7f9c9d779576a2ffd9836b22ecba0bd5b6046e7ce9103'
             and self.code_allowed[str(SDK/'dist/selection-JInn13lc.js')]=='ccff13111aa60369ac9d88b526a58a7df1f733f1d99d205c01c6186036957e66',
             'actual_original_factory_and_selector')
        command=CODEX/'node_modules/.bin/codex'
        need(command.resolve(strict=True)==Path(native_pin['launcher']['path']),'actual_original_native_command_target')
        self.aliases[str(command)]={'path':str(command),'resolved':str(command.resolve(strict=True)),
            'identity':list(identity(command.lstat())),'sha256':native_pin['launcher']['sha256']}
        return {'sdkRoot':str(SDK),'codexRoot':str(CODEX),
            'pluginEntry':str(ROOT/'installed-plugin-copy/index.js'),
            'nativeCommand':str(command),'nativeLauncher':native_pin['launcher']['path'],
            'nativeBinary':native_pin['native']['path']}, {
            'normalReceiptSha256':sha(normal_raw),'nativeReceiptSha256':sha(native_raw),
            'binarySha256':BINARY_SHA,'sourceCommit':COMMIT,'sourceTree':TREE,
            'historicalSourceQualificationInherited':False,'currentSelectedSourcePinsRehashed':True}

    def admit_actual_harnesses(self,registry,runtime):
        need(self.old_sources is not None,'source_inventory_before_actual_registry')
        columns=registry['columns'];row=registry['row']
        plugins=exact_json(row[columns.index('plugins_json')])
        need(isinstance(plugins,list) and len(plugins)<=128,'bounded_actual_registry_plugins')
        enabled=[p for p in plugins if isinstance(p,dict) and p.get('enabled') is True
                 and isinstance(p.get('startup'),dict) and p['startup'].get('agentHarnesses')]
        need(1<=len(enabled)<=8,'finite_actual_enabled_harness_roots')
        roots=[];ids={'openai'}
        for plugin in enabled:
            identifier=plugin.get('pluginId');root=Path(plugin.get('rootDir',''))
            need(isinstance(identifier,str) and re.fullmatch('[a-z0-9][a-z0-9_.-]{0,79}',identifier)
                 and root.is_absolute() and root==Path(os.path.normpath(str(root)))
                 and root.is_relative_to(LIVE/'npm/projects'),'actual_finite_harness_code_root')
            need(root not in roots,'unique_actual_harness_roots');roots.append(root);ids.add(identifier)
            for name in ('openclaw.plugin.json','package.json','dist/index.js'):
                path=root/name
                if name=='dist/index.js' and str(path) not in self.old_sources:continue
                need(valid_pin(self.old_sources.get(str(path))),'historically_pinned_actual_harness_metadata')
                self._admit_code(path,self.old_sources[str(path)]);self.pin_code(path)
        updated=dict(runtime);updated['harnessOwnerPluginIds']=sorted(ids)
        updated['harnessCodeRoots']=[str(path) for path in sorted(roots,key=str)]
        return updated

    def verify(self):
        self.remaining()
        for path,value in list(self.records.items()):
            self._file(Path(path),value['sha256'],value['cap'],private=value['private'],
                       collect=False,record=False)
        for path,value in self.aliases.items():
            need(identity(Path(path).lstat())==tuple(value['identity'])
                 and str(Path(path).resolve(strict=True))==value['resolved'],'all_original_code_aliases_after')
        self.remaining();return True

    def public_pins(self):
        return {path:value for path,value in self.code_allowed.items()
                if Path(path)!=BINARY and path not in self.tools_allowed}

    def close(self):
        if self.closed:return
        for row in reversed(self.rows):self._close(row)
        self.closed=True

    def public(self):
        return {'schema':'heptabao.mac-finite-current-input-admission.r3',
            'privateFrozenInputsAttempted':self.private_attempted,'projectionAttemptedOnce':self.projected,
            'readOnlySourceRecordCount':len(self.records),'selectedPublicCodeCount':len(self.code_allowed),
            'totalHashedBytes':self.total_hashed,'newAggregateHashByteBound':MAX_ALL_HASHED,
            'sourceRecords':list(self.records.values()),'publicCodeAliases':list(self.aliases.values()),
            'allOwnedInputDescriptorsClosed':all(row['closed'] for row in self.rows),
            'closeErrors':list(self.close_errors),'currentProductionDatabasesOpened':False,
            'providerRequested':False,'refreshRequested':False,'j3160Contacted':False,
            'dylibDependencyGraphQualified':False}
