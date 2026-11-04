#!/usr/bin/env python3
"""Read-only installed runtime/config audit; no native app-server or OAuth call.

This receipt narrows the prior isolated HTTP gateway result. It does not turn
that result into a production runtime, native consumer, or business success.
"""
from pathlib import Path
import hashlib, json, os, plistlib, re, shlex, sqlite3

ROOT = Path('/Volumes/T5/hepta-vnext-recovery-20261013/authbus-profile2-selector-c138-20261104-r1')
OUT = ROOT / 'runtime-contract-source-r1'
LIVE = Path('/Users/qianqi/.openclaw')
SDK = Path('/opt/homebrew/lib/node_modules/openclaw/dist')
CODEX = LIVE / 'npm/projects/openclaw-codex-8902d781d4__openclaw-generation__g-49fd4dbfde2c5057/node_modules/@openclaw/codex'
sha = lambda value: hashlib.sha256(value).hexdigest()

def save(path, value):
    data = (json.dumps(value, sort_keys=True, indent=2) + '\n').encode()
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'wb') as stream:
        stream.write(data); stream.flush(); os.fsync(stream.fileno())
    return sha(data)

def model_ref(value):
    return value.get('primary') if isinstance(value, dict) else value

def main():
    os.umask(0o077)
    checks = []
    def check(case, passed):
        checks.append({'case': case, 'passed': bool(passed)})
        if not passed: raise RuntimeError(case)
    config_bytes = (LIVE / 'openclaw.json').read_bytes()
    check('reviewed_production_config', sha(config_bytes) == 'ca2dd7d7879fa901dfb24e00837b56a4e0fd230600d7ed1e3086eda194187d4d')
    config = json.loads(config_bytes)
    default = config['agents']['defaults']; agents = config['agents'].get('list', [])
    agent = next((entry for entry in agents if entry.get('id') == 'main'), {})
    model = model_ref(agent.get('model', default['model']))
    check('actual_default_model', model == 'openai/gpt-5.6-sol')
    provider = config['models']['providers']['openai']
    model_cfg = next((x for x in provider.get('models', []) if x.get('id') in ('gpt-5.6-sol', model)), {})
    policies = [agent.get('models', {}).get(model, {}).get('agentRuntime'), default.get('models', {}).get(model, {}).get('agentRuntime'),
        model_cfg.get('agentRuntime'), agent.get('models', {}).get('openai/*', {}).get('agentRuntime'),
        default.get('models', {}).get('openai/*', {}).get('agentRuntime'), provider.get('agentRuntime')]
    check('no_explicit_default_runtime_policy', not any(x and x.get('id') for x in policies))
    check('custom_chatgpt_provider', provider.get('api') == 'openai-chatgpt-responses' and provider.get('baseUrl') == 'https://chatgpt.com/backend-api/codex')
    entry = config['plugins']['entries']['codex']; app = entry.get('config', {}).get('appServer', {})
    check('production_codex_enabled_and_allowed', entry.get('enabled') is True and 'codex' in config['plugins']['allow'])
    check('production_codex_default_agent_home', 'homeScope' not in app and 'command' not in app and 'transport' not in app)
    database = LIVE / 'state/openclaw.sqlite'
    connection = sqlite3.connect('file:' + str(database) + '?mode=ro', uri=True)
    connection.execute('PRAGMA query_only=ON'); connection.execute('BEGIN')
    row = connection.execute("SELECT install_records_json,plugins_json FROM installed_plugin_index WHERE index_key='installed-plugin-index'").fetchone()
    connection.rollback(); connection.close()
    check('actual_installed_index_exists', row is not None)
    install = json.loads(row[0])['codex']; plugins = json.loads(row[1])
    registered = [p for p in plugins if p.get('pluginId') == 'codex']
    check('unique_actual_codex_registry_entry', len(registered) == 1 and registered[0]['enabled'] is True and registered[0]['rootDir'] == str(CODEX))
    check('native_harness_declared', registered[0]['startup']['agentHarnesses'] == ['codex'] and install['version'] == '2026.7.1-1')
    pins = {}
    expected = {
        SDK / 'selection-JInn13lc.js': 'ccff13111aa60369ac9d88b526a58a7df1f733f1d99d205c01c6186036957e66',
        SDK / 'embedded-agent-DGUuxGR2.js': 'a1fd6d325758a6a96323027ab2778fa9779fbef55bc597b1a629fc6d0ad1acec',
        CODEX / 'dist/harness.js': '8919eefce05b3127251724c8f8cad7f1ac1a0994c57b243361092ea4de096f72',
        CODEX / 'dist/config-CYEDnLJ2.js': 'dd8d2fc434fc538ba8e69ebe0f2aa470eadcfb86c2ef95b19a7570afb51290a0',
        CODEX / 'dist/shared-client-4ICy3U6d.js': 'bff60f1bb2cb73ad44c7f9c9d779576a2ffd9836b22ecba0bd5b6046e7ce9103',
    }
    for path, wanted in expected.items():
        actual = sha(path.read_bytes()); check('source.' + path.name, actual == wanted); pins[str(path)] = actual
    for path in [SDK / 'harness-runtimes-CA3PNIDt.js', SDK / 'model-runtime-policy-Ca791C2-.js', SDK / 'openai-routing-DXJmS9CT.js',
                 CODEX / 'openclaw.plugin.json', CODEX / 'dist/index.js', LIVE / 'extensions/openclaw-authbus/index.js', LIVE / 'extensions/openclaw-authbus/codex-client-recycler.js']:
        pins[str(path)] = sha(path.read_bytes())
    environment_path = LIVE / 'service-env/ai.openclaw.gateway.env'; env_bytes = environment_path.read_bytes(); relevant = {}
    allowed = {'CODEX_HOME','OPENCLAW_CODEX_APP_SERVER_BIN','OPENCLAW_CODEX_APP_SERVER_ARGS','OPENCLAW_CONFIG_PATH','OPENCLAW_STATE_DIR','OPENCLAW_BUILD_PRIVATE_QA','OPENCLAW_QA_FORCE_RUNTIME','HOME'}
    for line in env_bytes.decode().splitlines():
        match = re.match(r'\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)=(.*)', line)
        if match and match[1] in allowed:
            value = shlex.split(match[2]); check('literal_runtime_environment', len(value) == 1); relevant[match[1]] = value[0]
    check('service_environment_does_not_override_native_runtime', relevant == {'HOME': '/Users/qianqi'})
    native_path = OUT / 'native-pin.public.json'; native_bytes = native_path.read_bytes(); native = json.loads(native_bytes)
    check('exact_managed_native_pin_receipt', sha(native_bytes) == 'fce8536b33a83b920accd7264991759a13011057cac3502b0ce14fffc075339e' and native['native']['version'] == 'codex-cli 0.144.3')
    official_bytes = (OUT / 'official-source-contract.public.json').read_bytes(); official = json.loads(official_bytes)
    check('exact_official_version_source_receipt', sha(official_bytes) == 'f9de7db17bf33d0195ccad087b333bf8a83957b35417be0ca4712fda33775adc' and official['commit'] == '78ad6e6bfd1d3b6a209acd3ef82172a96b25179c')
    prior_path = ROOT / 'final360-gateway-r8/result.public.json'; prior_bytes = prior_path.read_bytes(); prior = json.loads(prior_bytes)
    check('original_gateway_failure_unchanged', sha(prior_bytes) == 'f93f529a2e4b30e18e729856d141b8c0ae6d4b29988180c50504bf53f04726de' and prior['ok'] is False)
    isolated = json.loads((ROOT / 'final360-gateway-r8/state/openclaw.json').read_bytes())
    check('original_isolated_gateway_excluded_codex', isolated['plugins']['allow'] == ['openai','openclaw-authbus'] and 'codex' not in isolated['plugins']['entries'])
    check('all_audited_sources_unchanged', all(sha(Path(path).read_bytes()) == value for path, value in pins.items()))
    check('production_config_and_env_unchanged', (LIVE / 'openclaw.json').read_bytes() == config_bytes and environment_path.read_bytes() == env_bytes)
    authbus = config['plugins']['entries']['openclaw-authbus']
    report = {'schema':'heptabao.mac-installed-runtime-contract-readonly.v1','ok':True,'checks':checks,
        'scope':'Read-only installed source, registration and current configuration audit; native factory and production runtime not executed.',
        'configSha256':sha(config_bytes),'defaultModel':model,'providerApi':provider['api'],'providerBaseUrl':provider['baseUrl'],
        'sourcePins':pins,'installedPluginIndexRowSha256':sha(('\n'.join(row)).encode()),
        'codexRegistry':{'enabled':True,'origin':registered[0]['origin'],'version':install['version'],'rootDir':str(CODEX),'startupHarnesses':registered[0]['startup']['agentHarnesses']},
        'runtimePolicy':{'source':'implicit','runtime':'auto','basis':'No explicit matching model/agent/provider policy; chatgpt.com is not the api.openai.com implicit Codex-default predicate.',
            'autoSelectionContract':'The actual selector chooses a registered supporting plugin by priority. Installed codex supports openai/codex with priority100.',
            'actualProductionProcessRegistryQueried':False,'liveSessionRuntimeOverrideQueried':False,'productionRuntimeFullFidelityQualified':False},
        'nativeSourceContract':{'homeScope':'agent','homeScopeSource':'installed default; current config omits it','commandSource':'managed','nativePinReceiptSha256':sha(native_bytes),
            'nativeBinary':native['native'],'agentHome':str(LIVE/'agents/main/agent/codex-home'),'agentAuthFileExists':(LIVE/'agents/main/agent/codex-home/auth.json').is_file(),
            'authSource':'Current contract resolves SDK openai order and passes chatgptAuthTokens to local account/login/start unless caller explicitly selects native-auth null sentinel.',
            'userHomeSourceForced':False,'actualNativeConsumptionTested':False,'officialSourceContractSha256':sha(official_bytes)},
        'knownRegisteredAuthBusConsumer':{'plugin':'openclaw-authbus','enabled':authbus.get('enabled'),'endpoint':authbus.get('config',{}).get('address'),
            'scope':'Installed importer/order/renewal/revocation contract consumes the configured Bao endpoint and updates SDK credential stores. No complete enumeration of every possible business consumer is implied.'},
        'priorGatewayR8':{'receiptSha256':sha(prior_bytes),'originalOutcomeStillFailed':True,'isolatedAllowlist':isolated['plugins']['allow'],
            'originalExactDefaultModelPreserved':True,'productionCodexPluginCollectionPreserved':False,'nativeCodexFactoryValidated':False,
            'qualifiedScope':'Real installed OpenClaw built-in ChatGPT Responses HTTP gateway, true single provider HTTP429 and isolated full-state cold-restart rollback; not proof of complete production runtime/registry fidelity.'},
        'productionChanged':False,'productionTrafficCutover':False,'appServerStarted':False,'gatewayStarted':False,'providerRequests':0,
        'modelRequestReplayed':False,'refreshReplayed':False,'credentialValuesPublished':False,'nativeBackgroundNetworkAttemptsObserved':False,
        'nextValidation':'Actual installed registry loading/selection and Codex factory require a separate fresh agent-scope kernel-contained test; native background model/cloud/plugin network attempts must be accounted for separately.'}
    value = save(OUT / 'result.public.json', report)
    print(json.dumps({'ok':True,'checks':len(checks),'receipt':str(OUT/'result.public.json'),'sha256':value}))

if __name__ == '__main__': main()
