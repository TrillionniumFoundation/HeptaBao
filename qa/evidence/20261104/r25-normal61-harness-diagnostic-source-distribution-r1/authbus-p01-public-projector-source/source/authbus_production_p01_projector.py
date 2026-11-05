#!/usr/bin/env python3
"""Project only eight exact archived public receipts from stdin; no host access.

This program performs no filesystem open, listing, SQL, subprocess, socket,
service action or credential issuance. New registration paths are proposals,
not observed paths. The only data source is the fixed complete stdin payload.
"""
import hashlib
import json
import sys
import time

INPUT_BYTES = 328295
INPUT_SHA256 = "d0bab0c53bd92524b6a7ca7c3d5bc7ab60b26eb742c4a8e2c6f094c62e3f7b59"
MAX_INPUT_BYTES = 524288
MAX_OUTPUT_BYTES = 524288
NEW_LOCAL_DEADLINE_SECONDS = 5.0
SOURCE_PINS = {
  "mac": {
    "blob": "53996b7f5c59b2cb18fe6979efded3d6138ad67c",
    "bytes": 46277,
    "sha256": "001d9d3384f1b8c00fa3cba8af7f3020bedc54f26678611ab3cd3a524ce23902"
  },
  "rog": {
    "blob": "f44ea5f57b3db01bbe04a4bf24629997ae480bb7",
    "bytes": 46630,
    "sha256": "aee43560000aa4878be8c2175a3ab13e056ce0442e2bba1a9606ae0ffadd5531"
  },
  "x230": {
    "blob": "197ff767f16fbda8eb20aac80418a02915291925",
    "bytes": 23439,
    "sha256": "63f198cd17e100f9ce8e9e7329d2c1e711a46afe223878afd6cd74900e80feb5"
  },
  "pocket": {
    "blob": "e36e19e00b75dc313ce1a750751dfa5f2f1aafb4",
    "bytes": 58853,
    "sha256": "b55436c3622263112b429517e821f41c9a58225619e1e375d65804e1484f1ef6"
  },
  "registration": {
    "blob": "e2b3ad87420facc83b31f7bdc50b0d9564b0b924",
    "bytes": 18231,
    "sha256": "f458db4ebda522c3054c48eca917b8d7aaafcef33c13892a846c53441b49aa64"
  },
  "cleanup": {
    "blob": "16a6217e0163265b27a2e79f9aeffb26431b47ca",
    "bytes": 96796,
    "sha256": "aa23dcf2c01b9ea0372a67942510b6e9d8b49a1d3e823b2e62344748fdb92cf0"
  },
  "xr01Raw": {
    "blob": "b8df3efcf2ba7eb510abd5b9a203d68b4f12d856",
    "bytes": 11770,
    "sha256": "df94b577ce539fa23316d686c287b8aaeb8f6f3ee2561a5d1875368c8420dbff"
  },
  "macCanonicalCron": {
    "bytes": 1274,
    "sha256": "8e4397c745b22bf834e52fd352f3fdb98985c792b1506f34c1c024da3f303ab1",
    "blob": "62350066cecf7a534c5a7370a7e9ac59a5f02545"
  }
}
CONFIG_FIELDS = [
    "plugins.entries.openclaw-authbus.config.address",
    "plugins.entries.openclaw-authbus.config.caFile",
    "plugins.entries.openclaw-authbus.config.roleIdFile",
    "plugins.entries.openclaw-authbus.config.secretIdFile",
]
HOST_ORDER = ["mac", "rog", "pocket4", "x230"]
PROPOSED_HOMES = {
    "mac": "/Users/qianqi",
    "rog": "/home/qian-qi",
    "pocket4": "/home/alex",
}
def need(value, code):
    if not value:
        raise ValueError(code)

def sha(raw):
    return hashlib.sha256(raw).hexdigest()

def git_blob(raw):
    return hashlib.sha1(b"blob " + str(len(raw)).encode("ascii") + b"\0" + raw).hexdigest()

def encode(value):
    return (json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True) + "\n").encode("utf-8")

def citation(name, pointer):
    return {"source": name, "jsonPointer": pointer, **SOURCE_PINS[name]}

def full_nine(value):
    need(isinstance(value, list) and len(value) == 9
         and all(type(v) is int or (isinstance(v, str) and v.isdecimal()) for v in value),
         "original_full_nine_shape")
    return [str(v) for v in value]

def pointer_entry(name, pass_index, entry_index, entry):
    row = {
        "path": entry["path"],
        "kind": entry["kind"],
        "status": entry["status"],
        "evidence": citation(name, "/passes/" + str(pass_index) + "/entries/" + str(entry_index)),
    }
    for key in ("bytes", "sha256", "expected_prior_sha256", "prior_sha_matches", "absence_stable"):
        if key in entry:
            row[key] = entry[key]
    if "identity" in entry:
        row["originalIdentityDecimalStrings"] = full_nine(entry["identity"])
    return row

def inventory_entries(name, source):
    rows = []
    for pi, one_pass in enumerate(source["passes"]):
        for ei, entry in enumerate(one_pass["entries"]):
            rows.append((pointer_entry(name, pi, ei, entry), entry))
    return rows

def service_queries(name, source):
    rows = []
    for index, query in enumerate(source["queries"]):
        if query["kind"] in ("launchctl", "systemctl"):
            rows.append({
                "kind": query["kind"], "label": query["label"],
                "exitCode": query["exit_code"],
                "projectionComplete": query["projection_complete"],
                "projection": query["projection"],
                "evidence": citation(name, "/queries/" + str(index)),
                "currentAuthority": False,
                "notAtomicServiceOwnership": True,
            })
    return rows

def inventory_host(name, source, registration):
    entries = inventory_entries(name, source)
    configs = [(row, original) for row, original in entries if original["kind"] == "openclaw_config"]
    need(len(configs) == 1, "single_observed_config." + name)
    config_row, config = configs[0]
    view = config["projection"]
    need(view["host_id"] == name, "config_host." + name)
    config_row["connectionProjection"] = {
        "address": view["address"], "paths": view["connection_paths"],
        "completeAddressAvailable": False,
        "reason": "Endpoint projection may omit userinfo, path, query or fragment; use the separately approved private original capsule for an inverse.",
    }
    config_row["enabled"] = view["enabled"]
    config_row["flags"] = view["flags"]
    config_row["agents"] = view["agents"]
    config_row["orderExcludedAgents"] = view["order_excluded_agents"]
    config_row["nonConnectionFieldsMustRemainExact"] = True
    services = []
    credential_files = []
    caches = []
    holds = []
    environment = []
    for row, original in entries:
        path = original["path"]
        if original["kind"] in ("launchd_plist", "systemd_unit"):
            services.append({**row, "projection": original["projection"],
                             "arbitraryArgumentsRemainUnresolved": True})
            for condition in original["projection"].get("conditions", []):
                if condition.get("key") == "ConditionPathExists" and condition.get("negated") is True:
                    holds.append({"condition": condition, "definition": row,
                                  "automaticReleaseAllowed": False, "markerPayloadReadHere": False})
        if "/credentials/authbus/" in path:
            credential_files.append(row)
        if "/authbus/" in path and "/credentials/" not in path:
            caches.append(row)
        if original["kind"] == "environment_projection":
            environment.append({**row, "projection": original["projection"], "sourceOrEvalAllowed": False})
    return {
        "host": name,
        "observedConfiguredAgentIds": [a["id"] for a in view["agents"]],
        "clientDenominatorScope": "Only the exact selected archived OpenClaw configuration; no global client enumeration.",
        "config": config_row,
        "credentialPointerFileObservations": credential_files,
        "cacheObservations": caches,
        "serviceDefinitions": services,
        "serviceQueries": service_queries(name, source),
        "environmentDefinitions": environment,
        "holdConditions": holds,
        "sourceObservationStatus": source["status"],
        "sourceObservationFailure": source["failure"],
        "startedUnixNsOriginalDecimal": str(source["started_unix_ns"]),
        "historicalRegistration": registration,
        "currentLiveStateProvedByProjection": False,
        "rollback": {
            "configPath": config_row["path"],
            "allowedChangedKeys": CONFIG_FIELDS,
            "predecessorHashObserved": config_row["sha256"],
            "privateOriginalBytesRequiredBeforeAnyMutation": True,
            "cannotRestoreConfigFromPublicProjection": True,
            "requireExpectedAfterHashBeforeSingleInverse": True,
            "preserveAllServiceDefinitionsAndHoldMarkers": True,
            "restartOnlyToActuallyCapturedPredecessorState": True,
            "unknownInverseStopsWithoutRetry": True,
        },
    }

def project(sources):
    registration = sources["registration"]
    cleanup = sources["cleanup"]
    need([x["host"] for x in registration["host_rows"]] == HOST_ORDER, "registration_host_order")
    need([x["host"] for x in cleanup["hosts"]] == HOST_ORDER, "cleanup_host_order")
    reg = {row["host"]: row for row in registration["host_rows"]}
    for host in ("mac", "rog", "pocket4"):
        need(reg[host]["reviewable_future_change"]["keys"] == CONFIG_FIELDS, "four_config_fields." + host)
    mac = inventory_host("mac", sources["mac"], reg["mac"])
    rog = inventory_host("rog", sources["rog"], reg["rog"])
    need(mac["observedConfiguredAgentIds"] == ["main", "trnm", "hepta-ui", "hepta", "hepta-backend"], "mac_five_exact")
    need(rog["observedConfiguredAgentIds"] == ["main", "azi2", "azi3", "azi4", "azi5", "zbj-llm-runtime"], "rog_six_exact")
    mac["canonicalCronSupplement"] = {
        "path": sources["macCanonicalCron"]["path"],
        "leafStatus": sources["macCanonicalCron"]["leaf_status"],
        "twoEnoentObservations": sources["macCanonicalCron"]["absence_observations"],
        "evidence": citation("macCanonicalCron", ""),
        "previousInventoryExitUnchanged": True,
        "notSimultaneousWithInventory": True,
    }
    mac["gatewayRollbackRule"] = "Only an exact later source-bound transition may stop/restart ai.openclaw.gateway. Original KeepAlive, plist, environment, arbitrary argument hashes and four relay registrations are preserved; a QA launchd pass does not qualify the production manager."
    rog["disabledConfigMustRemainDisabled"] = rog["config"]["enabled"] is False
    rog["historicalConfigDriftNotRepaired"] = rog["config"].get("prior_sha_matches") is False
    rog["gatewayRollbackRule"] = "Preserve the observed inactive/dead gateway, enabled unit and disabled AuthBus config until a separately authorized transition. Do not restore the older config or release either held helper."

    pocket_source = cleanup["hosts"][2]
    pocket_config = pocket_source["configured_authbus_client"]
    actual_pocket = sources["pocket"]
    need([x["id"] for x in pocket_config["configured_agents"]] == ["main", "tg8687951891"], "pocket_two_selected_not_host_number")
    pocket = {
        "host": "pocket4",
        "observedConfiguredAgentIds": ["main", "tg8687951891"],
        "clientDenominatorScope": "Two selected historical agents. Pocket4 is the host identifier, not an assertion of four agents.",
        "config": {**pocket_config, "evidence": citation("cleanup", "/hosts/2/configured_authbus_client")},
        "serviceDefinitions": [
            {**row, "evidence": citation("cleanup", "/hosts/2/exact_current_service_entrypoints/" + str(i))}
            for i, row in enumerate(pocket_source["exact_current_service_entrypoints"])
        ],
        "serviceQueries": {
            "original": pocket_source["installed_service_states"],
            "evidence": citation("cleanup", "/hosts/2/installed_service_states"),
            "currentAuthority": False,
        },
        "heldRegistration": {**reg["pocket4"]["hold"], "evidence": citation("registration", "/host_rows/2/hold")},
        "historicalRegistration": reg["pocket4"],
        "historicalIsolatedConsumer": {
            "productCommit": actual_pocket["sourceCommit"], "productTree": actual_pocket["sourceTree"],
            "evidence": citation("pocket", ""),
            "ok": actual_pocket["ok"], "realServiceManagerExercised": actual_pocket["realServiceManagerExercised"],
            "allAccountsQualified": actual_pocket["allAccountsQualified"],
            "productionTrafficCutover": actual_pocket["productionTrafficCutover"],
            "newProductQualificationTransferred": False,
        },
        "currentLiveStateProvedByProjection": False,
        "rollback": {
            "configPath": pocket_config["config_path"],
            "allowedChangedKeys": CONFIG_FIELDS,
            "predecessorHashObserved": pocket_config["config_sha256"],
            "privateOriginalBytesRequiredBeforeAnyMutation": True,
            "cannotRestoreConfigFromPublicProjection": True,
            "requireExpectedAfterHashBeforeSingleInverse": True,
            "automaticHoldReleaseAllowed": False,
            "preserveExactTwoDropinsAndMarkers": True,
            "unknownInverseStopsWithoutRetry": True,
        },
    }
    xsource = sources["x230"]
    xentries = inventory_entries("x230", xsource)
    x230 = {
        "host": "x230", "observedConfiguredAgentIds": None, "installedConsumerCount": None,
        "clientDenominatorScope": "Still unknown; historical errno2 is not current absence or zero clients.",
        "historicalConfigPath": "/home/qian/.openclaw/openclaw.json",
        "historicalRuntimeReport": {
            "evidence": citation("xr01Raw", ""),
            "status": sources["xr01Raw"]["status"],
            "credentialDiscovery": sources["xr01Raw"]["credential_binding_discovery"],
            "errors": sources["xr01Raw"]["errors"],
            "configuredAgents": sources["xr01Raw"]["configured_agents"],
            "qualification": sources["xr01Raw"]["qualification"],
        },
        "serviceDefinitions": [
            {**row, "projection": original["projection"]}
            for row, original in xentries if original["kind"] == "systemd_unit"
        ],
        "serviceQueries": service_queries("x230", xsource),
        "oracleObservations": [
            {"projection": q["projection"], "evidence": citation("x230", "/queries/" + str(i))}
            for i, q in enumerate(xsource["queries"]) if q["kind"] == "docker"
        ],
        "historicalRegistration": reg["x230"],
        "currentLiveStateProvedByProjection": False,
        "rollback": {
            "configurationMutationReady": False,
            "noClientInstallationFromHistoricalAbsence": True,
            "proxyAndOracleMustRemainUnchanged": True,
            "noContainerDeletionFromNetworkOrMountMetadata": True,
        },
    }
    hosts = [mac, rog, pocket, x230]
    public_readset = []
    for i, entry in enumerate(registration["evidence"]):
        need(set(entry) == {"host", "path", "sha256"} and entry["host"] in HOST_ORDER, "registered_public_read_shape")
        public_readset.append({
            "id": "REG-" + str(i+1).zfill(2),
            "host": entry["host"], "path": entry["path"],
            "expectedSha256": entry["sha256"],
            "source": citation("registration", "/evidence/" + str(i)),
            "scope": "Existing exact public startup/backup/hold receipt, not private payload or a new restore.",
            "firstOperation": {"tool": "file_info", "args": {"host": entry["host"], "path": entry["path"]}},
            "admission": {"regularNoSymlink": True, "maximumBytes": 2097152, "sha256MustEqual": entry["sha256"], "versionRequired": True},
            "followingOperation": {"tool": "binary_read", "host": entry["host"], "path": entry["path"],
                                  "expectedVersion": "THE_SUCCESSFUL_SAME_FILE_INFO_VERSION", "chunkLimitBytes": 65536, "maximumWholeBytes": 2097152},
            "stopOnDriftOrUnknown": True, "automaticRetry": False,
            "dispatchReady": False, "requiresSeparateExactRootReadGo": True,
        })
    need(len(public_readset) == 9, "nine_public_receipt_refs_not_nine_backup_payloads")
    semantic_readset = [
        {
            "id": "MAC-GATEWAY-DEFINITION", "host": "mac",
            "entries": [
                {k: row[k] for k in ("path", "bytes", "sha256", "evidence")}
                for row in mac["serviceDefinitions"] + mac["environmentDefinitions"]
                if row["path"] in (
                    "/Users/qianqi/Library/LaunchAgents/ai.openclaw.gateway.plist",
                    "/Users/qianqi/.openclaw/service-env/ai.openclaw.gateway.env")
            ],
            "purpose": "Resolve seven hashed non-executable plist arguments and environment source order using exact pinned bodies; publish only semantically proven executable/script/config paths. Never evaluate shell/env or expose arbitrary argv values.",
            "publicValuesOnly": True, "newPathsFromUnknownArgumentsAllowed": False, "dispatchReady": False,
        },
        {
            "id": "X230-EXACT-CONFIG-METADATA", "host": "x230", "path": "/home/qian/.openclaw/openclaw.json",
            "source": citation("xr01Raw", "/errors"),
            "purpose": "One exact-path held ancestor/named/FD metadata observation and repeated errno2 classification. A present file remains metadata-only; a missing ancestor is distinguished from a missing leaf.",
            "fileBodyRead": False, "directoryListing": False, "secondGuessedPath": False, "dispatchReady": False,
        },
    ]
    proposed = []
    for host in ("mac", "rog", "pocket4"):
        home = PROPOSED_HOMES[host]
        root = home + "/heptabao-production-authbus-registration-r1"
        config = next(h["rollback"]["configPath"] for h in hosts if h["host"] == host)
        proposed.append({
            "host": host, "homeFromExistingEvidence": home,
            "proposalOnlyNewRoot": root, "rootExistenceObserved": False,
            "createOnly": True, "existingEntryRefused": True,
            "publicRegistrationPath": root + "/registration.public.json",
            "serverDataPath": root + "/server/data",
            "serverConfigurationPath": root + "/server/config.private.json",
            "clientCredentialGenerationPath": root + "/credentials/generation-r1",
            "proposedNewClientFiles": {
                "caFile": root + "/credentials/generation-r1/ca.crt",
                "roleIdFile": root + "/credentials/generation-r1/role_id",
                "secretIdFile": root + "/credentials/generation-r1/secret_id",
            },
            "clientConfigurationPath": config,
            "allowedClientChangeKeys": CONFIG_FIELDS,
            "proposedRoleName": "heptabao-authbus-" + host + "-r1",
            "proposedPolicyName": "heptabao-authbus-" + host + "-r1",
            "newRoleAndPolicyMustBeAbsent": True,
            "privateFileMode": "0600", "privateDirectoryMode": "0700",
            "actualOwnerAndNamedParentPins": None,
            "automaticServiceStart": False, "automaticHoldRelease": False,
        })
    return {
        "schema": "heptabao.authbus-production-p01-public-projection.r1",
        "qualification": "ARCHIVED_PUBLIC_SOURCE_MAPPING_ONLY",
        "sourceReferences": SOURCE_PINS, "hostOrder": HOST_ORDER, "hosts": hosts,
        "newProductionRegistrationReusableFromTheseReceipts": False,
        "registrationConclusionScope": "None of these frozen public observations establishes an accepted HeptaBao production cluster/CA/AppRole registration. This is not a global absence claim.",
        "exactExistingPublicReceiptReadset": public_readset,
        "exactDependencyResolutionReadset": semantic_readset,
        "proposedNewCreateOnlyHostRegistrations": proposed,
        "productionIssuerDependencyGraph": [
            {"step": "T01", "action": "Bind accepted canonical binaries, actual host/member identities, addresses/ports and HA source evidence to a new cluster deployment contract; no loopback fixture identity is accepted."},
            {"step": "T02", "action": "After separate exact GO, verify each proposed new root and role/policy name absent; create only the owned registration roots and retain complete independent readbacks. Any existing entry stops."},
            {"step": "T03", "action": "Under a separately reviewed secure issuer, generate one new independent CA and per-member leaf key/certificate; SANs must equal the actually bound addresses/names. Private keys remain private; public chains/full hashes and issuer receipts are required."},
            {"step": "T04", "action": "Initialize the new cluster once, retain actual clusterId/member evidence and private recovery custody, and read back the real native profile. Never import fixture root tokens, unseal keys, role IDs or SecretIDs."},
            {"step": "T05", "action": "Render exact per-host ACL from the installed AuthBus operation closure and real profile/grant mapping: canonical read grants separated from per-host inbox proposals; freeze policy hash, create once and independently read back."},
            {"step": "T06", "action": "Create each new per-host AppRole once with explicitly reviewed token/SecretID TTL and use limits; obtain RoleID and issue SecretID from real authenticated responses. Bind response, issuer/cluster, policy hash and the private generation files without public values."},
            {"step": "T07", "action": "Use actual issued tokens for lookup-self before renewal, renewal and lookup-self after renewal, unassigned rejection, revoke and revoked rejection. HTTP200 alone is not TTL/expiry extension evidence. Unknown stops without replay."},
            {"step": "T08", "action": "For one host at a time, obtain an exact private rollback capsule and real service writer custody, then change only four client connection fields under expected-before/after guards. Keep models, enabled, provider, refresh/quota, order, caches and hold directives unchanged."},
            {"step": "T09", "action": "Qualify actual persistence/cold-start and one strict inverse for that host under separate manager GO. Existing inactive or held services are not automatically started or released."},
            {"step": "T10", "action": "Register the newly introduced cluster/credential backup dependency explicitly, prove one source-bound encrypted capture/restore on the accepted product, and only then consider separately authorized legacy cleanup."},
        ],
        "actualIssuedProductionValues": {
            "address": None, "clusterId": None, "memberSet": None,
            "caAndLeafReadback": None, "issuerReceipt": None,
            "policyReadbacks": None, "perHostRoleIdSource": None, "perHostSecretIdSource": None,
            "tokenLifetimeUsePolicy": None, "renewalLookupBeforeAfter": None,
            "serviceTransitions": None, "backupRestoreReceipt": None,
        },
        "generationRule": "All generated values must come from later real secure issuance responses, with exact root-reviewed binding; never populate these slots from the loopback qualification fixture.",
        "nativeClosedGuardsRemain": ["MFA state and JWT/Kubernetes/OIDC state must remain compatible with the admitted native profile; unsupported routes remain refused.", "A route selector is not an authentication grant.", "No relaxed namespace/profile or unknown-delivery replay."],
        "noHostAccess": True, "noPrivateBodyInputs": True, "noSqlite": True,
        "noChild": True, "noNetwork": True, "noServiceMutation": True,
        "j3160Contacted": False, "providerCalled": False,
        "currentProductOrProductionQualificationTransferred": False,
        "hostDispatchAuthorized": False,
    }

def main():
    started = time.monotonic()
    raw = sys.stdin.buffer.read(MAX_INPUT_BYTES + 1)
    need(len(raw) == INPUT_BYTES and len(raw) <= MAX_INPUT_BYTES and sha(raw) == INPUT_SHA256, "fixed_complete_public_input")
    document = json.loads(raw)
    need(set(document) == {"schema", "sources"}
         and document["schema"] == "heptabao.authbus-registration-public-projection-input.r1"
         and set(document["sources"]) == set(SOURCE_PINS), "closed_source_set")
    sources = {}
    for name, expected in SOURCE_PINS.items():
        original = document["sources"][name]
        need(isinstance(original, str), "original_public_text")
        body = original.encode("utf-8")
        need(len(body) == expected["bytes"] and sha(body) == expected["sha256"]
             and git_blob(body) == expected["blob"], "whole_original." + name)
        sources[name] = json.loads(body)
    result = project(sources)
    need(time.monotonic() - started < NEW_LOCAL_DEADLINE_SECONDS, "local_projection_deadline")
    output = encode(result)
    need(len(output) <= MAX_OUTPUT_BYTES, "bounded_public_projection")
    sys.stdout.buffer.write(output)
    sys.stdout.buffer.flush()
    need(time.monotonic() - started < NEW_LOCAL_DEADLINE_SECONDS, "local_postflush_deadline")
    return 0

if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as error:
        # Fixed class/code only; never interpolate source body, arbitrary argv or credentials.
        sys.stderr.write(json.dumps({"schema":"heptabao.authbus-p01-projection-error.r1",
                                   "errorType":type(error).__name__,
                                   "code":str(error) if type(error) is ValueError else "projection_unavailable"})+"\n")
        sys.exit(1)
